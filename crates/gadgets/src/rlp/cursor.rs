//! Cursor-walking RLP decoder: safe by construction, expensive.
//!
//! Every offset is *derived* from bytes actually read out of the buffer, so
//! there is no witness hint for a prover to forge. The canonical-form checks
//! are still required — a non-minimal encoding is a property of the bytes, not
//! of the parsing strategy — but the structural forgeries in the test suite are
//! impossible here rather than merely rejected.
//!
//! The cost is that every read is witness-indexed at roughly 10 constraints per
//! buffer byte (see `crate::bytes`). Reading a long-form length means up to 8
//! such reads before the payload offset is even known.
//!
//! This exists as the correctness baseline. If [`super::layout`] disagrees with
//! it on any input, the layout decoder is wrong.

use ark_ff::PrimeField;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::gr1cs::SynthesisError;

use super::{Item, RlpDecoder};
use crate::bytes::{byte_to_field, one_hot, select_byte_with};

pub struct Cursor;

/// Decoded shape of a prefix byte.
struct Prefix<F: PrimeField> {
    /// Payload length when it is encoded directly in the prefix.
    short_len: FpVar<F>,
    /// Number of length bytes following the prefix, zero for short forms.
    len_of_len: FpVar<F>,
    is_single_byte: Boolean<F>,
    is_short_form: Boolean<F>,
    is_long_form: Boolean<F>,
    is_list: Boolean<F>,
}

/// Classifies a prefix byte into the four RLP forms.
///
/// All branches are evaluated; R1CS has no early exit. The classification is
/// derived from the byte's value with comparisons, and exactly one of the four
/// form indicators is true by construction of the ranges.
fn classify<F: PrimeField>(prefix: &UInt8<F>) -> Result<Prefix<F>, SynthesisError> {
    use ark_r1cs_std::convert::ToBitsGadget;
    let v = byte_to_field(prefix)?;
    let bits = prefix.to_bits_le()?;

    // Range indicators from the byte's own bits, which UInt8 already holds
    // constrained. Summing equality tests over 0..bound costs ~10 constraints
    // per tested value; reading bits costs almost nothing.
    //
    //   v < 0x80  iff  bit7 == 0
    //   v < 0xc0  iff  !(bit7 & bit6)
    //   v < 0xb8  iff  v < 0x80, or (0x80..0xc0 and low6 < 0x38)
    //   v < 0xf8  iff  v < 0xc0, or (0xc0.. and low3 != 7)
    let b7 = bits[7].clone();
    let b6 = bits[6].clone();
    let lt_80 = !b7.clone();
    let lt_c0 = !(b7.clone() & b6.clone());

    // Within a 0x40 block, the offset is the low 6 bits. Short form ends at
    // 0x37 (55), so lt_b8 means low6 <= 0x37, i.e. not (bit5 & bit4 & bit3).
    let low6_lt_38 = !(bits[5].clone() & bits[4].clone() & bits[3].clone());
    let lt_b8 = lt_80.clone() | (lt_c0.clone() & low6_lt_38.clone());
    let lt_f8 = lt_c0.clone() | low6_lt_38.clone();

    let is_single_byte = lt_80.clone();
    let is_short_str = lt_b8.clone() & !lt_80.clone();
    let is_long_str = lt_c0.clone() & !lt_b8.clone();
    let is_short_list = lt_f8.clone() & !lt_c0.clone();
    let is_long_list = !lt_f8.clone();

    let is_short_form = is_short_str.clone() | is_short_list.clone();
    let is_long_form = is_long_str.clone() | is_long_list.clone();
    let is_list = is_short_list.clone() | is_long_list.clone();

    // Short forms carry the length in the prefix: v - base.
    let short_len = FpVar::conditionally_select(
        &is_short_str,
        &(&v - FpVar::constant(F::from(0x80u64))),
        &FpVar::conditionally_select(
            &is_short_list,
            &(&v - FpVar::constant(F::from(0xc0u64))),
            &FpVar::zero(),
        )?,
    )?;

    // Long forms carry the number of length bytes: v - base.
    let len_of_len = FpVar::conditionally_select(
        &is_long_str,
        &(&v - FpVar::constant(F::from(0xb7u64))),
        &FpVar::conditionally_select(
            &is_long_list,
            &(&v - FpVar::constant(F::from(0xf7u64))),
            &FpVar::zero(),
        )?,
    )?;

    Ok(Prefix {
        short_len,
        len_of_len,
        is_single_byte,
        is_short_form,
        is_long_form,
        is_list,
    })
}

/// `v < bound` for a field element known to hold a byte value.
fn less_than_const<F: PrimeField>(v: &FpVar<F>, bound: u64) -> Result<Boolean<F>, SynthesisError> {
    // v is a byte, so v < bound iff v is one of 0..bound. Build the indicator
    // as a sum of equality tests: cheap enough at 256 positions and avoids a
    // general comparison gadget.
    let mut acc = FpVar::zero();
    for i in 0..bound {
        acc += FpVar::from(v.is_eq(&FpVar::constant(F::from(i)))?);
    }
    // acc is 0 or 1 because the tested values are distinct.
    let is_lt = acc.is_eq(&FpVar::one())?;
    Ok(is_lt)
}

/// Reads up to `MAX_LEN_BYTES` length bytes and assembles the big-endian value.
///
/// Enforces canonical form: no leading zeros, and the assembled value must be
/// at least 56 (below that, short form was required).
///
/// # Why 2 and not 8
///
/// RLP allows up to 8 length bytes, encoding payloads up to 2^64. Every buffer
/// in this relation is bounded at a few kilobytes, so a payload needing more
/// than 2 length bytes (65,535) cannot fit and its item would be rejected by
/// the containment check anyway.
///
/// This matters because each length byte is a witness-indexed read at ~9,200
/// constraints in a 1KB buffer, paid unconditionally on every `decode_item`
/// regardless of form. Going from 8 to 2 removes ~55k constraints per item,
/// which measured as roughly half the decoder's cost.
///
/// An item claiming more than `MAX_LEN_BYTES` length bytes is rejected rather
/// than truncated: `len_of_len` is enforced within range below.
const MAX_LEN_BYTES: usize = 2;

fn read_long_length<F: PrimeField>(
    buf: &[UInt8<F>],
    at: &FpVar<F>,
    len_of_len: &FpVar<F>,
    active: &Boolean<F>,
) -> Result<FpVar<F>, SynthesisError> {
    let mut value = FpVar::zero();
    let mut first_byte = FpVar::zero();

    for i in 0..MAX_LEN_BYTES {
        let idx = at + FpVar::constant(F::from((1 + i) as u64));
        let sel = one_hot(&idx, buf.len())?;
        let byte = select_byte_with(buf, &sel)?;
        let bv = byte_to_field(&byte)?;

        // This byte participates only while i < len_of_len.
        let in_range = less_than_field(&FpVar::constant(F::from(i as u64)), len_of_len)?;
        let contrib = FpVar::conditionally_select(&in_range, &bv, &FpVar::zero())?;
        let shifted = FpVar::conditionally_select(
            &in_range,
            &(&value * FpVar::constant(F::from(256u64))),
            &value,
        )?;
        value = shifted + contrib;

        if i == 0 {
            first_byte = bv;
        }
    }

    // An item claiming more length bytes than we read must be rejected, not
    // silently truncated: otherwise a prover hides length bytes we never see.
    let within = less_than_field(
        len_of_len,
        &FpVar::constant(F::from((MAX_LEN_BYTES + 1) as u64)),
    )?;
    within.conditional_enforce_equal(&Boolean::TRUE, active)?;

    // Canonical: the first length byte must be nonzero, and the value must be
    // at least 56 or short form was required.
    let first_is_zero = first_byte.is_eq(&FpVar::zero())?;
    first_is_zero.conditional_enforce_equal(&Boolean::FALSE, active)?;

    let at_least_56 = less_than_field(&FpVar::constant(F::from(55u64)), &value)?;
    at_least_56.conditional_enforce_equal(&Boolean::TRUE, active)?;

    Ok(value)
}

/// `a < b` for small field elements, via bit decomposition of the difference.
fn less_than_field<F: PrimeField>(a: &FpVar<F>, b: &FpVar<F>) -> Result<Boolean<F>, SynthesisError> {
    use ark_r1cs_std::convert::ToBitsGadget;
    // b - a - 1 is non-negative iff a < b. Decompose into 32 bits and require
    // the value fits, which it does for all offsets and lengths here.
    let diff = b - a;
    let bits = diff.to_bits_le()?;
    // If a >= b the difference wraps and the high bits are set.
    let mut high_set = Boolean::FALSE;
    for bit in bits.iter().skip(32) {
        high_set = high_set | bit;
    }
    let is_zero = diff.is_eq(&FpVar::zero())?;
    Ok(!high_set & !is_zero)
}

impl<F: PrimeField> RlpDecoder<F> for Cursor {
    fn decode_item(
        buf: &[UInt8<F>],
        at: &FpVar<F>,
        active: &Boolean<F>,
    ) -> Result<Item<F>, SynthesisError> {
        let sel = one_hot(at, buf.len())?;
        let prefix = select_byte_with(buf, &sel)?;
        let p = classify(&prefix)?;

        // Long-length canonicity only binds when this really is a long form
        // *and* the caller wants this decode to bind at all.
        let long_active = active.clone() & p.is_long_form.clone();
        let long_len = read_long_length(buf, at, &p.len_of_len, &long_active)?;

        // Payload length by form.
        let payload_len = FpVar::conditionally_select(
            &p.is_single_byte,
            &FpVar::one(),
            &FpVar::conditionally_select(&p.is_long_form, &long_len, &p.short_len)?,
        )?;

        // Header length by form: 0 for a bare byte, 1 for short, 1 + n for long.
        let header_len = FpVar::conditionally_select(
            &p.is_single_byte,
            &FpVar::zero(),
            &FpVar::conditionally_select(
                &p.is_long_form,
                &(FpVar::one() + &p.len_of_len),
                &FpVar::one(),
            )?,
        )?;

        let offset = at + &header_len;

        // Canonical: a short string of exactly one byte below 0x80 must have
        // been written bare. Reject 0x81 followed by such a byte.
        let is_one_byte_str = p.is_short_form.clone()
            & !p.is_list.clone()
            & p.short_len.is_eq(&FpVar::one())?;
        let content_sel = one_hot(&offset, buf.len())?;
        let content = select_byte_with(buf, &content_sel)?;
        let content_lt_80 = less_than_const(&byte_to_field(&content)?, 0x80)?;
        (is_one_byte_str & content_lt_80).conditional_enforce_equal(&Boolean::FALSE, active)?;

        // The item must fit inside the buffer.
        let end = &offset + &payload_len;
        let fits = less_than_field(&end, &FpVar::constant(F::from((buf.len() + 1) as u64)))?;
        fits.conditional_enforce_equal(&Boolean::TRUE, active)?;

        Ok(Item {
            offset,
            payload_len,
            header_len,
            is_list: p.is_list,
        })
    }

    fn decode_list(
        buf: &[UInt8<F>],
        at: &FpVar<F>,
        n: usize,
        active: &Boolean<F>,
    ) -> Result<Vec<Item<F>>, SynthesisError> {
        let list = Self::decode_item(buf, at, active)?;
        list.is_list.conditional_enforce_equal(&Boolean::TRUE, active)?;

        let list_end = list.end();
        let mut cursor = list.offset.clone();
        let mut items = Vec::with_capacity(n);

        for _ in 0..n {
            let child = Self::decode_item(buf, &cursor, active)?;
            // Containment: the child must not reach past the list's payload.
            let child_end = child.end();
            let contained = less_than_field(&child_end, &(&list_end + FpVar::one()))?;
            contained.conditional_enforce_equal(&Boolean::TRUE, active)?;
            cursor = child_end;
            items.push(child);
        }

        // Tiling: the children must exactly fill the payload, no gap.
        cursor.conditional_enforce_equal(&list_end, active)?;

        Ok(items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adversarial_suite() {
        super::super::tests::run_suite::<Cursor>();
    }

    #[test]
    fn cost() {
        super::super::tests::report_cost::<Cursor>("cursor");
    }

    /// Where does decode_item's cost actually go?
    ///
    /// This decides whether a witness-supplied layout can help. If the cost is
    /// in the single prefix decode, a layout hint saves nothing, because that
    /// decode is required either way to verify the hint.
    #[test]
    fn cost_breakdown() {
        use ark_bn254::Fr;
        use ark_r1cs_std::alloc::AllocVar;
        use ark_relations::gr1cs::ConstraintSystem;
        use crate::bytes::alloc_bounded;

        let bound = 1024;
        let data = vec![0x85, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa];

        // one_hot + select_byte for a single prefix read
        let c = ConstraintSystem::<Fr>::new_ref();
        let buf = alloc_bounded(c.clone(), &data, bound).unwrap();
        let at = FpVar::new_witness(c.clone(), || Ok(Fr::from(0u64))).unwrap();
        let before = c.num_constraints();
        let sel = crate::bytes::one_hot(&at, bound).unwrap();
        let _ = crate::bytes::select_byte_with(&buf, &sel).unwrap();
        println!("  one byte read (one_hot + select): {}", c.num_constraints() - before);

        // full decode_item
        let c2 = ConstraintSystem::<Fr>::new_ref();
        let buf2 = alloc_bounded(c2.clone(), &data, bound).unwrap();
        let at2 = FpVar::new_witness(c2.clone(), || Ok(Fr::from(0u64))).unwrap();
        let before2 = c2.num_constraints();
        let _ = <Cursor as RlpDecoder<Fr>>::decode_item(&buf2, &at2, &Boolean::TRUE).unwrap();
        println!("  full decode_item:                 {}", c2.num_constraints() - before2);
    }
}
