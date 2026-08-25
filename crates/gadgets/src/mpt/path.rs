//! Hex-prefix path encoding, and nibble access over the key.
//!
//! Extension and leaf nodes carry their partial path hex-prefix encoded: the
//! first nibble is two flag bits, and an odd-length path packs its first real
//! nibble into the low half of that same byte.
//!
//! ```text
//! flag nibble:  0b00 -> extension, even    0b01 -> extension, odd
//!               0b10 -> leaf, even         0b11 -> leaf, odd
//! ```
//!
//! Both flag bits are load-bearing. Misreading the leaf bit turns a value into
//! a child reference; misreading the odd bit shifts the entire path by one
//! nibble, which silently proves inclusion at a different key.

use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::convert::ToBitsGadget;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_r1cs_std::uint8::UInt8;
use ark_r1cs_std::GR1CSVar;
use ark_relations::gr1cs::SynthesisError;

use crate::bytes::{one_hot, select_byte_with};

/// The two flag bits of a hex-prefix path.
pub struct Flags<F: PrimeField> {
    pub is_leaf: Boolean<F>,
    pub is_odd: Boolean<F>,
}

/// Reads the flag nibble from a path field's first byte.
///
/// Bit 5 of the byte is the leaf flag, bit 4 the odd flag — that is, bits 1 and
/// 0 of the high nibble.
pub fn read_flags<F: PrimeField>(first: &UInt8<F>) -> Result<Flags<F>, SynthesisError> {
    let bits = first.to_bits_le()?;
    Ok(Flags {
        is_leaf: bits[5].clone(),
        is_odd: bits[4].clone(),
    })
}

/// Enforces that the flag nibble's unused bits are zero.
///
/// The high nibble is `00`, `01`, `10`, or `11` in its low two bits; bits 6 and
/// 7 must be clear. Without this a prover has two spare bits to vary the byte
/// while keeping the flags, which changes the node's hash and therefore which
/// node the parent must reference.
pub fn assert_canonical_flags<F: PrimeField>(
    first: &UInt8<F>,
    active: &Boolean<F>,
) -> Result<(), SynthesisError> {
    let bits = first.to_bits_le()?;
    bits[6].conditional_enforce_equal(&Boolean::FALSE, active)?;
    bits[7].conditional_enforce_equal(&Boolean::FALSE, active)?;
    Ok(())
}

/// Enforces that an even-length path has a zero pad nibble.
///
/// An even path's first byte is `flag<<4` with the low nibble zero. A nonzero
/// pad is non-canonical and, like the spare flag bits, gives a prover freedom
/// to vary the encoding.
pub fn assert_even_pad_is_zero<F: PrimeField>(
    first: &UInt8<F>,
    is_odd: &Boolean<F>,
    active: &Boolean<F>,
) -> Result<(), SynthesisError> {
    let bits = first.to_bits_le()?;
    let bind = active.clone() & !is_odd.clone();
    for bit in bits.iter().take(4) {
        // Only when the path is even; an odd path uses these bits for data.
        bit.conditional_enforce_equal(&Boolean::FALSE, &bind)?;
    }
    Ok(())
}

/// Reads nibble `i` of a byte buffer, where nibble `2k` is the high half of
/// byte `k` and nibble `2k+1` the low half.
///
/// One byte read plus a select between halves.
pub fn nibble_at<F: PrimeField>(
    buf: &[UInt8<F>],
    index: &FpVar<F>,
) -> Result<FpVar<F>, SynthesisError> {
    // byte = index / 2, high half when index is even.
    let (byte_index, remainder) = halve_with_remainder(index)?;
    let sel = one_hot(&byte_index, buf.len())?;
    let byte = select_byte_with(buf, &sel)?;
    let bits = byte.to_bits_le()?;

    let mut high = FpVar::zero();
    let mut low = FpVar::zero();
    for i in 0..4 {
        low += FpVar::from(bits[i].clone()) * FpVar::constant(F::from(1u64 << i));
        high += FpVar::from(bits[i + 4].clone()) * FpVar::constant(F::from(1u64 << i));
    }

    let is_even = !remainder;
    FpVar::conditionally_select(&is_even, &high, &low)
}

/// Returns `(floor(index / 2), index mod 2)` for a 32-bit non-negative index.
///
/// The quotient range constraint is essential. Over a prime field,
/// `index = 2*half + rem` alone has a solution for either boolean remainder;
/// bounding `half` below 2^32 makes the integer decomposition unique.
fn halve_with_remainder<F: PrimeField>(
    index: &FpVar<F>,
) -> Result<(FpVar<F>, Boolean<F>), SynthesisError> {
    let cs = index.cs();
    let val = index.value().unwrap_or(F::zero());
    let as_u64 = field_to_u64(val);

    let half = FpVar::new_witness(cs.clone(), || Ok(F::from(as_u64 / 2)))?;
    let rem = Boolean::new_witness(cs.clone(), || Ok(as_u64 % 2 == 1))?;
    let mut bounded_half = FpVar::zero();
    for bit in 0..32 {
        let value = (as_u64 / 2) >> bit & 1 == 1;
        let bit_var = Boolean::new_witness(cs.clone(), || Ok(value))?;
        bounded_half += FpVar::from(bit_var) * FpVar::constant(F::from(1u64 << bit));
    }
    half.enforce_equal(&bounded_half)?;
    (&half * FpVar::constant(F::from(2u64)) + FpVar::from(rem.clone())).enforce_equal(index)?;
    Ok((half, rem))
}

fn field_to_u64<F: PrimeField>(v: F) -> u64 {
    let bytes = v.into_bigint().to_bytes_le();
    let mut out = [0u8; 8];
    let n = bytes.len().min(8);
    out[..n].copy_from_slice(&bytes[..n]);
    u64::from_le_bytes(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_relations::gr1cs::ConstraintSystem;

    use crate::bytes::alloc_bounded;
    use crate::mpt::tests::hex_prefix;

    fn flags_of(byte: u8) -> (bool, bool) {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let b = UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap();
        let f = read_flags(&b).unwrap();
        assert!(cs.is_satisfied().unwrap());
        (f.is_leaf.value().unwrap(), f.is_odd.value().unwrap())
    }

    #[test]
    fn flags_match_the_yellow_paper() {
        assert_eq!(
            flags_of(hex_prefix(&[], false)[0]),
            (false, false),
            "even extension"
        );
        assert_eq!(
            flags_of(hex_prefix(&[0xa], false)[0]),
            (false, true),
            "odd extension"
        );
        assert_eq!(
            flags_of(hex_prefix(&[], true)[0]),
            (true, false),
            "even leaf"
        );
        assert_eq!(
            flags_of(hex_prefix(&[0xa], true)[0]),
            (true, true),
            "odd leaf"
        );
    }

    #[test]
    fn canonical_flags_reject_spare_bits() {
        // 0x40 sets bit 6, which no valid hex-prefix byte uses.
        let cs = ConstraintSystem::<Fr>::new_ref();
        let b = UInt8::new_witness(cs.clone(), || Ok(0x60u8)).unwrap();
        assert_canonical_flags(&b, &Boolean::TRUE).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "accepted a spare flag bit");
    }

    #[test]
    fn even_pad_must_be_zero() {
        // 0x25: leaf, even, but with a nonzero pad nibble.
        let cs = ConstraintSystem::<Fr>::new_ref();
        let b = UInt8::new_witness(cs.clone(), || Ok(0x25u8)).unwrap();
        let f = read_flags(&b).unwrap();
        assert_even_pad_is_zero(&b, &f.is_odd, &Boolean::TRUE).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "accepted a nonzero even pad");
    }

    #[test]
    fn even_pad_check_permits_odd_paths() {
        // 0x3a: leaf, odd, low nibble is real path data.
        let cs = ConstraintSystem::<Fr>::new_ref();
        let b = UInt8::new_witness(cs.clone(), || Ok(0x3au8)).unwrap();
        let f = read_flags(&b).unwrap();
        assert_even_pad_is_zero(&b, &f.is_odd, &Boolean::TRUE).unwrap();
        assert!(cs.is_satisfied().unwrap(), "rejected a valid odd path");
    }

    /// The quotient/remainder decomposition stays satisfiable at any 32-bit
    /// offset and must not be gated, since a false gate would leave the
    /// quotient unconstrained.
    ///
    /// This matters because the traversal calls `nibble_at` speculatively with
    /// offsets derived from a decode that may not apply.
    #[test]
    fn nibble_reads_stay_satisfiable_at_any_offset() {
        let data = vec![0x35u8, 0x71];
        for idx in [0u64, 3, 4, 63, 1000] {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let buf = alloc_bounded(cs.clone(), &data, 32).unwrap();
            let i = FpVar::new_witness(cs.clone(), || Ok(Fr::from(idx))).unwrap();
            let _ = nibble_at(&buf, &i).unwrap();
            assert!(
                cs.is_satisfied().unwrap(),
                "nibble_at unsatisfiable at offset {idx}"
            );
        }
    }

    #[test]
    fn nibbles_read_high_half_first() {
        let data = vec![0x35u8, 0x71];
        let expected = [3u8, 5, 7, 1];
        for (i, want) in expected.iter().enumerate() {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let buf = alloc_bounded(cs.clone(), &data, 32).unwrap();
            let idx = FpVar::new_witness(cs.clone(), || Ok(Fr::from(i as u64))).unwrap();
            let got = nibble_at(&buf, &idx).unwrap();
            assert_eq!(got.value().unwrap(), Fr::from(*want as u64), "nibble {i}");
            assert!(cs.is_satisfied().unwrap());
        }
    }
}
