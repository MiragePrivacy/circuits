//! Byte plumbing shared by every parser.
//!
//! # The recurring hazard
//!
//! Circuits have no dynamic arrays. A bounded buffer is always MAX bytes wide
//! and only the first `len` are real, so every gadget must make the padded tail
//! inert. A prover controls those bytes and will choose values that make an
//! underconstrained circuit accept.
//!
//! Spec 12.5: "Every active node byte beyond its exact length is
//! zero-constrained. No padded node may contribute a hash, path nibble, child
//! reference, or acceptance selector."
//!
//! # Cost
//!
//! [`select_byte`] is O(N) constraints per single byte read, because arkworks
//! has no random-access gadget: every position is tested and the hits summed.
//! This is the expensive primitive and the reason byte-level parsing dominates
//! the relation.
//!
//! Read a fixed offset wherever the format fixes one, and prefer
//! [`select_bytes`] over repeated [`select_byte`] calls at consecutive offsets
//! — it shares the equality indicators across the run instead of rebuilding
//! them per byte.
//!
//! For contrast, gnark's `std/math/uints` does bytewise operations via lookup
//! tables at 1-3 constraints each. That option does not exist in Groth16, and
//! it is the price of staying inside the Fortanix EDP enclave.

use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::convert::ToBitsGadget;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_r1cs_std::uint8::UInt8;
use ark_r1cs_std::GR1CSVar;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};

/// `sel[i] = 1` for `i < len`, else 0. Also enforces `len <= n`.
///
/// Built as a latched running product rather than N independent comparators:
///
/// ```text
/// running[i+1] = running[i] * (1 - is_boundary[i])
/// ```
///
/// Two reasons. It costs roughly one constraint per position instead of ~10 for
/// a full comparison, and monotonicity is *structural* — once the mask latches
/// to zero it cannot come back, so a prover cannot produce a mask with holes.
/// With independent comparators, monotonicity is a separate constraint that is
/// easy to forget and invisible when forgotten.
///
/// # `active`
///
/// The `len <= n` check is a genuine assertion about the caller's data, so it
/// binds only when `active` is set. A speculative caller — one decoding a node
/// that may be of another shape — would otherwise be rejected for a length it
/// never meant to claim.
///
/// The mask itself is always computed correctly; only the bound assertion is
/// gated. Compare `one_hot`, whose constraint is definitional and must *not*
/// be gated.
pub fn prefix_mask<F: PrimeField>(
    len: &FpVar<F>,
    n: usize,
    active: &Boolean<F>,
) -> Result<Vec<Boolean<F>>, SynthesisError> {
    let mut sel = Vec::with_capacity(n);
    let mut running = Boolean::TRUE;

    for i in 0..n {
        let is_boundary = len.is_eq(&FpVar::constant(F::from(i as u64)))?;
        running = running.clone() & !is_boundary;
        sel.push(running.clone());
    }

    // `len <= n`: either a boundary was hit inside the buffer (running is now
    // false) or len is exactly n (running is still true and every byte is
    // selected). Any larger len also leaves running true, so this alone is
    // insufficient — constrain the bound explicitly.
    let at_most_n = len.is_eq(&FpVar::constant(F::from(n as u64)))?;
    running.conditional_enforce_equal(&at_most_n, active)?;

    Ok(sel)
}

/// Enforces `len <= n` when `active`, without the zero-tail requirement.
///
/// [`assert_zero_tail`] carries the same bound, so use this only where a length
/// is checked against a buffer it is not itself the extent of.
pub fn assert_at_most<F: PrimeField>(
    len: &FpVar<F>,
    n: usize,
    active: &Boolean<F>,
) -> Result<(), SynthesisError> {
    let _ = prefix_mask(len, n, active)?;
    Ok(())
}

/// Requires `buf[i] == 0` for every `i >= len`.
///
/// This is the check that makes a bounded buffer safe to hash or parse.
pub fn assert_zero_tail<F: PrimeField>(
    buf: &[UInt8<F>],
    len: &FpVar<F>,
    active: &Boolean<F>,
) -> Result<(), SynthesisError> {
    let sel = prefix_mask(len, buf.len(), active)?;
    let zero = UInt8::constant(0);
    for (byte, keep) in buf.iter().zip(sel.iter()) {
        // Outside the prefix the byte must be zero; inside, unconstrained here.
        let expected = UInt8::conditionally_select(keep, byte, &zero)?;
        byte.conditional_enforce_equal(&expected, active)?;
    }
    Ok(())
}

/// A one-hot indicator vector for a witness index.
///
/// `out[i] == 1` iff `idx == i`, for `i` in `0..n`, and zero everywhere if
/// `idx >= n`.
///
/// Cheaper than a full equality gadget per position, though only modestly: the
/// indicators are allocated as witnesses and constrained jointly rather than
/// derived one at a time. Measured at ~9 constraints per buffer byte against
/// ~10 for per-position `is_eq`.
///
/// The real value is reuse. Build this once and pass it to
/// [`select_byte_with`] for every read against the same index.
///
/// The joint constraints are:
///
/// - each `out[i]` is boolean (one constraint each, from the allocation);
/// - `sum(out) == in_range`, so at most one is set;
/// - `sum(i * out[i]) == idx * in_range`, which pins *which* one.
///
/// Proving those three facts is equivalent to proving each `out[i] = (idx ==
/// i)` individually, at a fraction of the cost. Reuse the vector across every
/// read against the same index.
pub fn one_hot<F: PrimeField>(idx: &FpVar<F>, n: usize) -> Result<Vec<Boolean<F>>, SynthesisError> {
    let cs = idx.cs();
    let idx_val = idx.value().ok();

    let mut sel = Vec::with_capacity(n);
    for i in 0..n {
        let bit = idx_val.map(|v| v == F::from(i as u64)).unwrap_or(false);
        sel.push(Boolean::new_witness(cs.clone(), || Ok(bit))?);
    }

    enforce_one_hot(idx, &sel)?;
    Ok(sel)
}

/// A one-hot indicator vector that must actually hit, when `active`.
///
/// [`one_hot`] alone permits the all-zero assignment for *any* index, because
/// the all-zero vector is how an out-of-range index is encoded. That is the
/// right default for a speculative read, and wrong wherever the caller knows
/// the index is in range: a prover who claims out-of-range for an in-range
/// index suppresses the read, and [`select_byte_with`] returns zero.
///
/// Suppressing a read is not the same as choosing an out-of-range index, and no
/// range constraint on the index prevents it. Where a zero read would satisfy
/// something, use this instead.
///
/// The hit assertion is separate from [`enforce_one_hot`] on purpose. That
/// function's constraints define the indicators and must stay ungated; this one
/// asserts a fact about the caller's data and is therefore gated.
pub fn one_hot_in_range<F: PrimeField>(
    idx: &FpVar<F>,
    n: usize,
    active: &Boolean<F>,
) -> Result<Vec<Boolean<F>>, SynthesisError> {
    let sel = one_hot(idx, n)?;
    let mut sum = FpVar::zero();
    for bit in &sel {
        sum += FpVar::from(bit.clone());
    }
    sum.conditional_enforce_equal(&FpVar::one(), active)?;
    Ok(sel)
}

fn enforce_one_hot<F: PrimeField>(
    idx: &FpVar<F>,
    sel: &[Boolean<F>],
) -> Result<(), SynthesisError> {
    // Exactly one indicator when idx is in range, none when it is not.
    let mut sum = FpVar::zero();
    let mut weighted = FpVar::zero();
    for (i, b) in sel.iter().enumerate() {
        let f = FpVar::from(b.clone());
        sum += &f;
        weighted += f * FpVar::constant(F::from(i as u64));
    }

    // Boolean indicators do not by themselves make their sum boolean. Without
    // this constraint, several hits can have a weighted average equal to idx
    // (for example positions 0 and 2 for idx 1).
    (&sum * (&sum - FpVar::one())).enforce_equal(&FpVar::zero())?;

    // in_range is itself derived from the indicators, so a prover cannot claim
    // in-range for an out-of-range index.
    let in_range = sum.clone();
    weighted.enforce_equal(&(idx * &in_range))?;

    Ok(())
}

/// Reads `buf[idx]` for a witness `idx`.
///
/// O(N) constraints. An out-of-range `idx` yields zero rather than failing;
/// callers that need in-range enforcement must add it, because "reads as zero"
/// is a valid parse outcome in some positions and a bug in others.
///
/// When reading several times against the same index, build the indicator
/// vector once with [`one_hot`] and use [`select_byte_with`].
pub fn select_byte<F: PrimeField>(
    buf: &[UInt8<F>],
    idx: &FpVar<F>,
) -> Result<UInt8<F>, SynthesisError> {
    let sel = one_hot(idx, buf.len())?;
    select_byte_with(buf, &sel)
}

/// Reads a byte using a precomputed one-hot indicator vector.
///
/// Computed as a field-level dot product, `sum_i sel[i] * buf[i]`, then
/// decomposed back into a byte: one constraint per position plus nine. Because
/// `sel` is at most one-hot the sum is the addressed byte, or zero.
pub fn select_byte_with<F: PrimeField>(
    buf: &[UInt8<F>],
    sel: &[Boolean<F>],
) -> Result<UInt8<F>, SynthesisError> {
    field_to_byte(&dot(sel, &to_fields(buf)?))
}

/// Reads `l` consecutive bytes starting at a witness `offset`.
///
/// Computes the equality indicator for each buffer position **once** and reuses
/// it across the whole run, rather than rebuilding it per byte. That is the
/// difference between `l` equality tests per position and one.
///
/// Each output byte costs one product per buffer position. Out-of-range
/// offsets read zeros, which speculative callers rely on; where the offset is
/// known to be in range, [`shift_window`] is far cheaper.
///
/// **Read a fixed offset wherever the format fixes one.** Witness-dependent
/// reads are the most expensive thing in this circuit after keccak itself, and
/// unlike keccak their cost scales with the compiled buffer bound rather than
/// the real input size.
pub fn select_bytes<F: PrimeField>(
    buf: &[UInt8<F>],
    offset: &FpVar<F>,
    l: usize,
) -> Result<Vec<UInt8<F>>, SynthesisError> {
    let n = buf.len();
    // One indicator vector, shared across every output byte.
    let hit = one_hot(offset, n)?;

    let fields = to_fields(buf)?;
    (0..l)
        .map(|j| {
            // Output byte j reads buf[offset + j], so position i contributes
            // when offset == i - j.
            let terms = if j < n { &fields[j..] } else { &[][..] };
            field_to_byte(&dot(&hit, terms))
        })
        .collect()
}

/// Packs 16 big-endian bytes into one field element.
///
/// Used for the two 128-bit statement-hash limbs (spec 10.1) and the hi/lo
/// split of any 256-bit value (spec 8.1).
///
/// 16 bytes is always below the BN254 modulus, so the packing is injective and
/// no reduction can occur. **Never widen this to 32 bytes**: a 256-bit value
/// does not fit in one field element and would alias.
pub fn pack_bytes_16<F: PrimeField>(bytes: &[UInt8<F>]) -> Result<FpVar<F>, SynthesisError> {
    assert_eq!(bytes.len(), 16, "pack_bytes_16 takes exactly 16 bytes");
    let mut acc = FpVar::zero();
    for byte in bytes {
        let as_field = byte_to_field(byte)?;
        acc = acc * FpVar::constant(F::from(256u64)) + as_field;
    }
    Ok(acc)
}

/// A `UInt8` as a field element, from its bit decomposition.
///
/// `UInt8` is literally 8 `Boolean`s in arkworks, so the bits are already
/// constrained and this is a linear combination rather than a range check.
pub fn byte_to_field<F: PrimeField>(byte: &UInt8<F>) -> Result<FpVar<F>, SynthesisError> {
    // to_bits_be gives most-significant first; weight accordingly.
    let bits = byte.to_bits_be()?;
    let mut acc = FpVar::zero();
    for (i, bit) in bits.iter().enumerate() {
        let weight = F::from(1u64 << (7 - i));
        acc += FpVar::from(bit.clone()) * FpVar::constant(weight);
    }
    Ok(acc)
}

/// Asserts a 32-byte topic is a canonically left-padded 20-byte address:
/// twelve zero bytes then the address.
///
/// Spec 12.6.2 requires this for topic 2, the recipient. Topic 1 is parsed and
/// length-checked but its value is unconstrained per spec 12.4 — the payment
/// source is deliberately free, and spec 9 records why constraining it is
/// unreachable.
pub fn assert_padded_address_topic<F: PrimeField>(
    topic: &[UInt8<F>],
    addr: &[UInt8<F>],
) -> Result<(), SynthesisError> {
    assert_eq!(topic.len(), 32, "topic must be 32 bytes");
    assert_eq!(addr.len(), 20, "address must be 20 bytes");

    let zero = UInt8::constant(0);
    for byte in topic.iter().take(12) {
        byte.enforce_equal(&zero)?;
    }
    for (t, a) in topic[12..].iter().zip(addr.iter()) {
        t.enforce_equal(a)?;
    }
    Ok(())
}

/// Allocates a bounded buffer as witness, padded with zeros to `n`.
pub fn alloc_bounded<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    data: &[u8],
    n: usize,
) -> Result<Vec<UInt8<F>>, SynthesisError> {
    assert!(data.len() <= n, "input exceeds the compiled bound");
    let mut padded = data.to_vec();
    padded.resize(n, 0);
    padded
        .iter()
        .map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)))
        .collect()
}

/// A zero field element carrying a buffer's constraint system.
///
/// `FpVar::zero()` is a constant with no `cs`, and any gadget that allocates
/// witnesses from an offset needs one — passing a constant zero yields
/// `MissingCS` at synthesis time. Deriving zero from a buffer byte keeps the
/// reference at the cost of one equality constraint.
pub fn zero_like<F: PrimeField>(buf: &[UInt8<F>]) -> Result<FpVar<F>, SynthesisError> {
    let cs = buf
        .first()
        .map(|b| b.cs())
        .unwrap_or(ConstraintSystemRef::None);
    let z = FpVar::new_witness(cs, || Ok(F::zero()))?;
    z.enforce_equal(&FpVar::zero())?;
    Ok(z)
}

/// `a < b` for small non-negative field elements.
///
/// Both operands must be known to fit well below 2^32, which every offset,
/// length and index in this crate does. The difference is bit-decomposed and
/// the high bits checked: if `a >= b` the subtraction wraps in the field and
/// those bits are set.
///
/// Consolidated here from three near-identical copies that had accumulated in
/// `rlp::cursor` and `mpt::traverse`. A comparison gadget is exactly the kind
/// of thing that should exist once: a subtle difference between copies is
/// invisible until it is a soundness bug.
pub fn lt<F: PrimeField>(a: &FpVar<F>, b: &FpVar<F>) -> Result<Boolean<F>, SynthesisError> {
    let diff = b - a;
    let bits = diff.to_bits_le()?;
    let mut high = Boolean::FALSE;
    for bit in bits.iter().skip(32) {
        high |= bit;
    }
    let is_zero = diff.is_eq(&FpVar::zero())?;
    Ok(!high & !is_zero)
}

/// `a <= b`, on the same terms as [`lt`].
pub fn le<F: PrimeField>(a: &FpVar<F>, b: &FpVar<F>) -> Result<Boolean<F>, SynthesisError> {
    let is_eq = a.is_eq(b)?;
    Ok(lt(a, b)? | is_eq)
}

/// A buffer as field-valued bytes. Emits no constraints: each value is a
/// linear combination of the byte's existing bits.
pub fn to_fields<F: PrimeField>(buf: &[UInt8<F>]) -> Result<Vec<FpVar<F>>, SynthesisError> {
    buf.iter().map(byte_to_field).collect()
}

/// A `UInt8` equal to a byte-valued field expression. Nine constraints: eight
/// booleanity checks and the recomposition.
///
/// Unsatisfiable when `value` is not in `0..256`, so this doubles as a range
/// check.
pub fn field_to_byte<F: PrimeField>(value: &FpVar<F>) -> Result<UInt8<F>, SynthesisError> {
    if let FpVar::Constant(c) = value {
        return Ok(UInt8::constant(field_to_u64(*c) as u8));
    }
    let native = value.value().map(|v| field_to_u64(v) as u8).unwrap_or(0);
    let byte = UInt8::new_witness(value.cs(), || Ok(native))?;
    byte_to_field(&byte)?.enforce_equal(value)?;
    Ok(byte)
}

/// `sum(sel[i] * vals[i])`, one constraint per non-constant term.
pub fn dot<F: PrimeField>(sel: &[Boolean<F>], vals: &[FpVar<F>]) -> FpVar<F> {
    let mut acc = FpVar::zero();
    for (s, v) in sel.iter().zip(vals.iter()) {
        acc += FpVar::from(s.clone()) * v;
    }
    acc
}

/// Little-endian bits of `value`, which must be below `2^n`. `n + 1`
/// constraints.
pub fn to_bits_bounded<F: PrimeField>(
    value: &FpVar<F>,
    n: usize,
) -> Result<Vec<Boolean<F>>, SynthesisError> {
    if let FpVar::Constant(c) = value {
        let native = field_to_u64(*c);
        assert!(n >= 64 || native >> n == 0, "constant exceeds {n} bits");
        return Ok((0..n).map(|i| Boolean::constant((native >> i) & 1 == 1)).collect());
    }
    let native = value.value().map(field_to_u64).unwrap_or(0);
    let mut acc = FpVar::zero();
    let mut bits = Vec::with_capacity(n);
    for i in 0..n {
        let bit = Boolean::new_witness(value.cs(), || Ok((native >> i) & 1 == 1))?;
        acc += FpVar::from(bit.clone()) * FpVar::constant(F::from(1u64 << i));
        bits.push(bit);
    }
    acc.enforce_equal(value)?;
    Ok(bits)
}

/// `out[j] = buf[offset + j]` for `j < width`, reading zero past the buffer.
///
/// A log-depth shifter over field-valued bytes. Each stage shifts by one power
/// of two and only keeps the positions later stages can still reach, so a
/// 32-byte read from a 532-byte node costs ~1.3k constraints where a one-hot
/// read over the bits costs ~136k.
///
/// `offset` must be below the next power of two above `buf.len()`, or the
/// decomposition is unsatisfiable. Offsets inside that range but past the
/// buffer read zeros, so a caller that needs the read to land in the buffer
/// must bound `offset` itself.
pub fn shift_window<F: PrimeField>(
    buf: &[FpVar<F>],
    offset: &FpVar<F>,
    width: usize,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    let stages = usize::BITS as usize - buf.len().leading_zeros() as usize;
    let bits = to_bits_bounded(offset, stages)?;
    let zero = FpVar::zero();
    let mut cur = buf.to_vec();
    for stage in (0..stages).rev() {
        let step = 1 << stage;
        let keep = (width + step - 1).min(cur.len());
        let bit = FpVar::from(bits[stage].clone());
        cur = (0..keep)
            .map(|j| {
                let here = &cur[j];
                let there = cur.get(j + step).unwrap_or(&zero);
                here + &bit * (there - here)
            })
            .collect();
    }
    cur.resize(width, zero);
    Ok(cur)
}

/// `[x <= c]` for `x < 2^n` and constant `c < 2^n`. `n + 2` constraints.
pub fn le_const<F: PrimeField>(x: &FpVar<F>, c: u64, n: usize) -> Result<Boolean<F>, SynthesisError> {
    // c + 2^n - x lies in [c + 1, c + 2^n], below 2^(n + 1); its top bit is
    // set exactly when x <= c.
    let shifted = FpVar::constant(F::from(c + (1 << n))) - x;
    Ok(to_bits_bounded(&shifted, n + 1)?[n].clone())
}

/// `out[i] = buf[i - amount]` for `i < width`, zero before `amount` and past
/// the buffer. `amount` must be below `2^bits`. One constraint per output per
/// bit of `amount`.
pub fn shift_right<F: PrimeField>(
    buf: &[FpVar<F>],
    amount: &FpVar<F>,
    width: usize,
    bits: usize,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    let bits = to_bits_bounded(amount, bits)?;
    let zero = FpVar::zero();
    let mut cur: Vec<FpVar<F>> = (0..width)
        .map(|i| buf.get(i).cloned().unwrap_or_else(FpVar::zero))
        .collect();
    for (stage, bit) in bits.iter().enumerate() {
        let step = 1 << stage;
        let bit = FpVar::from(bit.clone());
        cur = (0..width)
            .map(|i| {
                let here = &cur[i];
                let there = i.checked_sub(step).map(|at| &cur[at]).unwrap_or(&zero);
                here + &bit * (there - here)
            })
            .collect();
    }
    Ok(cur)
}

/// `sel[i] = [i < len]` for `i < n`, requiring `len <= n` unconditionally.
///
/// Two constraints per position: booleanity and monotonicity. With the sum
/// pinned to `len`, a monotone boolean vector is exactly the prefix mask.
/// Unlike [`prefix_mask`] there is no speculative mode: a length past `n` is
/// unsatisfiable whatever the caller's `active` flag.
pub fn prefix_mask_exact<F: PrimeField>(
    len: &FpVar<F>,
    n: usize,
) -> Result<Vec<Boolean<F>>, SynthesisError> {
    let native = len.value().map(field_to_u64).unwrap_or(0);
    let mut sel: Vec<Boolean<F>> = Vec::with_capacity(n);
    let mut sum = FpVar::zero();
    for i in 0..n {
        let bit = Boolean::new_witness(len.cs(), || Ok((i as u64) < native))?;
        if let Some(prev) = sel.last() {
            // Once zero, stays zero.
            (FpVar::from(bit.clone()) * (FpVar::one() - FpVar::from(prev.clone())))
                .enforce_equal(&FpVar::zero())?;
        }
        sum += FpVar::from(bit.clone());
        sel.push(bit);
    }
    sum.enforce_equal(len)?;
    Ok(sel)
}

/// Requires `buf[i] == 0` wherever `mask[i]` is false. One constraint per byte.
pub fn assert_zero_outside<F: PrimeField>(
    buf: &[FpVar<F>],
    mask: &[Boolean<F>],
) -> Result<(), SynthesisError> {
    for (byte, keep) in buf.iter().zip(mask.iter()) {
        (byte * (FpVar::one() - FpVar::from(keep.clone()))).enforce_equal(&FpVar::zero())?;
    }
    Ok(())
}

fn field_to_u64<F: PrimeField>(v: F) -> u64 {
    use ark_ff::BigInteger;
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
    use ark_r1cs_std::GR1CSVar;
    use ark_relations::gr1cs::ConstraintSystem;

    fn fp(cs: ConstraintSystemRef<Fr>, v: u64) -> FpVar<Fr> {
        FpVar::new_witness(cs, || Ok(Fr::from(v))).unwrap()
    }

    #[test]
    fn prefix_mask_selects_the_prefix() {
        for len in 0..=8usize {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let sel = prefix_mask(&fp(cs.clone(), len as u64), 8, &Boolean::TRUE).unwrap();
            let got: Vec<bool> = sel.iter().map(|b| b.value().unwrap()).collect();
            let want: Vec<bool> = (0..8).map(|i| i < len).collect();
            assert_eq!(got, want, "len {len}");
            assert!(cs.is_satisfied().unwrap(), "len {len}");
        }
    }

    /// `one_hot` on an out-of-range index must stay satisfiable.
    ///
    /// Its weighted-sum constraint is definitional: the witness is chosen to
    /// satisfy it. For an out-of-range index every indicator is false, so the
    /// sum is zero and `idx * 0 == 0` holds. That means it needs no `active`
    /// gate — and gating it would be wrong, since a false `active` would leave
    /// the indicators unconstrained and a prover could pick any of them.
    #[test]
    fn one_hot_is_satisfiable_out_of_range() {
        for idx in [0u64, 7, 8, 99, 100_000] {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let sel = one_hot(&fp(cs.clone(), idx), 8).unwrap();
            assert!(
                cs.is_satisfied().unwrap(),
                "one_hot unsatisfiable at idx {idx}"
            );
            let hits: usize = sel.iter().filter(|b| b.value().unwrap()).count();
            assert_eq!(hits, if idx < 8 { 1 } else { 0 }, "hit count at idx {idx}");
        }
    }

    #[test]
    fn one_hot_rejects_multiple_hits_with_the_right_weighted_average() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        // [1, 0, 1] has weighted sum 2 == idx * sum, so the old weighted-only
        // relation accepted it even though it is not one-hot.
        let sel = [true, false, true]
            .into_iter()
            .map(|value| Boolean::new_witness(cs.clone(), || Ok(value)).unwrap())
            .collect::<Vec<_>>();
        enforce_one_hot(&fp(cs.clone(), 1), &sel).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "accepted a multi-hit selector");
    }

    #[test]
    fn prefix_mask_rejects_len_past_the_bound() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let _ = prefix_mask(&fp(cs.clone(), 9), 8, &Boolean::TRUE).unwrap();
        assert!(
            !cs.is_satisfied().unwrap(),
            "len 9 accepted for an 8-byte buffer"
        );
    }

    #[test]
    fn zero_tail_accepts_a_properly_padded_buffer() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let buf = alloc_bounded(cs.clone(), &[1, 2, 3], 8).unwrap();
        assert_zero_tail(&buf, &fp(cs.clone(), 3), &Boolean::TRUE).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn zero_tail_rejects_a_dirty_tail() {
        // The attack this exists to stop: a prover supplies nonzero bytes past
        // the witnessed length, hoping they contribute to a hash or a parse.
        let cs = ConstraintSystem::<Fr>::new_ref();
        let buf = alloc_bounded(cs.clone(), &[1, 2, 3, 0xff], 8).unwrap();
        assert_zero_tail(&buf, &fp(cs.clone(), 3), &Boolean::TRUE).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "dirty tail accepted");
    }

    #[test]
    fn select_byte_reads_the_right_position() {
        let data: Vec<u8> = (0..16).map(|i| (i * 7 + 3) as u8).collect();
        for idx in 0..data.len() {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let buf = alloc_bounded(cs.clone(), &data, 16).unwrap();
            let got = select_byte(&buf, &fp(cs.clone(), idx as u64)).unwrap();
            assert_eq!(got.value().unwrap(), data[idx], "idx {idx}");
            assert!(cs.is_satisfied().unwrap());
        }
    }

    #[test]
    fn select_byte_out_of_range_reads_zero() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let buf = alloc_bounded(cs.clone(), &[1, 2, 3], 4).unwrap();
        let got = select_byte(&buf, &fp(cs.clone(), 99)).unwrap();
        assert_eq!(got.value().unwrap(), 0);
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn select_bytes_reads_a_run() {
        let data: Vec<u8> = (0..16).map(|i| i as u8).collect();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let buf = alloc_bounded(cs.clone(), &data, 16).unwrap();
        let got = select_bytes(&buf, &fp(cs.clone(), 4), 5).unwrap();
        let got: Vec<u8> = got.iter().map(|b| b.value().unwrap()).collect();
        assert_eq!(got, vec![4, 5, 6, 7, 8]);
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn pack_16_matches_native() {
        let bytes: [u8; 16] = core::array::from_fn(|i| (i * 17 + 1) as u8);
        let cs = ConstraintSystem::<Fr>::new_ref();
        let buf = alloc_bounded(cs.clone(), &bytes, 16).unwrap();
        let packed = pack_bytes_16(&buf).unwrap();
        let expected = Fr::from(u128::from_be_bytes(bytes));
        assert_eq!(packed.value().unwrap(), expected);
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn padded_address_topic_accepts_canonical_padding() {
        let addr: [u8; 20] = core::array::from_fn(|i| (i + 1) as u8);
        let mut topic = [0u8; 32];
        topic[12..].copy_from_slice(&addr);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let t = alloc_bounded(cs.clone(), &topic, 32).unwrap();
        let a = alloc_bounded(cs.clone(), &addr, 20).unwrap();
        assert_padded_address_topic(&t, &a).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn padded_address_topic_rejects_dirty_padding() {
        // Non-canonical padding: a nonzero byte in the leading twelve.
        let addr: [u8; 20] = core::array::from_fn(|i| (i + 1) as u8);
        let mut topic = [0u8; 32];
        topic[0] = 1;
        topic[12..].copy_from_slice(&addr);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let t = alloc_bounded(cs.clone(), &topic, 32).unwrap();
        let a = alloc_bounded(cs.clone(), &addr, 20).unwrap();
        assert_padded_address_topic(&t, &a).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "dirty padding accepted");
    }

    #[test]
    fn select_bytes_is_cheaper_than_repeated_select_byte() {
        // The sharing claim, verified rather than asserted.
        let n = 256;
        let l = 32;

        let cs_a = ConstraintSystem::<Fr>::new_ref();
        let buf_a = alloc_bounded(cs_a.clone(), &vec![0u8; n], n).unwrap();
        let off_a = fp(cs_a.clone(), 0);
        let before_a = cs_a.num_constraints();
        for j in 0..l {
            let idx = &off_a + FpVar::constant(Fr::from(j as u64));
            let _ = select_byte(&buf_a, &idx).unwrap();
        }
        let naive = cs_a.num_constraints() - before_a;

        let cs_b = ConstraintSystem::<Fr>::new_ref();
        let buf_b = alloc_bounded(cs_b.clone(), &vec![0u8; n], n).unwrap();
        let off_b = fp(cs_b.clone(), 0);
        let before_b = cs_b.num_constraints();
        let _ = select_bytes(&buf_b, &off_b, l).unwrap();
        let shared = cs_b.num_constraints() - before_b;

        println!("reading {l} bytes from {n}: naive {naive}, shared {shared}");
        assert!(
            shared < naive,
            "sharing did not reduce cost: {shared} vs {naive}"
        );
    }

    #[test]
    fn select_byte_cost() {
        for n in [64usize, 256, 1024] {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let buf = alloc_bounded(cs.clone(), &vec![0u8; n], n).unwrap();
            let idx = fp(cs.clone(), 0);
            let before = cs.num_constraints();
            let _ = select_byte(&buf, &idx).unwrap();
            println!(
                "select_byte over {n} bytes: {} constraints",
                cs.num_constraints() - before
            );
        }
    }

    /// Adds `delta` to one witness variable's assignment.
    ///
    /// Symbolic linear combinations cache their values when created. The system
    /// is finalized (inlining every combination into witness terms) and the
    /// cache dropped, so each constraint re-evaluates from the edited witness.
    fn tamper(cs: &ConstraintSystemRef<Fr>, variable: ark_relations::gr1cs::Variable, delta: Fr) {
        cs.finalize();
        let index = variable.index().expect("a witness variable");
        let mut inner = cs.borrow_mut().unwrap();
        inner.assignments.witness_assignment[index] += delta;
        inner.assignments.lc_assignment.clear();
    }

    fn bit_variable(bit: &Boolean<Fr>) -> ark_relations::gr1cs::Variable {
        match bit {
            Boolean::Var(b) => b.variable(),
            Boolean::Constant(_) => panic!("expected an allocated bit"),
        }
    }

    #[test]
    fn field_to_byte_binds_its_bits() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let byte = field_to_byte(&fp(cs.clone(), 0x5a)).unwrap();
        assert_eq!(byte.value().unwrap(), 0x5a);
        assert!(cs.is_satisfied().unwrap());
        let bit = byte.to_bits_le().unwrap()[1].clone();
        tamper(&cs, bit_variable(&bit), -Fr::from(1u64));
        assert!(!cs.is_satisfied().unwrap(), "a byte detached from its value");

        let cs = ConstraintSystem::<Fr>::new_ref();
        let _ = field_to_byte(&fp(cs.clone(), 256)).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "accepted 256 as a byte");
    }

    #[test]
    fn to_bits_bounded_binds_and_bounds() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let bits = to_bits_bounded(&fp(cs.clone(), 9), 8).unwrap();
        assert!(cs.is_satisfied().unwrap());
        tamper(&cs, bit_variable(&bits[1]), Fr::from(1u64));
        assert!(!cs.is_satisfied().unwrap(), "bits detached from their value");

        let cs = ConstraintSystem::<Fr>::new_ref();
        let _ = to_bits_bounded(&fp(cs.clone(), 300), 8).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "accepted 300 in eight bits");
    }

    #[test]
    fn prefix_mask_exact_is_exactly_the_length() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mask = prefix_mask_exact(&fp(cs.clone(), 5), 10).unwrap();
        let values: Vec<bool> = mask.iter().map(|b| b.value().unwrap()).collect();
        assert_eq!(values, (0..10).map(|i| i < 5).collect::<Vec<_>>());
        assert!(cs.is_satisfied().unwrap());

        // Moving the edge either way, or punching a hole, must fail.
        for (at, delta) in [(5, 1i64), (4, -1), (2, -1)] {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let mask = prefix_mask_exact(&fp(cs.clone(), 5), 10).unwrap();
            let delta = if delta > 0 { Fr::from(1u64) } else { -Fr::from(1u64) };
            tamper(&cs, bit_variable(&mask[at]), delta);
            assert!(!cs.is_satisfied().unwrap(), "accepted a mask edited at {at}");
        }

        // A hole inside the prefix paid for by a bit past it keeps the sum, so
        // only monotonicity catches it. In the sponge this would exempt a byte
        // past the length from the zero tail.
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mask = prefix_mask_exact(&fp(cs.clone(), 5), 10).unwrap();
        tamper(&cs, bit_variable(&mask[2]), -Fr::from(1u64));
        tamper(&cs, bit_variable(&mask[7]), Fr::from(1u64));
        assert!(!cs.is_satisfied().unwrap(), "accepted a non-monotone mask");

        let cs = ConstraintSystem::<Fr>::new_ref();
        let _ = prefix_mask_exact(&fp(cs.clone(), 11), 10).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "accepted a length past the buffer");
    }

    #[test]
    fn assert_zero_outside_rejects_a_dirty_tail() {
        for (data, ok) in [(vec![1u8, 2, 3, 0, 0], true), (vec![1, 2, 3, 0, 7], false)] {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let buf = alloc_bounded(cs.clone(), &data, 5).unwrap();
            let mask = prefix_mask_exact(&fp(cs.clone(), 3), 5).unwrap();
            assert_zero_outside(&to_fields(&buf).unwrap(), &mask).unwrap();
            assert_eq!(cs.is_satisfied().unwrap(), ok, "{data:?}");
        }
    }

    #[test]
    fn shifts_read_the_addressed_window() {
        let data: Vec<u8> = (1..=40).collect();
        for offset in [0usize, 1, 7, 31, 39, 40, 63] {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let buf = to_fields(&alloc_bounded(cs.clone(), &data, 40).unwrap()).unwrap();
            let left = shift_window(&buf, &fp(cs.clone(), offset as u64), 4).unwrap();
            let right = shift_right(&buf, &fp(cs.clone(), offset as u64 % 16), 44, 4).unwrap();
            for (j, v) in left.iter().enumerate() {
                let want = data.get(offset + j).copied().unwrap_or(0);
                assert_eq!(v.value().unwrap(), Fr::from(want as u64), "left {offset}+{j}");
            }
            for (i, v) in right.iter().enumerate() {
                let want = i
                    .checked_sub(offset % 16)
                    .and_then(|at| data.get(at))
                    .copied()
                    .unwrap_or(0);
                assert_eq!(v.value().unwrap(), Fr::from(want as u64), "right {i}");
            }
            assert!(cs.is_satisfied().unwrap());
        }

        // The offset is decomposed exactly: one past the shifter's range fails.
        let cs = ConstraintSystem::<Fr>::new_ref();
        let buf = to_fields(&alloc_bounded(cs.clone(), &data, 40).unwrap()).unwrap();
        let _ = shift_window(&buf, &fp(cs.clone(), 64), 4).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "accepted an offset past the shifter");
    }
}
