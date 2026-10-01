//! Sponge construction: absorb, pad, squeeze.
//!
//! Two entry points, because the relation needs both:
//!
//! - [`keccak256_fixed`] hashes a buffer whose length is known at compile time.
//!   The commitment (226 bytes) and statement (285 bytes) preimages are this
//!   case, and it is much cheaper: padding lands at a fixed offset, so no
//!   selection logic is needed.
//! - [`keccak256_var`] hashes a bounded buffer with a **witnessed** length.
//!   Receipts and MPT nodes are this case, and it is the harder one.
//!
//! # Why the variable case is expensive
//!
//! ZoKrates' reference takes a compile-time `N` and absorbs unconditionally. A
//! witnessed length cannot do that: the circuit must run the maximum number of
//! permutations regardless, and select which output is the real one. So a
//! 300-byte receipt in a 2048-byte buffer still pays for 16 permutations.
//!
//! That is the single largest cost lever in the relation, and it is why spec
//! section 12.9's `MAX_RECEIPT_BYTES` and `MAX_MPT_NODE_BYTES` matter far more
//! than they look. Real ERC-20 receipts are often 200-400 bytes against a 2048
//! bound; measuring the real distribution before freezing those numbers is
//! worth more than any further backend comparison.
//!
//! # The padded tail is a soundness hazard
//!
//! For the variable case, every byte beyond the witnessed length must be
//! zero-constrained, and the padding must be applied at the witnessed length
//! rather than the buffer width. A prover controls those bytes. Spec 12.5.

use ark_ff::PrimeField;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::convert::ToBitsGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::gr1cs::SynthesisError;

use super::permutation::{DirectPermutation, PermutationBackend, State};
use super::{DELIM_KECCAK, RATE};
use crate::bytes::{assert_zero_outside, prefix_mask_exact, to_fields};

/// A byte as 8 boolean signals, least-significant bit first.
///
/// `UInt8` is literally this in arkworks, so [`to_byte`] is free: it reads the
/// existing bit decomposition rather than allocating or range-checking.
pub type Byte<F> = [Boolean<F>; 8];

/// A `UInt8` as sponge bytes. Emits no constraints.
pub fn to_byte<F: PrimeField>(b: &UInt8<F>) -> Result<Byte<F>, SynthesisError> {
    let bits = b.to_bits_le()?;
    Ok(core::array::from_fn(|i| bits[i].clone()))
}

/// A buffer of `UInt8` as sponge bytes.
pub fn to_bytes<F: PrimeField>(buf: &[UInt8<F>]) -> Result<Vec<Byte<F>>, SynthesisError> {
    buf.iter().map(to_byte).collect()
}

fn empty_state<F: PrimeField>() -> State<F> {
    core::array::from_fn(|_| core::array::from_fn(|_| Boolean::FALSE))
}

/// XOR a rate-sized block of bytes into the state.
///
/// Lane `i` covers bytes `8i..8i+8`; within a lane, byte `j` occupies bits
/// `8j..8j+8` little-endian. That convention is what removes ZoKrates'
/// explicit `swap_u64` calls: with a bit array, the byte order is an indexing
/// choice rather than a computation.
fn absorb_block<F: PrimeField>(st: &mut State<F>, block: &[Byte<F>]) -> Result<(), SynthesisError> {
    debug_assert!(block.len() <= RATE);
    for (byte_idx, byte) in block.iter().enumerate() {
        let lane = byte_idx / 8;
        let within = byte_idx % 8;
        for (bit, value) in byte.iter().enumerate() {
            let pos = within * 8 + bit;
            st[lane][pos] = st[lane][pos].clone() ^ value;
        }
    }
    Ok(())
}

/// Read the first 32 bytes of the state as the digest.
fn squeeze_256<F: PrimeField>(st: &State<F>) -> [Byte<F>; 32] {
    core::array::from_fn(|byte_idx| {
        let lane = byte_idx / 8;
        let within = byte_idx % 8;
        core::array::from_fn(|bit| st[lane][within * 8 + bit].clone())
    })
}

/// Keccak-256 over a buffer whose length is fixed at compile time.
///
/// Used for the commitment and statement preimages. Padding lands at a known
/// offset, so this needs no selection logic and costs exactly
/// `ceil((len + 1) / RATE)` permutations.
pub fn keccak256_fixed<F: PrimeField>(input: &[Byte<F>]) -> Result<[Byte<F>; 32], SynthesisError> {
    keccak256_fixed_with(input, &mut DirectPermutation)
}

pub fn keccak256_fixed_with<F: PrimeField, B: PermutationBackend<F>>(
    input: &[Byte<F>],
    backend: &mut B,
) -> Result<[Byte<F>; 32], SynthesisError> {
    let mut st = empty_state::<F>();

    let full_blocks = input.len() / RATE;
    for b in 0..full_blocks {
        absorb_block(&mut st, &input[b * RATE..(b + 1) * RATE])?;
        st = backend.permute(st)?;
    }

    // Final partial block, with padding. The delimiter goes at the first free
    // byte and 0x80 into the last byte of the rate; when the remainder is
    // exactly RATE-1 these coincide and the byte is 0x81.
    let rem = &input[full_blocks * RATE..];
    let mut last: Vec<Byte<F>> = rem.to_vec();
    let mut pad = vec![0u8; RATE - rem.len()];
    pad[0] = DELIM_KECCAK;
    let plen = pad.len();
    pad[plen - 1] |= 0x80;
    for byte in pad {
        last.push(core::array::from_fn(|bit| {
            Boolean::constant((byte >> bit) & 1 == 1)
        }));
    }
    absorb_block(&mut st, &last)?;
    st = backend.permute(st)?;

    Ok(squeeze_256(&st))
}

/// Keccak-256 over a bounded buffer with a witnessed length.
///
/// `buf` is `MAX` bytes wide; only the first `len` are real. The tail is
/// zero-constrained here, so callers need not do it separately.
///
/// # Cost
///
/// Runs `ceil((MAX + 1) / RATE)` permutations unconditionally, because the
/// circuit cannot branch on a witness. Around the permutations it costs about
/// five constraints per buffer byte: the prefix mask (two), the zero tail
/// (one), and placing the delimiter (two).
///
/// # Construction
///
/// 1. Zero-constrain the tail (spec 12.5), so padded bytes cannot contribute.
/// 2. Build the padded message in-circuit. Because the tail is zero, the
///    message is the buffer itself with `DELIM_KECCAK` XORed in at index `len`
///    and `0x80` at the last byte of the final rate block; only bit 0 of each
///    byte and bit 7 of each block end ever differ from the buffer.
/// 3. Absorb every block and permute, retaining the state after each.
/// 4. Select the digest of the state following the block that contains the
///    padding.
///
/// Step 4 selects by the length-derived final block, which the prover does not
/// choose. Squeezing is a projection, so selecting the 256 digest bits of each
/// candidate state is the same as squeezing the selected state.
///
/// # Length
///
/// `len <= MAX` and the zero tail are enforced unconditionally. A slot whose
/// digest is ignored (an inactive trie level) must therefore still present a
/// zero buffer and zero length, which `alloc_bounded` of an empty value does.
pub fn keccak256_var<F: PrimeField>(
    buf: &[UInt8<F>],
    len: &FpVar<F>,
) -> Result<[Byte<F>; 32], SynthesisError> {
    keccak256_var_with(buf, len, &mut DirectPermutation)
}

pub fn keccak256_var_with<F: PrimeField, B: PermutationBackend<F>>(
    buf: &[UInt8<F>],
    len: &FpVar<F>,
    backend: &mut B,
) -> Result<[Byte<F>; 32], SynthesisError> {
    let max = buf.len();
    let max_blocks = max / RATE + 1;
    let padded_len = max_blocks * RATE;

    // 1. sel[i] = [i < len], and nothing past len.
    let mut sel = prefix_mask_exact(len, max)?;
    assert_zero_outside(&to_fields(buf)?, &sel)?;
    sel.resize(padded_len, Boolean::FALSE);

    // 2. Padded message.
    let mut message = Vec::with_capacity(padded_len);
    for i in 0..padded_len {
        let mut byte: Byte<F> = match buf.get(i) {
            Some(b) => to_byte(b)?,
            None => core::array::from_fn(|_| Boolean::FALSE),
        };
        // The delimiter sits at the mask's falling edge.
        let is_delim = match i {
            0 => !sel[0].clone(),
            _ => sel[i - 1].clone() & !sel[i].clone(),
        };
        byte[0] = byte[0].clone() ^ is_delim;

        // The last byte of a block takes 0x80 when this is the first block end
        // at which the padding has started.
        if (i + 1) % RATE == 0 {
            let started = !sel[i].clone();
            let in_final_block = match i.checked_sub(RATE) {
                Some(prev) => started & sel[prev].clone(),
                None => started,
            };
            byte[7] = byte[7].clone() ^ in_final_block;
        }
        message.push(byte);
    }

    // 3. Absorb every block, retaining each digest.
    let mut st = empty_state::<F>();
    let mut digests = Vec::with_capacity(max_blocks);
    for b in 0..max_blocks {
        absorb_block(&mut st, &message[b * RATE..(b + 1) * RATE])?;
        st = backend.permute(st)?;
        digests.push(squeeze_256(&st));
    }

    // 4. Block b is final iff the padding started within it: sel is false at
    // its end and true at the previous block end (or b == 0).
    let mut chosen = digests[max_blocks - 1].clone();
    for b in (0..max_blocks - 1).rev() {
        let end = (b + 1) * RATE - 1;
        let started = !sel[end].clone();
        let is_final = if b == 0 {
            started
        } else {
            started & sel[b * RATE - 1].clone()
        };
        for (out, bits) in chosen.iter_mut().zip(digests[b].iter()) {
            for (o, bit) in out.iter_mut().zip(bits.iter()) {
                *o = is_final.select(bit, o)?;
            }
        }
    }

    Ok(chosen)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::GR1CSVar;
    use ark_relations::gr1cs::{ConstraintSystem, ConstraintSystemRef};

    fn alloc_bytes(cs: ConstraintSystemRef<Fr>, data: &[u8]) -> Vec<Byte<Fr>> {
        data.iter()
            .map(|&b| {
                core::array::from_fn(|bit| {
                    Boolean::new_witness(cs.clone(), || Ok((b >> bit) & 1 == 1)).unwrap()
                })
            })
            .collect()
    }

    fn read_digest(d: &[Byte<Fr>; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, byte) in d.iter().enumerate() {
            for (bit, b) in byte.iter().enumerate() {
                if b.value().unwrap() {
                    out[i] |= 1 << bit;
                }
            }
        }
        out
    }

    /// Every case checks against the native reference, never against itself.
    fn check(data: &[u8]) {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let input = alloc_bytes(cs.clone(), data);
        let digest = keccak256_fixed(&input).unwrap();
        assert_eq!(
            read_digest(&digest),
            mirage_encoding::keccak256(data),
            "digest mismatch for {} byte input",
            data.len()
        );
        assert!(
            cs.is_satisfied().unwrap(),
            "unsatisfied for len {}",
            data.len()
        );
    }

    #[test]
    fn empty_input() {
        check(b"");
    }

    #[test]
    fn short_input() {
        check(b"abc");
    }

    #[test]
    fn transfer_signature() {
        // The topic-0 preimage the relation actually needs.
        check(b"Transfer(address,address,uint256)");
    }

    #[test]
    fn block_boundaries() {
        // 135 puts delimiter and 0x80 in the same byte; 136 forces a second
        // block that is pure padding; 137 starts a real second block.
        for len in [134usize, 135, 136, 137, 271, 272, 273] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            check(&data);
        }
    }

    #[test]
    fn commitment_preimage_length() {
        check(&vec![0xab; mirage_encoding::commitment::PREIMAGE_LEN]);
    }

    #[test]
    fn statement_preimage_length() {
        check(&vec![0xcd; mirage_encoding::statement::PREIMAGE_LEN]);
    }

    /// Variable-length: hash `data` inside a `max`-byte buffer and check the
    /// digest against the native reference.
    fn check_var(data: &[u8], max: usize) {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let buf = crate::bytes::alloc_bounded(cs.clone(), data, max).unwrap();
        let len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(data.len() as u64))).unwrap();
        let digest = keccak256_var(&buf, &len).unwrap();
        assert_eq!(
            read_digest(&digest),
            mirage_encoding::keccak256(data),
            "digest mismatch: len {} in {} byte buffer",
            data.len(),
            max
        );
        assert!(
            cs.is_satisfied().unwrap(),
            "unsatisfied: len {} in {} byte buffer",
            data.len(),
            max
        );
    }

    #[test]
    fn var_matches_native_at_boundaries() {
        // The lengths where block selection or padding placement changes.
        // Cheap enough to run on every `cargo test`.
        let max = 2 * RATE;
        for len in [0usize, 1, 134, 135, 136, 137, 270, 271, 272] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            check_var(&data, max);
        }
    }

    /// Every length in a two-block buffer, exercising each block-selection
    /// branch and both padding placements.
    ///
    /// Ignored by default: ~11 minutes in debug, and a suite that slow gets
    /// skipped, which defeats the point. Run it after any change to the
    /// padding or state-selection logic:
    ///
    /// ```sh
    /// cargo test -p mirage-gadgets --release -- --ignored
    /// ```
    #[test]
    #[ignore = "exhaustive; run explicitly after touching padding or selection"]
    fn var_matches_native_across_every_length() {
        let max = 2 * RATE;
        for len in 0..=max {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            check_var(&data, max);
        }
    }

    #[test]
    fn var_matches_native_in_a_large_buffer() {
        // A short message in a wide buffer: the case the relation actually
        // hits, where most permutations are over padding.
        for len in [0usize, 1, 100, 135, 136, 137, 300] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            check_var(&data, 512);
        }
    }

    #[test]
    fn var_agrees_with_fixed() {
        // The two entry points must not disagree.
        let data: Vec<u8> = (0..200).map(|i| (i % 251) as u8).collect();

        let cs = ConstraintSystem::<Fr>::new_ref();
        let fixed_in = alloc_bytes(cs.clone(), &data);
        let fixed = read_digest(&keccak256_fixed(&fixed_in).unwrap());

        let cs2 = ConstraintSystem::<Fr>::new_ref();
        let buf = crate::bytes::alloc_bounded(cs2.clone(), &data, 512).unwrap();
        let len = FpVar::new_witness(cs2.clone(), || Ok(Fr::from(data.len() as u64))).unwrap();
        let var = read_digest(&keccak256_var(&buf, &len).unwrap());

        assert_eq!(fixed, var);
    }

    #[test]
    fn var_rejects_a_dirty_tail() {
        // A prover claims a short length but leaves nonzero bytes past it,
        // hoping they feed the sponge. assert_zero_tail must reject.
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut data = vec![0xaa; 8];
        data.resize(64, 0);
        data[20] = 0xff; // past the claimed length
        let buf = crate::bytes::alloc_bounded(cs.clone(), &data, 64).unwrap();
        let len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(8u64))).unwrap();
        let _ = keccak256_var(&buf, &len).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "dirty tail accepted");
    }

    #[test]
    fn var_cost() {
        for max in [256usize, 512] {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let buf = crate::bytes::alloc_bounded(cs.clone(), &[0u8; 8], max).unwrap();
            let len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(8u64))).unwrap();
            let before = cs.num_constraints();
            let _ = keccak256_var(&buf, &len).unwrap();
            let cost = cs.num_constraints() - before;
            let blocks = max / RATE + 1;
            println!("keccak_var over {max} bytes ({blocks} blocks): {cost} constraints");
        }
    }

    #[test]
    fn cost_per_block() {
        for (len, blocks) in [(100usize, 1usize), (200, 2), (400, 3)] {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let input = alloc_bytes(cs.clone(), &vec![0u8; len]);
            let before = cs.num_constraints();
            let _ = keccak256_fixed(&input).unwrap();
            let cost = cs.num_constraints() - before;
            println!(
                "{len} bytes ({blocks} blocks): {cost} constraints, {} per block",
                cost / blocks
            );
        }
    }
}
