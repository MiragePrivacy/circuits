//! Positive delayed-witness ancestry, spec 12.7.
//!
//! One header array: `H[0]` is the witness header the statement names, and
//! `H[d]` is the hidden transaction header. Every link satisfies
//!
//! ```text
//! parentHash(H[i]) == keccak256(H[i + 1])
//! ```
//!
//! The escrow authenticates `H[0]` with `blockhash`, so each ancestor is fixed
//! by a hash its already-authenticated child carries. Fabricating one means
//! finding a Keccak preimage. The reverse direction does not hold, which is why
//! the distance is strictly positive: an earlier block cannot authenticate
//! arbitrary descendants.
//!
//! Authenticated headers are consensus headers, so each link also steps the
//! block number by exactly one. Only the endpoint's number is read, and it
//! must equal `witnessBlockNumber - d`; the intermediate numbers follow.
//!
//! # Fixed shape
//!
//! `d` is private. The chain `H[0..d]` occupies `MAX` slots, the first
//! `min_distance` always active and the active slots a prefix; `H[d]` has its
//! own slot. Every slot is hashed whether or not it is active, so neither the
//! constraint count nor the permutation count depends on `d`.
//!
//! # Cost
//!
//! Each header is an [`AbsorbedMessage`] of exactly `header_bytes / RATE + 1`
//! blocks, so a header must be at least `(header_bytes / RATE) * RATE` bytes.
//! A chain slot materializes only `parentHash`, which lies in the first block
//! and is free; only the transaction header's parsed fields cost XORs. Hashes
//! are compared as two packed 128-bit halves.

use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};

use crate::bytes::{byte_to_field, pack_bytes_16};
use crate::header::{self, AUTHENTICATED_PREFIX_READS};
use crate::keccak::sponge::AbsorbedMessage;
use crate::keccak::{PermutationBackend, RATE};

/// The compiled shape of the chain.
#[derive(Clone, Copy, Debug)]
pub struct Bounds {
    /// Longest header. Headers hash in `header_bytes / RATE + 1` blocks.
    pub header_bytes: usize,
    pub min_distance: usize,
    pub max_distance: usize,
}

impl Bounds {
    /// Header lengths this shape can hash.
    pub fn header_range(&self) -> core::ops::RangeInclusive<usize> {
        (self.header_bytes / RATE) * RATE..=self.header_bytes
    }

    fn blocks(&self) -> usize {
        self.header_bytes / RATE + 1
    }
}

/// The fields the relation reads from the hidden transaction header `H[d]`.
pub struct Endpoint<F: PrimeField> {
    pub transactions_root: Vec<UInt8<F>>,
    pub receipts_root: Vec<UInt8<F>>,
    pub number: FpVar<F>,
}

/// Verifies the witness-first header chain `headers = [H[0], ..., H[d]]` and
/// returns its endpoint.
///
/// `witness_hash` and `witness_number` are the statement's `witnessBlockHash`
/// and `witnessBlockNumber`. A chain outside the bounds leaves the system
/// unsatisfied; callers check it first.
pub fn verify_with<F: PrimeField, B: PermutationBackend<F>>(
    cs: ConstraintSystemRef<F>,
    headers: &[Vec<u8>],
    bounds: &Bounds,
    witness_hash: &[UInt8<F>],
    witness_number: &FpVar<F>,
    backend: &mut B,
) -> Result<Endpoint<F>, SynthesisError> {
    let d = headers.len().saturating_sub(1);
    let chain = Chain {
        links: headers[..d].iter().map(Vec::as_slice).collect(),
        active: (0..bounds.max_distance).map(|i| i < d).collect(),
        tx: headers.last().map_or(&[][..], Vec::as_slice),
    };
    verify_chain(cs, &chain, bounds, witness_hash, witness_number, backend)
}

/// A chain witness: the headers before `H[d]`, each slot's selector, and
/// `H[d]`.
struct Chain<'a> {
    links: Vec<&'a [u8]>,
    active: Vec<bool>,
    tx: &'a [u8],
}

fn verify_chain<F: PrimeField, B: PermutationBackend<F>>(
    cs: ConstraintSystemRef<F>,
    w: &Chain,
    bounds: &Bounds,
    witness_hash: &[UInt8<F>],
    witness_number: &FpVar<F>,
    backend: &mut B,
) -> Result<Endpoint<F>, SynthesisError> {
    let (min, max) = (bounds.min_distance, bounds.max_distance);
    assert!(min >= 1, "the witness must strictly follow the transaction block");
    assert!(min <= max, "no slot for the minimum distance");
    assert_eq!(witness_hash.len(), 32);

    // An inactive slot hashes a blank header of the shortest length.
    let blank = vec![0u8; *bounds.header_range().start()];
    let mut parents = Vec::with_capacity(max);
    let mut digests = Vec::with_capacity(max);
    let mut active = Vec::with_capacity(max);
    for i in 0..max {
        let slot = AbsorbedMessage::new(
            cs.clone(),
            w.links.get(i).copied().unwrap_or(&blank),
            bounds.blocks(),
            backend,
        )?;
        active.push(if i < min {
            Boolean::TRUE
        } else {
            Boolean::new_witness(cs.clone(), || Ok(w.active[i]))?
        });
        // A two-byte long list whose first item is a 32-byte string, so
        // `parentHash` sits at bytes 4..36.
        for (at, want) in [(0, 0xf9u64), (3, 0xa0)] {
            byte_to_field(&slot.byte(at))?
                .conditional_enforce_equal(&FpVar::constant(F::from(want)), &active[i])?;
        }
        parents.push(halves(&(4..36).map(|k| slot.byte(k)).collect::<Vec<_>>())?);
        digests.push(halves(&digest_bytes(&slot))?);
    }
    let tx = AbsorbedMessage::new(cs.clone(), w.tx, bounds.blocks(), backend)?;
    let tx_digest = halves(&digest_bytes(&tx))?;

    // H[0] is the exact block the statement names.
    for (got, want) in digests[0].iter().zip(&halves(witness_hash)?) {
        got.enforce_equal(want)?;
    }

    for i in 1..max {
        // Each active ancestor is the parent of the slot before it.
        for (digest, parent) in digests[i].iter().zip(&parents[i - 1]) {
            digest.conditional_enforce_equal(parent, &active[i])?;
        }
        // Active slots form a prefix.
        if i > min {
            active[i - 1].conditional_enforce_equal(&Boolean::TRUE, &active[i])?;
        }
    }

    // H[d] is the parent of the last active slot. On a prefix,
    // `active[i] - active[i + 1]` is one exactly there.
    for i in min - 1..max {
        let next = active.get(i + 1).map_or(FpVar::zero(), |a| FpVar::from(a.clone()));
        let last = FpVar::from(active[i].clone()) - next;
        for (digest, parent) in tx_digest.iter().zip(&parents[i]) {
            (digest - parent).mul_equals(&last, &FpVar::zero())?;
        }
    }

    // Only the bytes the prefix parser reads are materialized.
    let view = (0..AUTHENTICATED_PREFIX_READS[1].end)
        .map(|i| {
            if AUTHENTICATED_PREFIX_READS.iter().any(|r| r.contains(&i)) {
                tx.byte(i)
            } else {
                UInt8::constant(0)
            }
        })
        .collect::<Vec<_>>();
    let parsed = header::parse_authenticated_prefix(&view, &FpVar::zero(), &Boolean::TRUE)?;

    let distance: FpVar<F> = active.iter().map(|a| FpVar::from(a.clone())).sum();
    (&parsed.number + distance).enforce_equal(witness_number)?;

    Ok(Endpoint {
        transactions_root: parsed.transactions_root,
        receipts_root: parsed.receipts_root,
        number: parsed.number,
    })
}

fn digest_bytes<F: PrimeField>(hash: &AbsorbedMessage<F>) -> Vec<UInt8<F>> {
    hash.digest.iter().map(|b| UInt8::from_bits_le(b)).collect()
}

/// A 32-byte hash as two 128-bit field elements. Emits no constraints.
fn halves<F: PrimeField>(bytes: &[UInt8<F>]) -> Result<[FpVar<F>; 2], SynthesisError> {
    Ok([pack_bytes_16(&bytes[..16])?, pack_bytes_16(&bytes[16..])?])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_r1cs_std::GR1CSVar;
    use ark_relations::gr1cs::ConstraintSystem;

    use crate::bytes::alloc_bounded;
    use crate::header::tests::header_with_parent;
    use crate::keccak::DirectPermutation;

    const TX_NUMBER: u64 = 21_000_000;
    const TX_ROOT: [u8; 32] = [0xab; 32];

    fn bounds(min: usize, max: usize) -> Bounds {
        Bounds {
            header_bytes: 679,
            min_distance: min,
            max_distance: max,
        }
    }

    fn keccak(b: &[u8]) -> [u8; 32] {
        mirage_encoding::keccak256(b)
    }

    /// `[H[0], ..., H[d]]` over a transaction header at `TX_NUMBER`.
    fn chain(distance: usize) -> Vec<Vec<u8>> {
        let mut out = vec![header_with_parent(&[0x01; 32], &TX_ROOT, TX_NUMBER)];
        for k in 1..=distance as u64 {
            let parent = keccak(&out[0]);
            out.insert(0, header_with_parent(&parent, &[0xcd; 32], TX_NUMBER + k));
        }
        out
    }

    struct Case {
        headers: Vec<Vec<u8>>,
        /// Overrides the length-derived selectors.
        active: Option<Vec<bool>>,
        witness_hash: [u8; 32],
        witness_number: u64,
    }

    impl Case {
        fn genuine(distance: usize) -> Self {
            let headers = chain(distance);
            Self {
                witness_hash: keccak(&headers[0]),
                witness_number: TX_NUMBER + distance as u64,
                headers,
                active: None,
            }
        }
    }

    fn run(case: &Case, min: usize, max: usize) -> (bool, Endpoint<Fr>) {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let hash = alloc_bounded(cs.clone(), &case.witness_hash, 32).unwrap();
        let number = FpVar::new_witness(cs.clone(), || Ok(Fr::from(case.witness_number))).unwrap();
        let d = case.headers.len() - 1;
        let chain = Chain {
            links: case.headers[..d].iter().map(Vec::as_slice).collect(),
            active: case.active.clone().unwrap_or_else(|| (0..max).map(|i| i < d).collect()),
            tx: &case.headers[d],
        };
        let end = verify_chain(
            cs.clone(),
            &chain,
            &bounds(min, max),
            &hash,
            &number,
            &mut DirectPermutation,
        )
        .unwrap();
        (cs.is_satisfied().unwrap(), end)
    }

    fn accepted(case: &Case, min: usize, max: usize) -> bool {
        run(case, min, max).0
    }

    #[test]
    fn accepts_the_minimum_and_maximum_distance() {
        for d in [1, 2] {
            let (ok, end) = run(&Case::genuine(d), 1, 2);
            assert!(ok, "rejected a genuine chain at distance {d}");
            let root: Vec<u8> = end.receipts_root.iter().map(|b| b.value().unwrap()).collect();
            assert_eq!(root, TX_ROOT, "endpoint is not H[{d}]");
            assert_eq!(end.number.value().unwrap(), Fr::from(TX_NUMBER));
        }
    }

    /// **Forgery: the transaction block is its own witness.**
    #[test]
    fn rejects_a_zero_distance() {
        assert!(!accepted(&Case::genuine(0), 1, 2), "accepted d = 0");
    }

    #[test]
    fn rejects_a_distance_below_the_minimum() {
        assert!(!accepted(&Case::genuine(1), 2, 3), "accepted d < min");
    }

    #[test]
    fn rejects_the_wrong_witness() {
        let mut case = Case::genuine(1);
        case.witness_hash[0] ^= 1;
        assert!(!accepted(&case, 1, 2), "accepted a foreign witness hash");

        let mut case = Case::genuine(1);
        case.witness_number += 1;
        assert!(!accepted(&case, 1, 2), "accepted a foreign witness number");
    }

    /// **Forgery: an ancestor that is not the parent of its child.**
    #[test]
    fn rejects_a_broken_parent_link() {
        let mut case = Case::genuine(2);
        case.headers[2] = header_with_parent(&[0x01; 32], &[0xee; 32], TX_NUMBER);
        assert!(!accepted(&case, 1, 2), "accepted an unlinked transaction header");

        let mut case = Case::genuine(3);
        case.headers[1] = header_with_parent(&keccak(&case.headers[2]), &[0xee; 32], TX_NUMBER + 2);
        assert!(!accepted(&case, 1, 3), "accepted an unlinked intermediate header");
    }

    /// **Forgery: hash-linked headers whose numbers skip a block.**
    #[test]
    fn rejects_an_off_by_one_number() {
        let tx = header_with_parent(&[0x01; 32], &TX_ROOT, TX_NUMBER - 1);
        let witness = header_with_parent(&keccak(&tx), &[0xcd; 32], TX_NUMBER + 1);
        let case = Case {
            witness_hash: keccak(&witness),
            witness_number: TX_NUMBER + 1,
            headers: vec![witness, tx],
            active: None,
        };
        assert!(!accepted(&case, 1, 2), "accepted a two-block gap as one link");
    }

    /// A selector claiming fewer links than supplied must not let a later
    /// header stand in for `H[d]`.
    #[test]
    fn rejects_a_short_selector() {
        let mut case = Case::genuine(2);
        case.active = Some(vec![true, false]);
        assert!(!accepted(&case, 1, 2), "accepted H[2] as the parent of H[0]");
    }

    /// Active slots must be a prefix, or a link would be skipped.
    #[test]
    fn rejects_a_gap_in_the_active_slots() {
        let mut case = Case::genuine(3);
        case.active = Some(vec![true, false, true]);
        assert!(!accepted(&case, 1, 3), "accepted a non-prefix selector");
    }

    /// The fixed block count makes a short header unprovable rather than
    /// hashed in fewer blocks.
    #[test]
    fn rejects_a_header_short_of_the_final_block() {
        let mut case = Case::genuine(1);
        case.headers[1].truncate(543);
        case.headers[0] = header_with_parent(&keccak(&case.headers[1]), &[0xcd; 32], TX_NUMBER + 1);
        case.witness_hash = keccak(&case.headers[0]);
        assert!(!accepted(&case, 1, 2), "accepted a 543-byte header");
    }
}
