//! The statement hash and its two public signals, spec 10.2.
//!
//! The escrow builds this preimage itself from its own storage and call
//! context; the caller never supplies a public-input array. The circuit
//! receives every field privately, recomputes the hash, and exposes only the
//! two 128-bit limbs.
//!
//! # Why only two public signals
//!
//! Each public input costs a scalar multiplication in the on-chain verifier and
//! a G1 point in the embedded verification key. Hashing the full context down
//! to one `bytes32` and exposing its halves keeps the verifier at two
//! multiplications regardless of how many context fields the relation binds.
//!
//! It hides nothing: every field in the preimage is already public on-chain.
//!
//! # Why omitting a field is a soundness bug
//!
//! Spec 10.1 states it plainly. Each field in the preimage is what stops a
//! proof from being replayed in a different context — a different row, a later
//! bond attempt, another escrow, another chain. A field left out of the hash is
//! a dimension along which a valid proof becomes reusable.
//!
//! `mirage_encoding::statement` is the native reference this must agree with
//! byte for byte, and the deterministic vectors are the shared proof that it
//! does.

use ark_ff::PrimeField;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::gr1cs::SynthesisError;

use crate::bytes::pack_bytes_16;
use crate::keccak::keccak256_fixed;
use crate::keccak::sponge::to_bytes;

/// Byte width of the spec 10.2 preimage.
pub const PREIMAGE_LEN: usize = 285;

/// The public context a proof is bound to.
///
/// Field order and widths follow spec 10.2 exactly. Changing any of them is a
/// new circuit version under 18.4.
pub struct Context<F: PrimeField> {
    /// 32 bytes.
    pub instance_domain: Vec<UInt8<F>>,
    /// 32 bytes, left-padded chain ID.
    pub chain_id: Vec<UInt8<F>>,
    /// 20 bytes.
    pub escrow: Vec<UInt8<F>>,
    /// 32 bytes.
    pub request_id: Vec<UInt8<F>>,
    /// 4 bytes, big-endian.
    pub row_index: Vec<UInt8<F>>,
    /// 32 bytes.
    pub intent_commitment: Vec<UInt8<F>>,
    /// 4 bytes, big-endian.
    pub bond_attempt: Vec<UInt8<F>>,
    /// 8 bytes, big-endian.
    pub bond_start_block: Vec<UInt8<F>>,
    /// 8 bytes, big-endian.
    pub bond_deadline: Vec<UInt8<F>>,
    /// 20 bytes.
    pub bonded_collector: Vec<UInt8<F>>,
    /// 20 bytes, zero for native ETH.
    pub row_payout_asset: Vec<UInt8<F>>,
    /// 32 bytes.
    pub row_payout_amount: Vec<UInt8<F>>,
    /// 8 bytes, big-endian.
    pub witness_block_number: Vec<UInt8<F>>,
    /// 32 bytes.
    pub witness_block_hash: Vec<UInt8<F>>,
}

/// Protocol relation version, the preimage's leading byte.
pub const RELATION_VERSION: u8 = 2;

impl<F: PrimeField> Context<F> {
    /// The packed preimage, in spec 10.2 order.
    ///
    /// Widths are asserted rather than assumed: a field of the wrong length
    /// would silently shift everything after it, producing a hash that agrees
    /// with nothing.
    pub fn preimage(&self) -> Vec<UInt8<F>> {
        let parts: [(&Vec<UInt8<F>>, usize); 14] = [
            (&self.instance_domain, 32),
            (&self.chain_id, 32),
            (&self.escrow, 20),
            (&self.request_id, 32),
            (&self.row_index, 4),
            (&self.intent_commitment, 32),
            (&self.bond_attempt, 4),
            (&self.bond_start_block, 8),
            (&self.bond_deadline, 8),
            (&self.bonded_collector, 20),
            (&self.row_payout_asset, 20),
            (&self.row_payout_amount, 32),
            (&self.witness_block_number, 8),
            (&self.witness_block_hash, 32),
        ];

        let mut out = Vec::with_capacity(PREIMAGE_LEN);
        out.push(UInt8::constant(RELATION_VERSION));
        for (bytes, width) in parts {
            assert_eq!(bytes.len(), width, "statement field has the wrong width");
            out.extend_from_slice(bytes);
        }
        debug_assert_eq!(out.len(), PREIMAGE_LEN);
        out
    }
}

/// The two 128-bit limbs of the statement hash.
pub struct Signals<F: PrimeField> {
    pub hi: FpVar<F>,
    pub lo: FpVar<F>,
}

/// Computes the statement hash and returns its limbs.
///
/// The caller allocates these as public inputs; this gadget only produces the
/// values. Splitting it that way keeps the public-input decision in the
/// relation, where the spec 10.1 argument for exactly two signals lives.
pub fn compute<F: PrimeField>(ctx: &Context<F>) -> Result<Signals<F>, SynthesisError> {
    let preimage = ctx.preimage();
    let digest_bits = keccak256_fixed(&to_bytes(&preimage)?)?;

    // The digest as 32 bytes, then split into two 16-byte limbs. 16 bytes is
    // always below the BN254 modulus, so each packing is injective; 32 would
    // alias.
    let digest: Vec<UInt8<F>> = digest_bits
        .iter()
        .map(|b| UInt8::from_bits_le(b))
        .collect();

    Ok(Signals {
        hi: pack_bytes_16(&digest[..16])?,
        lo: pack_bytes_16(&digest[16..])?,
    })
}

/// Enforces that the computed signals equal the claimed public inputs.
pub fn enforce<F: PrimeField>(
    computed: &Signals<F>,
    public_hi: &FpVar<F>,
    public_lo: &FpVar<F>,
    active: &Boolean<F>,
) -> Result<(), SynthesisError> {
    computed.hi.conditional_enforce_equal(public_hi, active)?;
    computed.lo.conditional_enforce_equal(public_lo, active)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_r1cs_std::GR1CSVar;
    use ark_relations::gr1cs::ConstraintSystem;

    use crate::bytes::alloc_bounded;
    use mirage_encoding::statement::Statement;

    fn native_sample() -> Statement {
        Statement {
            instance_domain: [0x11; 32],
            chain_id: 1,
            escrow: [0x22; 20],
            request_id: [0x33; 32],
            row_index: 7,
            intent_commitment: [0x44; 32],
            bond_attempt: 3,
            bond_start_block: 1000,
            bond_deadline: 1180,
            bonded_collector: [0x55; 20],
            row_payout_asset: [0u8; 20],
            row_payout_amount: {
                let mut a = [0u8; 32];
                a[24..].copy_from_slice(&1_000_000_000u64.to_be_bytes());
                a
            },
            witness_block_number: 1100,
            witness_block_hash: [0x66; 32],
        }
    }

    fn alloc_ctx(cs: ark_relations::gr1cs::ConstraintSystemRef<Fr>, s: &Statement) -> Context<Fr> {
        let b = |v: &[u8], n: usize| alloc_bounded(cs.clone(), v, n).unwrap();
        Context {
            instance_domain: b(&s.instance_domain, 32),
            chain_id: b(&mirage_encoding::u64_to_word(s.chain_id), 32),
            escrow: b(&s.escrow, 20),
            request_id: b(&s.request_id, 32),
            row_index: b(&s.row_index.to_be_bytes(), 4),
            intent_commitment: b(&s.intent_commitment, 32),
            bond_attempt: b(&s.bond_attempt.to_be_bytes(), 4),
            bond_start_block: b(&s.bond_start_block.to_be_bytes(), 8),
            bond_deadline: b(&s.bond_deadline.to_be_bytes(), 8),
            bonded_collector: b(&s.bonded_collector, 20),
            row_payout_asset: b(&s.row_payout_asset, 20),
            row_payout_amount: b(&s.row_payout_amount, 32),
            witness_block_number: b(&s.witness_block_number.to_be_bytes(), 8),
            witness_block_hash: b(&s.witness_block_hash, 32),
        }
    }

    /// The circuit must agree with the native encoder byte for byte. This is
    /// the check that keeps the circuit, the client, and the Solidity contract
    /// interoperable.
    #[test]
    fn preimage_matches_the_native_encoder() {
        let s = native_sample();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let ctx = alloc_ctx(cs.clone(), &s);

        let got: Vec<u8> = ctx.preimage().iter().map(|b| b.value().unwrap()).collect();
        assert_eq!(got.len(), PREIMAGE_LEN);
        assert_eq!(got, s.preimage().to_vec(), "preimage bytes differ");
    }

    #[test]
    fn signals_match_the_native_hash() {
        let s = native_sample();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let ctx = alloc_ctx(cs.clone(), &s);
        let sig = compute(&ctx).unwrap();
        assert!(cs.is_satisfied().unwrap());

        let (hi, lo) = s.public_signals();
        assert_eq!(sig.hi.value().unwrap(), Fr::from(hi), "hi limb");
        assert_eq!(sig.lo.value().unwrap(), Fr::from(lo), "lo limb");
    }

    /// Spec 10.1: omitting any context field would be a critical soundness bug.
    /// Mutating each field in turn must change the digest.
    #[test]
    fn every_field_is_bound() {
        let base = native_sample();
        let base_hash = {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let ctx = alloc_ctx(cs.clone(), &base);
            compute(&ctx).unwrap().hi.value().unwrap()
        };

        let mutations: Vec<Statement> = vec![
            Statement { instance_domain: [0x12; 32], ..native_sample() },
            Statement { chain_id: 2, ..native_sample() },
            Statement { escrow: [0x23; 20], ..native_sample() },
            Statement { request_id: [0x34; 32], ..native_sample() },
            Statement { row_index: 8, ..native_sample() },
            Statement { intent_commitment: [0x45; 32], ..native_sample() },
            Statement { bond_attempt: 4, ..native_sample() },
            Statement { bond_start_block: 1001, ..native_sample() },
            Statement { bond_deadline: 1181, ..native_sample() },
            Statement { bonded_collector: [0x56; 20], ..native_sample() },
            Statement { row_payout_asset: [0x01; 20], ..native_sample() },
            Statement { row_payout_amount: [0x01; 32], ..native_sample() },
            Statement { witness_block_number: 1101, ..native_sample() },
            Statement { witness_block_hash: [0x67; 32], ..native_sample() },
        ];
        assert_eq!(mutations.len(), 14, "one case per context field");

        for (i, m) in mutations.iter().enumerate() {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let ctx = alloc_ctx(cs.clone(), m);
            let h = compute(&ctx).unwrap().hi.value().unwrap();
            assert_ne!(h, base_hash, "field {i} does not affect the digest");
        }
    }

    #[test]
    fn cost() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let ctx = alloc_ctx(cs.clone(), &native_sample());
        let before = cs.num_constraints();
        let _ = compute(&ctx).unwrap();
        println!(
            "statement hash ({PREIMAGE_LEN} byte preimage): {} constraints",
            cs.num_constraints() - before
        );
    }
}
