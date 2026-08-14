//! Statement hash, spec section 10.2.
//!
//! ```text
//! statementHash = keccak256(abi.encodePacked(
//!     uint8(2),
//!     instanceDomain,           // 32 bytes
//!     uint256(chainId),         // 32 bytes, left-padded
//!     address(this),            // 20 bytes
//!     requestId,                // 32 bytes
//!     uint32(rowIndex),         // 4 bytes
//!     intentCommitment,         // 32 bytes
//!     uint32(bondAttempt),      // 4 bytes
//!     uint64(bondStartBlock),   // 8 bytes
//!     uint64(bondDeadline),     // 8 bytes
//!     bondedCollector,          // 20 bytes
//!     rowPayoutAsset,           // 20 bytes, zero for native ETH
//!     uint256(rowPayoutAmount), // 32 bytes
//!     uint64(witnessBlockNumber), // 8 bytes
//!     witnessBlockHash          // 32 bytes
//! ))
//! ```
//!
//! Total: 1 + 32 + 32 + 20 + 32 + 4 + 32 + 4 + 8 + 8 + 20 + 20 + 32 + 8 + 32 = 285 bytes.
//!
//! The escrow builds this itself from its own storage and call context; the
//! caller never supplies a public-input array. The circuit receives every field
//! privately, range-constrains it, recomputes this hash, and exposes only the
//! two 128-bit limbs.
//!
//! Spec 10.1: omitting any context field would be a critical soundness bug.

use crate::{keccak256, split_limbs, Address, Bytes32, RELATION_VERSION};

pub const PREIMAGE_LEN: usize = 285;

#[derive(Debug, Clone)]
pub struct Statement {
    pub instance_domain: Bytes32,
    pub chain_id: u64,
    pub escrow: Address,
    pub request_id: Bytes32,
    pub row_index: u32,
    pub intent_commitment: Bytes32,
    /// Retained from v1.1 as a replay tag. It no longer feeds a key derivation,
    /// but keeping it here means a proof produced under one lease attempt
    /// cannot be presented under a later attempt of the same row.
    pub bond_attempt: u32,
    pub bond_start_block: u64,
    pub bond_deadline: u64,
    pub bonded_collector: Address,
    /// Zero address for native ETH. Bound alongside the amount: binding the
    /// amount alone would leave a proof valid against a row whose amount
    /// matched but whose asset differed.
    pub row_payout_asset: Address,
    pub row_payout_amount: Bytes32,
    pub witness_block_number: u64,
    pub witness_block_hash: Bytes32,
}

impl Statement {
    pub fn preimage(&self) -> [u8; PREIMAGE_LEN] {
        let mut out = [0u8; PREIMAGE_LEN];
        let mut i = 0;

        let mut put = |src: &[u8], i: &mut usize| {
            out[*i..*i + src.len()].copy_from_slice(src);
            *i += src.len();
        };

        put(&[RELATION_VERSION], &mut i);
        put(&self.instance_domain, &mut i);
        put(&crate::u64_to_word(self.chain_id), &mut i);
        put(&self.escrow, &mut i);
        put(&self.request_id, &mut i);
        put(&self.row_index.to_be_bytes(), &mut i);
        put(&self.intent_commitment, &mut i);
        put(&self.bond_attempt.to_be_bytes(), &mut i);
        put(&self.bond_start_block.to_be_bytes(), &mut i);
        put(&self.bond_deadline.to_be_bytes(), &mut i);
        put(&self.bonded_collector, &mut i);
        put(&self.row_payout_asset, &mut i);
        put(&self.row_payout_amount, &mut i);
        put(&self.witness_block_number.to_be_bytes(), &mut i);
        put(&self.witness_block_hash, &mut i);

        debug_assert_eq!(i, PREIMAGE_LEN);
        out
    }

    pub fn hash(&self) -> Bytes32 {
        keccak256(&self.preimage())
    }

    /// The two public Groth16 signals: the high and low 128-bit limbs of the
    /// statement hash.
    ///
    /// Spec 10.1: hashing the full public context down to two signals shrinks
    /// the embedded verification key and removes two scalar multiplications per
    /// row from the on-chain trace. It hides nothing — every field is already
    /// public on-chain.
    pub fn public_signals(&self) -> (u128, u128) {
        split_limbs(&self.hash())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Statement {
        Statement {
            instance_domain: [0x11; 32],
            chain_id: 1,
            escrow: [0x22; 20],
            request_id: [0x33; 32],
            row_index: 0,
            intent_commitment: [0x44; 32],
            bond_attempt: 1,
            bond_start_block: 1000,
            bond_deadline: 1180,
            bonded_collector: [0x55; 20],
            row_payout_asset: [0u8; 20],
            row_payout_amount: {
                let mut a = [0u8; 32];
                a[31] = 100;
                a
            },
            witness_block_number: 1100,
            witness_block_hash: [0x66; 32],
        }
    }

    #[test]
    fn preimage_length_is_fixed() {
        assert_eq!(sample().preimage().len(), PREIMAGE_LEN);
    }

    #[test]
    fn signals_reconstruct_the_hash() {
        let s = sample();
        let (hi, lo) = s.public_signals();
        assert_eq!(crate::join_limbs(hi, lo), s.hash());
    }

    #[test]
    fn bond_attempt_changes_the_hash() {
        // The replay-tag property: a proof for attempt 1 must not verify under
        // attempt 2 of the same row.
        let a = sample();
        let mut b = sample();
        b.bond_attempt = 2;
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn payout_asset_changes_the_hash() {
        let a = sample();
        let mut b = sample();
        b.row_payout_asset = [0x77; 20];
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn collector_changes_the_hash() {
        let a = sample();
        let mut b = sample();
        b.bonded_collector = [0x56; 20];
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn witness_block_changes_the_hash() {
        let a = sample();
        let mut b = sample();
        b.witness_block_hash = [0x67; 32];
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn every_field_is_bound() {
        // Spec 10.1: omitting any context field is a critical soundness bug.
        // Mutating each field in turn must change the digest. If a field is
        // ever dropped from `preimage()`, this catches it.
        let base = sample().hash();
        let mutations: Vec<Statement> = vec![
            Statement { instance_domain: [0x12; 32], ..sample() },
            Statement { chain_id: 2, ..sample() },
            Statement { escrow: [0x23; 20], ..sample() },
            Statement { request_id: [0x34; 32], ..sample() },
            Statement { row_index: 1, ..sample() },
            Statement { intent_commitment: [0x45; 32], ..sample() },
            Statement { bond_attempt: 2, ..sample() },
            Statement { bond_start_block: 1001, ..sample() },
            Statement { bond_deadline: 1181, ..sample() },
            Statement { bonded_collector: [0x56; 20], ..sample() },
            Statement { row_payout_asset: [0x01; 20], ..sample() },
            Statement { row_payout_amount: [0x01; 32], ..sample() },
            Statement { witness_block_number: 1101, ..sample() },
            Statement { witness_block_hash: [0x67; 32], ..sample() },
        ];
        assert_eq!(mutations.len(), 14, "one case per context field");
        for (i, m) in mutations.iter().enumerate() {
            assert_ne!(m.hash(), base, "field {i} does not affect the digest");
        }
    }
}
