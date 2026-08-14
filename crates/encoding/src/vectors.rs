//! Deterministic vector generation, spec section 19.1.
//!
//! Emits the fixtures in `test/vectors/` that the circuit gadgets, the nomad
//! client, and the Solidity contract are all checked against. This crate is the
//! reference: if a vector disagrees with an implementation, the implementation
//! is wrong.
//!
//! Every case carries the packed preimage alongside the digest, so a mismatch
//! identifies whether the disagreement is in the packing or the hash rather
//! than requiring a bisection.

use crate::commitment::Intent;
use crate::statement::Statement;
use crate::AssetKind;
use serde::Serialize;

#[derive(Serialize)]
pub struct VectorFile<I, E> {
    pub spec_section: &'static str,
    pub description: &'static str,
    pub cases: Vec<Case<I, E>>,
}

/// Input and expected are separate types: the input is the field set an
/// implementation packs, the expected is the preimage and digest it must
/// produce. Emitting both means a failure says whether the packing or the
/// hashing disagreed.
#[derive(Serialize)]
pub struct Case<I, E> {
    pub name: &'static str,
    pub description: &'static str,
    pub input: I,
    pub expected: E,
}

fn hx(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Deterministic filler so vectors are reproducible: byte `i` is `seed + i`.
fn fill<const N: usize>(seed: u8) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8);
    }
    out
}

fn amount(v: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..32].copy_from_slice(&v.to_be_bytes());
    out
}

/// The commitment cases spec 19.1 and 19.3 require.
pub fn intent_cases() -> Vec<(&'static str, &'static str, Intent)> {
    let base = Intent {
        instance_domain: fill(0x10),
        chain_id: 1,
        escrow: fill(0x20),
        request_id: fill(0x30),
        row_index: 0,
        asset_kind: AssetKind::Erc20,
        settlement_token: fill(0x40),
        recipient: fill(0x50),
        settlement_amount: amount(1),
        salt: fill(0x60),
    };

    vec![
        (
            "erc20_row_zero_amount_one",
            "Smallest valid ERC-20 row: index 0, amount 1",
            base.clone(),
        ),
        (
            "erc20_row_max_index",
            "Row index 31, the largest valid index in a 32-row batch",
            Intent { row_index: 31, ..base.clone() },
        ),
        (
            "native_row",
            "Native ETH settlement: asset kind 0, token must be exactly zero",
            Intent {
                asset_kind: AssetKind::Native,
                settlement_token: [0u8; 20],
                ..base.clone()
            },
        ),
        (
            "amount_at_limb_boundary",
            "settlementAmount = 2^128 exactly: hi limb 1, lo limb 0",
            Intent {
                settlement_amount: {
                    let mut a = [0u8; 32];
                    a[15] = 1;
                    a
                },
                ..base.clone()
            },
        ),
        (
            "amount_below_limb_boundary",
            "settlementAmount = 2^128 - 1: hi limb 0, lo limb max",
            Intent {
                settlement_amount: {
                    let mut a = [0u8; 32];
                    a[16..32].copy_from_slice(&[0xff; 16]);
                    a
                },
                ..base.clone()
            },
        ),
        (
            "amount_max",
            "settlementAmount = 2^256 - 1, both limbs saturated",
            Intent { settlement_amount: [0xff; 32], ..base.clone() },
        ),
        (
            "chain_id_large",
            "chainId near 2^64 - 1, the widest value the circuit accepts",
            Intent { chain_id: u64::MAX, ..base.clone() },
        ),
    ]
}

/// The statement cases spec 19.1 requires, including the attempt-1 vs
/// attempt-2 pair that must differ.
pub fn statement_cases(commitment: crate::Bytes32) -> Vec<(&'static str, &'static str, Statement)> {
    let base = Statement {
        instance_domain: fill(0x10),
        chain_id: 1,
        escrow: fill(0x20),
        request_id: fill(0x30),
        row_index: 0,
        intent_commitment: commitment,
        bond_attempt: 1,
        bond_start_block: 1_000,
        bond_deadline: 1_180,
        bonded_collector: fill(0x70),
        row_payout_asset: [0u8; 20],
        row_payout_amount: amount(1_000_000_000_000_000_000),
        witness_block_number: 1_100,
        witness_block_hash: fill(0x80),
    };

    vec![
        (
            "native_payout_attempt_one",
            "Native ETH payout, first bond attempt",
            base.clone(),
        ),
        (
            "native_payout_attempt_two",
            "Same row, second attempt: digest must differ from attempt one",
            Statement { bond_attempt: 2, ..base.clone() },
        ),
        (
            "erc20_payout",
            "ERC-20 payout asset, exercising the asset field",
            Statement { row_payout_asset: fill(0x90), ..base.clone() },
        ),
        (
            "block_numbers_wide",
            "Bond window and witness block near 2^64 - 1",
            Statement {
                bond_start_block: u64::MAX - 200,
                bond_deadline: u64::MAX - 20,
                witness_block_number: u64::MAX - 100,
                ..base.clone()
            },
        ),
    ]
}

#[derive(Serialize)]
pub struct StatementVector {
    pub input: StatementInput,
    pub expected: StatementExpected,
}

/// Field widths are the spec 10.2 packing, not Solidity's natural types.
/// `row_index` and `bond_attempt` pack as 4 bytes, the block numbers as 8, and
/// `chain_id` as a left-padded 32-byte word. A contract that packs any of these
/// at a different width produces a different digest.
#[derive(Serialize)]
pub struct StatementInput {
    pub relation_version: u8,
    pub instance_domain: String,
    pub chain_id: String,
    pub escrow: String,
    pub request_id: String,
    pub row_index: u32,
    pub intent_commitment: String,
    pub bond_attempt: u32,
    pub bond_start_block: String,
    pub bond_deadline: String,
    pub bonded_collector: String,
    pub row_payout_asset: String,
    pub row_payout_amount: String,
    pub witness_block_number: String,
    pub witness_block_hash: String,
}

#[derive(Serialize)]
pub struct StatementExpected {
    pub preimage: String,
    pub preimage_length: usize,
    pub statement_hash: String,
    /// The two Groth16 public signals, in the order the verifier takes them.
    pub signal_hi: String,
    pub signal_lo: String,
}

impl From<&Statement> for StatementVector {
    fn from(s: &Statement) -> Self {
        let hash = s.hash();
        let (hi, lo) = crate::split_limbs(&hash);
        StatementVector {
            input: StatementInput {
                relation_version: crate::RELATION_VERSION,
                instance_domain: hx(&s.instance_domain),
                chain_id: format!("0x{:x}", s.chain_id),
                escrow: hx(&s.escrow),
                request_id: hx(&s.request_id),
                row_index: s.row_index,
                intent_commitment: hx(&s.intent_commitment),
                bond_attempt: s.bond_attempt,
                bond_start_block: format!("0x{:x}", s.bond_start_block),
                bond_deadline: format!("0x{:x}", s.bond_deadline),
                bonded_collector: hx(&s.bonded_collector),
                row_payout_asset: hx(&s.row_payout_asset),
                row_payout_amount: hx(&s.row_payout_amount),
                witness_block_number: format!("0x{:x}", s.witness_block_number),
                witness_block_hash: hx(&s.witness_block_hash),
            },
            expected: StatementExpected {
                preimage: hx(&s.preimage()),
                preimage_length: crate::statement::PREIMAGE_LEN,
                statement_hash: hx(&hash),
                signal_hi: format!("0x{hi:032x}"),
                signal_lo: format!("0x{lo:032x}"),
            },
        }
    }
}

#[derive(Serialize)]
pub struct IntentVector {
    pub input: IntentInput,
    pub expected: IntentExpected,
}

#[derive(Serialize)]
pub struct IntentInput {
    pub relation_version: u8,
    pub instance_domain: String,
    pub chain_id: String,
    pub escrow: String,
    pub request_id: String,
    pub row_index: u32,
    pub asset_kind: u8,
    pub settlement_token: String,
    pub recipient: String,
    pub settlement_amount: String,
    pub salt: String,
}

#[derive(Serialize)]
pub struct IntentExpected {
    pub preimage: String,
    pub preimage_length: usize,
    pub commitment: String,
    pub commitment_hi: String,
    pub commitment_lo: String,
}

impl From<&Intent> for IntentVector {
    fn from(i: &Intent) -> Self {
        let commitment = i.commitment();
        let (hi, lo) = crate::split_limbs(&commitment);
        IntentVector {
            input: IntentInput {
                relation_version: crate::RELATION_VERSION,
                instance_domain: hx(&i.instance_domain),
                chain_id: format!("0x{:x}", i.chain_id),
                escrow: hx(&i.escrow),
                request_id: hx(&i.request_id),
                row_index: i.row_index,
                asset_kind: i.asset_kind as u8,
                settlement_token: hx(&i.settlement_token),
                recipient: hx(&i.recipient),
                settlement_amount: hx(&i.settlement_amount),
                salt: hx(&i.salt),
            },
            expected: IntentExpected {
                preimage: hx(&i.preimage()),
                preimage_length: crate::commitment::PREIMAGE_LEN,
                commitment: hx(&commitment),
                commitment_hi: format!("0x{hi:032x}"),
                commitment_lo: format!("0x{lo:032x}"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_intent_case_validates() {
        for (name, _, intent) in intent_cases() {
            assert!(intent.validate().is_ok(), "case {name} is itself invalid");
        }
    }

    #[test]
    fn intent_cases_have_distinct_commitments() {
        let cases = intent_cases();
        for (i, (na, _, a)) in cases.iter().enumerate() {
            for (nb, _, b) in cases.iter().skip(i + 1) {
                assert_ne!(a.commitment(), b.commitment(), "{na} collides with {nb}");
            }
        }
    }

    #[test]
    fn attempt_one_and_two_differ() {
        let cases = statement_cases([0x44; 32]);
        assert_ne!(cases[0].2.hash(), cases[1].2.hash());
    }
}
