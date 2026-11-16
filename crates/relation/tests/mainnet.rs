//! Runs the relation against real mainnet fixtures.
//!
//! Every fixture in `test/vectors/mainnet.json` is a real ERC-20 Transfer whose
//! receipt-trie reconstruction was checked against the block header's
//! `receiptsRoot` at collection time. Satisfying the circuit on them is the
//! difference between "works on a fixture I built" and "works on chain data".
//!
//! Skipped with a clear message when the dataset is absent, so the suite still
//! runs in a checkout that has not collected it.

use std::path::PathBuf;

use ark_bn254::Fr;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
use mirage_relation::{
    fixture, Bounds, IntentOpening, KeccacheckReceiptCircuit, StatementContext, Witness,
};
use serde::Deserialize;

mod common;

#[derive(Deserialize)]
struct Dataset {
    count: usize,
    fixtures: Vec<Fixture>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct Fixture {
    tx_hash: String,
    block_number: u64,
    tx_index: usize,
    receipt_type: u8,
    header: String,
    receipts_root: String,
    key: String,
    receipt: String,
    nodes: Vec<String>,
    intent: FixtureIntent,
    depth: usize,
    max_node_bytes: usize,
    receipt_bytes: usize,
    header_bytes: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct FixtureIntent {
    instance_domain: String,
    chain_id: u64,
    escrow: String,
    request_id: String,
    row_index: u32,
    asset_kind: u8,
    settlement_token: String,
    recipient: String,
    settlement_amount: String,
    salt: String,
    commitment: String,
}

fn dataset_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test/vectors/mainnet.json")
}

fn load() -> Option<Dataset> {
    let path = dataset_path();
    let raw = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn bytes(s: &str) -> Vec<u8> {
    hex::decode(s.trim_start_matches("0x")).expect("fixture hex")
}

fn arr<const N: usize>(s: &str) -> [u8; N] {
    let v = bytes(s);
    assert_eq!(v.len(), N, "expected {N} bytes in {s}");
    let mut out = [0u8; N];
    out.copy_from_slice(&v);
    out
}

fn witness(f: &Fixture) -> Witness {
    // Synthetic descendants above the real transaction header stand in for
    // the later canonical witness block.
    let headers = fixture::descendants(bytes(&f.header), f.block_number, fixture::MIN_DISTANCE);
    Witness {
        root: bytes(&f.receipts_root),
        key: bytes(&f.key),
        receipt: bytes(&f.receipt),
        headers: headers.clone(),
        nodes: f.nodes.iter().map(|n| bytes(n)).collect(),
        log_index: 0,
        intent: IntentOpening {
            instance_domain: arr(&f.intent.instance_domain),
            chain_id: f.intent.chain_id,
            escrow: arr(&f.intent.escrow),
            request_id: arr(&f.intent.request_id),
            row_index: f.intent.row_index,
            asset_kind: f.intent.asset_kind,
            settlement_token: arr(&f.intent.settlement_token),
            recipient: arr(&f.intent.recipient),
            settlement_amount: arr(&f.intent.settlement_amount),
            salt: arr(&f.intent.salt),
        },
        statement: StatementContext {
            instance_domain: arr(&f.intent.instance_domain),
            chain_id: f.intent.chain_id,
            escrow: arr(&f.intent.escrow),
            request_id: arr(&f.intent.request_id),
            row_index: f.intent.row_index,
            // The escrow's stored commitment: what ties the opening to the
            // public signals.
            intent_commitment: arr(&f.intent.commitment),
            bond_attempt: 1,
            bond_start_block: f.block_number.saturating_sub(100),
            bond_deadline: f.block_number + 80,
            bonded_collector: [0x55; 20],
            row_payout_asset: [0u8; 20],
            row_payout_amount: {
                let mut a = [0u8; 32];
                a[24..].copy_from_slice(&1_000_000_000u64.to_be_bytes());
                a
            },
            witness_block_number: f.block_number + fixture::MIN_DISTANCE as u64,
            // The witness header's own keccak: the chain reaches the real
            // transaction header only through it.
            witness_block_hash: mirage_encoding::keccak256(&headers[0]),
        },
    }
}

/// Bounds wide enough for every observed fixture.
fn bounds(d: &Dataset) -> Bounds {
    let b = Bounds::default();
    let max = |f: &dyn Fn(&Fixture) -> usize| d.fixtures.iter().map(f).max().unwrap_or(0);
    assert!(
        max(&|f| f.depth) <= b.depth,
        "a fixture is deeper than the bound"
    );
    assert!(
        max(&|f| f.max_node_bytes) <= b.node_bytes,
        "a fixture node exceeds the bound"
    );
    assert!(
        max(&|f| f.receipt_bytes) <= b.receipt_bytes,
        "a fixture receipt exceeds the bound"
    );
    assert!(
        max(&|f| f.header_bytes) <= b.header_bytes,
        "a fixture header exceeds the bound: {} vs {}",
        max(&|f| f.header_bytes),
        b.header_bytes
    );
    b
}

/// The circuit must be satisfied by every real fixture.
///
/// Constraint synthesis only, not proving: a full proof per fixture would take
/// hours. Satisfaction is what correctness turns on; the proving cost is
/// measured separately by `mirage-prover`.
#[test]
fn satisfies_every_mainnet_fixture() {
    let Some(d) = load() else {
        eprintln!(
            "skipping: {} not found.\n\
             Collect it with:\n  cargo run -p mirage-fixtures --release --bin collect",
            dataset_path().display()
        );
        return;
    };

    assert_eq!(d.count, d.fixtures.len(), "declared count disagrees");
    assert!(!d.fixtures.is_empty(), "empty dataset");
    let b = bounds(&d);

    // The production circuit: every permutation goes through Keccacheck.
    let failed = common::run(
        &d.fixtures,
        |f| {
            format!(
                "{} (block {}, tx {}, type {}, depth {})",
                f.tx_hash, f.block_number, f.tx_index, f.receipt_type, f.depth
            )
        },
        |f| {
            let cs = ConstraintSystem::<Fr>::new_ref();
            KeccacheckReceiptCircuit::prove(b, witness(f))
                .generate_constraints(cs.clone())
                .expect("synthesis");
            cs.finalize();
            match cs.is_satisfied() {
                Ok(true) => Ok(()),
                _ => Err(format!("{:?}", cs.which_is_unsatisfied().ok().flatten())),
            }
        },
    );

    assert!(
        failed.is_empty(),
        "{} of {} mainnet fixtures unsatisfied:\n  {}",
        failed.len(),
        d.fixtures.len(),
        failed.join("\n  ")
    );
    eprintln!("all {} mainnet fixtures satisfied", d.fixtures.len());
}

/// Fast integration gate for the experimental batched-Keccak circuit. Use the
/// deepest collected proof so branch/extension chaining is exercised without
/// paying for 100 GKR satisfaction scans on every optimization iteration.
#[test]
fn keccacheck_satisfies_a_deep_mainnet_fixture() {
    let Some(d) = load() else {
        return;
    };
    let b = bounds(&d);
    let fixture = d
        .fixtures
        .iter()
        .max_by_key(|fixture| fixture.depth)
        .expect("nonempty fixture set");
    let cs = ConstraintSystem::<Fr>::new_ref();
    KeccacheckReceiptCircuit::prove(b, witness(fixture))
        .generate_constraints(cs.clone())
        .expect("synthesis");
    assert!(
        cs.is_satisfied().unwrap_or(false),
        "Keccacheck failed {} (block {}, tx {}, depth {}): {:?}",
        fixture.tx_hash,
        fixture.block_number,
        fixture.tx_index,
        fixture.depth,
        cs.which_is_unsatisfied().ok().flatten()
    );
}

/// The dataset must cover more than one shape, or it is not testing variety.
#[test]
fn dataset_is_varied() {
    let Some(d) = load() else {
        return;
    };

    let tokens: std::collections::BTreeSet<&str> = d
        .fixtures
        .iter()
        .map(|f| f.intent.settlement_token.as_str())
        .collect();
    let types: std::collections::BTreeSet<u8> = d.fixtures.iter().map(|f| f.receipt_type).collect();
    let blocks: std::collections::BTreeSet<u64> =
        d.fixtures.iter().map(|f| f.block_number).collect();

    assert!(tokens.len() >= 5, "only {} distinct tokens", tokens.len());
    assert!(types.len() >= 2, "only {} receipt types", types.len());
    assert!(blocks.len() >= 10, "only {} distinct blocks", blocks.len());

    eprintln!(
        "{} fixtures: {} tokens, {} blocks, receipt types {:?}",
        d.fixtures.len(),
        tokens.len(),
        blocks.len(),
        types
    );
}

/// Every commitment must be distinct: a repeat would mean the derivation is not
/// binding the transaction hash, and the dataset would be exercising far less
/// of the commitment gadget than it appears to.
#[test]
fn commitments_are_distinct() {
    let Some(d) = load() else {
        return;
    };
    let set: std::collections::BTreeSet<&str> = d
        .fixtures
        .iter()
        .map(|f| f.intent.commitment.as_str())
        .collect();
    assert_eq!(
        set.len(),
        d.fixtures.len(),
        "duplicate commitments in the dataset"
    );
}
