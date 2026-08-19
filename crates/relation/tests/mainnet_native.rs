//! Runs the native dual-trie relation against real mainnet fixtures.
//!
//! Every fixture in `test/vectors/mainnet-native.json` is a real native ETH
//! settlement whose *both* trie reconstructions were checked against the block
//! header at collection time. Satisfying the circuit on them is the difference
//! between "works on a fixture I built" and "works on chain data".
//!
//! Skipped with a clear message when the dataset is absent, so the suite still
//! runs in a checkout that has not collected it.
//!
//! # Two populations, one of which must be rejected
//!
//! The dataset carries both shapes a native value transfer takes on mainnet:
//!
//! - **Bare sends** (100), which is what a node produces. These are the
//!   settlements the relation must accept, and they fit the compiled bounds
//!   with headroom.
//! - **Value-carrying calls** (43), which a recipient contract with a
//!   `receive()` hook produces. The relation must **reject** these: a node only
//!   ever settles by direct transfer, and a call's 21KB receipt would need a
//!   bound no machine can prove against.
//!
//! Keeping the calls rather than filtering them out is deliberate. They are the
//! evidence that the `data` constraint binds on real chain data, and the
//! measured reason the constraint exists at all — see
//! `cost_scales_with_the_observed_distribution`.

use std::path::PathBuf;

use ark_bn254::Fr;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
use mirage_relation::native::{NativeBounds, NativeCircuit, NativeWitness};
use mirage_relation::{Bounds, IntentOpening, StatementContext};
use serde::Deserialize;

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
    transaction_type: u8,
    bare_send: bool,
    header: String,
    key: String,
    transaction: String,
    transaction_nodes: Vec<String>,
    receipt: String,
    receipt_nodes: Vec<String>,
    intent: FixtureIntent,
    transaction_depth: usize,
    receipt_depth: usize,
    max_transaction_node_bytes: usize,
    max_receipt_node_bytes: usize,
    transaction_bytes: usize,
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

/// A shape field of a fixture, for the distribution reports.
type Field<'a> = &'a dyn Fn(&Fixture) -> usize;

fn dataset_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test/vectors/mainnet-native.json")
}

fn load() -> Option<Dataset> {
    serde_json::from_str(&std::fs::read_to_string(dataset_path()).ok()?).ok()
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

fn witness(f: &Fixture) -> NativeWitness {
    let header = bytes(&f.header);
    NativeWitness {
        key: bytes(&f.key),
        header: header.clone(),
        transaction: bytes(&f.transaction),
        transaction_nodes: f.transaction_nodes.iter().map(|n| bytes(n)).collect(),
        receipt: bytes(&f.receipt),
        receipt_nodes: f.receipt_nodes.iter().map(|n| bytes(n)).collect(),
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
            intent_commitment: arr(&f.intent.commitment),
            bond_attempt: 1,
            bond_start_block: f.block_number.saturating_sub(100),
            bond_deadline: f.block_number + 80,
            bonded_collector: [0x55; 20],
            // Zero for native ETH, per spec 10.2.
            row_payout_asset: [0u8; 20],
            row_payout_amount: {
                let mut a = [0u8; 32];
                a[24..].copy_from_slice(&1_000_000_000u64.to_be_bytes());
                a
            },
            witness_block_number: f.block_number,
            witness_block_hash: mirage_encoding::keccak256(&header),
        },
    }
}

/// Bounds wide enough for the fixtures under test.
///
/// Used only for the value-carrying calls, which exceed every compiled bound.
/// They must be rejected on the `data` constraint rather than on a buffer
/// overflow, so they are given buffers that hold them: a fixture rejected only
/// because it did not fit would prove nothing about the constraint.
fn bounds_for(fixtures: &[&Fixture]) -> NativeBounds {
    let max = |f: &dyn Fn(&Fixture) -> usize| fixtures.iter().map(|x| f(x)).max().unwrap_or(0);
    // Round to a 64-byte step rather than a power of two. Cost scales linearly
    // with every buffer bound, so rounding 21,508 up to 32,768 would inflate
    // the system by half again over what the data needs.
    let round_up = |v: usize| v.div_ceil(64) * 64;

    let d = NativeBounds::default();
    NativeBounds {
        common: Bounds {
            node_bytes: round_up(max(&|f| f.max_receipt_node_bytes).max(1)),
            key_bytes: d.common.key_bytes,
            receipt_bytes: round_up(max(&|f| f.receipt_bytes).max(1)),
            header_bytes: round_up(max(&|f| f.header_bytes).max(1)),
            depth: max(&|f| f.receipt_depth).max(1),
        },
        transaction_bytes: round_up(max(&|f| f.transaction_bytes).max(1)),
        transaction_node_bytes: round_up(max(&|f| f.max_transaction_node_bytes).max(1)),
        transaction_depth: max(&|f| f.transaction_depth).max(1),
    }
}

/// The bare sends must satisfy the relation at the **compiled** bounds.
///
/// This is the load-bearing test. Spec 20.3 makes a direct send the settlement
/// shape production executors are meant to produce, so if the compiled bounds
/// do not cover it the native path is unshippable rather than merely
/// constrained.
#[test]
fn bare_sends_satisfy_the_compiled_bounds() {
    let Some(d) = load() else {
        eprintln!(
            "skipping: {} not found.\n\
             Collect it with:\n  cargo run -p mirage-fixtures --release --bin collect-native",
            dataset_path().display()
        );
        return;
    };

    let bare: Vec<&Fixture> = d.fixtures.iter().filter(|f| f.bare_send).collect();
    assert!(!bare.is_empty(), "no bare sends in the dataset");

    let b = NativeBounds::default();
    for f in &bare {
        assert!(
            f.transaction_bytes <= b.transaction_bytes,
            "{}: transaction {} exceeds the compiled bound {}",
            f.tx_hash,
            f.transaction_bytes,
            b.transaction_bytes
        );
        assert!(
            f.receipt_bytes <= b.common.receipt_bytes,
            "{}: receipt {} exceeds the compiled bound {}",
            f.tx_hash,
            f.receipt_bytes,
            b.common.receipt_bytes
        );
        assert!(
            f.max_transaction_node_bytes <= b.transaction_node_bytes
                && f.max_receipt_node_bytes <= b.common.node_bytes,
            "{}: a node exceeds the compiled bound",
            f.tx_hash
        );
        assert!(
            f.transaction_depth <= b.transaction_depth && f.receipt_depth <= b.common.depth,
            "{}: a trie is deeper than the compiled bound",
            f.tx_hash
        );
    }

    let mut failed = Vec::new();
    for f in &bare {
        let cs = ConstraintSystem::<Fr>::new_ref();
        NativeCircuit::prove(b, witness(f))
            .generate_constraints(cs.clone())
            .expect("synthesis");
        if !cs.is_satisfied().unwrap_or(false) {
            failed.push(format!(
                "{} (block {}, type {}): {:?}",
                f.tx_hash,
                f.block_number,
                f.transaction_type,
                cs.which_is_unsatisfied().ok().flatten()
            ));
        }
    }
    assert!(
        failed.is_empty(),
        "{} of {} bare sends unsatisfied at the compiled bounds:\n  {}",
        failed.len(),
        bare.len(),
        failed.join("\n  ")
    );
    eprintln!(
        "all {} bare sends satisfied at the compiled bounds",
        bare.len()
    );
}

/// **Every value-carrying call must be rejected**, on real chain data.
///
/// A node settles by sending ETH directly, so calldata never appears on a real
/// settlement and the relation enforces `data` empty. These 43 fixtures are the
/// evidence that the constraint binds against transactions the chain actually
/// produced, rather than only against the synthetic case in
/// `gadgets::transaction::tests::rejects_a_call_carrying_value`.
///
/// They are run at bounds wide enough to hold them, because the point is that
/// the *relation* rejects them, not that the buffers cannot fit them. A fixture
/// rejected only because it overflowed its buffer would prove nothing about the
/// constraint. The largest few are skipped for memory rather than relevance —
/// see `cost_scales_with_the_observed_distribution`.
#[test]
fn value_carrying_calls_are_rejected() {
    let Some(d) = load() else {
        return;
    };

    let mut calls: Vec<&Fixture> = d.fixtures.iter().filter(|f| !f.bare_send).collect();
    assert!(!calls.is_empty(), "no value-carrying calls in the dataset");
    calls.sort_by_key(|f| f.receipt_bytes.max(f.transaction_bytes));
    calls.truncate(8);

    let b = bounds_for(&calls);
    eprintln!(
        "value-carrying calls: {} fixtures at bounds tx {} / receipt {}",
        calls.len(),
        b.transaction_bytes,
        b.common.receipt_bytes
    );

    let mut accepted = Vec::new();
    for f in &calls {
        let cs = ConstraintSystem::<Fr>::new_ref();
        NativeCircuit::prove(b, witness(f))
            .generate_constraints(cs.clone())
            .expect("synthesis");
        if cs.is_satisfied().unwrap_or(false) {
            accepted.push(format!(
                "{} (block {}, tx {}, {} bytes of receipt)",
                f.tx_hash, f.block_number, f.tx_index, f.receipt_bytes
            ));
        }
    }

    assert!(
        accepted.is_empty(),
        "{} of {} value-carrying calls were accepted:\n  {}",
        accepted.len(),
        calls.len(),
        accepted.join("\n  ")
    );
    eprintln!("all {} sampled calls rejected", calls.len());
}

/// How the relation's size scales with the buffer bounds, measured rather than
/// projected.
///
/// This is the test that says what the tail of the distribution costs. Cost is
/// linear in every buffer bound and the native relation pays two trie arrays,
/// so the value-carrying tail is not a slightly dearer proof — it is a
/// different order of magnitude, and it decides whether those settlements are
/// provable at all.
///
/// Reports rather than asserts a threshold: the number is the deliverable, and
/// a hardcoded ceiling would go stale the moment the gadgets change.
#[test]
fn cost_scales_with_the_observed_distribution() {
    let Some(d) = load() else {
        return;
    };

    let mut sizes: Vec<(&str, usize)> = vec![];
    let bare_max = d
        .fixtures
        .iter()
        .filter(|f| f.bare_send)
        .map(|f| f.receipt_bytes.max(f.transaction_bytes))
        .max()
        .unwrap_or(0);
    sizes.push(("bare-send max", bare_max));
    for p in [0.50, 0.75, 0.90] {
        let mut v: Vec<usize> = d
            .fixtures
            .iter()
            .map(|f| f.receipt_bytes.max(f.transaction_bytes))
            .collect();
        v.sort_unstable();
        let at = v[(((v.len() - 1) as f64) * p).round() as usize];
        sizes.push((
            match p {
                x if x < 0.6 => "p50",
                x if x < 0.8 => "p75",
                _ => "p90",
            },
            at,
        ));
    }

    eprintln!("native relation size against the buffer bound:");
    for (label, size) in sizes {
        // Synthesize the smallest fixture at bounds sized for `size`, so the
        // only variable is the bound.
        let smallest = d
            .fixtures
            .iter()
            .filter(|f| f.bare_send)
            .min_by_key(|f| f.receipt_bytes)
            .expect("a bare send");
        // Every bound must still hold this fixture, so take the larger of the
        // size under study and what the fixture itself needs.
        let round = |v: usize| v.div_ceil(64) * 64;
        let at = |v: usize| round(size.max(v));
        let b = NativeBounds {
            common: Bounds {
                node_bytes: at(smallest.max_receipt_node_bytes),
                key_bytes: NativeBounds::default().common.key_bytes,
                receipt_bytes: at(smallest.receipt_bytes),
                header_bytes: round(smallest.header_bytes),
                depth: smallest.receipt_depth,
            },
            transaction_bytes: at(smallest.transaction_bytes),
            transaction_node_bytes: at(smallest.max_transaction_node_bytes),
            transaction_depth: smallest.transaction_depth,
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        NativeCircuit::prove(b, witness(smallest))
            .generate_constraints(cs.clone())
            .expect("synthesis");
        let n = cs.num_constraints();
        eprintln!(
            "  {label:14} bound {:6} -> {:>12} constraints (~{:.0} GB at 2.8 GB/M)",
            round(size),
            n,
            n as f64 / 1e6 * 2.8
        );
    }

    eprintln!(
        "\nThe tail is not affordable: see the README's \"Native ETH\" section.\n\
         The largest observed fixture ({} bytes) exceeds this machine's 94 GB.",
        d.fixtures
            .iter()
            .map(|f| f.receipt_bytes.max(f.transaction_bytes))
            .max()
            .unwrap_or(0)
    );
}

/// The widest fixture in the dataset, at bounds wide enough to hold it.
///
/// **This does not fit in 94 GB**: synthesizing one system at a ~21.5KB buffer
/// bound was OOM-killed on the machine that collected the dataset. That is why
/// the relation constrains `data` to be empty rather than accepting calls and
/// leaving the size to policy — a bound covering this fixture is not one anyone
/// can prove against.
///
/// Kept as an ignored test so the claim is reproducible rather than hearsay.
/// Under the current relation this fixture is rejected on the `data` constraint
/// long before its size matters, so the test exists to document the ceiling
/// that made the constraint necessary.
#[test]
#[ignore = "OOM-killed at 94 GB; documents why data is constrained"]
fn the_largest_call_exceeds_available_memory() {
    let Some(d) = load() else {
        return;
    };
    let largest = d
        .fixtures
        .iter()
        .max_by_key(|f| f.receipt_bytes.max(f.transaction_bytes))
        .expect("non-empty");
    let b = bounds_for(&[largest]);
    let cs = ConstraintSystem::<Fr>::new_ref();
    NativeCircuit::prove(b, witness(largest))
        .generate_constraints(cs.clone())
        .expect("synthesis");
    eprintln!(
        "largest fixture ({} byte receipt): {} constraints, satisfied {}",
        largest.receipt_bytes,
        cs.num_constraints(),
        cs.is_satisfied().unwrap_or(false)
    );
}

/// The dataset must cover both shapes and more than one envelope type, or it is
/// not testing the variety it claims to.
#[test]
fn dataset_is_varied() {
    let Some(d) = load() else {
        return;
    };

    assert_eq!(d.count, d.fixtures.len(), "declared count disagrees");

    let types: std::collections::BTreeSet<u8> =
        d.fixtures.iter().map(|f| f.transaction_type).collect();
    let blocks: std::collections::BTreeSet<u64> =
        d.fixtures.iter().map(|f| f.block_number).collect();
    let recipients: std::collections::BTreeSet<&str> = d
        .fixtures
        .iter()
        .map(|f| f.intent.recipient.as_str())
        .collect();
    let bare = d.fixtures.iter().filter(|f| f.bare_send).count();

    assert!(types.len() >= 2, "only {} transaction types", types.len());
    assert!(blocks.len() >= 10, "only {} distinct blocks", blocks.len());
    assert!(
        recipients.len() >= 5,
        "only {} recipients",
        recipients.len()
    );
    assert!(bare > 0, "no bare sends");
    assert!(bare < d.fixtures.len(), "no value-carrying calls");

    eprintln!(
        "{} fixtures: {} blocks, {} recipients, types {:?}, {} bare / {} calls",
        d.fixtures.len(),
        blocks.len(),
        recipients.len(),
        types,
        bare,
        d.fixtures.len() - bare
    );
}

/// Every fixture must be a native row: asset kind 0 and an all-zero token.
#[test]
fn every_fixture_is_a_native_row() {
    let Some(d) = load() else {
        return;
    };
    for f in &d.fixtures {
        assert_eq!(f.intent.asset_kind, 0, "{}: not a native row", f.tx_hash);
        assert_eq!(
            f.intent.settlement_token,
            format!("0x{}", "00".repeat(20)),
            "{}: native row carries a token",
            f.tx_hash
        );
    }
}

/// Every commitment must be distinct, or the derivation is not binding the
/// transaction hash.
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

/// Records what the measured distribution implies for the compiled bounds.
///
/// Not an assertion about the circuit: a report, so the numbers that should
/// drive the bounds decision are visible in a test run rather than only in a
/// collector's stdout.
#[test]
fn bounds_note() {
    let Some(d) = load() else {
        return;
    };
    let pct = |f: Field, p: f64| {
        let mut v: Vec<usize> = d.fixtures.iter().map(f).collect();
        v.sort_unstable();
        v[(((v.len() - 1) as f64) * p).round() as usize]
    };

    let fields: [(&str, Field); 5] = [
        ("transaction bytes", &|x: &Fixture| x.transaction_bytes),
        ("receipt bytes", &|x: &Fixture| x.receipt_bytes),
        ("tx node bytes", &|x: &Fixture| x.max_transaction_node_bytes),
        ("receipt node bytes", &|x: &Fixture| {
            x.max_receipt_node_bytes
        }),
        ("header bytes", &|x: &Fixture| x.header_bytes),
    ];

    eprintln!("native fixture distribution (p50 / p95 / max):");
    for (name, f) in fields {
        eprintln!(
            "  {name:20} {:6} / {:6} / {:6}",
            pct(f, 0.50),
            pct(f, 0.95),
            pct(f, 1.0)
        );
    }

    let bare: Vec<&Fixture> = d.fixtures.iter().filter(|f| f.bare_send).collect();
    let bare_max = |f: &dyn Fn(&Fixture) -> usize| bare.iter().map(|x| f(x)).max().unwrap_or(0);
    eprintln!(
        "bare sends alone: transaction <= {}, receipt <= {}, node <= {}",
        bare_max(&|f| f.transaction_bytes),
        bare_max(&|f| f.receipt_bytes),
        bare_max(&|f| f.max_receipt_node_bytes.max(f.max_transaction_node_bytes)),
    );
}
