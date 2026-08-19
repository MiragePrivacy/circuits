//! The library proving path produces what the escrow expects.

use mirage_prover::{check_bounds, prove_seeded, setup, Keys, SettlementError};
use mirage_relation::{fixture, Bounds};
use std::sync::OnceLock;

/// One setup for the whole binary.
///
/// Setup costs ~33s and ~8.7 GiB. Run per test and in parallel it exhausts
/// memory before any assertion is reached, so every test shares this key.
fn keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| setup(Bounds::default(), 0).expect("setup"))
}

#[test]
fn proves_and_self_checks_a_genuine_settlement() {
    let bounds = Bounds::default();
    let keys = keys();
    let settlement = prove_seeded(keys, bounds, &fixture::genuine(), 0).expect("prove");

    // The signals must be the ones the native encoder derives, since that is
    // what the escrow recomputes from its own storage.
    let (hi, lo) = mirage_relation::public_signals(&fixture::genuine());
    assert_eq!(settlement.signals, [hi, lo], "signals disagree with the encoder");

    // Every coordinate is a field element, so none may be all-zero: a zero
    // point would mean the conversion dropped a coordinate.
    for (i, p) in settlement.proof.iter().enumerate() {
        assert!(p.iter().any(|&b| b != 0), "proof element {i} is zero");
    }
}

#[test]
fn rejects_a_witness_past_a_bound() {
    let bounds = Bounds::default();
    let mut w = fixture::genuine();
    w.receipt = vec![0u8; bounds.receipt_bytes + 1];

    match check_bounds(bounds, &w) {
        Err(SettlementError::Bounds(msg)) => {
            assert!(msg.contains("receipt"), "unhelpful message: {msg}")
        }
        other => panic!("expected a bounds error, got {other:?}"),
    }
}

#[test]
fn accepts_a_witness_within_every_bound() {
    check_bounds(Bounds::default(), &fixture::genuine()).expect("the fixture must fit");
}

/// A key must survive the round trip the ceremony's output takes to a node.
#[test]
fn a_serialized_proving_key_round_trips() {
    use ark_serialize::CanonicalSerialize;

    let keys = keys();

    let mut bytes = Vec::new();
    keys.pk.serialize_compressed(&mut bytes).expect("serialize");
    let loaded = mirage_prover::load_proving_key(&bytes, true).expect("load");

    assert_eq!(
        mirage_prover::verifying_key_constants(&mirage_prover::verifying_key_of(&loaded)),
        mirage_prover::verifying_key_constants(&keys.vk),
        "a round-tripped key must imply the same verifying key"
    );
}

/// Reading a compressed key as uncompressed must fail rather than yield a key
/// that produces rejected proofs.
#[test]
fn a_mismatched_encoding_is_rejected() {
    use ark_serialize::CanonicalSerialize;

    let keys = keys();
    let mut bytes = Vec::new();
    keys.pk.serialize_compressed(&mut bytes).expect("serialize");

    assert!(
        mirage_prover::load_proving_key(&bytes, false).is_err(),
        "a compressed key read as uncompressed must not load"
    );
}

/// The constants must be the ones the exported verifier compiles in.
///
/// This is the check a node runs against a deployed escrow: if the derived
/// constants and the contract's disagree, the key and the verifier came from
/// different setups and every proof would be rejected.
#[test]
fn verifying_key_constants_have_the_verifier_shape() {
    let keys = keys();
    let c = mirage_prover::verifying_key_constants(&keys.vk);

    assert_eq!(
        c.ic.len(),
        3,
        "two public signals plus the constant term, matching PUB_0/PUB_1/CONSTANT"
    );
    for (i, p) in c.ic.iter().enumerate() {
        assert!(
            p[0].iter().any(|&b| b != 0) || p[1].iter().any(|&b| b != 0),
            "IC point {i} is the origin"
        );
    }
}

/// The derived constants must be the ones the exported verifier compiles in.
///
/// The seeded setup is reproducible, so `contracts/Verifier.sol` is the exact
/// artifact this key produces. Parsing it back and comparing is what makes the
/// node's on-chain key check meaningful: if these agree here, a disagreement in
/// production means the escrow was built from a different setup.
#[test]
fn derived_constants_match_the_exported_verifier() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../contracts/Verifier.sol");
    let Ok(source) = std::fs::read_to_string(path) else {
        eprintln!("skipping: {path} not exported");
        return;
    };

    let constant = |name: &str| -> [u8; 32] {
        let line = source
            .lines()
            .find(|l| l.contains(&format!("constant {name} =")))
            .unwrap_or_else(|| panic!("{name} missing from the exported verifier"));
        let decimal = line
            .rsplit('=')
            .next()
            .unwrap()
            .trim()
            .trim_end_matches(';');
        let n: num_bigint::BigUint = decimal.parse().expect("constant is not a decimal integer");
        let be = n.to_bytes_be();
        let mut out = [0u8; 32];
        out[32 - be.len()..].copy_from_slice(&be);
        out
    };

    let c = mirage_prover::verifying_key_constants(&keys().vk);
    for (i, (x, y)) in [
        ("CONSTANT_X", "CONSTANT_Y"),
        ("PUB_0_X", "PUB_0_Y"),
        ("PUB_1_X", "PUB_1_Y"),
    ]
    .iter()
    .enumerate()
    {
        assert_eq!(
            c.ic[i],
            [constant(x), constant(y)],
            "IC point {i} disagrees with the exported verifier's {x}/{y}"
        );
    }
}
