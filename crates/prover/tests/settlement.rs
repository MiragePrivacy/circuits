//! The library proving path produces what the escrow expects.

use mirage_prover::{check_bounds, prove_seeded, setup, SettlementError};
use mirage_relation::{fixture, Bounds};

#[test]
fn proves_and_self_checks_a_genuine_settlement() {
    let bounds = Bounds::default();
    let keys = setup(bounds, 0).expect("setup");
    let settlement = prove_seeded(&keys, bounds, &fixture::genuine(), 0).expect("prove");

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
