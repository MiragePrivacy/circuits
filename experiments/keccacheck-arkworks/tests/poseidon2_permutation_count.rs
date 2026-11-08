//! Pins the sponge permutation count of a proof, which prices round count changes.
//!
//! The counter is global, so this binary holds a single test.

use gkr::poseidon::COUNT_16;
use mirage_keccacheck_arkworks::verifier::make_witness;
use std::sync::atomic::Ordering;

#[test]
fn prover_permutation_count_matches_transcript_model() {
    for (instances, expected) in [(2, 1_835), (4, 2_007), (64, 2_783)] {
        COUNT_16.store(0, Ordering::Relaxed);
        let _ = make_witness(instances);
        assert_eq!(COUNT_16.load(Ordering::Relaxed), expected, "{instances}");
    }
}
