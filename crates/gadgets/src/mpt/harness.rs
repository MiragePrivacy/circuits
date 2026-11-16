//! Test harness: builds a witness from native fixtures and runs a verifier.
//!
//! Separated from the tests so every case is expressed as "take a genuine
//! proof, corrupt exactly one thing, expect rejection". A test that builds its
//! own bespoke witness tends to drift into testing what the code does rather
//! than what it must do.

use ark_bn254::Fr;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::{ConstraintSystem, ConstraintSystemRef};

use super::{MptVerifier, ProofNode};
use crate::bytes::alloc_bounded;

/// A native inclusion proof, before it becomes circuit witness.
#[derive(Clone)]
pub struct NativeProof {
    pub root: [u8; 32],
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    /// Root first.
    pub nodes: Vec<Vec<u8>>,
}

/// Compiled bounds used by the tests. Deliberately small so the suite is fast;
/// the production values are in `crate::bounds`.
/// A fully-populated branch node is 532 bytes: 16 hash references at 33 bytes
/// plus an empty value slot plus a 3-byte list header. That is the structural
/// worst case for a receipt trie, so 544 gives a small margin without paying
/// for headroom that cannot be used.
pub const TEST_NODE_BYTES: usize = 544;

/// Overridable for cost probes.
pub fn node_bound() -> usize {
    std::env::var("MPT_NODE_BOUND")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(TEST_NODE_BYTES)
}
/// A receipt-trie key is `rlp(transactionIndex)`. The index fits in three bytes
/// for any plausible block, so the encoding is at most four bytes. A 32-byte
/// key buffer is 8x larger than anything real and costs directly: path matching
/// iterates `key.len() * 2` times.
pub const TEST_KEY_BYTES: usize = 4;
pub const TEST_VALUE_BYTES: usize = 512;

/// Overridable for cost probes.
pub fn value_bound() -> usize {
    std::env::var("MPT_VALUE_BOUND")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(TEST_VALUE_BYTES)
}
pub const TEST_DEPTH: usize = 4;

/// Runs a verifier against a native proof and reports whether it was accepted.
///
/// Rejection may be signalled either by an unsatisfied constraint system or by
/// `Err`; neither yields a proof, so both count.
pub fn verify<V: MptVerifier<Fr>>(p: &NativeProof) -> bool {
    let cs = ConstraintSystem::<Fr>::new_ref();
    match build_and_run::<V>(cs.clone(), p) {
        Err(_) => false,
        Ok(()) => cs.is_satisfied().unwrap_or(false),
    }
}

fn build_and_run<V: MptVerifier<Fr>>(
    cs: ConstraintSystemRef<Fr>,
    p: &NativeProof,
) -> Result<(), ark_relations::gr1cs::SynthesisError> {
    assert!(
        p.nodes.len() <= TEST_DEPTH,
        "fixture deeper than TEST_DEPTH"
    );

    let root = alloc_bounded(cs.clone(), &p.root, 32)?;
    let key = alloc_bounded(cs.clone(), &p.key, TEST_KEY_BYTES)?;
    let key_len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(p.key.len() as u64)))?;
    let value = alloc_bounded(cs.clone(), &p.value, value_bound())?;
    let value_len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(p.value.len() as u64)))?;

    let mut nodes = Vec::with_capacity(TEST_DEPTH);
    for i in 0..TEST_DEPTH {
        let (bytes, len, active) = match p.nodes.get(i) {
            Some(n) => (n.clone(), n.len(), true),
            None => (Vec::new(), 0, false),
        };
        nodes.push(ProofNode {
            bytes: alloc_bounded(cs.clone(), &bytes, node_bound())?,
            len: FpVar::new_witness(cs.clone(), || Ok(Fr::from(len as u64)))?,
            active: Boolean::new_witness(cs.clone(), || Ok(active))?,
        });
    }

    V::verify_inclusion(&root, &key, &key_len, &value, &value_len, &nodes)
}

/// Reports the constraint cost of one verification.
pub fn cost<V: MptVerifier<Fr>>(p: &NativeProof) -> usize {
    let cs = ConstraintSystem::<Fr>::new_ref();
    let before = cs.num_constraints();
    let _ = build_and_run::<V>(cs.clone(), p);
    cs.num_constraints() - before
}

/// Names the first unsatisfied constraint, for diagnosing a rejected genuine
/// proof. `ConstraintSystem::which_is_unsatisfied` returns the label, which is
/// the one debugging affordance arkworks has that Circom does not.
pub fn which_failed<V: MptVerifier<Fr>>(p: &NativeProof) -> Option<String> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    match build_and_run::<V>(cs.clone(), p) {
        Err(e) => Some(format!("synthesis error: {e:?}")),
        Ok(()) => cs.which_is_unsatisfied().ok().flatten(),
    }
}

/// Reports the constraint index at which each stage of the traversal ends, so
/// a failing index can be attributed to a stage rather than guessed at.
pub fn stage_map<V: MptVerifier<Fr>>(p: &NativeProof) -> Vec<(String, usize)> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    let mut marks = Vec::new();

    let root = alloc_bounded(cs.clone(), &p.root, 32).unwrap();
    let key = alloc_bounded(cs.clone(), &p.key, TEST_KEY_BYTES).unwrap();
    let key_len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(p.key.len() as u64))).unwrap();
    let value = alloc_bounded(cs.clone(), &p.value, value_bound()).unwrap();
    let value_len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(p.value.len() as u64))).unwrap();
    marks.push(("inputs allocated".to_string(), cs.num_constraints()));

    let mut nodes = Vec::with_capacity(TEST_DEPTH);
    for i in 0..TEST_DEPTH {
        let (bytes, len, active) = match p.nodes.get(i) {
            Some(n) => (n.clone(), n.len(), true),
            None => (Vec::new(), 0, false),
        };
        nodes.push(ProofNode {
            bytes: alloc_bounded(cs.clone(), &bytes, node_bound()).unwrap(),
            len: FpVar::new_witness(cs.clone(), || Ok(Fr::from(len as u64))).unwrap(),
            active: Boolean::new_witness(cs.clone(), || Ok(active)).unwrap(),
        });
    }
    marks.push(("nodes allocated".to_string(), cs.num_constraints()));

    let _ = V::verify_inclusion(&root, &key, &key_len, &value, &value_len, &nodes);
    marks.push(("verify done".to_string(), cs.num_constraints()));
    marks.push((
        format!(
            "UNSATISFIED at {:?}",
            cs.which_is_unsatisfied().ok().flatten()
        ),
        0,
    ));
    marks
}
