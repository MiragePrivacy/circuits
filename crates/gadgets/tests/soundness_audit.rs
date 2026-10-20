//! Reproductions of soundness findings, not assertions that the circuit is safe.
//! These tests should stop reproducing after the corresponding fixes.

use ark_bn254::Fr;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, GR1CSVar};
use ark_relations::gr1cs::{ConstraintSystem, ConstraintSystemRef};
use mirage_gadgets::bytes::{alloc_bounded, one_hot, select_byte_with};

/// Repoints a witness index after synthesis.
///
/// Symbolic linear combinations cache their values when created. The system
/// is finalized (inlining every combination into witness terms) and the
/// cache dropped, so each constraint re-evaluates from the edited witness.
fn repoint(cs: &ConstraintSystemRef<Fr>, idx: &FpVar<Fr>, value: u64) {
    let FpVar::Var(allocated) = idx else {
        unreachable!()
    };
    cs.finalize();
    let mut inner = cs.borrow_mut().unwrap();
    inner.assignments.witness_assignment[allocated.variable.index().unwrap()] = Fr::from(value);
    inner.assignments.lc_assignment.clear();
}

#[test]
fn audit_reproduces_zero_selector_for_in_range_index() {
    let cs = ConstraintSystem::<Fr>::new_ref();
    let buf = alloc_bounded(cs.clone(), &[11, 22, 33], 3).unwrap();
    // Generate the all-zero selector witness using an out-of-range index.
    let idx = FpVar::new_witness(cs.clone(), || Ok(Fr::from(99u64))).unwrap();
    let selectors = one_hot(&idx, buf.len()).unwrap();
    let read = select_byte_with(&buf, &selectors).unwrap();
    assert_eq!(read.value().unwrap(), 0);
    assert!(cs.is_satisfied().unwrap());

    // A malicious prover controls assignments, not just the honest generator.
    // Change only the index assignment; all other assignments stay unchanged.
    repoint(&cs, &idx, 1);
    assert!(cs.is_satisfied().unwrap(), "attack no longer reproduces");
    assert_ne!(read.value().unwrap(), 22, "buf[1] is 22, not zero");
}

/// `one_hot_in_range` must reject the all-zero selector for an in-range index.
///
/// The all-zero vector is how `one_hot` encodes out-of-range, so it is
/// satisfiable for any index. Where the caller knows the index is in range,
/// accepting it lets a prover suppress the read and get zero back.
#[test]
fn in_range_selector_rejects_a_suppressed_read() {
    use ark_r1cs_std::boolean::Boolean;
    use mirage_gadgets::bytes::one_hot_in_range;

    let cs = ConstraintSystem::<Fr>::new_ref();
    let buf = alloc_bounded(cs.clone(), &[11, 22, 33], 3).unwrap();
    let idx = FpVar::new_witness(cs.clone(), || Ok(Fr::from(99u64))).unwrap();
    let selectors = one_hot_in_range(&idx, buf.len(), &Boolean::TRUE).unwrap();
    let read = select_byte_with(&buf, &selectors).unwrap();
    assert_eq!(read.value().unwrap(), 0);
    // Out of range with an asserted hit is already unsatisfiable.
    assert!(!cs.is_satisfied().unwrap());

    // Repoint the index at an in-range slot, keeping the all-zero selector.
    repoint(&cs, &idx, 1);
    assert!(
        !cs.is_satisfied().unwrap(),
        "all-zero selector still accepted for an in-range index"
    );
}

/// The ungated form stays satisfiable out of range, which speculative
/// callers depend on.
#[test]
fn in_range_selector_still_permits_speculative_reads() {
    use ark_r1cs_std::boolean::Boolean;
    use mirage_gadgets::bytes::one_hot_in_range;

    let cs = ConstraintSystem::<Fr>::new_ref();
    let buf = alloc_bounded(cs.clone(), &[11, 22, 33], 3).unwrap();
    let idx = FpVar::new_witness(cs.clone(), || Ok(Fr::from(99u64))).unwrap();
    let _ = one_hot_in_range(&idx, buf.len(), &Boolean::FALSE).unwrap();
    assert!(cs.is_satisfied().unwrap());
}
