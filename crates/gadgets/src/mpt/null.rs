//! A verifier that enforces nothing.
//!
//! Exists so the adversarial suite can be shown to have teeth: every forgery
//! case must be *accepted* by this and *rejected* by the real implementation.
//! A case that passes against `Null` is not testing anything.
//!
//! This is the tests-first discipline made mechanical. Without it, a forgery
//! test written after the implementation tends to assert what the code already
//! does rather than what it must do.

use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::gr1cs::SynthesisError;

use super::{MptVerifier, ProofNode};

pub struct Null;

impl<F: PrimeField> MptVerifier<F> for Null {
    fn verify_inclusion(
        _root: &[UInt8<F>],
        _key: &[UInt8<F>],
        _key_len: &FpVar<F>,
        _value: &[UInt8<F>],
        _value_len: &FpVar<F>,
        _nodes: &[ProofNode<F>],
    ) -> Result<(), SynthesisError> {
        Ok(())
    }
}
