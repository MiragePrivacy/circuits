//! Experimental arkworks R1CS verifier for Keccacheck.
//!
//! The native GKR prover is used unchanged from Reilabs commit `15f00e3`.
//! This crate ports only the verifier that would replace Mirage's direct
//! Keccak-f constraints.

pub mod batch;
pub mod direct;
pub mod matrix;
pub mod poseidon2;
mod poseidon2_constants;
#[cfg(test)]
mod soundness;
#[cfg(test)]
mod spec_model;
#[cfg(test)]
mod testkit;
pub mod verifier;
