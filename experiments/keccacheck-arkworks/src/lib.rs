//! Experimental arkworks R1CS verifier for Keccacheck.
//!
//! The native GKR prover is used unchanged from Reilabs commit `15f00e3`.
//! This crate ports only the verifier that would replace Mirage's direct
//! Keccak-f constraints.

pub mod direct;
pub mod poseidon2;
mod poseidon2_constants;
pub mod verifier;
