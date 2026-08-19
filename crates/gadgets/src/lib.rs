//! In-circuit primitives for the settlement relation.
//!
//! Every gadget here must be checked against `mirage-encoding`, which runs
//! natively and is the reference. A gadget that agrees with itself proves
//! nothing.
//!
//! # The recurring hazard
//!
//! Circuits have no dynamic arrays. A bounded byte buffer is always MAX bytes
//! wide and only the first `len` are real, so every gadget must make the padded
//! tail inert. A prover controls those bytes and will choose values that make
//! an underconstrained circuit accept.
//!
//! Spec 12.5: "Every active node byte beyond its exact length is
//! zero-constrained. No padded node may contribute a hash, path nibble, child
//! reference, or acceptance selector."
//!
//! There is no Picus frontend for arkworks, so nothing will catch a missing
//! constraint statically. `ark-r1cs-std` additionally has live underconstraining
//! bugs (#212, #213, #216). Assume no tool will save you.
//!
//! # Debugging
//!
//! `ConstraintSystem::which_is_unsatisfied()` returns the failing constraint's
//! label, and `ConstraintLayer` captures source locations. Use
//! `cs.is_satisfied()` in every gadget test, and assert on `num_constraints()`
//! so a cost regression is visible in the diff.

pub mod bytes;
pub mod commitment;
pub mod header;
pub mod keccak;
pub mod mpt;
pub mod receipt;
pub mod rlp;
pub mod transaction;
pub mod statement;

/// Compiled bounds from spec section 12.9.
///
/// Prototype values, not privacy-approved production choices. A production
/// build must satisfy both the proving budget and the settlement-candidate
/// ranks in spec 17.8. Changing any of them is a new circuit version under
/// 18.4: new setup, new verification key, new audit delta.
///
/// These are also the dominant cost lever. Real ERC-20 receipts are often
/// 200-400 bytes against `MAX_RECEIPT_BYTES` of 2048, and mainnet receipt tries
/// run 6-9 deep against `MAX_MPT_DEPTH` of 16. Measuring the real distribution
/// before freezing them is worth more than any further backend comparison.
pub mod bounds {
    pub const MAX_HEADER_BYTES: usize = 1024;
    pub const MAX_RECEIPT_BYTES: usize = 2048;
    pub const MAX_MPT_NODE_BYTES: usize = 2048;
    pub const MAX_MPT_DEPTH: usize = 16;
    pub const MAX_LOGS: usize = 8;

    /// The native relation's transaction buffer. A bare value transfer is
    /// ~110 bytes for EIP-1559 and less for legacy; the headroom covers a
    /// non-empty access list, which the relation does not walk but must still
    /// contain.
    pub const MAX_TRANSACTION_BYTES: usize = 512;

    /// Unused in step 2, which reveals the transaction block. Step 5 adds the
    /// ancestry chain that consumes these.
    pub const MIN_WITNESS_DISTANCE: usize = 8;
    pub const MAX_WITNESS_DISTANCE: usize = 16;
}
