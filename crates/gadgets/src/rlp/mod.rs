//! RLP decoding.
//!
//! Two implementations behind one trait, so the adversarial suite grades both
//! on identical terms:
//!
//! - [`cursor`] derives every offset by walking the buffer. Obviously sound —
//!   there is nothing for a prover to forge — and expensive, because each step
//!   produces a witness-dependent offset at ~10 constraints per buffer byte.
//! - [`layout`] takes the field layout as a witness hint and verifies it.
//!   Affordable, and sound only if the verification is complete.
//!
//! The point of the trait is that [`tests`] cannot be written to suit either
//! one. A forged layout that the cursor implementation rejects structurally
//! must also be rejected by the layout implementation, or the layout
//! implementation is broken.
//!
//! # Why this needs adversarial tests before code
//!
//! A missing constraint here is an authorization bug with no symptom: valid
//! proofs still verify, and forged ones additionally verify. Spec 2.1. There is
//! no Picus frontend for arkworks, so nothing catches it statically.
//!
//! The specific hazard for [`layout`] is that a prover supplies a *different
//! but self-consistent* set of offsets over the same bytes. Chain arithmetic
//! alone (`offset[i] + len[i] == offset[i+1]`) does not stop this, because the
//! attacker picks every offset consistently. It is a valid parse of a
//! different tree.

pub mod cursor;
pub mod layout;

#[cfg(test)]
mod tests;

use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::gr1cs::SynthesisError;

/// One decoded RLP item: where its payload starts and how long it is.
///
/// `header_len` is the prefix size (1 for a single byte or short form, more for
/// long form), so the item as a whole spans
/// `[offset - header_len, offset + payload_len)`.
#[derive(Clone)]
pub struct Item<F: PrimeField> {
    /// Offset of the payload's first byte.
    pub offset: FpVar<F>,
    /// Payload length in bytes.
    pub payload_len: FpVar<F>,
    /// Prefix length in bytes.
    pub header_len: FpVar<F>,
    /// True when the item is a list rather than a string.
    pub is_list: ark_r1cs_std::boolean::Boolean<F>,
}

impl<F: PrimeField> Item<F> {
    /// Offset one past the item's last byte.
    pub fn end(&self) -> FpVar<F> {
        &self.offset + &self.payload_len
    }

    /// Total encoded size including the prefix.
    pub fn total_len(&self) -> FpVar<F> {
        &self.header_len + &self.payload_len
    }
}

/// An RLP decoder over a bounded buffer.
///
/// Implementations differ in how offsets are obtained, not in what they must
/// guarantee. Every method must reject non-canonical encodings and any item
/// whose bounds escape its parent.
///
/// # Conditional enforcement
///
/// Every method takes an `active` flag, and **every** constraint it emits must
/// be gated on it. This is not optional convenience.
///
/// A circuit cannot branch, so a caller that does not know a node's shape must
/// run both interpretations and select the result. That only works if each
/// interpretation is *total* — if it computes a possibly-wrong answer on
/// unexpected input rather than making the system unsatisfiable.
///
/// An enforcing decoder is not total. `decode_list(2)` on a 17-item list does
/// not return a wrong answer; it emits a false constraint, and false
/// constraints do not select away. One speculative call poisons the whole
/// proof.
///
/// So `active` decides whether the decode's assertions bind, and the caller
/// selects among outputs afterwards. Confirmed the hard way: see
/// `mpt::node::tests::{short_decode_rejects_a_branch, branch_decode_rejects_a_leaf}`.
///
/// Cost is unchanged — `conditional_enforce_equal` is the same constraint count
/// as `enforce_equal`.
pub trait RlpDecoder<F: PrimeField> {
    /// Decodes the item whose prefix begins at `at`.
    ///
    /// Must enforce canonical form: no long-form length where short form fits,
    /// no leading zeros in the length bytes, and no `0x81 xx` for a byte below
    /// `0x80`.
    fn decode_item(
        buf: &[UInt8<F>],
        at: &FpVar<F>,
        active: &ark_r1cs_std::boolean::Boolean<F>,
    ) -> Result<Item<F>, SynthesisError>;

    /// Decodes a list at `at` into exactly `n` child items.
    ///
    /// Must enforce that the children tile the list payload exactly: the first
    /// starts at the payload start, each abuts the next, and the last ends at
    /// the payload end. A list with a different number of items must be
    /// rejected rather than truncated.
    fn decode_list(
        buf: &[UInt8<F>],
        at: &FpVar<F>,
        n: usize,
        active: &ark_r1cs_std::boolean::Boolean<F>,
    ) -> Result<Vec<Item<F>>, SynthesisError>;
}
