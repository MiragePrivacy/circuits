//! ERC-20 receipt relation: envelope parsing and Transfer-log selection.
//!
//! Spec 12.6.1 (accepted envelopes) and 12.6.2 (the selected log).
//!
//! # What this proves
//!
//! Given a receipt and a log index, that the receipt is a successful canonical
//! Ethereum receipt containing, at that index, a `Transfer` event emitted by
//! the committed token, to the committed recipient, for the committed amount.
//!
//! # What it deliberately does not prove
//!
//! The sender. Topic 1 is parsed and length-checked but its value is
//! unconstrained (spec 12.4). Spec 9 records why binding it is unreachable: the
//! payment source is chosen at execution time and cannot be committed at
//! deployment, shared state is forbidden, and a bond-time source commitment
//! would turn the executor's inventory into a clustering oracle.
//!
//! It also does not prove the transaction sender, target, calldata, signature,
//! or that `transfer` was used rather than `transferFrom`. Those are
//! operational policy, not circuit assertions.
//!
//! # Envelope shapes
//!
//! Spec 12.6.1 accepts a legacy receipt encoded directly as its RLP payload, or
//! an EIP-2718 typed receipt whose one-byte prefix is `0x01`, `0x02`, `0x03`, or
//! `0x04`, followed immediately by the payload.
//!
//! The payload is always the canonical four-item list:
//!
//! ```text
//! [status, cumulativeGasUsed, logsBloom, logs]
//! ```
//!
//! Note the asymmetry with transactions: the receipt envelope set includes
//! `0x03` and `0x04`, while the native relation's *transaction* set does not.
//! A settlement of a supported transaction type may sit in a block alongside
//! receipts of any type.
//!
//! # Cost note
//!
//! Every windowed read of the receipt buffer costs ~10 constraints per buffer
//! byte, so `MAX_RECEIPT_BYTES` governs this module the way
//! `MAX_MPT_NODE_BYTES` governs the traversal. Read fixed offsets wherever the
//! format fixes one: the four-item payload structure sits at computable
//! positions once the envelope type is known.

pub mod envelope;
pub mod log;

#[cfg(test)]
mod tests;

use ark_ff::PrimeField;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::gr1cs::SynthesisError;

/// The committed settlement details a receipt must match.
pub struct Intent<F: PrimeField> {
    /// 20 bytes.
    pub token: Vec<UInt8<F>>,
    /// 20 bytes.
    pub recipient: Vec<UInt8<F>>,
    /// 32 bytes, big-endian.
    pub amount: Vec<UInt8<F>>,
}

/// Verifies the spec 12.6 relation over a bounded receipt buffer.
pub trait ReceiptRelation<F: PrimeField> {
    /// `receipt` is the bounded buffer, `receipt_len` its real length, and
    /// `log_index` selects which log to check.
    ///
    /// Must enforce: a supported envelope, a canonical four-item payload,
    /// `status == 1`, a 256-byte `logsBloom`, and the spec 12.6.2 conditions on
    /// the selected log.
    fn verify(
        receipt: &[UInt8<F>],
        receipt_len: &FpVar<F>,
        log_index: &FpVar<F>,
        intent: &Intent<F>,
        active: &Boolean<F>,
    ) -> Result<(), SynthesisError>;
}
