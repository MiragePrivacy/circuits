//! Native-ETH transaction relation: envelope parsing and value-transfer checks.
//!
//! The transaction-trie counterpart to [`crate::receipt`]. Where the ERC-20
//! relation reads a `Transfer` log out of a receipt, a native settlement moves
//! ETH in the transaction itself and emits no log at all, so the settled
//! recipient and amount are the transaction's own `to` and `value` fields.
//!
//! # What this proves
//!
//! Given a transaction and a committed intent, that the transaction is a
//! supported envelope whose `to` equals the committed recipient and whose
//! `value` equals the committed amount.
//!
//! Inclusion under the header's `transactionsRoot`, and the matching receipt's
//! `status == 1`, are the caller's job. Both are load-bearing: a transaction
//! that reverts is still in the transactions trie and still names a `to` and a
//! `value`, so the transaction alone proves an *attempt* to pay rather than a
//! payment. See `mirage_relation::NativeCircuit`.
//!
//! # What it deliberately does not prove
//!
//! The sender, for the same reason the ERC-20 relation does not (spec 12.4 and
//! spec 9): the payment source is chosen at execution time and cannot be
//! committed at deployment. The signature fields are structurally bounded but
//! never verified — consensus already checked them, since an unsigned
//! transaction cannot be in the trie in the first place.
//!
//! Nor does it prove the transaction is a *bare* transfer. `data` is left
//! unconstrained, so a contract call that happens to carry the right `to` and
//! `value` satisfies the relation. That is intentional: what the escrow owes is
//! delivery of ETH to the recipient, and value attached to a call delivers it
//! exactly as a bare send does.
//!
//! # Envelope shapes
//!
//! Spec 12.6.1's transaction set, which is deliberately narrower than the
//! receipt set. Note the asymmetry: the receipt envelope set includes `0x03`
//! and `0x04`, this one does not. A settlement of a supported transaction type
//! may sit in a block alongside receipts of any type.
//!
//! ```text
//! legacy      (no prefix)  [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
//! EIP-2930    (0x01)       [chainId, nonce, gasPrice, gasLimit, to, value, data,
//!                           accessList, yParity, r, s]
//! EIP-1559    (0x02)       [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas,
//!                           gasLimit, to, value, data, accessList, yParity, r, s]
//! ```
//!
//! Blob transactions (`0x03`) are excluded because their `to` cannot be null
//! and their payload carries blob commitments the relation would have to bound;
//! set-code transactions (`0x04`) are excluded because an authorization list
//! lets the `to` account execute delegated code, so `to`/`value` no longer
//! describe the settlement on their own.
//!
//! # Why all three shapes are decoded
//!
//! The three layouts have different item counts (9, 11, 12) and put `to` and
//! `value` at different indices. `decode_list` enforces an exact count, so one
//! decode cannot cover all three: a 12-item decode of a legacy transaction does
//! not return a wrong answer, it emits a false constraint, and false
//! constraints do not select away.
//!
//! So each shape is decoded under its own `active` flag and the results are
//! selected on the envelope type. R1CS pays for all three regardless, which is
//! the same trade the MPT traversal makes between branch and short nodes.
//!
//! # Cost note
//!
//! Three speculative `decode_list` calls is 32 `decode_item` calls over the
//! transaction buffer, so `MAX_TRANSACTION_BYTES` governs this module the way
//! `MAX_RECEIPT_BYTES` governs the receipt relation. The bound is the reason
//! `data` is not walked: a bare send's payload is empty, and the relation reads
//! `to` and `value` at positions the decode already produced.

pub mod envelope;

#[cfg(test)]
mod tests;

use ark_ff::PrimeField;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::gr1cs::SynthesisError;

/// The committed settlement details a native transaction must match.
///
/// The token is absent by construction: a native row's `settlementToken` is
/// enforced all-zero when its commitment is opened, so there is nothing for
/// this relation to compare against.
pub struct NativeIntent<F: PrimeField> {
    /// 20 bytes.
    pub recipient: Vec<UInt8<F>>,
    /// 32 bytes, big-endian.
    pub amount: Vec<UInt8<F>>,
}

/// Verifies the native value-transfer relation over a bounded transaction
/// buffer.
pub trait TransactionRelation<F: PrimeField> {
    /// `transaction` is the bounded buffer and `transaction_len` its real
    /// length.
    ///
    /// Must enforce: a supported envelope, a canonical payload with the item
    /// count its type fixes, `to` present and 20 bytes, `to` equal to the
    /// committed recipient, and `value` equal to the committed amount.
    fn verify(
        transaction: &[UInt8<F>],
        transaction_len: &FpVar<F>,
        intent: &NativeIntent<F>,
        active: &Boolean<F>,
    ) -> Result<(), SynthesisError>;
}

/// The spec 12.6.1 transaction relation.
pub struct NativeTransfer;

impl<F: PrimeField> TransactionRelation<F> for NativeTransfer {
    fn verify(
        transaction: &[UInt8<F>],
        transaction_len: &FpVar<F>,
        intent: &NativeIntent<F>,
        active: &Boolean<F>,
    ) -> Result<(), SynthesisError> {
        let fields = envelope::parse(transaction, transaction_len, active)?;
        envelope::enforce_transfer(transaction, &fields, intent, active)
    }
}
