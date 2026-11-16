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
//! # Bare sends only
//!
//! `data` must be empty. A node settles by sending ETH directly, so calldata
//! never appears on a real settlement, and the relation enforces that rather
//! than trusting the enclave to produce it.
//!
//! This is a bounds decision as much as a semantic one. A call carrying value
//! delivers ETH exactly as a bare send does, so an earlier draft left `data`
//! unconstrained — but a call's payload is unbounded and its receipt may carry
//! any number of logs. Measured on mainnet: 7KB transactions and 21KB receipts
//! against a bare send's 122 and 393 bytes, which at the observed p90 is 213M
//! constraints, roughly 598 GB. Leaving it open would mean a relation that
//! *accepts* settlements no machine can prove.
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
//! # Parsing an authenticated transaction
//!
//! The three layouts differ only in how many integer items precede `to`. The
//! envelope type selects which walked offset is `to`, and everything after it
//! is read from one window. Structural re-validation that consensus already
//! guarantees for an included transaction (item count, canonical lengths of
//! unread fields) is not repeated; see [`envelope`].

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
    /// Must enforce: a supported envelope, `to` present and 20 bytes, `to`
    /// equal to the committed recipient, `value` equal to the committed amount,
    /// and empty `data`. The caller must have authenticated the transaction.
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
        envelope::verify(transaction, transaction_len, intent, active)
    }
}
