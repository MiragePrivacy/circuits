//! Transaction envelope parsing and the `to`/`value` relation, spec 12.6.1.
//!
//! The three supported layouts and where they put the fields the relation
//! reads:
//!
//! ```text
//! type  items  to  value  data
//! 0x00      9   3      4     5   legacy
//! 0x01     11   4      5     6   EIP-2930
//! 0x02     12   5      6     7   EIP-1559
//! ```
//!
//! # What is and is not re-validated
//!
//! The transaction reaching this gadget is the value of a leaf the caller has
//! already authenticated under the header's `transactionsRoot`, so its bytes
//! are exactly a transaction some block included. Consensus clients reject
//! non-canonical RLP and wrong item counts, so re-proving the whole list
//! structure in-circuit would only re-check what inclusion already implies.
//!
//! What remains is everything that fixes *meaning*: the envelope type, the
//! list closing at the transaction's length, the prefix of every item walked
//! on the way to `to`, `to` being a 20-byte string, `value` being a minimal
//! integer of at most 32 bytes, and `data` being empty. Items past `data`
//! (access list, signature) are never read.
//!
//! All reads are field-level shifts over the buffer: five one-byte reads walk
//! the items before `to`, and one 55-byte window covers `to`, `value` and the
//! `data` prefix.

use ark_ff::PrimeField;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::convert::ToBitsGadget;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::gr1cs::SynthesisError;

use super::NativeIntent;
use crate::bytes::{field_to_byte, prefix_mask_exact, shift_window, to_fields};

/// Items preceding `to` in the longest supported layout (EIP-1559).
const MAX_ITEMS_BEFORE_TO: usize = 5;

/// `to` prefix and address, `value` prefix and up to 32 payload bytes, and the
/// `data` prefix.
const WINDOW: usize = 1 + 20 + 1 + 32 + 1;

fn constant<F: PrimeField>(v: u64) -> FpVar<F> {
    FpVar::constant(F::from(v))
}

/// Proves the transaction is a supported envelope that pays `intent` with
/// empty calldata. Every assertion binds only when `active`.
pub fn verify<F: PrimeField>(
    transaction: &[UInt8<F>],
    transaction_len: &FpVar<F>,
    intent: &NativeIntent<F>,
    active: &Boolean<F>,
) -> Result<(), SynthesisError> {
    assert!(transaction.len() >= 4, "transaction buffer too small");
    assert_eq!(intent.recipient.len(), 20, "recipient must be 20 bytes");
    assert_eq!(intent.amount.len(), 32, "amount must be 32 bytes");

    // An inactive caller may pass anything. Zeroing the buffer keeps every
    // derived offset small, so the shifts stay satisfiable.
    let mut tx = to_fields(transaction)?;
    if !matches!(active, Boolean::Constant(true)) {
        let gate = FpVar::from(active.clone());
        tx = tx.iter().map(|b| b * &gate).collect();
    }
    let first = field_to_byte(&tx[0])?.to_bits_le()?;

    // The first byte decides the shape: a list header (legacy), or a type
    // prefix tested positively. Any other first byte must itself be the list
    // header below, so 0x03, 0x04 and unknown types fail that check; exactly
    // one of the three selectors is then set.
    let legacy = first[7].clone() & first[6].clone();
    let type1 = tx[0].is_eq(&FpVar::one())?;
    let type2 = tx[0].is_eq(&constant(2))?;
    let (legacy, type1, type2) = (
        FpVar::from(legacy),
        FpVar::from(type1),
        FpVar::from(type2),
    );
    let typed = &type1 + &type2;

    // A signed transaction's payload is at least 56 bytes and the buffer keeps
    // it below 64 KiB, so the list header is 0xf8 or 0xf9.
    let at = |k: usize| &tx[k] + &typed * (&tx[k + 1] - &tx[k]);
    let header = at(0);
    let wide = FpVar::from(header.is_eq(&constant(0xf9))?);
    header.conditional_enforce_equal(&(constant::<F>(0xf8) + &wide), active)?;
    let len_hi = at(1);
    let payload = &len_hi + &wide * (&len_hi * constant::<F>(255) + at(2));
    let start = &typed + constant::<F>(2) + &wide;
    (&start + &payload).conditional_enforce_equal(transaction_len, active)?;

    // Walk the items before `to`. Each is an integer: a single byte below
    // 0x80, or a short string.
    let mut cursor = start;
    let mut offsets = Vec::with_capacity(MAX_ITEMS_BEFORE_TO + 1);
    offsets.push(cursor.clone());
    for _ in 0..MAX_ITEMS_BEFORE_TO {
        let prefix = &shift_window(&tx, &cursor, 1)?[0];
        let bits = field_to_byte(prefix)?.to_bits_le()?;
        let long_or_list =
            bits[7].clone() & (bits[6].clone() | (bits[5].clone() & bits[4].clone() & bits[3].clone()));
        long_or_list.conditional_enforce_equal(&Boolean::FALSE, active)?;
        let size = FpVar::one() + FpVar::from(bits[7].clone()) * (prefix - constant::<F>(0x80));
        cursor += size;
        offsets.push(cursor.clone());
    }
    let to_at = &legacy * &offsets[3] + &type1 * &offsets[4] + &type2 * &offsets[5];
    let w = shift_window(&tx, &to_at, WINDOW)?;

    // `to` is a 20-byte string. A creation's empty `to` (0x80) and a
    // list-shaped `to` are both rejected here.
    w[0].conditional_enforce_equal(&constant(0x94), active)?;
    for (got, want) in w[1..21].iter().zip(intent.recipient.iter()) {
        got.conditional_enforce_equal(&crate::bytes::byte_to_field(want)?, active)?;
    }

    // `value`: a bare byte below 0x80 is its own one-byte payload; otherwise a
    // short string. The amount comparison below bounds it to 32 bytes.
    let value_prefix = field_to_byte(&w[21])?;
    let prefixed = FpVar::from(value_prefix.to_bits_le()?[7].clone());
    let value_prefix = &w[21];
    let value_len = FpVar::one() + &prefixed * (value_prefix - constant::<F>(0x81));
    let value_at = constant::<F>(21) + &prefixed;
    let value_end = &value_at + &value_len;

    // Minimal encoding: no leading zero byte. Without it `0x82 0x00 0x01` and
    // `0x01` both encode 1 and the right-alignment below reads the padded form
    // a byte apart.
    let lead = &w[22] + (FpVar::one() - &prefixed) * (&w[21] - &w[22]);
    let empty = value_len.is_zero()?;
    let lead_zero = lead.is_zero()?;
    (!empty & lead_zero).conditional_enforce_equal(&Boolean::FALSE, active)?;

    // Compare against the committed amount right-aligned. Both halves are
    // assertions about the commitment: inside the payload its bytes match,
    // outside they are zero. Comparing a read against zero outside the payload
    // would be vacuous, since a read there already yields zero.
    let mut padded = vec![FpVar::zero(); 10];
    padded.extend(w.iter().cloned());
    let tail = shift_window(&padded, &(&value_end - constant::<F>(22)), 32)?;
    // Requires `value_len <= 32`.
    let leading = prefix_mask_exact(&(constant::<F>(32) - &value_len), 32)?;
    for ((want, got), zero) in intent.amount.iter().zip(tail.iter()).zip(leading.iter()) {
        let kept = got - FpVar::from(zero.clone()) * got;
        crate::bytes::byte_to_field(want)?.conditional_enforce_equal(&kept, active)?;
    }

    // `data` is empty: the settlement is a bare send.
    //
    // A call carrying value has an unbounded payload and a receipt that may
    // carry any number of logs, measured on mainnet at 7KB and 21KB against
    // bare sends' 122 and 393 bytes. Enforcing this is what makes the compiled
    // bounds structural rather than a policy the enclave must uphold.
    shift_window(&w, &value_end, 1)?[0].conditional_enforce_equal(&constant(0x80), active)?;
    Ok(())
}
