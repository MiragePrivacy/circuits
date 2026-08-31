//! Log selection and Transfer validation, spec 12.6.2.
//!
//! # Walking to the selected log
//!
//! Logs are a variable-length RLP list, so reaching log `k` means decoding
//! logs `0..k`. Depth is a witness, so all `MAX_LOGS` steps run and the result
//! is selected — the usual shape.
//!
//! The walk must also enforce that `log_index` is genuinely in range. Reading
//! past the end of the list would otherwise decode whatever follows, and in a
//! bounded buffer that is attacker-influenced padding.
//!
//! # What is checked on the selected log
//!
//! Per spec 12.6.2, with the log being `[address, topics, data]`:
//!
//! - `address` equals the committed token
//! - `topics` has exactly three entries
//! - `topics[0]` is the Transfer signature
//! - `topics[1]` is parsed and length-checked, **value unconstrained** (12.4)
//! - `topics[2]` is canonically padded and equals the committed recipient
//! - `data` is exactly 32 bytes and equals the committed amount
//!
//! The topic-0 check is load-bearing in a way that is easy to underrate.
//! `Approval(address,address,uint256)` has the identical three-topic shape —
//! signature, two addresses, value in data — so without it an approval, which
//! moves no funds, satisfies a commitment to a payment.

use ark_ff::PrimeField;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::convert::ToBitsGadget;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::gr1cs::SynthesisError;

use super::Intent;
use crate::bounds::MAX_LOGS;
use crate::bytes::{lt, one_hot, select_bytes, zero_like};
use crate::rlp::{cursor::Cursor, Item, RlpDecoder};

/// keccak256("Transfer(address,address,uint256)")
pub const TRANSFER_TOPIC0: [u8; 32] = [
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d, 0xaa,
    0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef,
];

/// Walks to log `index` within the logs list and returns it.
///
/// Enforces that `index` is within the list: the walk tracks whether each step
/// stayed inside the list bounds, and the selected step must have.
pub fn select_log<F: PrimeField>(
    receipt: &[UInt8<F>],
    logs: &Item<F>,
    index: &FpVar<F>,
    active: &Boolean<F>,
) -> Result<Item<F>, SynthesisError> {
    let logs_end = logs.end();
    let mut cursor = logs.offset.clone();

    let hit = one_hot(index, MAX_LOGS)?;
    let mut selected = logs.clone();
    let mut in_range = Boolean::FALSE;

    for is_selected in &hit {
        // This step is real only while the cursor is still inside the list.
        let within = lt(&cursor, &logs_end)?;
        let step_active = active.clone() & within.clone();

        let item = Cursor::decode_item(receipt, &cursor, &step_active)?;
        // A log is itself a list; anything else here is malformed.
        item.is_list
            .conditional_enforce_equal(&Boolean::TRUE, &step_active)?;

        // Is this the one?
        selected = select_item(is_selected, &item, &selected)?;
        in_range = Boolean::conditionally_select(is_selected, &within, &in_range)?;

        cursor = FpVar::conditionally_select(&within, &item.end(), &cursor)?;
    }

    // The selected index must have been a real log. Without this, an index past
    // the end selects a step whose decode was inactive, and the relation reads
    // padding.
    in_range.conditional_enforce_equal(&Boolean::TRUE, active)?;

    Ok(selected)
}

fn select_item<F: PrimeField>(
    cond: &Boolean<F>,
    a: &Item<F>,
    b: &Item<F>,
) -> Result<Item<F>, SynthesisError> {
    Ok(Item {
        offset: FpVar::conditionally_select(cond, &a.offset, &b.offset)?,
        payload_len: FpVar::conditionally_select(cond, &a.payload_len, &b.payload_len)?,
        header_len: FpVar::conditionally_select(cond, &a.header_len, &b.header_len)?,
        is_list: Boolean::conditionally_select(cond, &a.is_list, &b.is_list)?,
    })
}

/// Enforces the spec 12.6.2 conditions on one log.
pub fn assert_transfer<F: PrimeField>(
    receipt: &[UInt8<F>],
    log: &Item<F>,
    intent: &Intent<F>,
    active: &Boolean<F>,
) -> Result<(), SynthesisError> {
    // A log is [address, topics, data].
    let parts = Cursor::decode_list(receipt, &(&log.offset - &log.header_len), 3, active)?;
    let address = &parts[0];
    let topics = &parts[1];
    let data = &parts[2];

    // The emitter is the committed token. Any ERC-20 emits the same signature,
    // so without this a worthless token's Transfer satisfies a commitment to a
    // valuable one.
    address
        .payload_len
        .conditional_enforce_equal(&FpVar::constant(F::from(20u64)), active)?;
    let emitter = select_bytes(receipt, &address.offset, 20)?;
    for (got, want) in emitter.iter().zip(intent.token.iter()) {
        got.conditional_enforce_equal(want, active)?;
    }

    // Exactly three topics, each 32 bytes.
    let t = Cursor::decode_list(receipt, &(&topics.offset - &topics.header_len), 3, active)?;
    for topic in &t {
        topic
            .payload_len
            .conditional_enforce_equal(&FpVar::constant(F::from(32u64)), active)?;
    }

    // topics[0] is the Transfer signature. Approval has the same three-topic
    // shape, so this is what separates a payment from an allowance change.
    let sig = select_bytes(receipt, &t[0].offset, 32)?;
    for (got, want) in sig.iter().zip(TRANSFER_TOPIC0.iter()) {
        got.conditional_enforce_equal(&UInt8::constant(*want), active)?;
    }

    // topics[1] is the sender. Parsed and length-checked above; value
    // deliberately unconstrained per spec 12.4.

    // topics[2] is the recipient, canonically left-padded.
    let to = select_bytes(receipt, &t[2].offset, 32)?;
    for byte in to.iter().take(12) {
        byte.conditional_enforce_equal(&UInt8::constant(0), active)?;
    }
    for (got, want) in to[12..].iter().zip(intent.recipient.iter()) {
        got.conditional_enforce_equal(want, active)?;
    }

    // data is exactly 32 bytes and equals the committed amount.
    data.payload_len
        .conditional_enforce_equal(&FpVar::constant(F::from(32u64)), active)?;
    let value = select_bytes(receipt, &data.offset, 32)?;
    for (got, want) in value.iter().zip(intent.amount.iter()) {
        got.conditional_enforce_equal(want, active)?;
    }

    Ok(())
}

/// The sole log of a single-log receipt, with no walk.
///
/// Spec 20.3 requires production settlements be a direct `transfer()` call, and
/// such a receipt carries exactly one Transfer and nothing else. When that holds
/// there is no log to select: the list's first item *is* the log, and the walk
/// that reaches index `k` of up to `MAX_LOGS` is pure waste.
///
/// Measured at a 1024-byte receipt bound: the walk costs 338,867 constraints,
/// 18% of the whole receipt relation, to reach index 0 of a one-element list.
///
/// # What this gives up
///
/// A receipt with any second event becomes unprovable. That is a real
/// narrowing: a token with a transfer hook, a fee-on-transfer token emitting a
/// second Transfer, or any token that logs alongside its transfer is excluded.
///
/// Spec 12.9 puts the cost of an unprovable settlement on the executor, who has
/// already paid, so this must be enforced by the enclave's pre-settlement token
/// review rather than discovered at proving time. It is the same class of
/// decision as the compiled bounds: cheaper circuit, narrower supported set.
///
/// [`select_log`] remains for the general case and both are covered by the same
/// adversarial suite.
pub fn sole_log<F: PrimeField>(
    receipt: &[UInt8<F>],
    logs: &Item<F>,
    active: &Boolean<F>,
) -> Result<Item<F>, SynthesisError> {
    let log = Cursor::decode_item(receipt, &logs.offset, active)?;
    log.is_list
        .conditional_enforce_equal(&Boolean::TRUE, active)?;

    // Exactly one: the log must fill the list. Without this a prover appends a
    // second event whose contents the relation never inspects, which is the
    // whole point of restricting to one.
    log.end().conditional_enforce_equal(&logs.end(), active)?;

    Ok(log)
}

/// The full spec 12.6 relation, walking to a selected log.
pub struct Erc20;

/// The spec 12.6 relation restricted to single-log receipts.
///
/// Identical to [`Erc20`] except that it requires exactly one log and skips the
/// walk. See [`sole_log`] for what that trades away.
pub struct Erc20SingleLog;

/// The single-Transfer relation expressed as a finite set of fixed layouts.
///
/// Once a receipt is restricted to one canonical ERC-20 `Transfer`, only two
/// values move any field boundary: whether an EIP-2718 type byte is present,
/// and the encoded width of `cumulativeGasUsed`. Enumerating those 18 layouts
/// turns every receipt access into a compile-time index. The candidate flags
/// are derived from the receipt bytes and exact length, so the native witness
/// builder supplies no trusted parse result.
pub struct Erc20FixedLayout;

impl<F: PrimeField> super::ReceiptRelation<F> for Erc20FixedLayout {
    fn verify(
        receipt: &[UInt8<F>],
        receipt_len: &FpVar<F>,
        log_index: &FpVar<F>,
        intent: &Intent<F>,
        active: &Boolean<F>,
    ) -> Result<(), SynthesisError> {
        // This relation is deliberately the same single-log narrowing as
        // `Erc20SingleLog`.
        log_index.conditional_enforce_equal(&FpVar::zero(), active)?;

        // A typed envelope is one of exactly 0x01..0x04. Legacy starts with the
        // payload's 0xf9 list prefix. All supported direct-transfer receipts
        // have a two-byte outer payload length.
        let mut type_ok = Boolean::FALSE;
        for t in 1u8..=4 {
            type_ok |= receipt[0].is_eq(&UInt8::constant(t))?;
        }
        let legacy_prefix = receipt[0].is_eq(&UInt8::constant(0xf9))?;
        let typed_payload_prefix = receipt[1].is_eq(&UInt8::constant(0xf9))?;

        let mut accepted = Boolean::FALSE;
        for payload_at in 0usize..=1 {
            for gas_total in 1usize..=9 {
                // Outer list: three-byte header plus a body containing status
                // (1), gas (gas_total), bloom (259), and logs (159).
                let total = payload_at + 422 + gas_total;
                let length_matches =
                    receipt_len.is_eq(&FpVar::constant(F::from(total as u64)))?;
                let envelope_matches = if payload_at == 0 {
                    legacy_prefix.clone()
                } else {
                    type_ok.clone() & typed_payload_prefix.clone()
                };
                let candidate = length_matches & envelope_matches;
                accepted |= candidate.clone();

                check_fixed_layout(
                    receipt,
                    payload_at,
                    gas_total,
                    intent,
                    &(active.clone() & candidate),
                )?;
            }
        }

        accepted.conditional_enforce_equal(&Boolean::TRUE, active)?;
        Ok(())
    }
}

fn check_fixed_layout<F: PrimeField>(
    receipt: &[UInt8<F>],
    payload_at: usize,
    gas_total: usize,
    intent: &Intent<F>,
    active: &Boolean<F>,
) -> Result<(), SynthesisError> {
    // payload = [status, cumulativeGasUsed, logsBloom, [Transfer]]
    assert!(receipt.len() >= payload_at + 431, "receipt bound too small");
    let body_len = 419 + gas_total;
    byte_eq(receipt, payload_at, 0xf9, active)?;
    byte_eq(receipt, payload_at + 1, 0x01, active)?;
    byte_eq(receipt, payload_at + 2, (body_len - 256) as u8, active)?;
    byte_eq(receipt, payload_at + 3, 0x01, active)?; // successful status

    let gas_at = payload_at + 4;
    if gas_total == 1 {
        // Empty (zero) or a bare byte below 0x80. 0x81 would be non-minimal.
        let bits = receipt[gas_at].to_bits_le()?;
        let empty = receipt[gas_at].is_eq(&UInt8::constant(0x80))?;
        (!bits[7].clone() | empty).conditional_enforce_equal(&Boolean::TRUE, active)?;
    } else {
        byte_eq(receipt, gas_at, 0x80 + (gas_total - 1) as u8, active)?;
        if gas_total == 2 {
            // RLP must encode a one-byte value below 0x80 in bare form.
            let bits = receipt[gas_at + 1].to_bits_le()?;
            bits[7].conditional_enforce_equal(&Boolean::TRUE, active)?;
        }
    }

    let bloom_at = gas_at + gas_total;
    byte_eq(receipt, bloom_at, 0xb9, active)?;
    byte_eq(receipt, bloom_at + 1, 0x01, active)?;
    byte_eq(receipt, bloom_at + 2, 0x00, active)?;

    let logs_at = bloom_at + 259;
    byte_eq(receipt, logs_at, 0xf8, active)?;
    byte_eq(receipt, logs_at + 1, 0x9d, active)?; // one 157-byte log

    let log_at = logs_at + 2;
    byte_eq(receipt, log_at, 0xf8, active)?;
    byte_eq(receipt, log_at + 1, 0x9b, active)?; // 155-byte log body

    let address_at = log_at + 2;
    byte_eq(receipt, address_at, 0x94, active)?;
    bytes_equal(&receipt[address_at + 1..address_at + 21], &intent.token, active)?;

    let topics_at = address_at + 21;
    byte_eq(receipt, topics_at, 0xf8, active)?;
    byte_eq(receipt, topics_at + 1, 0x63, active)?;

    let topic0_at = topics_at + 2;
    byte_eq(receipt, topic0_at, 0xa0, active)?;
    for (got, want) in receipt[topic0_at + 1..topic0_at + 33]
        .iter()
        .zip(TRANSFER_TOPIC0.iter())
    {
        got.conditional_enforce_equal(&UInt8::constant(*want), active)?;
    }

    let topic1_at = topic0_at + 33;
    byte_eq(receipt, topic1_at, 0xa0, active)?; // sender intentionally free

    let topic2_at = topic1_at + 33;
    byte_eq(receipt, topic2_at, 0xa0, active)?;
    for byte in &receipt[topic2_at + 1..topic2_at + 13] {
        byte.conditional_enforce_equal(&UInt8::constant(0), active)?;
    }
    bytes_equal(
        &receipt[topic2_at + 13..topic2_at + 33],
        &intent.recipient,
        active,
    )?;

    let data_at = topic2_at + 33;
    byte_eq(receipt, data_at, 0xa0, active)?;
    bytes_equal(&receipt[data_at + 1..data_at + 33], &intent.amount, active)?;
    Ok(())
}

fn byte_eq<F: PrimeField>(
    receipt: &[UInt8<F>],
    at: usize,
    want: u8,
    active: &Boolean<F>,
) -> Result<(), SynthesisError> {
    receipt[at].conditional_enforce_equal(&UInt8::constant(want), active)
}

fn bytes_equal<F: PrimeField>(
    got: &[UInt8<F>],
    want: &[UInt8<F>],
    active: &Boolean<F>,
) -> Result<(), SynthesisError> {
    assert_eq!(got.len(), want.len());
    for (got, want) in got.iter().zip(want.iter()) {
        got.conditional_enforce_equal(want, active)?;
    }
    Ok(())
}

impl<F: PrimeField> super::ReceiptRelation<F> for Erc20SingleLog {
    fn verify(
        receipt: &[UInt8<F>],
        receipt_len: &FpVar<F>,
        log_index: &FpVar<F>,
        intent: &Intent<F>,
        active: &Boolean<F>,
    ) -> Result<(), SynthesisError> {
        // The index must be zero: there is only one log to select.
        log_index.conditional_enforce_equal(&FpVar::zero(), active)?;

        let payload = super::envelope::parse(receipt, receipt_len, active)?;
        let log = sole_log(receipt, &payload.logs, active)?;
        assert_transfer(receipt, &log, intent, active)
    }
}

impl<F: PrimeField> super::ReceiptRelation<F> for Erc20 {
    fn verify(
        receipt: &[UInt8<F>],
        receipt_len: &FpVar<F>,
        log_index: &FpVar<F>,
        intent: &Intent<F>,
        active: &Boolean<F>,
    ) -> Result<(), SynthesisError> {
        let _ = zero_like(receipt)?;
        let payload = super::envelope::parse(receipt, receipt_len, active)?;
        let log = select_log(receipt, &payload.logs, log_index, active)?;
        assert_transfer(receipt, &log, intent, active)
    }
}
