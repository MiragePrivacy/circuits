//! Receipt envelope and payload parsing, spec 12.6.1.
//!
//! A receipt is either a bare RLP payload (legacy) or a one-byte EIP-2718 type
//! prefix followed by that payload. The payload is always the canonical
//! four-item list `[status, cumulativeGasUsed, logsBloom, logs]`.
//!
//! # Distinguishing the two shapes
//!
//! The first byte tells you which: an RLP list header is `0xc0` or above, and
//! every supported type prefix is `0x01`-`0x04`. There is no ambiguity, and
//! anything else must fail closed.
//!
//! Note the direction of that check. It is tempting to test "is this byte a
//! valid type prefix" and treat everything else as legacy, but that accepts a
//! receipt beginning with, say, `0x7f` as a legacy payload whose RLP header is
//! nonsense. The check has to be positive on both branches: either a list
//! header, or one of exactly four prefix values.

use ark_ff::PrimeField;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::gr1cs::SynthesisError;

use crate::bytes::{one_hot, select_byte_with, zero_like};
use crate::rlp::{cursor::Cursor, Item, RlpDecoder};

/// The four payload fields, located.
pub struct Payload<F: PrimeField> {
    pub status: Item<F>,
    pub cumulative_gas: Item<F>,
    pub logs_bloom: Item<F>,
    pub logs: Item<F>,
}

/// `logsBloom` is fixed at 256 bytes by consensus.
pub const BLOOM_BYTES: u64 = 256;

/// Parses the envelope and payload, enforcing everything spec 12.6.1 requires
/// except the log contents.
///
/// Enforced here:
/// - a supported envelope: an RLP list header, or a type prefix in `0x01`-`0x04`
/// - exactly four payload items, tiling the list
/// - `status == 1`, encoded as the single byte `0x01`
/// - `logsBloom` exactly 256 bytes
/// - `cumulativeGasUsed` at most 8 bytes, so it is below 2^64
/// - the payload closing exactly at the receipt's real length
pub fn parse<F: PrimeField>(
    receipt: &[UInt8<F>],
    receipt_len: &FpVar<F>,
    active: &Boolean<F>,
) -> Result<Payload<F>, SynthesisError> {
    let zero = zero_like(receipt)?;

    // The first byte decides the shape.
    let sel = one_hot(&zero, receipt.len())?;
    let first = select_byte_with(receipt, &sel)?;

    // A typed receipt starts with one of exactly four prefixes.
    let mut is_typed = Boolean::FALSE;
    for t in 1u8..=4 {
        is_typed |= first.is_eq(&UInt8::constant(t))?;
    }

    // A legacy receipt starts with an RLP list header, 0xc0 or above. Read it
    // from the byte's own bits: bits 7 and 6 both set means >= 0xc0.
    let bits = {
        use ark_r1cs_std::convert::ToBitsGadget;
        first.to_bits_le()?
    };
    let is_list_header = bits[7].clone() & bits[6].clone();

    // Exactly one of the two, positively. Anything else fails closed.
    (is_typed.clone() | is_list_header.clone()).conditional_enforce_equal(&Boolean::TRUE, active)?;
    (is_typed.clone() & is_list_header).conditional_enforce_equal(&Boolean::FALSE, active)?;

    // The payload begins after the prefix, if there is one.
    let payload_at = FpVar::conditionally_select(&is_typed, &FpVar::one(), &FpVar::zero())? + &zero;

    // Four items, tiling the list exactly. `decode_list` enforces the count and
    // the tiling; a fifth item or a gap is rejected there.
    let items = Cursor::decode_list(receipt, &payload_at, 4, active)?;
    let list = Cursor::decode_item(receipt, &payload_at, active)?;
    list.is_list.conditional_enforce_equal(&Boolean::TRUE, active)?;

    // The receipt must end where the payload ends: no trailing bytes.
    list.end().conditional_enforce_equal(receipt_len, active)?;

    let status = items[0].clone();
    let cumulative_gas = items[1].clone();
    let logs_bloom = items[2].clone();
    let logs = items[3].clone();

    // status == 1. RLP encodes the integer 1 as the single byte 0x01, which is
    // below 0x80 and so is written bare: a one-byte payload at the item's own
    // offset. Pre-Byzantium state-root receipts are 32 bytes and rejected by
    // the length check alone.
    status
        .payload_len
        .conditional_enforce_equal(&FpVar::one(), active)?;
    let status_sel = one_hot(&status.offset, receipt.len())?;
    let status_byte = select_byte_with(receipt, &status_sel)?;
    status_byte.conditional_enforce_equal(&UInt8::constant(1), active)?;

    // logsBloom is exactly 256 bytes.
    logs_bloom
        .payload_len
        .conditional_enforce_equal(&FpVar::constant(F::from(BLOOM_BYTES)), active)?;

    // cumulativeGasUsed below 2^64: at most 8 payload bytes. The RLP decoder
    // already rejects non-canonical encodings, so a short field cannot have
    // leading zeros.
    let gas_ok = crate::bytes::le(
        &cumulative_gas.payload_len,
        &FpVar::constant(F::from(8u64)),
    )?;
    gas_ok.conditional_enforce_equal(&Boolean::TRUE, active)?;

    Ok(Payload {
        status,
        cumulative_gas,
        logs_bloom,
        logs,
    })
}
