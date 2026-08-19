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
//! Each is decoded speculatively under its own `active` flag, because
//! `decode_list` enforces an exact item count and a false constraint does not
//! select away. See the module docs on [`super`].

use ark_ff::PrimeField;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::gr1cs::SynthesisError;

use super::NativeIntent;
use crate::bytes::{le, one_hot, select_byte_with, select_bytes, zero_like};
use crate::rlp::{cursor::Cursor, Item, RlpDecoder};

/// A supported envelope, its item count, and the indices of `to` and `value`.
///
/// Ordered legacy first so the table reads like the spec's.
const SHAPES: [Shape; 3] = [
    Shape {
        prefix: None,
        items: 9,
        to: 3,
        value: 4,
        data: 5,
    },
    Shape {
        prefix: Some(0x01),
        items: 11,
        to: 4,
        value: 5,
        data: 6,
    },
    Shape {
        prefix: Some(0x02),
        items: 12,
        to: 5,
        value: 6,
        data: 7,
    },
];

struct Shape {
    /// `None` for legacy, which carries no EIP-2718 type prefix.
    prefix: Option<u8>,
    items: usize,
    to: usize,
    value: usize,
    data: usize,
}

/// The fields the native relation reads, selected across the envelope shapes.
pub struct Fields<F: PrimeField> {
    /// The `to` item. Its payload is the 20-byte recipient.
    pub to: Item<F>,
    /// The `value` item. Its payload is a canonical big-endian integer.
    pub value: Item<F>,
    /// The `data` item, which a settlement must leave empty.
    pub data: Item<F>,
}

/// Parses the envelope and returns the items the relation reads.
///
/// Enforced here:
/// - a supported envelope: an RLP list header, or a type prefix of `0x01` or
///   `0x02`
/// - the exact item count that envelope's type fixes, tiling the list
/// - the payload closing exactly at the transaction's real length
///
/// The field assertions are [`enforce_transfer`]'s job, so that a
/// caller can parse without committing to an intent.
pub fn parse<F: PrimeField>(
    transaction: &[UInt8<F>],
    transaction_len: &FpVar<F>,
    active: &Boolean<F>,
) -> Result<Fields<F>, SynthesisError> {
    let zero = zero_like(transaction)?;

    // The first byte decides the shape.
    let sel = one_hot(&zero, transaction.len())?;
    let first = select_byte_with(transaction, &sel)?;

    // A legacy transaction starts with an RLP list header, 0xc0 or above. Read
    // it from the byte's own bits: bits 7 and 6 both set means >= 0xc0.
    let is_list_header = {
        use ark_r1cs_std::convert::ToBitsGadget;
        let bits = first.to_bits_le()?;
        bits[7].clone() & bits[6].clone()
    };

    // One selector per shape. The typed ones test the prefix byte directly;
    // legacy is the list-header case.
    //
    // Testing each prefix positively is what excludes 0x03 and 0x04: an
    // unsupported type matches no shape, so the exactly-one check below fails
    // closed. A range test would have admitted them.
    let mut is_shape = Vec::with_capacity(SHAPES.len());
    for shape in &SHAPES {
        is_shape.push(match shape.prefix {
            None => is_list_header.clone(),
            Some(t) => first.is_eq(&UInt8::constant(t))?,
        });
    }

    // Exactly one shape, positively. Anything else fails closed.
    //
    // The shapes are mutually exclusive by construction — 0x01 and 0x02 are
    // distinct and both below 0xc0 — so summing the selectors and requiring 1
    // gives both "at least one" and "at most one" in a single constraint.
    let mut matched = FpVar::zero();
    for hit in &is_shape {
        matched += FpVar::from(hit.clone());
    }
    matched.conditional_enforce_equal(&FpVar::one(), active)?;

    // Decode each shape speculatively, gated on its own selector, and select
    // the two fields afterwards. A shape whose selector is false computes a
    // possibly-wrong answer rather than emitting a false constraint, which is
    // what makes selecting valid.
    let mut to: Option<Item<F>> = None;
    let mut value: Option<Item<F>> = None;
    let mut data: Option<Item<F>> = None;

    for (shape, hit) in SHAPES.iter().zip(is_shape.iter()) {
        let shape_active = active.clone() & hit;

        // The payload begins after the type prefix, if there is one.
        let payload_at = match shape.prefix {
            None => zero.clone(),
            Some(_) => &zero + FpVar::one(),
        };

        let items = Cursor::decode_list(transaction, &payload_at, shape.items, &shape_active)?;

        // The list must span the whole transaction: no trailing bytes.
        let list = Cursor::decode_item(transaction, &payload_at, &shape_active)?;
        list.is_list
            .conditional_enforce_equal(&Boolean::TRUE, &shape_active)?;
        list.end()
            .conditional_enforce_equal(transaction_len, &shape_active)?;

        to = Some(match to {
            None => items[shape.to].clone(),
            Some(prev) => select_item(hit, &items[shape.to], &prev)?,
        });
        value = Some(match value {
            None => items[shape.value].clone(),
            Some(prev) => select_item(hit, &items[shape.value], &prev)?,
        });
        data = Some(match data {
            None => items[shape.data].clone(),
            Some(prev) => select_item(hit, &items[shape.data], &prev)?,
        });
    }

    Ok(Fields {
        to: to.expect("SHAPES is non-empty"),
        value: value.expect("SHAPES is non-empty"),
        data: data.expect("SHAPES is non-empty"),
    })
}

/// Enforces that the parsed transaction pays the committed intent.
///
/// - `to` is exactly 20 bytes and equals the committed recipient
/// - `value` equals the committed amount
/// - `data` is empty: a bare send, not a call
///
/// The `to` length check is what rejects a contract creation, whose `to` is the
/// empty string. Without it a creation's zero-length `to` would read as zero
/// bytes out of the buffer and could be matched against a zero recipient — and
/// while the commitment already forbids a zero recipient, relying on that would
/// make this relation sound only by a neighbour's constraint.
pub fn enforce_transfer<F: PrimeField>(
    transaction: &[UInt8<F>],
    fields: &Fields<F>,
    intent: &NativeIntent<F>,
    active: &Boolean<F>,
) -> Result<(), SynthesisError> {
    assert_eq!(intent.recipient.len(), 20, "recipient must be 20 bytes");
    assert_eq!(intent.amount.len(), 32, "amount must be 32 bytes");

    // `to` is a 20-byte string. A creation's `to` is empty and is rejected
    // here.
    fields
        .to
        .payload_len
        .conditional_enforce_equal(&FpVar::constant(F::from(20u64)), active)?;
    for (got, want) in select_bytes(transaction, &fields.to.offset, 20)?
        .iter()
        .zip(intent.recipient.iter())
    {
        got.conditional_enforce_equal(want, active)?;
    }

    // `data` is empty: the settlement is a bare send.
    //
    // A node settles by sending ETH directly, so calldata never appears on a
    // real settlement. Enforcing that here rather than trusting the enclave to
    // produce it is what makes the compiled bounds structural: a call carrying
    // value has an unbounded payload and a receipt that may carry any number of
    // logs, measured on mainnet at 7KB and 21KB against bare sends' 122 and 393
    // bytes. Left unconstrained, the relation would accept settlements whose
    // buffers no machine can allocate — 213M constraints at the observed p90,
    // roughly 598 GB.
    //
    // The trade is the usual one: a settlement that attaches calldata becomes
    // unprovable, and spec 12.9 puts that on the executor. That is the right
    // side to fail on, because the alternative is a settlement that is
    // *accepted* by the circuit and still cannot be proven.
    fields
        .data
        .payload_len
        .conditional_enforce_equal(&FpVar::zero(), active)?;

    // `value` is a canonical big-endian RLP integer, so at most 32 payload
    // bytes. Longer is not an amount this relation can compare.
    let fits = le(&fields.value.payload_len, &FpVar::constant(F::from(32u64)))?;
    fits.conditional_enforce_equal(&Boolean::TRUE, active)?;

    // Minimal encoding: no leading zero byte.
    //
    // The RLP decoder does not supply this. Its canonical-form checks govern
    // *length* bytes and the one-byte-string case; the payload of a string item
    // is arbitrary bytes as far as RLP is concerned, and minimality is an
    // integer rule layered on top. Without it `0x82 0x00 0x01` and `0x01` both
    // encode 1, and the right-alignment reads the padded form shifted by a
    // byte, so a prover picks which amount the commitment appears to name.
    let has_payload = le(&FpVar::one(), &fields.value.payload_len)?;
    let first = select_byte(transaction, &fields.value.offset, &has_payload)?;
    let first_is_zero = first.is_eq(&UInt8::constant(0))?;
    (has_payload & first_is_zero).conditional_enforce_equal(&Boolean::FALSE, active)?;

    // Compare against the committed 32-byte amount right-aligned: an RLP
    // integer is minimally encoded, so a 6-byte value must match the low 6
    // bytes of the commitment and the high 26 must be zero.
    //
    // Both halves of that are assertions about the commitment, not about what
    // was read. Comparing the *read* byte against zero outside the payload
    // would be vacuous — an out-of-range read already yields zero — so a
    // zero-value transaction would satisfy any commitment at all.
    for (i, want) in intent.amount.iter().enumerate() {
        // Commitment byte i is at value-payload position i - (32 - len), which
        // exists only once i has passed the leading zeros.
        let from_end = FpVar::constant(F::from((32 - i) as u64));
        let within = le(&from_end, &fields.value.payload_len)?;

        // Read the payload byte that lines up with commitment byte i. When the
        // value is shorter, the offset falls before the payload and the read is
        // suppressed to zero.
        let at = &fields.value.offset + &fields.value.payload_len - &from_end;
        let got = select_byte(transaction, &at, &within)?;

        // Inside the payload the bytes must match; outside, the *commitment*
        // byte must be zero. `got` is zero there either way, so requiring
        // `want == got` covers both cases in one constraint.
        want.conditional_enforce_equal(&got, active)?;
    }

    Ok(())
}

/// Reads `buf[at]`, or zero when `live` is false.
///
/// The offset is only meaningful inside the payload, and an out-of-range read
/// already yields zero, but computing it against a wrapped-around offset would
/// read an unrelated byte. Zeroing the index keeps the discarded reads pinned
/// to `buf[0]`-or-nothing rather than somewhere a prover chooses.
fn select_byte<F: PrimeField>(
    buf: &[UInt8<F>],
    at: &FpVar<F>,
    live: &Boolean<F>,
) -> Result<UInt8<F>, SynthesisError> {
    let guarded = FpVar::conditionally_select(live, at, &FpVar::zero())?;
    let sel = one_hot(&guarded, buf.len())?;
    let byte = select_byte_with(buf, &sel)?;
    UInt8::conditionally_select(live, &byte, &UInt8::constant(0))
}

/// Selects between two decoded items.
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
