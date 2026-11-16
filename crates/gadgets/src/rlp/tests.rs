//! Adversarial suite for the RLP decoders.
//!
//! Written before either implementation and run against both, so neither is
//! graded on its own terms.
//!
//! Each negative case names the forgery it prevents. A decoder that passes the
//! positive cases and fails any negative one is not slow or incomplete — it is
//! an authorization bypass, because the whole point of the relation is that
//! only a genuine receipt satisfies it.

use super::*;
use ark_bn254::Fr;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::GR1CSVar;
use ark_relations::gr1cs::{ConstraintSystem, ConstraintSystemRef};

use crate::bytes::alloc_bounded;

// ---------------------------------------------------------------- helpers

fn cs() -> ConstraintSystemRef<Fr> {
    ConstraintSystem::<Fr>::new_ref()
}

fn f(cs: ConstraintSystemRef<Fr>, v: u64) -> FpVar<Fr> {
    FpVar::new_witness(cs, || Ok(Fr::from(v))).unwrap()
}

/// Native RLP encoding of a byte string, for building fixtures.
fn enc_str(payload: &[u8]) -> Vec<u8> {
    if payload.len() == 1 && payload[0] < 0x80 {
        return payload.to_vec();
    }
    let mut out = Vec::new();
    if payload.len() < 56 {
        out.push(0x80 + payload.len() as u8);
    } else {
        let len_be = trim_leading_zeros(&payload.len().to_be_bytes());
        out.push(0xb7 + len_be.len() as u8);
        out.extend_from_slice(&len_be);
    }
    out.extend_from_slice(payload);
    out
}

/// Native RLP encoding of a list from already-encoded children.
fn enc_list(children: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = children.concat();
    let mut out = Vec::new();
    if body.len() < 56 {
        out.push(0xc0 + body.len() as u8);
    } else {
        let len_be = trim_leading_zeros(&body.len().to_be_bytes());
        out.push(0xf7 + len_be.len() as u8);
        out.extend_from_slice(&len_be);
    }
    out.extend_from_slice(&body);
    out
}

fn trim_leading_zeros(b: &[u8]) -> Vec<u8> {
    let first = b.iter().position(|&x| x != 0).unwrap_or(b.len() - 1);
    b[first..].to_vec()
}

/// A receipt-shaped fixture: `[status, cumulativeGasUsed, logsBloom, logs]`.
fn receipt_fixture() -> Vec<u8> {
    enc_list(&[
        enc_str(&[1]),          // status
        enc_str(&[0x52, 0x08]), // cumulativeGasUsed
        enc_str(&[0u8; 256]),   // logsBloom
        enc_list(&[]),          // logs, empty
    ])
}

/// Runs `body` against a decoder and reports whether the system is satisfied.
///
/// A decoder may also signal rejection by returning `Err`; both count as
/// rejection, since neither produces a proof.
fn accepts<Body>(buf_bytes: &[u8], bound: usize, body: Body) -> bool
where
    Body: Fn(
        &[ark_r1cs_std::uint8::UInt8<Fr>],
        ConstraintSystemRef<Fr>,
    ) -> Result<(), SynthesisError>,
{
    let c = cs();
    let buf = alloc_bounded(c.clone(), buf_bytes, bound).unwrap();
    match body(&buf, c.clone()) {
        Err(_) => false,
        Ok(()) => c.is_satisfied().unwrap_or(false),
    }
}

// ------------------------------------------------------- positive cases

/// Every decoder must handle the four RLP forms and agree on the boundaries.
pub fn accepts_canonical_forms<D: RlpDecoder<Fr>>() {
    let cases: Vec<(&str, Vec<u8>, u64, u64)> = vec![
        // (name, encoding, expected payload offset, expected payload len)
        ("single byte", vec![0x7f], 0, 1),
        ("empty string", enc_str(&[]), 1, 0),
        ("short string", enc_str(&[0xaa; 5]), 1, 5),
        ("long string", enc_str(&[0xbb; 100]), 2, 100),
        ("empty list", enc_list(&[]), 1, 0),
        (
            "short list",
            enc_list(&[enc_str(&[1]), enc_str(&[2])]),
            1,
            2,
        ),
    ];

    for (name, bytes, want_off, want_len) in cases {
        let c = cs();
        let buf = alloc_bounded(c.clone(), &bytes, 512).unwrap();
        let item = D::decode_item(&buf, &f(c.clone(), 0), &Boolean::TRUE).unwrap();
        assert!(c.is_satisfied().unwrap(), "{name}: unsatisfied");
        assert_eq!(
            item.offset.value().unwrap(),
            Fr::from(want_off),
            "{name}: wrong payload offset"
        );
        assert_eq!(
            item.payload_len.value().unwrap(),
            Fr::from(want_len),
            "{name}: wrong payload length"
        );
    }
}

/// A four-item receipt list must decode into exactly four children that tile
/// the payload.
pub fn accepts_receipt_shape<D: RlpDecoder<Fr>>() {
    let bytes = receipt_fixture();
    let c = cs();
    let buf = alloc_bounded(c.clone(), &bytes, 1024).unwrap();
    let items = D::decode_list(&buf, &f(c.clone(), 0), 4, &Boolean::TRUE).unwrap();
    assert!(c.is_satisfied().unwrap(), "receipt shape rejected");

    // logsBloom is the third field and must be exactly 256 bytes; spec 12.6.1.
    assert_eq!(items[2].payload_len.value().unwrap(), Fr::from(256u64));
}

// ------------------------------------------------------- forgery cases

/// **Forgery: non-minimal single byte.**
///
/// `0x81 0x7f` encodes the byte `0x7f`, which RLP requires be written bare.
/// Accepting it lets an attacker shift every subsequent field by one byte
/// while keeping the payload identical.
pub fn rejects_non_minimal_single_byte<D: RlpDecoder<Fr>>() {
    let forged = vec![0x81, 0x7f];
    assert!(
        !accepts(&forged, 64, |buf, c| {
            D::decode_item(buf, &f(c, 0), &Boolean::TRUE).map(|_| ())
        }),
        "accepted 0x81 0x7f for a byte below 0x80"
    );
}

/// **Forgery: long form where short form fits.**
///
/// `0xb8 0x05 ...` claims long form for a 5-byte string that must use `0x85`.
/// Accepting it gives the attacker a one-byte shift of the payload start.
pub fn rejects_long_form_for_short_payload<D: RlpDecoder<Fr>>() {
    let mut forged = vec![0xb8, 0x05];
    forged.extend_from_slice(&[0xaa; 5]);
    assert!(
        !accepts(&forged, 64, |buf, c| {
            D::decode_item(buf, &f(c, 0), &Boolean::TRUE).map(|_| ())
        }),
        "accepted long form for a payload short form can encode"
    );
}

/// **Forgery: leading zeros in a long-form length.**
///
/// `0xb9 0x00 0x40` encodes length 64 in two bytes where one suffices.
/// Accepting it shifts the payload start by one.
pub fn rejects_leading_zero_length<D: RlpDecoder<Fr>>() {
    let mut forged = vec![0xb9, 0x00, 0x40];
    forged.extend_from_slice(&[0xcc; 64]);
    assert!(
        !accepts(&forged, 256, |buf, c| {
            D::decode_item(buf, &f(c, 0), &Boolean::TRUE).map(|_| ())
        }),
        "accepted a length with leading zeros"
    );
}

/// **Forgery: payload runs past the buffer.**
///
/// A prefix claiming 200 bytes in a buffer holding 10. Accepting it lets the
/// decoder read zero padding as though it were data.
pub fn rejects_payload_past_buffer<D: RlpDecoder<Fr>>() {
    let forged = vec![0xb8, 200, 0xaa, 0xbb];
    assert!(
        !accepts(&forged, 16, |buf, c| {
            D::decode_item(buf, &f(c, 0), &Boolean::TRUE).map(|_| ())
        }),
        "accepted a payload longer than the buffer"
    );
}

/// **Forgery: wrong child count.**
///
/// The receipt payload must be exactly four items (spec 12.6.1). A three-item
/// or five-item list must be rejected, not silently truncated or padded — an
/// attacker who can add a phantom field controls what the relation reads as
/// `logs`.
pub fn rejects_wrong_child_count<D: RlpDecoder<Fr>>() {
    let three = enc_list(&[enc_str(&[1]), enc_str(&[2]), enc_str(&[3])]);
    assert!(
        !accepts(&three, 512, |buf, c| {
            D::decode_list(buf, &f(c, 0), 4, &Boolean::TRUE).map(|_| ())
        }),
        "accepted a three-item list where four were required"
    );

    let five = enc_list(&[
        enc_str(&[1]),
        enc_str(&[2]),
        enc_str(&[3]),
        enc_str(&[4]),
        enc_str(&[5]),
    ]);
    assert!(
        !accepts(&five, 512, |buf, c| {
            D::decode_list(buf, &f(c, 0), 4, &Boolean::TRUE).map(|_| ())
        }),
        "accepted a five-item list where four were required"
    );
}

/// **Forgery: children do not tile the payload.**
///
/// A list header claiming more payload than its children occupy leaves a gap.
/// If the decoder does not require the last child to end exactly at the list
/// end, the attacker hides bytes there — and in a nested context those bytes
/// are a whole item the relation never inspects.
pub fn rejects_untiled_list<D: RlpDecoder<Fr>>() {
    // A two-item list whose header claims four extra payload bytes.
    let body = [enc_str(&[1]), enc_str(&[2])].concat();
    let mut forged = vec![0xc0 + (body.len() + 4) as u8];
    forged.extend_from_slice(&body);
    forged.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

    assert!(
        !accepts(&forged, 512, |buf, c| {
            D::decode_list(buf, &f(c, 0), 2, &Boolean::TRUE).map(|_| ())
        }),
        "accepted a list whose children leave a gap"
    );
}

/// **Forgery: a child escapes its parent.**
///
/// The child's declared length reaches past the list's end. Without a
/// containment check the decoder reads sibling or trailing bytes as this
/// child's payload — the mid-`logsBloom` attack.
pub fn rejects_child_escaping_parent<D: RlpDecoder<Fr>>() {
    // List header says 3 bytes of payload; the single child claims 8.
    let mut forged = vec![0xc3, 0x88];
    forged.extend_from_slice(&[0xaa; 10]);

    assert!(
        !accepts(&forged, 512, |buf, c| {
            D::decode_list(buf, &f(c, 0), 1, &Boolean::TRUE).map(|_| ())
        }),
        "accepted a child reaching past its parent's end"
    );
}

/// **Forgery: a string decoded as a list.**
///
/// A `0x80`-range prefix is a string and must not satisfy `decode_list`,
/// otherwise an attacker presents opaque bytes where the relation expects
/// structure.
pub fn rejects_string_as_list<D: RlpDecoder<Fr>>() {
    let s = enc_str(&[0xaa; 8]);
    assert!(
        !accepts(&s, 512, |buf, c| {
            D::decode_list(buf, &f(c, 0), 1, &Boolean::TRUE).map(|_| ())
        }),
        "accepted a string where a list was required"
    );
}

/// **Not a decoder responsibility: reading inside the zero-padded tail.**
///
/// A zero byte is a canonically valid empty string, so a decoder given only a
/// buffer cannot tell padding from data. Rejecting reads past the real data is
/// the *caller's* job, by deriving every offset from a root item whose bounds
/// were established against the witnessed length.
///
/// This case is recorded rather than asserted, because getting it wrong is a
/// real forgery: an attacker who can start a parse in the tail gets a free
/// empty item. The defence lives in two places already present:
///
/// - `crate::bytes::assert_zero_tail` forces the tail to be zeros, so nothing
///   an attacker chooses can live there;
/// - `decode_list` containment forces every child inside its parent, so a
///   traversal rooted at offset 0 can never reach the tail.
///
/// The relation must therefore never call `decode_item` at a free offset. Every
/// offset must descend from the root.
pub fn tail_reads_are_the_callers_responsibility<D: RlpDecoder<Fr>>() {
    let bytes = enc_str(&[0xaa; 4]);
    // Reading at 40 in a zero tail yields an empty string, and that is correct
    // behaviour for a decoder with no length parameter.
    let accepted = accepts(&bytes, 64, |buf, c| {
        D::decode_item(buf, &f(c, 40), &Boolean::TRUE).map(|_| ())
    });
    assert!(
        accepted,
        "a zero byte is a valid empty string; the decoder should not reject it"
    );
}

/// Reports the constraint cost of decoding a receipt-shaped list.
///
/// This is the number that decides whether a decoder is usable: the relation
/// decodes the receipt, its logs list, and one log, over buffers bounded at
/// hundreds to thousands of bytes.
pub fn report_cost<D: RlpDecoder<Fr>>(label: &str) {
    for bound in [256usize, 512, 1024] {
        let bytes = receipt_fixture();
        if bytes.len() > bound {
            continue;
        }
        let c = cs();
        let buf = alloc_bounded(c.clone(), &bytes, bound).unwrap();
        let before = c.num_constraints();
        let _ = D::decode_list(&buf, &f(c.clone(), 0), 4, &Boolean::TRUE).unwrap();
        println!(
            "{label}: 4-item receipt list in {bound} byte buffer: {} constraints",
            c.num_constraints() - before
        );
    }
}

/// Runs the whole suite against one decoder.
///
/// Called by each implementation's test module so both are graded identically.
pub fn run_suite<D: RlpDecoder<Fr>>() {
    accepts_canonical_forms::<D>();
    accepts_receipt_shape::<D>();
    rejects_non_minimal_single_byte::<D>();
    rejects_long_form_for_short_payload::<D>();
    rejects_leading_zero_length::<D>();
    rejects_payload_past_buffer::<D>();
    rejects_wrong_child_count::<D>();
    rejects_untiled_list::<D>();
    rejects_child_escaping_parent::<D>();
    rejects_string_as_list::<D>();
    tail_reads_are_the_callers_responsibility::<D>();
}
