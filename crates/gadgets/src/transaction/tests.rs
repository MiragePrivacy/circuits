//! Adversarial suite for the native-ETH transaction relation.
//!
//! Every negative case is a route to proving a payment that did not happen as
//! committed, which is a route to collecting an escrow without settling.
//!
//! Fixtures are built with a native encoder so the tests grade the circuit
//! against real Ethereum encoding rather than against itself.

use super::*;
use ark_bn254::Fr;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::{ConstraintSystem, ConstraintSystemRef};

use crate::bytes::alloc_bounded;

/// Bound used by the suite. Small enough to keep tests fast; production value
/// is `crate::bounds::MAX_TRANSACTION_BYTES`.
const TEST_TRANSACTION_BYTES: usize = 512;

// --------------------------------------------------------------- fixtures

fn enc_str(payload: &[u8]) -> Vec<u8> {
    if payload.len() == 1 && payload[0] < 0x80 {
        return payload.to_vec();
    }
    let mut out = Vec::new();
    if payload.len() < 56 {
        out.push(0x80 + payload.len() as u8);
    } else {
        let lb = trim(&payload.len().to_be_bytes());
        out.push(0xb7 + lb.len() as u8);
        out.extend_from_slice(&lb);
    }
    out.extend_from_slice(payload);
    out
}

fn enc_list(children: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = children.concat();
    let mut out = Vec::new();
    if body.len() < 56 {
        out.push(0xc0 + body.len() as u8);
    } else {
        let lb = trim(&body.len().to_be_bytes());
        out.push(0xf7 + lb.len() as u8);
        out.extend_from_slice(&lb);
    }
    out.extend_from_slice(&body);
    out
}

fn trim(b: &[u8]) -> Vec<u8> {
    let first = b.iter().position(|&x| x != 0).unwrap_or(b.len() - 1);
    b[first..].to_vec()
}

/// A canonical RLP integer: minimally encoded, big-endian, no leading zeros.
fn enc_int(v: u128) -> Vec<u8> {
    if v == 0 {
        return enc_str(&[]);
    }
    enc_str(&trim(&v.to_be_bytes()))
}

const RECIPIENT: [u8; 20] = [0x22; 20];
const OTHER: [u8; 20] = [0x44; 20];

fn amount(v: u128) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[16..].copy_from_slice(&v.to_be_bytes());
    a
}

/// A 32-byte signature component, RLP-encoded.
fn sig() -> Vec<u8> {
    enc_str(&[0x77; 32])
}

/// An empty access list.
fn access_list() -> Vec<u8> {
    enc_list(&[])
}

/// Builds a transaction of the given type paying `value` to `to`.
///
/// `type_prefix` of `None` is legacy; `Some(1)` is EIP-2930 and `Some(2)` is
/// EIP-1559. Unsupported types are built the same way so the suite can check
/// they are rejected.
fn transaction(type_prefix: Option<u8>, to: &[u8], value: u128) -> Vec<u8> {
    let payload = match type_prefix {
        // [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
        None => enc_list(&[
            enc_int(9),
            enc_int(20_000_000_000),
            enc_int(21_000),
            enc_str(to),
            enc_int(value),
            enc_str(&[]),
            enc_int(37),
            sig(),
            sig(),
        ]),
        // [chainId, nonce, gasPrice, gasLimit, to, value, data, accessList,
        //  yParity, r, s]
        Some(0x01) => enc_list(&[
            enc_int(1),
            enc_int(9),
            enc_int(20_000_000_000),
            enc_int(21_000),
            enc_str(to),
            enc_int(value),
            enc_str(&[]),
            access_list(),
            enc_int(0),
            sig(),
            sig(),
        ]),
        // [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to,
        //  value, data, accessList, yParity, r, s]
        _ => enc_list(&[
            enc_int(1),
            enc_int(9),
            enc_int(1_500_000_000),
            enc_int(20_000_000_000),
            enc_int(21_000),
            enc_str(to),
            enc_int(value),
            enc_str(&[]),
            access_list(),
            enc_int(0),
            sig(),
            sig(),
        ]),
    };
    match type_prefix {
        Some(t) => {
            let mut out = vec![t];
            out.extend_from_slice(&payload);
            out
        }
        None => payload,
    }
}

/// The genuine case: an EIP-1559 transfer of 1 ETH to the committed recipient.
fn genuine() -> (Vec<u8>, [u8; 32]) {
    let v = 1_000_000_000_000_000_000u128;
    (transaction(Some(0x02), &RECIPIENT, v), amount(v))
}

// --------------------------------------------------------------- harness

fn cs() -> ConstraintSystemRef<Fr> {
    ConstraintSystem::<Fr>::new_ref()
}

/// Runs the relation over a transaction and reports acceptance.
///
/// Rejection may be an unsatisfied system or an `Err`; neither yields a proof.
fn accepts(bytes: &[u8], recipient: &[u8; 20], amt: &[u8; 32]) -> bool {
    let c = cs();
    let buf = alloc_bounded(c.clone(), bytes, TEST_TRANSACTION_BYTES).unwrap();
    let len = FpVar::new_witness(c.clone(), || Ok(Fr::from(bytes.len() as u64))).unwrap();
    let intent = NativeIntent {
        recipient: alloc_bounded(c.clone(), recipient, 20).unwrap(),
        amount: alloc_bounded(c.clone(), amt, 32).unwrap(),
    };

    match NativeTransfer::verify(&buf, &len, &intent, &Boolean::TRUE) {
        Err(_) => false,
        Ok(()) => c.is_satisfied().unwrap_or(false),
    }
}

/// Convenience: run against the committed recipient.
fn accepts_genuine_intent(bytes: &[u8], amt: &[u8; 32]) -> bool {
    accepts(bytes, &RECIPIENT, amt)
}

// -------------------------------------------------------- positive cases

#[test]
fn accepts_a_genuine_transfer() {
    let (tx, amt) = genuine();
    assert!(
        accepts_genuine_intent(&tx, &amt),
        "rejected a genuine native transfer"
    );
}

/// Every accepted envelope shape: legacy, EIP-2930, EIP-1559.
///
/// The three have different item counts and put `to` and `value` at different
/// indices, so this is the test that the speculative decode-and-select works.
#[test]
fn accepts_every_supported_envelope() {
    let v = 5_000_000_000_000_000u128;
    for prefix in [None, Some(0x01), Some(0x02)] {
        let tx = transaction(prefix, &RECIPIENT, v);
        assert!(
            accepts_genuine_intent(&tx, &amount(v)),
            "rejected envelope {prefix:?}"
        );
    }
}

/// A value spanning the full width, where the RLP payload is 32 bytes and no
/// right-alignment shift applies.
#[test]
fn accepts_a_full_width_value() {
    let v = u128::MAX;
    let tx = transaction(Some(0x02), &RECIPIENT, v);
    assert!(accepts_genuine_intent(&tx, &amount(v)));
}

/// A one-byte value, which RLP writes bare. The right-alignment must place it
/// at the commitment's last byte.
#[test]
fn accepts_a_single_byte_value() {
    let tx = transaction(Some(0x02), &RECIPIENT, 1);
    assert!(accepts_genuine_intent(&tx, &amount(1)));
}

/// A value whose encoding needs the 0x80-prefixed form because the byte is at
/// or above 0x80. Distinguishes bare-byte handling from short-string handling.
#[test]
fn accepts_a_value_at_the_bare_byte_boundary() {
    for v in [0x7f, 0x80, 0x81] {
        let tx = transaction(Some(0x02), &RECIPIENT, v);
        assert!(
            accepts_genuine_intent(&tx, &amount(v)),
            "rejected value {v:#x}"
        );
    }
}

/// **A call carrying value is rejected**, even though it delivers the ETH.
///
/// A node settles by sending directly, so calldata never appears on a real
/// settlement. The constraint exists for the bounds: a call's payload is
/// unbounded and its receipt may carry any number of logs, which on mainnet
/// reaches 21KB against a bare send's 393 bytes. Without this the relation
/// would accept settlements no machine can prove.
#[test]
fn rejects_a_call_carrying_value() {
    let v = 1_000u128;
    let payload = enc_list(&[
        enc_int(1),
        enc_int(9),
        enc_int(1_500_000_000),
        enc_int(20_000_000_000),
        enc_int(100_000),
        enc_str(&RECIPIENT),
        enc_int(v),
        enc_str(&[0xde, 0xad, 0xbe, 0xef]),
        access_list(),
        enc_int(0),
        sig(),
        sig(),
    ]);
    let mut tx = vec![0x02];
    tx.extend_from_slice(&payload);
    assert!(
        !accepts_genuine_intent(&tx, &amount(v)),
        "accepted a settlement carrying calldata"
    );
}

/// A single calldata byte is still calldata.
#[test]
fn rejects_a_one_byte_call() {
    let v = 1_000u128;
    let payload = enc_list(&[
        enc_int(1),
        enc_int(9),
        enc_int(1_500_000_000),
        enc_int(20_000_000_000),
        enc_int(21_000),
        enc_str(&RECIPIENT),
        enc_int(v),
        enc_str(&[0x00]),
        access_list(),
        enc_int(0),
        sig(),
        sig(),
    ]);
    let mut tx = vec![0x02];
    tx.extend_from_slice(&payload);
    assert!(
        !accepts_genuine_intent(&tx, &amount(v)),
        "accepted a settlement carrying one calldata byte"
    );
}

/// A non-empty access list, which the relation must contain but never walks.
#[test]
fn accepts_a_non_empty_access_list() {
    let v = 42u128;
    let entry = enc_list(&[enc_str(&OTHER), enc_list(&[enc_str(&[0x01; 32])])]);
    let payload = enc_list(&[
        enc_int(1),
        enc_int(9),
        enc_int(1_500_000_000),
        enc_int(20_000_000_000),
        enc_int(21_000),
        enc_str(&RECIPIENT),
        enc_int(v),
        enc_str(&[]),
        enc_list(&[entry]),
        enc_int(0),
        sig(),
        sig(),
    ]);
    let mut tx = vec![0x02];
    tx.extend_from_slice(&payload);
    assert!(accepts_genuine_intent(&tx, &amount(v)));
}

// -------------------------------------------------------- negative cases

/// **Forgery: pay someone else.** The whole point of binding `to`.
#[test]
fn rejects_a_different_recipient() {
    let v = 1_000u128;
    let tx = transaction(Some(0x02), &OTHER, v);
    assert!(
        !accepts_genuine_intent(&tx, &amount(v)),
        "accepted a transfer to an uncommitted recipient"
    );
}

/// **Forgery: pay less than committed.**
#[test]
fn rejects_a_smaller_value() {
    let tx = transaction(Some(0x02), &RECIPIENT, 1);
    assert!(
        !accepts_genuine_intent(&tx, &amount(1_000_000)),
        "accepted a transfer of less than the committed amount"
    );
}

/// **Forgery: a zero-value transaction against a nonzero commitment.**
///
/// `rlp(0)` is the empty string, so its payload length is zero and every
/// commitment byte must be checked against nothing. If the right-alignment
/// treated absent bytes as matching, this would pass.
#[test]
fn rejects_a_zero_value() {
    let tx = transaction(Some(0x02), &RECIPIENT, 0);
    assert!(
        !accepts_genuine_intent(&tx, &amount(1_000_000)),
        "accepted a zero-value transaction"
    );
}

/// **Forgery: a value that shares its low bytes with the commitment.**
///
/// The right-alignment reads the payload from its end, so a longer value whose
/// tail matches must still be rejected on the leading bytes.
#[test]
fn rejects_a_value_sharing_its_low_bytes() {
    let committed = 0x1234u128;
    let paid = 0xff_1234u128;
    let tx = transaction(Some(0x02), &RECIPIENT, paid);
    assert!(
        !accepts_genuine_intent(&tx, &amount(committed)),
        "accepted a value whose low bytes match the commitment"
    );
}

/// **Forgery: a contract creation.** `to` is the empty string, so a naive
/// 20-byte read would pull zeros or neighbouring bytes.
#[test]
fn rejects_a_contract_creation() {
    let v = 1_000u128;
    let tx = transaction(Some(0x02), &[], v);
    assert!(
        !accepts_genuine_intent(&tx, &amount(v)),
        "accepted a contract creation as a settlement"
    );
}

/// **Forgery: a short `to`.** Anything but 20 bytes is not an address.
#[test]
fn rejects_a_short_to() {
    let v = 1_000u128;
    let tx = transaction(Some(0x02), &RECIPIENT[..19], v);
    assert!(
        !accepts_genuine_intent(&tx, &amount(v)),
        "accepted a 19-byte to"
    );
}

/// **Forgery: an unsupported envelope type.**
///
/// Blob (0x03) and set-code (0x04) transactions are excluded by spec 12.6.1,
/// and their layouts put different fields at the indices this relation reads.
/// The receipt relation accepts 0x03 and 0x04, so this asymmetry is easy to
/// get wrong by copying it.
#[test]
fn rejects_unsupported_envelope_types() {
    let v = 1_000u128;
    for t in [0x00u8, 0x03, 0x04, 0x05, 0x7f] {
        let mut tx = vec![t];
        tx.extend_from_slice(&transaction(Some(0x02), &RECIPIENT, v)[1..]);
        assert!(
            !accepts_genuine_intent(&tx, &amount(v)),
            "accepted envelope type {t:#04x}"
        );
    }
}

/// **Forgery: a legacy body wearing a typed prefix.**
///
/// A 9-item list behind an 0x02 prefix would put `value` where EIP-1559 keeps
/// `data` if the item count were not enforced per shape.
#[test]
fn rejects_a_type_mismatched_body() {
    let v = 1_000u128;
    let legacy = transaction(None, &RECIPIENT, v);

    let mut mislabelled = vec![0x02];
    mislabelled.extend_from_slice(&legacy);
    assert!(
        !accepts_genuine_intent(&mislabelled, &amount(v)),
        "accepted a legacy body behind an EIP-1559 prefix"
    );

    // And the reverse: a 12-item body with no prefix at all.
    let typed = transaction(Some(0x02), &RECIPIENT, v);
    assert!(
        !accepts_genuine_intent(&typed[1..], &amount(v)),
        "accepted an EIP-1559 body as legacy"
    );
}

/// **Out of scope: extra items appended to the list.**
///
/// A 13-item EIP-1559 list is not a transaction any block can include, and the
/// relation only sees transactions authenticated under `transactionsRoot`. The
/// gadget reads up to `data` and does not re-count trailing items, so in
/// isolation it accepts this; the walked prefix still fixes `to` and `value`.
#[test]
fn extra_items_are_left_to_inclusion() {
    let v = 1_000u128;
    let payload = enc_list(&[
        enc_int(1),
        enc_int(9),
        enc_int(1_500_000_000),
        enc_int(20_000_000_000),
        enc_int(21_000),
        enc_str(&RECIPIENT),
        enc_int(v),
        enc_str(&[]),
        access_list(),
        enc_int(0),
        sig(),
        sig(),
        enc_int(1),
    ]);
    let mut tx = vec![0x02];
    tx.extend_from_slice(&payload);
    assert!(
        accepts_genuine_intent(&tx, &amount(v)),
        "the item count is no longer re-validated in-circuit"
    );
}

/// **Forgery: trailing bytes after the list.**
///
/// The padded tail of a bounded buffer is prover-controlled. Without the
/// end-of-list check, a shorter real transaction could be followed by bytes
/// that a later read picks up.
#[test]
fn rejects_trailing_bytes() {
    let v = 1_000u128;
    let mut tx = transaction(Some(0x02), &RECIPIENT, v);
    let real_len = tx.len();
    tx.extend_from_slice(&[0xaa; 8]);

    let c = cs();
    let buf = alloc_bounded(c.clone(), &tx, TEST_TRANSACTION_BYTES).unwrap();
    // Claim the longer length: the list ends before it.
    let len = FpVar::new_witness(c.clone(), || Ok(Fr::from(tx.len() as u64))).unwrap();
    let intent = NativeIntent {
        recipient: alloc_bounded(c.clone(), &RECIPIENT, 20).unwrap(),
        amount: alloc_bounded(c.clone(), &amount(v), 32).unwrap(),
    };
    let accepted = match NativeTransfer::verify(&buf, &len, &intent, &Boolean::TRUE) {
        Err(_) => false,
        Ok(()) => c.is_satisfied().unwrap_or(false),
    };
    assert!(!accepted, "accepted a transaction with trailing bytes");
    assert_ne!(real_len, tx.len(), "fixture did not actually append");
}

/// **Forgery: a non-canonical value encoding.**
///
/// `0x82 0x00 0x01` encodes 1 with a leading zero. Accepting it would give a
/// prover two encodings of the same amount, and the right-alignment would read
/// the padded form as a different number.
#[test]
fn rejects_a_non_canonical_value() {
    let v = 1u128;
    let payload = enc_list(&[
        enc_int(1),
        enc_int(9),
        enc_int(1_500_000_000),
        enc_int(20_000_000_000),
        enc_int(21_000),
        enc_str(&RECIPIENT),
        vec![0x82, 0x00, 0x01],
        enc_str(&[]),
        access_list(),
        enc_int(0),
        sig(),
        sig(),
    ]);
    let mut tx = vec![0x02];
    tx.extend_from_slice(&payload);
    assert!(
        !accepts_genuine_intent(&tx, &amount(v)),
        "accepted a non-canonically encoded value"
    );
}

/// **Forgery: `to` as a list rather than a string.**
///
/// A list whose payload is 20 bytes has the same length as an address.
#[test]
fn rejects_a_list_shaped_to() {
    let v = 1_000u128;
    let payload = enc_list(&[
        enc_int(1),
        enc_int(9),
        enc_int(1_500_000_000),
        enc_int(20_000_000_000),
        enc_int(21_000),
        enc_list(&[enc_str(&[0x22; 19])]),
        enc_int(v),
        enc_str(&[]),
        access_list(),
        enc_int(0),
        sig(),
        sig(),
    ]);
    let mut tx = vec![0x02];
    tx.extend_from_slice(&payload);
    assert!(
        !accepts_genuine_intent(&tx, &amount(v)),
        "accepted a list where an address was required"
    );
}

/// The relation must be inert when inactive, so a caller running it
/// speculatively alongside another branch is not poisoned by it.
#[test]
fn inactive_relation_is_inert() {
    let c = cs();
    let garbage = vec![0xff; 40];
    let buf = alloc_bounded(c.clone(), &garbage, TEST_TRANSACTION_BYTES).unwrap();
    let len = FpVar::new_witness(c.clone(), || Ok(Fr::from(garbage.len() as u64))).unwrap();
    let intent = NativeIntent {
        recipient: alloc_bounded(c.clone(), &RECIPIENT, 20).unwrap(),
        amount: alloc_bounded(c.clone(), &amount(1), 32).unwrap(),
    };

    NativeTransfer::verify(&buf, &len, &intent, &Boolean::FALSE).unwrap();
    assert!(
        c.is_satisfied().unwrap(),
        "an inactive relation emitted a binding constraint"
    );
}

/// Cost, so a regression is visible in the diff.
#[test]
fn cost() {
    let c = cs();
    let (tx, amt) = genuine();
    let buf = alloc_bounded(c.clone(), &tx, TEST_TRANSACTION_BYTES).unwrap();
    let len = FpVar::new_witness(c.clone(), || Ok(Fr::from(tx.len() as u64))).unwrap();
    let intent = NativeIntent {
        recipient: alloc_bounded(c.clone(), &RECIPIENT, 20).unwrap(),
        amount: alloc_bounded(c.clone(), &amt, 32).unwrap(),
    };

    let before = c.num_constraints();
    NativeTransfer::verify(&buf, &len, &intent, &Boolean::TRUE).unwrap();
    println!(
        "  native transaction relation ({TEST_TRANSACTION_BYTES}-byte buffer): {}",
        c.num_constraints() - before
    );
    assert!(c.is_satisfied().unwrap());
}

// ---------------------------------------------------- crafted misparses

/// An EIP-1559 body from raw pieces, so a test can place bytes the RLP
/// encoder would never produce.
fn raw_1559(pieces: &[Vec<u8>]) -> Vec<u8> {
    let mut tx = vec![0x02];
    tx.extend_from_slice(&enc_list(pieces));
    tx
}

/// **Forgery: a list where an integer belongs.** Read with the string size
/// formula, `0xc1` claims 66 bytes instead of 2, so the walk would land on
/// bytes the prover planted as a second, fake `to` and `value`.
#[test]
fn rejects_a_list_before_to() {
    let v = 1_000u128;
    let tx = raw_1559(&[
        enc_int(1),
        vec![0xc1, 0x05],
        vec![0x00; 64],
        enc_int(1),
        enc_int(1),
        enc_int(21_000),
        enc_str(&RECIPIENT),
        enc_int(v),
        enc_str(&[]),
        access_list(),
        enc_int(0),
        sig(),
        sig(),
    ]);
    assert!(
        !accepts_genuine_intent(&tx, &amount(v)),
        "accepted a walk through a list-shaped integer"
    );
}

/// **Forgery: a 21-byte `to` whose first 20 bytes are the recipient.** The
/// trailing byte would read as a one-byte value, and the real (zero) value
/// as empty calldata.
#[test]
fn rejects_a_to_longer_than_an_address() {
    let mut to = vec![0x95];
    to.extend_from_slice(&RECIPIENT);
    to.push(0x01);
    let tx = raw_1559(&[
        enc_int(1),
        enc_int(9),
        enc_int(1),
        enc_int(1),
        enc_int(21_000),
        to,
        enc_int(0),
        enc_str(&[]),
        access_list(),
        enc_int(0),
        sig(),
        sig(),
    ]);
    assert!(
        !accepts_genuine_intent(&tx, &amount(1)),
        "accepted a 21-byte to as the recipient"
    );
}

/// **Forgery: a list header that is not the canonical long form.** The
/// header byte fixes where the items start; any other byte must fail.
#[test]
fn rejects_a_non_canonical_list_header() {
    let v = 1_000u128;
    let tx = transaction(Some(0x02), &RECIPIENT, v);
    assert_eq!(tx[1], 0xf8, "fixture should use a one-byte length");
    for header in [0xc0u8, 0xf7, 0xfa] {
        let mut bad = tx.clone();
        bad[1] = header;
        assert!(
            !accepts_genuine_intent(&bad, &amount(v)),
            "accepted list header {header:#x}"
        );
    }
}
