//! Adversarial suite for the ERC-20 receipt relation.
//!
//! Written before the implementation. Every negative case is a route to proving
//! a Transfer that did not happen as committed, which is a route to collecting
//! an escrow without settling.
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
/// is `crate::bounds::MAX_RECEIPT_BYTES`.
pub const TEST_RECEIPT_BYTES: usize = 1024;

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

/// keccak256("Transfer(address,address,uint256)")
pub fn transfer_topic0() -> [u8; 32] {
    mirage_encoding::keccak256(b"Transfer(address,address,uint256)")
}

/// A 32-byte topic holding a left-padded address.
pub fn addr_topic(addr: &[u8; 20]) -> Vec<u8> {
    let mut t = vec![0u8; 12];
    t.extend_from_slice(addr);
    t
}

/// One log: `[address, topics, data]`.
pub fn log_item(emitter: &[u8; 20], topics: &[Vec<u8>], data: &[u8]) -> Vec<u8> {
    enc_list(&[
        enc_str(emitter),
        enc_list(&topics.iter().map(|t| enc_str(t)).collect::<Vec<_>>()),
        enc_str(data),
    ])
}

/// A canonical ERC-20 Transfer log.
pub fn transfer_log(token: &[u8; 20], from: &[u8; 20], to: &[u8; 20], amount: &[u8; 32]) -> Vec<u8> {
    log_item(
        token,
        &[
            transfer_topic0().to_vec(),
            addr_topic(from),
            addr_topic(to),
        ],
        amount,
    )
}

/// A receipt: `[status, cumulativeGasUsed, logsBloom, logs]`, optionally with
/// an EIP-2718 type prefix.
pub fn receipt(status: u8, logs: &[Vec<u8>], type_prefix: Option<u8>) -> Vec<u8> {
    let payload = enc_list(&[
        enc_str(&[status]),
        enc_str(&[0x52, 0x08]),
        enc_str(&[0u8; 256]),
        enc_list(logs),
    ]);
    match type_prefix {
        Some(t) => {
            let mut out = vec![t];
            out.extend_from_slice(&payload);
            out
        }
        None => payload,
    }
}

pub const TOKEN: [u8; 20] = [0x11; 20];
pub const RECIPIENT: [u8; 20] = [0x22; 20];
pub const SENDER: [u8; 20] = [0x33; 20];

pub fn amount(v: u128) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[16..].copy_from_slice(&v.to_be_bytes());
    a
}

/// The genuine case: a type-2 receipt with one matching Transfer at index 0.
pub fn genuine() -> (Vec<u8>, usize, [u8; 32]) {
    let amt = amount(1_000_000);
    let r = receipt(
        1,
        &[transfer_log(&TOKEN, &SENDER, &RECIPIENT, &amt)],
        Some(0x02),
    );
    (r, 0, amt)
}

// --------------------------------------------------------------- harness

fn cs() -> ConstraintSystemRef<Fr> {
    ConstraintSystem::<Fr>::new_ref()
}

fn intent(token: &[u8; 20], recipient: &[u8; 20], amt: &[u8; 32], c: ConstraintSystemRef<Fr>) -> Intent<Fr> {
    Intent {
        token: alloc_bounded(c.clone(), token, 20).unwrap(),
        recipient: alloc_bounded(c.clone(), recipient, 20).unwrap(),
        amount: alloc_bounded(c, amt, 32).unwrap(),
    }
}

/// Runs a relation over a receipt and reports acceptance.
///
/// Rejection may be an unsatisfied system or an `Err`; neither yields a proof.
pub fn accepts<R: ReceiptRelation<Fr>>(
    receipt_bytes: &[u8],
    log_index: usize,
    token: &[u8; 20],
    recipient: &[u8; 20],
    amt: &[u8; 32],
) -> bool {
    let c = cs();
    let buf = alloc_bounded(c.clone(), receipt_bytes, TEST_RECEIPT_BYTES).unwrap();
    let len = FpVar::new_witness(c.clone(), || Ok(Fr::from(receipt_bytes.len() as u64))).unwrap();
    let idx = FpVar::new_witness(c.clone(), || Ok(Fr::from(log_index as u64))).unwrap();
    let i = intent(token, recipient, amt, c.clone());

    match R::verify(&buf, &len, &idx, &i, &Boolean::TRUE) {
        Err(_) => false,
        Ok(()) => c.is_satisfied().unwrap_or(false),
    }
}

/// Convenience: run against the genuine intent.
fn accepts_genuine_intent<R: ReceiptRelation<Fr>>(
    receipt_bytes: &[u8],
    log_index: usize,
    amt: &[u8; 32],
) -> bool {
    accepts::<R>(receipt_bytes, log_index, &TOKEN, &RECIPIENT, amt)
}

// -------------------------------------------------------- positive cases

/// The baseline.
pub fn accepts_genuine_receipt<R: ReceiptRelation<Fr>>() {
    let (r, idx, amt) = genuine();
    assert!(
        accepts_genuine_intent::<R>(&r, idx, &amt),
        "rejected a genuine Transfer receipt"
    );
}

/// Every accepted envelope shape (spec 12.6.1): legacy, and typed 0x01-0x04.
pub fn accepts_every_supported_envelope<R: ReceiptRelation<Fr>>() {
    let amt = amount(42);
    let log = transfer_log(&TOKEN, &SENDER, &RECIPIENT, &amt);

    for prefix in [None, Some(0x01), Some(0x02), Some(0x03), Some(0x04)] {
        let r = receipt(1, std::slice::from_ref(&log), prefix);
        assert!(
            accepts_genuine_intent::<R>(&r, 0, &amt),
            "rejected envelope {prefix:?}"
        );
    }
}

/// The Transfer need not be the first log.
pub fn accepts_a_later_log<R: ReceiptRelation<Fr>>() {
    let amt = amount(7);
    let other = log_item(&[0x99; 20], &[vec![0xab; 32]], &[0xcd; 8]);
    let r = receipt(
        1,
        &[
            other.clone(),
            other,
            transfer_log(&TOKEN, &SENDER, &RECIPIENT, &amt),
        ],
        Some(0x02),
    );
    assert!(
        accepts_genuine_intent::<R>(&r, 2, &amt),
        "rejected a Transfer at log index 2"
    );
}

/// Spec 12.4: any sender is valid. The relation must not constrain topic 1.
pub fn accepts_any_sender<R: ReceiptRelation<Fr>>() {
    let amt = amount(5);
    for from in [[0x00; 20], [0xff; 20], RECIPIENT, TOKEN] {
        let r = receipt(
            1,
            &[transfer_log(&TOKEN, &from, &RECIPIENT, &amt)],
            Some(0x02),
        );
        assert!(
            accepts_genuine_intent::<R>(&r, 0, &amt),
            "rejected sender {from:?}; topic 1 must be unconstrained"
        );
    }
}

/// The fixtures must be valid Ethereum encodings, or everything else is
/// grading the circuit against nonsense.
pub fn fixtures_are_well_formed() {
    assert_eq!(
        hex::encode(transfer_topic0()),
        "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
        "Transfer signature"
    );

    let t = addr_topic(&RECIPIENT);
    assert_eq!(t.len(), 32);
    assert!(t[..12].iter().all(|&b| b == 0), "topic must be left-padded");

    let (r, _, _) = genuine();
    assert_eq!(r[0], 0x02, "typed prefix");
    assert!(r.len() < TEST_RECEIPT_BYTES, "fixture exceeds the test bound");

    // logsBloom is 256 bytes, so its RLP header is 0xb9 0x01 0x00.
    let legacy = receipt(1, &[], None);
    let bloom_at = legacy.iter().position(|&b| b == 0xb9).unwrap();
    assert_eq!(&legacy[bloom_at..bloom_at + 3], &[0xb9, 0x01, 0x00]);
}

// -------------------------------------------------------- forgery cases

/// **Forgery: a failed transaction.**
///
/// `status == 0` means the transfer reverted. Accepting it proves a settlement
/// that never moved funds.
pub fn rejects_failed_status<R: ReceiptRelation<Fr>>() {
    let amt = amount(1);
    let r = receipt(
        0,
        &[transfer_log(&TOKEN, &SENDER, &RECIPIENT, &amt)],
        Some(0x02),
    );
    assert!(
        !accepts_genuine_intent::<R>(&r, 0, &amt),
        "accepted a receipt with status 0"
    );
}

/// **Forgery: a Transfer from a different token.**
///
/// The emitter must equal the committed token. Any ERC-20 emits the same event
/// signature, so without this check a worthless token's Transfer satisfies a
/// commitment to a valuable one.
pub fn rejects_wrong_emitter<R: ReceiptRelation<Fr>>() {
    let amt = amount(1);
    let r = receipt(
        1,
        &[transfer_log(&[0xee; 20], &SENDER, &RECIPIENT, &amt)],
        Some(0x02),
    );
    assert!(
        !accepts_genuine_intent::<R>(&r, 0, &amt),
        "accepted a Transfer emitted by a different token"
    );
}

/// **Forgery: a different recipient.**
pub fn rejects_wrong_recipient<R: ReceiptRelation<Fr>>() {
    let amt = amount(1);
    let r = receipt(
        1,
        &[transfer_log(&TOKEN, &SENDER, &[0xee; 20], &amt)],
        Some(0x02),
    );
    assert!(
        !accepts_genuine_intent::<R>(&r, 0, &amt),
        "accepted a Transfer to a different recipient"
    );
}

/// **Forgery: a different amount.**
pub fn rejects_wrong_amount<R: ReceiptRelation<Fr>>() {
    let sent = amount(1);
    let committed = amount(1_000_000);
    let r = receipt(
        1,
        &[transfer_log(&TOKEN, &SENDER, &RECIPIENT, &sent)],
        Some(0x02),
    );
    assert!(
        !accepts_genuine_intent::<R>(&r, 0, &committed),
        "accepted a Transfer for the wrong amount"
    );
}

/// **Forgery: a non-Transfer event.**
///
/// `Approval` has the same three-topic shape as `Transfer`: signature, owner,
/// spender, with the value in data. Without a topic-0 check an approval proves
/// a payment.
pub fn rejects_wrong_event_signature<R: ReceiptRelation<Fr>>() {
    let amt = amount(1);
    let approval = mirage_encoding::keccak256(b"Approval(address,address,uint256)");
    let r = receipt(
        1,
        &[log_item(
            &TOKEN,
            &[
                approval.to_vec(),
                addr_topic(&SENDER),
                addr_topic(&RECIPIENT),
            ],
            &amt,
        )],
        Some(0x02),
    );
    assert!(
        !accepts_genuine_intent::<R>(&r, 0, &amt),
        "accepted an Approval event as a Transfer"
    );
}

/// **Forgery: the wrong topic count.**
///
/// A Transfer has exactly three topics. A two-topic log shifts what the
/// relation reads as the recipient; a four-topic log lets an attacker append
/// data the relation ignores.
pub fn rejects_wrong_topic_count<R: ReceiptRelation<Fr>>() {
    let amt = amount(1);

    let two = receipt(
        1,
        &[log_item(
            &TOKEN,
            &[transfer_topic0().to_vec(), addr_topic(&RECIPIENT)],
            &amt,
        )],
        Some(0x02),
    );
    assert!(
        !accepts_genuine_intent::<R>(&two, 0, &amt),
        "accepted a two-topic log"
    );

    let four = receipt(
        1,
        &[log_item(
            &TOKEN,
            &[
                transfer_topic0().to_vec(),
                addr_topic(&SENDER),
                addr_topic(&RECIPIENT),
                vec![0xff; 32],
            ],
            &amt,
        )],
        Some(0x02),
    );
    assert!(
        !accepts_genuine_intent::<R>(&four, 0, &amt),
        "accepted a four-topic log"
    );
}

/// **Forgery: non-canonical recipient padding.**
///
/// Topic 2 must be twelve zero bytes then the address. A nonzero high byte
/// changes the topic while leaving the low 20 bytes intact, so a relation that
/// only compares the tail accepts a topic the chain never produced.
pub fn rejects_dirty_recipient_padding<R: ReceiptRelation<Fr>>() {
    let amt = amount(1);
    let mut topic = addr_topic(&RECIPIENT);
    topic[0] = 0x01;

    let r = receipt(
        1,
        &[log_item(
            &TOKEN,
            &[transfer_topic0().to_vec(), addr_topic(&SENDER), topic],
            &amt,
        )],
        Some(0x02),
    );
    assert!(
        !accepts_genuine_intent::<R>(&r, 0, &amt),
        "accepted a recipient topic with nonzero padding"
    );
}

/// **Forgery: data that is not exactly 32 bytes.**
///
/// Spec 12.6.2 requires exactly 32. A shorter field left-shifts the value; a
/// longer one leaves bytes the relation never inspects.
pub fn rejects_wrong_data_length<R: ReceiptRelation<Fr>>() {
    let amt = amount(1);

    for data_len in [16usize, 31, 33, 64] {
        let mut data = vec![0u8; data_len];
        let n = data_len.min(32);
        data[data_len - n..].copy_from_slice(&amt[32 - n..]);

        let r = receipt(
            1,
            &[log_item(
                &TOKEN,
                &[
                    transfer_topic0().to_vec(),
                    addr_topic(&SENDER),
                    addr_topic(&RECIPIENT),
                ],
                &data,
            )],
            Some(0x02),
        );
        assert!(
            !accepts_genuine_intent::<R>(&r, 0, &amt),
            "accepted a {data_len}-byte data field"
        );
    }
}

/// **Forgery: a log index past the end of the list.**
///
/// Selecting a log that does not exist must fail rather than read padding.
pub fn rejects_out_of_range_log_index<R: ReceiptRelation<Fr>>() {
    let (r, _, amt) = genuine();
    for idx in [1usize, 2, 7, 99] {
        assert!(
            !accepts_genuine_intent::<R>(&r, idx, &amt),
            "accepted log index {idx} in a one-log receipt"
        );
    }
}

/// **Forgery: an unsupported envelope type.**
///
/// Spec 12.6.1 fixes the accepted set. An unknown prefix must fail closed
/// rather than be skipped as though it were payload.
pub fn rejects_unsupported_envelope<R: ReceiptRelation<Fr>>() {
    let amt = amount(1);
    let log = transfer_log(&TOKEN, &SENDER, &RECIPIENT, &amt);
    for prefix in [0x00u8, 0x05, 0x7f] {
        let r = receipt(1, std::slice::from_ref(&log), Some(prefix));
        assert!(
            !accepts_genuine_intent::<R>(&r, 0, &amt),
            "accepted envelope type {prefix:#04x}"
        );
    }
}

/// **Forgery: a `logsBloom` that is not 256 bytes.**
///
/// Its length is fixed by consensus. A short bloom shifts every following
/// field, which moves what the relation reads as the logs list.
pub fn rejects_wrong_bloom_length<R: ReceiptRelation<Fr>>() {
    let amt = amount(1);
    let payload = enc_list(&[
        enc_str(&[1]),
        enc_str(&[0x52, 0x08]),
        enc_str(&[0u8; 128]), // half-length bloom
        enc_list(&[transfer_log(&TOKEN, &SENDER, &RECIPIENT, &amt)]),
    ]);
    let mut r = vec![0x02];
    r.extend_from_slice(&payload);

    assert!(
        !accepts_genuine_intent::<R>(&r, 0, &amt),
        "accepted a 128-byte logsBloom"
    );
}

/// **Forgery: a payload with the wrong field count.**
///
/// Spec 12.6.1 requires exactly four items. A fifth lets an attacker append a
/// field; a third shifts everything.
pub fn rejects_wrong_payload_field_count<R: ReceiptRelation<Fr>>() {
    let amt = amount(1);
    let five = enc_list(&[
        enc_str(&[1]),
        enc_str(&[0x52, 0x08]),
        enc_str(&[0u8; 256]),
        enc_list(&[transfer_log(&TOKEN, &SENDER, &RECIPIENT, &amt)]),
        enc_str(&[0xff; 4]),
    ]);
    let mut r = vec![0x02];
    r.extend_from_slice(&five);

    assert!(
        !accepts_genuine_intent::<R>(&r, 0, &amt),
        "accepted a five-item receipt payload"
    );
}

// ------------------------------------------------------------- the suite

pub fn run_forgeries<R: ReceiptRelation<Fr>>() {
    rejects_failed_status::<R>();
    rejects_wrong_emitter::<R>();
    rejects_wrong_recipient::<R>();
    rejects_wrong_amount::<R>();
    rejects_wrong_event_signature::<R>();
    rejects_wrong_topic_count::<R>();
    rejects_dirty_recipient_padding::<R>();
    rejects_wrong_data_length::<R>();
    rejects_out_of_range_log_index::<R>();
    rejects_unsupported_envelope::<R>();
    rejects_wrong_bloom_length::<R>();
    rejects_wrong_payload_field_count::<R>();
}

pub fn run_suite<R: ReceiptRelation<Fr>>() {
    accepts_genuine_receipt::<R>();
    accepts_every_supported_envelope::<R>();
    accepts_a_later_log::<R>();
    accepts_any_sender::<R>();
    run_forgeries::<R>();
}

/// The real relation against the full suite.
#[test]
fn adversarial_suite() {
    run_suite::<super::log::Erc20>();
}

/// The single-log variant against the same suite, minus the one case that
/// assumes a walk.
///
/// `accepts_a_later_log` is excluded by construction: the variant exists
/// precisely because there is no later log.
#[test]
fn single_log_adversarial_suite() {
    use super::log::Erc20SingleLog as R;
    accepts_genuine_receipt::<R>();
    accepts_every_supported_envelope::<R>();
    accepts_any_sender::<R>();
    run_forgeries::<R>();
}

/// The narrowing the variant trades for its saving: a receipt with a second
/// event must be rejected, where the general relation accepts it.
///
/// This is what makes the enclave's pre-settlement token review load-bearing
/// rather than advisory. A token with a transfer hook produces a receipt this
/// circuit cannot prove, and spec 12.9 puts that loss on the executor.
#[test]
fn single_log_rejects_a_second_event() {
    let amt = amount(9);
    let extra = log_item(&[0x99; 20], &[vec![0xab; 32]], &[0xcd; 8]);
    let r = receipt(
        1,
        &[transfer_log(&TOKEN, &SENDER, &RECIPIENT, &amt), extra],
        Some(0x02),
    );

    assert!(
        accepts::<super::log::Erc20>(&r, 0, &TOKEN, &RECIPIENT, &amt),
        "the general relation should accept a two-log receipt"
    );
    assert!(
        !accepts::<super::log::Erc20SingleLog>(&r, 0, &TOKEN, &RECIPIENT, &amt),
        "the single-log variant accepted a receipt with a second event"
    );
}

/// Both relations must agree on every single-log receipt, or the optimization
/// changed the relation rather than only its cost.
#[test]
fn variants_agree_on_single_log_receipts() {
    let amt = amount(1234);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("genuine", genuine().0),
        (
            "legacy envelope",
            receipt(1, &[transfer_log(&TOKEN, &SENDER, &RECIPIENT, &amt)], None),
        ),
        (
            "wrong recipient",
            receipt(
                1,
                &[transfer_log(&TOKEN, &SENDER, &[0xee; 20], &amt)],
                Some(0x02),
            ),
        ),
        (
            "failed status",
            receipt(
                0,
                &[transfer_log(&TOKEN, &SENDER, &RECIPIENT, &amt)],
                Some(0x02),
            ),
        ),
    ];

    for (name, r) in cases {
        let a = if name == "genuine" { genuine().2 } else { amt };
        let general = accepts::<super::log::Erc20>(&r, 0, &TOKEN, &RECIPIENT, &a);
        let single = accepts::<super::log::Erc20SingleLog>(&r, 0, &TOKEN, &RECIPIENT, &a);
        assert_eq!(general, single, "variants disagree on `{name}`");
    }
}

/// What the saving actually is.
#[test]
fn single_log_cost() {
    let (r, _, amt) = genuine();
    for bound in [512usize, 1024, 2048] {
        let mut costs = Vec::new();
        for single in [false, true] {
            let c = cs();
            let buf = alloc_bounded(c.clone(), &r, bound).unwrap();
            let len = FpVar::new_witness(c.clone(), || Ok(Fr::from(r.len() as u64))).unwrap();
            let idx = FpVar::new_witness(c.clone(), || Ok(Fr::from(0u64))).unwrap();
            let it = intent(&TOKEN, &RECIPIENT, &amt, c.clone());
            let before = c.num_constraints();
            if single {
                let _ = <super::log::Erc20SingleLog as ReceiptRelation<Fr>>::verify(
                    &buf, &len, &idx, &it, &Boolean::TRUE,
                );
            } else {
                let _ = <super::log::Erc20 as ReceiptRelation<Fr>>::verify(
                    &buf, &len, &idx, &it, &Boolean::TRUE,
                );
            }
            costs.push(c.num_constraints() - before);
        }
        println!(
            "{bound:>5} byte bound: general {:>8}, single-log {:>8}  ({:.0}% saved)",
            costs[0],
            costs[1],
            100.0 * (costs[0] - costs[1]) as f64 / costs[0] as f64
        );
    }
}

/// The number the whole receipt exercise was meant to produce: how much does
/// the relation cost at a realistic bound?
#[test]
fn cost() {
    for bound in [512usize, 1024, 2048] {
        let (r, idx, amt) = genuine();
        if r.len() > bound {
            continue;
        }
        let c = cs();
        let buf = alloc_bounded(c.clone(), &r, bound).unwrap();
        let len = FpVar::new_witness(c.clone(), || Ok(Fr::from(r.len() as u64))).unwrap();
        let i = FpVar::new_witness(c.clone(), || Ok(Fr::from(idx as u64))).unwrap();
        let it = intent(&TOKEN, &RECIPIENT, &amt, c.clone());
        let before = c.num_constraints();
        let _ = <super::log::Erc20 as ReceiptRelation<Fr>>::verify(
            &buf, &len, &i, &it, &Boolean::TRUE,
        );
        println!(
            "receipt relation, {bound} byte bound: {} constraints",
            c.num_constraints() - before
        );
    }
}

/// How much of the relation is the log walk?
///
/// The walk exists to reach log `k` of up to `MAX_LOGS`. If the scope is direct
/// ERC-20 transfers, which have exactly one log, all of it is waste.
#[test]
fn log_walk_cost() {
    let (r, _, amt) = genuine();
    let bound = 1024usize;

    let c = cs();
    let buf = alloc_bounded(c.clone(), &r, bound).unwrap();
    let len = FpVar::new_witness(c.clone(), || Ok(Fr::from(r.len() as u64))).unwrap();
    let before_env = c.num_constraints();
    let payload = super::envelope::parse(&buf, &len, &Boolean::TRUE).unwrap();
    let env = c.num_constraints() - before_env;

    let idx = FpVar::new_witness(c.clone(), || Ok(Fr::from(0u64))).unwrap();
    let before_walk = c.num_constraints();
    let log = super::log::select_log(&buf, &payload.logs, &idx, &Boolean::TRUE).unwrap();
    let walk = c.num_constraints() - before_walk;

    let it = intent(&TOKEN, &RECIPIENT, &amt, c.clone());
    let before_check = c.num_constraints();
    super::log::assert_transfer(&buf, &log, &it, &Boolean::TRUE).unwrap();
    let check = c.num_constraints() - before_check;

    println!("envelope parse:   {env}");
    println!("log walk:         {walk}   <- {} MAX_LOGS steps", crate::bounds::MAX_LOGS);
    println!("transfer checks:  {check}");
    println!("total:            {}", env + walk + check);
}

#[test]
fn fixture_sanity() {
    fixtures_are_well_formed();
}

/// A relation that enforces nothing, so the suite can be shown to have teeth.
pub struct Null;

impl<F: PrimeField> ReceiptRelation<F> for Null {
    fn verify(
        _receipt: &[UInt8<F>],
        _receipt_len: &FpVar<F>,
        _log_index: &FpVar<F>,
        _intent: &Intent<F>,
        _active: &Boolean<F>,
    ) -> Result<(), SynthesisError> {
        Ok(())
    }
}

/// Every forgery case must fail against a relation that enforces nothing.
///
/// A case that passes against `Null` is not testing anything, and would give
/// false confidence on the axis where it matters most.
#[test]
fn forgeries_defeat_the_null_relation() {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    let cases: Vec<(&str, fn())> = vec![
        ("failed_status", || rejects_failed_status::<Null>()),
        ("wrong_emitter", || rejects_wrong_emitter::<Null>()),
        ("wrong_recipient", || rejects_wrong_recipient::<Null>()),
        ("wrong_amount", || rejects_wrong_amount::<Null>()),
        ("wrong_event_signature", || {
            rejects_wrong_event_signature::<Null>()
        }),
        ("wrong_topic_count", || rejects_wrong_topic_count::<Null>()),
        ("dirty_recipient_padding", || {
            rejects_dirty_recipient_padding::<Null>()
        }),
        ("wrong_data_length", || rejects_wrong_data_length::<Null>()),
        ("out_of_range_log_index", || {
            rejects_out_of_range_log_index::<Null>()
        }),
        ("unsupported_envelope", || {
            rejects_unsupported_envelope::<Null>()
        }),
        ("wrong_bloom_length", || rejects_wrong_bloom_length::<Null>()),
        ("wrong_payload_field_count", || {
            rejects_wrong_payload_field_count::<Null>()
        }),
    ];

    for (name, case) in cases {
        assert!(
            catch_unwind(AssertUnwindSafe(case)).is_err(),
            "forgery case `{name}` passed against a relation that enforces \
             nothing, so it is not testing anything"
        );
    }
}
