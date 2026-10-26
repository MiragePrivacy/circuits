//! The ERC-20 delayed-witness receipt relation as a provable circuit.
//!
//! Wires `mirage-gadgets` into a `ConstraintSynthesizer` so a real Groth16
//! proof can be generated. That is the point of this crate: every memory and
//! timing figure recorded so far is *derived* from constraint counts, and only
//! an actual proving run replaces them with measurements.
//!
//! # Scope
//!
//! Wired: the intent commitment (8.3), the positive ancestry chain from the
//! statement's witness block to the hidden transaction block (12.7), header
//! parse (12.7.1), MPT inclusion (12.5), the ERC-20 relation (12.6), and the
//! statement hash (10.2).
//!
//! The statement names only the later witness block. The transaction block is
//! private, and the public data narrows it to
//! `witnessBlockNumber - [MIN, MAX]_WITNESS_DISTANCE` intersected with the
//! lease window (spec 12.11).
//!
//! The native-ETH counterpart is [`native::NativeCircuit`], a separate circuit
//! with its own verification key. Read its module docs before treating the two
//! as interchangeable: their constraint counts differ, so proving time
//! distinguishes the asset kind, which spec 12.9 forbids.
//! # What this relation does not prove
//!
//! It proves a matching Transfer exists somewhere in the transaction block, not
//! that a particular transaction produced it: the MPT key is a free witness
//! and no transaction identity reaches the statement. One on-chain Transfer
//! therefore satisfies every live row whose intent shares
//! `(token, recipient, amount)`, and the log's sender is unconstrained.
//!
//! That is closed by policy, not here: the nomad must never hold two live
//! requests with identical intents. Settlement soundness depends on that
//! invariant holding off-chain. See the "Carried by out-of-circuit policy"
//! section of `experiments/keccacheck-arkworks/RESULTS.md` for the analysis
//! and the alternatives if it stops being tenable.

pub mod native;

use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::convert::ToBitsGadget;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use mirage_gadgets::ancestry;
use mirage_gadgets::bytes::alloc_bounded;
use mirage_gadgets::keccak::{DirectPermutation, PermutationBackend};
use mirage_gadgets::mpt::{constructed_traverse::ConstructedLeafTraversal, ProofNode};
use mirage_gadgets::receipt::{log::Erc20FixedLayout, Intent, ReceiptRelation};
use mirage_gadgets::statement;

/// What this circuit does and does not include, so the measured numbers are
/// read correctly.
///
/// Included: the header chain from the witness block to the transaction block,
/// MPT inclusion of the receipt under the transaction header's `receiptsRoot`,
/// the full spec 12.6 ERC-20 relation over that receipt, and the statement
/// hash exposing two public signals.
pub const MEASUREMENT_SCOPE: &str =
    "commitment + header chain + MPT inclusion + ERC-20 relation + statement hash";

/// Prints an attributable constraint delta when `RELATION_PROFILE` is set.
///
/// This deliberately observes only `num_constraints`: it does not allocate
/// variables or otherwise change the circuit. Optimization branches use these
/// stable stage names so their deltas can be compared against one baseline.
pub(crate) fn profile<F: PrimeField>(cs: &ConstraintSystemRef<F>, stage: &str, last: &mut usize) {
    if std::env::var_os("RELATION_PROFILE").is_none() {
        return;
    }
    let now = cs.num_constraints();
    eprintln!("{stage:>24}: {:>10}", now - *last);
    *last = now;
    STAGE_MARKS.lock().unwrap().push((stage.to_string(), now));
}

static STAGE_MARKS: std::sync::Mutex<Vec<(String, usize)>> = std::sync::Mutex::new(Vec::new());

/// The `(stage, constraints so far)` marks recorded by the last profiled
/// synthesis, each stage ending at its mark. Empty unless `RELATION_PROFILE`
/// is set.
pub fn take_stage_marks() -> Vec<(String, usize)> {
    std::mem::take(&mut STAGE_MARKS.lock().unwrap())
}

/// Compiled bounds for this build.
#[derive(Clone, Copy)]
pub struct Bounds {
    pub node_bytes: usize,
    pub key_bytes: usize,
    pub receipt_bytes: usize,
    pub header_bytes: usize,
    pub depth: usize,
    /// Smallest private distance from the transaction block to the witness.
    pub min_distance: usize,
    /// Largest such distance; the chain has `max_distance + 1` header slots.
    pub max_distance: usize,
}

impl Default for Bounds {
    /// Universal tier for the current three-byte transaction-index-key policy.
    /// Such a key has at most six nibbles. Every branch consumes one nibble and
    /// every extension consumes at least one, so at most six ancestors plus
    /// the constructed terminal leaf can occur: total depth seven.
    fn default() -> Self {
        Self {
            node_bytes: 544,
            // `rlp(transactionIndex)`. Every index below 128 encodes bare, so
            // all 100 mainnet fixtures have a 1-byte key. Two bytes covers
            // indices to 255 via 0x81 0xNN, and three to 65535; blocks do not
            // reach 65k transactions, so 3 is the true worst case.
            //
            // Path matching iterates `key.len() * 2` times over two buffers, so
            // this is a direct multiplier on that sub-step.
            key_bytes: 3,
            // A canonical status receipt containing exactly one ERC-20
            // Transfer is at most 432 bytes, including a typed envelope and a
            // nine-byte cumulativeGasUsed item. The production policy already
            // rejects additional logs, so 448 retains 16 bytes above the
            // structural maximum rather than padding to a general receipt.
            receipt_bytes: 448,
            // Measured across 100 mainnet blocks: 632 to 655 bytes, a 23-byte
            // spread driven entirely by `extraData`. A Prague header with
            // 32-byte extraData and eight-byte integers is 670 bytes, and 679
            // is the last length that hashes in five Keccak blocks. Every
            // ancestry slot hashes exactly five, so headers must also be at
            // least 544 bytes; a Prague header is at least 609.
            header_bytes: 679,
            depth: 7,
            min_distance: mirage_gadgets::bounds::MIN_WITNESS_DISTANCE,
            max_distance: mirage_gadgets::bounds::MAX_WITNESS_DISTANCE,
        }
    }
}

impl Bounds {
    /// The header chain's shape.
    pub fn chain(&self) -> ancestry::Bounds {
        ancestry::Bounds {
            header_bytes: self.header_bytes,
            min_distance: self.min_distance,
            max_distance: self.max_distance,
        }
    }
}

/// The private witness. `None` yields a setup-only instance, which is what
/// `circuit_specific_setup` needs.
#[derive(Clone, Default)]
pub struct Witness {
    pub root: Vec<u8>,
    pub key: Vec<u8>,
    pub receipt: Vec<u8>,
    /// RLP headers `H[0..=d]`: the statement's witness block first, each
    /// following header the parent of the one before, and the transaction
    /// block whose `receiptsRoot` the trie hangs from last.
    pub headers: Vec<Vec<u8>>,
    /// Root first.
    pub nodes: Vec<Vec<u8>>,
    pub log_index: usize,
    /// The private opening of the escrow's stored `intentCommitment`.
    ///
    /// Replaces the previously free token/recipient/amount witnesses: those
    /// were unbound, so a prover could supply any triple and prove a Transfer
    /// matching it.
    pub intent: IntentOpening,
    /// Spec 10.2 context. Public on-chain; private here only to keep the
    /// Groth16 public-input vector at two elements.
    pub statement: StatementContext,
}

/// The spec 8.3 commitment opening, natively.
#[derive(Clone, Default)]
pub struct IntentOpening {
    pub instance_domain: [u8; 32],
    pub chain_id: u64,
    pub escrow: [u8; 20],
    pub request_id: [u8; 32],
    pub row_index: u32,
    /// 0 native, 1 ERC-20.
    pub asset_kind: u8,
    pub settlement_token: [u8; 20],
    pub recipient: [u8; 20],
    pub settlement_amount: [u8; 32],
    pub salt: [u8; 32],
}

/// The spec 10.2 fields, natively.
#[derive(Clone, Default)]
pub struct StatementContext {
    pub instance_domain: [u8; 32],
    pub chain_id: u64,
    pub escrow: [u8; 20],
    pub request_id: [u8; 32],
    pub row_index: u32,
    pub intent_commitment: [u8; 32],
    pub bond_attempt: u32,
    pub bond_start_block: u64,
    pub bond_deadline: u64,
    pub bonded_collector: [u8; 20],
    pub row_payout_asset: [u8; 20],
    pub row_payout_amount: [u8; 32],
    pub witness_block_number: u64,
    pub witness_block_hash: [u8; 32],
}

/// The relation.
#[derive(Clone)]
pub struct ReceiptCircuit {
    pub bounds: Bounds,
    pub witness: Option<Witness>,
}

impl ReceiptCircuit {
    /// A circuit shaped for setup, with no witness values.
    pub fn setup(bounds: Bounds) -> Self {
        Self {
            bounds,
            witness: None,
        }
    }

    pub fn prove(bounds: Bounds, witness: Witness) -> Self {
        Self {
            bounds,
            witness: Some(witness),
        }
    }

    fn w(&self) -> Witness {
        self.witness.clone().unwrap_or_default()
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for ReceiptCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        generate_constraints_with_backend(self, cs, &mut DirectPermutation)
    }
}

/// Experimental relation using one deferred Keccacheck batch instead of 38
/// directly arithmetized Keccak-f permutations.
#[derive(Clone)]
pub struct KeccacheckReceiptCircuit(pub ReceiptCircuit);

impl KeccacheckReceiptCircuit {
    pub fn setup(bounds: Bounds) -> Self {
        Self(ReceiptCircuit::setup(bounds))
    }

    pub fn prove(bounds: Bounds, witness: Witness) -> Self {
        Self(ReceiptCircuit::prove(bounds, witness))
    }
}

impl ConstraintSynthesizer<Fr> for KeccacheckReceiptCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let mut batch = mirage_keccacheck_arkworks::batch::KeccacheckBatch::new(cs.clone());
        generate_constraints_with_backend(self.0, cs.clone(), &mut batch)?;
        let before = cs.num_constraints();
        let result = batch.finish()?;
        if std::env::var_os("RELATION_PROFILE").is_some() {
            eprintln!(
                "{:>24}: {:>10} ({} -> {} permutations)",
                "Keccacheck verifier",
                cs.num_constraints() - before,
                result.recorded,
                result.padded,
            );
        }
        Ok(())
    }
}

pub fn generate_constraints_with_backend<F: PrimeField, B: PermutationBackend<F>>(
    circuit: ReceiptCircuit,
    cs: ConstraintSystemRef<F>,
    backend: &mut B,
) -> Result<(), SynthesisError> {
    let b = circuit.bounds;
    let w = circuit.w();
    let mut mark = cs.num_constraints();

    // ---- public inputs ----
    //
    // Exactly two, per spec 10.1: the statement hash's 128-bit limbs. Each
    // public input costs a scalar multiplication in the on-chain verifier
    // and a G1 point in the embedded verification key, so collapsing the
    // full context to two keeps the verifier fixed regardless of how many
    // fields the relation binds.
    let (want_hi, want_lo) = native_signals(&w.statement);
    let public_hi = FpVar::new_input(cs.clone(), || Ok(F::from(want_hi)))?;
    let public_lo = FpVar::new_input(cs.clone(), || Ok(F::from(want_lo)))?;

    // ---- witness allocation ----
    let key = alloc_bounded(cs.clone(), &w.key, b.key_bytes)?;
    let key_len = FpVar::new_witness(cs.clone(), || Ok(F::from(w.key.len() as u64)))?;

    let receipt = alloc_bounded(cs.clone(), &w.receipt, b.receipt_bytes)?;
    let receipt_len = FpVar::new_witness(cs.clone(), || Ok(F::from(w.receipt.len() as u64)))?;

    // The terminal leaf is constructed from the key remainder and receipt,
    // so only the at-most `depth - 1` ancestor nodes are witnesses.
    let ancestor_count = w.nodes.len().saturating_sub(1);
    let mut nodes = Vec::with_capacity(b.depth.saturating_sub(1));
    for i in 0..b.depth.saturating_sub(1) {
        // An active root is necessarily a branch: a root leaf is the
        // zero-ancestor case constructed below. With three-byte RLP
        // transaction-index keys, only first nibbles 0..=8 can occur, so
        // at most nine 33-byte child references plus seven empty slots,
        // an empty value and the three-byte list header fit in 308 bytes.
        // Deeper branches can occupy all sixteen slots: 16*33 bytes of
        // hash references, one empty value byte, and a three-byte list
        // header are exactly 532 bytes. These are structural maxima, not
        // sampled cutoffs.
        let node_bound = if i == 0 { 308 } else { 532 };
        let (bytes, len, active) = match w.nodes.get(i).filter(|_| i < ancestor_count) {
            Some(n) => (n.clone(), n.len(), true),
            None => (Vec::new(), 0, false),
        };
        nodes.push(ProofNode {
            bytes: alloc_bounded(cs.clone(), &bytes, node_bound)?,
            len: FpVar::new_witness(cs.clone(), || Ok(F::from(len as u64)))?,
            active: Boolean::new_witness(cs.clone(), || Ok(active))?,
        });
    }

    // The opened commitment, whose token/recipient/amount become the intent
    // the receipt relation checks. Opening it and then checking the log
    // against different values would defeat the whole exercise, so the same
    // allocations are used for both.
    let opening = alloc_opening(cs.clone(), &w.intent)?;
    let ctx = alloc_statement(cs.clone(), &w.statement)?;
    let intent = Intent {
        token: opening.settlement_token.clone(),
        recipient: opening.recipient.clone(),
        amount: opening.settlement_amount.clone(),
    };
    let log_index = FpVar::new_witness(cs.clone(), || Ok(F::from(w.log_index as u64)))?;
    profile(&cs, "allocation", &mut mark);

    // ---- the relation ----
    //
    // The chain of bindings is what makes this a proof rather than a
    // satisfiability check:
    //
    //   commitment ->  token/recipient/amount
    //   header     ->  receiptsRoot -> MPT inclusion -> receipt -> log
    //
    // The commitment is the escrow's stored value, carried into the
    // statement hash and therefore into the public signals. Opening it here
    // is what turns "some Transfer happened" into "the Transfer this escrow
    // committed to happened".
    mirage_gadgets::commitment::open_with(
        &opening,
        &ctx.intent_commitment,
        &Boolean::TRUE,
        backend,
    )?;
    profile(&cs, "intent commitment", &mut mark);

    // This is the ERC-20 relation, so the opening must be an ERC-20 intent.
    // A native opening forces `settlement_token` to zero, and the log walk
    // then requires address(0) to have emitted a Transfer. That is
    // unsatisfiable, but only because address(0) has no code. Pin the kind
    // directly rather than resting on that.
    opening.asset_kind.enforce_equal(&UInt8::constant(
        mirage_gadgets::commitment::ASSET_KIND_ERC20,
    ))?;

    // The commitment's deployment/request/row context must be the same
    // context whose statement hash the verifier checks. The commitment
    // hash alone only authenticates the opening internally.
    enforce_bytes_equal(&opening.instance_domain, &ctx.instance_domain)?;
    enforce_bytes_equal(&opening.chain_id, &ctx.chain_id)?;
    enforce_bytes_equal(&opening.escrow, &ctx.escrow)?;
    enforce_bytes_equal(&opening.request_id, &ctx.request_id)?;
    enforce_bytes_equal(&opening.row_index, &ctx.row_index)?;
    profile(&cs, "context equality", &mut mark);
    //
    // The transaction header supplies the root rather than the caller.
    // Accepting a caller-supplied root would let a prover invent a trie
    // containing whatever it liked. That header is reached by parent hashes
    // from the exact witness block the verifier selected.
    let parsed = ancestry::verify_with(
        cs.clone(),
        &w.headers,
        &b.chain(),
        &ctx.witness_block_hash,
        &fixed_be_value(&ctx.witness_block_number)?,
        backend,
    )?;
    profile(&cs, "header chain", &mut mark);

    // Settlement is valid only in the half-open/closed lease interval:
    // bondStartBlock < txBlockNumber <= bondDeadline.
    let bond_start = fixed_be_value(&ctx.bond_start_block)?;
    let bond_deadline = fixed_be_value(&ctx.bond_deadline)?;
    lt_u64(&bond_start, &parsed.number)?.enforce_equal(&Boolean::TRUE)?;
    lt_u64(&bond_deadline, &parsed.number)?.enforce_equal(&Boolean::FALSE)?;
    profile(&cs, "block/time checks", &mut mark);

    // The receipt is the MPT leaf's value, so inclusion binds the exact
    // bytes the log walk then inspects. Without that link the relation
    // would prove a Transfer in *some* receipt rather than one in this
    // block's trie.
    ConstructedLeafTraversal::verify_inclusion_with(
        &parsed.receipts_root,
        &key,
        &key_len,
        &receipt,
        &receipt_len,
        &nodes,
        backend,
    )?;
    profile(&cs, "MPT traversal", &mut mark);
    // The single-log variant: spec 20.3 requires production settlements be a
    // direct `transfer()` call, whose receipt carries exactly one event.
    // Skipping the walk to log `k` saves 16% of the receipt relation.
    //
    // The trade is that a receipt with any second event becomes unprovable,
    // which the enclave's pre-settlement token review must enforce rather
    // than the prover discovering it. See `receipt::log::sole_log`.
    Erc20FixedLayout::verify(&receipt, &receipt_len, &log_index, &intent, &Boolean::TRUE)?;
    profile(&cs, "receipt relation", &mut mark);

    // ---- statement hash ----
    //
    // Recomputed from privately supplied context and checked against the
    // two public signals. Every field is already public on-chain; hashing
    // them down only shrinks the verifier.
    let signals = statement::compute_with(&ctx, backend)?;
    statement::enforce(&signals, &public_hi, &public_lo, &Boolean::TRUE)?;
    profile(&cs, "statement hash", &mut mark);

    Ok(())
}

pub(crate) fn enforce_bytes_equal<F: PrimeField>(
    left: &[UInt8<F>],
    right: &[UInt8<F>],
) -> Result<(), SynthesisError> {
    assert_eq!(
        left.len(),
        right.len(),
        "bound fields must have the same width"
    );
    for (left, right) in left.iter().zip(right.iter()) {
        left.enforce_equal(right)?;
    }
    Ok(())
}

pub(crate) fn fixed_be_value<F: PrimeField>(bytes: &[UInt8<F>]) -> Result<FpVar<F>, SynthesisError> {
    let mut value = FpVar::zero();
    for byte in bytes {
        value =
            value * FpVar::constant(F::from(256u64)) + mirage_gadgets::bytes::byte_to_field(byte)?;
    }
    Ok(value)
}

/// Compares field elements that are required here to be unsigned 64-bit
/// integers. Range-constraining both operands prevents field wraparound from
/// changing the ordering relation.
pub(crate) fn lt_u64<F: PrimeField>(a: &FpVar<F>, b: &FpVar<F>) -> Result<Boolean<F>, SynthesisError> {
    let a_bits = a.to_bits_le()?;
    let b_bits = b.to_bits_le()?;
    for bit in a_bits.iter().skip(64).chain(b_bits.iter().skip(64)) {
        bit.enforce_equal(&Boolean::FALSE)?;
    }

    let mut equal = Boolean::TRUE;
    let mut less = Boolean::FALSE;
    for i in (0..64).rev() {
        less |= equal.clone() & !a_bits[i].clone() & b_bits[i].clone();
        equal &= !(a_bits[i].clone() ^ &b_bits[i]);
    }
    Ok(less)
}

/// The commitment opening as circuit bytes, in spec 8.3 widths.
pub(crate) fn alloc_opening<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    i: &IntentOpening,
) -> Result<mirage_gadgets::commitment::Opening<F>, SynthesisError> {
    let b = |v: &[u8], n: usize| alloc_bounded(cs.clone(), v, n);
    Ok(mirage_gadgets::commitment::Opening {
        instance_domain: b(&i.instance_domain, 32)?,
        chain_id: b(&mirage_encoding::u64_to_word(i.chain_id), 32)?,
        escrow: b(&i.escrow, 20)?,
        request_id: b(&i.request_id, 32)?,
        row_index: b(&i.row_index.to_be_bytes(), 4)?,
        asset_kind: b(&[i.asset_kind], 1)?[0].clone(),
        settlement_token: b(&i.settlement_token, 20)?,
        recipient: b(&i.recipient, 20)?,
        settlement_amount: b(&i.settlement_amount, 32)?,
        salt: b(&i.salt, 32)?,
    })
}

/// The statement context as circuit bytes, in spec 10.2 widths.
pub(crate) fn alloc_statement<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    c: &StatementContext,
) -> Result<statement::Context<F>, SynthesisError> {
    let b = |v: &[u8], n: usize| alloc_bounded(cs.clone(), v, n);
    Ok(statement::Context {
        instance_domain: b(&c.instance_domain, 32)?,
        chain_id: b(&mirage_encoding::u64_to_word(c.chain_id), 32)?,
        escrow: b(&c.escrow, 20)?,
        request_id: b(&c.request_id, 32)?,
        row_index: b(&c.row_index.to_be_bytes(), 4)?,
        intent_commitment: b(&c.intent_commitment, 32)?,
        bond_attempt: b(&c.bond_attempt.to_be_bytes(), 4)?,
        bond_start_block: b(&c.bond_start_block.to_be_bytes(), 8)?,
        bond_deadline: b(&c.bond_deadline.to_be_bytes(), 8)?,
        bonded_collector: b(&c.bonded_collector, 20)?,
        row_payout_asset: b(&c.row_payout_asset, 20)?,
        row_payout_amount: b(&c.row_payout_amount, 32)?,
        witness_block_number: b(&c.witness_block_number.to_be_bytes(), 8)?,
        witness_block_hash: b(&c.witness_block_hash, 32)?,
    })
}

/// The public signals for a witness, from the native reference encoder.
///
/// The verifier needs these to check a proof, and the escrow computes the same
/// values on-chain from its own storage.
pub fn public_signals(w: &Witness) -> (u128, u128) {
    native_signals(&w.statement)
}

/// The expected public signals, from the native reference encoder.
///
/// Computing them natively rather than in-circuit is deliberate: the circuit's
/// job is to prove it can reproduce them, and taking both sides from the same
/// implementation would prove nothing.
pub(crate) fn native_signals(c: &StatementContext) -> (u128, u128) {
    mirage_encoding::statement::Statement {
        instance_domain: c.instance_domain,
        chain_id: c.chain_id,
        escrow: c.escrow,
        request_id: c.request_id,
        row_index: c.row_index,
        intent_commitment: c.intent_commitment,
        bond_attempt: c.bond_attempt,
        bond_start_block: c.bond_start_block,
        bond_deadline: c.bond_deadline,
        bonded_collector: c.bonded_collector,
        row_payout_asset: c.row_payout_asset,
        row_payout_amount: c.row_payout_amount,
        witness_block_number: c.witness_block_number,
        witness_block_hash: c.witness_block_hash,
    }
    .public_signals()
}

/// Builds a witness whose receipt sits in a two-level trie.
///
/// Exposed so the prover crate measures the same shape the gadget tests do.
pub mod fixture {
    use super::Witness;

    /// The escrow address the fixture statement commits to.
    ///
    /// This is what a `CREATE` from `0x01..01` at nonce 0 produces, so a
    /// consumer can deploy the escrow at this address rather than relocating
    /// it. That matters because the escrow caches its EIP-712 domain separator
    /// over `address(this)` at construction: a copy moved after deployment
    /// carries the separator of wherever it was built, and every bond
    /// signature checked against it fails. Keeping the address reachable lets
    /// the whole fund/bond/collect chain run against this proof.
    pub const FIXTURE_ESCROW: [u8; 20] = [
        0x1c, 0x81, 0xa6, 0x1a, 0x40, 0x70, 0x17, 0xc5, 0x83, 0x97, 0xa4, 0x7d, 0x2a, 0xb2, 0x81,
        0x91, 0xb9, 0xb8, 0xec, 0x9b,
    ];

    pub fn enc_str(p: &[u8]) -> Vec<u8> {
        if p.len() == 1 && p[0] < 0x80 {
            return p.to_vec();
        }
        let mut out = Vec::new();
        if p.len() < 56 {
            out.push(0x80 + p.len() as u8);
        } else {
            let lb = trim(&p.len().to_be_bytes());
            out.push(0xb7 + lb.len() as u8);
            out.extend_from_slice(&lb);
        }
        out.extend_from_slice(p);
        out
    }

    pub fn enc_list(c: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = c.concat();
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

    pub fn trim(b: &[u8]) -> Vec<u8> {
        let first = b.iter().position(|&x| x != 0).unwrap_or(b.len() - 1);
        b[first..].to_vec()
    }

    pub fn keccak(b: &[u8]) -> [u8; 32] {
        mirage_encoding::keccak256(b)
    }

    pub fn hex_prefix(nibbles: &[u8], is_leaf: bool) -> Vec<u8> {
        let odd = nibbles.len() % 2 == 1;
        let flag = (if is_leaf { 2u8 } else { 0 }) | (if odd { 1 } else { 0 });
        let mut out = Vec::new();
        if odd {
            out.push((flag << 4) | nibbles[0]);
            for p in nibbles[1..].chunks(2) {
                out.push((p[0] << 4) | p[1]);
            }
        } else {
            out.push(flag << 4);
            for p in nibbles.chunks(2) {
                out.push((p[0] << 4) | p[1]);
            }
        }
        out
    }

    pub fn to_nibbles(b: &[u8]) -> Vec<u8> {
        b.iter().flat_map(|x| [x >> 4, x & 0x0f]).collect()
    }

    pub const TOKEN: [u8; 20] = [0x11; 20];
    pub const RECIPIENT: [u8; 20] = [0x22; 20];
    pub const SENDER: [u8; 20] = [0x33; 20];

    /// A receipt containing one canonical Transfer, in a two-level trie.
    pub fn genuine() -> Witness {
        let mut amount = [0u8; 32];
        amount[16..].copy_from_slice(&1_000_000u128.to_be_bytes());

        let topic0 = keccak(b"Transfer(address,address,uint256)");
        let mut from_topic = vec![0u8; 12];
        from_topic.extend_from_slice(&SENDER);
        let mut to_topic = vec![0u8; 12];
        to_topic.extend_from_slice(&RECIPIENT);

        let log = enc_list(&[
            enc_str(&TOKEN),
            enc_list(&[enc_str(&topic0), enc_str(&from_topic), enc_str(&to_topic)]),
            enc_str(&amount),
        ]);

        let payload = enc_list(&[
            enc_str(&[1]),
            enc_str(&[0x52, 0x08]),
            enc_str(&[0u8; 256]),
            enc_list(&[log]),
        ]);
        let mut receipt = vec![0x02];
        receipt.extend_from_slice(&payload);

        // Trie: root branch, leaf under the key's first nibble.
        let key = vec![0x35, 0x71];
        let nibbles = to_nibbles(&key);
        let leaf = enc_list(&[enc_str(&hex_prefix(&nibbles[1..], true)), enc_str(&receipt)]);

        let mut children: Vec<Vec<u8>> = (0..16).map(|_| enc_str(&[])).collect();
        children[nibbles[0] as usize] = enc_str(&keccak(&leaf));
        children.push(enc_str(&[]));
        let root_node = enc_list(&children);

        // The commitment opening, and the commitment the escrow would store.
        // Computed with the native encoder so the circuit proves it can
        // reproduce it rather than agreeing with itself.
        let intent = super::IntentOpening {
            instance_domain: [0x11; 32],
            chain_id: 1,
            // The address a CREATE from 0x01..01 at nonce 0 produces. The
            // escrow caches its EIP-712 domain separator over `address(this)`
            // at construction, so a consumer that wants a working `bond()` has
            // to deploy the contract rather than relocate it: a relocated copy
            // carries the separator of wherever it was built, and its bond
            // signatures no longer validate. A reachable address keeps the
            // whole fund/bond/collect chain exercisable.
            escrow: FIXTURE_ESCROW,
            request_id: [0x33; 32],
            row_index: 0,
            asset_kind: 1,
            settlement_token: TOKEN,
            recipient: RECIPIENT,
            settlement_amount: amount,
            salt: [0x77; 32],
        };
        let commitment = mirage_encoding::commitment::Intent {
            instance_domain: intent.instance_domain,
            chain_id: intent.chain_id,
            escrow: intent.escrow,
            request_id: intent.request_id,
            row_index: intent.row_index,
            asset_kind: mirage_encoding::AssetKind::Erc20,
            settlement_token: intent.settlement_token,
            recipient: intent.recipient,
            settlement_amount: intent.settlement_amount,
            salt: intent.salt,
        }
        .commitment();

        // The transaction header must carry the trie's actual root, or the
        // binding chain header -> receiptsRoot -> inclusion does not close.
        let root_hash = keccak(&root_node);
        let headers = header_chain(&[0x05; 32], &root_hash, TX_BLOCK_NUMBER, MIN_DISTANCE);
        let header_hash = keccak(&headers[0]);

        Witness {
            root: root_hash.to_vec(),
            key,
            receipt,
            headers,
            nodes: vec![root_node, leaf],
            log_index: 0,
            intent: intent.clone(),
            statement: super::StatementContext {
                instance_domain: [0x11; 32],
                chain_id: 1,
                escrow: FIXTURE_ESCROW,
                request_id: [0x33; 32],
                row_index: 0,
                // The escrow's stored commitment, so the opening above binds
                // to what the statement hash carries.
                intent_commitment: commitment,
                bond_attempt: 1,
                // A lease a real `bond()` can actually grant: the escrow sets
                // `bondStartBlock = block.number` and
                // `executionDeadline = block.number + BOND_DURATION_BLOCKS`,
                // which is 25. A wider lease makes the proof unusable by any
                // caller that bonded through the contract rather than by
                // writing storage, so the consumers of this fixture would have
                // to forge the bond state to spend it.
                bond_start_block: 20_999_900,
                bond_deadline: 20_999_925,
                bonded_collector: [0x55; 20],
                // An ERC-20 payout asset, not native. The escrow that consumes
                // this fixture is EscrowERC20, which rejects a zero payout
                // asset; a native payout belongs to the native relation.
                row_payout_asset: [0x77; 20],
                row_payout_amount: {
                    let mut a = [0u8; 32];
                    a[24..].copy_from_slice(&1_000_000_000u64.to_be_bytes());
                    a
                },
                witness_block_number: TX_BLOCK_NUMBER + MIN_DISTANCE as u64,
                witness_block_hash: header_hash,
            },
        }
    }

    /// The genuine fixture's hidden transaction block, inside its lease.
    pub const TX_BLOCK_NUMBER: u64 = 20_999_902;

    /// The distance every fixture uses unless a test says otherwise.
    pub const MIN_DISTANCE: usize = mirage_gadgets::bounds::MIN_WITNESS_DISTANCE;

    /// `[H[0], ..., H[distance]]`: a transaction header carrying both roots,
    /// extended by `distance` synthetic descendants. Witness header first.
    pub fn header_chain(
        transactions_root: &[u8; 32],
        receipts_root: &[u8; 32],
        tx_number: u64,
        distance: usize,
    ) -> Vec<Vec<u8>> {
        descendants(
            header_with_roots(transactions_root, receipts_root, tx_number),
            tx_number,
            distance,
        )
    }

    /// Extends an existing transaction header by `distance` synthetic
    /// descendants, each the child of the one after it. Witness header first.
    pub fn descendants(tx_header: Vec<u8>, tx_number: u64, distance: usize) -> Vec<Vec<u8>> {
        let mut chain = vec![tx_header];
        for k in 1..=distance as u64 {
            let parent = keccak(&chain[0]);
            chain.insert(0, header(&parent, &[0x0b; 32], &[0x0c; 32], tx_number + k));
        }
        chain
    }

    /// A 21-field post-Prague header carrying both trie roots.
    ///
    /// The native relation reads `transactionsRoot` as well, so it cannot use
    /// the placeholder the ERC-20 fixture leaves there.
    pub fn header_with_roots(
        transactions_root: &[u8; 32],
        receipts_root: &[u8; 32],
        number: u64,
    ) -> Vec<u8> {
        header(&[0x01; 32], transactions_root, receipts_root, number)
    }

    /// A 21-field post-Prague header with a chosen parent.
    pub fn header(
        parent_hash: &[u8; 32],
        transactions_root: &[u8; 32],
        receipts_root: &[u8; 32],
        number: u64,
    ) -> Vec<u8> {
        enc_list(&[
            enc_str(parent_hash),          // parentHash
            enc_str(&[0x02; 32]),          // ommersHash
            enc_str(&[0x03; 20]),          // beneficiary
            enc_str(&[0x04; 32]),          // stateRoot
            enc_str(transactions_root),    // transactionsRoot
            enc_str(receipts_root),        // receiptsRoot
            enc_str(&[0u8; 256]),          // logsBloom
            enc_str(&[]),                  // difficulty
            enc_str(&trim(&number.to_be_bytes())), // number
            enc_str(&[0x01, 0xc9, 0xc3, 0x80]),    // gasLimit
            enc_str(&[0x52, 0x08]),                // gasUsed
            enc_str(&[0x66, 0x00, 0x00, 0x00]),    // timestamp
            enc_str(&[]),                          // extraData
            enc_str(&[0x06; 32]),                  // prevRandao
            enc_str(&[0u8; 8]),                    // nonce
            enc_str(&[0x07]),                      // baseFeePerGas
            enc_str(&[0x08; 32]),                  // withdrawalsRoot
            enc_str(&[]),                          // blobGasUsed
            enc_str(&[]),                          // excessBlobGas
            enc_str(&[0x09; 32]),                  // parentBeaconBlockRoot
            enc_str(&[0x0a; 32]),                  // requestsHash
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_relations::gr1cs::ConstraintSystem;
    use fixture::{header_chain, keccak, MIN_DISTANCE, TX_BLOCK_NUMBER};

    fn refresh_commitment(w: &mut Witness) {
        w.statement.intent_commitment = mirage_encoding::commitment::Intent {
            instance_domain: w.intent.instance_domain,
            chain_id: w.intent.chain_id,
            escrow: w.intent.escrow,
            request_id: w.intent.request_id,
            row_index: w.intent.row_index,
            asset_kind: mirage_encoding::AssetKind::Erc20,
            settlement_token: w.intent.settlement_token,
            recipient: w.intent.recipient,
            settlement_amount: w.intent.settlement_amount,
            salt: w.intent.salt,
        }
        .commitment();
    }

    /// Rebuilds the chain over the genuine receipt root at `distance`, and the
    /// witness fields that name its head.
    fn rechain(w: &mut Witness, tx_number: u64, distance: usize) {
        let root: [u8; 32] = w.root.clone().try_into().unwrap();
        w.headers = header_chain(&[0x05; 32], &root, tx_number, distance);
        w.statement.witness_block_number = tx_number + distance as u64;
        w.statement.witness_block_hash = keccak(&w.headers[0]);
    }

    /// The batched circuit is the one that ships. Deferring every permutation
    /// to one GKR batch changes how Keccak is proved, not what the relation
    /// says, and keeps a 39-header chain cheap enough to synthesize per test.
    fn satisfied(w: Witness) -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        KeccacheckReceiptCircuit::prove(Bounds::default(), w)
            .generate_constraints(cs.clone())
            .unwrap();
        cs.finalize();
        cs.is_satisfied().unwrap()
    }

    fn assert_rejected(w: Witness, message: &str) {
        assert!(!satisfied(w), "{message}");
    }

    /// The ERC-20 relation must not accept a native-asset opening.
    ///
    /// A native opening forces `settlement_token` to zero, which the log walk
    /// then requires address(0) to have emitted. That is unsatisfiable only
    /// because address(0) has no code; the relation pins the kind directly.
    #[test]
    fn rejects_a_native_asset_opening() {
        let mut w = fixture::genuine();
        w.intent.asset_kind = 0;
        w.intent.settlement_token = [0u8; 20];
        refresh_commitment(&mut w);
        assert_rejected(w, "accepted a native opening in the ERC-20 relation");
    }

    /// A prover must not be able to substitute the settlement details: they
    /// come from the opened commitment, which the statement hash carries into
    /// the public signals.
    #[test]
    fn rejects_a_substituted_recipient() {
        let mut w = fixture::genuine();
        w.intent.recipient = [0xee; 20];
        assert_rejected(w, "accepted a recipient the commitment does not open to");
    }

    /// The same for the amount: pay less than committed, prove the full sum.
    #[test]
    fn rejects_a_substituted_amount() {
        let mut w = fixture::genuine();
        let mut smaller = [0u8; 32];
        smaller[31] = 1;
        w.intent.settlement_amount = smaller;
        assert_rejected(w, "accepted an amount the commitment does not open to");
    }

    #[test]
    fn rejects_a_commitment_from_another_context() {
        let mut w = fixture::genuine();
        // Keep the statement context fixed, but provide a perfectly valid
        // commitment and opening for a different domain/chain/escrow/request/row.
        w.intent.instance_domain = [0xa1; 32];
        w.intent.chain_id = 2;
        w.intent.escrow = [0xa2; 20];
        w.intent.request_id = [0xa3; 32];
        w.intent.row_index = 7;
        refresh_commitment(&mut w);
        assert_rejected(w, "accepted a commitment created for another context");
    }

    #[test]
    fn rejects_an_unauthenticated_header_hash() {
        let mut w = fixture::genuine();
        w.statement.witness_block_hash[0] ^= 1;
        assert_rejected(w, "accepted a header not named by the statement");
    }

    #[test]
    fn rejects_a_header_number_different_from_the_statement() {
        let mut w = fixture::genuine();
        w.statement.witness_block_number += 1;
        assert_rejected(w, "accepted a block number not named by the statement");
    }

    /// The lease binds the hidden transaction block, not the witness.
    #[test]
    fn rejects_blocks_outside_the_lease_window() {
        let mut at_start = fixture::genuine();
        at_start.statement.bond_start_block = TX_BLOCK_NUMBER;
        assert_rejected(at_start, "accepted a block at bondStartBlock");

        let mut after_deadline = fixture::genuine();
        after_deadline.statement.bond_deadline = TX_BLOCK_NUMBER - 1;
        assert_rejected(after_deadline, "accepted a block after bondDeadline");

        // Both bounds hold for the witness block, so only the transaction
        // block can be what the lease rejects.
        let mut witness_inside = fixture::genuine();
        witness_inside.statement.bond_start_block = TX_BLOCK_NUMBER;
        assert!(witness_inside.statement.witness_block_number > TX_BLOCK_NUMBER);
        assert_rejected(witness_inside, "checked the lease against the witness block");
    }

    #[test]
    fn rejects_a_tampered_receipt_byte() {
        let mut w = fixture::genuine();
        let last = w.receipt.len() - 1;
        w.receipt[last] ^= 1;
        assert_rejected(w, "accepted a receipt the trie does not hold");
    }

    #[test]
    fn genuine_witness_satisfies_the_circuit() {
        assert!(satisfied(fixture::genuine()), "rejected the genuine fixture");
    }

    #[test]
    fn accepts_the_maximum_distance() {
        let mut w = fixture::genuine();
        let max = Bounds::default().max_distance;
        rechain(&mut w, TX_BLOCK_NUMBER, max);
        assert!(satisfied(w), "rejected a chain at the maximum distance");
    }

    /// **Forgery: the transaction block named as its own witness.**
    ///
    /// The spec 5.3 exact-block statement this relation replaces.
    #[test]
    fn rejects_the_transaction_block_as_witness() {
        let mut w = fixture::genuine();
        rechain(&mut w, TX_BLOCK_NUMBER, 0);
        assert_rejected(w, "accepted a zero witness distance");
    }

    #[test]
    fn rejects_a_distance_below_the_minimum() {
        let mut w = fixture::genuine();
        rechain(&mut w, TX_BLOCK_NUMBER, MIN_DISTANCE - 1);
        assert_rejected(w, "accepted a witness closer than the minimum distance");
    }

    /// A chain longer than the slots loses its transaction header, so its
    /// receipt root is not the one the endpoint supplies.
    #[test]
    fn rejects_a_distance_above_the_maximum() {
        let mut w = fixture::genuine();
        let max = Bounds::default().max_distance;
        rechain(&mut w, TX_BLOCK_NUMBER, max + 1);
        assert_rejected(w, "accepted a chain longer than the compiled slots");
    }

    /// **Forgery: a fabricated ancestor carrying an invented receipts root.**
    ///
    /// The witness block is genuine, but the transaction header is not its
    /// ancestor.
    #[test]
    fn rejects_a_fabricated_transaction_header() {
        let mut w = fixture::genuine();
        let last = w.headers.len() - 1;
        w.headers[last] = fixture::header(
            &[0xfe; 32],
            &[0x05; 32],
            &w.root.clone().try_into().unwrap(),
            TX_BLOCK_NUMBER,
        );
        assert_rejected(w, "accepted a transaction header off the witness's ancestry");
    }

    #[test]
    fn keccacheck_records_every_header_permutation() {
        use mirage_keccacheck_arkworks::batch::KeccacheckBatch;

        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = ReceiptCircuit::prove(Bounds::default(), fixture::genuine());
        let mut batch = KeccacheckBatch::new(cs.clone());
        generate_constraints_with_backend(circuit, cs.clone(), &mut batch).unwrap();
        let before_batch_verifier = cs.num_constraints();
        let result = batch.finish().unwrap();
        eprintln!(
            "keccacheck relation: {} recorded, {} padded, {} non-GKR, {} GKR, {} total",
            result.recorded,
            result.padded,
            before_batch_verifier,
            result.profile.total,
            cs.num_constraints(),
        );
        // 32 relation permutations plus five per header slot.
        assert_eq!(result.recorded, 32 + 5 * (Bounds::default().max_distance + 1));
        assert_eq!(result.padded, 256);
        assert_eq!(cs.num_constraints(), ERC20_CONSTRAINTS);
        assert!(
            cs.is_satisfied().unwrap(),
            "unsatisfied: {:?}",
            cs.which_is_unsatisfied()
        );
    }

    const ERC20_CONSTRAINTS: usize = 3_074_926;

    #[test]
    fn batched_setup_and_prove_shapes_match() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        KeccacheckReceiptCircuit::setup(Bounds::default())
            .generate_constraints(cs.clone())
            .unwrap();
        assert_eq!(cs.num_constraints(), ERC20_CONSTRAINTS);
    }
}
