//! The native-ETH exact-block dual-trie relation as a provable circuit.
//!
//! The counterpart to [`crate::ReceiptCircuit`]. A native settlement moves ETH
//! in the transaction itself and emits no log, so the settled recipient and
//! amount come from the transaction's `to` and `value` rather than from a
//! `Transfer` event.
//!
//! # Why two tries
//!
//! The transaction names the payment; the receipt says whether it happened. A
//! transaction that reverts is still in the transactions trie and still carries
//! a `to` and a `value`, so a transaction-only proof proves an *attempt* to pay.
//!
//! Both tries are keyed by the same `rlp(transactionIndex)`, so one key serves
//! both walks — but they are two independent node arrays under two different
//! roots, and the traversal is the dominant cost in the whole relation. That is
//! the price of the native path.
//!
//! ```text
//! commitment              -> recipient / amount, asset kind native
//! header -> transactionsRoot -> MPT inclusion -> transaction -> to / value
//! header -> receiptsRoot     -> MPT inclusion -> receipt     -> status == 1
//! header -> keccak           -> statement's witnessBlockHash
//! header.number              -> bondStartBlock < n <= bondDeadline
//! statement context          -> keccak -> the two public signals
//! ```
//!
//! # Scope
//!
//! Step 3 of spec section 25: native ETH, transaction block public, no
//! delayed-witness ancestry. As with step 2 the transaction block is public,
//! which spec 5.3 marks testnet-only; step 5's ancestry chain is what closes
//! that.
//!
//! # This circuit's proving time leaks the asset kind
//!
//! Spec 12.9 requires the native path cost the same as the ERC-20 path, because
//! a settlement whose proving time identifies its asset kind splits the
//! anonymity set: an observer timing a collect learns whether it was ETH or a
//! token, which halves the candidate universe before any other analysis.
//!
//! This build does not satisfy that. It is a separate `ConstraintSynthesizer`
//! with its own verification key and its own constraint count, so the two paths
//! are distinguishable by timing. The choice is deliberate — a standalone
//! circuit gets the transaction parser reviewed in isolation and produces the
//! real constraint measurement that any unification would have to be designed
//! against — but it is a **release gate, not a detail**. Closing it means
//! either padding the cheaper relation to the dearer one's constraint count, or
//! merging both into one circuit whose asset kind selects which assertions bind.
//!
//! Until then this is testnet-only for the same class of reason step 2 is.

use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use mirage_gadgets::bytes::alloc_bounded;
use mirage_gadgets::commitment::ASSET_KIND_NATIVE;
use mirage_gadgets::header;
use mirage_gadgets::mpt::{traverse::Traversal, MptVerifier, ProofNode};
use mirage_gadgets::receipt::envelope;
use mirage_gadgets::statement;
use mirage_gadgets::transaction::{NativeIntent, NativeTransfer, TransactionRelation};

use crate::{
    alloc_opening, alloc_statement, enforce_bytes_equal, fixed_be_value, lt_u64, native_signals,
    Bounds, IntentOpening, StatementContext,
};

/// What this circuit does and does not include, so the measured numbers are
/// read correctly.
pub const MEASUREMENT_SCOPE: &str =
    "commitment + header + dual MPT inclusion + native transfer relation + statement hash";

/// Compiled bounds for the native build.
///
/// The receipt-side bounds are inherited from the ERC-20 relation, which
/// measured them against 100 mainnet blocks. The two new ones are the
/// transaction buffer and the transaction trie's node bound.
#[derive(Clone, Copy)]
pub struct NativeBounds {
    /// Receipt-trie and shared bounds.
    pub common: Bounds,
    /// The transaction buffer.
    ///
    /// A bare EIP-1559 value transfer is ~110 bytes and a legacy one less. The
    /// headroom covers a non-empty access list, which the relation must contain
    /// but never walks, and the same asymmetry the ERC-20 bounds keep: an
    /// over-tight bound makes a settlement unprovable at the executor's expense
    /// (spec 12.9), so headroom is cheap insurance.
    pub transaction_bytes: usize,
    /// The transaction trie's maximum node size.
    ///
    /// A transaction-trie branch node holds 16 hash references plus a value
    /// slot, the same structure as a receipt-trie branch, so 544 is the same
    /// structural worst case. The tries have the same shape because they carry
    /// the same number of entries under the same keys.
    pub transaction_node_bytes: usize,
    /// The transaction trie's maximum depth.
    ///
    /// Equal to the receipt trie's by construction: both are keyed by
    /// `rlp(transactionIndex)` over the same entry count, so they have the same
    /// depth for any block.
    pub transaction_depth: usize,
}

impl Default for NativeBounds {
    fn default() -> Self {
        let common = Bounds::default();
        Self {
            transaction_bytes: 512,
            transaction_node_bytes: common.node_bytes,
            transaction_depth: common.depth,
            common,
        }
    }
}

/// The private witness for a native settlement.
///
/// `None` yields a setup-only instance, which is what `circuit_specific_setup`
/// needs.
#[derive(Clone, Default)]
pub struct NativeWitness {
    /// The trie key, `rlp(transactionIndex)`. Shared by both tries.
    pub key: Vec<u8>,
    /// The RLP block header carrying both roots.
    pub header: Vec<u8>,

    /// The settling transaction, envelope included.
    pub transaction: Vec<u8>,
    /// The transaction's inclusion path under `transactionsRoot`, root first.
    pub transaction_nodes: Vec<Vec<u8>>,

    /// The matching receipt, envelope included.
    pub receipt: Vec<u8>,
    /// The receipt's inclusion path under `receiptsRoot`, root first.
    pub receipt_nodes: Vec<Vec<u8>>,

    /// The private opening of the escrow's stored `intentCommitment`.
    pub intent: IntentOpening,
    /// Spec 10.2 context.
    pub statement: StatementContext,
}

/// The native relation.
#[derive(Clone)]
pub struct NativeCircuit {
    pub bounds: NativeBounds,
    pub witness: Option<NativeWitness>,
}

impl NativeCircuit {
    /// A circuit shaped for setup, with no witness values.
    pub fn setup(bounds: NativeBounds) -> Self {
        Self {
            bounds,
            witness: None,
        }
    }

    pub fn prove(bounds: NativeBounds, witness: NativeWitness) -> Self {
        Self {
            bounds,
            witness: Some(witness),
        }
    }

    fn w(&self) -> NativeWitness {
        self.witness.clone().unwrap_or_default()
    }
}

/// Allocates a bounded node array for one trie.
fn alloc_nodes<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    nodes: &[Vec<u8>],
    depth: usize,
    node_bytes: usize,
) -> Result<Vec<ProofNode<F>>, SynthesisError> {
    let mut out = Vec::with_capacity(depth);
    for i in 0..depth {
        let (bytes, len, active) = match nodes.get(i) {
            Some(n) => (n.clone(), n.len(), true),
            None => (Vec::new(), 0, false),
        };
        out.push(ProofNode {
            bytes: alloc_bounded(cs.clone(), &bytes, node_bytes)?,
            len: FpVar::new_witness(cs.clone(), || Ok(F::from(len as u64)))?,
            active: Boolean::new_witness(cs.clone(), || Ok(active))?,
        });
    }
    Ok(out)
}

impl<F: PrimeField> ConstraintSynthesizer<F> for NativeCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let b = self.bounds;
        let w = self.w();

        // ---- public inputs ----
        //
        // Exactly two, as in the ERC-20 relation: the statement hash's 128-bit
        // limbs. Keeping the same public-input shape means the escrow's
        // verifier call site is identical for both asset kinds.
        let (want_hi, want_lo) = native_signals(&w.statement);
        let public_hi = FpVar::new_input(cs.clone(), || Ok(F::from(want_hi)))?;
        let public_lo = FpVar::new_input(cs.clone(), || Ok(F::from(want_lo)))?;

        // ---- witness allocation ----
        let header_bytes = alloc_bounded(cs.clone(), &w.header, b.common.header_bytes)?;
        let header_len = FpVar::new_witness(cs.clone(), || Ok(F::from(w.header.len() as u64)))?;

        // One key, both tries. The transaction and its receipt sit at the same
        // index in their respective tries, which is what makes the two proofs
        // about the same transaction rather than two unrelated ones.
        let key = alloc_bounded(cs.clone(), &w.key, b.common.key_bytes)?;
        let key_len = FpVar::new_witness(cs.clone(), || Ok(F::from(w.key.len() as u64)))?;

        let transaction = alloc_bounded(cs.clone(), &w.transaction, b.transaction_bytes)?;
        let transaction_len =
            FpVar::new_witness(cs.clone(), || Ok(F::from(w.transaction.len() as u64)))?;

        let receipt = alloc_bounded(cs.clone(), &w.receipt, b.common.receipt_bytes)?;
        let receipt_len = FpVar::new_witness(cs.clone(), || Ok(F::from(w.receipt.len() as u64)))?;

        let transaction_nodes = alloc_nodes(
            cs.clone(),
            &w.transaction_nodes,
            b.transaction_depth,
            b.transaction_node_bytes,
        )?;
        let receipt_nodes = alloc_nodes(
            cs.clone(),
            &w.receipt_nodes,
            b.common.depth,
            b.common.node_bytes,
        )?;

        let opening = alloc_opening(cs.clone(), &w.intent)?;
        let ctx = alloc_statement(cs.clone(), &w.statement)?;
        let intent = NativeIntent {
            recipient: opening.recipient.clone(),
            amount: opening.settlement_amount.clone(),
        };

        // ---- the relation ----

        // The commitment is the escrow's stored value, carried into the
        // statement hash and therefore into the public signals. Opening it is
        // what turns "some ETH moved" into "the payment this escrow committed
        // to happened".
        mirage_gadgets::commitment::open(&opening, &ctx.intent_commitment, &Boolean::TRUE)?;

        // This circuit proves native settlements only. `open` already enforces
        // that a native row's token is all-zero, but nothing in it fixes *which*
        // kind this is: without this the ERC-20 verification key and the native
        // one would each accept the other's asset kind, and an escrow holding a
        // token row could be collected by proving an ETH transfer of the same
        // amount to the same recipient.
        opening
            .asset_kind
            .enforce_equal(&UInt8::constant(ASSET_KIND_NATIVE))?;

        // The commitment's deployment/request/row context must be the same
        // context whose statement hash the verifier checks.
        enforce_bytes_equal(&opening.instance_domain, &ctx.instance_domain)?;
        enforce_bytes_equal(&opening.chain_id, &ctx.chain_id)?;
        enforce_bytes_equal(&opening.escrow, &ctx.escrow)?;
        enforce_bytes_equal(&opening.request_id, &ctx.request_id)?;
        enforce_bytes_equal(&opening.row_index, &ctx.row_index)?;

        // The header supplies both roots rather than the caller. Accepting
        // caller-supplied roots would let a prover invent tries containing
        // whatever it liked.
        let parsed = header::parse(&header_bytes, &header_len, &Boolean::TRUE)?;

        // Authenticate the header itself: parsing roots out of it is not useful
        // unless it is the exact witness block the verifier selected.
        let header_digest =
            mirage_gadgets::keccak::keccak256_var(&header_bytes, &header_len, &Boolean::TRUE)?;
        for (got, want) in header_digest.iter().zip(ctx.witness_block_hash.iter()) {
            UInt8::from_bits_le(got).enforce_equal(want)?;
        }
        let witness_number = fixed_be_value(&ctx.witness_block_number)?;
        parsed.number.enforce_equal(&witness_number)?;

        // Settlement is valid only in the half-open/closed lease interval:
        // bondStartBlock < txBlockNumber <= bondDeadline.
        let bond_start = fixed_be_value(&ctx.bond_start_block)?;
        let bond_deadline = fixed_be_value(&ctx.bond_deadline)?;
        lt_u64(&bond_start, &parsed.number)?.enforce_equal(&Boolean::TRUE)?;
        lt_u64(&bond_deadline, &parsed.number)?.enforce_equal(&Boolean::FALSE)?;

        // Trie one: the transaction is at `key` under `transactionsRoot`. This
        // binds the exact bytes the transfer relation then reads.
        Traversal::verify_inclusion(
            &parsed.transactions_root,
            &key,
            &key_len,
            &transaction,
            &transaction_len,
            &transaction_nodes,
        )?;

        // Trie two: the receipt is at the *same* key under `receiptsRoot`.
        // Sharing the key is what makes this the settling transaction's own
        // receipt rather than some other successful transaction's.
        Traversal::verify_inclusion(
            &parsed.receipts_root,
            &key,
            &key_len,
            &receipt,
            &receipt_len,
            &receipt_nodes,
        )?;

        // The transaction pays the committed recipient the committed amount.
        NativeTransfer::verify(&transaction, &transaction_len, &intent, &Boolean::TRUE)?;

        // And it succeeded. `envelope::parse` enforces `status == 1` along with
        // the canonical four-item payload; the logs it returns are ignored,
        // because a native transfer emits none and a call carrying value may
        // emit any.
        envelope::parse(&receipt, &receipt_len, &Boolean::TRUE)?;

        // ---- statement hash ----
        let signals = statement::compute(&ctx)?;
        statement::enforce(&signals, &public_hi, &public_lo, &Boolean::TRUE)?;

        Ok(())
    }
}

/// The public signals for a native witness, from the native reference encoder.
pub fn public_signals(w: &NativeWitness) -> (u128, u128) {
    native_signals(&w.statement)
}

/// Builds a native witness whose transaction and receipt sit in two two-level
/// tries under the same key.
///
/// Exposed so the prover crate measures the same shape the relation tests do.
pub mod fixture {
    use super::{NativeWitness, StatementContext};
    use crate::fixture::{enc_list, enc_str, hex_prefix, keccak, to_nibbles, trim};
    use crate::IntentOpening;

    pub const RECIPIENT: [u8; 20] = [0x22; 20];

    /// A one-branch trie over a single entry, returning `(root_hash, nodes)`.
    ///
    /// The same shape the ERC-20 fixture uses: a root branch whose child at the
    /// key's first nibble is the leaf holding `value`.
    fn single_entry_trie(key: &[u8], value: &[u8]) -> ([u8; 32], Vec<Vec<u8>>) {
        let nibbles = to_nibbles(key);
        let leaf = enc_list(&[enc_str(&hex_prefix(&nibbles[1..], true)), enc_str(value)]);

        let mut children: Vec<Vec<u8>> = (0..16).map(|_| enc_str(&[])).collect();
        children[nibbles[0] as usize] = enc_str(&keccak(&leaf));
        children.push(enc_str(&[]));
        let root_node = enc_list(&children);

        (keccak(&root_node), vec![root_node, leaf])
    }

    /// An EIP-1559 transaction paying `value` to `to`.
    fn transaction(to: &[u8; 20], value: &[u8; 32]) -> Vec<u8> {
        let payload = enc_list(&[
            enc_str(&[0x01]),                         // chainId
            enc_str(&[0x09]),                         // nonce
            enc_str(&[0x59, 0x68, 0x2f, 0x00]),       // maxPriorityFeePerGas
            enc_str(&[0x04, 0xa8, 0x17, 0xc8, 0x00]), // maxFeePerGas
            enc_str(&[0x52, 0x08]),                   // gasLimit
            enc_str(to),                              // to
            enc_str(&trim(value)),                    // value
            enc_str(&[]),                             // data
            enc_list(&[]),                            // accessList
            enc_str(&[]),                             // yParity
            enc_str(&[0x77; 32]),                     // r
            enc_str(&[0x88; 32]),                     // s
        ]);
        let mut out = vec![0x02];
        out.extend_from_slice(&payload);
        out
    }

    /// A successful EIP-1559 receipt with no logs, as a native transfer
    /// produces.
    fn receipt() -> Vec<u8> {
        let payload = enc_list(&[
            enc_str(&[1]),          // status
            enc_str(&[0x52, 0x08]), // cumulativeGasUsed
            enc_str(&[0u8; 256]),   // logsBloom
            enc_list(&[]),          // logs
        ]);
        let mut out = vec![0x02];
        out.extend_from_slice(&payload);
        out
    }

    /// A genuine native settlement: 1 ETH to the committed recipient, included
    /// in both tries at the same key.
    pub fn genuine() -> NativeWitness {
        let mut amount = [0u8; 32];
        amount[16..].copy_from_slice(&1_000_000_000_000_000_000u128.to_be_bytes());

        let key = vec![0x35, 0x71];
        let transaction = transaction(&RECIPIENT, &amount);
        let receipt = receipt();

        let (transactions_root, transaction_nodes) = single_entry_trie(&key, &transaction);
        let (receipts_root, receipt_nodes) = single_entry_trie(&key, &receipt);

        // A native row: asset kind 0 and an all-zero settlement token, which
        // `commitment::open` enforces are consistent.
        let intent = IntentOpening {
            instance_domain: [0x11; 32],
            chain_id: 1,
            escrow: [0x22; 20],
            request_id: [0x33; 32],
            row_index: 0,
            asset_kind: 0,
            settlement_token: [0u8; 20],
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
            asset_kind: mirage_encoding::AssetKind::Native,
            settlement_token: intent.settlement_token,
            recipient: intent.recipient,
            settlement_amount: intent.settlement_amount,
            salt: intent.salt,
        }
        .commitment();

        // The header must carry both tries' actual roots, or neither binding
        // chain closes.
        let header =
            crate::fixture::header_with_roots(&transactions_root, &receipts_root, 21_000_000);
        let header_hash = keccak(&header);

        NativeWitness {
            key,
            header,
            transaction,
            transaction_nodes,
            receipt,
            receipt_nodes,
            intent,
            statement: StatementContext {
                instance_domain: [0x11; 32],
                chain_id: 1,
                escrow: [0x22; 20],
                request_id: [0x33; 32],
                row_index: 0,
                intent_commitment: commitment,
                bond_attempt: 1,
                bond_start_block: 20_999_900,
                bond_deadline: 21_000_080,
                bonded_collector: [0x55; 20],
                // Zero for native ETH, per spec 10.2. The escrow that consumes
                // this fixture is EscrowNative, whose payout asset is ETH.
                row_payout_asset: [0u8; 20],
                row_payout_amount: {
                    let mut a = [0u8; 32];
                    a[24..].copy_from_slice(&1_000_000_000u64.to_be_bytes());
                    a
                },
                witness_block_number: 21_000_000,
                witness_block_hash: header_hash,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_relations::gr1cs::ConstraintSystem;

    /// Recomputes the stored commitment after a witness field is changed, so a
    /// test targets the assertion it names rather than failing on the
    /// commitment opening.
    fn refresh_commitment(w: &mut NativeWitness) {
        w.statement.intent_commitment = mirage_encoding::commitment::Intent {
            instance_domain: w.intent.instance_domain,
            chain_id: w.intent.chain_id,
            escrow: w.intent.escrow,
            request_id: w.intent.request_id,
            row_index: w.intent.row_index,
            asset_kind: if w.intent.asset_kind == 0 {
                mirage_encoding::AssetKind::Native
            } else {
                mirage_encoding::AssetKind::Erc20
            },
            settlement_token: w.intent.settlement_token,
            recipient: w.intent.recipient,
            settlement_amount: w.intent.settlement_amount,
            salt: w.intent.salt,
        }
        .commitment();
    }

    fn satisfied(w: NativeWitness) -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        NativeCircuit::prove(NativeBounds::default(), w)
            .generate_constraints(cs.clone())
            .unwrap();
        cs.is_satisfied().unwrap()
    }

    fn assert_rejected(w: NativeWitness, message: &str) {
        assert!(!satisfied(w), "{message}");
    }

    #[test]
    fn accepts_a_genuine_native_settlement() {
        assert!(
            satisfied(fixture::genuine()),
            "rejected a genuine native settlement"
        );
    }

    /// **Forgery: pay a different recipient.**
    #[test]
    fn rejects_a_substituted_recipient() {
        let mut w = fixture::genuine();
        w.intent.recipient = [0x99; 20];
        refresh_commitment(&mut w);
        assert_rejected(w, "accepted a transfer to an uncommitted recipient");
    }

    /// **Forgery: claim a larger amount than the transaction paid.**
    #[test]
    fn rejects_a_substituted_amount() {
        let mut w = fixture::genuine();
        w.intent.settlement_amount[16..].copy_from_slice(&2u128.to_be_bytes());
        refresh_commitment(&mut w);
        assert_rejected(w, "accepted an amount the transaction did not pay");
    }

    /// **Forgery: an ERC-20 commitment proved through the native circuit.**
    ///
    /// Without the asset-kind pin, an escrow holding a token row could be
    /// collected by sending the same amount of ETH to the same recipient.
    #[test]
    fn rejects_an_erc20_asset_kind() {
        let mut w = fixture::genuine();
        w.intent.asset_kind = 1;
        w.intent.settlement_token = [0x11; 20];
        refresh_commitment(&mut w);
        assert_rejected(w, "accepted an ERC-20 row through the native relation");
    }

    /// **Forgery: a reverted transaction.**
    ///
    /// The transaction is in the trie and names the right `to` and `value`, but
    /// moved nothing. This is the case the receipt trie exists to catch.
    #[test]
    fn rejects_a_reverted_transaction() {
        let mut w = fixture::genuine();

        // Rebuild the receipt with status 0 and re-root its trie, so the only
        // thing wrong is the status.
        let payload = crate::fixture::enc_list(&[
            crate::fixture::enc_str(&[]), // status 0, RLP-encoded as empty
            crate::fixture::enc_str(&[0x52, 0x08]),
            crate::fixture::enc_str(&[0u8; 256]),
            crate::fixture::enc_list(&[]),
        ]);
        let mut failed = vec![0x02];
        failed.extend_from_slice(&payload);

        let nibbles = crate::fixture::to_nibbles(&w.key);
        let leaf = crate::fixture::enc_list(&[
            crate::fixture::enc_str(&crate::fixture::hex_prefix(&nibbles[1..], true)),
            crate::fixture::enc_str(&failed),
        ]);
        let mut children: Vec<Vec<u8>> = (0..16).map(|_| crate::fixture::enc_str(&[])).collect();
        children[nibbles[0] as usize] = crate::fixture::enc_str(&crate::fixture::keccak(&leaf));
        children.push(crate::fixture::enc_str(&[]));
        let root_node = crate::fixture::enc_list(&children);

        w.receipt = failed;
        w.receipt_nodes = vec![root_node.clone(), leaf];
        w.header = crate::fixture::header_with_roots(
            &crate::fixture::keccak(&w.transaction_nodes[0]),
            &crate::fixture::keccak(&root_node),
            21_000_000,
        );
        w.statement.witness_block_hash = crate::fixture::keccak(&w.header);

        assert_rejected(w, "accepted a reverted transaction as a settlement");
    }

    /// **Forgery: a header whose transactionsRoot is not the trie's.**
    ///
    /// The root must come from the header, or a prover invents a trie.
    #[test]
    fn rejects_a_foreign_transactions_root() {
        let mut w = fixture::genuine();
        w.header = crate::fixture::header_with_roots(
            &[0xab; 32],
            &crate::fixture::keccak(&w.receipt_nodes[0]),
            21_000_000,
        );
        w.statement.witness_block_hash = crate::fixture::keccak(&w.header);
        assert_rejected(w, "accepted a transactions root the header does not carry");
    }

    /// **Forgery: settle outside the bonded lease window.**
    #[test]
    fn rejects_a_block_outside_the_lease() {
        let mut w = fixture::genuine();
        w.statement.bond_start_block = 21_000_000;
        assert_rejected(w, "accepted a block at bondStartBlock");

        let mut w = fixture::genuine();
        w.statement.bond_deadline = 20_999_999;
        assert_rejected(w, "accepted a block past bondDeadline");
    }

    /// The two tries must be walked with the same key, or the receipt proves
    /// some other transaction succeeded.
    #[test]
    fn rejects_a_receipt_at_a_different_key() {
        let mut w = fixture::genuine();

        // Rebuild the receipt trie under a different key, and point the header
        // at it, so inclusion holds there but not at the transaction's key.
        let other_key = vec![0x46, 0x82];
        let nibbles = crate::fixture::to_nibbles(&other_key);
        let leaf = crate::fixture::enc_list(&[
            crate::fixture::enc_str(&crate::fixture::hex_prefix(&nibbles[1..], true)),
            crate::fixture::enc_str(&w.receipt),
        ]);
        let mut children: Vec<Vec<u8>> = (0..16).map(|_| crate::fixture::enc_str(&[])).collect();
        children[nibbles[0] as usize] = crate::fixture::enc_str(&crate::fixture::keccak(&leaf));
        children.push(crate::fixture::enc_str(&[]));
        let root_node = crate::fixture::enc_list(&children);

        w.receipt_nodes = vec![root_node.clone(), leaf];
        w.header = crate::fixture::header_with_roots(
            &crate::fixture::keccak(&w.transaction_nodes[0]),
            &crate::fixture::keccak(&root_node),
            21_000_000,
        );
        w.statement.witness_block_hash = crate::fixture::keccak(&w.header);

        assert_rejected(w, "accepted a receipt from a different trie key");
    }

    /// Constraint count, so a cost regression is visible in the diff.
    #[test]
    fn cost() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        NativeCircuit::prove(NativeBounds::default(), fixture::genuine())
            .generate_constraints(cs.clone())
            .unwrap();
        println!("  native relation: {} constraints", cs.num_constraints());
        assert!(cs.is_satisfied().unwrap());
    }
}
