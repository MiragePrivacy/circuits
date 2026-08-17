//! The traversal: walk root to leaf, authenticating each step.
//!
//! # The invariants
//!
//! Every one of these is a forgery case in [`super::tests`]. Dropping any lets
//! a prover show a receipt that is not in the trie, which is collecting an
//! escrow without settling.
//!
//! 1. **Anchoring.** `keccak(node[0])` equals the claimed root.
//! 2. **Linking.** `keccak(node[i])` equals the reference selected in
//!    `node[i-1]`.
//! 3. **Nibble selection.** The child followed from a branch is the one at the
//!    key's current nibble, not a free choice.
//! 4. **Path matching.** An extension's or leaf's hex-prefix path equals the
//!    next key nibbles.
//! 5. **Exact consumption.** The walk terminates at a leaf having consumed the
//!    key entirely — no more, no less.
//! 6. **Value binding.** The terminating leaf's value equals the claimed value.
//! 7. **Inert tail.** Slots past the real depth contribute nothing and cannot
//!    be activated to extend the trie.
//!
//! # Shape
//!
//! Depth is a witness, so all `MAX_DEPTH` levels are evaluated and the results
//! selected. Each level computes both the branch interpretation and the short
//! interpretation, then selects on the node's actual shape — R1CS has no
//! branching, so both are paid for regardless.
//!
//! That is why per-level cost is what governs the whole relation: it multiplies
//! by depth with no discount for shallow tries.

use ark_ff::PrimeField;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::gr1cs::SynthesisError;

use super::node::{branch_child_offset, decode_branch, decode_short, is_branch};
use super::path::{assert_canonical_flags, assert_even_pad_is_zero, nibble_at, read_flags};
use super::{MptVerifier, ProofNode};
use crate::bytes::{lt as less_than, one_hot, select_byte_with, select_bytes, zero_like};
use crate::keccak::keccak256_var;

/// # Conditional enforcement: the rule this module exists to demonstrate
///
/// A circuit cannot branch, so a caller that does not know a node's shape runs
/// both interpretations and selects. That only works when each is *total* —
/// computing a possibly-wrong answer rather than emitting a false constraint.
/// A gadget that asserts is not total, and a false constraint does not select
/// away: one speculative call poisons the whole proof.
///
/// So `RlpDecoder`, both node decoders, `branch_child_hash`, `prefix_mask` and
/// `keccak256_var` all take an `active` flag, and the traversal derives
/// `branch_active` / `short_active` from `is_branch`.
///
/// **But do not gate everything.** `bytes::one_hot`, `path::halve` and
/// `path::is_even` look like candidates and are not: their constraints are
/// *definitional*, chosen to be satisfiable for any input. Gating them would
/// leave their witnesses free for a prover to pick. Pinned by
/// `bytes::tests::one_hot_is_satisfiable_out_of_range` and
/// `path::tests::nibble_reads_stay_satisfiable_at_any_offset`.
///
/// The rule: **gate assertions about the caller's data; never gate a constraint
/// that defines a witness.**
///
/// Cost is unaffected either way — `conditional_enforce_equal` costs what
/// `enforce_equal` does.
///
/// # Debugging note
///
/// Four wrong guesses preceded the actual bug, which was `total_nibbles`
/// computed from the padded buffer width rather than a witnessed key length.
/// What found it was `harness::stage_map` plus per-sub-step constraint markers:
/// the failure sat two constraints past the level-1 tail read, which named the
/// culprit exactly. Reach for that before reasoning about which invariant looks
/// suspicious.
///
/// Per-sub-step constraint counts, collected when `MPT_PROFILE` is set.
///
/// Kept rather than deleted: the traversal is the dominant cost in the whole
/// relation, and every optimization needs a before/after on the same
/// breakdown. Run
/// `MPT_PROFILE=1 cargo test -p mirage-gadgets --release traverse::tests::profile -- --nocapture`.
fn profile<F: PrimeField>(buf: &[UInt8<F>], step: &str, last: &mut usize) {
    if std::env::var("MPT_PROFILE").is_err() {
        return;
    }
    use ark_r1cs_std::GR1CSVar;
    if let Some(b) = buf.first() {
        let now = b.cs().num_constraints();
        eprintln!("{:>12}  {step}", now - *last);
        *last = now;
    }
}

pub struct Traversal;

impl<F: PrimeField> MptVerifier<F> for Traversal {
    fn verify_inclusion(
        root: &[UInt8<F>],
        key: &[UInt8<F>],
        key_len: &FpVar<F>,
        value: &[UInt8<F>],
        value_len: &FpVar<F>,
        nodes: &[ProofNode<F>],
    ) -> Result<(), SynthesisError> {
        // What the next node's hash must equal. Starts as the claimed root
        // (invariant 1) and is replaced at each level by the selected child
        // reference (invariant 2).
        let mut expected: Vec<UInt8<F>> = root.to_vec();

        // How many key nibbles have been consumed. Derived from the key
        // buffer so it carries a constraint system; a bare FpVar::zero() is a
        // constant and yields MissingCS when a gadget allocates from it.
        let mut consumed = zero_like(key)?;

        // Whether the walk has already terminated at a leaf. Once set, later
        // levels must be inactive (invariant 7).
        let mut finished = Boolean::FALSE;

        // Twice the *witnessed* key length, not the buffer width.
        let total_nibbles = key_len * FpVar::constant(F::from(2u64));

        // The terminating leaf's node buffer and tail bounds, selected across
        // levels so the value comparison runs exactly once.
        let mut term_node: Vec<UInt8<F>> =
            nodes[0].bytes.iter().map(|_| UInt8::constant(0)).collect();
        let mut term_offset = zero_like(key)?;
        let mut term_len = zero_like(key)?;

        for level in nodes.iter() {
            let mut mark = level
                .bytes
                .first()
                .map(|b| {
                    use ark_r1cs_std::GR1CSVar;
                    b.cs().num_constraints()
                })
                .unwrap_or(0);
            let active = level.active.clone();

            // ---- invariant 1 and 2: this node hashes to what we expect ----
            //
            // Computed unconditionally: an inactive slot has zero length and
            // hashes to the empty-input digest, which will not match, so the
            // comparison is gated on `active` rather than the hash itself.
            let digest = keccak256_var(&level.bytes, &level.len, &active)?;
            for (d, e) in digest.iter().zip(expected.iter()) {
                let d_byte = bits_to_byte(d)?;
                d_byte.conditional_enforce_equal(e, &active)?;
            }

            // ---- decode both shapes, each gated on which it actually is ----
            //
            // `is_branch` only inspects the outer list and its first two items,
            // so it is total on any well-formed node and can bind on `active`
            // alone. The two full decoders are not total: each asserts its own
            // item count, so running both unconditionally makes every proof
            // unsatisfiable. Their assertions bind only for the matching shape.
            profile(&level.bytes, "link-hash", &mut mark);
            let this_is_branch = is_branch(&level.bytes, &level.len, &active)?;
            let branch_active = active.clone() & this_is_branch.clone();
            let short_active = active.clone() & !this_is_branch.clone();

            profile(&level.bytes, "is_branch", &mut mark);
            let branch = decode_branch(&level.bytes, &level.len, &branch_active)?;
            let short = decode_short(&level.bytes, &level.len, &short_active)?;

            // ---- branch case: follow the nibble's child (invariant 3) ----
            profile(&level.bytes, "decoders", &mut mark);
            let nibble = nibble_at(key, &consumed)?;
            let child_offset =
                branch_child_offset(&branch, &nibble, &branch_active)?;

            // ---- short case: read flags and match the path (invariant 4) ----
            profile(&level.bytes, "child-hash", &mut mark);
            let first_sel = one_hot(&short.path_offset, level.bytes.len())?;
            let first = select_byte_with(&level.bytes, &first_sel)?;
            // These bind only for short nodes: on a branch, `path_offset` is
            // a child-reference prefix such as 0xa0, whose high bits are set by
            // design. Applying the canonical-flag check there rejects every
            // genuine proof.
            assert_canonical_flags(&first, &short_active)?;
            let flags = read_flags(&first)?;
            assert_even_pad_is_zero(&first, &flags.is_odd, &short_active)?;

            // A short node's path nibbles must equal the key's next nibbles.
            // The path field holds `2*path_len - (is_odd ? 1 : 0)` nibbles,
            // starting at nibble 1 of the field when odd, nibble 2 when even.
            profile(&level.bytes, "flags", &mut mark);
            let path_nibbles = &short.path_len * FpVar::constant(F::from(2u64))
                - FpVar::conditionally_select(
                    &flags.is_odd,
                    &FpVar::one(),
                    &FpVar::constant(F::from(2u64)),
                )?;
            assert_path_matches(
                &level.bytes,
                &short,
                &flags.is_odd,
                key,
                &consumed,
                &path_nibbles,
                &short_active,
            )?;


            // An extension's tail is the child reference the walk follows next.
            //
            // Only 32 bytes are read, but at ~10 constraints per buffer byte
            // over a 544-byte node that is still 160k. It cannot be skipped for
            // branches — R1CS emits the constraints regardless of any gate — so
            // the saving has to come from reading less, not from reading
            // conditionally.
            // One windowed read, not two.
            //
            // The branch child reference and the extension tail are both
            // 32 bytes from this same buffer, at different offsets. Selecting
            // the offset first and reading once halves the cost: a 32-byte read
            // over a 544-byte node is ~160k constraints, and doing it twice was
            // 18% of a level.
            profile(&level.bytes, "path-match", &mut mark);
            let next_offset = FpVar::conditionally_select(
                &this_is_branch,
                &child_offset,
                &short.tail_offset,
            )?;
            let next_ref = select_bytes(&level.bytes, &next_offset, 32)?;

            // ---- terminate or descend ----
            profile(&level.bytes, "tail-read", &mut mark);
            let terminates = !this_is_branch.clone() & flags.is_leaf.clone();

            // Invariant 5: a terminating leaf must have consumed the key
            // exactly.
            let after = &consumed + &path_nibbles;
            after.conditional_enforce_equal(
                &total_nibbles,
                &(active.clone() & terminates.clone()),
            )?;

            // Invariant 6 is checked once, after the loop.
            //
            // The comparison is 51% of a level's cost but is meaningful only at
            // the terminating leaf. Selecting that level's node buffer and tail
            // bounds here costs a handful of selects; running the comparison at
            // every level costs ~2M each.
            let is_term = active.clone() & terminates.clone();
            term_node = select_bytes_cond(&level.bytes, &term_node, &is_term)?;
            term_offset =
                FpVar::conditionally_select(&is_term, &short.tail_offset, &term_offset)?;
            term_len = FpVar::conditionally_select(&is_term, &short.tail_len, &term_len)?;

            profile(&level.bytes, "consume+value", &mut mark);
            // Advance. A branch consumes one nibble, an extension consumes its
            // path, a leaf ends the walk.
            let step = FpVar::conditionally_select(
                &this_is_branch,
                &FpVar::one(),
                &path_nibbles,
            )?;
            consumed = FpVar::conditionally_select(
                &(active.clone() & !terminates.clone()),
                &(&consumed + &step),
                &consumed,
            )?;

            // The next expected hash.
            expected = cond_select_bytes(&next_ref, &expected, &(active.clone() & !terminates.clone()))?;

            profile(&level.bytes, "advance", &mut mark);
            // Invariant 7: nothing may follow a termination.
            let after_finish = finished.clone() & active.clone();
            after_finish.enforce_equal(&Boolean::FALSE)?;
            profile(&level.bytes, "finish-check", &mut mark);
            finished |= terminates;
        }

        // The walk must have terminated somewhere.
        finished.enforce_equal(&Boolean::TRUE)?;

        // Invariant 6, once.
        let term_short = super::node::ShortNode {
            path_offset: zero_like(key)?,
            path_len: zero_like(key)?,
            tail_offset: term_offset,
            tail_len: term_len,
        };
        assert_value_matches(&term_node, &term_short, value, value_len, &Boolean::TRUE)?;

        Ok(())
    }
}

/// Eight boolean bits, least significant first, back into a `UInt8`.
fn bits_to_byte<F: PrimeField>(bits: &[Boolean<F>; 8]) -> Result<UInt8<F>, SynthesisError> {
    Ok(UInt8::from_bits_le(bits))
}

/// Selects between two byte vectors of equal length.
fn select_bytes_cond<F: PrimeField>(
    a: &[UInt8<F>],
    b: &[UInt8<F>],
    cond: &Boolean<F>,
) -> Result<Vec<UInt8<F>>, SynthesisError> {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| UInt8::conditionally_select(cond, x, y))
        .collect()
}

fn cond_select_bytes<F: PrimeField>(
    new: &[UInt8<F>],
    old: &[UInt8<F>],
    cond: &Boolean<F>,
) -> Result<Vec<UInt8<F>>, SynthesisError> {
    select_bytes_cond(new, old, cond)
}

/// Enforces that a short node's path nibbles equal the key's next nibbles.
///
/// Invariant 4. Compares up to a compiled maximum, gating each position on
/// whether it is within the actual path length.
fn assert_path_matches<F: PrimeField>(
    node: &[UInt8<F>],
    short: &super::node::ShortNode<F>,
    is_odd: &Boolean<F>,
    key: &[UInt8<F>],
    consumed: &FpVar<F>,
    path_nibbles: &FpVar<F>,
    active: &Boolean<F>,
) -> Result<(), SynthesisError> {
    // Nibble j of the path lives at field nibble j + (odd ? 1 : 2).
    let skip = FpVar::conditionally_select(is_odd, &FpVar::one(), &FpVar::constant(F::from(2u64)))?;

    // A path can never exceed the key's nibble count: it matches key nibbles,
    // and the traversal consumes the key exactly. Deriving the bound from the
    // key buffer rather than a hardcoded 64 makes the cost track the real key
    // size — `rlp(transactionIndex)` is at most 4 bytes, so a 4-byte key buffer
    // gives 8 iterations rather than 64.
    let max_path_nibbles = key.len() * 2;
    for j in 0..max_path_nibbles {
        let jf = FpVar::constant(F::from(j as u64));
        let within = less_than(&jf, path_nibbles)?;

        // Path nibble, read relative to the path field's start.
        let path_pos = &short.path_offset * FpVar::constant(F::from(2u64)) + &skip + &jf;
        let from_path = nibble_at(node, &path_pos)?;

        // Key nibble.
        let key_pos = consumed + &jf;
        let from_key = nibble_at(key, &key_pos)?;

        from_path.conditional_enforce_equal(&from_key, &(active.clone() & within))?;
    }
    Ok(())
}

/// Enforces that a leaf's value equals the claimed value.
fn assert_value_matches<F: PrimeField>(
    node: &[UInt8<F>],
    short: &super::node::ShortNode<F>,
    value: &[UInt8<F>],
    value_len: &FpVar<F>,
    active: &Boolean<F>,
) -> Result<(), SynthesisError> {
    short
        .tail_len
        .conditional_enforce_equal(value_len, active)?;

    // Read the whole tail with ONE shared indicator vector rather than
    // rebuilding it per byte.
    //
    // Three shapes were measured for a 512-byte value in a 640-byte node:
    //
    // | shape | constraints |
    // |---|---|
    // | `one_hot` inside a per-byte loop | 3.39M |
    // | one shared `select_bytes` over the run | **2.02M** |
    // | hash both sides and compare 32 bytes | 3.08M |
    //
    // Hashing looks like it should win, since it replaces a long comparison
    // with a fixed 32-byte one. It loses because reading the tail as a bounded
    // buffer needs `select_bytes(node, offset, node.len())` — 640 bytes at 640
    // offsets, larger than the 512-byte read it replaces — and then pays two
    // variable-length keccaks on top.
    //
    // The lesson is the recurring one: the cost is the windowed read, not the
    // comparison. Any rewrite that still reads a witness-positioned run of the
    // node buffer pays the same price regardless of what it does afterwards.
    let got = select_bytes(node, &short.tail_offset, value.len())?;
    for (j, (g, want)) in got.iter().zip(value.iter()).enumerate() {
        let within = less_than(&FpVar::constant(F::from(j as u64)), value_len)?;
        g.conditional_enforce_equal(want, &(active.clone() & within))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The acceptance criterion for this module: genuine proof accepted, all
    /// nine forgeries rejected.
    ///
    /// Ignored until the conditional-enforcement refactor described on
    /// [`Traversal`] lands. Un-ignore it as part of that change; it is the
    /// definition of done, not an optional check.
    #[test]
    fn adversarial_suite() {
        super::super::tests::run_suite::<Traversal>();
    }

    /// Cost is measurable even while the suite fails: constraint count does
    /// not depend on satisfiability.
    /// Per-sub-step breakdown. See `profile`.
    #[test]
    fn profile_levels() {
        super::super::tests::report_cost::<Traversal>("traversal");
    }

    #[test]
    fn cost() {
        super::super::tests::report_cost::<Traversal>("traversal");
    }
}
