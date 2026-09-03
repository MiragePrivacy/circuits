//! MPT traversal with a canonically constructed terminal leaf.
//!
//! Witness nodes contain only branches and extensions. After those ancestors
//! consume a prefix of the key, the terminal leaf is constructed from the
//! remaining key nibbles and the already-bound receipt. This removes the
//! generic terminal decoder and witness-positioned value copy while preserving
//! the same root-to-value inclusion statement.

use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_r1cs_std::uint8::UInt8;
use ark_r1cs_std::GR1CSVar;
use ark_relations::gr1cs::SynthesisError;

use super::constructed_leaf::hash_leaf_from_remainder_with;
use super::node::{branch_child_offset, decode_branch, decode_short};
use super::path::{assert_canonical_flags, assert_even_pad_is_zero, nibble_at, read_flags};
use super::traverse::{assert_path_matches, bits_to_byte};
use super::{MptVerifier, ProofNode};
use crate::bytes::{one_hot, select_byte_with, select_bytes, zero_like};
use crate::keccak::{keccak256_var_with, DirectPermutation, PermutationBackend};

pub struct ConstructedLeafTraversal;

fn profile<F: PrimeField>(buf: &[UInt8<F>], step: &str, last: &mut usize) {
    if std::env::var_os("MPT_PROFILE").is_none() {
        return;
    }
    if let Some(byte) = buf.first() {
        let now = byte.cs().num_constraints();
        eprintln!("{:>12}  {step}", now - *last);
        *last = now;
    }
}

impl<F: PrimeField> MptVerifier<F> for ConstructedLeafTraversal {
    fn verify_inclusion(
        root: &[UInt8<F>],
        key: &[UInt8<F>],
        key_len: &FpVar<F>,
        value: &[UInt8<F>],
        value_len: &FpVar<F>,
        nodes: &[ProofNode<F>],
    ) -> Result<(), SynthesisError> {
        Self::verify_inclusion_with(
            root,
            key,
            key_len,
            value,
            value_len,
            nodes,
            &mut DirectPermutation,
        )
    }
}

impl ConstructedLeafTraversal {
    pub fn verify_inclusion_with<F: PrimeField, B: PermutationBackend<F>>(
        root: &[UInt8<F>],
        key: &[UInt8<F>],
        key_len: &FpVar<F>,
        value: &[UInt8<F>],
        value_len: &FpVar<F>,
        nodes: &[ProofNode<F>],
        backend: &mut B,
    ) -> Result<(), SynthesisError> {
        let mut expected = root.to_vec();
        let mut consumed = zero_like(key)?;
        let mut inactive_seen = Boolean::FALSE;

        for (level_index, level) in nodes.iter().enumerate() {
            let mut mark = level
                .bytes
                .first()
                .map(|byte| byte.cs().num_constraints())
                .unwrap_or(0);
            let active = level.active.clone();

            // Ancestors form one active prefix. Otherwise a prover could skip
            // a link and resume from an unrelated later node.
            (inactive_seen.clone() & active.clone()).enforce_equal(&Boolean::FALSE)?;
            inactive_seen |= !active.clone();

            let digest = keccak256_var_with(&level.bytes, &level.len, &active, backend)?;
            for (digest_byte, want) in digest.iter().zip(expected.iter()) {
                bits_to_byte(digest_byte)?.conditional_enforce_equal(want, &active)?;
            }
            profile(&level.bytes, "link-hash", &mut mark);

            // A non-leaf receipt trie contains indices 0 and 1, whose RLP
            // keys begin with nibbles 8 and 0. Therefore an active root cannot
            // be an extension; the zero-ancestor case handles a root leaf.
            // Compile this position as branch-only instead of paying for the
            // speculative short-node decoder and path machinery.
            if level_index == 0 {
                let branch = decode_branch(&level.bytes, &level.len, &active)?;
                let nibble = nibble_at(key, &consumed)?;
                let child_offset = branch_child_offset(&branch, &nibble, &active)?;
                let next_ref = select_bytes(&level.bytes, &child_offset, 32)?;
                consumed =
                    FpVar::conditionally_select(&active, &(&consumed + FpVar::one()), &consumed)?;
                expected = expected
                    .iter()
                    .zip(next_ref.iter())
                    .map(|(old, new)| UInt8::conditionally_select(&active, new, old))
                    .collect::<Result<Vec<_>, _>>()?;
                profile(&level.bytes, "root-branch", &mut mark);
                continue;
            }

            // Shape is a witness hint, not a trusted parse result. Whichever
            // value the prover chooses activates a decoder that fully proves
            // either 17 branch items or exactly two short-node items. This
            // avoids decoding the outer list and its first two children a
            // third time merely to choose between those same decoders.
            let native_len = fp_to_usize(level.len.value().unwrap_or(F::zero()));
            let native_bytes: Vec<u8> = level
                .bytes
                .iter()
                .take(native_len.min(level.bytes.len()))
                .map(|byte| byte.value().unwrap_or(0))
                .collect();
            let native_branch = native_list_arity(&native_bytes) == Some(17);
            let this_is_branch = Boolean::new_witness(level.len.cs(), || Ok(native_branch))?;
            profile(&level.bytes, "shape-hint", &mut mark);
            let branch_active = active.clone() & this_is_branch.clone();
            let short_active = active.clone() & !this_is_branch.clone();
            let branch = decode_branch(&level.bytes, &level.len, &branch_active)?;
            let short = decode_short(&level.bytes, &level.len, &short_active)?;
            profile(&level.bytes, "decoders", &mut mark);

            let nibble = nibble_at(key, &consumed)?;
            let child_offset = branch_child_offset(&branch, &nibble, &branch_active)?;
            profile(&level.bytes, "child-offset", &mut mark);

            let first_sel = one_hot(&short.path_offset, level.bytes.len())?;
            let first = select_byte_with(&level.bytes, &first_sel)?;
            assert_canonical_flags(&first, &short_active)?;
            let flags = read_flags(&first)?;
            assert_even_pad_is_zero(&first, &flags.is_odd, &short_active)?;

            // Every witnessed short node is an extension. The leaf is derived
            // below and therefore cannot be replaced by prover-supplied bytes.
            flags
                .is_leaf
                .conditional_enforce_equal(&Boolean::FALSE, &short_active)?;
            short
                .tail_len
                .conditional_enforce_equal(&FpVar::constant(F::from(32u64)), &short_active)?;
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
            profile(&level.bytes, "path-match", &mut mark);

            let next_offset =
                FpVar::conditionally_select(&this_is_branch, &child_offset, &short.tail_offset)?;
            let next_ref = select_bytes(&level.bytes, &next_offset, 32)?;
            profile(&level.bytes, "tail-read", &mut mark);
            let step = FpVar::conditionally_select(&this_is_branch, &FpVar::one(), &path_nibbles)?;
            consumed = FpVar::conditionally_select(&active, &(&consumed + step), &consumed)?;
            expected = expected
                .iter()
                .zip(next_ref.iter())
                .map(|(old, new)| UInt8::conditionally_select(&active, new, old))
                .collect::<Result<Vec<_>, _>>()?;
            profile(&level.bytes, "advance", &mut mark);
        }

        let mut leaf_mark = key
            .first()
            .map(|byte| byte.cs().num_constraints())
            .unwrap_or(0);
        let leaf_digest = hash_leaf_from_remainder_with(
            value,
            value_len,
            key,
            key_len,
            &consumed,
            &Boolean::TRUE,
            backend,
        )?;
        profile(key, "constructed-leaf", &mut leaf_mark);
        for (digest_byte, want) in leaf_digest.iter().zip(expected.iter()) {
            bits_to_byte(digest_byte)?.enforce_equal(want)?;
        }
        Ok(())
    }
}

fn fp_to_usize<F: PrimeField>(value: F) -> usize {
    let bytes = value.into_bigint().to_bytes_le();
    let mut out = [0u8; 8];
    let n = bytes.len().min(8);
    out[..n].copy_from_slice(&bytes[..n]);
    u64::from_le_bytes(out) as usize
}

/// Native witness generation only. Circuit soundness comes from the selected
/// decoder; a wrong result here makes a genuine witness fail, not a forgery
/// pass.
fn native_list_arity(bytes: &[u8]) -> Option<usize> {
    let (header, payload) = native_item_shape(bytes, 0)?;
    let end = header.checked_add(payload)?;
    if end != bytes.len() || bytes.first().copied()? < 0xc0 {
        return None;
    }
    let mut at = header;
    let mut count = 0;
    while at < end {
        let (item_header, item_payload) = native_item_shape(bytes, at)?;
        at = at.checked_add(item_header)?.checked_add(item_payload)?;
        if at > end {
            return None;
        }
        count += 1;
    }
    (at == end).then_some(count)
}

fn native_item_shape(bytes: &[u8], at: usize) -> Option<(usize, usize)> {
    let prefix = *bytes.get(at)?;
    match prefix {
        0x00..=0x7f => Some((0, 1)),
        0x80..=0xb7 => Some((1, (prefix - 0x80) as usize)),
        0xb8..=0xbf => native_long_shape(bytes, at, (prefix - 0xb7) as usize),
        0xc0..=0xf7 => Some((1, (prefix - 0xc0) as usize)),
        0xf8..=0xff => native_long_shape(bytes, at, (prefix - 0xf7) as usize),
    }
}

fn native_long_shape(bytes: &[u8], at: usize, len_of_len: usize) -> Option<(usize, usize)> {
    let mut payload = 0usize;
    for byte in bytes.get(at + 1..at + 1 + len_of_len)? {
        payload = payload.checked_mul(256)?.checked_add(*byte as usize)?;
    }
    Some((1 + len_of_len, payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_relations::gr1cs::{ConstraintSystem, ConstraintSystemRef};

    use crate::bytes::alloc_bounded;
    use crate::mpt::harness::NativeProof;
    use crate::mpt::tests::{branch_node, extension_node, leaf_node, simple_trie};

    fn genuine() -> NativeProof {
        let key = vec![0x35, 0x71];
        let value = vec![0x42; 300];
        let (root, key, value, nodes) = simple_trie(3, &key, &value);
        NativeProof {
            root,
            key,
            value,
            nodes,
        }
    }

    fn verify(p: &NativeProof) -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        match build(cs.clone(), p) {
            Err(_) => false,
            Ok(()) => cs.is_satisfied().unwrap_or(false),
        }
    }

    fn build(cs: ConstraintSystemRef<Fr>, p: &NativeProof) -> Result<(), SynthesisError> {
        let root = alloc_bounded(cs.clone(), &p.root, 32)?;
        let key = alloc_bounded(cs.clone(), &p.key, 3)?;
        let key_len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(p.key.len() as u64)))?;
        let value = alloc_bounded(cs.clone(), &p.value, 448)?;
        let value_len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(p.value.len() as u64)))?;

        let ancestor_count = p.nodes.len().saturating_sub(1);
        let mut nodes = Vec::with_capacity(3);
        for i in 0..3 {
            let (bytes, len, active) = match p.nodes.get(i).filter(|_| i < ancestor_count) {
                Some(node) => (node.clone(), node.len(), true),
                None => (Vec::new(), 0, false),
            };
            nodes.push(ProofNode {
                bytes: alloc_bounded(cs.clone(), &bytes, 544)?,
                len: FpVar::new_witness(cs.clone(), || Ok(Fr::from(len as u64)))?,
                active: Boolean::new_witness(cs.clone(), || Ok(active))?,
            });
        }
        ConstructedLeafTraversal::verify_inclusion(
            &root, &key, &key_len, &value, &value_len, &nodes,
        )
    }

    #[test]
    fn accepts_a_genuine_constructed_leaf_proof() {
        assert!(verify(&genuine()));
    }

    #[test]
    fn accepts_a_root_leaf_without_ancestors() {
        let key = vec![0x80];
        let value = vec![0x42; 300];
        let leaf = leaf_node(&[8, 0], &value);
        let proof = NativeProof {
            root: mirage_encoding::keccak256(&leaf),
            key,
            value,
            nodes: vec![leaf],
        };
        assert!(verify(&proof));
    }

    #[test]
    fn rejects_wrong_root_key_value_and_ancestor() {
        let mut wrong_root = genuine();
        wrong_root.root[0] ^= 1;
        assert!(!verify(&wrong_root), "accepted a wrong root");

        let mut wrong_key = genuine();
        wrong_key.key[1] ^= 1;
        assert!(!verify(&wrong_key), "accepted a wrong key remainder");

        let mut wrong_value = genuine();
        wrong_value.value[17] ^= 1;
        assert!(!verify(&wrong_value), "accepted a wrong receipt value");

        let mut wrong_ancestor = genuine();
        wrong_ancestor.nodes[0][7] ^= 1;
        assert!(
            !verify(&wrong_ancestor),
            "accepted an unauthenticated ancestor"
        );
    }

    #[test]
    fn rejects_an_extension_with_the_wrong_path() {
        let key = vec![0x35, 0x71];
        let value = vec![0x42; 300];
        let leaf = leaf_node(&[1], &value);
        let extension = extension_node(&[9, 9], &leaf);
        let mut children: [Option<Vec<u8>>; 16] = Default::default();
        children[3] = Some(extension.clone());
        let root_node = branch_node(children, None);
        let proof = NativeProof {
            root: mirage_encoding::keccak256(&root_node),
            key,
            value,
            nodes: vec![root_node, extension, leaf],
        };
        assert!(!verify(&proof), "accepted a mismatched extension path");
    }

    #[test]
    fn rejects_a_node_appended_after_the_terminal_leaf() {
        let mut proof = genuine();
        proof.nodes.push(leaf_node(&[1], &vec![0x55; 300]));
        assert!(!verify(&proof), "accepted a node past the terminal leaf");
    }
}
