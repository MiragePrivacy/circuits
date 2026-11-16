//! MPT traversal with a canonically constructed terminal leaf.
//!
//! Witness nodes contain only branches and extensions. After those ancestors
//! consume a prefix of the key, the terminal leaf is constructed from the
//! remaining key nibbles and the already-bound value. This removes the
//! generic terminal decoder and witness-positioned value copy while preserving
//! the same root-to-value inclusion statement.
//!
//! Each ancestor is checked against the layout [`super::levels`] derives for
//! it, and the followed child hash is read with one field-level shift.

use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_r1cs_std::uint8::UInt8;
use ark_r1cs_std::GR1CSVar;
use ark_relations::gr1cs::SynthesisError;

use super::constructed_leaf::hash_value_leaf_from_remainder_with;
use super::levels::{self, KeyNibbles};
use super::traverse::bits_to_byte;
use super::{MptVerifier, ProofNode};
use crate::bytes::{byte_to_field, shift_window, to_fields, zero_like};
use crate::keccak::{keccak256_var_with, DirectPermutation, PermutationBackend};

pub struct ConstructedLeafTraversal;

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
        Self::verify_inclusion_impl(root, key, key_len, value, value_len, nodes, backend)
    }

    /// Alias of [`Self::verify_inclusion_with`]: every leaf is constructed
    /// with the general value encoder.
    pub fn verify_value_inclusion_with<F: PrimeField, B: PermutationBackend<F>>(
        root: &[UInt8<F>],
        key: &[UInt8<F>],
        key_len: &FpVar<F>,
        value: &[UInt8<F>],
        value_len: &FpVar<F>,
        nodes: &[ProofNode<F>],
        backend: &mut B,
    ) -> Result<(), SynthesisError> {
        Self::verify_inclusion_impl(root, key, key_len, value, value_len, nodes, backend)
    }

    fn verify_inclusion_impl<F: PrimeField, B: PermutationBackend<F>>(
        root: &[UInt8<F>],
        key: &[UInt8<F>],
        key_len: &FpVar<F>,
        value: &[UInt8<F>],
        value_len: &FpVar<F>,
        nodes: &[ProofNode<F>],
        backend: &mut B,
    ) -> Result<(), SynthesisError> {
        let cs = key_len.cs().or(value_len.cs());
        let keys = KeyNibbles::new(key)?;
        let mut expected = to_fields(root)?;
        let mut consumed = zero_like(key)?;
        let mut inactive_seen = Boolean::FALSE;

        for (level_index, level) in nodes.iter().enumerate() {
            let active = level.active.clone();

            // Ancestors form one active prefix. Otherwise a prover could skip
            // a link and resume from an unrelated later node.
            (inactive_seen.clone() & active.clone()).enforce_equal(&Boolean::FALSE)?;
            inactive_seen |= !active.clone();

            let digest = keccak256_var_with(&level.bytes, &level.len, backend)?;
            for (digest_byte, want) in digest.iter().zip(expected.iter()) {
                byte_to_field(&bits_to_byte(digest_byte)?)?.conditional_enforce_equal(want, &active)?;
            }

            let native = native_bytes(level);
            let node = to_fields(&level.bytes)?;
            let position = keys.position(&consumed)?;
            let path: [FpVar<F>; 5] = core::array::from_fn(|t| keys.at(&position, t));

            // A non-leaf trie over indices 0 and 1 branches on nibbles 8 and
            // 0, so an active root is a branch; the zero-ancestor case is a
            // constructed root leaf. Deeper positions are a branch or an
            // extension, chosen by a witness bit that only selects which
            // layout the bytes are checked against.
            let is_branch = if level_index == 0 {
                Boolean::TRUE
            } else {
                Boolean::new_witness(cs.clone(), || Ok(is_branch_node(&native)))?
            };
            let branch_active = active.clone() & is_branch.clone();
            let child = levels::branch(
                cs.clone(),
                &node,
                &level.len,
                levels::native_occupancy(&native),
                &path[0],
                &branch_active,
            )?;
            let (offset, step) = if level_index == 0 {
                (child, FpVar::from(branch_active))
            } else {
                let short_active = active.clone() & !is_branch.clone();
                let (tail, nibbles) = levels::extension(
                    cs.clone(),
                    &node,
                    &level.len,
                    levels::native_extension_nibbles(&native),
                    &path,
                    &short_active,
                )?;
                (
                    FpVar::conditionally_select(&is_branch, &child, &tail)?,
                    FpVar::from(branch_active) + nibbles,
                )
            };

            let next = shift_window(&node, &offset, 32)?;
            consumed += step;
            expected = expected
                .iter()
                .zip(next.iter())
                .map(|(old, new)| FpVar::conditionally_select(&active, new, old))
                .collect::<Result<Vec<_>, _>>()?;
        }

        let leaf_digest = hash_value_leaf_from_remainder_with(
            value, value_len, &keys, key_len, &consumed, backend,
        )?;
        for (digest_byte, want) in leaf_digest.iter().zip(expected.iter()) {
            byte_to_field(&bits_to_byte(digest_byte)?)?.enforce_equal(want)?;
        }
        Ok(())
    }
}

fn native_bytes<F: PrimeField>(level: &ProofNode<F>) -> Vec<u8> {
    let len = fp_to_usize(level.len.value().unwrap_or(F::zero()));
    level
        .bytes
        .iter()
        .take(len.min(level.bytes.len()))
        .map(|byte| byte.value().unwrap_or(0))
        .collect()
}

fn is_branch_node(bytes: &[u8]) -> bool {
    native_list_arity(bytes) == Some(17)
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
            Err(e) => { if std::env::var_os("DBG").is_some() { eprintln!("err: {e:?}"); } false }
            Ok(()) => { if std::env::var_os("DBG").is_some() { eprintln!("unsat: {:?}", cs.which_is_unsatisfied()); } cs.is_satisfied().unwrap_or(false) }
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

    /// A `key_len` past the key buffer must be rejected.
    ///
    /// Nibble reads past the buffer return zero rather than failing, so an
    /// unbounded `key_len` let the path consume nibbles the key does not have.
    /// The relation derives `key_len` from the witness, so this is only
    /// constructible here.
    #[test]
    fn rejects_a_key_length_past_the_buffer() {
        let p = genuine();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let root = alloc_bounded(cs.clone(), &p.root, 32).unwrap();
        let key = alloc_bounded(cs.clone(), &p.key, 3).unwrap();
        // The buffer holds three bytes; claim four.
        let key_len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(4u64))).unwrap();
        let value = alloc_bounded(cs.clone(), &p.value, 448).unwrap();
        let value_len =
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(p.value.len() as u64))).unwrap();

        let ancestor_count = p.nodes.len().saturating_sub(1);
        let mut nodes = Vec::with_capacity(3);
        for i in 0..3 {
            let (bytes, len, active) = match p.nodes.get(i).filter(|_| i < ancestor_count) {
                Some(node) => (node.clone(), node.len(), true),
                None => (Vec::new(), 0, false),
            };
            nodes.push(ProofNode {
                bytes: alloc_bounded(cs.clone(), &bytes, 544).unwrap(),
                len: FpVar::new_witness(cs.clone(), || Ok(Fr::from(len as u64))).unwrap(),
                active: Boolean::new_witness(cs.clone(), || Ok(active)).unwrap(),
            });
        }
        ConstructedLeafTraversal::verify_inclusion(
            &root, &key, &key_len, &value, &value_len, &nodes,
        )
        .unwrap();
        assert!(
            !cs.is_satisfied().unwrap(),
            "accepted a key length past the key buffer"
        );
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

    /// Active slots must form one prefix. An inactive slot passes the expected
    /// hash through and consumes nothing, so a gap proves no more than the
    /// same nodes without it; the rule keeps one witness shape per proof.
    #[test]
    fn rejects_a_gap_between_active_slots() {
        let p = genuine();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let root = alloc_bounded(cs.clone(), &p.root, 32).unwrap();
        let key = alloc_bounded(cs.clone(), &p.key, 3).unwrap();
        let key_len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(p.key.len() as u64))).unwrap();
        let value = alloc_bounded(cs.clone(), &p.value, 448).unwrap();
        let value_len =
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(p.value.len() as u64))).unwrap();
        let slot = |bytes: &[u8], active: bool| ProofNode {
            bytes: alloc_bounded(cs.clone(), bytes, 544).unwrap(),
            len: FpVar::new_witness(cs.clone(), || Ok(Fr::from(bytes.len() as u64))).unwrap(),
            active: Boolean::new_witness(cs.clone(), || Ok(active)).unwrap(),
        };
        let nodes = vec![slot(&[], false), slot(&p.nodes[0], true), slot(&[], false)];
        ConstructedLeafTraversal::verify_inclusion(&root, &key, &key_len, &value, &value_len, &nodes)
            .unwrap();
        assert!(!cs.is_satisfied().unwrap(), "accepted an inactive slot before the root");
    }
}
