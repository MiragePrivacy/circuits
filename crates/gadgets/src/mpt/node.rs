//! Node decoding: branch, extension, and leaf.
//!
//! # Why branch nodes get a specialized decoder
//!
//! A general `rlp::decode_list(17)` costs 17 full `decode_item` calls at
//! ~41.5k each, roughly 700k per node. But branch children are almost entirely
//! fixed-shape: each is either `0x80` (empty, 1 byte) or `0xa0` followed by a
//! 32-byte hash (33 bytes). Only the 17th item, the value slot, is variable,
//! and in a receipt trie it is empty except at a terminal branch.
//!
//! That makes the layout derivable from 16 one-byte reads plus arithmetic
//! rather than 16 item decodes. The prefix byte at each child's start tells you
//! its size directly, and the next child's offset follows by addition.
//!
//! Inlined children — nodes under 32 bytes embedded rather than hashed — do
//! occur, so the decoder must handle a third case. It is rejected here rather
//! than supported: a receipt trie's children are leaves holding whole receipts,
//! which are never under 32 bytes at the depths that matter. Spec 12.9's bounds
//! already make unsupported shapes unprovable, and this is one more.

use ark_ff::PrimeField;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::gr1cs::SynthesisError;

use crate::bytes::{one_hot, select_byte_with, select_bytes, zero_like as zero_at};
use crate::rlp::{cursor::Cursor, RlpDecoder};

/// A branch node's child layout.
///
/// Deliberately does **not** carry the child hashes. Reading all sixteen costs
/// 16 x 32 byte-reads at ~10 constraints per buffer byte — measured at 2.7M for
/// a 640-byte node, which is worse than the general RLP decode it was meant to
/// beat. Only one child is followed per traversal level, so fifteen of those
/// reads are waste.
///
/// Instead this records where each child sits, and [`branch_child_hash`] reads
/// exactly the one the key selects.
pub struct Branch<F: PrimeField> {
    /// Payload offset of each child slot, sixteen entries.
    pub child_offset: Vec<FpVar<F>>,
    /// Whether each slot holds a hash reference rather than being empty.
    pub occupied: Vec<Boolean<F>>,
    /// Offset of the value slot's payload.
    pub value_offset: FpVar<F>,
    /// Length of the value slot's payload.
    pub value_len: FpVar<F>,
}

/// Child-reference prefixes.
const EMPTY: u8 = 0x80;
const HASH_REF: u8 = 0xa0;

/// Decodes the sixteen child slots of a branch node plus its value slot.
///
/// Walks the children by arithmetic on their prefix bytes rather than by
/// decoding each as a general RLP item. Each slot must be exactly `0x80` or
/// `0xa0` followed by 32 bytes; anything else is rejected, including inlined
/// nodes.
pub fn decode_branch<F: PrimeField>(
    node: &[UInt8<F>],
    node_len: &FpVar<F>,
    active: &Boolean<F>,
) -> Result<Branch<F>, SynthesisError> {
    // The outer list header, decoded generally: its length varies with fill.
    let list = Cursor::decode_item(node, &zero_at(node)?, active)?;
    list.is_list.conditional_enforce_equal(&Boolean::TRUE, active)?;
    // The list must span the whole node, or bytes hide outside it.
    list.end().conditional_enforce_equal(node_len, active)?;

    let mut cursor = list.offset.clone();
    let mut child_offset = Vec::with_capacity(16);
    let mut occupied = Vec::with_capacity(16);

    for _ in 0..16 {
        let sel = one_hot(&cursor, node.len())?;
        let prefix = select_byte_with(node, &sel)?;

        // Exactly two shapes are accepted. Rejecting everything else is what
        // stops a prover presenting an inlined node the traversal would then
        // interpret as a hash.
        let is_empty = prefix.is_eq(&UInt8::constant(EMPTY))?;
        let is_hash = prefix.is_eq(&UInt8::constant(HASH_REF))?;
        (is_empty.clone() | is_hash.clone()).conditional_enforce_equal(&Boolean::TRUE, active)?;

        // Record where the hash sits; do not read it. See `Branch`.
        child_offset.push(&cursor + FpVar::one());
        occupied.push(is_hash.clone());

        // 1 byte for empty, 33 for a hash reference.
        let step = FpVar::conditionally_select(
            &is_hash,
            &FpVar::constant(F::from(33u64)),
            &FpVar::one(),
        )?;
        cursor = cursor + step;
    }

    // The seventeenth item is the value slot, decoded generally: it is empty in
    // every non-terminal branch and a whole receipt in a terminal one.
    let value = Cursor::decode_item(node, &cursor, active)?;
    // It must close the list exactly, so nothing hides after it.
    value.end().conditional_enforce_equal(&list.end(), active)?;

    Ok(Branch {
        child_offset,
        occupied,
        value_offset: value.offset,
        value_len: value.payload_len,
    })
}

/// Reads the 32 hash bytes of the child at `nibble`.
///
/// One 32-byte read rather than sixteen. The offset is selected arithmetically
/// from the layout, so the read itself is a single `select_bytes` at a
/// witness-dependent position.
///
/// Also enforces that the selected slot is occupied: following an empty slot
/// would mean the key leads nowhere, and a traversal that tolerates it proves
/// inclusion of a key that is absent.
pub fn branch_child_hash<F: PrimeField>(
    node: &[UInt8<F>],
    branch: &Branch<F>,
    nibble: &FpVar<F>,
    active: &Boolean<F>,
) -> Result<Vec<UInt8<F>>, SynthesisError> {
    let offset = branch_child_offset(branch, nibble, active)?;
    select_bytes(node, &offset, 32)
}

/// Selects the offset of the child at `nibble`, without reading it.
///
/// Split out from [`branch_child_hash`] so a caller that also needs an
/// extension's tail can select between the two offsets and perform a single
/// windowed read. Reading 32 bytes from a 544-byte node is ~160k constraints,
/// so doing it once instead of twice is worth the indirection.
///
/// Enforces that the selected slot is occupied: following an empty slot means
/// the key leads nowhere, and a traversal that tolerates it proves inclusion of
/// a key that is absent.
pub fn branch_child_offset<F: PrimeField>(
    branch: &Branch<F>,
    nibble: &FpVar<F>,
    active: &Boolean<F>,
) -> Result<FpVar<F>, SynthesisError> {
    let sel = one_hot(nibble, 16)?;

    let mut offset = FpVar::zero();
    let mut occupied = Boolean::FALSE;
    for i in 0..16 {
        offset = FpVar::conditionally_select(&sel[i], &branch.child_offset[i], &offset)?;
        occupied = Boolean::conditionally_select(&sel[i], &branch.occupied[i], &occupied)?;
    }
    occupied.conditional_enforce_equal(&Boolean::TRUE, active)?;
    Ok(offset)
}

/// A two-item node: extension or leaf, distinguished by its path flags.
pub struct ShortNode<F: PrimeField> {
    /// Payload offset of the hex-prefix path field.
    pub path_offset: FpVar<F>,
    pub path_len: FpVar<F>,
    /// Payload offset of the second item: a child reference, or the value.
    pub tail_offset: FpVar<F>,
    pub tail_len: FpVar<F>,
}

/// Decodes an extension or leaf node.
///
/// Both are two-item lists; which one it is comes from the path's flag bits,
/// read separately by `super::path::read_flags`.
pub fn decode_short<F: PrimeField>(
    node: &[UInt8<F>],
    node_len: &FpVar<F>,
    active: &Boolean<F>,
) -> Result<ShortNode<F>, SynthesisError> {
    let items = Cursor::decode_list(node, &zero_at(node)?, 2, active)?;
    // The list must span the whole node.
    let list = Cursor::decode_item(node, &zero_at(node)?, active)?;
    list.end().conditional_enforce_equal(node_len, active)?;

    Ok(ShortNode {
        path_offset: items[0].offset.clone(),
        path_len: items[0].payload_len.clone(),
        tail_offset: items[1].offset.clone(),
        tail_len: items[1].payload_len.clone(),
    })
}

/// Distinguishes a branch from a short node by its item count.
///
/// A branch has 17 items, an extension or leaf 2. Rather than counting items —
/// which would mean decoding them all — this reads the second item's prefix:
/// in a branch the first two items are both child slots, so the second starts
/// at a predictable offset. In practice the caller knows which it expects from
/// the traversal position, so this is a cross-check rather than a dispatch.
pub fn is_branch<F: PrimeField>(
    node: &[UInt8<F>],
    node_len: &FpVar<F>,
    active: &Boolean<F>,
) -> Result<Boolean<F>, SynthesisError> {
    // A branch node is at minimum 17 single-byte items plus a header: 18
    // bytes. A short node with a hash tail is at most 1 + 33 + a short path.
    // The reliable discriminator is the item count, so decode two items and
    // check whether they close the list.
    let list = Cursor::decode_item(node, &zero_at(node)?, active)?;
    list.is_list.conditional_enforce_equal(&Boolean::TRUE, active)?;
    list.end().conditional_enforce_equal(node_len, active)?;

    let first = Cursor::decode_item(node, &list.offset, active)?;
    let second = Cursor::decode_item(node, &first.end(), active)?;
    // Two items exactly means the second closes the list.
    let closes = second.end().is_eq(&list.end())?;
    Ok(!closes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::GR1CSVar;
    use ark_relations::gr1cs::ConstraintSystem;

    use crate::bytes::alloc_bounded;
    use crate::mpt::tests::{branch_node, leaf_node, to_nibbles};

    const BOUND: usize = 640;

    fn alloc(bytes: &[u8]) -> (ConstraintSystemRefAlias, Vec<UInt8<Fr>>, FpVar<Fr>) {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let buf = alloc_bounded(cs.clone(), bytes, BOUND).unwrap();
        let len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(bytes.len() as u64))).unwrap();
        (cs, buf, len)
    }

    type ConstraintSystemRefAlias = ark_relations::gr1cs::ConstraintSystemRef<Fr>;

    #[test]
    fn decodes_a_sparse_branch() {
        let leaf = leaf_node(&[5, 7, 1], &[0xaa; 40]);
        let mut children: [Option<Vec<u8>>; 16] = Default::default();
        children[3] = Some(leaf.clone());
        let node = branch_node(children, None);

        let (cs, buf, len) = alloc(&node);
        let b = decode_branch(&buf, &len, &Boolean::TRUE).unwrap();
        assert!(cs.is_satisfied().unwrap(), "rejected a valid sparse branch");

        for (i, occ) in b.occupied.iter().enumerate() {
            assert_eq!(
                occ.value().unwrap(),
                i == 3,
                "slot {i} occupancy"
            );
        }

        // Read only the child the key selects, which is the whole point.
        let nibble = FpVar::new_witness(cs.clone(), || Ok(Fr::from(3u64))).unwrap();
        let hash = branch_child_hash(&buf, &b, &nibble, &Boolean::TRUE).unwrap();
        let got: Vec<u8> = hash.iter().map(|x| x.value().unwrap()).collect();
        assert_eq!(got, mirage_encoding::keccak256(&leaf).to_vec(), "slot 3 hash");
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn decodes_a_dense_branch() {
        let mut children: [Option<Vec<u8>>; 16] = Default::default();
        for (i, slot) in children.iter_mut().enumerate() {
            *slot = Some(leaf_node(&[i as u8], &[0xbb; 40]));
        }
        let node = branch_node(children, None);

        let (cs, buf, len) = alloc(&node);
        let b = decode_branch(&buf, &len, &Boolean::TRUE).unwrap();
        assert!(cs.is_satisfied().unwrap(), "rejected a valid dense branch");
        for (i, occ) in b.occupied.iter().enumerate() {
            assert!(occ.value().unwrap(), "slot {i} should be occupied");
        }
    }

    #[test]
    fn rejects_an_inlined_child() {
        // A child under 32 bytes is embedded rather than hashed. Unsupported.
        let tiny = leaf_node(&[1], &[0xcc; 2]);
        assert!(tiny.len() < 32, "fixture should be inline-sized");
        let mut children: [Option<Vec<u8>>; 16] = Default::default();
        children[3] = Some(tiny);
        let node = branch_node(children, None);

        let (cs, buf, len) = alloc(&node);
        let _ = decode_branch(&buf, &len, &Boolean::TRUE);
        assert!(!cs.is_satisfied().unwrap(), "accepted an inlined child");
    }

    /// Decoding a branch as a short node must fail: a 17-item list cannot be
    /// read as 2 items, because `decode_list` enforces exact tiling.
    ///
    /// This is why a traversal cannot call both decoders unconditionally on
    /// every node and select afterwards, which is the obvious R1CS shape.
    #[test]
    fn short_decode_rejects_a_branch() {
        let leaf = leaf_node(&[5, 7, 1], &[0xaa; 40]);
        let mut children: [Option<Vec<u8>>; 16] = Default::default();
        children[3] = Some(leaf);
        let node = branch_node(children, None);

        let (cs, buf, len) = alloc(&node);
        let _ = decode_short(&buf, &len, &Boolean::TRUE);
        assert!(
            !cs.is_satisfied().unwrap(),
            "decode_short accepted a 17-item branch"
        );
    }

    /// And the reverse.
    #[test]
    fn branch_decode_rejects_a_leaf() {
        let node = leaf_node(&[5, 7, 1], &[0xaa; 40]);
        let (cs, buf, len) = alloc(&node);
        let _ = decode_branch(&buf, &len, &Boolean::TRUE);
        assert!(
            !cs.is_satisfied().unwrap(),
            "decode_branch accepted a 2-item leaf"
        );
    }

    #[test]
    fn decodes_a_leaf() {
        let node = leaf_node(&[5, 7, 1], b"a-receipt-value");
        let (cs, buf, len) = alloc(&node);
        let s = decode_short(&buf, &len, &Boolean::TRUE).unwrap();
        assert!(cs.is_satisfied().unwrap(), "rejected a valid leaf");
        assert_eq!(
            s.tail_len.value().unwrap(),
            Fr::from(b"a-receipt-value".len() as u64)
        );
    }

    /// Does `is_branch` stay satisfiable on a leaf?
    ///
    /// It decodes two items to count them. On a two-item leaf the second decode
    /// lands on the value item, which exists — but the *third* implicit read,
    /// and the containment assertions of both, bind against a list that has
    /// already ended.
    ///
    /// If this fails, `is_branch` is the remaining traversal bug.
    #[test]
    fn is_branch_is_satisfiable_on_a_leaf() {
        let node = leaf_node(&[5, 7, 1], &[0xaa; 40]);
        let (cs, buf, len) = alloc(&node);
        let _ = is_branch(&buf, &len, &Boolean::TRUE).unwrap();
        assert!(
            cs.is_satisfied().unwrap(),
            "is_branch unsatisfiable on a valid leaf: {:?}",
            cs.which_is_unsatisfied()
        );
    }

    /// And on a branch, where the second item is a child slot.
    #[test]
    fn is_branch_is_satisfiable_on_a_branch() {
        let leaf = leaf_node(&[5, 7, 1], &[0xaa; 40]);
        let mut children: [Option<Vec<u8>>; 16] = Default::default();
        children[3] = Some(leaf);
        let node = branch_node(children, None);
        let (cs, buf, len) = alloc(&node);
        let _ = is_branch(&buf, &len, &Boolean::TRUE).unwrap();
        assert!(
            cs.is_satisfied().unwrap(),
            "is_branch unsatisfiable on a valid branch: {:?}",
            cs.which_is_unsatisfied()
        );
    }

    /// Runs each traversal component on the leaf, in the traversal's order,
    /// with the traversal's active flags. Whichever assertion fails here is
    /// the bug.
    #[test]
    fn traversal_components_on_a_leaf() {
        let node = leaf_node(&[5, 7, 1], &[0xaa; 40]);

        let steps: Vec<(&str, fn(&[UInt8<Fr>], &FpVar<Fr>) -> ())> = vec![
            ("is_branch", |b, l| {
                let _ = is_branch(b, l, &Boolean::TRUE).unwrap();
            }),
            ("decode_short(active)", |b, l| {
                let _ = decode_short(b, l, &Boolean::TRUE).unwrap();
            }),
            ("decode_branch(inactive)", |b, l| {
                let _ = decode_branch(b, l, &Boolean::FALSE).unwrap();
            }),
        ];

        for (name, step) in steps {
            let (cs, buf, len) = alloc(&node);
            step(&buf, &len);
            assert!(
                cs.is_satisfied().unwrap(),
                "{name} unsatisfiable on a leaf: {:?}",
                cs.which_is_unsatisfied()
            );
        }

        // And the combination the traversal actually builds.
        let (cs, buf, len) = alloc(&node);
        let ib = is_branch(&buf, &len, &Boolean::TRUE).unwrap();
        let branch_active = ib.clone();
        let short_active = !ib.clone();
        let b = decode_branch(&buf, &len, &branch_active).unwrap();
        let _ = decode_short(&buf, &len, &short_active).unwrap();
        let nibble = FpVar::new_witness(cs.clone(), || Ok(Fr::from(5u64))).unwrap();
        let _ = branch_child_hash(&buf, &b, &nibble, &branch_active).unwrap();
        assert!(
            cs.is_satisfied().unwrap(),
            "combined traversal step unsatisfiable on a leaf: {:?}",
            cs.which_is_unsatisfied()
        );
    }

    #[test]
    fn distinguishes_branch_from_short() {
        let leaf = leaf_node(&[5, 7, 1], &[0xaa; 40]);
        let (cs1, buf1, len1) = alloc(&leaf);
        assert!(!is_branch(&buf1, &len1, &Boolean::TRUE).unwrap().value().unwrap(), "leaf");
        assert!(cs1.is_satisfied().unwrap());

        let mut children: [Option<Vec<u8>>; 16] = Default::default();
        children[3] = Some(leaf);
        let node = branch_node(children, None);
        let (cs2, buf2, len2) = alloc(&node);
        assert!(is_branch(&buf2, &len2, &Boolean::TRUE).unwrap().value().unwrap(), "branch");
        assert!(cs2.is_satisfied().unwrap());
    }

    #[test]
    fn branch_decode_cost() {
        let mut children: [Option<Vec<u8>>; 16] = Default::default();
        for (i, slot) in children.iter_mut().enumerate() {
            *slot = Some(leaf_node(&[i as u8], &[0xbb; 40]));
        }
        let node = branch_node(children, None);

        let (cs, buf, len) = alloc(&node);
        let before = cs.num_constraints();
        let b = decode_branch(&buf, &len, &Boolean::TRUE).unwrap();
        let layout = cs.num_constraints() - before;

        let nibble = FpVar::new_witness(cs.clone(), || Ok(Fr::from(3u64))).unwrap();
        let before2 = cs.num_constraints();
        let _ = branch_child_hash(&buf, &b, &nibble, &Boolean::TRUE).unwrap();
        let read = cs.num_constraints() - before2;

        println!("branch layout ({BOUND} B buffer):        {layout} constraints");
        println!("one selected child hash read:           {read} constraints");
        println!("total per traversal level:              {} constraints", layout + read);

        // For comparison: a general 17-item RLP list decode over the same node.
        let (cs2, buf2, _) = alloc(&node);
        let z = zero_at(&buf2).unwrap();
        let before3 = cs2.num_constraints();
        let _ = Cursor::decode_list(&buf2, &z, 17, &Boolean::TRUE).unwrap();
        println!("general decode_list(17):                {} constraints", cs2.num_constraints() - before3);
    }
}
