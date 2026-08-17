//! Receipt-trie reconstruction and proof extraction.
//!
//! Ethereum's receipt trie is a hexary Merkle-Patricia trie keyed by
//! `rlp(transactionIndex)`. Rebuilding it locally, rather than trusting an
//! `eth_getProof`-style RPC, means the reconstructed root can be checked
//! against the block header's `receiptsRoot` — a single equality that catches
//! every encoding mistake at once.
//!
//! Three details are easy to get wrong and each produces a valid-looking trie
//! with the wrong root:
//!
//! - **The inline threshold.** A node whose encoding is under 32 bytes is
//!   embedded in its parent rather than referenced by hash.
//! - **Hex-prefix flags.** Bit 5 marks a leaf, bit 4 an odd nibble count, and
//!   an odd path packs its first nibble into the flag byte's low half.
//! - **Canonical integers.** `rlp(0)` is the empty string, not a zero byte, so
//!   index 0's key is `0x80`.

use std::collections::HashMap;

use crate::hash;
use crate::rlp::{decode_all, Item};

/// A built trie: its root hash and every node keyed by hash.
pub struct Trie {
    pub root: [u8; 32],
    nodes: HashMap<[u8; 32], Vec<u8>>,
}

/// Splits bytes into nibbles, high half first.
pub fn nibbles(b: &[u8]) -> Vec<u8> {
    b.iter().flat_map(|&x| [x >> 4, x & 0x0f]).collect()
}

/// Hex-prefix encoding for a leaf or extension path.
pub fn hex_prefix(nibs: &[u8], is_leaf: bool) -> Vec<u8> {
    let odd = nibs.len() % 2 == 1;
    let flag = (if is_leaf { 2u8 } else { 0 }) | (if odd { 1 } else { 0 });

    let mut out = Vec::with_capacity(nibs.len() / 2 + 1);
    let rest = if odd {
        out.push((flag << 4) | nibs[0]);
        &nibs[1..]
    } else {
        out.push(flag << 4);
        nibs
    };
    for pair in rest.chunks(2) {
        out.push((pair[0] << 4) | pair[1]);
    }
    out
}

/// The trie key for a transaction index: `rlp(index)`.
pub fn key_for(index: usize) -> Vec<u8> {
    Item::int(index as u64).encode()
}

impl Trie {
    /// Builds the trie over `values`, keyed by their positions.
    pub fn build(values: &[Vec<u8>]) -> Self {
        let mut nodes = HashMap::new();
        let entries: Vec<Entry> = values
            .iter()
            .enumerate()
            .map(|(i, v)| (nibbles(&key_for(i)), v.clone()))
            .collect();

        let node = build_node(&entries, &mut nodes);
        let enc = node.encode();
        let root = hash(&enc);
        nodes.insert(root, enc);
        Trie { root, nodes }
    }

    /// The nodes from the root to the leaf holding `key`, root first.
    ///
    /// Inlined children are returned as their own encodings, so the caller
    /// sees a uniform list regardless of whether a node was referenced by hash
    /// or embedded.
    pub fn proof(&self, key: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        let path = nibbles(key);
        let mut out = vec![self
            .nodes
            .get(&self.root)
            .ok_or("root missing from store")?
            .clone()];
        let mut pos = 0usize;

        loop {
            let node = decode_all(out.last().unwrap())?;
            let items = match &node {
                Item::List(items) => items,
                Item::Str(_) => return Err("node is not a list".into()),
            };

            let next_ref = match items.len() {
                17 => {
                    if pos >= path.len() {
                        return Ok(out); // value sits in the branch's slot 16
                    }
                    let r = items[path[pos] as usize].clone();
                    pos += 1;
                    r
                }
                2 => {
                    let hp = match &items[0] {
                        Item::Str(b) => b.clone(),
                        Item::List(_) => return Err("path field is a list".into()),
                    };
                    if hp[0] & 0x20 != 0 {
                        return Ok(out); // leaf: the walk ends here
                    }
                    let odd = hp[0] & 0x10 != 0;
                    pos += nibbles(&hp).len() - if odd { 1 } else { 2 };
                    items[1].clone()
                }
                n => return Err(format!("unexpected node arity {n}")),
            };

            match next_ref {
                // An empty slot means the key is absent.
                Item::Str(ref b) if b.is_empty() => return Ok(out),
                // A 32-byte reference is a hash into the store.
                Item::Str(ref b) if b.len() == 32 => {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(b);
                    match self.nodes.get(&h) {
                        Some(n) => out.push(n.clone()),
                        None => return Ok(out),
                    }
                }
                // Anything else is an inlined node.
                other => out.push(other.encode()),
            }
        }
    }
}

/// A child reference: the node inlined when its encoding is under 32 bytes,
/// otherwise its hash.
fn child_ref(node: &Item, store: &mut HashMap<[u8; 32], Vec<u8>>) -> Item {
    let enc = node.encode();
    if enc.len() < 32 {
        return node.clone();
    }
    let h = hash(&enc);
    store.insert(h, enc);
    Item::Str(h.to_vec())
}

/// A remaining key path in nibbles, paired with the value it leads to.
type Entry = (Vec<u8>, Vec<u8>);

fn build_node(entries: &[Entry], store: &mut HashMap<[u8; 32], Vec<u8>>) -> Item {
    if entries.len() == 1 {
        let (path, value) = &entries[0];
        return Item::List(vec![
            Item::str(hex_prefix(path, true)),
            Item::str(value.clone()),
        ]);
    }

    // A shared prefix becomes an extension node.
    let first = &entries[0].0;
    let mut shared = 0usize;
    while entries
        .iter()
        .all(|(p, _)| p.len() > shared && p[shared] == first[shared])
    {
        shared += 1;
    }
    if shared > 0 {
        let stripped: Vec<Entry> = entries
            .iter()
            .map(|(p, v)| (p[shared..].to_vec(), v.clone()))
            .collect();
        let child = build_node(&stripped, store);
        return Item::List(vec![
            Item::str(hex_prefix(&first[..shared], false)),
            child_ref(&child, store),
        ]);
    }

    // Otherwise a branch, split on the first nibble.
    let mut slots: Vec<Item> = vec![Item::empty(); 17];
    let mut buckets: HashMap<u8, Vec<Entry>> = HashMap::new();
    for (path, value) in entries {
        match path.split_first() {
            None => slots[16] = Item::str(value.clone()),
            Some((nib, rest)) => buckets
                .entry(*nib)
                .or_default()
                .push((rest.to_vec(), value.clone())),
        }
    }
    for (nib, group) in buckets {
        let child = build_node(&group, store);
        slots[nib as usize] = child_ref(&child, store);
    }
    Item::List(slots)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_prefix_matches_the_yellow_paper() {
        assert_eq!(hex_prefix(&[], false), vec![0x00], "even extension");
        assert_eq!(hex_prefix(&[0xa], false), vec![0x1a], "odd extension");
        assert_eq!(hex_prefix(&[], true), vec![0x20], "even leaf");
        assert_eq!(hex_prefix(&[0xa], true), vec![0x3a], "odd leaf");
        assert_eq!(hex_prefix(&[1, 2], true), vec![0x20, 0x12], "even leaf pair");
    }

    #[test]
    fn index_zero_keys_to_the_empty_string() {
        // rlp(0) is 0x80, not 0x00. Getting this wrong shifts every key.
        assert_eq!(key_for(0), vec![0x80]);
        assert_eq!(key_for(1), vec![0x01]);
        assert_eq!(key_for(127), vec![0x7f]);
        assert_eq!(key_for(128), vec![0x81, 0x80]);
        assert_eq!(key_for(256), vec![0x82, 0x01, 0x00]);
    }

    /// The canonical empty-trie root, from the yellow paper.
    #[test]
    fn empty_trie_is_not_built() {
        // A trie over no values has the well-known root; we never build one,
        // but the constant is worth pinning as documentation.
        let known = "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421";
        assert_eq!(hex::encode(hash(&Item::empty().encode())), known);
    }

    #[test]
    fn single_entry_trie_round_trips() {
        let values = vec![b"the-receipt".to_vec()];
        let t = Trie::build(&values);
        let proof = t.proof(&key_for(0)).unwrap();
        assert_eq!(proof.len(), 1, "a one-entry trie is a lone leaf");

        let node = decode_all(&proof[0]).unwrap();
        match node {
            Item::List(items) => {
                assert_eq!(items.len(), 2, "leaf has two items");
                assert_eq!(items[1], Item::str(values[0].clone()), "leaf value");
            }
            _ => panic!("expected a list"),
        }
    }

    #[test]
    fn multi_entry_trie_yields_a_path_per_key() {
        // Values large enough that children are hash-referenced rather than
        // inlined, which is the case real receipts hit.
        let values: Vec<Vec<u8>> = (0..24u8).map(|i| vec![i; 64]).collect();
        let t = Trie::build(&values);

        for (i, value) in values.iter().enumerate() {
            let proof = t.proof(&key_for(i)).unwrap();
            assert!(!proof.is_empty(), "empty proof for {i}");

            // The first node must hash to the root.
            assert_eq!(hash(&proof[0]), t.root, "proof {i} not rooted");

            // The last node must be a leaf holding this value.
            let last = decode_all(proof.last().unwrap()).unwrap();
            match last {
                Item::List(items) if items.len() == 2 => {
                    assert_eq!(items[1], Item::str(value.clone()), "leaf value {i}");
                }
                Item::List(items) if items.len() == 17 => {
                    assert_eq!(items[16], Item::str(value.clone()), "branch value {i}");
                }
                _ => panic!("proof {i} does not end at a value"),
            }
        }
    }

    #[test]
    fn proof_nodes_chain_by_hash() {
        let values: Vec<Vec<u8>> = (0..40u8).map(|i| vec![i; 80]).collect();
        let t = Trie::build(&values);
        let proof = t.proof(&key_for(17)).unwrap();
        assert!(proof.len() >= 2, "expected a multi-level proof");

        // Every node after the first must be referenced by its parent.
        for w in proof.windows(2) {
            let (parent, child) = (&w[0], &w[1]);
            let want = hash(child);
            let parent_node = decode_all(parent).unwrap();
            let refs: Vec<Vec<u8>> = match parent_node {
                Item::List(items) => items
                    .iter()
                    .filter_map(|i| match i {
                        Item::Str(b) if b.len() == 32 => Some(b.clone()),
                        _ => None,
                    })
                    .collect(),
                _ => vec![],
            };
            assert!(
                refs.iter().any(|r| r[..] == want[..]),
                "child not referenced by its parent"
            );
        }
    }
}
