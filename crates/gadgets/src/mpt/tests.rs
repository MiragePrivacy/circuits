//! Adversarial suite for MPT inclusion.
//!
//! Written before the implementation. Each negative case names the forgery it
//! prevents, and every one of them is a path to proving a receipt that is not
//! in the trie — which is a path to collecting an escrow without settling.
//!
//! The fixtures are built with a native trie implementation so the tests grade
//! the circuit against real Ethereum encoding rather than against itself.

use super::*;
use ark_bn254::Fr;

// --------------------------------------------------------------- fixtures

/// Native hex-prefix encoding, as used by extension and leaf path fields.
///
/// The first nibble carries two flags: bit 1 marks a leaf, bit 0 marks an odd
/// nibble count. An odd path packs its first nibble into the low half of the
/// flag byte; an even path is followed by a zero pad nibble.
pub fn hex_prefix(nibbles: &[u8], is_leaf: bool) -> Vec<u8> {
    let odd = nibbles.len() % 2 == 1;
    let flag = (if is_leaf { 2u8 } else { 0 }) | (if odd { 1 } else { 0 });

    let mut out = Vec::new();
    if odd {
        out.push((flag << 4) | nibbles[0]);
        for pair in nibbles[1..].chunks(2) {
            out.push((pair[0] << 4) | pair[1]);
        }
    } else {
        out.push(flag << 4);
        for pair in nibbles.chunks(2) {
            out.push((pair[0] << 4) | pair[1]);
        }
    }
    out
}

/// Splits a byte string into nibbles, high half first.
pub fn to_nibbles(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(b >> 4);
        out.push(b & 0x0f);
    }
    out
}

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

fn keccak(b: &[u8]) -> [u8; 32] {
    mirage_encoding::keccak256(b)
}

/// A leaf node: hex-prefixed remaining path, then the value.
pub fn leaf_node(path_nibbles: &[u8], value: &[u8]) -> Vec<u8> {
    enc_list(&[enc_str(&hex_prefix(path_nibbles, true)), enc_str(value)])
}

/// An extension node: hex-prefixed shared path, then a child reference.
pub fn extension_node(path_nibbles: &[u8], child: &[u8]) -> Vec<u8> {
    enc_list(&[enc_str(&hex_prefix(path_nibbles, false)), child_ref(child)])
}

/// A branch node: 16 child slots plus a value slot.
pub fn branch_node(children: [Option<Vec<u8>>; 16], value: Option<&[u8]>) -> Vec<u8> {
    let mut items: Vec<Vec<u8>> = Vec::with_capacity(17);
    for c in children {
        items.push(match c {
            Some(node) => child_ref(&node),
            None => enc_str(&[]),
        });
    }
    items.push(match value {
        Some(v) => enc_str(v),
        None => enc_str(&[]),
    });
    enc_list(&items)
}

/// A child reference: the node inlined if under 32 bytes, else its hash.
pub fn child_ref(node: &[u8]) -> Vec<u8> {
    if node.len() < 32 {
        node.to_vec()
    } else {
        enc_str(&keccak(node))
    }
}

/// A two-level trie: root branch, one leaf under nibble `n`.
///
/// Returns (root hash, key, value, nodes root-first).
pub fn simple_trie(n: u8, key: &[u8], value: &[u8]) -> ([u8; 32], Vec<u8>, Vec<u8>, Vec<Vec<u8>>) {
    let nibbles = to_nibbles(key);
    assert_eq!(
        nibbles[0], n,
        "key's first nibble must select the branch slot"
    );

    let leaf = leaf_node(&nibbles[1..], value);
    let mut children: [Option<Vec<u8>>; 16] = Default::default();
    children[n as usize] = Some(leaf.clone());
    let root = branch_node(children, None);

    (
        keccak(&root),
        key.to_vec(),
        value.to_vec(),
        vec![root, leaf],
    )
}

// ---------------------------------------------------------------- harness

use super::harness::{cost, verify, NativeProof};

/// A genuine proof: root branch, one leaf under the key's first nibble.
fn genuine() -> NativeProof {
    let key = vec![0x35, 0x71];
    let value = b"a-receipt-standing-in-for-the-real-thing".to_vec();
    let (root, key, value, nodes) = simple_trie(0x3, &key, &value);
    NativeProof {
        root,
        key,
        value,
        nodes,
    }
}

// ------------------------------------------------------- positive cases

/// The baseline. If this fails nothing else means anything.
pub fn accepts_genuine_proof<V: MptVerifier<Fr>>() {
    let g = genuine();
    if !verify::<V>(&g) {
        panic!(
            "rejected a genuine inclusion proof\n  unsatisfied: {:?}",
            super::harness::which_failed::<V>(&g)
        );
    }
}

/// The fixtures must themselves be valid Ethereum encodings, or every other
/// test grades the circuit against nonsense.
pub fn fixtures_are_well_formed() {
    // Hex-prefix flags, from the yellow paper.
    assert_eq!(hex_prefix(&[], false), vec![0x00], "even extension");
    assert_eq!(hex_prefix(&[0xa], false), vec![0x1a], "odd extension");
    assert_eq!(hex_prefix(&[], true), vec![0x20], "even leaf");
    assert_eq!(hex_prefix(&[0xa], true), vec![0x3a], "odd leaf");
    assert_eq!(
        hex_prefix(&[0x1, 0x2], true),
        vec![0x20, 0x12],
        "even leaf, two nibbles"
    );

    assert_eq!(to_nibbles(&[0x35, 0x71]), vec![3, 5, 7, 1]);

    // Branch node sizes vary sharply with how many children are populated,
    // which matters for the bounds measurement: a single structural estimate
    // is not enough, the real distribution is needed.
    //
    // One hash child plus 15 empties: 33 + 16 = 49 payload bytes, short form.
    let big_leaf = leaf_node(&[5, 7, 1], &[0xaa; 40]);
    assert!(big_leaf.len() >= 32, "leaf should be hash-referenced");
    let mut children: [Option<Vec<u8>>; 16] = Default::default();
    children[3] = Some(big_leaf);
    let sparse = branch_node(children, None);
    assert_eq!(sparse.len(), 50, "sparse branch");
    assert_eq!(sparse[0], 0xf1, "sparse branch uses short-form list prefix");

    // All 16 children hash-referenced: 16*33 + 1 = 529 payload bytes. The
    // ~530 byte figure quoted for branch nodes is this worst case, not the
    // typical one.
    let mut full: [Option<Vec<u8>>; 16] = Default::default();
    for slot in full.iter_mut() {
        *slot = Some(leaf_node(&[1, 2, 3], &[0xbb; 40]));
    }
    let dense = branch_node(full, None);
    assert_eq!(dense.len(), 532, "dense branch");
    assert_eq!(dense[0], 0xf9, "dense branch uses two length bytes");

    // The genuine proof must be internally consistent before it can serve as
    // the base for corruption.
    let g = genuine();
    assert_eq!(keccak(&g.nodes[0]), g.root, "root hash mismatch in fixture");
    assert_eq!(g.nodes.len(), 2, "expected a branch and a leaf");
}

// -------------------------------------------------------- forgery cases
//
// Each takes the genuine proof and corrupts exactly one thing. The `Null`
// verifier accepts all of them, which is how the suite proves it has teeth.

/// **Forgery: a node not authenticated against its parent.**
///
/// The core of the construction. If `keccak(node[i])` is not enforced equal to
/// the reference selected in `node[i-1]`, a prover substitutes any node and
/// proves any value.
pub fn rejects_unlinked_node<V: MptVerifier<Fr>>() {
    let mut p = genuine();
    // Replace the leaf with one holding a different value. The root branch
    // still references the original leaf's hash, so the link is broken.
    let nibbles = to_nibbles(&p.key);
    p.nodes[1] = leaf_node(&nibbles[1..], b"a-value-the-prover-would-prefer");
    assert!(
        !verify::<V>(&p),
        "accepted a node not matching its parent reference"
    );
}

/// **Forgery: root hash not checked against the claimed root.**
///
/// Without anchoring, the prover builds an entire self-consistent trie
/// containing whatever it wants.
pub fn rejects_wrong_root<V: MptVerifier<Fr>>() {
    let mut p = genuine();
    p.root[0] ^= 0xff;
    assert!(!verify::<V>(&p), "accepted a proof against the wrong root");
}

/// **Forgery: following the wrong branch slot.**
///
/// The child taken from a branch must be the one at the key's current nibble.
/// Here the leaf is placed in slot 4 while the key selects slot 3.
pub fn rejects_wrong_nibble_child<V: MptVerifier<Fr>>() {
    let key = vec![0x35, 0x71];
    let value = b"a-receipt".to_vec();
    let nibbles = to_nibbles(&key);
    let leaf = leaf_node(&nibbles[1..], &value);

    let mut children: [Option<Vec<u8>>; 16] = Default::default();
    children[4] = Some(leaf.clone()); // key says 3
    let root = branch_node(children, None);

    let p = NativeProof {
        root: keccak(&root),
        key,
        value,
        nodes: vec![root, leaf],
    };
    assert!(
        !verify::<V>(&p),
        "accepted a child from the wrong nibble slot"
    );
}

/// **Forgery: leaf path does not match the key remainder.**
///
/// A leaf's hex-prefix path must equal what is left of the key. Skipping the
/// comparison proves inclusion at any key sharing a prefix.
pub fn rejects_leaf_path_mismatch<V: MptVerifier<Fr>>() {
    let key = vec![0x35, 0x71];
    let value = b"a-receipt".to_vec();
    // Leaf claims path 5,7,2 while the key's remainder is 5,7,1.
    let leaf = leaf_node(&[5, 7, 2], &value);

    let mut children: [Option<Vec<u8>>; 16] = Default::default();
    children[3] = Some(leaf.clone());
    let root = branch_node(children, None);

    let p = NativeProof {
        root: keccak(&root),
        key,
        value,
        nodes: vec![root, leaf],
    };
    assert!(
        !verify::<V>(&p),
        "accepted a leaf whose path differs from the key"
    );
}

/// **Forgery: extension path not compared.**
///
/// The same failure one level up: an extension's path must match the next key
/// nibbles, or the traversal jumps to an unrelated subtree.
pub fn rejects_extension_path_mismatch<V: MptVerifier<Fr>>() {
    let key = vec![0x35, 0x71];
    let value = b"a-receipt".to_vec();

    // root -> extension(claims 5,7 but key has 5,7 after nibble 3) -> leaf
    // Corrupt the extension to claim 9,9.
    let leaf = leaf_node(&[], &value);
    let ext = extension_node(&[9, 9], &leaf);
    let mut children: [Option<Vec<u8>>; 16] = Default::default();
    children[3] = Some(ext.clone());
    let root = branch_node(children, None);

    let p = NativeProof {
        root: keccak(&root),
        key,
        value,
        nodes: vec![root, ext, leaf],
    };
    assert!(
        !verify::<V>(&p),
        "accepted an extension whose path differs from the key"
    );
}

/// **Forgery: hex-prefix flags ignored.**
///
/// Reading a leaf as an extension, or misreading the odd-length flag, shifts
/// the path by a nibble. Both flag bits must be enforced.
pub fn rejects_hex_prefix_flag_confusion<V: MptVerifier<Fr>>() {
    let key = vec![0x35, 0x71];
    let value = b"a-receipt".to_vec();
    let nibbles = to_nibbles(&key);

    // Build a leaf then flip its leaf flag to extension, keeping everything
    // else identical. A verifier ignoring the flag treats the value as a
    // child reference.
    let mut leaf = leaf_node(&nibbles[1..], &value);
    // The path field is the second byte of the node (after the list prefix);
    // clear bit 5 of its first nibble.
    let path_byte = 2;
    leaf[path_byte] &= 0xdf;

    let mut children: [Option<Vec<u8>>; 16] = Default::default();
    children[3] = Some(leaf.clone());
    let root = branch_node(children, None);

    let p = NativeProof {
        root: keccak(&root),
        key,
        value,
        nodes: vec![root, leaf],
    };
    assert!(
        !verify::<V>(&p),
        "accepted a node with a corrupted hex-prefix flag"
    );
}

/// **Forgery: an inactive depth slot treated as active.**
///
/// Slots past the real depth are held inert. If a prover activates one and
/// supplies a node, it extends the trie with a node of its choosing.
pub fn rejects_active_slot_past_depth<V: MptVerifier<Fr>>() {
    let mut p = genuine();
    // Append an unrelated node after the leaf. Nothing references it, so a
    // correct verifier must either ignore it or reject; it must never treat
    // its value as the proven one.
    p.nodes.push(leaf_node(&[1, 2], b"an-appended-node"));
    assert!(
        !verify::<V>(&p),
        "accepted a proof with a node past the terminating leaf"
    );
}

/// **Forgery: value at the leaf not bound to the claimed value.**
///
/// The point of the whole proof. The leaf's value field must equal the receipt
/// the relation goes on to parse.
pub fn rejects_value_mismatch<V: MptVerifier<Fr>>() {
    let mut p = genuine();
    p.value = b"a-different-receipt-entirely".to_vec();
    assert!(!verify::<V>(&p), "accepted a value not present at the leaf");
}

/// **Forgery: key not fully consumed.**
///
/// Terminating at a leaf while key nibbles remain proves inclusion of a
/// different key.
pub fn rejects_partial_key_consumption<V: MptVerifier<Fr>>() {
    let key = vec![0x35, 0x71];
    let value = b"a-receipt".to_vec();
    // Leaf claims to terminate after consuming only one further nibble.
    let leaf = leaf_node(&[5], &value);

    let mut children: [Option<Vec<u8>>; 16] = Default::default();
    children[3] = Some(leaf.clone());
    let root = branch_node(children, None);

    let p = NativeProof {
        root: keccak(&root),
        key,
        value,
        nodes: vec![root, leaf],
    };
    assert!(
        !verify::<V>(&p),
        "accepted a leaf that leaves key nibbles unconsumed"
    );
}

/// **Forgery: the value is present at a non-terminating level.**
///
/// Specific to the optimization that hoists the value comparison out of the
/// per-level loop. That check now runs once, against a node buffer selected by
/// the `terminates` flag. If the selection is wrong — picking the last active
/// level, say, or the first — a prover can place the claimed value in a branch
/// node's value slot and satisfy the check without a leaf holding it.
///
/// Here the root branch's value slot holds the claimed value while the leaf
/// holds something else. Only the leaf's value may satisfy invariant 6.
pub fn rejects_value_at_a_non_terminating_level<V: MptVerifier<Fr>>() {
    let key = vec![0x35, 0x71];
    let claimed = b"the-value-the-prover-wants-to-prove".to_vec();
    let nibbles = to_nibbles(&key);

    // Leaf holds something else entirely.
    let leaf = leaf_node(&nibbles[1..], b"what-the-leaf-actually-holds");
    let mut children: [Option<Vec<u8>>; 16] = Default::default();
    children[3] = Some(leaf.clone());
    // Root branch's value slot holds the claimed value.
    let root = branch_node(children, Some(&claimed));

    let p = NativeProof {
        root: keccak(&root),
        key,
        value: claimed,
        nodes: vec![root, leaf],
    };
    assert!(
        !verify::<V>(&p),
        "accepted a value taken from a non-terminating level"
    );
}

// ------------------------------------------------------------- the suite

/// Every forgery case, run against one verifier.
pub fn run_forgeries<V: MptVerifier<Fr>>() {
    rejects_unlinked_node::<V>();
    rejects_wrong_root::<V>();
    rejects_wrong_nibble_child::<V>();
    rejects_leaf_path_mismatch::<V>();
    rejects_extension_path_mismatch::<V>();
    rejects_hex_prefix_flag_confusion::<V>();
    rejects_active_slot_past_depth::<V>();
    rejects_value_mismatch::<V>();
    rejects_value_at_a_non_terminating_level::<V>();
    rejects_partial_key_consumption::<V>();
}

/// The full suite: the genuine proof must verify and every forgery must not.
pub fn run_suite<V: MptVerifier<Fr>>() {
    accepts_genuine_proof::<V>();
    run_forgeries::<V>();
}

#[test]
fn fixture_sanity() {
    fixtures_are_well_formed();
}

/// The suite must have teeth: a verifier enforcing nothing must fail every
/// forgery case. If any of these passes against `Null`, that case is not
/// testing anything and would give false confidence against the real
/// implementation.
#[test]
fn forgeries_defeat_the_null_verifier() {
    use super::null::Null;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    let cases: Vec<(&str, fn())> = vec![
        ("unlinked_node", || rejects_unlinked_node::<Null>()),
        ("wrong_root", || rejects_wrong_root::<Null>()),
        ("wrong_nibble_child", || {
            rejects_wrong_nibble_child::<Null>()
        }),
        ("leaf_path_mismatch", || {
            rejects_leaf_path_mismatch::<Null>()
        }),
        ("extension_path_mismatch", || {
            rejects_extension_path_mismatch::<Null>()
        }),
        ("hex_prefix_flag_confusion", || {
            rejects_hex_prefix_flag_confusion::<Null>()
        }),
        ("active_slot_past_depth", || {
            rejects_active_slot_past_depth::<Null>()
        }),
        ("value_mismatch", || rejects_value_mismatch::<Null>()),
        ("value_at_non_terminating_level", || {
            rejects_value_at_a_non_terminating_level::<Null>()
        }),
        ("partial_key_consumption", || {
            rejects_partial_key_consumption::<Null>()
        }),
    ];

    for (name, case) in cases {
        let caught = catch_unwind(AssertUnwindSafe(case));
        assert!(
            caught.is_err(),
            "forgery case `{name}` passed against a verifier that enforces \
             nothing, so it is not testing anything"
        );
    }
}

/// Reports the cost of one verification, once an implementation exists.
pub fn report_cost<V: MptVerifier<Fr>>(label: &str) {
    println!(
        "{label}: inclusion proof: {} constraints",
        cost::<V>(&genuine())
    );
}
