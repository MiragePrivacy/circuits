//! Field-level checks for the two ancestor node shapes.
//!
//! Both tries are keyed by `rlp(transactionIndex)`, so every value slot is
//! empty and every child is a 32-byte hash reference: a key is never a prefix
//! of another, and every node below the root holds at least one whole
//! transaction or receipt. That fixes each shape's layout up to a handful of
//! witnessed parameters, which the node bytes are then checked against.
//!
//! - A branch is `header || slot_0 .. slot_15 || 0x80`, each slot `0x80` or
//!   `0xa0 || hash`. Sixteen occupancy bits determine every offset and the
//!   list header.
//! - An extension is `RLP([HP(path, false), hash])` with a path of one to five
//!   nibbles. Its bytes up to the hash follow from the key, so it is compared
//!   against the key instead of decoded.
//!
//! A wrong witness parameter cannot misparse the node: every byte the layout
//! implies is checked, and the layout is the unique RLP parse of those bytes.

use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};

use crate::bytes::{dot, one_hot_in_range};

const EMPTY: u64 = 0x80;
const HASH_REF: u64 = 0xa0;

fn constant<F: PrimeField>(v: u64) -> FpVar<F> {
    FpVar::constant(F::from(v))
}

/// The key as nibbles, high half of each byte first. Free: each nibble is a
/// linear combination of the key's existing bits.
pub struct KeyNibbles<F: PrimeField> {
    nibbles: Vec<FpVar<F>>,
}

impl<F: PrimeField> KeyNibbles<F> {
    pub fn new(key: &[UInt8<F>]) -> Result<Self, SynthesisError> {
        use ark_r1cs_std::convert::ToBitsGadget;
        let mut nibbles = Vec::with_capacity(key.len() * 2);
        for byte in key {
            let bits = byte.to_bits_le()?;
            let half = |from: usize| {
                (0..4).fold(FpVar::zero(), |acc, i| {
                    acc + FpVar::from(bits[from + i].clone()) * constant::<F>(1 << i)
                })
            };
            nibbles.push(half(4));
            nibbles.push(half(0));
        }
        Ok(Self { nibbles })
    }

    pub fn len(&self) -> usize {
        self.nibbles.len()
    }

    /// One-hot position of `consumed` over `0..=len`. Always in range: a path
    /// can never consume more nibbles than the key has.
    pub fn position(&self, consumed: &FpVar<F>) -> Result<Vec<Boolean<F>>, SynthesisError> {
        one_hot_in_range(consumed, self.nibbles.len() + 1, &Boolean::TRUE)
    }

    /// The nibble `t` past `position`, zero past the key.
    pub fn at(&self, position: &[Boolean<F>], t: usize) -> FpVar<F> {
        let tail = self.nibbles.get(t..).unwrap_or(&[]);
        dot(position, tail)
    }
}

/// Native occupancy of a well-formed branch with an empty value slot. Witness
/// generation only; a wrong answer fails the checks rather than passing them.
pub fn native_occupancy(node: &[u8]) -> [bool; 16] {
    let mut occupied = [false; 16];
    let mut at = match node.first() {
        Some(0xc0..=0xf7) => 1,
        Some(&p @ 0xf8..=0xff) => 1 + (p - 0xf7) as usize,
        _ => return occupied,
    };
    for slot in occupied.iter_mut() {
        match node.get(at) {
            Some(0xa0) => {
                *slot = true;
                at += 33;
            }
            _ => at += 1,
        }
    }
    occupied
}

/// Native extension path length, or zero for anything that is not a
/// two-item node with a hash tail.
pub fn native_extension_nibbles(node: &[u8]) -> usize {
    let path = match node.get(1) {
        Some(&b) if b < 0x80 => vec![b],
        Some(&b @ 0x81..=0xb7) => node.get(2..2 + (b - 0x80) as usize).unwrap_or(&[]).to_vec(),
        _ => return 0,
    };
    match path.first() {
        Some(&flag) if flag >> 4 == 0 => 2 * (path.len() - 1),
        Some(&flag) if flag >> 4 == 1 => 2 * path.len() - 1,
        _ => 0,
    }
}

/// Checks a branch node's layout and returns the offset of the child hash at
/// `nibble`, which must be occupied.
///
/// Every check binds only when `active`. `node` is the field-valued buffer and
/// must be the same bytes the caller hashes.
pub fn branch<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    node: &[FpVar<F>],
    len: &FpVar<F>,
    occupied: [bool; 16],
    nibble: &FpVar<F>,
    active: &Boolean<F>,
) -> Result<FpVar<F>, SynthesisError> {
    let occ = occupied
        .iter()
        .map(|&o| Boolean::new_witness(cs.clone(), || Ok(o)))
        .collect::<Result<Vec<_>, _>>()?;

    // count[i][c] = [c occupied slots precede slot i], built incrementally so
    // each vector is one-hot by construction.
    let mut count: Vec<Vec<FpVar<F>>> = vec![vec![FpVar::one()]];
    for (i, o) in occ.iter().enumerate() {
        let o = FpVar::from(o.clone());
        let prev = &count[i];
        let next = (0..=i + 1)
            .map(|c| {
                let stay = prev.get(c).cloned().unwrap_or_else(FpVar::zero);
                let moved = match c {
                    0 => FpVar::zero(),
                    _ => prev[c - 1].clone(),
                };
                &stay + &o * (moved - &stay)
            })
            .collect();
        count.push(next);
    }
    let pop = &count[16];

    // The list header is 1, 2 or 3 bytes as the payload `17 + 32 * pop` is
    // below 56, below 256, or neither.
    let two = FpVar::one() - &pop[0] - &pop[1];
    let three = pop[8..].iter().fold(FpVar::zero(), |acc, p| acc + p);
    let header_len = FpVar::one() + &two + &three;

    // shifted(k) = node[header_len + k], for the few k a slot can start at.
    let zero = FpVar::zero();
    let byte = |k: usize| node.get(k).unwrap_or(&zero).clone();
    let mut cache = std::collections::HashMap::new();
    let mut shifted = |k: usize| -> FpVar<F> {
        cache
            .entry(k)
            .or_insert_with(|| {
                let one = byte(k + 1);
                let two_ = byte(k + 2);
                &one + &two * (&two_ - &one) + &three * (byte(k + 3) - &two_)
            })
            .clone()
    };

    // Slot i starts at i + 32c for the c occupied slots before it.
    for (i, o) in occ.iter().enumerate() {
        let prefix = (0..=i).fold(FpVar::zero(), |acc, c| acc + &count[i][c] * shifted(i + 32 * c));
        let want = constant::<F>(EMPTY) + FpVar::from(o.clone()) * constant::<F>(HASH_REF - EMPTY);
        prefix.conditional_enforce_equal(&want, active)?;
    }
    let value = (0..=16).fold(FpVar::zero(), |acc, c| acc + &pop[c] * shifted(16 + 32 * c));
    value.conditional_enforce_equal(&constant(EMPTY), active)?;

    let payload = |c: usize| 17 + 32 * c as u64;
    let expect = |f: &dyn Fn(usize) -> u64, from: usize| {
        (from..=16).fold(FpVar::zero(), |acc, c| acc + &pop[c] * constant::<F>(f(c)))
    };
    let first = expect(
        &|c| match payload(c) {
            p if p < 56 => 0xc0 + p,
            p if p < 256 => 0xf8,
            _ => 0xf9,
        },
        0,
    );
    byte(0).conditional_enforce_equal(&first, active)?;
    let active_f = FpVar::from(active.clone());
    let second = expect(
        &|c| match payload(c) {
            p if p < 256 => p,
            p => p >> 8,
        },
        2,
    );
    ((byte(1) - second) * (&two * &active_f)).enforce_equal(&zero)?;
    let third = expect(&|c| payload(c) & 0xff, 8);
    ((byte(2) - third) * (&three * &active_f)).enforce_equal(&zero)?;

    let pop_value = (0..=16).fold(FpVar::zero(), |acc, c| acc + &pop[c] * constant::<F>(c as u64));
    let want_len = &header_len + constant::<F>(17) + pop_value * constant::<F>(32);
    len.conditional_enforce_equal(&want_len, active)?;

    // The followed slot must hold a hash, or the key leads nowhere.
    let sel = one_hot_in_range(nibble, 16, active)?;
    let hit = sel
        .iter()
        .zip(occ.iter())
        .fold(FpVar::zero(), |acc, (s, o)| acc + FpVar::from(s.clone() & o));
    hit.conditional_enforce_equal(&FpVar::one(), active)?;

    let before = count[..16].iter().map(|slot| {
        slot.iter()
            .enumerate()
            .fold(FpVar::zero(), |acc, (c, p)| acc + p * constant::<F>(c as u64))
    });
    let preceding = sel
        .iter()
        .zip(before)
        .fold(FpVar::zero(), |acc, (s, n)| acc + FpVar::from(s.clone()) * n);
    Ok(header_len + nibble + FpVar::one() + preceding * constant::<F>(32))
}

/// Checks an extension node against the key and returns `(hash offset,
/// nibbles consumed)`, both zero when inactive.
///
/// `path[t]` is the key nibble `t` past the current position. The five layouts
/// are `c0+len || HP || 0xa0 || hash`, with HP bare for one nibble and a short
/// string otherwise.
pub fn extension<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    node: &[FpVar<F>],
    len: &FpVar<F>,
    nibbles: usize,
    path: &[FpVar<F>; 5],
    active: &Boolean<F>,
) -> Result<(FpVar<F>, FpVar<F>), SynthesisError> {
    let pair = |a: usize| &path[a] * constant::<F>(16) + &path[a + 1];
    let odd = || &path[0] + constant::<F>(0x10);
    let layouts: [Vec<FpVar<F>>; 5] = [
        vec![odd()],
        vec![constant(0x82), constant(0x00), pair(0)],
        vec![constant(0x82), odd(), pair(1)],
        vec![constant(0x83), constant(0x00), pair(0), pair(2)],
        vec![constant(0x83), odd(), pair(1), pair(3)],
    ];

    let mut any = FpVar::zero();
    let mut want_len = FpVar::zero();
    let mut offset = FpVar::zero();
    let mut step = FpVar::zero();
    for (m, hp) in layouts.iter().enumerate() {
        let selected = Boolean::new_witness(cs.clone(), || Ok(nibbles == m + 1))?;
        let body = hp.len() + 33;
        let mut expected = vec![constant::<F>(0xc0 + body as u64)];
        expected.extend(hp.iter().cloned());
        expected.push(constant(HASH_REF));
        for (got, want) in node.iter().zip(expected.iter()) {
            got.conditional_enforce_equal(want, &selected)?;
        }
        let s = FpVar::from(selected);
        any += &s;
        want_len += &s * constant::<F>(body as u64 + 1);
        offset += &s * constant::<F>(hp.len() as u64 + 2);
        step += &s * constant::<F>(m as u64 + 1);
    }
    any.enforce_equal(&FpVar::from(active.clone()))?;
    len.conditional_enforce_equal(&want_len, active)?;
    Ok((offset, step))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_r1cs_std::GR1CSVar;
    use ark_relations::gr1cs::ConstraintSystem;

    use crate::bytes::{alloc_bounded, shift_window, to_fields};
    use crate::mpt::tests::{branch_node, extension_node, hex_prefix, leaf_node};

    const BOUND: usize = 532;

    fn child(slot: usize) -> Vec<u8> {
        leaf_node(&[slot as u8], &[slot as u8 + 1; 40])
    }

    /// A branch with an empty value slot whose occupied slots hold distinct
    /// hashed children.
    fn branch_with(occupied: [bool; 16]) -> Vec<u8> {
        let children = core::array::from_fn(|i| occupied[i].then(|| child(i)));
        branch_node(children, None)
    }

    fn pattern(slots: &[usize]) -> [bool; 16] {
        core::array::from_fn(|i| slots.contains(&i))
    }

    /// Runs the branch checker and the child read it feeds. Returns
    /// satisfiability and the 32 bytes read at the returned offset.
    fn run_branch(
        node: &[u8],
        len: usize,
        occupied: [bool; 16],
        nibble: u64,
        active: bool,
    ) -> (bool, Vec<u8>) {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let buf = alloc_bounded(cs.clone(), node, BOUND).unwrap();
        let fields = to_fields(&buf).unwrap();
        let len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(len as u64))).unwrap();
        let nibble = FpVar::new_witness(cs.clone(), || Ok(Fr::from(nibble))).unwrap();
        let active = Boolean::new_witness(cs.clone(), || Ok(active)).unwrap();
        let offset = branch(cs.clone(), &fields, &len, occupied, &nibble, &active).unwrap();
        let read = shift_window(&fields, &offset, 32).unwrap();
        let bytes = read
            .iter()
            .map(|b| {
                let v = b.value().unwrap();
                (0..=255u8).find(|x| Fr::from(*x as u64) == v).unwrap_or(0)
            })
            .collect();
        (cs.is_satisfied().unwrap(), bytes)
    }

    fn accepts(node: &[u8], occupied: [bool; 16], nibble: u64) -> bool {
        run_branch(node, node.len(), occupied, nibble, true).0
    }

    /// Covers each list-header width: one occupied slot (short list), two
    /// and seven (0xf8), eight and up (0xf9).
    #[test]
    fn branch_reads_every_occupied_child_at_every_header_width() {
        for slots in [
            vec![5],
            vec![0, 15],
            vec![0, 2, 4, 6, 8, 10, 12],
            vec![1, 3, 5, 7, 9, 11, 13, 15],
            (0..9).collect(),
            (0..16).collect(),
        ] {
            let occupied = pattern(&slots);
            let node = branch_with(occupied);
            for &slot in &slots {
                let (ok, read) = run_branch(&node, node.len(), occupied, slot as u64, true);
                assert!(ok, "rejected slot {slot} of {slots:?}");
                assert_eq!(
                    read,
                    mirage_encoding::keccak256(&child(slot)).to_vec(),
                    "read the wrong child for slot {slot} of {slots:?}"
                );
            }
        }
    }

    /// Any occupancy claim other than the node's own is a different parse,
    /// which would move the followed hash. Every single-bit lie must fail,
    /// whichever occupied slot is followed.
    #[test]
    fn branch_rejects_every_single_occupancy_flip() {
        for slots in [
            vec![3, 9],
            vec![1, 3, 5, 7, 9, 11, 13],
            vec![0, 1, 2, 3, 4, 5, 6, 7],
            (0..16).collect(),
        ] {
            let occupied = pattern(&slots);
            let node = branch_with(occupied);
            for &follow in &slots {
                for flip in 0..16 {
                    let mut lie = occupied;
                    lie[flip] = !lie[flip];
                    assert!(
                        !accepts(&node, lie, follow as u64),
                        "accepted occupancy flip {flip} of {slots:?} following {follow}"
                    );
                }
            }
        }
    }

    /// Moving an occupied slot keeps the count, header and length intact, so
    /// only the per-slot prefix checks can catch it. Following the moved slot
    /// would otherwise read 32 bytes straddling real children.
    #[test]
    fn branch_rejects_every_occupancy_swap() {
        for slots in [vec![3, 9], vec![0, 4, 8, 12, 15], vec![1, 2, 3, 4, 5, 6, 7, 8]] {
            let occupied = pattern(&slots);
            let node = branch_with(occupied);
            for &from in &slots {
                for to in (0..16).filter(|s| !occupied[*s]) {
                    let mut lie = occupied;
                    lie[from] = false;
                    lie[to] = true;
                    for follow in (0..16).filter(|s| lie[*s]) {
                        assert!(
                            !accepts(&node, lie, follow as u64),
                            "accepted slot {from} moved to {to} of {slots:?} following {follow}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn branch_rejects_following_an_empty_slot() {
        let occupied = pattern(&[2, 7]);
        let node = branch_with(occupied);
        for nibble in (0..16).filter(|n| ![2, 7].contains(n)) {
            assert!(!accepts(&node, occupied, nibble as u64), "followed empty slot {nibble}");
        }
    }

    #[test]
    fn branch_rejects_a_wrong_length() {
        let occupied = pattern(&[2, 7, 11]);
        let node = branch_with(occupied);
        for len in [node.len() - 32, node.len() - 1, node.len() + 1, node.len() + 32] {
            assert!(
                !run_branch(&node, len, occupied, 7, true).0,
                "accepted length {len} for a {}-byte node",
                node.len()
            );
        }
    }

    /// The tries never store a value in a branch, so a branch carrying one
    /// is not a shape the layout admits.
    #[test]
    fn branch_rejects_a_value_slot() {
        let occupied = pattern(&[2, 7]);
        let children = core::array::from_fn(|i| occupied[i].then(|| child(i)));
        let node = branch_node(children, Some(b"value"));
        assert!(!accepts(&node, occupied, 7));
    }

    /// A one-byte value keeps the node's length, so only the value-slot check
    /// sees it.
    #[test]
    fn branch_rejects_a_one_byte_value() {
        let occupied = pattern(&[2, 7]);
        let children = core::array::from_fn(|i| occupied[i].then(|| child(i)));
        let node = branch_node(children, Some(&[0x05]));
        assert_eq!(node.len(), branch_with(occupied).len());
        assert!(!accepts(&node, occupied, 7));
    }

    /// Every list-header byte is pinned by the occupancy count, at each width.
    #[test]
    fn branch_rejects_a_tampered_header_byte() {
        for slots in [vec![5], vec![0, 15], (0..9).collect::<Vec<_>>()] {
            let occupied = pattern(&slots);
            let node = branch_with(occupied);
            let header = match node[0] {
                0xf9 => 3,
                0xf8 => 2,
                _ => 1,
            };
            for at in 0..header {
                for delta in [1u8, 0x10, 0x80] {
                    let mut bad = node.clone();
                    bad[at] ^= delta;
                    assert!(
                        !accepts(&bad, occupied, slots[0] as u64),
                        "accepted header byte {at} ^ {delta:#x} of {slots:?}"
                    );
                }
            }
        }
    }

    /// A long-form header for a short payload is non-canonical RLP that
    /// shifts every slot by one byte.
    #[test]
    fn branch_rejects_a_non_canonical_header() {
        let occupied = pattern(&[2, 7]);
        let node = branch_with(occupied);
        assert_eq!(node[0], 0xf8, "fixture should use a one-byte length");
        let mut wide = vec![0xf9, 0x00];
        wide.extend_from_slice(&node[1..]);
        assert!(!accepts(&wide, occupied, 7));
    }

    #[test]
    fn branch_rejects_an_inlined_child() {
        let tiny = leaf_node(&[1], &[0xcc; 2]);
        assert!(tiny.len() < 32, "fixture should be inline-sized");
        let mut children: [Option<Vec<u8>>; 16] = Default::default();
        children[3] = Some(tiny);
        children[9] = Some(child(9));
        let node = branch_node(children, None);
        for claim in [pattern(&[9]), pattern(&[3, 9]), native_occupancy(&node)] {
            assert!(!accepts(&node, claim, 9), "accepted an inlined child under {claim:?}");
        }
    }

    #[test]
    fn branch_rejects_an_extension() {
        let node = extension_node(&[1, 2], &child(4));
        for slots in [vec![0], vec![1], vec![2, 3]] {
            for nibble in 0..16 {
                assert!(!accepts(&node, pattern(&slots), nibble));
            }
        }
    }

    #[test]
    fn branch_is_inert_when_inactive() {
        let garbage = vec![0xff; BOUND];
        let (ok, _) = run_branch(&garbage, 7, pattern(&[1, 4]), 3, false);
        assert!(ok, "an inactive branch check emitted a binding constraint");
    }

    /// Runs the extension checker with the key nibbles at the current
    /// position. Returns satisfiability, the hash read at the returned offset,
    /// and the nibbles consumed.
    fn run_extension(
        node: &[u8],
        len: usize,
        claimed: usize,
        path: [u8; 5],
        active: bool,
    ) -> (bool, Vec<u8>, u64) {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let buf = alloc_bounded(cs.clone(), node, BOUND).unwrap();
        let fields = to_fields(&buf).unwrap();
        let len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(len as u64))).unwrap();
        let path: [FpVar<Fr>; 5] = core::array::from_fn(|t| {
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(path[t] as u64))).unwrap()
        });
        let active = Boolean::new_witness(cs.clone(), || Ok(active)).unwrap();
        let (offset, step) = extension(cs.clone(), &fields, &len, claimed, &path, &active).unwrap();
        let read = shift_window(&fields, &offset, 32).unwrap();
        let to_u8 = |v: Fr| (0..=255u8).find(|x| Fr::from(*x as u64) == v).unwrap_or(0);
        let bytes = read.iter().map(|b| to_u8(b.value().unwrap())).collect();
        let step = to_u8(step.value().unwrap()) as u64;
        (cs.is_satisfied().unwrap(), bytes, step)
    }

    const KEY_PATH: [u8; 5] = [0x0, 0x1, 0xa, 0xf, 0x7];

    #[test]
    fn extension_reads_the_child_at_every_path_length() {
        for m in 1..=5 {
            let node = extension_node(&KEY_PATH[..m], &child(m));
            assert_eq!(native_extension_nibbles(&node), m);
            let (ok, read, step) = run_extension(&node, node.len(), m, KEY_PATH, true);
            assert!(ok, "rejected a {m}-nibble extension");
            assert_eq!(read, mirage_encoding::keccak256(&child(m)).to_vec());
            assert_eq!(step, m as u64);
        }
    }

    #[test]
    fn extension_rejects_every_wrong_length_claim() {
        for m in 1..=5 {
            let node = extension_node(&KEY_PATH[..m], &child(m));
            for claim in (0..=6).filter(|c| *c != m) {
                assert!(
                    !run_extension(&node, node.len(), claim, KEY_PATH, true).0,
                    "accepted a {m}-nibble extension claimed as {claim}"
                );
            }
        }
    }

    /// The extension's path must be the key's own nibbles, or the proof is
    /// about a different key.
    #[test]
    fn extension_rejects_a_path_that_is_not_the_key() {
        for m in 1..=5 {
            let node = extension_node(&KEY_PATH[..m], &child(m));
            for at in 0..m {
                let mut key = KEY_PATH;
                key[at] ^= 0x8;
                assert!(
                    !run_extension(&node, node.len(), m, key, true).0,
                    "accepted a {m}-nibble extension against a key differing at {at}"
                );
            }
        }
    }

    /// A leaf-flagged short node is a terminal value, not a link.
    #[test]
    fn extension_rejects_leaf_flags() {
        for m in 1..=5 {
            let hp = hex_prefix(&KEY_PATH[..m], true);
            let mut path_item = if hp.len() == 1 { hp.clone() } else { vec![0x80 + hp.len() as u8] };
            if hp.len() > 1 {
                path_item.extend_from_slice(&hp);
            }
            let mut body = path_item;
            body.push(0xa0);
            body.extend_from_slice(&mirage_encoding::keccak256(&child(m)));
            let mut node = vec![0xc0 + body.len() as u8];
            node.extend_from_slice(&body);
            for claim in 1..=5 {
                assert!(
                    !run_extension(&node, node.len(), claim, KEY_PATH, true).0,
                    "accepted a leaf-flagged {m}-nibble node claimed as {claim}"
                );
            }
        }
    }

    #[test]
    fn extension_rejects_a_nonzero_even_pad() {
        for m in [2, 4] {
            let mut node = extension_node(&KEY_PATH[..m], &child(m));
            assert_eq!(node[2], 0x00, "even path flag byte");
            node[2] = 0x05;
            assert!(!run_extension(&node, node.len(), m, KEY_PATH, true).0);
        }
    }

    #[test]
    fn extension_rejects_an_inlined_child() {
        let tiny = leaf_node(&[1], &[0xcc; 2]);
        let node = extension_node(&KEY_PATH[..2], &tiny);
        for claim in 1..=5 {
            assert!(!run_extension(&node, node.len(), claim, KEY_PATH, true).0);
        }
    }

    #[test]
    fn extension_rejects_a_branch() {
        let node = branch_with(pattern(&[0, 1]));
        for claim in 1..=5 {
            assert!(!run_extension(&node, node.len(), claim, KEY_PATH, true).0);
        }
    }

    #[test]
    fn extension_rejects_a_wrong_length() {
        let node = extension_node(&KEY_PATH[..3], &child(3));
        for len in [node.len() - 1, node.len() + 1] {
            assert!(!run_extension(&node, len, 3, KEY_PATH, true).0);
        }
    }

    /// An inactive slot's bytes are unauthenticated, so it must not be able to
    /// claim a layout: the nibbles it consumed would shift the key remainder
    /// the terminal leaf is built from.
    #[test]
    fn extension_cannot_consume_while_inactive() {
        for m in 1..=5 {
            let node = extension_node(&KEY_PATH[..m], &child(m));
            assert!(
                !run_extension(&node, node.len(), m, KEY_PATH, false).0,
                "an inactive slot consumed {m} nibbles"
            );
        }
    }

    #[test]
    fn extension_is_inert_when_inactive() {
        let garbage = vec![0xff; BOUND];
        let (ok, _, step) = run_extension(&garbage, 9, 0, KEY_PATH, false);
        assert!(ok, "an inactive extension check emitted a binding constraint");
        assert_eq!(step, 0, "an inactive extension consumed nibbles");
    }
}
