//! Merkle-Patricia-Trie inclusion for the receipt trie.
//!
//! Proves that a receipt sits at key `rlp(transactionIndex)` under a claimed
//! `receiptsRoot`. Spec 12.5.
//!
//! # Node types
//!
//! Ethereum's hexary MPT has three:
//!
//! - **Branch**: 17 items. Sixteen child references indexed by nibble, plus a
//!   value slot. Each child is empty (`0x80`), a 32-byte hash (`0xa0` + 32), or
//!   an inlined node under 32 bytes.
//! - **Extension**: 2 items. A hex-prefix-encoded partial path and a child
//!   reference.
//! - **Leaf**: 2 items. A hex-prefix-encoded path remainder and the value.
//!
//! Extension and leaf are distinguished by the high nibble of the first
//! path byte: bit 5 set means leaf. Bit 4 set means the path has an odd number
//! of nibbles, so the low nibble of that first byte is path data.
//!
//! # Why branch nodes get a specialized decoder
//!
//! A general `rlp::decode_list(17)` walks every child to find the next offset,
//! and each step is a witness-indexed read. But branch children are almost
//! entirely fixed-shape: 33 bytes for a hash reference, 1 byte for empty. That
//! makes the layout derivable from 16 one-byte reads rather than 16 full item
//! decodes, which is the difference between affordable and not.
//!
//! # The traversal invariant
//!
//! Each node is authenticated against its parent: `keccak(node[i])` must equal
//! the child reference selected in `node[i-1]`, and the root's hash must equal
//! the claimed `receiptsRoot`. The key is consumed nibble by nibble, and the
//! walk must terminate at a leaf having consumed the key exactly.
//!
//! Every one of those is a place where a missing constraint lets a prover
//! present an unrelated node. The adversarial suite in [`tests`] names each.

pub mod constructed_leaf;
pub mod constructed_traverse;
#[cfg(test)]
pub mod harness;
pub mod node;
#[cfg(test)]
pub mod null;
pub mod path;
pub mod traverse;

#[cfg(test)]
mod tests;

use ark_ff::PrimeField;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::gr1cs::SynthesisError;

/// One node in a proof, as a bounded buffer plus its real length.
pub struct ProofNode<F: PrimeField> {
    pub bytes: Vec<UInt8<F>>,
    pub len: FpVar<F>,
    /// False for slots past the real trie depth. Inactive slots are held to
    /// zero length and contribute nothing.
    pub active: Boolean<F>,
}

/// Verifies that `value` is stored at `key` under `root`.
///
/// `key` is a bounded buffer of raw key bytes traversed as nibbles, and
/// `key_len` is how many of those bytes are real. The length must be witnessed
/// rather than taken from `key.len()`: the receipt trie's key is
/// `rlp(transactionIndex)`, whose length varies with the index, and a buffer's
/// padded width is not its content length.
///
/// Getting this wrong is not a test artifact. `key.len() * 2` on a 32-byte
/// buffer holding a 2-byte key claims 64 nibbles where 4 exist, so the
/// exact-consumption invariant can never be satisfied.
///
/// `nodes` runs root-first and must be exactly `MAX_MPT_DEPTH` long, with
/// inactive trailing slots.
pub trait MptVerifier<F: PrimeField> {
    fn verify_inclusion(
        root: &[UInt8<F>],
        key: &[UInt8<F>],
        key_len: &FpVar<F>,
        value: &[UInt8<F>],
        value_len: &FpVar<F>,
        nodes: &[ProofNode<F>],
    ) -> Result<(), SynthesisError>;
}
