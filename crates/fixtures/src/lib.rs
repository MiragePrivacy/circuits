//! Mainnet fixture collection: RLP encoding, receipt-trie reconstruction, and
//! spec 8.3 commitment derivation.
//!
//! Split from the binary so the encoding and trie logic are unit-testable
//! without network access. That matters more than usual here: reconstructing a
//! receipt trie means getting hex-prefix encoding, the 32-byte inline threshold,
//! and canonical RLP integers all exactly right, and any one of them wrong
//! still produces a *valid-looking* trie with a different root.
//!
//! The collector checks its reconstructed root against the block header's
//! `receiptsRoot`, which is a single equality that catches every one of those
//! independently. A block that fails is dropped rather than written.

pub mod commitment;
pub mod rlp;
pub mod trie;

use mirage_encoding::keccak256;
use serde::{Deserialize, Serialize};

/// One end-to-end fixture: a real mainnet Transfer, its inclusion proof, and a
/// commitment derived from it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fixture {
    pub tx_hash: String,
    pub block_number: u64,
    pub tx_index: usize,
    /// EIP-2718 envelope type, 0 for legacy.
    pub receipt_type: u8,
    pub log_index: usize,

    /// RLP block header, whose `receiptsRoot` the trie hangs from.
    pub header: String,
    pub receipts_root: String,
    /// `rlp(transactionIndex)`, the trie key.
    pub key: String,
    /// The receipt as it appears in the trie, envelope included.
    pub receipt: String,
    /// Inclusion path, root first.
    pub nodes: Vec<String>,

    /// The spec 8.3 opening and its commitment.
    pub intent: commitment::Intent,

    /// Shape, for the bounds analysis.
    pub depth: usize,
    pub max_node_bytes: usize,
    pub receipt_bytes: usize,
    pub header_bytes: usize,
}

/// The collected dataset.
#[derive(Debug, Serialize, Deserialize)]
pub struct Dataset {
    pub source: String,
    pub scope: String,
    pub note: String,
    pub count: usize,
    pub fixtures: Vec<Fixture>,
}

/// Summary of the shape distribution, which is what the compiled bounds must
/// accommodate.
pub struct Shape {
    pub depth: (usize, usize),
    pub node_bytes: (usize, usize),
    pub receipt_bytes: (usize, usize),
    pub header_bytes: (usize, usize),
    pub types: Vec<u8>,
}

impl Dataset {
    pub fn shape(&self) -> Option<Shape> {
        if self.fixtures.is_empty() {
            return None;
        }
        let range = |f: &dyn Fn(&Fixture) -> usize| {
            let vals: Vec<usize> = self.fixtures.iter().map(f).collect();
            (*vals.iter().min().unwrap(), *vals.iter().max().unwrap())
        };
        let mut types: Vec<u8> = self.fixtures.iter().map(|f| f.receipt_type).collect();
        types.sort_unstable();
        types.dedup();

        Some(Shape {
            depth: range(&|f| f.depth),
            node_bytes: range(&|f| f.max_node_bytes),
            receipt_bytes: range(&|f| f.receipt_bytes),
            header_bytes: range(&|f| f.header_bytes),
            types,
        })
    }
}

/// keccak256, re-exported so callers need not depend on `mirage-encoding`.
pub fn hash(bytes: &[u8]) -> [u8; 32] {
    keccak256(bytes)
}

pub fn hex_str(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Parses `0x`-prefixed hex, tolerating an odd digit count.
pub fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    let t = s.strip_prefix("0x").unwrap_or(s);
    let padded;
    let t = if t.len() % 2 == 1 {
        padded = format!("0{t}");
        &padded
    } else {
        t
    };
    hex::decode(t).map_err(|e| format!("bad hex {s}: {e}"))
}

/// Parses hex expected to be exactly `n` bytes.
pub fn from_hex_fixed(s: &str, n: usize) -> Result<Vec<u8>, String> {
    let b = from_hex(s)?;
    if b.len() != n {
        return Err(format!("expected {n} bytes in {s}, got {}", b.len()));
    }
    Ok(b)
}

/// Parses a hex quantity into its canonical RLP integer bytes: minimal
/// big-endian, empty for zero.
pub fn from_hex_quantity(s: &str) -> Result<Vec<u8>, String> {
    let b = from_hex(s)?;
    let trimmed: Vec<u8> = b.into_iter().skip_while(|&x| x == 0).collect();
    Ok(trimmed)
}
