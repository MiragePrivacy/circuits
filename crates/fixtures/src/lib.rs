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

pub mod chain;
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

/// One end-to-end native-ETH fixture: a real mainnet value transfer, both
/// inclusion proofs, and a commitment derived from it.
///
/// The dual-trie shape is the difference from [`Fixture`]. The transaction and
/// its receipt sit at the same index in their respective tries, so one key
/// serves both proofs, but the node arrays and roots are independent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeFixture {
    pub tx_hash: String,
    pub block_number: u64,
    pub tx_index: usize,
    /// EIP-2718 envelope type, 0 for legacy.
    pub transaction_type: u8,
    /// True when the transaction carries no calldata.
    ///
    /// Both shapes are provable. Recorded because they differ by an order of
    /// magnitude in size, so the bounds analysis must see them separately.
    pub bare_send: bool,

    /// RLP block header, carrying both roots.
    pub header: String,
    pub transactions_root: String,
    pub receipts_root: String,
    /// `rlp(transactionIndex)`, the key for both tries.
    pub key: String,

    /// The transaction as it appears in the trie, envelope included.
    pub transaction: String,
    /// Inclusion path under `transactionsRoot`, root first.
    pub transaction_nodes: Vec<String>,

    /// The receipt as it appears in the trie, envelope included.
    pub receipt: String,
    /// Inclusion path under `receiptsRoot`, root first.
    pub receipt_nodes: Vec<String>,

    /// The spec 8.3 opening and its commitment, asset kind native.
    pub intent: commitment::Intent,

    /// Shape, for the bounds analysis.
    pub transaction_depth: usize,
    pub receipt_depth: usize,
    pub max_transaction_node_bytes: usize,
    pub max_receipt_node_bytes: usize,
    pub transaction_bytes: usize,
    pub receipt_bytes: usize,
    pub header_bytes: usize,
}

/// The collected native dataset.
#[derive(Debug, Serialize, Deserialize)]
pub struct NativeDataset {
    pub source: String,
    pub scope: String,
    pub note: String,
    pub count: usize,
    pub fixtures: Vec<NativeFixture>,
}

/// Summary of the native shape distribution.
pub struct NativeShape {
    pub transaction_depth: (usize, usize),
    pub receipt_depth: (usize, usize),
    pub transaction_node_bytes: (usize, usize),
    pub receipt_node_bytes: (usize, usize),
    pub transaction_bytes: (usize, usize),
    pub receipt_bytes: (usize, usize),
    pub header_bytes: (usize, usize),
    pub types: Vec<u8>,
}

impl NativeDataset {
    pub fn shape(&self) -> Option<NativeShape> {
        Self::shape_of(&self.fixtures.iter().collect::<Vec<_>>())
    }

    /// The distribution over a subset, so bare sends and value-carrying calls
    /// can be reported separately. They differ by an order of magnitude, and a
    /// combined maximum hides which population drives each bound.
    pub fn shape_of(fixtures: &[&NativeFixture]) -> Option<NativeShape> {
        if fixtures.is_empty() {
            return None;
        }
        let range = |f: &dyn Fn(&NativeFixture) -> usize| {
            let vals: Vec<usize> = fixtures.iter().map(|x| f(x)).collect();
            (*vals.iter().min().unwrap(), *vals.iter().max().unwrap())
        };
        let mut types: Vec<u8> = fixtures.iter().map(|f| f.transaction_type).collect();
        types.sort_unstable();
        types.dedup();

        Some(NativeShape {
            transaction_depth: range(&|f| f.transaction_depth),
            receipt_depth: range(&|f| f.receipt_depth),
            transaction_node_bytes: range(&|f| f.max_transaction_node_bytes),
            receipt_node_bytes: range(&|f| f.max_receipt_node_bytes),
            transaction_bytes: range(&|f| f.transaction_bytes),
            receipt_bytes: range(&|f| f.receipt_bytes),
            header_bytes: range(&|f| f.header_bytes),
            types,
        })
    }

    /// The 95th percentile of a field, which is what a bound should be set
    /// from rather than the maximum.
    ///
    /// Spec 12.9 puts an unprovable settlement's cost on the executor, so a
    /// bound wants the tail plus headroom. Reporting only the max hides how
    /// far out that max sits: one 5KB outlier among 99 sub-300-byte receipts
    /// is a different decision from a distribution that is genuinely wide.
    pub fn percentile(&self, f: impl Fn(&NativeFixture) -> usize, p: f64) -> usize {
        let mut vals: Vec<usize> = self.fixtures.iter().map(&f).collect();
        if vals.is_empty() {
            return 0;
        }
        vals.sort_unstable();
        vals[(((vals.len() - 1) as f64) * p).round() as usize]
    }
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
