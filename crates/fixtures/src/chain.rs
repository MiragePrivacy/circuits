//! Building circuit inputs from JSON-RPC block and receipt objects.
//!
//! The encoders live here rather than in the collector binary because two
//! callers need them: fixture collection, and any prover assembling a witness
//! from a live chain. A second implementation of either encoder would be a
//! byte-exact reimplementation of consensus encoding, which is the category of
//! duplication this crate exists to avoid.
//!
//! Both encoders are checked by reconstruction rather than by inspection. A
//! header must re-hash to the block hash and a receipt trie must rebuild to the
//! header's `receiptsRoot`; either check catches an encoding mistake that
//! reading the code would not.

use serde_json::Value;

use crate::rlp::Item;
use crate::trie::{key_for, Trie};
use crate::{from_hex, from_hex_fixed, from_hex_quantity, hash, hex_str};

/// `Transfer(address,address,uint256)`.
pub const TRANSFER_TOPIC0: &str = "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

/// The RLP block header, in the frozen 21-field post-Prague layout.
///
/// Field order is consensus-critical and the widths are not interchangeable:
/// hashes are fixed-width and quantities are minimal-length big-endian, so a
/// quantity encoded at a fixed width produces a valid-looking header with the
/// wrong hash.
pub fn encode_header(h: &Value) -> Result<Vec<u8>, String> {
    let f = |k: &str| -> Result<&str, String> {
        h.get(k)
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("header missing {k}"))
    };
    let fixed = |k: &str, n: usize| -> Result<Item, String> { Ok(Item::Str(from_hex_fixed(f(k)?, n)?)) };
    let qty = |k: &str| -> Result<Item, String> { Ok(Item::Str(from_hex_quantity(f(k)?)?)) };

    let extra = from_hex(f("extraData")?)?;

    Ok(Item::List(vec![
        fixed("parentHash", 32)?,
        fixed("sha3Uncles", 32)?,
        fixed("miner", 20)?,
        fixed("stateRoot", 32)?,
        fixed("transactionsRoot", 32)?,
        fixed("receiptsRoot", 32)?,
        fixed("logsBloom", 256)?,
        qty("difficulty")?,
        qty("number")?,
        qty("gasLimit")?,
        qty("gasUsed")?,
        qty("timestamp")?,
        Item::Str(extra),
        fixed("mixHash", 32)?,
        fixed("nonce", 8)?,
        qty("baseFeePerGas")?,
        fixed("withdrawalsRoot", 32)?,
        qty("blobGasUsed")?,
        qty("excessBlobGas")?,
        fixed("parentBeaconBlockRoot", 32)?,
        fixed("requestsHash", 32)?,
    ])
    .encode())
}

/// The receipt as it appears in the trie, EIP-2718 envelope included.
pub fn encode_receipt(r: &Value) -> Result<Vec<u8>, String> {
    let logs: Result<Vec<Item>, String> = r
        .get("logs")
        .and_then(|v| v.as_array())
        .ok_or("receipt missing logs")?
        .iter()
        .map(|log| {
            let addr = from_hex_fixed(log["address"].as_str().ok_or("log address")?, 20)?;
            let topics: Result<Vec<Item>, String> = log["topics"]
                .as_array()
                .ok_or("log topics")?
                .iter()
                .map(|t| Ok(Item::Str(from_hex_fixed(t.as_str().ok_or("topic")?, 32)?)))
                .collect();
            let data = from_hex(log["data"].as_str().unwrap_or("0x"))?;
            Ok(Item::List(vec![
                Item::Str(addr),
                Item::List(topics?),
                Item::Str(data),
            ]))
        })
        .collect();

    let status = u64::from_str_radix(
        r["status"].as_str().ok_or("status")?.trim_start_matches("0x"),
        16,
    )
    .map_err(|e| e.to_string())?;
    let gas = u64::from_str_radix(
        r["cumulativeGasUsed"]
            .as_str()
            .ok_or("gas")?
            .trim_start_matches("0x"),
        16,
    )
    .map_err(|e| e.to_string())?;

    let payload = Item::List(vec![
        Item::int(status),
        Item::int(gas),
        Item::Str(from_hex_fixed(r["logsBloom"].as_str().ok_or("bloom")?, 256)?),
        Item::List(logs?),
    ])
    .encode();

    Ok(match receipt_type(r) {
        0 => payload,
        t => {
            let mut out = vec![t];
            out.extend_from_slice(&payload);
            out
        }
    })
}

/// The EIP-2718 envelope type, 0 for legacy.
pub fn receipt_type(r: &Value) -> u8 {
    r.get("type")
        .and_then(|v| v.as_str())
        .map(|s| u8::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0))
        .unwrap_or(0)
}

/// One Transfer log and nothing else: a direct ERC-20 transfer call.
///
/// Spec 20.3 requires production settlements take this shape, and the
/// single-log circuit variant makes anything else unprovable.
pub fn is_direct_transfer(r: &Value) -> bool {
    let logs = match r.get("logs").and_then(|v| v.as_array()) {
        Some(l) => l,
        None => return false,
    };
    if logs.len() != 1 {
        return false;
    }
    let topics = match logs[0].get("topics").and_then(|v| v.as_array()) {
        Some(t) => t,
        None => return false,
    };
    let status_ok = r["status"].as_str() == Some("0x1");
    let data_len = from_hex(logs[0]["data"].as_str().unwrap_or("0x"))
        .map(|d| d.len())
        .unwrap_or(0);

    status_ok
        && topics.len() == 3
        && topics[0]
            .as_str()
            .unwrap_or("")
            .trim_start_matches("0x")
            .eq_ignore_ascii_case(TRANSFER_TOPIC0)
        && data_len == 32
}

/// A receipt's inclusion proof under a block's `receiptsRoot`.
pub struct Inclusion {
    /// The RLP block header.
    pub header: Vec<u8>,
    /// `rlp(transactionIndex)`, the trie key.
    pub key: Vec<u8>,
    /// The receipt as it appears in the trie.
    pub receipt: Vec<u8>,
    /// The inclusion path, root first.
    pub nodes: Vec<Vec<u8>>,
    pub receipts_root: [u8; 32],
}

/// Rebuilds a block's receipt trie and extracts the inclusion proof for
/// `tx_index`.
///
/// `block` is an `eth_getBlockByNumber` result and `receipts` an
/// `eth_getBlockReceipts` result for the same block. Both consistency checks
/// are enforced rather than assumed: the header must re-hash to the block hash,
/// and the rebuilt trie must match the header's `receiptsRoot`. Either failure
/// means the encoding disagrees with consensus, and a witness built on it would
/// produce a proof no verifier accepts.
pub fn inclusion_proof(
    block: &Value,
    receipts: &[Value],
    tx_index: usize,
) -> Result<Inclusion, String> {
    let header = encode_header(block)?;
    let block_hash = block["hash"].as_str().ok_or("block hash")?;
    if hex_str(&hash(&header)) != block_hash {
        return Err(format!(
            "header hash mismatch: built {} want {block_hash}",
            hex_str(&hash(&header))
        ));
    }

    let encoded: Result<Vec<Vec<u8>>, String> = receipts.iter().map(encode_receipt).collect();
    let encoded = encoded?;
    let receipt = encoded
        .get(tx_index)
        .ok_or_else(|| format!("tx index {tx_index} past the block's {} receipts", encoded.len()))?
        .clone();

    let trie = Trie::build(&encoded);
    let want_root = block["receiptsRoot"].as_str().ok_or("receiptsRoot")?;
    if hex_str(&trie.root) != want_root {
        return Err(format!(
            "receiptsRoot mismatch: built {} want {want_root}",
            hex_str(&trie.root)
        ));
    }

    let key = key_for(tx_index);
    let nodes = trie.proof(&key)?;
    Ok(Inclusion {
        header,
        key,
        receipt,
        nodes,
        receipts_root: trie.root,
    })
}
