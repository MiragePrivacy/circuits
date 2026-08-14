//! Collects real mainnet ERC-20 Transfer fixtures for end-to-end circuit tests.
//!
//! ```sh
//! cargo run -p mirage-fixtures --release --bin collect -- \
//!     --count 100 --out test/vectors/mainnet.json
//! ```
//!
//! For each candidate block it fetches every receipt, rebuilds the receipt trie
//! locally, and **checks the reconstructed root against the block header's
//! `receiptsRoot`**. A mismatch means the encoding is wrong somewhere, so the
//! block is dropped rather than written: a fixture that does not correspond to
//! real chain state would silently invalidate every test built on it.
//!
//! The header is likewise re-encoded and checked against the block hash, which
//! catches schema drift if mainnet moves past the frozen 21-field layout.
//!
//! Scope is direct ERC-20 transfer calls — receipts whose only event is one
//! Transfer — matching what the escrow's executors produce under spec 20.3.

use std::collections::BTreeSet;
use std::time::Duration;

use mirage_fixtures::commitment;
use mirage_fixtures::rlp::Item;
use mirage_fixtures::trie::{key_for, Trie};
use mirage_fixtures::{from_hex, from_hex_fixed, from_hex_quantity, hash, hex_str, Dataset, Fixture};
use serde_json::Value;

/// Default endpoint. Override with `--rpc`.
///
/// Free public endpoints vary in what they serve. `eth_getBlockReceipts` over a
/// full block is a heavy call, and several time it out beyond a few thousand
/// blocks of the tip, so sampling walks back in small steps rather than wide
/// historical strides. Variety comes from block spacing, not from reaching deep
/// history.
const RPC: &str = "https://eth.drpc.org";
const TRANSFER_TOPIC0: &str = "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let count = arg(&args, "--count").and_then(|v| v.parse().ok()).unwrap_or(100usize);
    let out = arg(&args, "--out").unwrap_or_else(|| "test/vectors/mainnet.json".into());
    let rpc_url = arg(&args, "--rpc").unwrap_or_else(|| RPC.into());
    // A prime stride spreads sampling rather than clustering in one period of
    // activity. Kept small because free endpoints time out on blocks far from
    // the tip; raise it against an archive node.
    let stride: u64 = arg(&args, "--stride").and_then(|v| v.parse().ok()).unwrap_or(13);

    let latest = match rpc(&rpc_url, "eth_blockNumber", vec![]) {
        Ok(v) => u64::from_str_radix(v.as_str().unwrap_or("0x0").trim_start_matches("0x"), 16)
            .unwrap_or(0),
        Err(e) => {
            eprintln!("cannot reach {rpc_url}: {e}");
            eprintln!("\nThis binary needs outbound network access. If the sandbox blocks it,");
            eprintln!("run from a shell that does not, or pass --rpc with a reachable endpoint.");
            std::process::exit(1);
        }
    };
    eprintln!("latest block {latest}");

    let mut fixtures: Vec<Fixture> = Vec::new();
    // Stay back from the tip: recent blocks can still reorg.
    let mut block = latest.saturating_sub(128);
    let mut scanned = 0u32;

    while fixtures.len() < count && scanned < 600 && block > 1_000_000 {
        scanned += 1;
        let want = (count - fixtures.len()).min(3);
        match collect_block(&rpc_url, block, want) {
            Ok(got) if !got.is_empty() => {
                eprintln!("  block {block}: +{} (total {})", got.len(), fixtures.len() + got.len());
                fixtures.extend(got);
            }
            Ok(_) => {}
            Err(e) => eprintln!("  block {block}: {e}"),
        }
        block = block.saturating_sub(stride);
    }

    let dataset = Dataset {
        source: "ethereum mainnet via publicnode".into(),
        scope: "direct ERC-20 transfer calls: exactly one Transfer log, status 1".into(),
        note: "Only settlementToken, recipient and settlementAmount are real. The \
               escrow-side commitment fields are derived from the transaction hash so \
               fixtures are reproducible and each commitment differs."
            .into(),
        count: fixtures.len(),
        fixtures,
    };

    let json = serde_json::to_string_pretty(&dataset).expect("serialize");
    std::fs::write(&out, json).unwrap_or_else(|e| panic!("write {out}: {e}"));
    eprintln!("\nwrote {} fixtures to {out}", dataset.count);

    // The distribution is the point: it tells us whether the compiled bounds
    // accommodate real mainnet data.
    if let Some(s) = dataset.shape() {
        eprintln!("  depth         {} to {}", s.depth.0, s.depth.1);
        eprintln!("  node bytes    {} to {}", s.node_bytes.0, s.node_bytes.1);
        eprintln!("  receipt bytes {} to {}", s.receipt_bytes.0, s.receipt_bytes.1);
        eprintln!("  header bytes  {} to {}", s.header_bytes.0, s.header_bytes.1);
        eprintln!("  receipt types {:?}", s.types);
        eprintln!("\nagainst the compiled bounds (node 544, key 4, receipt 1024, depth 4):");
        report("depth", s.depth.1, 4);
        report("node bytes", s.node_bytes.1, 544);
        report("receipt bytes", s.receipt_bytes.1, 1024);
        report("header bytes", s.header_bytes.1, 640);
    }
}

fn report(name: &str, observed: usize, bound: usize) {
    let verdict = if observed <= bound { "fits" } else { "EXCEEDS" };
    eprintln!("  {name:14} max {observed:5} vs bound {bound:5}  {verdict}");
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn rpc(url: &str, method: &str, params: Vec<Value>) -> Result<Value, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "method": method, "params": params, "id": 1
    });

    let mut last = String::new();
    for attempt in 0..4 {
        let res = ureq::post(url)
            .timeout(Duration::from_secs(60))
            .send_json(body.clone());
        match res {
            Ok(r) => {
                let v: Value = r.into_json().map_err(|e| e.to_string())?;
                if let Some(err) = v.get("error") {
                    return Err(format!("{method}: {err}"));
                }
                return v.get("result").cloned().ok_or_else(|| "no result".into());
            }
            Err(e) => {
                last = e.to_string();
                std::thread::sleep(Duration::from_millis(500 * (attempt + 1)));
            }
        }
    }
    Err(format!("{method} failed: {last}"))
}

/// Re-encodes the 21-field post-Prague header, spec 12.7.1.
fn encode_header(h: &Value) -> Result<Vec<u8>, String> {
    let f = |k: &str| -> Result<&str, String> {
        h.get(k).and_then(|v| v.as_str()).ok_or_else(|| format!("header missing {k}"))
    };
    let fixed = |k: &str, n: usize| -> Result<Item, String> {
        Ok(Item::Str(from_hex_fixed(f(k)?, n)?))
    };
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

/// The receipt as it appears in the trie, envelope included.
fn encode_receipt(r: &Value) -> Result<Vec<u8>, String> {
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
        r["cumulativeGasUsed"].as_str().ok_or("gas")?.trim_start_matches("0x"),
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

    let tx_type = r
        .get("type")
        .and_then(|v| v.as_str())
        .map(|s| u8::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0))
        .unwrap_or(0);

    Ok(if tx_type == 0 {
        payload
    } else {
        let mut out = vec![tx_type];
        out.extend_from_slice(&payload);
        out
    })
}

/// One Transfer log and nothing else: a direct ERC-20 transfer call.
fn is_direct_transfer(r: &Value) -> bool {
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
        && topics[0].as_str().unwrap_or("").trim_start_matches("0x").eq_ignore_ascii_case(TRANSFER_TOPIC0)
        && data_len == 32
}

fn collect_block(url: &str, number: u64, want: usize) -> Result<Vec<Fixture>, String> {
    let tag = Value::String(format!("0x{number:x}"));
    let block = rpc(url, "eth_getBlockByNumber", vec![tag.clone(), Value::Bool(false)])?;
    let receipts = rpc(url, "eth_getBlockReceipts", vec![tag])?;
    let receipts = receipts.as_array().ok_or("receipts not an array")?;
    if receipts.is_empty() {
        return Ok(vec![]);
    }

    // The header must re-encode to the block hash, or the schema has drifted.
    let header = encode_header(&block)?;
    let block_hash = block["hash"].as_str().ok_or("block hash")?;
    if hex_str(&hash(&header)) != block_hash {
        return Err("header hash mismatch: schema drift?".into());
    }

    let encoded: Result<Vec<Vec<u8>>, String> = receipts.iter().map(encode_receipt).collect();
    let encoded = encoded?;

    // The reconstructed root must equal the header's. This single equality
    // catches every encoding mistake at once.
    let trie = Trie::build(&encoded);
    let receipts_root = block["receiptsRoot"].as_str().ok_or("receiptsRoot")?;
    if hex_str(&trie.root) != receipts_root {
        return Err(format!(
            "receiptsRoot mismatch: built {} want {receipts_root}",
            hex_str(&trie.root)
        ));
    }

    let mut out = Vec::new();
    for (i, r) in receipts.iter().enumerate() {
        if out.len() >= want {
            break;
        }
        if !is_direct_transfer(r) {
            continue;
        }

        let log = &r["logs"][0];
        let token: [u8; 20] = from_hex_fixed(log["address"].as_str().ok_or("addr")?, 20)?
            .try_into()
            .map_err(|_| "token width")?;
        let to_topic = from_hex_fixed(log["topics"][2].as_str().ok_or("topic2")?, 32)?;
        let recipient: [u8; 20] = to_topic[12..].try_into().map_err(|_| "recipient width")?;
        let amount: [u8; 32] = from_hex(log["data"].as_str().ok_or("data")?)?
            .try_into()
            .map_err(|_| "amount width")?;

        // Spec 12.3 rejects these, so they cannot appear in a valid fixture.
        if recipient.iter().all(|&b| b == 0) || amount.iter().all(|&b| b == 0) {
            continue;
        }

        let tx_hash_hex = r["transactionHash"].as_str().ok_or("tx hash")?;
        let tx_hash: [u8; 32] = from_hex_fixed(tx_hash_hex, 32)?
            .try_into()
            .map_err(|_| "tx hash width")?;

        let key = key_for(i);
        let nodes = trie.proof(&key)?;

        out.push(Fixture {
            tx_hash: tx_hash_hex.into(),
            block_number: number,
            tx_index: i,
            receipt_type: r
                .get("type")
                .and_then(|v| v.as_str())
                .map(|s| u8::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0))
                .unwrap_or(0),
            log_index: 0,
            header: hex_str(&header),
            receipts_root: receipts_root.into(),
            key: hex_str(&key),
            receipt: hex_str(&encoded[i]),
            depth: nodes.len(),
            max_node_bytes: nodes.iter().map(|n| n.len()).max().unwrap_or(0),
            receipt_bytes: encoded[i].len(),
            header_bytes: header.len(),
            nodes: nodes.iter().map(|n| hex_str(n)).collect(),
            intent: commitment::derive(&tx_hash, &token, &recipient, &amount),
        });
    }

    // Distinct types are what make the dataset varied, so note when a block
    // contributes an envelope we have not seen.
    let types: BTreeSet<u8> = out.iter().map(|f| f.receipt_type).collect();
    if types.len() > 1 {
        eprintln!("    (types {types:?})");
    }

    Ok(out)
}
