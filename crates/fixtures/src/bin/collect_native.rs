//! Collects real mainnet native-ETH settlement fixtures for the dual-trie
//! relation.
//!
//! ```sh
//! cargo run -p mirage-fixtures --release --bin collect-native -- \
//!     --count 100 --out test/vectors/mainnet-native.json
//! ```
//!
//! For each candidate block it fetches every transaction *and* every receipt,
//! rebuilds **both** tries locally, and checks each reconstructed root against
//! the block header's `transactionsRoot` and `receiptsRoot`. A mismatch means
//! the encoding is wrong somewhere, so the block is dropped rather than
//! written.
//!
//! The transaction check is the one that earns its keep here. The receipt
//! encoder was already proven by the ERC-20 collector; `encode_transaction` is
//! new, has five envelope layouts, and includes signature fields that no other
//! part of this workspace exercises. Rebuilding the transaction trie is a
//! single equality that catches any error in any of them.
//!
//! Scope is native ETH settlements: a transaction of type 0x00, 0x01 or 0x02
//! moving nonzero value to a non-null `to`, whose receipt succeeded. Calldata
//! is not required to be empty, because the relation does not constrain it.

use std::collections::BTreeSet;
use std::time::Duration;

use mirage_fixtures::chain::{
    encode_header, encode_receipt, encode_transaction, is_bare_send, is_native_transfer,
    transaction_type,
};
use mirage_fixtures::commitment;
use mirage_fixtures::trie::{key_for, Trie};
use mirage_fixtures::{
    from_hex_fixed, from_hex_quantity, hash, hex_str, NativeDataset, NativeFixture,
};
use serde_json::Value;

/// Default endpoint. Override with `--rpc`.
const RPC: &str = "https://eth.drpc.org";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let count = arg(&args, "--count")
        .and_then(|v| v.parse().ok())
        .unwrap_or(100usize);
    let out = arg(&args, "--out").unwrap_or_else(|| "test/vectors/mainnet-native.json".into());
    let rpc_url = arg(&args, "--rpc").unwrap_or_else(|| RPC.into());
    let stride: u64 = arg(&args, "--stride")
        .and_then(|v| v.parse().ok())
        .unwrap_or(13);
    // How many of `count` must be bare sends. The relation only accepts those,
    // so they are the population the bounds are set from; the calls are kept as
    // rejection fixtures and are cheap to find, so a quota stops them crowding
    // out the ones that matter.
    let want_bare: usize = arg(&args, "--bare")
        .and_then(|v| v.parse().ok())
        .unwrap_or(count);
    // Merge into an existing dataset rather than replacing it, so a top-up run
    // keeps what a previous one collected.
    let merge = args.iter().any(|a| a == "--merge");

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

    let mut fixtures: Vec<NativeFixture> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    if merge {
        if let Some(prior) = std::fs::read_to_string(&out)
            .ok()
            .and_then(|raw| serde_json::from_str::<NativeDataset>(&raw).ok())
        {
            eprintln!("merging into {} existing fixtures", prior.count);
            seen.extend(prior.fixtures.iter().map(|f| f.tx_hash.clone()));
            fixtures = prior.fixtures;
        }
    }

    // Stay back from the tip: recent blocks can still reorg.
    let mut block = latest.saturating_sub(128);
    let mut scanned = 0u32;

    let bare_count = |v: &[NativeFixture]| v.iter().filter(|f| f.bare_send).count();
    while (fixtures.len() < count || bare_count(&fixtures) < want_bare)
        && scanned < 3000
        && block > 1_000_000
    {
        scanned += 1;
        // Once the bare quota is the only thing outstanding, stop taking calls.
        let bare_only = bare_count(&fixtures) < want_bare && fixtures.len() >= count;
        let want = if bare_only {
            (want_bare - bare_count(&fixtures)).min(3)
        } else {
            (count - fixtures.len()).min(3)
        };

        match collect_block(&rpc_url, block, want, bare_only) {
            Ok(got) if !got.is_empty() => {
                let fresh: Vec<NativeFixture> = got
                    .into_iter()
                    .filter(|f| seen.insert(f.tx_hash.clone()))
                    .collect();
                if !fresh.is_empty() {
                    eprintln!(
                        "  block {block}: +{} (total {}, {} bare)",
                        fresh.len(),
                        fixtures.len() + fresh.len(),
                        bare_count(&fixtures) + fresh.iter().filter(|f| f.bare_send).count()
                    );
                    fixtures.extend(fresh);
                }
            }
            Ok(_) => {}
            Err(e) => eprintln!("  block {block}: {e}"),
        }
        block = block.saturating_sub(stride);
    }

    let dataset = NativeDataset {
        source: "ethereum mainnet via drpc".into(),
        scope: "native ETH settlements: nonzero value to a non-null to, status 1, \
                transaction type 0x00/0x01/0x02"
            .into(),
        note: "Only recipient and settlementAmount are real. The escrow-side commitment \
               fields are derived from the transaction hash so fixtures are reproducible \
               and each commitment differs. settlementToken is all-zero, as spec 8.3 \
               requires of a native row."
            .into(),
        count: fixtures.len(),
        fixtures,
    };

    let json = serde_json::to_string_pretty(&dataset).expect("serialize");
    std::fs::write(&out, json).unwrap_or_else(|e| panic!("write {out}: {e}"));
    eprintln!("\nwrote {} fixtures to {out}", dataset.count);

    // The distribution is the point: it tells us whether the compiled bounds
    // accommodate real mainnet data.
    //
    // Reported split by shape, because the two populations differ by an order
    // of magnitude and a combined maximum hides which one drives each bound.
    let bare: Vec<&NativeFixture> = dataset.fixtures.iter().filter(|f| f.bare_send).collect();
    let calls: Vec<&NativeFixture> = dataset.fixtures.iter().filter(|f| !f.bare_send).collect();
    eprintln!(
        "  {} bare sends, {} value-carrying calls",
        bare.len(),
        calls.len()
    );

    if let Some(s) = NativeDataset::shape_of(&bare) {
        eprintln!("\nbare sends:");
        summarize(&s);
    }
    if let Some(s) = NativeDataset::shape_of(&calls) {
        eprintln!("\nvalue-carrying calls:");
        summarize(&s);
    }

    if let Some(s) = dataset.shape() {
        eprintln!("\nall fixtures, against the compiled bounds:");
        report("tx depth", s.transaction_depth.1, 4);
        report("receipt depth", s.receipt_depth.1, 4);
        report("tx node bytes", s.transaction_node_bytes.1, 544);
        report("rcpt node bytes", s.receipt_node_bytes.1, 544);
        report("tx bytes", s.transaction_bytes.1, 512);
        report("receipt bytes", s.receipt_bytes.1, 512);
        report("header bytes", s.header_bytes.1, 704);

        // A bound wants the tail plus headroom, not the median and not one
        // outlier. Spec 12.9 puts an unprovable settlement on the executor.
        eprintln!("\npercentiles (p50 / p95 / max), which is what a bound is set from:");
        pct(&dataset, "tx bytes", &|f| f.transaction_bytes);
        pct(&dataset, "receipt bytes", &|f| f.receipt_bytes);
        pct(&dataset, "tx node bytes", &|f| f.max_transaction_node_bytes);
        pct(&dataset, "rcpt node bytes", &|f| f.max_receipt_node_bytes);
        pct(&dataset, "header bytes", &|f| f.header_bytes);
    }
}

fn summarize(s: &mirage_fixtures::NativeShape) {
    eprintln!(
        "  tx depth        {} to {}",
        s.transaction_depth.0, s.transaction_depth.1
    );
    eprintln!(
        "  receipt depth   {} to {}",
        s.receipt_depth.0, s.receipt_depth.1
    );
    eprintln!(
        "  tx node bytes   {} to {}",
        s.transaction_node_bytes.0, s.transaction_node_bytes.1
    );
    eprintln!(
        "  rcpt node bytes {} to {}",
        s.receipt_node_bytes.0, s.receipt_node_bytes.1
    );
    eprintln!(
        "  tx bytes        {} to {}",
        s.transaction_bytes.0, s.transaction_bytes.1
    );
    eprintln!(
        "  receipt bytes   {} to {}",
        s.receipt_bytes.0, s.receipt_bytes.1
    );
    eprintln!(
        "  header bytes    {} to {}",
        s.header_bytes.0, s.header_bytes.1
    );
    eprintln!("  tx types        {:?}", s.types);
}

fn pct(d: &NativeDataset, name: &str, f: &dyn Fn(&NativeFixture) -> usize) {
    eprintln!(
        "  {name:16} {:5} / {:5} / {:5}",
        d.percentile(f, 0.50),
        d.percentile(f, 0.95),
        d.percentile(f, 1.0)
    );
}

fn report(name: &str, observed: usize, bound: usize) {
    let verdict = if observed <= bound { "fits" } else { "EXCEEDS" };
    eprintln!("  {name:16} max {observed:5} vs bound {bound:5}  {verdict}");
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
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

fn collect_block(
    url: &str,
    number: u64,
    want: usize,
    bare_only: bool,
) -> Result<Vec<NativeFixture>, String> {
    let tag = Value::String(format!("0x{number:x}"));
    // `true` for full transaction objects: the transaction trie needs bodies,
    // not hashes.
    let block = rpc(
        url,
        "eth_getBlockByNumber",
        vec![tag.clone(), Value::Bool(true)],
    )?;
    let receipts = rpc(url, "eth_getBlockReceipts", vec![tag])?;
    let receipts = receipts.as_array().ok_or("receipts not an array")?;
    let transactions = block["transactions"]
        .as_array()
        .ok_or("transactions not an array")?;

    if transactions.is_empty() {
        return Ok(vec![]);
    }
    if transactions.len() != receipts.len() {
        return Err(format!(
            "{} transactions but {} receipts",
            transactions.len(),
            receipts.len()
        ));
    }

    // The header must re-encode to the block hash, or the schema has drifted.
    let header = encode_header(&block)?;
    let block_hash = block["hash"].as_str().ok_or("block hash")?;
    if hex_str(&hash(&header)) != block_hash {
        return Err("header hash mismatch: schema drift?".into());
    }

    // Trie one: transactions. This is the check that grades `encode_transaction`
    // across every envelope the block happens to contain.
    let encoded_txs: Result<Vec<Vec<u8>>, String> =
        transactions.iter().map(encode_transaction).collect();
    let encoded_txs = encoded_txs?;
    let tx_trie = Trie::build(&encoded_txs);
    let transactions_root = block["transactionsRoot"]
        .as_str()
        .ok_or("transactionsRoot")?;
    if hex_str(&tx_trie.root) != transactions_root {
        return Err(format!(
            "transactionsRoot mismatch: built {} want {transactions_root}",
            hex_str(&tx_trie.root)
        ));
    }

    // Trie two: receipts.
    let encoded_receipts: Result<Vec<Vec<u8>>, String> =
        receipts.iter().map(encode_receipt).collect();
    let encoded_receipts = encoded_receipts?;
    let receipt_trie = Trie::build(&encoded_receipts);
    let receipts_root = block["receiptsRoot"].as_str().ok_or("receiptsRoot")?;
    if hex_str(&receipt_trie.root) != receipts_root {
        return Err(format!(
            "receiptsRoot mismatch: built {} want {receipts_root}",
            hex_str(&receipt_trie.root)
        ));
    }

    // Candidates spread across the whole block rather than taken from the
    // front. Native transfers cluster — exchange withdrawals batch at the top,
    // MEV and contract calls sit lower — so taking the first few per block
    // yields a set narrower than mainnet actually is.
    let candidates: Vec<usize> = (0..transactions.len())
        .filter(|&i| is_native_transfer(&transactions[i], &receipts[i]))
        .filter(|&i| !bare_only || is_bare_send(&transactions[i]))
        .collect();
    if candidates.is_empty() {
        return Ok(vec![]);
    }

    // Prefer variety within the block: alternate bare sends and value-carrying
    // calls, and take legacy or EIP-2930 envelopes ahead of the ubiquitous
    // EIP-1559 when the block offers them.
    let mut picks: Vec<usize> = Vec::new();
    let mut seen_bare = false;
    let mut seen_call = false;
    let mut seen_types: BTreeSet<u8> = BTreeSet::new();
    for &i in &candidates {
        if picks.len() >= want {
            break;
        }
        let bare = is_bare_send(&transactions[i]);
        let ty = transaction_type(&transactions[i]);
        let novel_kind = (bare && !seen_bare) || (!bare && !seen_call);
        if novel_kind || seen_types.insert(ty) {
            seen_bare |= bare;
            seen_call |= !bare;
            picks.push(i);
        }
    }
    // Backfill from the spread of what is left, so a block rich in one shape
    // still contributes its quota.
    if picks.len() < want {
        let step = (candidates.len() / want.max(1)).max(1);
        for &i in candidates.iter().step_by(step) {
            if picks.len() >= want {
                break;
            }
            if !picks.contains(&i) {
                picks.push(i);
            }
        }
    }
    picks.sort_unstable();

    let mut out = Vec::new();
    for i in picks {
        let tx = &transactions[i];

        let recipient: [u8; 20] = from_hex_fixed(tx["to"].as_str().ok_or("to")?, 20)?
            .try_into()
            .map_err(|_| "recipient width")?;

        // `value` is a minimal-length quantity; the commitment carries it
        // right-aligned in 32 bytes, which is what the relation compares.
        let value = from_hex_quantity(tx["value"].as_str().ok_or("value")?)?;
        if value.len() > 32 {
            return Err("value wider than 32 bytes".into());
        }
        let mut amount = [0u8; 32];
        amount[32 - value.len()..].copy_from_slice(&value);

        // Spec 12.3 rejects these, so they cannot appear in a valid fixture.
        if recipient.iter().all(|&b| b == 0) || amount.iter().all(|&b| b == 0) {
            continue;
        }

        let tx_hash_hex = tx["hash"].as_str().ok_or("tx hash")?;
        let tx_hash: [u8; 32] = from_hex_fixed(tx_hash_hex, 32)?
            .try_into()
            .map_err(|_| "tx hash width")?;

        // One key, both tries: the transaction and its receipt sit at the same
        // index.
        let key = key_for(i);
        let tx_nodes = tx_trie.proof(&key)?;
        let receipt_nodes = receipt_trie.proof(&key)?;

        out.push(NativeFixture {
            tx_hash: tx_hash_hex.into(),
            block_number: number,
            tx_index: i,
            transaction_type: transaction_type(tx),
            bare_send: is_bare_send(tx),
            header: hex_str(&header),
            transactions_root: transactions_root.into(),
            receipts_root: receipts_root.into(),
            key: hex_str(&key),
            transaction: hex_str(&encoded_txs[i]),
            receipt: hex_str(&encoded_receipts[i]),
            transaction_depth: tx_nodes.len(),
            receipt_depth: receipt_nodes.len(),
            max_transaction_node_bytes: tx_nodes.iter().map(|n| n.len()).max().unwrap_or(0),
            max_receipt_node_bytes: receipt_nodes.iter().map(|n| n.len()).max().unwrap_or(0),
            transaction_bytes: encoded_txs[i].len(),
            receipt_bytes: encoded_receipts[i].len(),
            header_bytes: header.len(),
            transaction_nodes: tx_nodes.iter().map(|n| hex_str(n)).collect(),
            receipt_nodes: receipt_nodes.iter().map(|n| hex_str(n)).collect(),
            intent: commitment::derive_native(&tx_hash, &recipient, &amount),
        });
    }

    // Distinct types are what make the dataset varied.
    let types: BTreeSet<u8> = out.iter().map(|f| f.transaction_type).collect();
    if types.len() > 1 {
        eprintln!("    (types {types:?})");
    }

    Ok(out)
}
