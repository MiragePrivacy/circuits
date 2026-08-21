//! Generates a real native-ETH Groth16 proof and reports what it actually cost.
//!
//! The native counterpart to `measure`. Every native figure recorded so far is
//! derived: 17.8M constraints scaled by the ERC-20 path's measured cost, or by
//! the arkworks benchmark's 2.8 GB per million. Both are projections across a
//! 1.7x constraint gap, and the memory one decides whether the relation fits a
//! provisioned enclave at all. This measures it.
//!
//! Run:
//! ```sh
//! RAYON_NUM_THREADS=16 cargo run -p mirage-prover --release --bin measure-native
//! ```
//!
//! Peak RSS comes from `/proc/self/status` `VmHWM`, matching `measure` so the
//! two paths are directly comparable.
//!
//! Setup and proving are measured through `mirage_prover::native`, not raw
//! arkworks, so the figure covers the path a node actually takes -- including
//! the self-verify that `prove` does before returning.

use std::time::Instant;

use ark_bn254::Fr;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;

use mirage_relation::native::{fixture, NativeBounds, NativeCircuit, MEASUREMENT_SCOPE};

/// Peak resident set size in bytes, from `VmHWM`.
fn peak_rss() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM:"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
        })
        .map(|kb| kb * 1024)
        .unwrap_or(0)
}

fn gb(bytes: u64) -> f64 {
    bytes as f64 / 1024.0 / 1024.0 / 1024.0
}

fn main() {
    let threads = std::env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "default".into());
    let bounds = NativeBounds::default();

    println!("scope:   {MEASUREMENT_SCOPE}");
    println!(
        "bounds:  tx {} B / node {} B / depth {}, receipt {} B / node {} B / depth {}, header {} B",
        bounds.transaction_bytes,
        bounds.transaction_node_bytes,
        bounds.transaction_depth,
        bounds.common.receipt_bytes,
        bounds.common.node_bytes,
        bounds.common.depth,
        bounds.common.header_bytes,
    );
    println!("threads: {threads}");
    println!();

    // ---- constraint count ----
    let t = Instant::now();
    let cs = ConstraintSystem::<Fr>::new_ref();
    NativeCircuit::prove(bounds, fixture::genuine())
        .generate_constraints(cs.clone())
        .expect("synthesis");
    let satisfied = cs.is_satisfied().expect("satisfiability");
    let n = cs.num_constraints();
    println!(
        "synthesis:    {:>8.1}s   {n} constraints, satisfied={satisfied}",
        t.elapsed().as_secs_f64()
    );
    assert!(satisfied, "witness does not satisfy the circuit");
    drop(cs);

    // ---- setup ----
    let t = Instant::now();
    let keys = mirage_prover::native::setup(bounds, 0).expect("native setup");
    let setup_secs = t.elapsed().as_secs_f64();
    let pk_bytes = keys.pk.serialized_size(ark_serialize::Compress::No);
    let pk_compressed = keys.pk.serialized_size(ark_serialize::Compress::Yes);
    println!(
        "setup:        {setup_secs:>8.1}s   proving key {:.2} GB ({:.2} GB compressed)",
        gb(pk_bytes as u64),
        gb(pk_compressed as u64)
    );
    println!("              peak RSS so far {:.1} GB", gb(peak_rss()));

    // ---- prove ----
    //
    // Through the library, so the measurement includes the native self-verify a
    // node pays for on every settlement.
    let t = Instant::now();
    let settlement =
        mirage_prover::native::prove_seeded(&keys, bounds, &fixture::genuine(), 0).expect("prove");
    let prove_secs = t.elapsed().as_secs_f64();
    println!("prove:        {prove_secs:>8.1}s   (includes the native self-verify)");

    println!();
    println!("peak RSS:     {:.1} GB", gb(peak_rss()));
    println!(
        "signals:      {:#034x} {:#034x}",
        settlement.signals[0], settlement.signals[1]
    );

    println!();
    println!("against spec 19.7: p95 under 75s");
    println!(
        "  prove {prove_secs:.1}s -> {}",
        if prove_secs <= 75.0 { "WITHIN" } else { "OVER" }
    );
    println!(
        "  projection was {:.0} GB at 2.8 GB/M; measured {:.1} GB",
        n as f64 / 1e6 * 2.8,
        gb(peak_rss())
    );
}
