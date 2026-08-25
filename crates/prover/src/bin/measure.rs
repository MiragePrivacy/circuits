//! Generates a real Groth16 proof and reports what it actually cost.
//!
//! Every memory and timing figure in FINDINGS up to this point is *derived*:
//! RAM extrapolates 2.8 GB per million constraints from the arkworks benchmark,
//! and time extrapolates 21s per 3M measured on a multiplication chain, which
//! is the prover's best case. This binary replaces both with measurements.
//!
//! Run:
//! ```sh
//! RAYON_NUM_THREADS=16 cargo run -p mirage-prover --release --bin measure
//! ```
//!
//! Peak RSS is read from `/proc/self/status` `VmHWM`, the same metric the
//! arkworks benchmark used, so the two are comparable.

use std::time::Instant;

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;

use mirage_relation::{fixture, Bounds, ReceiptCircuit, MEASUREMENT_SCOPE};

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
    let bounds = Bounds::default();

    println!("scope:   {MEASUREMENT_SCOPE}");
    println!(
        "bounds:  node {} B, key {} B, receipt {} B, depth {}",
        bounds.node_bytes, bounds.key_bytes, bounds.receipt_bytes, bounds.depth
    );
    println!("threads: {threads}");
    println!();

    // ---- constraint count ----
    let t = Instant::now();
    let cs = ConstraintSystem::<Fr>::new_ref();
    ReceiptCircuit::prove(bounds, fixture::genuine())
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
    //
    // circuit_specific_setup is a toy setup, not a ceremony. It is the right
    // thing to measure here because the proving key it produces has production
    // size and shape; spec 18.2's multiparty ceremony produces the same
    // artifact through a sound process.
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0);
    let t = Instant::now();
    let (pk, vk) =
        Groth16::<Bn254>::circuit_specific_setup(ReceiptCircuit::setup(bounds), &mut rng)
            .expect("setup");
    let setup_secs = t.elapsed().as_secs_f64();
    let pk_bytes = pk.serialized_size(ark_serialize::Compress::No);
    let pk_compressed = pk.serialized_size(ark_serialize::Compress::Yes);
    println!(
        "setup:        {setup_secs:>8.1}s   proving key {:.2} GB ({:.2} GB compressed)",
        gb(pk_bytes as u64),
        gb(pk_compressed as u64)
    );

    // ---- prove ----
    let t = Instant::now();
    let proof = Groth16::<Bn254>::prove(
        &pk,
        ReceiptCircuit::prove(bounds, fixture::genuine()),
        &mut rng,
    )
    .expect("prove");
    let prove_secs = t.elapsed().as_secs_f64();
    println!("prove:        {prove_secs:>8.1}s");

    // ---- verify ----
    let t = Instant::now();
    // The two public signals the escrow reconstructs on-chain.
    let (hi, lo) = mirage_relation::public_signals(&fixture::genuine());
    let ok = Groth16::<Bn254>::verify(&vk, &[Fr::from(hi), Fr::from(lo)], &proof).expect("verify");
    let verify_ms = t.elapsed().as_secs_f64() * 1000.0;
    println!("verify:       {verify_ms:>8.2}ms  valid={ok}");
    assert!(ok, "proof did not verify");

    println!();
    println!("peak RSS:     {:.1} GB", gb(peak_rss()));
    println!(
        "proof size:   {} bytes",
        proof.serialized_size(ark_serialize::Compress::Yes)
    );
    println!("public:       2 signals (statement hash limbs)");

    // A proof must not verify against the wrong statement.
    let bad = Groth16::<Bn254>::verify(&vk, &[Fr::from(hi) + Fr::from(1u64), Fr::from(lo)], &proof)
        .expect("verify");
    assert!(!bad, "proof verified against a different statement");
    println!("wrong stmt:   correctly rejected");

    println!();
    println!("against spec 19.7: p95 under 75s, memory under 70% of enclave allocation");
    println!(
        "  prove {prove_secs:.1}s -> {}",
        if prove_secs <= 75.0 { "WITHIN" } else { "OVER" }
    );
    println!(
        "  derived estimate was {:.0}s at {:.0} GB; measured {prove_secs:.0}s at {:.0} GB",
        n as f64 / 1e6 * 7.0,
        n as f64 / 1e6 * 2.8,
        gb(peak_rss())
    );
}
