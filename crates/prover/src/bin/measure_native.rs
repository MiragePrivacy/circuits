//! Compare native Keccacheck with the same relation using direct Keccak.
//!
//! Run each in a fresh, otherwise idle process with the same thread count:
//! ```sh
//! RAYON_NUM_THREADS=16 cargo run -p mirage-prover --release --bin measure-native -- --direct
//! RAYON_NUM_THREADS=16 cargo run -p mirage-prover --release --bin measure-native
//! ```
//! Both use identical bounds and witnesses. Proving includes GKR witness
//! generation (Keccacheck) and the library's Groth16 self-verification. Peak
//! RSS covers constraint counting, setup, and all proofs; it is not a
//! proving-only memory measurement. Seeded randomness is for benchmarks only.

use std::time::Instant;

use ark_bn254::Fr;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisMode};
use ark_serialize::CanonicalSerialize;
use mirage_relation::native::{
    fixture, KeccacheckNativeCircuit, NativeBounds, NativeCircuit, MEASUREMENT_SCOPE,
};

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

fn gib(bytes: u64) -> f64 {
    bytes as f64 / 1024.0 / 1024.0 / 1024.0
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let direct = args.iter().any(|arg| arg == "--direct");
    let iterations: usize = args
        .iter()
        .position(|arg| arg == "--iterations")
        .map(|at| {
            args.get(at + 1)
                .expect("--iterations requires a count")
                .parse()
                .expect("invalid count")
        })
        .unwrap_or(3);
    assert!(iterations > 0, "at least one proof is required");
    let threads = std::env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "default".into());
    let bounds = NativeBounds::default();
    let witness = fixture::genuine();

    println!("scope: {MEASUREMENT_SCOPE}");
    println!(
        "backend: {}",
        if direct {
            "direct Keccak"
        } else {
            "Keccacheck"
        }
    );
    println!("threads: {threads}; proofs: {iterations}");
    println!(
        "bounds: tx {} B / node {} B / depth {}, receipt {} B / node {} B / depth {}, header {} B",
        bounds.transaction_bytes,
        bounds.transaction_node_bytes,
        bounds.transaction_depth,
        bounds.common.receipt_bytes,
        bounds.common.node_bytes,
        bounds.common.depth,
        bounds.common.header_bytes,
    );

    // Count without an expensive diagnostic satisfiability scan. Every proof
    // below is checked cryptographically by the public library API.
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_mode(SynthesisMode::Setup);
    if direct {
        NativeCircuit::setup(bounds)
            .generate_constraints(cs.clone())
            .expect("synthesis");
    } else {
        KeccacheckNativeCircuit::setup(bounds)
            .generate_constraints(cs.clone())
            .expect("synthesis");
    }
    println!("constraints: {}", cs.num_constraints());
    drop(cs);

    let t = Instant::now();
    let keys = if direct {
        mirage_prover::native::setup(bounds, 0)
    } else {
        mirage_prover::native::setup_keccacheck(bounds, 0)
    }
    .expect("setup");
    println!("setup_seconds: {:.3}", t.elapsed().as_secs_f64());
    println!(
        "proving_key_gib: {:.3}",
        gib(keys.pk.serialized_size(ark_serialize::Compress::No) as u64)
    );
    println!(
        "compressed_proving_key_gib: {:.3}",
        gib(keys.pk.serialized_size(ark_serialize::Compress::Yes) as u64)
    );
    println!("peak_rss_after_setup_gib: {:.3}", gib(peak_rss()));

    let mut times = Vec::with_capacity(iterations);
    for i in 0..iterations {
        let t = Instant::now();
        let settlement = if direct {
            mirage_prover::native::prove_seeded(&keys, bounds, &witness, i as u64)
        } else {
            mirage_prover::native::prove_keccacheck_seeded(&keys, bounds, &witness, i as u64)
        }
        .expect("prove and self-verify");
        let secs = t.elapsed().as_secs_f64();
        assert_eq!(settlement.signals, {
            let (hi, lo) = mirage_relation::native::public_signals(&witness);
            [hi, lo]
        });
        println!("proof_{}_seconds: {secs:.3}", i + 1);
        times.push(secs);
    }
    times.sort_by(f64::total_cmp);
    let median = if iterations.is_multiple_of(2) {
        (times[iterations / 2 - 1] + times[iterations / 2]) / 2.0
    } else {
        times[iterations / 2]
    };
    println!("median_prove_seconds: {median:.3}");
    println!("peak_process_rss_gib: {:.3}", gib(peak_rss()));
}
