//! Synthetic Groth16 benchmark on BN254.
//!
//! Two circuit shapes:
//!   - `mul`:  x = x*x + c chain. One R1CS constraint per step. Dense, best case.
//!   - `bool`: boolean witnesses with XOR/AND chains, approximating keccak's shape.
//!
//! Usage: bench-arkworks <shape> <log2_constraints> <label>

use std::env;
use std::fs;
use std::time::Instant;

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_ff::UniformRand;
use ark_groth16::Groth16;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use ark_serialize::{CanonicalSerialize, Compress};
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;

/// x = x*x + c, repeated `steps` times. Each step is exactly one R1CS constraint
/// (the multiplication); the addition is folded into a linear combination.
#[derive(Clone)]
struct MulChain {
    x0: Option<Fr>,
    steps: usize,
}

impl ConstraintSynthesizer<Fr> for MulChain {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let mut x = FpVar::new_input(cs.clone(), || {
            self.x0.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let c = Fr::from(7u64);
        for _ in 0..self.steps {
            // new_witness + enforce_equal gives one multiplication constraint per step
            let sq = x.square()?;
            x = sq + c;
        }
        // Bind the final value to a public input so the chain cannot be optimized away.
        let out = FpVar::new_input(cs.clone(), || x.value())?;
        x.enforce_equal(&out)?;
        Ok(())
    }
}

/// Boolean-heavy circuit approximating the shape of a keccak permutation:
/// many Boolean witnesses, XOR chains (linear, free-ish) interleaved with AND
/// gates (one constraint each), plus the booleanity constraint per allocation.
#[derive(Clone)]
struct BoolChain {
    seed: Option<bool>,
    /// number of AND gates; total constraints ~= 2 * ands (booleanity + AND)
    ands: usize,
}

impl ConstraintSynthesizer<Fr> for BoolChain {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let seed = self.seed;
        // A small register file of bits, like a keccak lane set.
        let mut state: Vec<Boolean<Fr>> = Vec::with_capacity(64);
        for i in 0..64 {
            state.push(Boolean::new_witness(cs.clone(), || {
                seed.map(|s| s ^ (i % 3 == 0))
                    .ok_or(SynthesisError::AssignmentMissing)
            })?);
        }
        // Each round: chi-like step, and = a & b (1 constraint), xor is linear.
        for i in 0..self.ands {
            let a = state[i % 64].clone();
            let b = state[(i * 7 + 13) % 64].clone();
            let c = state[(i * 31 + 5) % 64].clone();
            let and = (&a) & (&b); // 1 multiplication constraint
            // Fresh boolean witness: booleanity is 1 more constraint
            let fresh = Boolean::new_witness(cs.clone(), || {
                Ok(and.value().unwrap_or(false) ^ c.value().unwrap_or(false))
            })?;
            let xored = and.clone() ^ &c; // linear, no constraint
            fresh.enforce_equal(&xored)?;
            state[i % 64] = fresh;
        }
        for b in state.iter().take(8) {
            let pubv = Boolean::new_input(cs.clone(), || Ok(b.value().unwrap_or(false)))?;
            b.enforce_equal(&pubv)?;
        }
        Ok(())
    }
}

fn peak_rss_kb() -> u64 {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM:"))
                .and_then(|l| l.split_whitespace().nth(1).map(|v| v.to_string()))
        })
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

macro_rules! run_bench {
    ($circuit_ctor:expr, $shape:expr, $param:expr, $label:expr, $threads:expr) => {{
        let mut rng = StdRng::seed_from_u64(0xB0BACAFE);
        // One fixed instance used for setup, proving and verification, so the
        // public inputs recovered below match the ones the proof commits to.
        let circuit = {
            let mut r = StdRng::seed_from_u64(0xC0FFEE);
            $circuit_ctor(&mut r)
        };

        // --- constraint count check (synthesis only, no proving) ---
        let cs = ConstraintSystem::<Fr>::new_ref();
        let t = Instant::now();
        circuit.clone().generate_constraints(cs.clone()).unwrap();
        let synth_only_ms = t.elapsed().as_secs_f64() * 1000.0;
        let t = Instant::now();
        cs.finalize();
        let finalize_ms = t.elapsed().as_secs_f64() * 1000.0;
        let num_constraints = cs.num_constraints();
        let num_witness = cs.num_witness_variables();
        let num_instance = cs.num_instance_variables();
        assert!(cs.is_satisfied().unwrap(), "circuit not satisfied");
        drop(cs);

        // --- setup ---
        let t = Instant::now();
        let (pk, vk) =
            Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();
        let setup_s = t.elapsed().as_secs_f64();

        let pk_c = pk.serialized_size(Compress::Yes);
        let pk_u = pk.serialized_size(Compress::No);

        // --- prove (run twice) ---
        let mut prove_times = Vec::new();
        let mut proof = None;
        for _ in 0..2 {
            let t = Instant::now();
            let p = Groth16::<Bn254>::prove(&pk, circuit.clone(), &mut rng).unwrap();
            prove_times.push(t.elapsed().as_secs_f64());
            proof = Some(p);
        }
        let proof = proof.unwrap();

        // --- verify ---
        let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();
        let inputs = {
            let cs = ConstraintSystem::<Fr>::new_ref();
            circuit.clone().generate_constraints(cs.clone()).unwrap();
            cs.finalize();
            let b = cs.borrow().unwrap();
            b.instance_assignment[1..].to_vec()
        };
        let mut verify_times = Vec::new();
        let mut ok = false;
        for _ in 0..3 {
            let t = Instant::now();
            ok = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &inputs, &proof).unwrap();
            verify_times.push(t.elapsed().as_secs_f64() * 1000.0);
        }
        verify_times.sort_by(|a, b| a.partial_cmp(b).unwrap());

        println!("RESULT_JSON {{\"shape\":\"{}\",\"param\":{},\"label\":\"{}\",\"threads\":{},\
\"constraints\":{},\"witness\":{},\"instance\":{},\
\"synth_only_ms\":{:.1},\"finalize_ms\":{:.1},\"setup_s\":{:.3},\
\"prove_s\":[{:.3},{:.3}],\"verify_ms\":{:.3},\"verified\":{},\
\"pk_compressed_bytes\":{},\"pk_uncompressed_bytes\":{},\"peak_rss_kb\":{}}}",
            $shape, $param, $label, $threads,
            num_constraints, num_witness, num_instance,
            synth_only_ms, finalize_ms, setup_s,
            prove_times[0], prove_times[1], verify_times[1], ok,
            pk_c, pk_u, peak_rss_kb());
    }};
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: {} <mul|bool> <log2_constraints> <label>", args[0]);
        std::process::exit(2);
    }
    let shape = args[1].clone();
    let log2n: u32 = args[2].parse().unwrap();
    let label = args[3].clone();
    let threads = rayon::current_num_threads();
    let n = 1usize << log2n;

    eprintln!(
        "== shape={} log2n={} target_constraints={} threads={} label={} ==",
        shape, log2n, n, threads, label
    );

    match shape.as_str() {
        "mul" => {
            // one constraint per step; 2 extra for the output binding
            let steps = n.saturating_sub(2);
            run_bench!(
                |rng: &mut StdRng| MulChain { x0: Some(Fr::rand(rng)), steps },
                "mul", n, label, threads
            );
        }
        "bool" => {
            // measured: 4 constraints per iteration (AND, booleanity of the
            // fresh witness, and the equality against the XOR combination)
            let ands = n / 4;
            run_bench!(
                |_rng: &mut StdRng| BoolChain { seed: Some(true), ands },
                "bool", n, label, threads
            );
        }
        other => {
            eprintln!("unknown shape {}", other);
            std::process::exit(2);
        }
    }
}
