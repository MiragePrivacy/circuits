//! Keccacheck Groth16 benchmark for the host and for an SGX enclave.
//!
//! One setup, then a plan of proofs against the same resident key, each
//! reporting wall time and the heap high-water mark. A counting allocator
//! measures heap rather than RSS, which an enclave cannot read.
//!
//! ```sh
//! sgx-bench --circuit native --setup-threads 16 --plan standard:16,standard:6,early-free:6
//! sgx-bench --circuit native --census      # host only: matrix non-zeros per stage
//! ```

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::Instant;

use ark_bn254::{Bn254, Fr};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{PrimeField, UniformRand};
use ark_groth16::r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};
use ark_groth16::{Groth16, Proof, ProvingKey};
use ark_poly::GeneralEvaluationDomain;
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisError, SynthesisMode,
    R1CS_PREDICATE_LABEL,
};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use rayon::prelude::*;

struct Counting;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grow(by: usize) {
    let now = CURRENT.fetch_add(by, Relaxed) + by;
    PEAK.fetch_max(now, Relaxed);
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            grow(layout.size());
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            grow(layout.size());
        }
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        unsafe { System.dealloc(p, layout) };
        CURRENT.fetch_sub(layout.size(), Relaxed);
    }

    unsafe fn realloc(&self, p: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let q = unsafe { System.realloc(p, layout, new_size) };
        if !q.is_null() {
            if new_size >= layout.size() {
                grow(new_size - layout.size());
            } else {
                CURRENT.fetch_sub(layout.size() - new_size, Relaxed);
            }
        }
        q
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn gib(bytes: usize) -> f64 {
    bytes as f64 / (1u64 << 30) as f64
}

/// Runs `f` and reports its wall time and the heap peak reached during it.
fn measure<T>(label: &str, f: impl FnOnce() -> T) -> T {
    PEAK.store(CURRENT.load(Relaxed), Relaxed);
    let before = CURRENT.load(Relaxed);
    let t = Instant::now();
    let out = f();
    println!(
        "{label}: {:.1}s, heap peak {:.2} GiB (resident before {:.2} GiB, after {:.2} GiB)",
        t.elapsed().as_secs_f64(),
        gib(PEAK.load(Relaxed)),
        gib(before),
        gib(CURRENT.load(Relaxed)),
    );
    out
}

fn pool(threads: usize) -> rayon::ThreadPool {
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .expect("thread pool")
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    Standard,
    EarlyFree,
    Streaming,
    Prover(mirage_prover::streaming::MsmStrategy),
}

/// The QAP witness map from per-constraint values rather than matrices.
///
/// Synthesis in `generate_lc_assignments` mode records every linear
/// combination's value as it is created, so `A·z`, `B·z` and `C·z` for each
/// constraint are lookups. Neither the inlined linear combinations nor the
/// matrices are ever built. The FFT steps follow
/// `LibsnarkReduction::witness_map_from_matrices` exactly.
fn witness_map_streaming(cs: &ConstraintSystem<Fr>) -> Vec<Fr> {
    use ark_ff::{FftField, Field, Zero};
    use ark_poly::EvaluationDomain;

    let num_inputs = cs.num_instance_variables();
    let num_constraints = cs.num_constraints();
    let r1cs = &cs.predicate_constraint_systems[R1CS_PREDICATE_LABEL];
    assert_eq!(r1cs.num_constraints(), num_constraints, "non-R1CS constraints present");
    let [a_lcs, b_lcs, c_lcs] = &r1cs.get_constraints()[..] else {
        panic!("R1CS has arity three");
    };
    let value = |v| cs.assigned_value(v).expect("unassigned linear combination");

    let domain = GeneralEvaluationDomain::<Fr>::new(num_constraints + num_inputs).expect("domain");
    let mut a = vec![Fr::zero(); domain.size()];
    let mut b = vec![Fr::zero(); domain.size()];
    for i in 0..num_constraints {
        a[i] = value(a_lcs[i]);
        b[i] = value(b_lcs[i]);
    }
    a[num_constraints..num_constraints + num_inputs]
        .clone_from_slice(cs.instance_assignment().expect("instance"));

    domain.ifft_in_place(&mut a);
    domain.ifft_in_place(&mut b);
    let coset = domain.get_coset(Fr::GENERATOR).expect("coset");
    coset.fft_in_place(&mut a);
    coset.fft_in_place(&mut b);
    let mut ab = domain.mul_polynomials_in_evaluation_domain(&a, &b);
    drop(a);
    drop(b);

    let mut c = vec![Fr::zero(); domain.size()];
    for i in 0..num_constraints {
        c[i] = value(c_lcs[i]);
    }
    domain.ifft_in_place(&mut c);
    coset.fft_in_place(&mut c);

    let vanishing = domain
        .evaluate_vanishing_polynomial(Fr::GENERATOR)
        .inverse()
        .expect("vanishing");
    ab.par_iter_mut().zip(c).for_each(|(ab_i, c_i)| {
        *ab_i -= &c_i;
        *ab_i *= &vanishing;
    });
    coset.ifft_in_place(&mut ab);
    ab
}

/// `ark_groth16`'s prover with the constraint system dropped once the QAP
/// witness map is computed, so the multiscalar multiplications run without
/// the matrices or the symbolic linear-combination store resident.
///
/// The MSM half follows `Groth16::create_proof_with_assignment` exactly, with
/// `r` and `s` drawn in the same order as `create_random_proof_with_reduction`.
fn prove_early_free<C: ConstraintSynthesizer<Fr>>(
    pk: &ProvingKey<Bn254>,
    circuit: C,
    rng: &mut StdRng,
    streaming: bool,
) -> Result<Proof<Bn254>, SynthesisError> {
    let r = Fr::rand(rng);
    let s = Fr::rand(rng);

    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: true,
        generate_lc_assignments: streaming,
    });
    measure("  synthesis (incl. GKR witness)", || circuit.generate_constraints(cs.clone()))?;
    let h = if streaming {
        measure("  witness map (streaming)", || witness_map_streaming(&cs.borrow().unwrap()))
    } else {
        measure("  finalize (inline LCs)", || cs.finalize());
        measure("  witness map", || LibsnarkReduction::witness_map::<Fr, GeneralEvaluationDomain<Fr>>(cs.clone()))?
    };
    let (input, aux) = {
        let inner = cs.borrow().unwrap();
        (
            inner.instance_assignment()?[1..].to_vec(),
            inner.witness_assignment()?.to_vec(),
        )
    };
    // The last reference: dropping it frees the matrices and LC store.
    assert!(cs.into_inner().is_some(), "constraint system still shared");
    println!("  after dropping the constraint system: resident {:.2} GiB", gib(CURRENT.load(Relaxed)));
    PEAK.store(CURRENT.load(Relaxed), Relaxed);
    let msm = Instant::now();

    let h: Vec<_> = h.into_par_iter().map(|x| x.into_bigint()).collect();
    let h_acc = <Bn254 as Pairing>::G1::msm_bigint(&pk.h_query, &h);
    drop(h);

    let aux: Vec<_> = aux.par_iter().map(|x| x.into_bigint()).collect();
    let l_aux_acc = <Bn254 as Pairing>::G1::msm_bigint(&pk.l_query, &aux);
    let r_s_delta_g1 = pk.delta_g1 * (r * s);
    let input: Vec<_> = input.iter().map(|x| x.into_bigint()).collect();
    let assignment = [&input[..], &aux[..]].concat();
    drop(aux);

    fn coeff<G: AffineRepr>(
        initial: G::Group,
        query: &[G],
        vk_param: G,
        assignment: &[<G::ScalarField as PrimeField>::BigInt],
    ) -> G::Group
    where
        G::Group: VariableBaseMSM<MulBase = G>,
    {
        let mut res = initial;
        res += query[0];
        res += G::Group::msm_bigint(&query[1..], assignment);
        res += vk_param;
        res
    }

    let g_a = coeff(pk.delta_g1 * r, &pk.a_query, pk.vk.alpha_g1, &assignment);
    let s_g_a = g_a * s;
    let g1_b = coeff(pk.delta_g1 * s, &pk.b_g1_query, pk.beta_g1, &assignment);
    let g2_b = coeff(pk.vk.delta_g2 * s, &pk.b_g2_query, pk.vk.beta_g2, &assignment);
    drop(assignment);

    let g_c = s_g_a + g1_b * r - r_s_delta_g1 + l_aux_acc + h_acc;
    println!("  MSMs: {:.1}s, heap peak {:.2} GiB", msm.elapsed().as_secs_f64(), gib(PEAK.load(Relaxed)));
    Ok(Proof {
        a: g_a.into_affine(),
        b: g2_b.into_affine(),
        c: g_c.into_affine(),
    })
}

/// Matrix non-zeros per relation stage and Keccacheck verifier phase. Each
/// entry is a field element and a column index, 40 bytes on a 64-bit target.
fn census(
    synthesize: impl FnOnce(
        ark_relations::gr1cs::ConstraintSystemRef<Fr>,
        &mut mirage_keccacheck_arkworks::batch::KeccacheckBatch,
    ),
) {
    let cs = ConstraintSystem::new_ref();
    cs.set_mode(SynthesisMode::Setup);
    let mut batch = mirage_keccacheck_arkworks::batch::KeccacheckBatch::new(cs.clone());
    synthesize(cs.clone(), &mut batch);
    let mut marks = mirage_relation::take_stage_marks();
    let mut at = cs.num_constraints();
    let profile = batch.finish().expect("verifier").profile;
    for (phase, n) in [
        ("verifier: allocation", profile.allocation),
        ("verifier: output binding", profile.output_binding),
        ("verifier: output reduction", profile.output_reduction),
        ("verifier: 24 rounds", profile.rounds),
        ("verifier: input binding", profile.input_binding),
    ] {
        at += n;
        marks.push((phase.into(), at));
    }
    let rows = cs.num_constraints();
    cs.finalize();
    let matrices = cs.to_matrices().expect("matrices");
    let m = &matrices[R1CS_PREDICATE_LABEL];
    let nnz_row = |i: usize| m.iter().map(|matrix| matrix[i].len()).sum::<usize>();

    let total: usize = (0..rows).map(nnz_row).sum();
    println!("census: {rows} constraints, {total} non-zeros, ~{:.2} GiB as (Fr, usize)", gib(total * 40));
    println!("{:>28} {:>11} {:>12} {:>8} {:>7}", "stage", "constraints", "non-zeros", "per row", "share");
    let mut start = 0;
    for (stage, end) in marks {
        let nnz: usize = (start..end.min(rows)).map(nnz_row).sum();
        let n = end.min(rows) - start;
        if n > 0 {
            println!(
                "{stage:>28} {n:>11} {nnz:>12} {:>8.1} {:>6.1}%",
                nnz as f64 / n as f64,
                100.0 * nnz as f64 / total as f64
            );
        }
        start = end.min(rows);
    }
    let widest = (0..rows).map(nnz_row).max().unwrap_or(0);
    let wide = (0..rows).filter(|&i| nnz_row(i) > 64).count();
    println!("widest row {widest} non-zeros; {wide} rows above 64");
}

struct Run<C> {
    setup: C,
    prove: Box<dyn Fn() -> C>,
    signals: [Fr; 2],
}

fn run<C: ConstraintSynthesizer<Fr> + Clone + Send + Sync>(run: Run<C>, setup_threads: usize, plan: &[(Mode, usize)]) {
    let mut rng = StdRng::seed_from_u64(0);
    let (pk, vk) = measure(&format!("setup threads={setup_threads}"), || {
        pool(setup_threads).install(|| Groth16::<Bn254>::circuit_specific_setup(run.setup.clone(), &mut rng))
    })
    .expect("setup");
    let pvk = Groth16::<Bn254>::process_vk(&vk).expect("process vk");
    println!("proving key resident: {:.2} GiB", gib(CURRENT.load(Relaxed)));

    for (i, &(mode, threads)) in plan.iter().enumerate() {
        let circuit = (run.prove)();
        let mut rng = StdRng::seed_from_u64(1 + i as u64);
        let proof = measure(&format!("prove mode={mode:?} threads={threads}"), || {
            pool(threads).install(|| match mode {
                Mode::Standard => Groth16::<Bn254>::prove(&pk, circuit, &mut rng),
                Mode::EarlyFree => prove_early_free(&pk, circuit, &mut rng, false),
                Mode::Streaming => prove_early_free(&pk, circuit, &mut rng, true),
                Mode::Prover(strategy) => mirage_prover::streaming::prove_with(&pk, circuit, &mut rng, strategy),
            })
        })
        .expect("prove");
        let ok = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &run.signals, &proof).expect("verify");
        println!("  verified: {ok}");
        assert!(ok, "proof did not verify");
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let arg = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let circuit = arg("--circuit").unwrap_or_else(|| "native".into());
    let setup_threads: usize = arg("--setup-threads").map_or(16, |v| v.parse().expect("--setup-threads"));
    let plan: Vec<(Mode, usize)> = arg("--plan")
        .unwrap_or_else(|| "standard:16".into())
        .split(',')
        .map(|step| {
            let (mode, threads) = step.split_once(':').expect("mode:threads");
            let mode = match mode {
                "standard" => Mode::Standard,
                "early-free" => Mode::EarlyFree,
                "streaming" => Mode::Streaming,
                "prover" => Mode::Prover(mirage_prover::streaming::MsmStrategy::Whole),
                chunked if chunked.starts_with("chunked-") => Mode::Prover(
                    mirage_prover::streaming::MsmStrategy::Chunked(chunked["chunked-".len()..].parse().expect("chunk size")),
                ),
                other => panic!("unknown mode {other}"),
            };
            (mode, threads.parse().expect("threads"))
        })
        .collect();

    use mirage_relation::native::{self, KeccacheckNativeCircuit, NativeBounds};
    use mirage_relation::{Bounds, KeccacheckReceiptCircuit};

    if args.iter().any(|a| a == "--census") {
        // SAFETY: single-threaded at this point.
        unsafe { std::env::set_var("RELATION_PROFILE", "1") };
        match circuit.as_str() {
            "native" => census(|cs, batch| {
                native::generate_constraints_with_backend(native::NativeCircuit::setup(NativeBounds::default()), cs, batch)
                    .expect("synthesis")
            }),
            "erc20" => census(|cs, batch| {
                mirage_relation::generate_constraints_with_backend(mirage_relation::ReceiptCircuit::setup(Bounds::default()), cs, batch)
                    .expect("synthesis")
            }),
            other => panic!("unknown circuit {other}"),
        }
        return;
    }

    println!("circuit={circuit} setup_threads={setup_threads} plan={plan:?}");
    match circuit.as_str() {
        "native" => {
            let w = native::fixture::genuine();
            let (hi, lo) = native::public_signals(&w);
            run(
                Run {
                    setup: KeccacheckNativeCircuit::setup(NativeBounds::default()),
                    prove: Box::new(move || KeccacheckNativeCircuit::prove(NativeBounds::default(), w.clone())),
                    signals: [Fr::from(hi), Fr::from(lo)],
                },
                setup_threads,
                &plan,
            );
        }
        "erc20" => {
            let w = mirage_relation::fixture::genuine();
            let (hi, lo) = mirage_relation::public_signals(&w);
            run(
                Run {
                    setup: KeccacheckReceiptCircuit::setup(Bounds::default()),
                    prove: Box::new(move || KeccacheckReceiptCircuit::prove(Bounds::default(), w.clone())),
                    signals: [Fr::from(hi), Fr::from(lo)],
                },
                setup_threads,
                &plan,
            );
        }
        other => panic!("unknown circuit {other}"),
    }
}
