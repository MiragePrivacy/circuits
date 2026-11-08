//! Identity and wiring of the two deployed Keccacheck relations.
//!
//! The digests pin the compiled matrices to `r1cs_digest` in the beta ceremony's
//! `inputs.json`, whose SHA-256 is `inputs_sha256` in
//! `crates/sgx-ceremony/releases/beta-20261104.json`. Large: run one at a time
//! with `--release -- --ignored --test-threads=1`.
#![cfg(feature = "export")]

use ark_bn254::Fr;
use ark_ff::Zero;
use ark_r1cs_std::boolean::Boolean;
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal, SynthesisError,
    SynthesisMode,
};
use mirage_gadgets::keccak::{DirectPermutation, PermutationBackend, State};
use mirage_keccacheck_arkworks::{
    batch::{BatchResult, KeccacheckBatch},
    matrix::Compiled,
};
use mirage_prover::ceremony::R1cs;
use mirage_relation::{
    fixture,
    native::{
        self, fixture as native_fixture, KeccacheckNativeCircuit, NativeBounds, NativeCircuit,
    },
    Bounds, KeccacheckReceiptCircuit, ReceiptCircuit,
};

const NATIVE_DIGEST: &str = "de23e3afaeb9a14f461eed444f9e2de1f5b3d4b6f60adfc190e71122a667b6bb";
const ERC20_DIGEST: &str = "2a689108a5035269d6e5471facf96e2f45e4e27cd6f2be9970a69e9efbb272f0";

fn setup_cs() -> ConstraintSystemRef<Fr> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    cs
}

fn prove_cs() -> ConstraintSystemRef<Fr> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs
}

fn digest_of(cs: &ConstraintSystemRef<Fr>) -> String {
    cs.finalize();
    hex::encode(R1cs::from_cs(cs).unwrap().digest())
}

fn digest_synthesized(
    cs: ConstraintSystemRef<Fr>,
    circuit: impl ConstraintSynthesizer<Fr>,
) -> String {
    circuit.generate_constraints(cs.clone()).unwrap();
    digest_of(&cs)
}

/// Sees each state the relation sends through the batch.
struct Recording {
    batch: KeccacheckBatch,
    inputs: Vec<State<Fr>>,
    outputs: Vec<State<Fr>>,
}

impl PermutationBackend<Fr> for Recording {
    fn permute(&mut self, state: State<Fr>) -> Result<State<Fr>, SynthesisError> {
        self.inputs.push(state.clone());
        let output = self.batch.permute(state)?;
        self.outputs.push(output.clone());
        Ok(output)
    }
}

/// Counts permutations under the direct backend.
#[derive(Default)]
struct Counting(usize);

impl PermutationBackend<Fr> for Counting {
    fn permute(&mut self, state: State<Fr>) -> Result<State<Fr>, SynthesisError> {
        self.0 += 1;
        DirectPermutation.permute(state)
    }
}

struct Wired {
    cs: ConstraintSystemRef<Fr>,
    recording_inputs: Vec<State<Fr>>,
    recording_outputs: Vec<State<Fr>>,
    result: BatchResult,
    before_verifier: usize,
}

fn wire(
    cs: ConstraintSystemRef<Fr>,
    relation: impl FnOnce(ConstraintSystemRef<Fr>, &mut Recording) -> Result<(), SynthesisError>,
) -> Wired {
    let mut recording = Recording {
        batch: KeccacheckBatch::new(cs.clone()),
        inputs: Vec::new(),
        outputs: Vec::new(),
    };
    relation(cs.clone(), &mut recording).unwrap();
    let before_verifier = cs.num_constraints();
    let Recording {
        batch,
        inputs,
        outputs,
    } = recording;
    let result = batch.finish().unwrap();
    Wired {
        cs,
        recording_inputs: inputs,
        recording_outputs: outputs,
        result,
        before_verifier,
    }
}

/// Column terms of a bit: `(column, negated)`; `None` for a constant.
fn bit_column(
    cs: &ConstraintSystemRef<Fr>,
    compiled: &Compiled,
    bit: &Boolean<Fr>,
) -> Option<(usize, bool)> {
    let Boolean::Var(bit) = bit else {
        return None;
    };
    let variable = bit.variable();
    if !variable.is_lc() {
        return Some((compiled.column(variable).unwrap(), false));
    }
    let inner = cs.borrow().unwrap();
    let lc = inner.get_lc(variable);
    let terms: Vec<_> =
        lc.0.iter()
            .filter(|(coeff, _)| !coeff.is_zero())
            .map(|(coeff, var)| (*coeff, compiled.column(*var).unwrap()))
            .collect();
    match terms.as_slice() {
        [(c, x)] if *c == Fr::from(1u64) => Some((*x, false)),
        [(a, 0), (b, x)] | [(b, x), (a, 0)] if *a == Fr::from(1u64) && *b == -Fr::from(1u64) => {
            Some((*x, true))
        }
        other => panic!("statement bit is not x or 1 - x: {other:?}"),
    }
}

/// Every recorded state is Boolean and reaches the verifier rows; every output
/// edit is seen there. Returns the count of witness bits examined.
fn assert_statement_wiring(wired: &Wired) -> usize {
    let compiled = Compiled::from_cs(&wired.cs).unwrap();
    let booleans = compiled.boolean_columns();
    let by_column = compiled.rows_by_column();
    let mut examined = 0;
    let mut unresolved = Vec::new();
    let mut unreachable = Vec::new();
    let states = wired
        .recording_inputs
        .iter()
        .chain(&wired.recording_outputs);
    for (index, state) in states.enumerate() {
        for (position, bit) in state.iter().flatten().enumerate() {
            let Some((column, _)) = bit_column(&wired.cs, &compiled, bit) else {
                continue;
            };
            examined += 1;
            if !booleans[column] {
                unresolved.push((index, position, column));
            }
            let last = by_column[column].last().copied().unwrap_or(0) as usize;
            if last < wired.before_verifier {
                unreachable.push((index, position, column));
            }
        }
    }
    assert_eq!(unresolved, Vec::new(), "non-Boolean statement bits");
    assert_eq!(
        unreachable,
        Vec::new(),
        "statement bits outside the verifier"
    );

    // No output of the batch is a constant: each is a fresh witness.
    for output in &wired.recording_outputs {
        assert!(output
            .iter()
            .flatten()
            .all(|bit| matches!(bit, Boolean::Var(_))));
    }

    // Editing one output bit of each permutation fails a verifier row.
    if !compiled.z.is_empty() {
        for (k, output) in wired.recording_outputs.iter().enumerate() {
            let (column, _) = bit_column(&wired.cs, &compiled, &output[k % 25][k % 64]).unwrap();
            let mut z = compiled.z.clone();
            z[column] = Fr::from(1u64) - z[column];
            assert!(
                by_column[column]
                    .iter()
                    .any(|row| *row as usize >= wired.before_verifier
                        && !compiled.residual_at(*row as usize, &z).is_zero()),
                "permutation {k} is not bound by the verifier"
            );
        }
        assert_eq!(compiled.unsatisfied(), Vec::<usize>::new());
    }
    examined
}

#[test]
#[ignore = "large"]
fn native_setup_digest_matches_ceremony() {
    assert_eq!(
        digest_synthesized(
            setup_cs(),
            KeccacheckNativeCircuit::setup(NativeBounds::default())
        ),
        NATIVE_DIGEST
    );
}

#[test]
#[ignore = "large"]
fn erc20_setup_digest_matches_ceremony() {
    assert_eq!(
        digest_synthesized(
            setup_cs(),
            KeccacheckReceiptCircuit::setup(Bounds::default())
        ),
        ERC20_DIGEST
    );
}

#[test]
#[ignore = "large"]
fn native_prove_mode_compiles_the_ceremony_circuit() {
    let circuit =
        KeccacheckNativeCircuit::prove(NativeBounds::default(), native_fixture::genuine());
    assert_eq!(digest_synthesized(prove_cs(), circuit), NATIVE_DIGEST);
}

#[test]
#[ignore = "large"]
fn erc20_prove_mode_compiles_the_ceremony_circuit() {
    let circuit = KeccacheckReceiptCircuit::prove(Bounds::default(), fixture::genuine());
    assert_eq!(digest_synthesized(prove_cs(), circuit), ERC20_DIGEST);
}

/// `finish` is part of the synthesizer: backend plus `finish` reproduces the
/// digest, and the backend alone compiles a relation with no Keccak binding.
#[test]
#[ignore = "large"]
fn native_synthesizer_runs_finish_under_setup() {
    let bounds = NativeBounds::default();
    let wired = wire(setup_cs(), |cs, backend| {
        native::generate_constraints_with_backend(NativeCircuit::setup(bounds), cs, backend)
    });
    assert_eq!((wired.result.recorded, wired.result.padded), (256, 256));
    assert_eq!(wired.result.profile.checks.len(), 3 + 24 * 7 + 25);
    assert_eq!(
        wired.before_verifier + wired.result.profile.total,
        wired.cs.num_constraints()
    );
    assert_eq!(digest_of(&wired.cs), NATIVE_DIGEST);
}

#[test]
#[ignore = "large"]
fn erc20_synthesizer_runs_finish_under_setup() {
    let bounds = Bounds::default();
    let wired = wire(setup_cs(), |cs, backend| {
        mirage_relation::generate_constraints_with_backend(
            ReceiptCircuit::setup(bounds),
            cs,
            backend,
        )
    });
    assert_eq!((wired.result.recorded, wired.result.padded), (232, 256));
    assert_eq!(wired.result.profile.checks.len(), 3 + 24 * 7 + 25);
    assert_eq!(
        wired.before_verifier + wired.result.profile.total,
        wired.cs.num_constraints()
    );
    assert_eq!(digest_of(&wired.cs), ERC20_DIGEST);
}

#[test]
#[ignore = "large"]
fn native_statement_is_wired_under_a_genuine_witness() {
    let bounds = NativeBounds::default();
    let wired = wire(prove_cs(), |cs, backend| {
        native::generate_constraints_with_backend(
            NativeCircuit::prove(bounds, native_fixture::genuine()),
            cs,
            backend,
        )
    });
    assert_eq!(wired.recording_outputs.len(), wired.result.recorded);
    let examined = assert_statement_wiring(&wired);
    eprintln!("native: {examined} witness statement bits");
    assert_eq!(digest_of(&wired.cs), NATIVE_DIGEST);
}

#[test]
#[ignore = "large"]
fn erc20_statement_is_wired_under_a_genuine_witness() {
    let bounds = Bounds::default();
    let wired = wire(prove_cs(), |cs, backend| {
        mirage_relation::generate_constraints_with_backend(
            ReceiptCircuit::prove(bounds, fixture::genuine()),
            cs,
            backend,
        )
    });
    assert_eq!(wired.recording_outputs.len(), wired.result.recorded);
    let examined = assert_statement_wiring(&wired);
    eprintln!("erc20: {examined} witness statement bits");
    assert_eq!(digest_of(&wired.cs), ERC20_DIGEST);
}

/// The direct relation makes as many permutation calls as the batch records.
#[test]
#[ignore = "large"]
fn permutation_counts_agree_with_the_direct_backend() {
    let mut counting = Counting::default();
    native::generate_constraints_with_backend(
        NativeCircuit::setup(NativeBounds::default()),
        setup_cs(),
        &mut counting,
    )
    .unwrap();
    assert_eq!(counting.0, 256);
    let mut counting = Counting::default();
    mirage_relation::generate_constraints_with_backend(
        ReceiptCircuit::setup(Bounds::default()),
        setup_cs(),
        &mut counting,
    )
    .unwrap();
    assert_eq!(counting.0, 232);
}

/// Keys of a ceremony run directory named by `MIRAGE_CEREMONY_RUN`.
///
/// The key is not derivable from the digest without Phase 1, but a proof built
/// from the reviewed relation verifies only if the key encodes those matrices.
fn ceremony_keys(circuit: &str) -> mirage_prover::Keys {
    use ark_serialize::{CanonicalDeserialize, Compress, Validate};
    let run = std::env::var("MIRAGE_CEREMONY_RUN").expect("MIRAGE_CEREMONY_RUN");
    let dir = std::path::Path::new(&run).join(circuit);
    let pk = std::fs::read(dir.join("final.pk")).unwrap();
    let vk = std::fs::read(dir.join("final.vk")).unwrap();
    mirage_prover::Keys {
        pk: mirage_prover::load_proving_key(&pk, false).unwrap(),
        vk: ark_groth16::VerifyingKey::deserialize_with_mode(&vk[..], Compress::No, Validate::Yes)
            .unwrap(),
    }
}

#[test]
#[ignore = "needs a ceremony run directory"]
fn native_ceremony_key_proves_the_reviewed_relation() {
    use ark_std::rand::SeedableRng;
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(1);
    mirage_prover::native::prove_keccacheck(
        &ceremony_keys("native-keccacheck"),
        NativeBounds::default(),
        &native_fixture::genuine(),
        &mut rng,
    )
    .unwrap();
}

#[test]
#[ignore = "needs a ceremony run directory"]
fn erc20_ceremony_key_proves_the_reviewed_relation() {
    use ark_std::rand::SeedableRng;
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(2);
    mirage_prover::prove_keccacheck(
        &ceremony_keys("erc20-keccacheck"),
        Bounds::default(),
        &fixture::genuine(),
        &mut rng,
    )
    .unwrap();
}

/// A key for the other relation must not verify, or the two tests above say nothing.
#[test]
#[ignore = "needs a ceremony run directory"]
fn a_ceremony_key_does_not_prove_the_other_relation() {
    use ark_std::rand::SeedableRng;
    let keys = ceremony_keys("native-keccacheck");
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(3);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        mirage_prover::prove_keccacheck(&keys, Bounds::default(), &fixture::genuine(), &mut rng)
    }));
    assert!(!matches!(outcome, Ok(Ok(_))));
}
