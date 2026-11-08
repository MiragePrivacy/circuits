//! Soundness tests of the Keccacheck verifier against a cheating prover.
//!
//! Every verdict here comes from evaluating the compiled matrices directly,
//! so cached linear-combination values cannot hide a failure.

use crate::{
    batch::{KeccacheckBatch, constant_state, transpose_states},
    matrix::Compiled,
    spec_model,
    testkit::{Break, Forged, Layer, Plan, hooks, prove, sumcheck_index, to_fr, to_fr05},
    verifier::{
        MIN_INSTANCES, NamedCheck, Witness, derive_r_native, derive_r_var, eval_eq,
        eval_mle_with_eq, make_witness_from_data, proof_elements, verify_boolean_batch,
        verify_witness_profile,
    },
};
use ark_bn254::Fr;
use ark_ff::{Field, One, UniformRand, Zero};
use ark_r1cs_std::{
    GR1CSVar,
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
};
use ark_relations::gr1cs::{
    ConstraintSystem, ConstraintSystemRef, SynthesisError, SynthesisMode, Variable,
};
use mirage_gadgets::keccak::{PermutationBackend, State};
use std::{
    cell::Cell,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Once,
};

/// Distinct, high-entropy instance-major states.
fn data(instances: usize) -> Vec<u64> {
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    (0..instances * 25)
        .map(|_| {
            x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = x;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        })
        .collect()
}

struct Run {
    cs: ConstraintSystemRef<Fr>,
    compiled: Compiled,
    checks: Vec<NamedCheck>,
}

impl Run {
    /// Label of every failing row, in row order.
    fn failures(&self) -> Vec<String> {
        self.compiled
            .unsatisfied()
            .into_iter()
            .map(|row| {
                self.checks
                    .iter()
                    .find(|check| check.rows.contains(&row))
                    .map_or_else(|| format!("unnamed row {row}"), |check| check.label.clone())
            })
            .collect()
    }
}

fn synthesize(forged: &Forged, removed: &[String], rebase: Option<(usize, usize, Fr)>) -> Run {
    let witness = Witness {
        proof: forged.proof.clone(),
        input: forged.input.clone(),
        output: forged.output.clone(),
    };
    let cs = ConstraintSystem::<Fr>::new_ref();
    let profile = hooks::with(removed, rebase, || {
        verify_witness_profile(cs.clone(), &witness)
    })
    .expect("synthesis");
    let compiled = Compiled::from_cs(&cs).unwrap();
    Run {
        cs,
        compiled,
        checks: profile.checks,
    }
}

thread_local! {
    static QUIET: Cell<bool> = const { Cell::new(false) };
    static PANIC_AT: Cell<Option<(bool, u32)>> = const { Cell::new(None) };
}

static PANIC_HOOK: Once = Once::new();

#[derive(Debug, PartialEq, Eq)]
enum Upstream {
    Accepts,
    /// A failing assert, by line of `keccacheck_og/verifier.rs`.
    AssertAt(u32),
    /// A panic elsewhere, for example a short transcript.
    PanicElsewhere,
}

/// Runs upstream's native verifier on the same statement and proof.
fn upstream(forged: &Forged) -> Upstream {
    upstream_with(
        &forged.input,
        &forged.output,
        &forged.proof_05,
        forged.r.clone(),
    )
}

fn upstream_with(
    input: &[u64],
    output: &[u64],
    proof: &[ark_bn254_05::Fr],
    r: Vec<ark_bn254_05::Fr>,
) -> Upstream {
    PANIC_HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if QUIET.get() {
                PANIC_AT.set(
                    info.location()
                        .map(|at| (at.file().ends_with("keccacheck_og/verifier.rs"), at.line())),
                );
            } else {
                previous(info);
            }
        }));
    });
    let num_vars = 6 + (input.len() / 25).ilog2() as usize;
    QUIET.set(true);
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        gkr::keccacheck_og::verifier::verify(num_vars, output, input, proof, r)
    }));
    QUIET.set(false);
    match outcome {
        Ok(()) => Upstream::Accepts,
        Err(_) => match PANIC_AT.get() {
            Some((true, line)) => Upstream::AssertAt(line),
            _ => Upstream::PanicElsewhere,
        },
    }
}

/// The upstream assert line that corresponds to a circuit check label.
fn upstream_line(label: &str) -> u32 {
    match label {
        "output sum" => 28,
        "output word reduction" => 38,
        "output bit reduction" => 46,
        label if label.starts_with("input lane") => 80,
        label => match label.rsplit(": ").next().unwrap() {
            "iota" => 107,
            "chi" => 126,
            "rho" => 146,
            "theta" => 166,
            "theta_d" => 186,
            "theta_c" => 216,
            "theta_a" => 244,
            other => panic!("unknown check {other}"),
        },
    }
}

/// The lie fails exactly its check, also upstream, and is a forgery without it.
fn assert_check_is_necessary(instances: usize, lie: Break, seed: usize) {
    let label = lie.label();
    let forged = prove(
        &data(instances),
        Plan {
            lie: Some(lie),
            seed,
            ..Plan::default()
        },
    );
    assert!(forged.statement_is_false(), "{label}: statement is true");

    let run = synthesize(&forged, &[], None);
    assert_eq!(run.failures(), [label.clone()], "lie {lie:?}");
    assert!(!run.cs.is_satisfied().unwrap(), "{label}: cs disagrees");
    assert_eq!(
        upstream(&forged),
        Upstream::AssertAt(lie.upstream_line()),
        "upstream, lie {lie:?}"
    );

    let removed = synthesize(&forged, std::slice::from_ref(&label), None);
    assert_eq!(
        removed.compiled.unsatisfied(),
        Vec::<usize>::new(),
        "no forgery without {label}"
    );
    assert!(removed.cs.is_satisfied().unwrap(), "{label}: cs disagrees");
    assert_eq!(
        removed.compiled.num_rows() + 1,
        run.compiled.num_rows(),
        "{label}: removal must drop one row"
    );
}

/// A false claim passes when the round relation of one sumcheck round is gone.
fn assert_round_relation_is_necessary(instances: usize, lie: Break, sumcheck: usize, round: usize) {
    let forged = prove(
        &data(instances),
        Plan {
            lie: Some(lie),
            rebase: Some((sumcheck, round)),
            seed: round,
            ..Plan::default()
        },
    );
    assert!(forged.statement_is_false());
    assert!(forged.rebase.is_some());
    let run = synthesize(&forged, &[], forged.rebase);
    assert_eq!(
        run.compiled.unsatisfied(),
        Vec::<usize>::new(),
        "no forgery without round {round} of sumcheck {sumcheck}, lie {lie:?}"
    );
}

/// Editing one sent coefficient only fails the end check of that sumcheck.
fn assert_round_tamper_fails(instances: usize, sumcheck: usize, round: usize, expected: &str) {
    let forged = prove(
        &data(instances),
        Plan {
            tamper: Some((sumcheck, round)),
            ..Plan::default()
        },
    );
    assert!(!forged.statement_is_false());
    let run = synthesize(&forged, &[], None);
    let failures = run.failures();
    assert_eq!(failures.first().map(String::as_str), Some(expected));
    assert_eq!(
        upstream(&forged),
        Upstream::AssertAt(upstream_line(expected))
    );
}

const SAMPLE_ROUNDS: [usize; 5] = [23, 22, 12, 1, 0];

fn all_rounds_for(layer: Layer) {
    for round in 0..24 {
        assert_check_is_necessary(4, Break::Round { round, layer }, round);
    }
    for round in SAMPLE_ROUNDS {
        assert_check_is_necessary(8, Break::Round { round, layer }, round + 1);
    }
}

// ---- 1. honest baseline ----

#[test]
fn honest_cheater_reproduces_upstream_proof() {
    for instances in [4, 8, 16] {
        let states = data(instances);
        let forged = prove(&states, Plan::default());
        let witness = make_witness_from_data(&states);
        assert_eq!(forged.proof, witness.proof, "{instances} instances");
        assert_eq!(forged.input, witness.input);
        assert_eq!(forged.output, witness.output);
        assert!(!forged.statement_is_false());
        let run = synthesize(&forged, &[], None);
        assert_eq!(run.failures(), Vec::<String>::new());
        assert_eq!(upstream(&forged), Upstream::Accepts);
    }
}

#[test]
fn every_named_check_is_one_row_in_verification_order() {
    let forged = prove(&data(4), Plan::default());
    let run = synthesize(&forged, &[], None);
    let mut expected = vec![
        "output sum".to_owned(),
        "output word reduction".to_owned(),
        "output bit reduction".to_owned(),
    ];
    for round in (0..24).rev() {
        for layer in Layer::ALL {
            expected.push(format!("round {round}: {}", layer.name()));
        }
    }
    for lane in 0..25 {
        expected.push(format!("input lane {lane}"));
    }
    let labels: Vec<_> = run.checks.iter().map(|check| check.label.clone()).collect();
    assert_eq!(labels, expected);
    for check in &run.checks {
        assert_eq!(check.rows.len(), 1, "{}", check.label);
    }
    assert!(
        run.checks
            .windows(2)
            .all(|w| w[0].rows.end <= w[1].rows.start)
    );
}

/// `FpVar::enforce_equal` on two constants emits nothing and never compares
/// them, so a verifier check must always have a variable side.
#[test]
fn no_check_collapses_to_constants_on_a_constant_statement() {
    let left = FpVar::<Fr>::Constant(Fr::from(1u64));
    left.enforce_equal(&FpVar::Constant(Fr::from(2u64)))
        .expect("arkworks drops constant-constant equality silently");

    let cs = ConstraintSystem::<Fr>::new_ref();
    let bits = vec![Boolean::<Fr>::FALSE; 4 * 25 * 64];
    let proof = vec![Fr::zero(); proof_elements(4)];
    let profile = verify_boolean_batch(cs, &proof, &bits, &bits).unwrap();
    assert_eq!(profile.checks.len(), 3 + 24 * 7 + 25);
    for check in &profile.checks {
        assert_eq!(check.rows.len(), 1, "{}", check.label);
    }
}

// ---- 1. each named check is enforced and necessary ----

#[test]
fn output_sum_is_necessary() {
    for (instances, seed) in [(4, 0), (4, 5), (8, 1), (8, 2)] {
        assert_check_is_necessary(instances, Break::OutputSum, seed);
    }
}

#[test]
fn output_word_reduction_is_necessary() {
    for (instances, seed) in [(4, 0), (4, 5), (8, 1), (8, 2)] {
        assert_check_is_necessary(instances, Break::OutputWords, seed);
    }
}

#[test]
fn output_bit_reduction_is_necessary() {
    for (instances, seed) in [(4, 0), (4, 5), (8, 1), (8, 2)] {
        assert_check_is_necessary(instances, Break::OutputBits, seed);
    }
}

#[test]
fn iota_is_necessary_in_every_round() {
    all_rounds_for(Layer::Iota);
}

#[test]
fn chi_is_necessary_in_every_round() {
    all_rounds_for(Layer::Chi);
}

#[test]
fn rho_is_necessary_in_every_round() {
    all_rounds_for(Layer::Rho);
}

#[test]
fn theta_is_necessary_in_every_round() {
    all_rounds_for(Layer::Theta);
}

#[test]
fn theta_d_is_necessary_in_every_round() {
    all_rounds_for(Layer::ThetaD);
}

#[test]
fn theta_c_is_necessary_in_every_round() {
    all_rounds_for(Layer::ThetaC);
}

#[test]
fn theta_a_is_necessary_in_every_round() {
    all_rounds_for(Layer::ThetaA);
}

#[test]
fn every_input_lane_is_necessary() {
    for lane in 0..25 {
        assert_check_is_necessary(4, Break::InputLane { lane }, lane);
    }
    for lane in [0, 12, 24] {
        assert_check_is_necessary(8, Break::InputLane { lane }, lane + 1);
    }
}

/// Varied lanes, instances, and bits within one round.
#[test]
fn lies_across_lanes_and_instances_are_caught() {
    for seed in 0..12 {
        for layer in [Layer::Theta, Layer::Chi] {
            assert_check_is_necessary(4, Break::Round { round: 7, layer }, seed);
        }
    }
}

// ---- 1. sumcheck round relations ----

/// There is no round-relation constraint: `p(0)` is derived from the running
/// claim, so `p(0) + p(1) = claim` holds by construction and a bad polynomial
/// surfaces at the end check of the same sumcheck, and no earlier.
#[test]
fn a_tampered_round_polynomial_fails_only_its_end_check() {
    let instances = 4;
    let num_vars = 8;
    assert_round_tamper_fails(instances, 0, 0, "output word reduction");
    for round in 0..6 {
        assert_round_tamper_fails(instances, 1, round, "output bit reduction");
    }
    for round_index in [23, 12, 0] {
        for layer in Layer::ALL {
            for sumcheck_round in 0..num_vars {
                assert_round_tamper_fails(
                    instances,
                    sumcheck_index(round_index, layer),
                    sumcheck_round,
                    &format!("round {round_index}: {}", layer.name()),
                );
            }
        }
    }
}

#[test]
fn every_round_relation_of_the_output_reductions_is_necessary() {
    for instances in [4usize] {
        for round in 0..instances.ilog2() as usize {
            assert_round_relation_is_necessary(instances, Break::OutputWords, 0, round);
        }
        for round in 0..6 {
            assert_round_relation_is_necessary(instances, Break::OutputBits, 1, round);
        }
    }
}

#[test]
fn every_round_relation_of_every_layer_is_necessary() {
    for round_index in [23, 12, 0] {
        for layer in Layer::ALL {
            let lie = Break::Round {
                round: round_index,
                layer,
            };
            for sumcheck_round in 0..8 {
                assert_round_relation_is_necessary(
                    4,
                    lie,
                    sumcheck_index(round_index, layer),
                    sumcheck_round,
                );
            }
        }
    }
}

// ---- 2. differential with upstream's native verifier ----

/// One perturbed element per stride position: same first failure in both.
#[test]
fn single_element_edits_agree_with_upstream() {
    for instances in [4] {
        let honest = prove(&data(instances), Plan::default());
        let stride = 41;
        for start in (0..honest.proof.len()).step_by(stride) {
            let mut forged = prove(&data(instances), Plan::default());
            forged.proof[start] += Fr::one();
            forged.proof_05[start] = to_fr05(forged.proof[start]);
            let failures = synthesize(&forged, &[], None).failures();
            let first = failures.first().expect("edit accepted by the circuit");
            assert_eq!(
                upstream(&forged),
                Upstream::AssertAt(upstream_line(first)),
                "element {start}: circuit first fails {first}"
            );
        }
    }
}

/// False statements with a transcript honestly derived over them.
#[test]
fn statement_edits_agree_with_upstream() {
    let instances = 4;
    for word in (0..25 * instances).step_by(3) {
        for bit in [0, 31, 63] {
            let mut forged = prove(&data(instances), Plan::default());
            forged.output[word] ^= 1 << bit;
            forged.r = derive_r_native(&forged.input, &forged.output, 2);
            let failures = synthesize(&forged, &[], None).failures();
            assert_eq!(failures.first().unwrap(), "output sum");
            assert_eq!(upstream(&forged), Upstream::AssertAt(28));

            let mut forged = prove(&data(instances), Plan::default());
            forged.input[word] ^= 1 << bit;
            forged.r = derive_r_native(&forged.input, &forged.output, 2);
            let failures = synthesize(&forged, &[], None).failures();
            assert_eq!(failures.first().unwrap(), "output sum");
            assert_eq!(upstream(&forged), Upstream::AssertAt(28));
        }
    }
}

/// Deliberate difference: upstream trusts its caller's `r`.
#[test]
fn upstream_accepts_any_r_and_the_circuit_derives_it() {
    let states = data(4);
    let chosen = vec![
        ark_bn254_05::Fr::from(12345u64),
        ark_bn254_05::Fr::from(678u64),
    ];
    let (proof, input, output) = gkr::keccacheck_og::prover::prove(&states, chosen.clone());
    assert_eq!(
        upstream_with(&input, &output, &proof, chosen),
        Upstream::Accepts
    );
    let forged = Forged {
        proof: proof.iter().copied().map(to_fr).collect(),
        proof_05: proof,
        input,
        output,
        r: vec![],
        rebase: None,
    };
    let failures = synthesize(&forged, &[], None).failures();
    assert_eq!(failures.first().unwrap(), "output sum");
}

/// Upstream ignores trailing proof elements; the circuit refuses them.
#[test]
fn proof_length_behavior_differs_from_upstream() {
    let forged = prove(&data(4), Plan::default());
    let mut longer = forged.proof_05.clone();
    longer.push(ark_bn254_05::Fr::from(9u64));
    assert_eq!(
        upstream_with(&forged.input, &forged.output, &longer, forged.r.clone()),
        Upstream::Accepts
    );
    let mut shorter = forged.proof_05.clone();
    shorter.pop();
    assert_eq!(
        upstream_with(&forged.input, &forged.output, &shorter, forged.r.clone()),
        Upstream::PanicElsewhere
    );

    let bits = |words: &[u64]| -> Vec<Boolean<Fr>> {
        words
            .iter()
            .flat_map(|word| (0..64).map(move |bit| Boolean::constant((word >> bit) & 1 == 1)))
            .collect()
    };
    let (input, output) = (bits(&forged.input), bits(&forged.output));
    let run = |proof: &[Fr]| {
        verify_boolean_batch(ConstraintSystem::<Fr>::new_ref(), proof, &input, &output).map(|_| ())
    };
    assert!(run(&forged.proof).is_ok());
    for bad in [
        &forged.proof[..forged.proof.len() - 1],
        &forged.proof[..0],
        &[forged.proof.clone(), vec![Fr::zero()]].concat()[..],
    ] {
        assert!(
            matches!(run(bad), Err(SynthesisError::Unsatisfiable)),
            "length {}",
            bad.len()
        );
    }
}

/// Upstream accepts a singleton batch; the circuit refuses to build one.
#[test]
fn singleton_behavior_differs_from_upstream() {
    let states = data(1);
    let (proof, input, output) = gkr::keccacheck_og::prover::prove(&states, vec![]);
    assert_eq!(
        upstream_with(&input, &output, &proof, vec![]),
        Upstream::Accepts
    );
}

// ---- 3. statement and wiring ----

/// The Boolean-only row of `column`, and that it excludes non-Boolean values.
fn assert_column_is_boolean(compiled: &Compiled, rows: &[Vec<u32>], column: usize) {
    let half = Fr::from(2u64).inverse().unwrap();
    let boolean_row = rows[column].iter().find(|row| {
        let row = **row as usize;
        [&compiled.a[row], &compiled.b[row], &compiled.c[row]]
            .iter()
            .all(|entries| entries.iter().all(|(_, col)| *col == column || *col == 0))
    });
    let row = *boolean_row.expect("no row over this column alone") as usize;
    let mut z = compiled.z.clone();
    for good in [Fr::zero(), Fr::one()] {
        z[column] = good;
        assert!(compiled.residual_at(row, &z).is_zero());
    }
    for bad in [Fr::from(2u64), -Fr::one(), half, Fr::from(3u64)] {
        z[column] = bad;
        assert!(!compiled.residual_at(row, &z).is_zero());
    }
}

#[test]
fn every_witness_statement_bit_is_boolean_constrained() {
    let forged = prove(&data(4), Plan::default());
    let run = synthesize(&forged, &[], None);
    let rows = run.compiled.rows_by_column();
    let first = run.compiled.num_instance + forged.proof.len();
    let booleans = run.compiled.boolean_columns();
    for column in first..first + 2 * 2 * 25 * 64 {
        assert_column_is_boolean(&run.compiled, &rows, column);
        assert!(booleans[column]);
    }
    for column in run.compiled.num_instance..first {
        assert!(!booleans[column], "proof element {column} is not Boolean");
    }
}

fn witness_state(cs: ConstraintSystemRef<Fr>, words: &[u64; 25]) -> State<Fr> {
    core::array::from_fn(|lane| {
        core::array::from_fn(|bit| {
            Boolean::new_witness(cs.clone(), || Ok((words[lane] >> bit) & 1 == 1)).unwrap()
        })
    })
}

fn state_at(states: &[u64], instance: usize) -> [u64; 25] {
    core::array::from_fn(|lane| states[instance * 25 + lane])
}

fn f1600(mut words: [u64; 25]) -> [u64; 25] {
    keccak::f1600(&mut words);
    words
}

fn column_of(compiled: &Compiled, bit: &Boolean<Fr>) -> Option<usize> {
    match bit {
        Boolean::Var(bit) => compiled.column(bit.variable()),
        Boolean::Constant(_) => None,
    }
}

/// Output bits allocated by `permute` and caller-owned input bits.
#[test]
fn permute_outputs_and_caller_inputs_are_boolean_constrained() {
    let cs = ConstraintSystem::<Fr>::new_ref();
    let mut batch = KeccacheckBatch::new(cs.clone());
    let states = data(3);
    let mut owned = Vec::new();
    for instance in 0..3 {
        let input = witness_state(cs.clone(), &state_at(&states, instance));
        let output = batch.permute(input.clone()).unwrap();
        owned.push(input);
        owned.push(output);
    }
    batch.finish().unwrap();
    let compiled = Compiled::from_cs(&cs).unwrap();
    assert!(compiled.unsatisfied().is_empty());
    let rows = compiled.rows_by_column();
    let mut seen = 0;
    for state in &owned {
        for bit in state.iter().flatten() {
            assert_column_is_boolean(&compiled, &rows, column_of(&compiled, bit).unwrap());
            seen += 1;
        }
    }
    assert_eq!(seen, 6 * 1600);
}

/// Padding enters the statement as compiled constants: a proof over any other
/// padding state fails.
#[test]
fn padding_states_are_constants_in_the_statement() {
    let states = data(3);
    let padded_states = [states.clone(), vec![0u64; 25]].concat();
    let witness = make_witness_from_data(&padded_states);

    let run_with = |padding_input: [u64; 25], padding_output: [u64; 25], proof: &[Fr]| {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut inputs = Vec::new();
        let mut outputs = Vec::new();
        for instance in 0..3 {
            let words = state_at(&states, instance);
            inputs.push(witness_state(cs.clone(), &words));
            outputs.push(witness_state(cs.clone(), &f1600(words)));
        }
        inputs.push(constant_state(&padding_input));
        outputs.push(constant_state(&padding_output));
        verify_boolean_batch(
            cs.clone(),
            proof,
            &transpose_states(&inputs),
            &transpose_states(&outputs),
        )
        .unwrap();
        Compiled::from_cs(&cs).unwrap().unsatisfied()
    };

    let zero = [0u64; 25];
    assert!(run_with(zero, f1600(zero), &witness.proof).is_empty());

    // A false padding output changes the derived challenges.
    let mut wrong_output = f1600(zero);
    wrong_output[4] ^= 1;
    assert!(!run_with(zero, wrong_output, &witness.proof).is_empty());

    // A genuine permutation of a non-zero padding state fails against the
    // zero-padding statement.
    let mut other = zero;
    other[0] = 1;
    let other_data = [states.clone(), other.to_vec()].concat();
    let other_proof = make_witness_from_data(&other_data).proof;
    assert!(!run_with(zero, f1600(zero), &other_proof).is_empty());
    assert!(run_with(other, f1600(other), &other_proof).is_empty());

    // The production path pads the same way.
    let cs = ConstraintSystem::<Fr>::new_ref();
    let mut batch = KeccacheckBatch::new(cs.clone());
    for instance in 0..3 {
        let _ = batch
            .permute(witness_state(cs.clone(), &state_at(&states, instance)))
            .unwrap();
    }
    let result = batch.finish().unwrap();
    assert_eq!((result.recorded, result.padded), (3, 4));
    assert!(Compiled::from_cs(&cs).unwrap().unsatisfied().is_empty());
}

#[test]
fn batch_order_agrees_across_transpose_derive_and_native() {
    for instances in [4usize, 8] {
        let states = data(instances);
        let witness = make_witness_from_data(&states);
        let cs = ConstraintSystem::<Fr>::new_ref();
        let inputs: Vec<_> = (0..instances)
            .map(|i| witness_state(cs.clone(), &state_at(&states, i)))
            .collect();
        let outputs: Vec<_> = (0..instances)
            .map(|i| witness_state(cs.clone(), &f1600(state_at(&states, i))))
            .collect();
        let bits = |states: &[State<Fr>]| -> Vec<FpVar<Fr>> {
            transpose_states(states)
                .into_iter()
                .map(FpVar::from)
                .collect()
        };
        let log = instances.ilog2() as usize;
        let derived = derive_r_var(&bits(&inputs), &bits(&outputs), log);
        let native = derive_r_native(&witness.input, &witness.output, log);
        assert_eq!(derived.len(), native.len());
        for (var, value) in derived.iter().zip(&native) {
            assert_eq!(to_fr05(var.value().unwrap()), *value);
        }

        // Bit positions: lane, then instance, then little-endian bit.
        let flat = transpose_states(&inputs);
        for lane in 0..25 {
            for instance in 0..instances {
                let word = witness.input[lane * instances + instance];
                for bit in 0..64 {
                    let at = (lane * instances + instance) * 64 + bit;
                    assert_eq!(flat[at].value().unwrap(), (word >> bit) & 1 == 1);
                }
            }
        }

        // Swapping two instances changes the challenge.
        let mut swapped = inputs.clone();
        swapped.swap(0, 1);
        let other = derive_r_var(&bits(&swapped), &bits(&outputs), log);
        assert_ne!(other[0].value().unwrap(), derived[0].value().unwrap());
    }
}

fn run_batch(
    cs: ConstraintSystemRef<Fr>,
    count: usize,
    states: &[u64],
) -> crate::batch::BatchResult {
    let mut batch = KeccacheckBatch::new(cs.clone());
    let witness_free = cs.is_in_setup_mode();
    for instance in 0..count {
        let words = state_at(states, instance);
        let state: State<Fr> = core::array::from_fn(|lane| {
            core::array::from_fn(|bit| {
                Boolean::new_witness(cs.clone(), || {
                    assert!(!witness_free, "setup evaluated a witness");
                    Ok((words[lane] >> bit) & 1 == 1)
                })
                .unwrap()
            })
        });
        let _ = batch.permute(state).unwrap();
    }
    batch.finish().unwrap()
}

/// Setup with no witness and prove with one compile to the same matrices.
fn assert_setup_matches_prove(count: usize) {
    let states = data(count);
    let setup_cs = ConstraintSystem::<Fr>::new_ref();
    setup_cs.set_mode(SynthesisMode::Setup);
    let setup_result = run_batch(setup_cs.clone(), count, &states);
    let prove_cs = ConstraintSystem::<Fr>::new_ref();
    let prove_result = run_batch(prove_cs.clone(), count, &states);
    assert_eq!(setup_result.padded, prove_result.padded);
    assert_eq!(setup_result.profile.total, prove_result.profile.total);
    assert_eq!(
        setup_cs.num_witness_variables(),
        prove_cs.num_witness_variables()
    );
    let (setup, prove) = (
        Compiled::from_cs(&setup_cs).unwrap(),
        Compiled::from_cs(&prove_cs).unwrap(),
    );
    assert!(
        setup.z.is_empty() || setup.z.len() == 1,
        "setup holds no witness"
    );
    assert!(setup.a == prove.a, "A differs at {count}");
    assert!(setup.b == prove.b, "B differs at {count}");
    assert!(setup.c == prove.c, "C differs at {count}");
    assert!(prove.unsatisfied().is_empty());
}

#[test]
fn setup_and_prove_compile_identical_matrices() {
    for count in [1, 2, 3, 4, 5, 8] {
        assert_setup_matches_prove(count);
    }
}

/// One output bit edit must fail, at this recorded count and padded size.
fn assert_batch_edge(count: usize) {
    let states = data(count);
    let cs = ConstraintSystem::<Fr>::new_ref();
    let mut batch = KeccacheckBatch::new(cs.clone());
    let mut last_output = None;
    for instance in 0..count {
        let state = witness_state(cs.clone(), &state_at(&states, instance));
        last_output = Some(batch.permute(state).unwrap());
    }
    let result = batch.finish().unwrap();
    assert_eq!(result.recorded, count);
    assert_eq!(result.padded, count.next_power_of_two().max(MIN_INSTANCES));
    let log = result.padded.ilog2() as usize;
    assert_eq!(result.profile.checks.len(), 3 + 24 * 7 + 25, "{count}");
    let compiled = Compiled::from_cs(&cs).unwrap();
    assert_eq!(
        compiled.unsatisfied(),
        Vec::<usize>::new(),
        "{count} -> {log}"
    );
    let column = column_of(&compiled, &last_output.unwrap()[24][63]).unwrap();
    let mut z = compiled.z.clone();
    z[column] = Fr::one() - z[column];
    assert!(!compiled.unsatisfied_under(&z).is_empty());
}

#[test]
fn batch_sizes_up_to_thirty_two() {
    for count in [1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32] {
        assert_batch_edge(count);
    }
}

#[test]
#[ignore = "large: run with --ignored in release"]
fn batch_sizes_up_to_production() {
    for count in [33, 63, 64, 65, 127, 128, 129, 232, 255, 256] {
        assert_batch_edge(count);
    }
}

#[test]
#[ignore = "large: run with --ignored in release"]
fn setup_and_prove_match_at_production_size() {
    assert_setup_matches_prove(232);
    assert_setup_matches_prove(256);
}

#[test]
#[ignore = "large: run with --ignored in release"]
fn production_batch_soundness() {
    let instances = 256;
    let states = data(instances);
    let honest = prove(&states, Plan::default());
    assert_eq!(honest.proof, make_witness_from_data(&states).proof);
    assert_eq!(upstream(&honest), Upstream::Accepts);
    assert_eq!(
        synthesize(&honest, &[], None).failures(),
        Vec::<String>::new()
    );
    for lie in [
        Break::OutputBits,
        Break::Round {
            round: 12,
            layer: Layer::Chi,
        },
        Break::InputLane { lane: 17 },
    ] {
        assert_check_is_necessary(instances, lie, 200);
    }
}

// ---- 4. gadget lowering, on matrices and not on cached values ----

/// Every cached linear-combination value equals its inlined expression.
#[test]
fn inlining_preserves_every_linear_combination() {
    let forged = prove(&data(4), Plan::default());
    let witness = Witness {
        proof: forged.proof.clone(),
        input: forged.input.clone(),
        output: forged.output.clone(),
    };
    let cs = ConstraintSystem::<Fr>::new_ref();
    verify_witness_profile(cs.clone(), &witness).unwrap();
    let (rows_before, witnesses_before) = (cs.num_constraints(), cs.num_witness_variables());
    let cached = cs.borrow().unwrap().assignments.lc_assignment.clone();
    assert!(cached.len() > 100_000, "{} cached", cached.len());
    let compiled = Compiled::from_cs(&cs).unwrap();
    assert_eq!(cs.num_constraints(), rows_before);
    assert_eq!(cs.num_witness_variables(), witnesses_before);
    let inner = cs.borrow().unwrap();
    for (index, value) in cached.iter().enumerate() {
        let evaluated: Fr = inner
            .get_lc(Variable::symbolic_lc(index))
            .0
            .iter()
            .filter(|(_, variable)| !variable.is_zero())
            .map(|(coeff, variable)| {
                assert!(!variable.is_lc(), "LC {index} is not fully inlined");
                let column = variable.get_variable_index(compiled.num_instance).unwrap();
                *coeff * compiled.z[column]
            })
            .sum();
        assert_eq!(evaluated, *value, "LC {index}");
    }
}

/// Every intermediate variable is a function of the proof and the statement.
#[test]
fn proof_and_statement_determine_every_witness() {
    for instances in [4usize] {
        let forged = prove(&data(instances), Plan::default());
        let run = synthesize(&forged, &[], None);
        let first = run.compiled.num_instance;
        let free: Vec<usize> =
            (first..first + forged.proof.len() + 2 * instances * 25 * 64).collect();
        assert_eq!(run.compiled.undetermined(&free), Vec::<usize>::new());
        // Nothing is free but what the prover legitimately chooses.
        let by_column = run.compiled.rows_by_column();
        for column in free {
            assert!(!by_column[column].is_empty(), "column {column} is unused");
        }
    }
}

/// Stale cached values hide an edit from `is_satisfied`, not from the matrices.
#[test]
fn matrix_evaluation_sees_what_the_cache_hides() {
    let cs = ConstraintSystem::<Fr>::new_ref();
    let x = FpVar::new_witness(cs.clone(), || Ok(Fr::from(3u64))).unwrap();
    let y = &x + &x;
    let bound = FpVar::new_witness(cs.clone(), || Ok(Fr::from(6u64))).unwrap();
    y.enforce_equal(&bound).unwrap();
    assert!(cs.is_satisfied().unwrap());
    let compiled = Compiled::from_cs(&cs).unwrap();
    let column = compiled
        .column(match &x {
            FpVar::Var(v) => v.variable,
            _ => unreachable!(),
        })
        .unwrap();
    cs.borrow_mut().unwrap().assignments.witness_assignment[column - compiled.num_instance] =
        Fr::from(4u64);
    let edited = Compiled::from_cs(&cs).unwrap();
    assert_eq!(edited.unsatisfied(), vec![0]);
}

fn fresh(cs: &ConstraintSystemRef<Fr>, value: Fr) -> FpVar<Fr> {
    FpVar::new_witness(cs.clone(), || Ok(value)).unwrap()
}

/// `build` lowers to `expected`: the bound row holds at it and only at it.
fn assert_lowers_to(expected: Fr, build: impl FnOnce(&ConstraintSystemRef<Fr>) -> FpVar<Fr>) {
    let cs = ConstraintSystem::<Fr>::new_ref();
    let result = build(&cs);
    if let Ok(value) = result.value() {
        assert_eq!(value, expected, "cached value");
    }
    let bound = fresh(&cs, expected);
    let before = cs.num_constraints();
    result.enforce_equal(&bound).unwrap();
    assert_eq!(cs.num_constraints(), before + 1);
    let compiled = Compiled::from_cs(&cs).unwrap();
    assert_eq!(compiled.unsatisfied(), Vec::<usize>::new());
    let column = match &bound {
        FpVar::Var(v) => compiled.column(v.variable).unwrap(),
        _ => unreachable!(),
    };
    let mut z = compiled.z.clone();
    z[column] += Fr::one();
    assert_eq!(compiled.unsatisfied_under(&z), vec![before]);
}

#[test]
fn constant_folding_preserves_field_operations() {
    let mut rng = ark_std::test_rng();
    let half = Fr::from(2u64).inverse().unwrap();
    let specials = [Fr::zero(), Fr::one(), -Fr::one(), Fr::from(2u64), half];
    let randoms: Vec<Fr> = (0..4).map(|_| Fr::rand(&mut rng)).collect();
    for x in specials.iter().chain(&randoms) {
        for y in specials.iter().chain(&randoms) {
            let (x, y) = (*x, *y);
            type Make = fn(&ConstraintSystemRef<Fr>, Fr) -> FpVar<Fr>;
            let var: Make = fresh;
            let con: Make = |_, value| FpVar::Constant(value);
            for (make_x, make_y) in [(var, var), (var, con), (con, var), (con, con)] {
                assert_lowers_to(x + y, |cs| make_x(cs, x) + make_y(cs, y));
                assert_lowers_to(x - y, |cs| make_x(cs, x) - make_y(cs, y));
                assert_lowers_to(x * y, |cs| make_x(cs, x) * make_y(cs, y));
                assert_lowers_to(-x, |cs| make_x(cs, x).negate().unwrap());
                assert_lowers_to(x + x, |cs| {
                    let v = make_x(cs, x);
                    &v + &v
                });
                assert_lowers_to(x * y + x, |cs| {
                    let (a, b) = (make_x(cs, x), make_y(cs, y));
                    &a * &b + &a
                });
                assert_lowers_to(Fr::one() - x - x, |cs| {
                    let a = make_x(cs, x);
                    FpVar::Constant(Fr::one()) - &a - &a
                });
            }
            assert_lowers_to(x * y, |cs| fresh(cs, x) * y);
            assert_lowers_to(x + y, |cs| {
                let mut v = fresh(cs, x);
                v += y;
                v
            });
            assert_lowers_to(x * y, |cs| {
                let mut v = fresh(cs, x);
                v *= &FpVar::Constant(y);
                v
            });
        }
    }
}

#[test]
fn boolean_conversion_preserves_the_bit() {
    for value in [false, true] {
        let expected = Fr::from(value as u64);
        assert_lowers_to(expected, |_| FpVar::from(Boolean::constant(value)));
        assert_lowers_to(expected, |cs| {
            FpVar::from(Boolean::new_witness(cs.clone(), || Ok(value)).unwrap())
        });
        assert_lowers_to(Fr::one() - expected, |cs| {
            FpVar::from(!Boolean::new_witness(cs.clone(), || Ok(value)).unwrap())
        });
        assert_lowers_to(expected * Fr::from(1u64 << 40), |cs| {
            let bit = FpVar::from(Boolean::new_witness(cs.clone(), || Ok(value)).unwrap());
            &bit * Fr::from(1u64 << 40)
        });
    }
}

/// Flat `.sum()` and a running fold are one relation over the same columns,
/// including repeated variables, cancelling terms, and pure constants.
#[test]
fn flat_sum_matches_a_fold() {
    let mut rng = ark_std::test_rng();
    for case in 0..40usize {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let pool: Vec<FpVar<Fr>> = (0..6)
            .map(|i| {
                let value = Fr::rand(&mut rng);
                match (case + i) % 3 {
                    0 => fresh(&cs, value),
                    1 => FpVar::Constant(value),
                    _ => fresh(&cs, value) * Fr::from(i as u64 + 2),
                }
            })
            .collect();
        let mut terms: Vec<FpVar<Fr>> = (0..case + 1)
            .map(|i| pool[(i * 5 + case) % 6].clone())
            .collect();
        terms.push(pool[0].clone());
        terms.push(pool[0].negate().unwrap());
        terms.push(FpVar::Constant(Fr::zero()));
        terms.push(&pool[1] * Fr::zero());

        let flat: FpVar<Fr> = terms.iter().cloned().sum();
        let by_ref: FpVar<Fr> = terms.iter().sum();
        let folded = terms
            .iter()
            .fold(FpVar::Constant(Fr::zero()), |acc, term| acc + term);
        let expected = folded.value().unwrap();
        assert_eq!(flat.value().unwrap(), expected);
        assert_eq!(by_ref.value().unwrap(), expected);

        // Bind all three; the matrices must hold them equal as linear forms.
        let bound = fresh(&cs, expected);
        for value in [&flat, &by_ref, &folded] {
            value.enforce_equal(&bound).unwrap();
        }
        let compiled = Compiled::from_cs(&cs).unwrap();
        assert_eq!(compiled.unsatisfied(), Vec::<usize>::new());
        let last = compiled.num_rows() - 3..compiled.num_rows();
        let form = |row: usize| {
            let mut entries = compiled.a[row].clone();
            entries.sort_by_key(|(_, col)| *col);
            entries
        };
        assert_eq!(form(last.start), form(last.start + 1), "case {case}");
        assert_eq!(form(last.start), form(last.start + 2), "case {case}");
    }
}

/// The two flat sums in the verifier: words from bits, MLE from an eq table.
#[test]
fn verifier_sums_lower_correctly() {
    let mut rng = ark_std::test_rng();
    // All-ones words reach the largest value and must not wrap.
    for word in [0u64, 1, u64::MAX, 0x8000_0000_0000_0001] {
        let expected = Fr::from(word);
        assert_lowers_to(expected, |cs| {
            (0..64)
                .map(|bit| {
                    let value = (word >> bit) & 1 == 1;
                    FpVar::from(Boolean::new_witness(cs.clone(), || Ok(value)).unwrap())
                        * Fr::from(1u64 << bit)
                })
                .sum()
        });
    }
    // Mixed constant and witness tables, as padded batches produce.
    for vars in 1..4 {
        let r: Vec<Fr> = (0..vars).map(|_| Fr::rand(&mut rng)).collect();
        let table: Vec<Fr> = (0..1usize << vars)
            .map(|i| Fr::from(i as u64 % 2))
            .collect();
        let expected: Fr = {
            let mut folded = table.clone();
            for ri in &r {
                let half = folded.len() / 2;
                folded = (0..half)
                    .map(|j| folded[j] + *ri * (folded[half + j] - folded[j]))
                    .collect();
            }
            folded[0]
        };
        assert_lowers_to(expected, |cs| {
            let r: Vec<_> = r.iter().map(|value| fresh(cs, *value)).collect();
            let mle: Vec<_> = table
                .iter()
                .enumerate()
                .map(|(i, value)| {
                    if i % 2 == 0 {
                        FpVar::Constant(*value)
                    } else {
                        fresh(cs, *value)
                    }
                })
                .collect();
            eval_mle_with_eq(&mle, &eval_eq(&r))
        });
    }
}

/// Statement packing is injective: the top of a chunk reaches 2^192 - 1.
#[test]
fn statement_packing_does_not_wrap() {
    let log = 2;
    let high = vec![u64::MAX; 100];
    let mut other = high.clone();
    other[0] ^= 1;
    assert_ne!(
        derive_r_native(&high, &high, log),
        derive_r_native(&other, &high, log)
    );
    let bits = |words: &[u64]| -> Vec<FpVar<Fr>> {
        words
            .iter()
            .flat_map(|word| (0..64).map(move |bit| FpVar::Constant(Fr::from((word >> bit) & 1))))
            .collect()
    };
    let derived = derive_r_var(&bits(&high), &bits(&high), log);
    assert_eq!(
        to_fr05(derived[0].value().unwrap()),
        derive_r_native(&high, &high, log)[0]
    );
    // Word-boundary edits are distinct across every position in a chunk.
    let mut seen = std::collections::HashSet::new();
    for word in 0..6 {
        for bit in [0, 63] {
            let mut edited = high.clone();
            edited[word] ^= 1 << bit;
            assert!(seen.insert(derive_r_native(&edited, &high, log)[0].to_string()));
        }
    }
}

/// The R1CS rejects a statement bit set to a value that packs to the same word.
#[test]
fn non_boolean_bits_cannot_mimic_a_word() {
    let forged = prove(&data(4), Plan::default());
    let run = synthesize(&forged, &[], None);
    let first = run.compiled.num_instance + forged.proof.len();
    let mut z = run.compiled.z.clone();
    let (low, high) = (first, first + 1);
    // Two low bits (b0, b1) with b0 + 2 b1 unchanged.
    let total = z[low] + z[high] + z[high];
    z[high] += Fr::one();
    z[low] = total - z[high] - z[high];
    let failing = run.compiled.unsatisfied_under(&z);
    assert!(
        failing.iter().any(|row| run.compiled.a[*row]
            .iter()
            .any(|(_, col)| *col == low || *col == high)),
        "non-Boolean decomposition accepted"
    );
}

// ---- R1CS against 01-spec.md ----

/// The circuit's residual for each named check equals the spec model's.
fn assert_residuals_match_spec(forged: &Forged) {
    let run = synthesize(forged, &[], None);
    let model = spec_model::residuals(&forged.input, &forged.output, &forged.proof_05);
    assert_eq!(run.checks.len(), model.len());
    let unsatisfied = run.compiled.unsatisfied();
    for (check, (label, expected)) in run.checks.iter().zip(&model) {
        assert_eq!(&check.label, label);
        let residual = run.compiled.residual_at(check.rows.start, &run.compiled.z);
        assert_eq!(to_fr05(residual), *expected, "{label}");
        assert_eq!(
            unsatisfied.contains(&check.rows.start),
            !expected.is_zero(),
            "{label}"
        );
    }
    // Nothing fails but named checks on these all-Boolean statements.
    assert_eq!(
        unsatisfied.len(),
        model.iter().filter(|(_, r)| !r.is_zero()).count()
    );
}

fn random_words(count: usize, seed: u64) -> Vec<u64> {
    let mut x = seed;
    (0..count)
        .map(|_| {
            x = x
                .wrapping_mul(0x5851_f42d_4c95_7f2d)
                .wrapping_add(0x1405_7b7e_f767_814f);
            x ^ (x >> 29)
        })
        .collect()
}

fn random_forged(instances: usize, statement: Option<(Vec<u64>, Vec<u64>)>) -> Forged {
    let mut rng = ark_std::test_rng();
    let proof: Vec<Fr> = (0..proof_elements(instances))
        .map(|_| Fr::rand(&mut rng))
        .collect();
    let (input, output) = statement.unwrap_or_else(|| {
        (
            random_words(25 * instances, 7),
            random_words(25 * instances, 11),
        )
    });
    Forged {
        proof_05: proof.iter().copied().map(to_fr05).collect(),
        proof,
        input,
        output,
        r: vec![],
        rebase: None,
    }
}

#[test]
fn r1cs_equals_spec_on_honest_and_cheating_transcripts() {
    for instances in [4] {
        assert_residuals_match_spec(&prove(&data(instances), Plan::default()));
    }
    for lie in [
        Break::OutputSum,
        Break::OutputWords,
        Break::OutputBits,
        Break::Round {
            round: 23,
            layer: Layer::Iota,
        },
        Break::Round {
            round: 11,
            layer: Layer::Rho,
        },
        Break::Round {
            round: 0,
            layer: Layer::ThetaC,
        },
        Break::InputLane { lane: 3 },
    ] {
        assert_residuals_match_spec(&prove(
            &data(4),
            Plan {
                lie: Some(lie),
                seed: 3,
                ..Plan::default()
            },
        ));
    }
}

/// Uniform proofs make every check fail with an unrelated value, so equality
/// of all 196 residuals compares the two functions at random points.
#[test]
fn r1cs_equals_spec_at_random_points() {
    for instances in [4, 8] {
        assert_residuals_match_spec(&random_forged(instances, None));
    }
    for (input, output) in [
        (vec![0u64; 100], vec![0u64; 100]),
        (vec![u64::MAX; 100], vec![u64::MAX; 100]),
        (vec![0u64; 100], vec![u64::MAX; 100]),
    ] {
        assert_residuals_match_spec(&random_forged(4, Some((input, output))));
    }
}

#[test]
#[ignore = "large: run with --ignored in release"]
fn r1cs_equals_spec_at_production_size() {
    assert_residuals_match_spec(&prove(&data(256), Plan::default()));
    assert_residuals_match_spec(&random_forged(256, None));
}

/// The relation checks exactly the 196 named equalities and Booleanity. Each
/// other row only defines a fresh column from columns already known.
#[test]
fn the_only_restricting_rows_are_named_checks_and_booleanity() {
    for instances in [4] {
        assert_only_named_checks_and_booleanity_restrict(instances);
    }
}

#[test]
#[ignore = "large: run with --ignored in release"]
fn the_only_restricting_rows_at_production_size() {
    assert_only_named_checks_and_booleanity_restrict(256);
}

fn assert_only_named_checks_and_booleanity_restrict(instances: usize) {
    let forged = prove(&data(instances), Plan::default());
    let run = synthesize(&forged, &[], None);
    let first = run.compiled.num_instance;
    let proof_end = first + forged.proof.len();
    let free_end = proof_end + 2 * instances * 25 * 64;
    let free: Vec<usize> = (first..free_end).collect();
    assert_eq!(run.compiled.undetermined(&free), Vec::<usize>::new());
    let defining = run.compiled.defining_rows(&free);
    let named: std::collections::HashSet<usize> =
        run.checks.iter().map(|check| check.rows.start).collect();
    let mut booleanity = 0;
    for row in (0..run.compiled.num_rows()).filter(|row| !defining[*row] && !named.contains(row)) {
        let columns: Vec<usize> = [
            &run.compiled.a[row],
            &run.compiled.b[row],
            &run.compiled.c[row],
        ]
        .iter()
        .flat_map(|entries| entries.iter().map(|(_, col)| *col))
        .filter(|col| *col != 0)
        .collect();
        assert!(
            !columns.is_empty() && columns.iter().all(|col| *col == columns[0]),
            "row {row} restricts {columns:?}"
        );
        assert!((proof_end..free_end).contains(&columns[0]));
        booleanity += 1;
    }
    assert_eq!(booleanity, 2 * instances * 25 * 64);
    assert_eq!(named.len(), 3 + 24 * 7 + 25);
}

/// Output bits enter only through their recomposed word, so a non-Boolean
/// decomposition of one word fails the two Booleanity rows and nothing else.
#[test]
fn booleanity_alone_stops_a_non_boolean_output_decomposition() {
    let forged = prove(&data(4), Plan::default());
    let run = synthesize(&forged, &[], None);
    let input_bits = 4 * 25 * 64;
    let first = run.compiled.num_instance + forged.proof.len() + input_bits;
    let (low, high) = (first, first + 1);
    let mut z = run.compiled.z.clone();
    z[low] += Fr::from(2u64);
    z[high] -= Fr::one();
    let failing = run.compiled.unsatisfied_under(&z);
    assert_eq!(failing.len(), 2, "{failing:?}");
    for row in failing {
        assert!(!run.checks.iter().any(|check| check.rows.contains(&row)));
        let columns: Vec<usize> = run.compiled.a[row]
            .iter()
            .chain(&run.compiled.b[row])
            .map(|(_, col)| *col)
            .filter(|col| *col != 0)
            .collect();
        assert!(columns.iter().all(|col| *col == low || *col == high));
    }
}
