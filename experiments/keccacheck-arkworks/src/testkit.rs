//! Test-only verifier hooks and a cheating Keccacheck prover.
//!
//! The prover recomputes the Fiat-Shamir transcript honestly over the claimed
//! statement. A lie is a break in the layered trace: every layer above the break
//! is consistent with the false claim and every layer below it is genuine, so
//! exactly one check sees an inconsistency.

use crate::verifier::derive_r_native;
use ark_bn254::Fr;
use ark_bn254_05::Fr as Fr05;
use ark_ff::{BigInt, PrimeField};
use ark_ff_05::{Field, One, PrimeField as PrimeField05, Zero};
use gkr::{
    reference::{PI, RHO_OFFSETS, ROUND_CONSTANTS},
    sumcheck::util::{
        HALF, add_col, calculate_evaluations_over_boolean_hypercube_for_eq as eq_table,
        derive_rot_evaluations_from_eq, eval_mle, to_field_vec, to_poly, to_poly_xor_base, xor,
    },
    transcript::Prover,
};

/// Verifier hooks. These exist only in test builds of this crate.
pub mod hooks {
    use ark_bn254::Fr;
    use std::cell::{Cell, RefCell};

    thread_local! {
        static REMOVED: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
        static REBASE: Cell<Option<(usize, usize, Fr)>> = const { Cell::new(None) };
        static SUMCHECK: Cell<usize> = const { Cell::new(0) };
    }

    pub fn check_removed(label: &str) -> bool {
        REMOVED.with(|removed| removed.borrow().iter().any(|entry| entry == label))
    }

    pub fn reset_sumchecks() {
        SUMCHECK.set(0);
    }

    pub fn next_sumcheck() -> usize {
        let index = SUMCHECK.get();
        SUMCHECK.set(index + 1);
        index
    }

    /// The free claim replacing the chained one at `(sumcheck, round)`, if any.
    pub fn rebased_claim(sumcheck: usize, round: usize) -> Option<Fr> {
        REBASE
            .get()
            .and_then(|(s, r, value)| (s == sumcheck && r == round).then_some(value))
    }

    /// Runs `body` with `labels` removed and one round relation dropped.
    pub fn with<T>(
        labels: &[String],
        rebase: Option<(usize, usize, Fr)>,
        body: impl FnOnce() -> T,
    ) -> T {
        REMOVED.with(|removed| *removed.borrow_mut() = labels.to_vec());
        REBASE.set(rebase);
        let out = body();
        REMOVED.with(|removed| removed.borrow_mut().clear());
        REBASE.set(None);
        out
    }
}

/// The checks of one Keccak round, in verification order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer {
    Iota,
    Chi,
    Rho,
    Theta,
    ThetaD,
    ThetaC,
    ThetaA,
}

impl Layer {
    pub const ALL: [Layer; 7] = [
        Layer::Iota,
        Layer::Chi,
        Layer::Rho,
        Layer::Theta,
        Layer::ThetaD,
        Layer::ThetaC,
        Layer::ThetaA,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Layer::Iota => "iota",
            Layer::Chi => "chi",
            Layer::Rho => "rho",
            Layer::Theta => "theta",
            Layer::ThetaD => "theta_d",
            Layer::ThetaC => "theta_c",
            Layer::ThetaA => "theta_a",
        }
    }

    fn position(self) -> usize {
        Self::ALL.iter().position(|layer| *layer == self).unwrap()
    }

    /// Lanes in the table the break edits.
    fn lanes(self) -> usize {
        match self {
            Layer::ThetaD | Layer::ThetaC => 5,
            _ => 25,
        }
    }
}

/// A single-bit difference in a lane-major table.
#[derive(Clone, Copy, Debug)]
pub struct Flip {
    pub lane: usize,
    pub instance: usize,
    pub bit: usize,
}

impl Flip {
    /// A flip varied by `seed` across lanes, instances, and bits.
    pub fn from_seed(seed: usize, lanes: usize, instances: usize) -> Self {
        Self {
            lane: (seed * 7 + 3) % lanes,
            instance: (seed * 3 + 1) % instances,
            bit: (seed * 11 + 5) % 64,
        }
    }

    fn apply(&self, table: &mut [u64], instances: usize) {
        table[self.lane * instances + self.instance] ^= 1 << self.bit;
    }
}

/// Where the trace is inconsistent.
#[derive(Clone, Copy, Debug)]
pub enum Break {
    OutputSum,
    OutputWords,
    OutputBits,
    Round { round: usize, layer: Layer },
    InputLane { lane: usize },
}

impl Break {
    /// The named check that sees this break.
    pub fn label(&self) -> String {
        match self {
            Break::OutputSum => "output sum".into(),
            Break::OutputWords => "output word reduction".into(),
            Break::OutputBits => "output bit reduction".into(),
            Break::Round { round, layer } => format!("round {round}: {}", layer.name()),
            Break::InputLane { lane } => format!("input lane {lane}"),
        }
    }

    /// The line of `gkr::keccacheck_og::verifier` whose assert sees this break.
    pub fn upstream_line(&self) -> u32 {
        match self {
            Break::OutputSum => 28,
            Break::OutputWords => 38,
            Break::OutputBits => 46,
            Break::Round { layer, .. } => match layer {
                Layer::Iota => 107,
                Layer::Chi => 126,
                Layer::Rho => 146,
                Layer::Theta => 166,
                Layer::ThetaD => 186,
                Layer::ThetaC => 216,
                Layer::ThetaA => 244,
            },
            Break::InputLane { .. } => 80,
        }
    }
}

/// Sumcheck index in verification order, matching `hooks::next_sumcheck`.
pub fn sumcheck_index(round: usize, layer: Layer) -> usize {
    2 + (23 - round) * 7 + layer.position()
}

/// What the prover does differently from an honest one.
#[derive(Clone, Copy, Debug, Default)]
pub struct Plan {
    pub lie: Option<Break>,
    pub seed: usize,
    /// Add one to the first sent coefficient at `(sumcheck, round)`.
    pub tamper: Option<(usize, usize)>,
    /// Restart the claim from the genuine polynomial at `(sumcheck, round)`.
    pub rebase: Option<(usize, usize)>,
}

pub struct Forged {
    pub proof: Vec<Fr>,
    pub proof_05: Vec<Fr05>,
    pub input: Vec<u64>,
    pub output: Vec<u64>,
    pub r: Vec<Fr05>,
    pub rebase: Option<(usize, usize, Fr)>,
}

impl Forged {
    /// Whether the claimed statement is false Keccak-f for some instance.
    pub fn statement_is_false(&self) -> bool {
        let instances = self.input.len() / 25;
        (0..instances).any(|instance| {
            let mut state: [u64; 25] =
                core::array::from_fn(|lane| self.input[lane * instances + instance]);
            keccak::f1600(&mut state);
            (0..25).any(|lane| state[lane] != self.output[lane * instances + instance])
        })
    }
}

pub fn to_fr(value: Fr05) -> Fr {
    Fr::from_bigint(BigInt(value.into_bigint().0)).unwrap()
}

pub fn to_fr05(value: Fr) -> Fr05 {
    Fr05::from_bigint(ark_ff_05::BigInt(value.into_bigint().0)).unwrap()
}

/// One round's tables, each the input of the sumcheck named after it.
struct RoundTrace {
    chi: Vec<u64>,
    pi: Vec<u64>,
    theta: Vec<u64>,
    d: Vec<u64>,
    a_theta: Vec<u64>,
    c: Vec<u64>,
    rot_c: Vec<u64>,
    a_c: Vec<u64>,
    a_a: Vec<u64>,
}

fn round_trace(a: &[u64], round: usize, flip: Option<(Layer, Flip)>) -> (RoundTrace, Vec<u64>) {
    let instances = a.len() / 25;
    let edit = |layer: Layer, table: &mut Vec<u64>| {
        if let Some((at, flip)) = flip
            && at == layer
        {
            flip.apply(table, instances);
        }
    };

    let a_a = a.to_vec();
    let mut a_up = a.to_vec();
    edit(Layer::ThetaA, &mut a_up);

    let mut c = vec![0u64; 5 * instances];
    for i in 0..instances {
        for x in 0..5 {
            for y in 0..5 {
                c[x * instances + i] ^= a_up[(y * 5 + x) * instances + i];
            }
        }
    }
    edit(Layer::ThetaC, &mut c);
    let rot_c: Vec<u64> = c.iter().map(|word| word.rotate_left(1)).collect();

    let mut d = vec![0u64; 5 * instances];
    for i in 0..instances {
        for x in 0..5 {
            d[x * instances + i] =
                c[((x + 4) % 5) * instances + i] ^ rot_c[((x + 1) % 5) * instances + i];
        }
    }
    edit(Layer::ThetaD, &mut d);

    let mut theta = a_up.clone();
    for i in 0..instances {
        for x in 0..5 {
            for y in 0..5 {
                theta[(y * 5 + x) * instances + i] ^= d[x * instances + i];
            }
        }
    }
    edit(Layer::Theta, &mut theta);

    let mut rho = theta.clone();
    for lane in 0..25 {
        for i in 0..instances {
            rho[lane * instances + i] = theta[lane * instances + i].rotate_left(RHO_OFFSETS[lane]);
        }
    }
    let mut pi = rho.clone();
    let mut source = 1usize;
    for target in PI {
        pi[target * instances..(target + 1) * instances]
            .copy_from_slice(&rho[source * instances..(source + 1) * instances]);
        source = target;
    }
    edit(Layer::Rho, &mut pi);

    let mut chi = pi.clone();
    for i in 0..instances {
        for y in 0..5 {
            for x in 0..5 {
                let at = |x: usize| pi[(y * 5 + x % 5) * instances + i];
                chi[(y * 5 + x) * instances + i] = at(x) ^ (!at(x + 1) & at(x + 2));
            }
        }
    }
    edit(Layer::Chi, &mut chi);

    let mut iota = chi.clone();
    for word in &mut iota[..instances] {
        *word ^= ROUND_CONSTANTS[round];
    }
    edit(Layer::Iota, &mut iota);

    (
        RoundTrace {
            chi,
            pi,
            theta,
            d,
            a_theta: a_up.clone(),
            c,
            rot_c,
            a_c: a_up,
            a_a,
        },
        iota,
    )
}

fn strip_pi(pi: &[Fr05]) -> Vec<Fr05> {
    let mut rho = pi.to_vec();
    let mut last = 1usize;
    for target in PI {
        rho[last] = pi[target];
        last = target;
    }
    rho
}

fn lanes_of(table: &[u64], instances: usize, f: fn(&[u64]) -> Vec<Fr05>) -> Vec<Vec<Fr05>> {
    table.chunks_exact(instances).map(f).collect()
}

/// `sum_i weights[i] * tables[i]`.
fn combine(weights: &[Fr05], tables: &[&Vec<Fr05>]) -> Vec<Fr05> {
    let mut out = vec![Fr05::zero(); tables[0].len()];
    for (weight, table) in weights.iter().zip(tables) {
        for (slot, value) in out.iter_mut().zip(table.iter()) {
            *slot += *weight * *value;
        }
    }
    out
}

/// Coefficients of the degree-`d` polynomial through `(k, evals[k])`.
fn interpolate(evals: &[Fr05]) -> Vec<Fr05> {
    let n = evals.len();
    let mut out = vec![Fr05::zero(); n];
    for (i, value) in evals.iter().enumerate() {
        let mut basis = vec![Fr05::zero(); n];
        basis[0] = Fr05::one();
        let mut denom = Fr05::one();
        let mut degree = 0;
        for j in (0..n).filter(|j| *j != i) {
            let node = Fr05::from(j as u64);
            for k in (0..=degree).rev() {
                let shifted = basis[k];
                basis[k + 1] += shifted;
                basis[k] = -shifted * node;
            }
            degree += 1;
            denom *= Fr05::from(i as u64) - node;
        }
        let scale = *value * denom.inverse().unwrap();
        for (slot, b) in out.iter_mut().zip(&basis) {
            *slot += scale * *b;
        }
    }
    out
}

struct Cheater {
    transcript: Prover,
    plan: Plan,
    sumcheck: usize,
    rebase_value: Option<(usize, usize, Fr)>,
}

impl Cheater {
    fn write_all(&mut self, values: &[Fr05]) {
        for value in values {
            self.transcript.write(*value);
        }
    }

    fn squeeze(&mut self, count: usize) -> Vec<Fr05> {
        (0..count).map(|_| self.transcript.read()).collect()
    }

    /// Proves the sum of `f` over the hypercube, whatever the running claim is.
    ///
    /// The verifier derives each round's constant term from its running claim,
    /// so this tracks the claim it computes. Returns that final claim, the
    /// challenges, and the tables evaluated at the challenges.
    fn sumcheck(
        &mut self,
        degree: usize,
        mut tables: Vec<Vec<Fr05>>,
        f: impl Fn(&[Fr05]) -> Fr05,
        mut claim: Fr05,
    ) -> (Fr05, Vec<Fr05>, Vec<Fr05>) {
        let index = self.sumcheck;
        self.sumcheck += 1;
        let vars = tables[0].len().ilog2() as usize;
        let mut challenges = Vec::with_capacity(vars);
        let mut point = vec![Fr05::zero(); tables.len()];
        for round in 0..vars {
            let half = tables[0].len() / 2;
            let mut evals = vec![Fr05::zero(); degree + 1];
            for x in 0..half {
                for (slot, table) in point.iter_mut().zip(&tables) {
                    *slot = table[x];
                }
                evals[0] += f(&point);
                for eval in evals.iter_mut().skip(1) {
                    for (slot, table) in point.iter_mut().zip(&tables) {
                        *slot += table[half + x] - table[x];
                    }
                    *eval += f(&point);
                }
            }
            let coeffs = interpolate(&evals);
            if self.plan.rebase == Some((index, round)) {
                claim = evals[0] + evals[1];
                self.rebase_value = Some((index, round, to_fr(claim)));
            }
            let mut sent = coeffs[1..].to_vec();
            if self.plan.tamper == Some((index, round)) {
                sent[0] += Fr05::one();
            }
            self.write_all(&sent);
            let c0 = HALF * (claim - sent.iter().sum::<Fr05>());
            let r = self.transcript.read();
            challenges.push(r);
            claim = c0 + r * sent.iter().rev().fold(Fr05::zero(), |acc, c| *c + r * acc);
            for table in &mut tables {
                for x in 0..half {
                    let (lo, hi) = (table[x], table[half + x]);
                    table[x] = lo + r * (hi - lo);
                }
                table.truncate(half);
            }
        }
        let finals = tables.iter().map(|table| table[0]).collect();
        (claim, challenges, finals)
    }

    fn round(
        &mut self,
        trace: &RoundTrace,
        num_vars: usize,
        alpha: &[Fr05],
        beta: &mut [Fr05],
        sum: Fr05,
        rc: u64,
    ) -> (Vec<Fr05>, Vec<Fr05>) {
        let instances = 1usize << (num_vars - 6);
        let one = Fr05::one();

        // iota
        let chi = lanes_of(&trace.chi, instances, to_poly);
        let rlc = combine(&beta[1..], &chi[1..].iter().collect::<Vec<_>>());
        let rc_table = to_poly(&vec![rc; instances]);
        let beta0 = beta[0];
        let (_, vrs_iota, f) = self.sumcheck(
            3,
            vec![eq_table(alpha), rc_table, chi[0].clone(), rlc],
            |v| v[0] * (beta0 * xor(v[2], v[1]) + v[3]),
            sum,
        );
        let (chi_00, chi_rlc) = (f[2], f[3]);
        self.write_all(&[chi_00, chi_rlc]);

        // chi
        let x = self.transcript.read();
        let y = self.transcript.read();
        beta[0] *= x;
        beta.iter_mut().skip(1).for_each(|b| *b *= y);
        let sum = beta[0] * chi_00 + y * chi_rlc;
        let weights = beta.to_vec();
        let mut tables = vec![eq_table(&vrs_iota)];
        tables.extend(lanes_of(&trace.pi, instances, to_poly));
        let (_, vrs_chi, f) = self.sumcheck(
            4,
            tables,
            |v| {
                v[0] * (0..25)
                    .map(|i| {
                        let not_next = one - v[1 + add_col(i, 1)];
                        weights[i] * xor(v[1 + i], not_next * v[1 + add_col(i, 2)])
                    })
                    .sum::<Fr05>()
            },
            sum,
        );
        let pi = f[1..].to_vec();
        self.write_all(&pi);

        // rho
        let rho = strip_pi(&pi);
        let weights = self.squeeze(25);
        beta.copy_from_slice(&weights);
        let sum = weights.iter().zip(&rho).map(|(b, v)| *b * *v).sum();
        let eq_chi = eq_table(&vrs_chi);
        let mut tables: Vec<Vec<Fr05>> = (0..25)
            .map(|lane| derive_rot_evaluations_from_eq(&eq_chi, RHO_OFFSETS[lane] as usize))
            .collect();
        tables.extend(lanes_of(&trace.theta, instances, to_poly));
        let (_, vrs_rho, f) = self.sumcheck(
            2,
            tables,
            |v| (0..25).map(|i| weights[i] * v[i] * v[25 + i]).sum(),
            sum,
        );
        let theta = f[25..].to_vec();
        self.write_all(&theta);

        // theta
        let weights = self.squeeze(25);
        beta.copy_from_slice(&weights);
        let sum = weights
            .iter()
            .zip(&theta)
            .map(|(b, v)| *b * (one - *v - *v))
            .sum();
        let a_theta = lanes_of(&trace.a_theta, instances, to_poly_xor_base);
        let mut tables = vec![eq_table(&vrs_rho)];
        for column in 0..5 {
            let rows: Vec<_> = (0..5).map(|row| &a_theta[row * 5 + column]).collect();
            let row_weights: Vec<_> = (0..5).map(|row| beta[row * 5 + column]).collect();
            tables.push(combine(&row_weights, &rows));
        }
        tables.extend(lanes_of(&trace.d, instances, to_poly_xor_base));
        let (_, vrs_theta, f) = self.sumcheck(
            3,
            tables,
            |v| v[0] * (0..5).map(|j| v[6 + j] * v[1 + j]).sum::<Fr05>(),
            sum,
        );
        let ai = f[1..6].to_vec();
        let d = f[6..].to_vec();
        self.write_all(&ai);
        self.write_all(&d);

        // theta_d
        let beta_d = self.squeeze(5);
        let sum = beta_d.iter().zip(&d).map(|(b, v)| *b * *v).sum();
        let mut tables = vec![eq_table(&vrs_theta)];
        tables.extend(lanes_of(&trace.c, instances, to_poly_xor_base));
        tables.extend(lanes_of(&trace.rot_c, instances, to_poly_xor_base));
        let (_, vrs_d, f) = self.sumcheck(
            3,
            tables,
            |v| {
                v[0] * (0..5)
                    .map(|j| beta_d[j] * v[1 + (j + 4) % 5] * v[6 + (j + 1) % 5])
                    .sum::<Fr05>()
            },
            sum,
        );
        let c = f[1..6].to_vec();
        let rot_c = f[6..].to_vec();
        self.write_all(&c);
        self.write_all(&rot_c);

        // theta_c
        let beta_c = self.squeeze(5);
        let beta_rot_c = self.squeeze(5);
        let sum = beta_c
            .iter()
            .zip(&c)
            .chain(beta_rot_c.iter().zip(&rot_c))
            .map(|(b, v)| *b * *v)
            .sum();
        let eq_d = eq_table(&vrs_d);
        let rot_one = derive_rot_evaluations_from_eq(&eq_d, RHO_OFFSETS[1] as usize);
        let mut tables = vec![eq_d, rot_one];
        tables.extend(lanes_of(&trace.a_c, instances, to_poly_xor_base));
        let (_, vrs_c, f) = self.sumcheck(
            6,
            tables,
            |v| {
                (0..5)
                    .map(|j| {
                        let product: Fr05 = (0..5).map(|i| v[2 + i * 5 + j]).product();
                        (beta_c[j] * v[0] + beta_rot_c[j] * v[1]) * product
                    })
                    .sum()
            },
            sum,
        );
        let a = f[2..].to_vec();
        self.write_all(&a);

        // theta_a
        let mut sum = Fr05::zero();
        for (column, value) in ai.iter().enumerate() {
            let b = self.transcript.read();
            for row in 0..5 {
                beta[row * 5 + column] *= b;
            }
            sum += b * *value;
        }
        let beta_a = self.squeeze(25);
        sum += beta_a.iter().zip(&a).map(|(b, v)| *b * *v).sum::<Fr05>();
        let weights = beta.to_vec();
        let mut tables = vec![eq_table(&vrs_theta), eq_table(&vrs_c)];
        tables.extend(lanes_of(&trace.a_a, instances, to_poly_xor_base));
        let (_, vrs_a, f) = self.sumcheck(
            2,
            tables,
            |v| {
                (0..25)
                    .map(|j| (weights[j] * v[0] + beta_a[j] * v[1]) * v[2 + j])
                    .sum()
            },
            sum,
        );
        let iota = f[2..].to_vec();
        self.write_all(&iota);
        (
            vrs_a,
            iota.iter().map(|v| HALF * (one - *v)).collect::<Vec<_>>(),
        )
    }
}

/// Proves `data` (instance-major states) with the deviations in `plan`.
pub fn prove(data: &[u64], plan: Plan) -> Forged {
    let instances = data.len() / 25;
    let log_instances = instances.ilog2() as usize;
    let num_vars = log_instances + 6;
    let lanes_for = |lanes: usize| Flip::from_seed(plan.seed, lanes, instances);

    let mut input = vec![0u64; 25 * instances];
    for instance in 0..instances {
        for lane in 0..25 {
            input[lane * instances + instance] = data[instance * 25 + lane];
        }
    }

    let mut traces = Vec::with_capacity(24);
    let mut state = input.clone();
    for round in 0..24 {
        let flip = match plan.lie {
            Some(Break::Round { round: at, layer }) if at == round => {
                Some((layer, lanes_for(layer.lanes())))
            }
            _ => None,
        };
        let (trace, next) = round_trace(&state, round, flip);
        traces.push(trace);
        state = next;
    }
    let genuine_output = state;

    let mut claimed_input = input.clone();
    if let Some(Break::InputLane { lane }) = plan.lie {
        let flip = Flip {
            lane,
            ..lanes_for(25)
        };
        flip.apply(&mut claimed_input, instances);
    }
    let mut flipped_output = genuine_output.clone();
    lanes_for(25).apply(&mut flipped_output, instances);
    let (claimed_output, sum_words, reduction_words) = match plan.lie {
        Some(Break::OutputSum) => (&flipped_output, &genuine_output, &genuine_output),
        Some(Break::OutputWords) => (&flipped_output, &flipped_output, &genuine_output),
        Some(Break::OutputBits) => (&flipped_output, &flipped_output, &flipped_output),
        _ => (&genuine_output, &genuine_output, &genuine_output),
    };

    let r = derive_r_native(&claimed_input, claimed_output, log_instances);
    let mut cheat = Cheater {
        transcript: Prover::new(),
        plan,
        sumcheck: 0,
        rebase_value: None,
    };
    r.iter()
        .for_each(|challenge| cheat.transcript.absorb(*challenge));
    let mut beta = cheat.squeeze(25);

    // output sum
    let word_tables: Vec<Vec<Fr05>> = sum_words
        .chunks_exact(instances)
        .map(to_field_vec)
        .collect();
    let mut sum = Fr05::zero();
    for (weight, table) in beta.iter().zip(&word_tables) {
        sum += *weight * eval_mle(table, &r);
    }
    cheat.transcript.write(sum);

    // output word reduction
    let reduction_tables: Vec<Vec<Fr05>> = reduction_words
        .chunks_exact(instances)
        .map(to_field_vec)
        .collect();
    let words_rlc = combine(&beta, &reduction_tables.iter().collect::<Vec<_>>());
    let (_, r_x, f) = cheat.sumcheck(2, vec![eq_table(&r), words_rlc], |v| v[0] * v[1], sum);
    let words_r_x = f[1];
    cheat.transcript.write(words_r_x);

    // output bit reduction, over the claimed or genuine bits of the break
    let bit_words = match plan.lie {
        Some(Break::OutputBits) => &genuine_output,
        _ => reduction_words,
    };
    let eq_x = eq_table(&r_x);
    let mut bit_table = vec![Fr05::zero(); 64];
    for (lane, weight) in beta.iter().enumerate() {
        let bits = to_poly(&bit_words[lane * instances..(lane + 1) * instances]);
        for (instance, scale) in eq_x.iter().enumerate() {
            for bit in 0..64 {
                bit_table[bit] += *weight * *scale * bits[instance * 64 + bit];
            }
        }
    }
    let powers: Vec<Fr05> = (0..64).map(|i| Fr05::from(1u64 << i)).collect();
    let (_, r_y, f) = cheat.sumcheck(2, vec![powers, bit_table], |v| v[0] * v[1], words_r_x);
    let bit_eval = f[1];
    cheat.transcript.write(bit_eval);

    let mut sum = bit_eval;
    let mut alpha = r_x;
    alpha.extend(r_y);
    for round in (0..24).rev() {
        let (next_alpha, iota) = cheat.round(
            &traces[round],
            num_vars,
            &alpha,
            &mut beta,
            sum,
            ROUND_CONSTANTS[round],
        );
        alpha = next_alpha;
        if round != 0 {
            beta = cheat.squeeze(25);
            sum = beta.iter().zip(&iota).map(|(b, v)| *b * *v).sum();
        }
    }

    let rebase = cheat.rebase_value;
    let proof_05 = cheat.transcript.finish();
    Forged {
        proof: proof_05.iter().copied().map(to_fr).collect(),
        proof_05,
        input: claimed_input,
        output: claimed_output.clone(),
        r,
        rebase,
    }
}
