//! Direct matrix evaluation and determinism analysis, independent of cached LC values.
#![allow(dead_code)]
use ark_bn254::Fr;
use ark_ff::{One, Zero};
use ark_relations::gr1cs::{ConstraintSystemRef, R1CS_PREDICATE_LABEL};

pub type Row = Vec<(Fr, usize)>;
pub struct R1cs {
    pub a: Vec<Row>,
    pub b: Vec<Row>,
    pub c: Vec<Row>,
    pub z: Vec<Fr>,
    pub num_instance: usize,
}

pub fn extract(cs: &ConstraintSystemRef<Fr>) -> R1cs {
    cs.finalize();
    let mut m = cs.to_matrices().unwrap();
    let mut m = m.remove(R1CS_PREDICATE_LABEL).unwrap();
    let c = m.pop().unwrap();
    let b = m.pop().unwrap();
    let a = m.pop().unwrap();
    let inner = cs.borrow().unwrap();
    let mut z = inner.assignments.instance_assignment.clone();
    let num_instance = z.len();
    z.extend_from_slice(&inner.assignments.witness_assignment);
    R1cs {
        a,
        b,
        c,
        z,
        num_instance,
    }
}

pub fn dot(row: &Row, z: &[Fr]) -> Fr {
    row.iter().map(|(coeff, i)| *coeff * z[*i]).sum()
}

impl R1cs {
    pub fn unsatisfied(&self) -> Vec<usize> {
        (0..self.a.len())
            .filter(|&i| {
                dot(&self.a[i], &self.z) * dot(&self.b[i], &self.z) != dot(&self.c[i], &self.z)
            })
            .collect()
    }

    /// Variables appearing in no constraint at all.
    pub fn unused(&self) -> Vec<usize> {
        let occ = self.occurrences();
        (0..self.z.len()).filter(|i| occ[*i] == 0).collect()
    }

    /// Fixpoint propagation: from `known`, a constraint A*B=C pins its single
    /// unknown variable given the assigned values. Returns the known mask.
    pub fn propagate(&self, mut known: Vec<bool>) -> Vec<bool> {
        for k in known.iter_mut().take(self.num_instance) {
            *k = true;
        }
        let unknowns = |row: &Row, known: &[bool]| -> Vec<usize> {
            row.iter()
                .filter(|(c, i)| !c.is_zero() && !known[*i])
                .map(|(_, i)| *i)
                .collect()
        };
        loop {
            let mut changed = false;
            for k in 0..self.a.len() {
                let (ua, ub, uc) = (
                    unknowns(&self.a[k], &known),
                    unknowns(&self.b[k], &known),
                    unknowns(&self.c[k], &known),
                );
                if ua.len() + ub.len() + uc.len() == 0 {
                    continue;
                }
                let target = match (ua.len(), ub.len(), uc.len()) {
                    (0, 0, 1) => Some(uc[0]),
                    (1, 0, 0) if !dot(&self.b[k], &self.z).is_zero() => Some(ua[0]),
                    (0, 1, 0) if !dot(&self.a[k], &self.z).is_zero() => Some(ub[0]),
                    // A known and zero forces C regardless of B, and the reverse.
                    (0, _, 1) if dot(&self.a[k], &self.z).is_zero() => Some(uc[0]),
                    (_, 0, 1) if dot(&self.b[k], &self.z).is_zero() => Some(uc[0]),
                    _ => None,
                };
                if let Some(t) = target {
                    known[t] = true;
                    changed = true;
                }
            }
            if !changed {
                return known;
            }
        }
    }

    /// Variables constrained by the pattern `(1 - x) * x = 0`.
    pub fn boolean_vars(&self) -> Vec<bool> {
        let mut out = vec![false; self.z.len()];
        for k in 0..self.a.len() {
            if self.c[k].iter().all(|(c, _)| c.is_zero())
                && self.b[k].len() == 1
                && self.b[k][0].0.is_one()
            {
                let x = self.b[k][0].1;
                let a = &self.a[k];
                if a.len() == 2
                    && a.iter().any(|(c, i)| *i == 0 && c.is_one())
                    && a.iter().any(|(c, i)| *i == x && *c == -Fr::one())
                {
                    out[x] = true;
                }
            }
        }
        out
    }

    pub fn occurrences(&self) -> Vec<u32> {
        let mut n = vec![0u32; self.z.len()];
        for m in [&self.a, &self.b, &self.c] {
            for row in m.iter() {
                for (coeff, i) in row {
                    if !coeff.is_zero() {
                        n[*i] += 1;
                    }
                }
            }
        }
        n
    }
}

/// Upstream `prove` over caller-supplied layers and per-round constants, with
/// the debug self-checks removed. The layers may describe any function.
pub fn prove_layers(
    states: &[gkr::reference::KeccakRoundState],
    rcs: &[u64; 24],
    r: Vec<ark_bn254_05::Fr>,
) -> Vec<Fr> {
    use ark_bn254_05::Fr as Fr05;
    use gkr::sumcheck::outputs::{prove_bits, prove_outputs};
    use gkr::sumcheck::util::{HALF, eval_mle, to_field_vec, to_poly};
    use std::str::FromStr;
    let instances = states[0].a.len() / 25;
    let num_vars = 6 + instances.ilog2() as usize;
    let mut prover = gkr::transcript::Prover::new();
    r.iter().for_each(|c| prover.absorb(*c));
    let mut beta = (0..25).map(|_| prover.read()).collect::<Vec<_>>();
    let words = to_field_vec(&states[23].iota);
    let c: Fr05 = words
        .chunks(instances)
        .enumerate()
        .map(|(i, w)| beta[i] * eval_mle(w, &r))
        .sum();
    prover.write(c);
    let eq_proof = prove_outputs(&mut prover, num_vars - 6, &r, &words, &beta, c);
    let mut bits = to_poly(&states[23].iota);
    let bit_proof = prove_bits(
        &mut prover,
        &eq_proof.r_x,
        &mut bits,
        &beta,
        eq_proof.word_rlc_eval,
    );
    let mut point = Vec::new();
    point.extend(eq_proof.r_x);
    point.extend(bit_proof.r_y);
    let mut sum = bit_proof.bit_rlc_eval;
    for round in (0..24).rev() {
        let p = gkr::keccacheck_og::prover::prove_round(
            &mut prover,
            num_vars,
            &states[round],
            &point,
            &mut beta,
            sum,
            rcs[round],
        );
        point = p.r;
        if round != 0 {
            sum = Fr05::from(0u64);
            beta.iter_mut().enumerate().for_each(|(i, b)| {
                *b = prover.read();
                sum += *b * (HALF * (Fr05::from(1u64) - p.iota_hat[i]));
            });
        }
    }
    prover
        .finish()
        .iter()
        .map(|x| Fr::from_str(&x.to_string()).unwrap())
        .collect()
}
