//! Keccacheck GKR verifier gadget.
//!
//! Ported from the upstream native and gnark verifiers at commit `15f00e3`.

use crate::poseidon2::SpongeVar;
use ark_bn254::Fr;
use ark_ff::{MontFp, One, Zero};
use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

const HALF: Fr =
    MontFp!("10944121435919637611123202872628637544274182200208017171849102093287904247809");

const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

const RHO_OFFSETS: [usize; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

type RoundClaims = (Vec<FpVar<Fr>>, Vec<FpVar<Fr>>);

struct TranscriptVar {
    sponge: SpongeVar,
    proof: Vec<FpVar<Fr>>,
    index: usize,
}

impl TranscriptVar {
    fn new(proof: Vec<FpVar<Fr>>) -> Self {
        Self {
            sponge: SpongeVar::new(),
            proof,
            index: 0,
        }
    }

    fn absorb(&mut self, value: &FpVar<Fr>) {
        self.sponge.absorb(value);
    }

    fn generate(&mut self) -> FpVar<Fr> {
        self.sponge.squeeze()
    }

    fn read(&mut self) -> Result<FpVar<Fr>, SynthesisError> {
        let value = self
            .proof
            .get(self.index)
            .cloned()
            .ok_or(SynthesisError::Unsatisfiable)?;
        self.index += 1;
        self.sponge.absorb(&value);
        Ok(value)
    }

    fn finish(self) -> Result<(), SynthesisError> {
        if self.index == self.proof.len() {
            Ok(())
        } else {
            Err(SynthesisError::Unsatisfiable)
        }
    }
}

fn xor(a: &FpVar<Fr>, b: &FpVar<Fr>) -> FpVar<Fr> {
    let ab = a * b;
    a + b - &ab - &ab
}

fn enforce_named(_label: &str, left: &FpVar<Fr>, right: &FpVar<Fr>) -> Result<(), SynthesisError> {
    left.enforce_equal(right)
}

fn eval_eq(r: &[FpVar<Fr>]) -> Vec<FpVar<Fr>> {
    if r.is_empty() {
        return vec![FpVar::Constant(Fr::one())];
    }
    let mut out = vec![FpVar::Constant(Fr::one()) - &r[0], r[0].clone()];
    for ri in &r[1..] {
        let one_minus = FpVar::Constant(Fr::one()) - ri;
        let mut next = Vec::with_capacity(out.len() * 2);
        for value in out {
            let lo = &value * &one_minus;
            let hi = value - &lo;
            next.push(lo);
            next.push(hi);
        }
        out = next;
    }
    out
}

fn eval_mle_with_eq(mle: &[FpVar<Fr>], eq: &[FpVar<Fr>]) -> FpVar<Fr> {
    assert_eq!(mle.len(), eq.len());
    mle.iter()
        .zip(eq)
        .fold(FpVar::Constant(Fr::zero()), |acc, (a, b)| acc + a * b)
}

fn eval_mle(mle: &[FpVar<Fr>], r: &[FpVar<Fr>]) -> FpVar<Fr> {
    assert_eq!(mle.len(), 1usize << r.len());
    let mut coeffs = mle.to_vec();
    for ri in r {
        let half = coeffs.len() / 2;
        coeffs = (0..half)
            .map(|j| &coeffs[j] + ri * (&coeffs[half + j] - &coeffs[j]))
            .collect();
    }
    coeffs[0].clone()
}

fn eq(a: &[FpVar<Fr>], b: &[FpVar<Fr>]) -> FpVar<Fr> {
    assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b)
        .fold(FpVar::Constant(Fr::one()), |acc, (x, y)| {
            let xy = x * y;
            let term = &xy + &xy + FpVar::Constant(Fr::one()) - x - y;
            acc * term
        })
}

fn prefix_eq(a: &[FpVar<Fr>], b: &[FpVar<Fr>], prefix: usize) -> FpVar<Fr> {
    eq(&a[..prefix], &b[..prefix])
}

fn rot_from_eq(
    lane: usize,
    eq_a_suffix: &[FpVar<Fr>],
    eq_b_suffix: &[FpVar<Fr>],
    prefix: &FpVar<Fr>,
) -> FpVar<Fr> {
    let mut rotated = vec![FpVar::Constant(Fr::zero()); eq_a_suffix.len()];
    let instances = eq_a_suffix.len() / 64;
    for instance in 0..instances {
        for bit in 0..64 {
            rotated[instance * 64 + bit] =
                eq_a_suffix[instance * 64 + (bit + RHO_OFFSETS[lane]) % 64].clone();
        }
    }
    prefix * eval_mle_with_eq(&rotated, eq_b_suffix)
}

fn verify_sumcheck<const DEGREE: usize>(
    transcript: &mut TranscriptVar,
    num_vars: usize,
    mut claim: FpVar<Fr>,
) -> Result<(FpVar<Fr>, Vec<FpVar<Fr>>), SynthesisError> {
    let mut challenges = Vec::with_capacity(num_vars);
    for _ in 0..num_vars {
        let mut p = Vec::with_capacity(DEGREE);
        for _ in 0..DEGREE {
            p.push(transcript.read()?);
        }
        let sum = p
            .iter()
            .cloned()
            .fold(FpVar::Constant(Fr::zero()), |acc, x| acc + x);
        let p0 = (claim - sum) * HALF;
        let r = transcript.generate();
        challenges.push(r.clone());
        let mut acc = p[DEGREE - 1].clone();
        for j in (0..DEGREE - 1).rev() {
            acc = &p[j] + &r * acc;
        }
        claim = p0 + r * acc;
    }
    Ok((claim, challenges))
}

fn add_col(j: usize, add: usize) -> usize {
    let col = j % 5;
    let row = j - col;
    (col + add) % 5 + row
}

fn strip_pi(pi: &[FpVar<Fr>]) -> Vec<FpVar<Fr>> {
    let mut rho = pi.to_vec();
    let mut last = 1usize;
    for target in PI {
        rho[last] = pi[target].clone();
        last = target;
    }
    rho
}

fn verify_round(
    transcript: &mut TranscriptVar,
    num_vars: usize,
    alpha: &[FpVar<Fr>],
    beta: &mut [FpVar<Fr>],
    sum: FpVar<Fr>,
    rc: u64,
    round: usize,
) -> Result<RoundClaims, SynthesisError> {
    let (ve, vrs_iota) = verify_sumcheck::<3>(transcript, num_vars, sum)?;
    let chi_00 = transcript.read()?;
    let chi_rlc = transcript.read()?;
    let e_eq = eq(alpha, &vrs_iota);
    let rc_bits = (0..64)
        .map(|bit| FpVar::Constant(Fr::from((rc >> bit) & 1)))
        .collect::<Vec<_>>();
    let e_rc = eval_mle(&rc_bits, &vrs_iota[num_vars - 6..]);
    let expected = e_eq * (&beta[0] * xor(&chi_00, &e_rc) + &chi_rlc);
    enforce_named(&format!("round {round}: iota"), &expected, &ve)?;

    let x = transcript.generate();
    let y = transcript.generate();
    beta[0] *= &x;
    for value in &mut beta[1..] {
        *value *= &y;
    }
    let expected_sum = &beta[0] * &chi_00 + &y * &chi_rlc;

    let (ve, vrs_chi) = verify_sumcheck::<4>(transcript, num_vars, expected_sum)?;
    let mut pi = Vec::with_capacity(25);
    for _ in 0..25 {
        pi.push(transcript.read()?);
    }
    let e_eq = eq(&vrs_iota, &vrs_chi);
    let mut checksum = FpVar::Constant(Fr::zero());
    for i in 0..25 {
        let chi = xor(
            &pi[i],
            &((FpVar::Constant(Fr::one()) - &pi[add_col(i, 1)]) * &pi[add_col(i, 2)]),
        );
        checksum += &e_eq * &beta[i] * chi;
    }
    enforce_named(&format!("round {round}: chi"), &checksum, &ve)?;

    let rho = strip_pi(&pi);
    let mut expected_sum = FpVar::Constant(Fr::zero());
    for i in 0..25 {
        beta[i] = transcript.generate();
        expected_sum += &beta[i] * &rho[i];
    }
    let (ve, vrs_rho) = verify_sumcheck::<2>(transcript, num_vars, expected_sum)?;
    let mut theta = Vec::with_capacity(25);
    for _ in 0..25 {
        theta.push(transcript.read()?);
    }
    let prefix = num_vars - 6;
    let eq_chi_suffix = eval_eq(&vrs_chi[prefix..]);
    let eq_rho_suffix = eval_eq(&vrs_rho[prefix..]);
    let prefix_value = prefix_eq(&vrs_chi, &vrs_rho, prefix);
    checksum = FpVar::Constant(Fr::zero());
    for i in 0..25 {
        let rotation = rot_from_eq(i, &eq_chi_suffix, &eq_rho_suffix, &prefix_value);
        checksum += &beta[i] * rotation * &theta[i];
    }
    enforce_named(&format!("round {round}: rho"), &checksum, &ve)?;

    let theta_xor_base = theta
        .iter()
        .map(|value| FpVar::Constant(Fr::one()) - value - value)
        .collect::<Vec<_>>();
    expected_sum = FpVar::Constant(Fr::zero());
    for i in 0..25 {
        beta[i] = transcript.generate();
        expected_sum += &beta[i] * &theta_xor_base[i];
    }

    let (ve, vrs_theta) = verify_sumcheck::<3>(transcript, num_vars, expected_sum)?;
    let mut ai = Vec::with_capacity(5);
    let mut d = Vec::with_capacity(5);
    for _ in 0..5 {
        ai.push(transcript.read()?);
    }
    for _ in 0..5 {
        d.push(transcript.read()?);
    }
    let e_eq = eq(&vrs_rho, &vrs_theta);
    checksum = FpVar::Constant(Fr::zero());
    for j in 0..5 {
        checksum += &e_eq * &d[j] * &ai[j];
    }
    enforce_named(&format!("round {round}: theta"), &checksum, &ve)?;

    expected_sum = FpVar::Constant(Fr::zero());
    let mut beta_d = Vec::with_capacity(5);
    for value in &d {
        let challenge = transcript.generate();
        expected_sum += &challenge * value;
        beta_d.push(challenge);
    }
    let (ve, vrs_d) = verify_sumcheck::<3>(transcript, num_vars, expected_sum)?;
    let mut c = Vec::with_capacity(5);
    let mut rot_c = Vec::with_capacity(5);
    for _ in 0..5 {
        c.push(transcript.read()?);
    }
    for _ in 0..5 {
        rot_c.push(transcript.read()?);
    }
    let e_eq = eq(&vrs_theta, &vrs_d);
    checksum = FpVar::Constant(Fr::zero());
    for j in 0..5 {
        checksum += &beta_d[j] * &e_eq * &c[(j + 4) % 5] * &rot_c[(j + 1) % 5];
    }
    enforce_named(&format!("round {round}: theta_d"), &checksum, &ve)?;

    expected_sum = FpVar::Constant(Fr::zero());
    let mut beta_c = Vec::with_capacity(5);
    let mut beta_rot_c = Vec::with_capacity(5);
    for value in &c {
        let challenge = transcript.generate();
        expected_sum += &challenge * value;
        beta_c.push(challenge);
    }
    for value in &rot_c {
        let challenge = transcript.generate();
        expected_sum += &challenge * value;
        beta_rot_c.push(challenge);
    }
    let (ve, vrs_c) = verify_sumcheck::<6>(transcript, num_vars, expected_sum)?;
    let mut a = Vec::with_capacity(25);
    for _ in 0..25 {
        a.push(transcript.read()?);
    }
    let e_eq = eq(&vrs_d, &vrs_c);
    let eq_d_suffix = eval_eq(&vrs_d[prefix..]);
    let eq_c_suffix = eval_eq(&vrs_c[prefix..]);
    let prefix_value = prefix_eq(&vrs_d, &vrs_c, prefix);
    let e_rot = rot_from_eq(1, &eq_d_suffix, &eq_c_suffix, &prefix_value);
    checksum = FpVar::Constant(Fr::zero());
    for j in 0..5 {
        let product = (0..5).fold(FpVar::Constant(Fr::one()), |acc, i| acc * &a[i * 5 + j]);
        checksum += (&beta_c[j] * &e_eq + &beta_rot_c[j] * &e_rot) * product;
    }
    enforce_named(&format!("round {round}: theta_c"), &checksum, &ve)?;

    expected_sum = FpVar::Constant(Fr::zero());
    for (i, value) in ai.iter().enumerate() {
        let challenge = transcript.generate();
        for row in 0..5 {
            beta[row * 5 + i] *= &challenge;
        }
        expected_sum += challenge * value;
    }
    let mut beta_a = Vec::with_capacity(25);
    for value in &a {
        let challenge = transcript.generate();
        expected_sum += &challenge * value;
        beta_a.push(challenge);
    }
    let (ve, vrs_a) = verify_sumcheck::<2>(transcript, num_vars, expected_sum)?;
    let mut iota = Vec::with_capacity(25);
    for _ in 0..25 {
        iota.push(transcript.read()?);
    }
    let e_eq_ai = eq(&vrs_theta, &vrs_a);
    let e_eq_a = eq(&vrs_c, &vrs_a);
    checksum = FpVar::Constant(Fr::zero());
    for j in 0..25 {
        checksum += &beta[j] * &e_eq_ai * &iota[j] + &beta_a[j] * &e_eq_a * &iota[j];
    }
    enforce_named(&format!("round {round}: theta_a"), &checksum, &ve)?;
    for value in &mut iota {
        *value = (FpVar::Constant(Fr::one()) - &*value) * HALF;
    }
    Ok((vrs_a, iota))
}

pub fn derive_r_native(output: &[u64], log_instances: usize) -> Vec<Fr> {
    if log_instances == 0 {
        return Vec::new();
    }
    let mut sponge = gkr::transcript::Sponge::new();
    for value in output {
        sponge.absorb(Fr::from(*value));
    }
    (0..log_instances).map(|_| sponge.squeeze()).collect()
}

fn derive_r_var(output: &[FpVar<Fr>], log_instances: usize) -> Vec<FpVar<Fr>> {
    if log_instances == 0 {
        return Vec::new();
    }
    let mut sponge = SpongeVar::new();
    for value in output {
        sponge.absorb(value);
    }
    (0..log_instances).map(|_| sponge.squeeze()).collect()
}

pub struct Witness {
    pub proof: Vec<Fr>,
    pub input: Vec<u64>,
    pub output: Vec<u64>,
}

#[derive(Clone, Debug)]
pub struct VerificationProfile {
    pub allocation: usize,
    pub output_binding: usize,
    pub output_reduction: usize,
    pub rounds: usize,
    pub input_binding: usize,
    pub total: usize,
}

pub fn verify_witness(
    cs: ConstraintSystemRef<Fr>,
    witness: &Witness,
) -> Result<(), SynthesisError> {
    verify_witness_profile(cs, witness).map(|_| ())
}

pub fn verify_witness_profile(
    cs: ConstraintSystemRef<Fr>,
    witness: &Witness,
) -> Result<VerificationProfile, SynthesisError> {
    let start = cs.num_constraints();
    let instances = witness.input.len() / 25;
    assert!(instances.is_power_of_two());
    assert_eq!(witness.output.len(), 25 * instances);
    let log_instances = instances.ilog2() as usize;
    let num_vars = log_instances + 6;

    let proof = witness
        .proof
        .iter()
        .map(|value| FpVar::new_witness(cs.clone(), || Ok(*value)))
        .collect::<Result<Vec<_>, _>>()?;
    let output = witness
        .output
        .iter()
        .map(|value| FpVar::new_witness(cs.clone(), || Ok(Fr::from(*value))))
        .collect::<Result<Vec<_>, _>>()?;
    let mut input_bits = Vec::with_capacity(witness.input.len() * 64);
    for value in &witness.input {
        for bit in 0..64 {
            input_bits.push(Boolean::new_witness(cs.clone(), || {
                Ok((value >> bit) & 1 == 1)
            })?);
        }
    }
    let input_bits = input_bits.into_iter().map(FpVar::from).collect::<Vec<_>>();
    let after_allocation = cs.num_constraints();

    let r = derive_r_var(&output, log_instances);
    let after_output_binding = cs.num_constraints();
    let mut transcript = TranscriptVar::new(proof);
    for challenge in &r {
        transcript.absorb(challenge);
    }
    let mut beta = (0..25).map(|_| transcript.generate()).collect::<Vec<_>>();
    let eq_r = eval_eq(&r);
    let mut expected_sum = FpVar::Constant(Fr::zero());
    for i in 0..25 {
        expected_sum +=
            &beta[i] * eval_mle_with_eq(&output[i * instances..(i + 1) * instances], &eq_r);
    }
    let mut sum = transcript.read()?;
    enforce_named("output sum", &sum, &expected_sum)?;

    let (claim, r_x) = verify_sumcheck::<2>(&mut transcript, log_instances, sum)?;
    let words_r_x = transcript.read()?;
    enforce_named(
        "output word reduction",
        &claim,
        &(&words_r_x * eq(&r, &r_x)),
    )?;

    let (claim, r_y) = verify_sumcheck::<2>(&mut transcript, 6, words_r_x)?;
    let bit_eval = transcript.read()?;
    let powers = (0..64)
        .map(|i| FpVar::Constant(Fr::from(1u64 << i)))
        .collect::<Vec<_>>();
    enforce_named(
        "output bit reduction",
        &claim,
        &(eval_mle(&powers, &r_y) * &bit_eval),
    )?;
    sum = bit_eval;
    let mut alpha = r_x;
    alpha.extend(r_y);
    let after_output_reduction = cs.num_constraints();

    let mut iota = Vec::new();
    for round in (0..24).rev() {
        (alpha, iota) = verify_round(
            &mut transcript,
            num_vars,
            &alpha,
            &mut beta,
            sum.clone(),
            ROUND_CONSTANTS[round],
            round,
        )?;
        if round != 0 {
            sum = FpVar::Constant(Fr::zero());
            for i in 0..25 {
                beta[i] = transcript.generate();
                sum += &beta[i] * &iota[i];
            }
        }
    }
    let after_rounds = cs.num_constraints();

    let eq_alpha = eval_eq(&alpha);
    for (i, iota_value) in iota.iter().enumerate() {
        let start = i * instances * 64;
        let end = start + instances * 64;
        enforce_named(
            &format!("input lane {i}"),
            &eval_mle_with_eq(&input_bits[start..end], &eq_alpha),
            iota_value,
        )?;
    }
    transcript.finish()?;
    let total = cs.num_constraints();
    Ok(VerificationProfile {
        allocation: after_allocation - start,
        output_binding: after_output_binding - after_allocation,
        output_reduction: after_output_reduction - after_output_binding,
        rounds: after_rounds - after_output_reduction,
        input_binding: total - after_rounds,
        total: total - start,
    })
}

pub fn make_witness(instances: usize) -> Witness {
    assert!(instances.is_power_of_two());
    let data = (0..instances * 25).map(|i| i as u64).collect::<Vec<_>>();
    let mut output = vec![0u64; instances * 25];
    for instance in 0..instances {
        let mut state: [u64; 25] = core::array::from_fn(|lane| data[instance * 25 + lane]);
        keccak::f1600(&mut state);
        for lane in 0..25 {
            output[lane * instances + instance] = state[lane];
        }
    }
    let r = derive_r_native(&output, instances.ilog2() as usize);
    let (proof, input, proved_output) = gkr::keccacheck_og::prover::prove(&data, r);
    assert_eq!(proved_output, output);
    Witness {
        proof,
        input,
        output,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn one_permutation_proof_satisfies() {
        let witness = make_witness(1);
        let cs = ConstraintSystem::<Fr>::new_ref();
        verify_witness(cs.clone(), &witness).unwrap();
        assert!(
            cs.is_satisfied().unwrap(),
            "{:?}",
            cs.which_is_unsatisfied()
        );
    }

    #[test]
    fn altered_output_is_rejected() {
        let mut witness = make_witness(1);
        witness.output[0] ^= 1;
        let cs = ConstraintSystem::<Fr>::new_ref();
        verify_witness(cs.clone(), &witness).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn altered_proof_is_rejected() {
        let mut witness = make_witness(1);
        witness.proof[0] += Fr::one();
        let cs = ConstraintSystem::<Fr>::new_ref();
        verify_witness(cs.clone(), &witness).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }
}
