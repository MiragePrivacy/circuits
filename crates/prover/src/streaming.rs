//! A Groth16 prover that never builds the constraint matrices.
//!
//! `ark_groth16`'s prover finalizes the constraint system, which inlines every
//! symbolic linear combination, then copies out all three matrices to compute
//! the QAP witness. For the Keccacheck circuits that is ~8 GiB of the ~10.5 GiB
//! proving peak and most of the time, yet the witness map only needs one value
//! per constraint for each of A, B and C.
//!
//! Synthesizing with `generate_lc_assignments` records each linear
//! combination's value as it is created, so those values are lookups. The
//! remaining steps (FFTs, then the five multiscalar multiplications) follow
//! `LibsnarkReduction::witness_map_from_matrices` and
//! `Groth16::create_proof_with_assignment` exactly, with `r` and `s` drawn in
//! the same order as `Groth16::prove`. The proof is therefore byte-identical
//! to `Groth16::prove` for the same key, circuit and RNG; only the memory and
//! time it takes differ.

use ark_bn254::{Bn254, Fr};
use ark_ec::{pairing::Pairing, CurveGroup, VariableBaseMSM};
use ark_ff::{FftField, Field, PrimeField, UniformRand, Zero};
use ark_groth16::{Proof, ProvingKey};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisError, SynthesisMode,
    R1CS_PREDICATE_LABEL,
};
use ark_std::rand::Rng;
use ark_std::{cfg_into_iter, cfg_iter, cfg_iter_mut};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

type G1 = <Bn254 as Pairing>::G1;
type BigInt = <Fr as PrimeField>::BigInt;

/// How the multiscalar multiplications walk the proving key.
#[derive(Clone, Copy, Debug)]
pub enum MsmStrategy {
    /// One MSM over each whole query, as `ark_groth16` does.
    Whole,
    /// Consecutive chunks of this many bases, summed. Each chunk's bucket
    /// accumulation stays within a contiguous slice of the key, which matters
    /// when memory is paged (an SGX enclave whose working set exceeds its EPC).
    Chunked(usize),
}

/// Bases per MSM chunk inside an SGX enclave.
///
/// Measured for the native circuit on a 378 MiB-EPC host (sgx1, 16 threads):
/// the proof took 132.7s with whole-key MSMs, and 104.0s, 90.8s, 84.5s, 84.2s
/// and 93.2s with chunks of 16Ki, 64Ki, 256Ki, 512Ki and 1Mi bases. 256Ki sits
/// on the plateau. On a host, where nothing is paged, chunking only adds
/// per-chunk overhead.
pub const SGX_MSM_CHUNK: usize = 1 << 18;

/// [`MsmStrategy::Chunked`] inside an enclave, [`MsmStrategy::Whole`] elsewhere.
pub const DEFAULT_STRATEGY: MsmStrategy = if cfg!(target_env = "sgx") {
    MsmStrategy::Chunked(SGX_MSM_CHUNK)
} else {
    MsmStrategy::Whole
};

/// Proves `circuit` against `pk` with [`DEFAULT_STRATEGY`].
pub fn prove<C: ConstraintSynthesizer<Fr>, R: Rng>(
    pk: &ProvingKey<Bn254>,
    circuit: C,
    rng: &mut R,
) -> Result<Proof<Bn254>, SynthesisError> {
    prove_with(pk, circuit, rng, DEFAULT_STRATEGY)
}

/// Proves `circuit` against `pk`, walking the key with `strategy`.
pub fn prove_with<C: ConstraintSynthesizer<Fr>, R: Rng>(
    pk: &ProvingKey<Bn254>,
    circuit: C,
    rng: &mut R,
    strategy: MsmStrategy,
) -> Result<Proof<Bn254>, SynthesisError> {
    let r = Fr::rand(rng);
    let s = Fr::rand(rng);

    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: true,
        generate_lc_assignments: true,
    });
    circuit.generate_constraints(cs.clone())?;
    let (h, input, aux) = {
        let inner = cs.borrow().ok_or(SynthesisError::MissingCS)?;
        (
            witness_map(&inner)?,
            inner.instance_assignment()?[1..].to_vec(),
            inner.witness_assignment()?.to_vec(),
        )
    };
    // Release the linear-combination store before the MSMs.
    drop(cs);

    let msm = |bases: &[<Bn254 as Pairing>::G1Affine], scalars: &[BigInt]| match strategy {
        MsmStrategy::Whole => G1::msm_bigint(bases, scalars),
        MsmStrategy::Chunked(size) => bases
            .chunks(size)
            .zip(scalars.chunks(size))
            .map(|(b, s)| G1::msm_bigint(b, s))
            .sum(),
    };

    let h: Vec<BigInt> = cfg_into_iter!(h).map(|x| x.into_bigint()).collect();
    let h_acc = msm(&pk.h_query, &h);
    drop(h);

    let aux: Vec<BigInt> = cfg_iter!(aux).map(|x| x.into_bigint()).collect();
    let l_aux_acc = msm(&pk.l_query, &aux);
    let r_s_delta_g1 = pk.delta_g1 * (r * s);
    let input: Vec<BigInt> = input.iter().map(|x| x.into_bigint()).collect();
    let assignment = [&input[..], &aux[..]].concat();
    drop(aux);

    // `Groth16::calculate_coeff`: query[0] carries the constant term.
    let a_acc = msm(&pk.a_query[1..], &assignment);
    let g_a = pk.delta_g1 * r + pk.a_query[0] + a_acc + pk.vk.alpha_g1;
    let b_g1_acc = msm(&pk.b_g1_query[1..], &assignment);
    let g1_b = pk.delta_g1 * s + pk.b_g1_query[0] + b_g1_acc + pk.beta_g1;
    let b_g2_acc = match strategy {
        MsmStrategy::Whole => <Bn254 as Pairing>::G2::msm_bigint(&pk.b_g2_query[1..], &assignment),
        MsmStrategy::Chunked(size) => pk.b_g2_query[1..]
            .chunks(size)
            .zip(assignment.chunks(size))
            .map(|(b, s)| <Bn254 as Pairing>::G2::msm_bigint(b, s))
            .sum(),
    };
    let g2_b = pk.vk.delta_g2 * s + pk.b_g2_query[0] + b_g2_acc + pk.vk.beta_g2;
    drop(assignment);

    let g_c = g_a * s + g1_b * r - r_s_delta_g1 + l_aux_acc + h_acc;
    Ok(Proof {
        a: g_a.into_affine(),
        b: g2_b.into_affine(),
        c: g_c.into_affine(),
    })
}

/// The QAP witness `h` from recorded per-constraint values.
fn witness_map(cs: &ConstraintSystem<Fr>) -> Result<Vec<Fr>, SynthesisError> {
    let num_inputs = cs.num_instance_variables();
    let num_constraints = cs.num_constraints();
    let r1cs = cs
        .predicate_constraint_systems
        .get(R1CS_PREDICATE_LABEL)
        .ok_or(SynthesisError::Unsatisfiable)?;
    // Every constraint must be R1CS, or some would be missing from A, B, C.
    if r1cs.num_constraints() != num_constraints {
        return Err(SynthesisError::Unsatisfiable);
    }
    let [a_lcs, b_lcs, c_lcs] = &r1cs.get_constraints()[..] else {
        return Err(SynthesisError::Unsatisfiable);
    };
    let value = |v| cs.assigned_value(v).ok_or(SynthesisError::AssignmentMissing);

    let domain = GeneralEvaluationDomain::<Fr>::new(num_constraints + num_inputs)
        .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
    let mut a = vec![Fr::zero(); domain.size()];
    let mut b = vec![Fr::zero(); domain.size()];
    for i in 0..num_constraints {
        a[i] = value(a_lcs[i])?;
        b[i] = value(b_lcs[i])?;
    }
    a[num_constraints..num_constraints + num_inputs].clone_from_slice(cs.instance_assignment()?);

    domain.ifft_in_place(&mut a);
    domain.ifft_in_place(&mut b);
    let coset = domain
        .get_coset(Fr::GENERATOR)
        .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
    coset.fft_in_place(&mut a);
    coset.fft_in_place(&mut b);
    let mut ab = domain.mul_polynomials_in_evaluation_domain(&a, &b);
    drop(a);
    drop(b);

    let mut c = vec![Fr::zero(); domain.size()];
    for i in 0..num_constraints {
        c[i] = value(c_lcs[i])?;
    }
    domain.ifft_in_place(&mut c);
    coset.fft_in_place(&mut c);

    let vanishing = domain
        .evaluate_vanishing_polynomial(Fr::GENERATOR)
        .inverse()
        .ok_or(SynthesisError::DivisionByZero)?;
    cfg_iter_mut!(ab).zip(c).for_each(|(ab_i, c_i)| {
        *ab_i -= &c_i;
        *ab_i *= &vanishing;
    });
    coset.ifft_in_place(&mut ab);
    Ok(ab)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_groth16::Groth16;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::eq::EqGadget;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::fields::FieldVar;
    use ark_snark::SNARK;
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    /// A small circuit with nested symbolic linear combinations, so values
    /// recorded during synthesis are exercised rather than plain variables.
    #[derive(Clone)]
    struct Chain(u64);

    impl ConstraintSynthesizer<Fr> for Chain {
        fn generate_constraints(
            self,
            cs: ark_relations::gr1cs::ConstraintSystemRef<Fr>,
        ) -> Result<(), SynthesisError> {
            let out = FpVar::new_input(cs.clone(), || {
                let mut x = Fr::from(self.0);
                for i in 0..50u64 {
                    x = (x + Fr::from(i)) * (x + Fr::from(3 * i)) + x;
                }
                Ok(x)
            })?;
            let mut x = FpVar::new_witness(cs, || Ok(Fr::from(self.0)))?;
            for i in 0..50u64 {
                let a = &x + FpVar::constant(Fr::from(i));
                let b = &x + FpVar::constant(Fr::from(3 * i)) + FpVar::constant(Fr::zero());
                x = a * b + &x;
            }
            x.enforce_equal(&out)
        }
    }

    #[test]
    fn matches_groth16_prove_byte_for_byte() {
        let mut rng = StdRng::seed_from_u64(0);
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(Chain(0), &mut rng).unwrap();
        for strategy in [MsmStrategy::Whole, MsmStrategy::Chunked(7), MsmStrategy::Chunked(64)] {
            let reference =
                Groth16::<Bn254>::prove(&pk, Chain(5), &mut StdRng::seed_from_u64(9)).unwrap();
            let streamed = prove_with(&pk, Chain(5), &mut StdRng::seed_from_u64(9), strategy).unwrap();
            assert_eq!(streamed, reference, "{strategy:?} differs from Groth16::prove");
        }
        let proof = prove(&pk, Chain(5), &mut rng).unwrap();
        let mut input = Fr::from(5u64);
        for i in 0..50u64 {
            input = (input + Fr::from(i)) * (input + Fr::from(3 * i)) + input;
        }
        assert!(Groth16::<Bn254>::verify(&vk, &[input], &proof).unwrap());
    }

    #[test]
    fn rejects_an_unsatisfied_witness() {
        // A wrong public input still yields a proof object, which must not
        // verify: the prover does not itself check satisfiability.
        let mut rng = StdRng::seed_from_u64(0);
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(Chain(0), &mut rng).unwrap();
        let proof = prove(&pk, Chain(5), &mut rng).unwrap();
        assert!(!Groth16::<Bn254>::verify(&vk, &[Fr::from(1u64)], &proof).unwrap());
    }

    /// The production circuits, against their seeded setup.
    #[test]
    #[ignore = "Keccacheck setup and three proofs per circuit; run explicitly in release mode"]
    fn matches_groth16_prove_on_the_keccacheck_circuits() {
        use mirage_relation::native::{fixture as native_fixture, KeccacheckNativeCircuit, NativeBounds};
        use mirage_relation::{fixture, Bounds, KeccacheckReceiptCircuit};

        let keys = crate::native::setup_keccacheck(NativeBounds::default(), 0).unwrap();
        let circuit = || KeccacheckNativeCircuit::prove(NativeBounds::default(), native_fixture::genuine());
        let reference = Groth16::<Bn254>::prove(&keys.pk, circuit(), &mut StdRng::seed_from_u64(3)).unwrap();
        for strategy in [MsmStrategy::Whole, MsmStrategy::Chunked(1 << 16)] {
            let streamed = prove_with(&keys.pk, circuit(), &mut StdRng::seed_from_u64(3), strategy).unwrap();
            assert_eq!(streamed, reference, "native {strategy:?}");
        }

        let keys = crate::setup_keccacheck(Bounds::default(), 0).unwrap();
        let circuit = || KeccacheckReceiptCircuit::prove(Bounds::default(), fixture::genuine());
        let reference = Groth16::<Bn254>::prove(&keys.pk, circuit(), &mut StdRng::seed_from_u64(3)).unwrap();
        for strategy in [MsmStrategy::Whole, MsmStrategy::Chunked(1 << 16)] {
            let streamed = prove_with(&keys.pk, circuit(), &mut StdRng::seed_from_u64(3), strategy).unwrap();
            assert_eq!(streamed, reference, "ERC-20 {strategy:?}");
        }
    }
}
