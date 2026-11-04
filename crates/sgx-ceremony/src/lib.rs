use anyhow::{ensure, Result};
use ark_bn254::{Bn254, Fr, G1Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, One, UniformRand, Zero};
use ark_groth16::ProvingKey;
use ark_serialize::{CanonicalDeserialize, Compress, Validate};
use ark_std::rand::{CryptoRng, RngCore};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use zeroize::Zeroize;

pub const MAX_KEY: usize = 2 << 30;
pub const INPUTS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/inputs.json"));

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inputs {
    pub version: u32,
    pub ceremony_id: String,
    pub source_revision: String,
    pub ptau_blake2b: String,
    pub circuits: Vec<Circuit>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Circuit {
    pub circuit: String,
    pub r1cs_digest: String,
    pub genesis_sha256: String,
    pub genesis_bytes: usize,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Output {
    pub version: u32,
    pub mode: String,
    pub inputs_sha256: String,
    pub circuit: String,
    pub proving_key_sha256: String,
    pub verifying_key_sha256: String,
}

pub fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn report_data(manifest: &[u8]) -> [u8; 64] {
    let mut h = Sha256::new();
    h.update(b"mirage-beta-ceremony-v1\0");
    h.update(manifest);
    let mut report = [0; 64];
    report[..32].copy_from_slice(&h.finalize());
    report
}

pub fn read_frame(r: &mut impl Read, limit: usize) -> Result<Vec<u8>> {
    let mut len = [0; 8];
    r.read_exact(&mut len)?;
    let len = usize::try_from(u64::from_be_bytes(len))?;
    ensure!(len <= limit, "frame exceeds limit");
    let mut bytes = vec![0; len];
    r.read_exact(&mut bytes)?;
    Ok(bytes)
}

pub fn write_frame(w: &mut impl Write, bytes: &[u8]) -> Result<()> {
    w.write_all(&(bytes.len() as u64).to_be_bytes())?;
    w.write_all(bytes)?;
    w.flush()?;
    Ok(())
}

pub fn read_key(bytes: &[u8]) -> Result<ProvingKey<Bn254>> {
    let mut input = bytes;
    let key = ProvingKey::deserialize_with_mode(&mut input, Compress::No, Validate::Yes)?;
    ensure!(input.is_empty(), "trailing key bytes");
    Ok(key)
}

/// Applies one secret delta update. No scalar or RNG state is exported.
pub fn contribute(key: &mut ProvingKey<Bn254>, rng: &mut (impl RngCore + CryptoRng)) -> Result<()> {
    ensure!(
        key.delta_g1 == ark_bn254::G1Affine::generator(),
        "not a genesis key"
    );
    ensure!(
        key.vk.delta_g2 == ark_bn254::G2Affine::generator(),
        "not a genesis key"
    );
    let mut delta = Fr::rand(rng);
    while delta.is_zero() || delta.is_one() {
        delta = Fr::rand(rng);
    }
    let mut inverse = delta.inverse().unwrap();
    key.delta_g1 = (key.delta_g1 * delta).into_affine();
    key.vk.delta_g2 = (key.vk.delta_g2 * delta).into_affine();
    for points in [&mut key.h_query, &mut key.l_query] {
        points
            .par_iter_mut()
            .for_each(|p| *p = (*p * inverse).into_affine());
    }
    delta.zeroize();
    inverse.zeroize();
    Ok(())
}

/// Independently checks the full key against the pinned genesis.
pub fn verify_update(
    before: &ProvingKey<Bn254>,
    after: &ProvingKey<Bn254>,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<()> {
    ensure!(
        before.vk.alpha_g1 == after.vk.alpha_g1
            && before.vk.beta_g2 == after.vk.beta_g2
            && before.vk.gamma_g2 == after.vk.gamma_g2
            && before.vk.gamma_abc_g1 == after.vk.gamma_abc_g1
            && before.beta_g1 == after.beta_g1
            && before.a_query == after.a_query
            && before.b_g1_query == after.b_g1_query
            && before.b_g2_query == after.b_g2_query,
        "fixed query changed"
    );
    ensure!(
        !after.delta_g1.is_zero()
            && !after.vk.delta_g2.is_zero()
            && after.delta_g1 != before.delta_g1,
        "invalid delta"
    );
    ensure!(
        Bn254::pairing(after.delta_g1, before.vk.delta_g2)
            == Bn254::pairing(before.delta_g1, after.vk.delta_g2),
        "delta mismatch"
    );
    for (old, new) in [
        (&before.h_query, &after.h_query),
        (&before.l_query, &after.l_query),
    ] {
        ensure!(old.len() == new.len(), "query length changed");
        let mut a = G1Projective::zero();
        let mut b = G1Projective::zero();
        for (old, new) in old.chunks(16384).zip(new.chunks(16384)) {
            let weights: Vec<Fr> = (0..old.len()).map(|_| Fr::rand(rng)).collect();
            a += G1Projective::msm_unchecked(old, &weights);
            b += G1Projective::msm_unchecked(new, &weights);
        }
        ensure!(
            Bn254::pairing(a, before.vk.delta_g2) == Bn254::pairing(b, after.vk.delta_g2),
            "query update mismatch"
        );
    }
    Ok(())
}

pub fn verify_manifest(
    inputs: &[u8],
    circuit: &str,
    manifest: &[u8],
    pk: &[u8],
    vk: &[u8],
) -> Result<()> {
    let output: Output = serde_json::from_slice(manifest)?;
    ensure!(
        output.version == 1 && output.mode == "beta-tee",
        "unsupported output"
    );
    ensure!(
        output.inputs_sha256 == hash(inputs) && output.circuit == circuit,
        "input binding mismatch"
    );
    ensure!(
        output.proving_key_sha256 == hash(pk) && output.verifying_key_sha256 == hash(vk),
        "output hash mismatch"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::gr1cs::{
        ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal,
        SynthesisError, SynthesisMode,
    };
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use mirage_prover::ceremony::{genesis, Powers, R1cs};

    #[derive(Clone)]
    struct Square;
    impl ConstraintSynthesizer<Fr> for Square {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let x = cs.new_witness_variable(|| Ok(Fr::from(3)))?;
            let y = cs.new_input_variable(|| Ok(Fr::from(9)))?;
            cs.enforce_r1cs_constraint(|| x.into(), || x.into(), || y.into())
        }
    }

    #[test]
    fn contribution_proves_and_tampering_is_rejected() {
        let cs = ConstraintSystem::new_ref();
        cs.set_mode(SynthesisMode::Setup);
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        Square.generate_constraints(cs.clone()).unwrap();
        cs.finalize();
        let r1cs = R1cs::from_cs(&cs).unwrap();
        let before = genesis(
            &r1cs,
            &Powers::from_secrets(r1cs.domain_size(), Fr::from(7), Fr::from(11), Fr::from(13)),
        )
        .unwrap();
        let mut rng = StdRng::seed_from_u64(42);
        let mut after = before.clone();
        contribute(&mut after, &mut rng).unwrap();
        verify_update(&before, &after, &mut rng).unwrap();
        let proof = ark_groth16::Groth16::<Bn254>::create_random_proof_with_reduction(
            Square, &after, &mut rng,
        )
        .unwrap();
        let vk = ark_groth16::prepare_verifying_key(&after.vk);
        assert!(ark_groth16::Groth16::<Bn254>::verify_proof(&vk, &proof, &[Fr::from(9)]).unwrap());
        assert!(
            !ark_groth16::Groth16::<Bn254>::verify_proof(&vk, &proof, &[Fr::from(10)]).unwrap()
        );
        assert!(contribute(&mut after.clone(), &mut rng).is_err());
        assert!(verify_update(&before, &before, &mut rng).is_err());
        for section in [0, 1, 2] {
            let mut bad = after.clone();
            let point = match section {
                0 => &mut bad.h_query[0],
                1 => &mut bad.l_query[0],
                _ => &mut bad.a_query[0],
            };
            *point = (*point + ark_bn254::G1Affine::generator()).into_affine();
            assert!(verify_update(&before, &bad, &mut rng).is_err());
        }
        let bytes = mirage_prover::save_proving_key(&after, false).unwrap();
        read_key(&bytes).unwrap();
        let mut trailing = bytes;
        trailing.push(0);
        assert!(read_key(&trailing).is_err());
    }

    #[test]
    fn transport_and_output_binding_fail_closed() {
        let mut oversized = u64::MAX.to_be_bytes().as_slice().to_vec();
        assert!(read_frame(&mut oversized.as_slice(), MAX_KEY).is_err());
        oversized = 4u64.to_be_bytes().to_vec();
        oversized.push(0);
        assert!(read_frame(&mut oversized.as_slice(), 4).is_err());
        let manifest = serde_json::to_vec(&Output {
            version: 1,
            mode: "beta-tee".into(),
            inputs_sha256: hash(b"inputs"),
            circuit: "native-keccacheck".into(),
            proving_key_sha256: hash(b"pk"),
            verifying_key_sha256: hash(b"vk"),
        })
        .unwrap();
        verify_manifest(b"inputs", "native-keccacheck", &manifest, b"pk", b"vk").unwrap();
        assert!(verify_manifest(b"other", "native-keccacheck", &manifest, b"pk", b"vk").is_err());
        assert!(verify_manifest(b"inputs", "erc20-keccacheck", &manifest, b"pk", b"vk").is_err());
        assert!(
            verify_manifest(b"inputs", "native-keccacheck", &manifest, b"corrupt", b"vk").is_err()
        );
        assert_ne!(report_data(&manifest), report_data(b"other"));
        assert_eq!(report_data(&manifest)[32..], [0; 32]);
    }
}
