//! Phase 2 ceremony adapter for the Keccacheck circuits.
//!
//! Converts between arkworks keys and the Bellman MPC parameter format that
//! the snarkjs contribution code reads and writes:
//!
//! * `export DIRECTORY PTAU` derives the genesis key from a Phase 1 transcript
//!   ([`mirage_prover::ceremony`]) and writes the initial challenge body;
//! * `check` and `verify` check a contribution against that genesis key;
//! * `finalize` checks the last contribution and writes the final keys.
//!
//! The selected circuit comes from `CEREMONY_CIRCUIT`.

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, VariableBaseMSM};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, ProvingKey};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisMode,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use ark_std::UniformRand;
use mirage_prover::ceremony::{self, Powers, R1cs};
use mirage_relation::native::{fixture, KeccacheckNativeCircuit, NativeBounds};
use mirage_relation::{Bounds, KeccacheckReceiptCircuit};
use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    path::Path,
    time::Instant,
};

/// Commit the binary was built from, set by the ceremony repository's build
/// wrapper. A trailing `-dirty` marks uncommitted changes.
const REVISION: Option<&str> = option_env!("CEREMONY_SOURCE_REV");

fn fq(w: &mut impl Write, x: Fq) {
    w.write_all(&x.into_bigint().to_bytes_be()).unwrap();
}
fn g1(w: &mut impl Write, p: &G1Affine) {
    if p.is_zero() {
        w.write_all(&[0; 64]).unwrap();
    } else {
        fq(w, p.x);
        fq(w, p.y);
    }
}
fn g2(w: &mut impl Write, p: &G2Affine) {
    if p.is_zero() {
        w.write_all(&[0; 128]).unwrap();
    } else {
        fq(w, p.x.c1);
        fq(w, p.x.c0);
        fq(w, p.y.c1);
        fq(w, p.y.c0);
    }
}
fn array<T>(w: &mut impl Write, points: &[T], encode: impl Fn(&mut dyn Write, &T)) {
    w.write_all(&u32::try_from(points.len()).unwrap().to_be_bytes())
        .unwrap();
    for p in points {
        encode(w, p);
    }
}
fn read_fq(r: &mut impl Read) -> Fq {
    let mut b = [0; 32];
    r.read_exact(&mut b).unwrap();
    let x = Fq::from_be_bytes_mod_order(&b);
    assert_eq!(x.into_bigint().to_bytes_be(), b, "noncanonical coordinate");
    x
}
fn read_g1(r: &mut impl Read) -> G1Affine {
    let x = read_fq(r);
    let y = read_fq(r);
    if x == Fq::from(0) && y == Fq::from(0) {
        return G1Affine::identity();
    }
    let p = G1Affine::new_unchecked(x, y);
    assert!(p.is_on_curve());
    p
}
fn read_g2(r: &mut impl Read) -> G2Affine {
    let xc1 = read_fq(r);
    let xc0 = read_fq(r);
    let yc1 = read_fq(r);
    let yc0 = read_fq(r);
    let x = Fq2::new(xc0, xc1);
    let y = Fq2::new(yc0, yc1);
    if x == Fq2::from(0) && y == Fq2::from(0) {
        return G2Affine::identity();
    }
    let p = G2Affine::new_unchecked(x, y);
    assert!(p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve());
    p
}
fn count(r: &mut impl Read) -> usize {
    let mut b = [0; 4];
    r.read_exact(&mut b).unwrap();
    u32::from_be_bytes(b) as usize
}
fn rss() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find(|l| l.starts_with("VmHWM:"))
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}
fn keccak256(bytes: &[u8]) -> String {
    use tiny_keccak::{Hasher, Keccak};
    let mut h = Keccak::v256();
    h.update(bytes);
    let mut out = [0; 32];
    h.finalize(&mut out);
    hex::encode(out)
}
fn synthesize(native: bool) -> R1cs {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    if native {
        KeccacheckNativeCircuit::setup(NativeBounds::default())
            .generate_constraints(cs.clone())
            .unwrap();
    } else {
        KeccacheckReceiptCircuit::setup(Bounds::default())
            .generate_constraints(cs.clone())
            .unwrap();
    }
    cs.finalize();
    R1cs::from_cs(&cs).unwrap()
}
fn circuit_json(circuit: &str, r1cs: &R1cs) -> String {
    format!(
        "\"circuit\":\"{circuit}\",\"r1cs_digest\":\"{}\",\"constraints\":{},\"variables\":{},\"public_inputs\":{},\"domain\":{},\"source_revision\":\"{}\"",
        hex::encode(r1cs.digest()),
        r1cs.num_constraints,
        r1cs.num_instance + r1cs.num_witness,
        r1cs.num_instance - 1,
        r1cs.domain_size(),
        REVISION.unwrap_or("unknown"),
    )
}

/// Reads a response and checks it against the genesis key: the delta update,
/// every H and L point by a randomized batch pairing check, and all other
/// sections byte for byte. Returns the contributed key.
fn check_response(dir: &Path, response: &Path) -> ProvingKey<Bn254> {
    let mut pk = ProvingKey::<Bn254>::deserialize_with_mode(
        BufReader::new(File::open(dir.join("genesis.pk")).unwrap()),
        Compress::No,
        Validate::No,
    )
    .unwrap();
    let mut r = BufReader::new(File::open(response).unwrap());
    assert_eq!(read_g1(&mut r), pk.vk.alpha_g1);
    assert_eq!(read_g1(&mut r), pk.beta_g1);
    assert_eq!(read_g2(&mut r), pk.vk.beta_g2);
    assert_eq!(read_g2(&mut r), pk.vk.gamma_g2);
    let d1 = read_g1(&mut r);
    let d2 = read_g2(&mut r);
    assert!(!d1.is_zero() && !d2.is_zero());
    assert_ne!(d1, pk.delta_g1);
    assert_eq!(
        Bn254::pairing(d1, pk.vk.delta_g2),
        Bn254::pairing(pk.delta_g1, d2)
    );
    let old_delta2 = pk.vk.delta_g2;
    pk.delta_g1 = d1;
    pk.vk.delta_g2 = d2;
    assert_eq!(count(&mut r), pk.vk.gamma_abc_g1.len());
    for p in &pk.vk.gamma_abc_g1 {
        assert_eq!(read_g1(&mut r), *p);
    }
    let mut seed = [0; 32];
    File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut seed)
        .unwrap();
    let mut check_rng = StdRng::from_seed(seed);
    for points in [&mut pk.h_query, &mut pk.l_query] {
        assert_eq!(count(&mut r), points.len());
        let mut before = G1Projective::default();
        let mut after = G1Projective::default();
        for chunk in points.chunks_mut(16384) {
            let scalars: Vec<_> = (0..chunk.len()).map(|_| Fr::rand(&mut check_rng)).collect();
            before += G1Projective::msm_unchecked(chunk, &scalars);
            for p in chunk.iter_mut() {
                *p = read_g1(&mut r);
            }
            after += G1Projective::msm_unchecked(chunk, &scalars);
        }
        assert_eq!(
            Bn254::pairing(before, old_delta2),
            Bn254::pairing(after, d2),
            "inconsistent query update"
        );
    }
    for points in [&pk.a_query, &pk.b_g1_query] {
        assert_eq!(count(&mut r), points.len());
        for p in points {
            assert_eq!(read_g1(&mut r), *p);
        }
    }
    assert_eq!(count(&mut r), pk.b_g2_query.len());
    // Fixed sections are compared byte-for-byte without repeating subgroup checks.
    for p in &pk.b_g2_query {
        let mut want = Vec::with_capacity(128);
        g2(&mut want, p);
        let mut got = [0; 128];
        r.read_exact(&mut got).unwrap();
        assert_eq!(got.as_slice(), want);
    }
    pk
}

/// Proves the genuine fixture with `pk`, verifies it, and checks that a
/// changed statement is rejected.
fn prove_fixture(pk: &ProvingKey<Bn254>, native: bool) -> (Vec<u8>, (u128, u128)) {
    let mut rng = StdRng::seed_from_u64(1);
    let (proof, (hi, lo)) = if native {
        (
            mirage_prover::streaming::prove(
                pk,
                KeccacheckNativeCircuit::prove(NativeBounds::default(), fixture::genuine()),
                &mut rng,
            )
            .unwrap(),
            mirage_relation::native::public_signals(&fixture::genuine()),
        )
    } else {
        (
            mirage_prover::streaming::prove(
                pk,
                KeccacheckReceiptCircuit::prove(
                    Bounds::default(),
                    mirage_relation::fixture::genuine(),
                ),
                &mut rng,
            )
            .unwrap(),
            mirage_relation::public_signals(&mirage_relation::fixture::genuine()),
        )
    };
    assert!(Groth16::<Bn254>::verify(&pk.vk, &[Fr::from(hi), Fr::from(lo)], &proof).unwrap());
    assert!(
        !Groth16::<Bn254>::verify(&pk.vk, &[Fr::from(hi) + Fr::from(1), Fr::from(lo)], &proof)
            .unwrap()
    );
    let words = mirage_prover::proof_points(&proof)
        .map(|v| format!("\"0x{}\"", hex::encode(v)))
        .join(",");
    (
        format!("{{\"proof\":[{words}],\"publicSignals\":[\"0x{hi:032x}\",\"0x{lo:032x}\"]}}")
            .into_bytes(),
        (hi, lo),
    )
}

fn verifier(pk: &ProvingKey<Bn254>) -> String {
    use taceo_groth16_sol::{askama::Template, SolidityVerifierConfig, SolidityVerifierContext};
    SolidityVerifierContext {
        vk: pk.vk.clone(),
        config: SolidityVerifierConfig::default(),
    }
    .render()
    .unwrap()
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let usage = "ceremony export DIRECTORY PTAU | check|verify|finalize DIRECTORY RESPONSE | digest | insecure-ptau FILE POWER | revision";
    assert!(args.len() >= 2, "{usage}");
    if args[1] == "revision" {
        println!("{}", REVISION.unwrap_or("unknown"));
        return;
    }
    if args[1] == "insecure-ptau" {
        assert_eq!(args.len(), 4, "{usage}");
        let power: u32 = args[3].parse().unwrap();
        let mut rng = StdRng::seed_from_u64(0);
        let powers = Powers::from_secrets(
            1 << power,
            Fr::rand(&mut rng),
            Fr::rand(&mut rng),
            Fr::rand(&mut rng),
        );
        let mut out = BufWriter::new(File::create(&args[2]).unwrap());
        ceremony::write_ptau(&mut out, &powers, power).unwrap();
        out.flush().unwrap();
        return;
    }
    let circuit = std::env::var("CEREMONY_CIRCUIT").unwrap_or_else(|_| "native-keccacheck".into());
    assert!(
        matches!(circuit.as_str(), "native-keccacheck" | "erc20-keccacheck"),
        "unsupported circuit"
    );
    let native = circuit == "native-keccacheck";
    if args[1] == "digest" {
        println!("{{{}}}", circuit_json(&circuit, &synthesize(native)));
        return;
    }
    assert!(args.len() == 4, "{usage}");
    let dir = Path::new(&args[2]);
    if args[1] == "export" {
        std::fs::create_dir_all(dir).unwrap();
        let t = Instant::now();
        let r1cs = synthesize(native);
        let synthesis = t.elapsed().as_secs_f64();
        let t = Instant::now();
        let n = r1cs.domain_size();
        let mut ptau = BufReader::new(File::open(&args[3]).unwrap());
        let power = ceremony::ptau_power(&mut ptau).unwrap();
        let powers = ceremony::read_ptau(&mut ptau, n).unwrap();
        drop(ptau);
        let mut seed = [0; 32];
        File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut seed)
            .unwrap();
        ceremony::check_powers(&powers, &mut StdRng::from_seed(seed)).unwrap();
        let ptau_seconds = t.elapsed().as_secs_f64();
        let t = Instant::now();
        let pk = ceremony::genesis(&r1cs, &powers).unwrap();
        drop(powers);
        let setup = t.elapsed().as_secs_f64();
        let t = Instant::now();
        let mut key = BufWriter::new(File::create(dir.join("genesis.pk")).unwrap());
        pk.serialize_uncompressed(&mut key).unwrap();
        key.flush().unwrap();
        let mut out = BufWriter::new(File::create(dir.join("challenge.body")).unwrap());
        g1(&mut out, &pk.vk.alpha_g1);
        g1(&mut out, &pk.beta_g1);
        g2(&mut out, &pk.vk.beta_g2);
        g2(&mut out, &pk.vk.gamma_g2);
        g1(&mut out, &pk.delta_g1);
        g2(&mut out, &pk.vk.delta_g2);
        for points in [
            &pk.vk.gamma_abc_g1,
            &pk.h_query,
            &pk.l_query,
            &pk.a_query,
            &pk.b_g1_query,
        ] {
            array(&mut out, points, |mut w, p| g1(&mut w, p));
        }
        array(&mut out, &pk.b_g2_query, |mut w, p| g2(&mut w, p));
        out.flush().unwrap();
        let result = format!("{{{},\"ptau_power\":{power},\"h_points\":{},\"l_points\":{},\"a_points\":{},\"b1_points\":{},\"b2_points\":{},\"pk_bytes\":{},\"challenge_bytes\":{},\"synthesis_seconds\":{synthesis},\"ptau_seconds\":{ptau_seconds},\"setup_seconds\":{setup},\"export_seconds\":{},\"peak_rss_kib\":{}}}", circuit_json(&circuit, &r1cs), pk.h_query.len(), pk.l_query.len(), pk.a_query.len(), pk.b_g1_query.len(), pk.b_g2_query.len(), pk.uncompressed_size(), std::fs::metadata(dir.join("challenge.body")).unwrap().len()+68, t.elapsed().as_secs_f64(), rss());
        std::fs::write(dir.join("circuit.json"), &result).unwrap();
        println!("{result}");
        return;
    }
    let t = Instant::now();
    let pk = check_response(dir, Path::new(&args[3]));
    let import = t.elapsed().as_secs_f64();
    match args[1].as_str() {
        "verify" => {
            println!("{{\"all_query_updates_batch_checked\":true,\"fixed_sections_checked\":true,\"import_seconds\":{import},\"peak_rss_kib\":{}}}", rss());
        }
        "check" => {
            let t = Instant::now();
            let (proof, _) = prove_fixture(&pk, native);
            let prove = t.elapsed().as_secs_f64();
            std::fs::write(dir.join("Verifier.sol"), verifier(&pk)).unwrap();
            std::fs::write(dir.join("proof.json"), proof).unwrap();
            let result = format!("{{\"proof_verified\":true,\"wrong_statement_rejected\":true,\"all_query_updates_batch_checked\":true,\"import_seconds\":{import},\"prove_seconds\":{prove},\"peak_rss_kib\":{}}}", rss());
            println!("{result}");
            std::fs::write(dir.join("interop.json"), result).unwrap();
        }
        "finalize" => {
            let out = dir.join("final");
            std::fs::create_dir_all(&out).unwrap();
            let (proof, _) = prove_fixture(&pk, native);
            let pk_bytes = mirage_prover::save_proving_key(&pk, false).unwrap();
            let vk_bytes = mirage_prover::serialize_verifying_key(&pk.vk).unwrap();
            let contract = verifier(&pk);
            std::fs::write(out.join("final.pk"), &pk_bytes).unwrap();
            std::fs::write(out.join("final.vk"), &vk_bytes).unwrap();
            std::fs::write(out.join("Verifier.sol"), &contract).unwrap();
            std::fs::write(out.join("proof.json"), proof).unwrap();
            let result = format!("{{\"circuit\":\"{circuit}\",\"proof_verified\":true,\"wrong_statement_rejected\":true,\"proving_key\":{{\"file\":\"final.pk\",\"compressed\":false,\"keccak256\":\"{}\"}},\"verifying_key\":{{\"file\":\"final.vk\",\"compressed\":false,\"keccak256\":\"{}\"}},\"verifier\":{{\"file\":\"Verifier.sol\",\"keccak256\":\"{}\"}},\"source_revision\":\"{}\"}}", keccak256(&pk_bytes), keccak256(&vk_bytes), keccak256(contract.as_bytes()), REVISION.unwrap_or("unknown"));
            std::fs::write(out.join("keys.json"), &result).unwrap();
            println!("{result}");
        }
        _ => panic!("{usage}"),
    }
}
