//! Exports the Solidity verifier the escrow embeds, and a proof to test it.
//!
//! ```sh
//! cargo run -p mirage-prover --release --bin export-verifier
//! ```
//!
//! Writes three artifacts to `contracts/`:
//!
//! - `Verifier.sol` — the verifier contract, rendered from gnark's template
//! - `proof.json` — a real proof and its two public signals
//! - `calldata.txt` — the exact `verifyProof` arguments
//!
//! # Why this closes a gap
//!
//! Spec 15.1 requires each escrow embed its own verifier with no external call.
//! Every size and gas figure recorded for that verifier so far came from an
//! independent build during the backend evaluation, not from this circuit. This
//! produces the actual contract for the actual verification key, so the size
//! can be compiled and measured rather than inherited.

use std::path::PathBuf;

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use taceo_groth16_sol::{SolidityVerifierConfig, SolidityVerifierContext};

use mirage_relation::{fixture, public_signals, Bounds, ReceiptCircuit};

fn main() {
    // CARGO_MANIFEST_DIR is `crates/prover`, so reaching the repo's
    // `contracts/` takes two levels up, not one.
    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts");
    std::fs::create_dir_all(&out).expect("create contracts/");

    let bounds = Bounds::default();
    let witness = fixture::genuine();

    // Setup. This is `circuit_specific_setup`, a toy: spec 18.2 requires a
    // multiparty Phase 2 producing the same artifact soundly. The verifier
    // rendered below is structurally identical either way, so the size and gas
    // measurements hold; only the key's provenance differs.
    eprintln!("setup...");
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0);
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(ReceiptCircuit::setup(bounds), &mut rng)
        .expect("setup");

    // The contract.
    eprintln!("rendering verifier...");
    let contract = render(&vk);
    let sol_path = out.join("Verifier.sol");
    std::fs::write(&sol_path, &contract).expect("write Verifier.sol");
    eprintln!(
        "  {} ({} bytes of Solidity)",
        sol_path.display(),
        contract.len()
    );

    // A real proof, so the contract can be exercised rather than merely
    // compiled.
    eprintln!("proving...");
    let proof = Groth16::<Bn254>::prove(&pk, ReceiptCircuit::prove(bounds, witness.clone()), &mut rng)
        .expect("prove");
    let (hi, lo) = public_signals(&witness);

    // Verify natively first: a contract test that fails is ambiguous unless the
    // proof is known good.
    assert!(
        Groth16::<Bn254>::verify(&vk, &[Fr::from(hi), Fr::from(lo)], &proof).expect("verify"),
        "the proof does not verify natively; the Solidity test would be meaningless"
    );

    let json = proof_json(&proof, hi, lo, &witness);
    std::fs::write(out.join("proof.json"), &json).expect("write proof.json");

    let calldata = calldata(&proof, hi, lo);
    std::fs::write(out.join("calldata.txt"), &calldata).expect("write calldata.txt");

    eprintln!("\n{}", calldata);
    eprintln!("Next: compile Verifier.sol with solc and call verifyProof with the above.");
    eprintln!("A Foundry test lives in ../../test/VerifierTest.sol.");
}

/// Renders the verifier contract for `vk`.
///
/// Direct: the workspace and `taceo-groth16-sol` both build against
/// `ark-groth16` 0.6, so the verifying key needs no conversion.
fn render(vk: &VerifyingKey<Bn254>) -> String {
    use taceo_groth16_sol::askama::Template;
    SolidityVerifierContext {
        vk: vk.clone(),
        config: SolidityVerifierConfig::default(),
    }
    .render()
    .expect("render template")
}

/// The proof as the eight field elements the Solidity verifier expects.
///
/// # Why this reads coordinates rather than serialized bytes
///
/// An earlier version serialized each point and sliced the buffer, which
/// required knowing arkworks' byte order, its endianness, and where each
/// coordinate sits. Three assumptions, each invisible when wrong: the contract
/// simply rejects every valid proof.
///
/// Reading `x` and `y` off the affine point and converting through `BigUint`
/// removes all three. `BigUint::to_bytes_be` is unambiguous, and the field
/// elements are what the precompile consumes.
///
/// The one convention that remains is G2 coordinate order: the EVM pairing
/// precompile takes `(x.c1, x.c0, y.c1, y.c0)`, confirmed against the generated
/// verifier's assembly, which stores `X_1` before `X_0`.
fn proof_points(proof: &Proof<Bn254>) -> [String; 8] {
    use ark_ff::PrimeField;
    use num_bigint::BigUint;

    let fq = |v: ark_bn254::Fq| -> String {
        let n: BigUint = v.into_bigint().into();
        let mut be = n.to_bytes_be();
        // Left-pad to a full 32-byte word.
        while be.len() < 32 {
            be.insert(0, 0);
        }
        format!("0x{}", hex::encode(be))
    };

    [
        fq(proof.a.x),
        fq(proof.a.y),
        // G2 coordinates are in Fq2; the precompile wants c1 before c0.
        fq(proof.b.x.c1),
        fq(proof.b.x.c0),
        fq(proof.b.y.c1),
        fq(proof.b.y.c0),
        fq(proof.c.x),
        fq(proof.c.y),
    ]
}

fn proof_json(proof: &Proof<Bn254>, hi: u128, lo: u128, w: &mirage_relation::Witness) -> String {
    let p = proof_points(proof);
    let s = &w.statement;
    let hx = |b: &[u8]| format!("0x{}", hex::encode(b));
    format!(
        r#"{{
  "proof": [
    "{}", "{}",
    "{}", "{}", "{}", "{}",
    "{}", "{}"
  ],
  "publicSignals": ["0x{:032x}", "0x{:032x}"],
  "statement": {{
    "instanceDomain": "{}",
    "chainId": {},
    "escrow": "{}",
    "requestId": "{}",
    "rowIndex": {},
    "intentCommitment": "{}",
    "bondAttempt": {},
    "bondStartBlock": {},
    "bondDeadline": {},
    "bondedCollector": "{}",
    "rowPayoutAsset": "{}",
    "rowPayoutAmount": "{}",
    "witnessBlockNumber": {},
    "witnessBlockHash": "{}"
  }},
  "note": "proof is [a.x, a.y, b.x1, b.x0, b.y1, b.y0, c.x, c.y]; the EVM pairing precompile takes G2 coordinates in that order, which is the reverse of arkworks' serialization. The statement block is what the escrow must reproduce from its own state for this proof to verify against it."
}}
"#,
        p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], hi, lo,
        hx(&s.instance_domain),
        s.chain_id,
        hx(&s.escrow),
        hx(&s.request_id),
        s.row_index,
        hx(&s.intent_commitment),
        s.bond_attempt,
        s.bond_start_block,
        s.bond_deadline,
        hx(&s.bonded_collector),
        hx(&s.row_payout_asset),
        hx(&s.row_payout_amount),
        s.witness_block_number,
        hx(&s.witness_block_hash),
    )
}

fn calldata(proof: &Proof<Bn254>, hi: u128, lo: u128) -> String {
    let p = proof_points(proof);
    format!(
        "verifyProof(\n  [{}, {}],\n  [[{}, {}], [{}, {}]],\n  [{}, {}],\n  [0x{:032x}, 0x{:032x}]\n)",
        p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], hi, lo
    )
}
