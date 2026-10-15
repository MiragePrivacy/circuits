//! Exports the Solidity verifier the escrow embeds, and a proof to test it.
//!
//! ```sh
//! cargo run -p mirage-prover --release --bin export-verifier
//! cargo run -p mirage-prover --release --bin export-verifier -- --keccachecheck
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

use ark_bn254::Bn254;
use ark_groth16::VerifyingKey;
use taceo_groth16_sol::{SolidityVerifierConfig, SolidityVerifierContext};

use mirage_relation::{fixture, Bounds};
fn main() {
    let keccachecheck = std::env::args().any(|arg| arg == "--keccachecheck");
    // CARGO_MANIFEST_DIR is `crates/prover`, so reaching the repo's

    // `contracts/` takes two levels up, not one.
    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts");
    std::fs::create_dir_all(&out).expect("create contracts/");

    let bounds = Bounds::default();
    let mut witness = fixture::genuine();
    if std::env::args().any(|arg| arg == "--gas-sim") {
        witness.statement.bond_deadline = witness.statement.bond_start_block + 75;
    }

    let batch_row = std::env::args().any(|arg| arg == "--batch-row");
    if batch_row {
        assert!(keccachecheck, "batch fixtures require Keccacheck");
        witness.statement.bond_start_block = 20_999_990;
        witness.statement.bond_deadline = witness.statement.bond_start_block + 75;
        witness.statement.witness_block_number = 20_999_999;
        witness.header = fixture::header_with_roots(
            &[0x44; 32],
            &witness.root.clone().try_into().expect("receipt root"),
            witness.statement.witness_block_number,
        );
        witness.statement.witness_block_hash = fixture::keccak(&witness.header);
        witness.intent.row_index = 1;
        witness.statement.row_index = 1;
        let i = &witness.intent;
        witness.statement.intent_commitment = mirage_encoding::commitment::Intent {
            instance_domain: i.instance_domain,
            chain_id: i.chain_id,
            escrow: i.escrow,
            request_id: i.request_id,
            row_index: i.row_index,
            asset_kind: mirage_encoding::AssetKind::Erc20,
            settlement_token: i.settlement_token,
            recipient: i.recipient,
            settlement_amount: i.settlement_amount,
            salt: i.salt,
        }
        .commitment();
    }

    // Setup. This is `circuit_specific_setup`, a toy: spec 18.2 requires a
    // multiparty Phase 2 producing the same artifact soundly. The verifier
    // rendered below is structurally identical either way, so the size and gas
    // measurements hold; only the key's provenance differs.
    eprintln!("setup...");
    let keys = if keccachecheck {
        mirage_prover::setup_keccacheck(bounds, 0).expect("Keccacheck setup")
    } else {
        mirage_prover::setup(bounds, 0).expect("setup")
    };

    // The contract.
    eprintln!("rendering verifier...");
    let contract = render(&keys.vk);
    let sol_path = out.join("Verifier.sol");
    std::fs::write(&sol_path, &contract).expect("write Verifier.sol");
    eprintln!(
        "  {} ({} bytes of Solidity)",
        sol_path.display(),
        contract.len()
    );

    // A real proof, so the contract can be exercised rather than merely
    // compiled. `prove` verifies natively before returning: a contract test
    // that fails is ambiguous unless the proof is known good.
    eprintln!("proving...");
    let settlement = if keccachecheck {
        mirage_prover::prove_keccacheck_seeded(&keys, bounds, &witness, 0)
            .expect("Keccacheck prove")
    } else {
        mirage_prover::prove_seeded(&keys, bounds, &witness, 0).expect("prove")
    };
    let [hi, lo] = settlement.signals;

    let json = proof_json(&settlement.proof, hi, lo, &witness);
    std::fs::write(
        out.join(if batch_row {
            "batch_row_proof.json"
        } else {
            "proof.json"
        }),
        &json,
    )
    .expect("write proof.json");

    let calldata = calldata(&settlement.proof, hi, lo);
    std::fs::write(
        out.join(if batch_row {
            "batch_row_calldata.txt"
        } else {
            "calldata.txt"
        }),
        &calldata,
    )
    .expect("write calldata.txt");

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

fn proof_json(proof: &[[u8; 32]; 8], hi: u128, lo: u128, w: &mirage_relation::Witness) -> String {
    let p = proof.map(|w| format!("0x{}", hex::encode(w)));
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
        p[0],
        p[1],
        p[2],
        p[3],
        p[4],
        p[5],
        p[6],
        p[7],
        hi,
        lo,
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

fn calldata(proof: &[[u8; 32]; 8], hi: u128, lo: u128) -> String {
    let p = proof.map(|w| format!("0x{}", hex::encode(w)));
    format!(
        "verifyProof(\n  [{}, {}],\n  [[{}, {}], [{}, {}]],\n  [{}, {}],\n  [0x{:032x}, 0x{:032x}]\n)",
        p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], hi, lo
    )
}
