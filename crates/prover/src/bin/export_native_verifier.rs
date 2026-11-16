//! Exports the Solidity verifier the native escrow embeds, and a proof to test it.
//!
//! ```sh
//! cargo run -p mirage-prover --release --features export --bin export-native-verifier
//! ```
//!
//! Writes three artifacts to `contracts/`:
//!
//! - `NativeVerifier.sol` — the verifier contract for the native relation
//! - `native_proof.json` — a real native proof and its two public signals
//! - `native_calldata.txt` — the exact `verifyProof` arguments
//!
//! # Why a second verifier
//!
//! Groth16's verifying key is derived from the constraint system, so the native
//! relation's key differs from the ERC-20 relation's and a proof from one does
//! not verify against the other. An escrow embeds whichever verifier matches
//! the asset it settles (spec 15.1 requires embedding rather than calling), so
//! the two contracts are separate artifacts rather than one shared deployment.
//!
//! The generator names every contract it renders `Verifier`, which would
//! collide with the ERC-20 one in the same compilation unit. It is renamed here
//! rather than in the escrow repo so the vendored copy needs no hand editing.

mod export_common;

use ark_bn254::Bn254;
use ark_groth16::VerifyingKey;
use taceo_groth16_sol::{SolidityVerifierConfig, SolidityVerifierContext};

use mirage_relation::native::{fixture, NativeBounds, NativeWitness};

fn main() {
    // CARGO_MANIFEST_DIR is `crates/prover`, so reaching the repo's
    // `contracts/` takes two levels up, not one.
    let out = export_common::output_dir();
    std::fs::create_dir_all(&out).expect("create contracts/");

    let bounds = NativeBounds::default();
    let mut witness = fixture::genuine();
    if std::env::args().any(|arg| arg == "--gas-sim") {
        let escrow: [u8; 20] = hex::decode("1c81a61a407017c58397a47d2ab28191b9b8ec9b")
            .unwrap()
            .try_into()
            .unwrap();
        witness.intent.escrow = escrow;
        witness.statement.escrow = escrow;
        witness.statement.bond_start_block = 20_999_990;
        witness.statement.bond_deadline = witness.statement.bond_start_block + 75;
        let i = &witness.intent;
        witness.statement.intent_commitment = mirage_encoding::commitment::Intent {
            instance_domain: i.instance_domain,
            chain_id: i.chain_id,
            escrow: i.escrow,
            request_id: i.request_id,
            row_index: i.row_index,
            asset_kind: mirage_encoding::AssetKind::Native,
            settlement_token: i.settlement_token,
            recipient: i.recipient,
            settlement_amount: i.settlement_amount,
            salt: i.salt,
        }
        .commitment();
    }

    // Setup. As with the ERC-20 export this is `circuit_specific_setup`, a toy:
    // spec 18.2 requires a multiparty Phase 2 producing the same artifact
    // soundly. The verifier rendered below is structurally identical either
    // way, so size and gas measurements hold; only the key's provenance differs.
    eprintln!("setup (native Keccacheck)...");
    let keys = export_common::ceremony_keys()
        .unwrap_or_else(|| mirage_prover::native::setup_keccacheck(bounds, 0).expect("setup"));

    eprintln!("rendering verifier...");
    let contract = render(&keys.vk);
    let sol_path = out.join("NativeVerifier.sol");
    std::fs::write(&sol_path, &contract).expect("write NativeVerifier.sol");
    eprintln!(
        "  {} ({} bytes of Solidity)",
        sol_path.display(),
        contract.len()
    );

    // A real proof, so the contract can be exercised rather than merely
    // compiled. `prove` verifies natively before returning: a contract test
    // that fails is ambiguous unless the proof is known good.
    eprintln!("proving...");
    let settlement =
        mirage_prover::native::prove_keccacheck_seeded(&keys, bounds, &witness, 0).expect("prove");
    let [hi, lo] = settlement.signals;

    std::fs::write(
        out.join("native_proof.json"),
        proof_json(&settlement.proof, hi, lo, &witness),
    )
    .expect("write native_proof.json");

    let calldata = calldata(&settlement.proof, hi, lo);
    std::fs::write(out.join("native_calldata.txt"), &calldata).expect("write native_calldata.txt");

    eprintln!("\n{}", calldata);
    eprintln!("Next: compile NativeVerifier.sol with solc and call verifyProof with the above.");
}

/// Renders the verifier contract for `vk`, renamed so it can sit alongside the
/// ERC-20 verifier.
fn render(vk: &VerifyingKey<Bn254>) -> String {
    use taceo_groth16_sol::askama::Template;
    let rendered = SolidityVerifierContext {
        vk: vk.clone(),
        config: SolidityVerifierConfig::default(),
    }
    .render()
    .expect("render template");

    let renamed = rendered.replace("contract Verifier {", "contract NativeVerifier {");
    assert_ne!(
        renamed, rendered,
        "generator no longer emits `contract Verifier {{`; the rename must be updated"
    );
    renamed
}

fn proof_json(proof: &[[u8; 32]; 8], hi: u128, lo: u128, w: &NativeWitness) -> String {
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
  "note": "native-ETH relation. proof is [a.x, a.y, b.x1, b.x0, b.y1, b.y0, c.x, c.y]; the EVM pairing precompile takes G2 coordinates in that order, which is the reverse of arkworks' serialization. The statement block is what the escrow must reproduce from its own state for this proof to verify against it."
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
