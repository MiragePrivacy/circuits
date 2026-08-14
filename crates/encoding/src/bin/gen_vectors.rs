//! Writes the deterministic vectors in `test/vectors/`, spec 19.1.
//!
//! These are the authority the Solidity encoder is checked against. Both files
//! carry the packed preimage alongside the digest, so a mismatch identifies
//! whether the disagreement is in the packing or the hash without bisecting.
//!
//! Regenerate after any encoding change:
//!
//!     cargo run -p mirage-encoding --bin gen-vectors

use mirage_encoding::vectors::{
    intent_cases, statement_cases, Case, IntentVector, StatementVector, VectorFile,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test/vectors");
    std::fs::create_dir_all(&out)?;

    let intents = VectorFile {
        spec_section: "8.3",
        description: "Intent commitment: 226-byte packed preimage and its keccak-256 digest",
        cases: intent_cases()
            .iter()
            .map(|(name, description, intent)| {
                let v = IntentVector::from(intent);
                Case { name, description, input: v.input, expected: v.expected }
            })
            .collect(),
    };
    let path = out.join("commitment.json");
    std::fs::write(&path, serde_json::to_string_pretty(&intents)? + "\n")?;
    println!("{} cases -> {}", intents.cases.len(), path.display());

    // Statement cases bind a commitment, so use the first intent case's digest
    // rather than a placeholder: the vectors then chain the way the real
    // protocol does.
    let commitment = intent_cases()[0].2.commitment();
    let statements = VectorFile {
        spec_section: "10.2",
        description: "Statement hash: 285-byte packed preimage, digest, and the two public signals",
        cases: statement_cases(commitment)
            .iter()
            .map(|(name, description, statement)| {
                let v = StatementVector::from(statement);
                Case { name, description, input: v.input, expected: v.expected }
            })
            .collect(),
    };
    let path = out.join("statement.json");
    std::fs::write(&path, serde_json::to_string_pretty(&statements)? + "\n")?;
    println!("{} cases -> {}", statements.cases.len(), path.display());

    Ok(())
}
