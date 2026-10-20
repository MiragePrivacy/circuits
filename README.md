# Mirage settlement circuits

Rust/arkworks Groth16 circuits over BN254 for ERC-20 and native ETH settlement.
Both expose two 128-bit limbs of a statement hash. Keccacheck verifies a batched
Keccak computation inside the circuit; the on-chain interface remains one
Groth16 proof.

The relations authenticate the exact transaction block. Delayed-witness ancestry
and equal-cost native/ERC-20 proving remain release gates. Seeded setup and
checked-in proof artifacts are development fixtures, not a production ceremony.

## Documentation

- [Native relation and compiled bounds](NATIVE_ETH_STACK.md)
- [Benchmarks, provenance, and reproduction](BENCHMARKS.md)
- [Escrow integration contract](ESCROW_INTEGRATION.md)
- [Backend rationale and security requirements](FINDINGS.md)
- [Keccacheck protocol and review items](experiments/keccacheck-arkworks/README.md)
- [Test vectors](test/vectors/README.md)

## Layout

| Path | Purpose |
|---|---|
| `crates/encoding` | Native commitment/statement encoders and deterministic vectors |
| `crates/gadgets` | Keccak, byte operations, RLP, MPT, receipt and transaction gadgets |
| `crates/relation` | ERC-20 receipt and native dual-trie relations |
| `crates/prover` | Setup, proving, key loading, Solidity export and measurements |
| `crates/sgx-bench` | Host/enclave proof strategies and matrix census |
| `crates/fixtures` | Mainnet collection and trie reconstruction |
| `contracts`, `test` | Generated verifiers, proofs and Foundry tests |
| `experiments/keccacheck-arkworks` | Pinned GKR backend and standalone comparison |
| `bench-arkworks` | Historical synthetic backend benchmark |

## Development

```sh
nix develop
cargo test --release
```

The dev shell enables BMI2/ADX field arithmetic. Mainnet fixture tests build a
constraint system per case and can take minutes. `FIXTURE_JOBS` controls their
parallelism; they print per-fixture progress. Run ignored gadget tests after
changing Keccak padding or state selection:

```sh
cargo test -p mirage-gadgets --release -- --ignored
```

Constraint-system changes require matching proving keys, verification keys,
Solidity verifiers and proof fixtures. Regenerate both affected relations:

```sh
cargo run -p mirage-prover --release --bin export-verifier
cargo run -p mirage-prover --release --bin export-native-verifier
forge test --match-path test/VerifierTest.sol -vv
```

Foundry must be available separately. A passing test against old checked-in
proofs does not validate a changed circuit. Keep encoder, circuit, and Solidity
packing tests consistent; resolve disagreements against the protocol encoding.
