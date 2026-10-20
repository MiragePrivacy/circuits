# Backend rationale and security requirements

## Backend decision

The implementation uses Rust arkworks Groth16 over BN254: a compact proof,
Solidity pairing verification, and a Rust proving path suitable for the enclave
integration. The August 2026 investigation compared Circom/snarkjs, zkVMs,
halo2 and gnark against verifier size/gas, proving cost and Rust enclave needs.
Those historical assessments are not current ecosystem compatibility claims.

The original synthetic benchmark measured about 21 seconds for three million
multiplication constraints at 16 threads, with 9-26% end-to-end improvements
from BMI2/ADX in the tested cases. These are backend calibration results, not
current relation performance. See [the raw-data report](bench-arkworks/RESULTS.md)
and [current benchmark status](BENCHMARKS.md).

Direct Boolean Keccak costs 153,600 constraints per permutation, plus 1,600 for
independently allocated input bits. Batching with Keccacheck amortizes the GKR
verifier across the relation's hashes. The transcript adaptation still requires
cryptographic review; fewer constraints alone do not establish soundness.

## Security requirements

- Bind the full intent and statement context, including domain, chain, escrow,
  request, row, lease attempt, collector and payout. Test mutations of every
  field; placeholder witness values can hide missing bindings.
- Treat layout hints, offsets and occupancy bits as untrusted witnesses. Range
  checks and one-hot in-range assertions must bind every dynamic read.
- Authenticate the header through the escrow-selected Ethereum block hash
  before relying on consensus canonicality for specialized parsing.
- Keep every MPT link, key-path match and terminal value binding in-circuit.
  Test genuine branch, extension and singleton shapes as well as mutations.
- Enforce minimal integer encoding, empty native calldata, successful status,
  recipient/value equality and the correct asset kind.
- Regenerate keys and verifier fixtures whenever constraints change. Seeded
  circuit-specific setup is only a development stand-in for a reviewed ceremony.

## Release gates

1. Review the Poseidon2-derived output challenge and transcript domain separation
   described in the [Keccacheck notes](experiments/keccacheck-arkworks/README.md).
2. Establish the operational payment-uniqueness policy. The statement does not
   bind transaction identity or sender; a matching payment can satisfy multiple
   identical intents, and a third-party payment can match. Rejecting duplicate
   live intents addresses reuse across those intents, not payer attribution.
3. Implement delayed-witness ancestry if settlement-block privacy is required.
4. Establish native/ERC-20 timing privacy; their separate keys and constraint
   counts do not provide it.
5. Measure a representative latency distribution and memory on target SGX
   hardware. A few host samples cannot establish enclave p95.

Detailed development chronology and superseded projections remain in Git
history before this cleanup. Keep new measurements in BENCHMARKS.md with their
revision, command, environment and raw evidence.
