# Escrow integration

The escrow must construct the statement from authenticated chain state and its
own row/lease state. It must not accept a caller-chosen public-input array.
The circuit verifies private header, trie and payment data against that statement.

## Statement ABI

`crates/encoding/src/statement.rs` defines the 285-byte packed preimage, in order:

```text
relationVersion:u8, instanceDomain:bytes32, chainId:uint256, escrow:address,
requestId:bytes32, rowIndex:u32, intentCommitment:bytes32, bondAttempt:u32,
bondStartBlock:u64, bondDeadline:u64, bondedCollector:address,
rowPayoutAsset:address, rowPayoutAmount:uint256, witnessBlockNumber:u64,
witnessBlockHash:bytes32
```

Integers are big-endian. The public inputs are the high and low 128-bit limbs
of Keccak-256 of the preimage, in that order. The Rust context currently accepts
a `u64` chain ID and left-pads it to the ABI's 32-byte field.

Derive `witnessBlockHash` from `blockhash(witnessBlockNumber)` and reject an
unavailable or inadmissible block. The circuit binds the header hash and checks
`bondStartBlock < header.number <= bondDeadline`. Lease fields are block numbers.
Bind row payout asset/amount independently of the hidden settlement asset/amount.
Increment the bond-attempt replay tag across lease attempts.

## Proof and verifier artifacts

`contracts/Verifier.sol` and `contracts/NativeVerifier.sol` are generated from
the respective circuit keys. `mirage_prover::proof_points` defines Solidity
proof serialization, including the G2 coordinate ordering. Use the generated
proof JSON/calldata fixtures for differential tests rather than repacking by hand.
The standalone verifier can be embedded in the escrow where the protocol
requires no shared verifier contract.

Regenerate artifacts with the commands in [README.md](README.md) after a
constraint change. Prover, loaded keys and embedded verifier must identify the
same circuit. Historical gas figures belong to their original verifier/compiler
configuration and are not current deployment measurements.

## Integration checks

- Compare intent and statement packing against the deterministic vectors.
- Accept matching native/ERC-20 proofs; reject modified proof points or signals.
- Reject wrong row, escrow, domain, lease attempt, collector and payout context.
- Reject unavailable block hashes and invalid witness/lease windows.
- Exercise the payment-uniqueness policy and keep it distinct from proof validity.

The relations prove exact-block settlement; delayed-witness ancestry is absent.
See [security requirements](FINDINGS.md). This file specifies the circuit-facing
contract, not the deployment status of the separate escrow repository.
