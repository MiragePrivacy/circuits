# Native ETH with Keccacheck

## Structural optimizations (2026-09-22)

The native circuit now applies the base circuit's authenticated header prefix,
constructed terminal leaves, structural ancestor bounds, and universal depth
seven to **both** tries. The transaction parser also shares one canonical RLP
walk across legacy, EIP-2930, and EIP-1559 layouts, decoding at most 12 items
instead of speculatively decoding 9 + 11 + 12 items and duplicate outer lists.

| Base technique | Native implementation |
|---|---|
| Authenticated header prefix (3b7b1a6) | Read both roots and block number at fixed offsets; retain the full header hash check. |
| Constructed terminal leaf (c7ef300) | Construct both leaves from authenticated values and key remainders; support short transactions and all RLP length transitions. |
| Structural ancestor buffers / universal depth (da4f097) | 308-byte root and 532-byte deeper ancestors; six ancestors plus one constructed leaf per trie. |
| Specialized receipt layout (1671ecd) | ERC-20 sole-Transfer layout does not apply; share native transaction decoding across the three supported layouts instead. |
| Structural 448-byte receipt limit (902ad3e) | Keep native receipts at 512 bytes: empty calldata can still invoke a receiver that emits logs. Keep the general status/receipt parser. |
| One-hot read fix (b5192b4) | Already inherited by shared gadgets. |
| Batched Keccacheck / reproducible proving | Retained, with one batch shared by all native hashes. |

The ERC-20 leaf path remains unchanged. The new general-value leaf encoder
handles bare RLP bytes, short strings, one-byte lengths, and two-byte lengths.
The existing proof-node API still includes the terminal node for compatibility;
its bytes are redundant because the circuit constructs the leaf. Prover bounds
check only witnessed ancestors against their actual compiled bounds.

Default transaction and receipt buffers remain 512 bytes, keys 3 bytes, headers
704 bytes. Both trie depths increase from 4 to 7, sufficient for six nibbles.
Setup and proving use the same fixed shape, independent of actual path depth.

| Metric | Previous native port | Optimized native |
|---|---:|---:|
| Constraints, Keccacheck | 11,620,286 | 7,327,757 |
| Constraints, direct control | 17,635,451 | 15,257,357 |
| Trie depth, each | 4 | 7 |
| Recorded / padded permutations | 51 / 64 | 65 / 128 |

This is **36.9% fewer constraints than the previous native Keccacheck port**, with
broader trie capacity. The 65 permutations comprise commitment 2, header 6,
transaction ancestors 23 + leaf 4, receipt ancestors 23 + leaf 4, statement 3.
The new shape requires a new native proving key and verifier; the Groth16
statement ABI is unchanged.

The native APIs remain `setup_keccacheck`, `prove_keccacheck`, and
`prove_keccacheck_seeded`. Seeded helpers are for reproducible tests/artifacts.

## Historical batching-only port

The following records the earlier depth-four implementation and its benchmark.
It is retained as historical evidence, not the current circuit shape.

## Host benchmark (2026-09-16 UTC)

Implementation commit: `948ff19dfa189638742fcb17e08ce5360e045cc2`.
Intel Core i9-14900HX, 16 Rayon threads, release build with the flake's
`-C target-feature=+bmi2,+adx` flags. The direct and Keccacheck runs used
the same executable, bounds, fixture, setup seed, and three proof seeds.
They ran sequentially in fresh processes after the build and validation jobs
finished. CPU affinity and background desktop activity were not controlled.

| Metric | Native direct Keccak | Native Keccacheck |
|---|---:|---:|
| Constraints | 17,635,451 | 11,620,286 |
| Setup | 69.828 s | 65.899 s |
| Proof 1 | 42.905 s | 46.035 s |
| Proof 2 | 44.871 s | 45.439 s |
| Proof 3 | 45.792 s | 44.071 s |
| **Median proving, including self-verification** | **44.871 s** | **45.439 s** |
| Proving key, uncompressed | 7.168 GiB | 4.378 GiB |
| Proving key, compressed | 3.584 GiB | 2.189 GiB |
| Peak RSS after setup | 14.216 GiB | 16.819 GiB |
| **Peak process RSS across count/setup/three proofs** | **27.272 GiB** | **24.831 GiB** |

All six proofs verified. Constraint count falls 34.1%, uncompressed key size
38.9%, and overall peak RSS 9.0%. These samples show no proving-latency
improvement: the observed median is 1.3% higher. Three host samples do not
establish a latency distribution, p95, or SGX hardware performance.

The profiles explain the limited timing benefit: flattening symbolic linear
combinations (`Inlining LCs`) costs 18.8–20.0 s per Keccacheck proof versus
4.4–5.1 s for direct Keccak. That offsets lower witness-map and curve
multiscalar-multiplication time. Optimizing that expression handling is separate
from the algorithm port measured here.

Raw profiles: [direct](experiments/keccacheck-arkworks/benchmarks/native-direct.log)
and [Keccacheck](experiments/keccacheck-arkworks/benchmarks/native-keccacheck.log).

## Validation

- Native Keccacheck mutation/count suite: 12 passed.
- Five selected mainnet bare sends satisfy the batched circuit at compiled
  bounds, covering legacy/EIP-1559 envelopes and largest/deepest sampled shapes.
- Native proof and regenerated verifier accepted by the escrow's 10 tests;
  ERC-20 escrow regression suite: 9 passed.
- Nomad: 105 regular unit tests, explicit native key/proof integration test,
  Fortanix compile check, and host/Fortanix Clippy checks passed.
- Circuit workspace/all-targets compilation passed. Clippy passed with the
  existing `manual_is_multiple_of` lint allowed in the unchanged constructed
  leaf gadget.

## Reproduction

```sh
# Real native proof plus matching Solidity verifier
RAYON_NUM_THREADS=16 cargo run -p mirage-prover --release --bin export-native-verifier

# Run sequentially in fresh processes on an otherwise idle host.
# Each command measures setup and three proofs, including self-verification.
RAYON_NUM_THREADS=16 cargo run -p mirage-prover --release --bin measure-native -- --direct
RAYON_NUM_THREADS=16 cargo run -p mirage-prover --release --bin measure-native

# Native mutation suite and representative mainnet fixtures through Keccacheck
RAYON_NUM_THREADS=1 cargo test -p mirage-relation --release --lib native::tests -- --test-threads=1
RAYON_NUM_THREADS=1 cargo test -p mirage-relation --release --test mainnet_native keccacheck_covers_mainnet_envelopes_and_deepest_tries -- --nocapture
```

`measure-native` reports the median and individual proof times, key sizes, and
peak process RSS across constraint counting, setup, and proving. This is host
measurement, not SGX hardware latency or proving-only peak memory.

Existing setup, transcript-review, and native-versus-ERC-20 timing/privacy
release gates still apply. See `crates/relation/src/native.rs` and
`experiments/keccacheck-arkworks/RESULTS.md`.
