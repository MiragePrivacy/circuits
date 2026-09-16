# Native ETH with Keccacheck

The native dual-trie circuit now authenticates every Keccak-f permutation with
one private Keccacheck GKR batch inside a single externally verified Groth16
proof. It builds on the optimized ERC-20 branch (circuits PR #2).

## Relation and APIs

`KeccacheckNativeCircuit` shares the native relation with the direct-Keccak
`NativeCircuit` control. A single backend collects hashes from:

| Input | Permutations at compiled bounds |
|---|---:|
| Intent commitment | 2 |
| Authenticated block header | 6 |
| Four transaction-trie nodes | 20 |
| Four receipt-trie nodes | 20 |
| Statement | 3 |
| **Total** | **51, padded to 64** |

The transaction and its successful receipt must remain under the same block
header and trie key. Bare-send, recipient, amount, asset-kind, commitment,
context, and lease-window checks are unchanged. Inactive node slots are still
part of the fixed circuit; witness depth cannot change the batch shape.

Native proving uses `mirage_prover::native::{setup_keccacheck,
prove_keccacheck, prove_keccacheck_seeded}`. Production callers supply fresh
randomness to `prove_keccacheck`; the seeded helper is only for tests and
reproducible artifacts. The original `setup`/`prove` APIs remain as the direct
control and use incompatible proving/verifying keys.

The native verifier exporter and Nomad native settlement flow use Keccacheck.
The escrow embeds the regenerated native verification key. The GKR proof is
private witness data; the on-chain Groth16 proof/statement ABI is unchanged.

## Bounds and constraint count

Both controls use identical bounds: 544-byte nodes, 3-byte keys, 512-byte
receipts, 704-byte headers, depth 4 for each trie, and 512-byte transactions.
This port keeps native parsing and trie traversal semantics unchanged; it does
not import the ERC-20-specific fixed receipt layout.

| Backend | Constraints |
|---|---:|
| Native direct Keccak | 17,635,451 |
| Native Keccacheck | 11,620,286 |
| Reduction | 6,015,165 (34.1%) |

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
