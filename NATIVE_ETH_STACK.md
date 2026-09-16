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
