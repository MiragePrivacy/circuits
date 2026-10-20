# Native ETH relation

## Authentication

`KeccacheckNativeCircuit` binds the intent opening, full header hash, both trie
roots, successful receipt status, transaction recipient/value, lease window and
statement hash. Transaction and receipt inclusion use the same private
`rlp(transactionIndex)` key. Receipt inclusion is required because a reverted
transaction still exists in the transaction trie.

Legacy, EIP-2930 and EIP-1559 transactions are supported. `data` must be empty;
blob and set-code transactions are rejected. An empty-data send can still invoke
a receiver and emit logs, so receipt size remains a bound to check before use.
Authenticated parsing relies on the escrow binding an actual Ethereum block
hash: consensus supplies canonical transaction and receipt encoding.

## Compiled shape

Source: `NativeBounds::default()` and `Bounds::default()` in `crates/relation`.

| Bound | Native | ERC-20 |
|---|---:|---:|
| Transaction bytes | 260 | N/A |
| Receipt bytes | 396 | 448 |
| Header bytes | 679 | 704 |
| Key bytes | 3 | 3 |
| Trie depth, including leaf | 7 each | 7 |
| Ancestor bytes, root / deeper | 308 / 532 | 308 / 532 |

The public node-buffer ceiling remains 544 bytes; structural allocation caps
ancestors at 308/532. Three key bytes cover transaction indices below 65,536.
Six nibbles permit at most six ancestors plus a terminal leaf. This is universal
within these bounds, not an unlimited Ethereum relation.

Terminal leaves are constructed from the authenticated value and remaining key.
The witness API retains redundant terminal-node bytes for compatibility.
Occupancy bits determine branch layout; extension bytes are checked against the
key. All parent-child hash links remain constrained. Removing intermediate
nodes would require an additional authenticated proof, not ordinary preprocessing.

Field-level byte reads, bounded shifts and specialized authenticated parsers
reduce the native relation to a recorded 2,046,951 constraints. Its 61 Keccak
permutations share one batch padded to 64. The ERC-20 Keccacheck relation has
1,889,993 recorded constraints. See [benchmark provenance](BENCHMARKS.md).

## Prover

`mirage_prover::native::{setup_keccacheck, prove_keccacheck}` are the native APIs.
Seeded variants exist for reproducible tests. The production Keccacheck proof
path evaluates linear combinations during synthesis, avoiding matrix creation
and LC inlining. Setup still constructs the constraint system.

`streaming::DEFAULT_STRATEGY` selects whole-key MSMs on hosts and sequential
262,144-base chunks for `target_env = "sgx"`. This changes proving execution,
not the relation or verification key. The proving key remains resident.

## Validation and limits

The October 1 validation record reports all 100 native bare sends and all 100
ERC-20 fixtures satisfying the Keccacheck circuits. The native dataset also
contains 43 value-carrying calls for rejection coverage. Synthetic depth-seven
and adversarial tests cover shapes beyond the sampled mainnet paths.
These are historical validation results, not tests rerun by this documentation edit.

```sh
nix develop
RAYON_NUM_THREADS=1 cargo test -p mirage-relation --release --lib native::tests -- --test-threads=1
cargo test -p mirage-relation --release --test mainnet_native -- --nocapture
cargo test -p mirage-relation --release --test mainnet -- --nocapture
```

Witnesses exceeding any bound cannot be proved; sampled maxima are not network
limits. The exact settlement block remains public, and separate native/ERC-20
circuits do not establish timing privacy. Transcript review, production setup
and integration policy requirements are described in [FINDINGS.md](FINDINGS.md).
