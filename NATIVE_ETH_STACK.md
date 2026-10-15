# Native ETH with Keccacheck

## Field-level parsing and current-network bounds (2026-10-01)

| Stage | Before | After |
|---|---:|---:|
| Transaction trie | 2,269,547 | 101,779 |
| Receipt trie | 2,269,547 | 107,446 |
| Transaction relation | 577,846 | 4,243 |
| Receipt status | 151,942 | 15 |
| Header hash | 46,183 | 18,163 |
| Witness allocation | 65,420 | 62,276 |
| Keccacheck verifier | 1,932,960 (65 -> 128) | 1,738,717 (61 -> 64) |
| **Total** | **7,327,757** | **2,046,951** |

The shared gadgets also reduce the ERC-20 Keccacheck relation from
4,036,383 to 1,889,993 constraints (direct control: 8,097,183 to 5,950,795),
with no ERC-20-specific change. Both need new proving keys and verifiers.

What changed:

- **Field-level byte reads.** `select_byte_with`/`select_bytes` previously
  selected bit by bit, eight constraints per buffer position per byte read.
  They now take one product per position and one recomposition per output.
  Reads at offsets known to be in range use `shift_window`, a log-depth
  shifter: a 32-byte read from a 532-byte node costs ~1.3k instead of ~133k.
- **Variable-length Keccak.** The tail is zero, so the padded message is the
  buffer with the delimiter and final pad bit XORed in; only the 256 digest
  bits are selected across blocks. About five constraints per buffer byte
  instead of ~40. Length bound and zero tail are now unconditional, which
  inactive trie slots already satisfy.
- **Branch nodes from occupancy bits.** Sixteen witnessed occupancy bits fix
  every slot offset and the list header; slot `i` is checked against its
  `i + 1` possible positions. Replaces 16 cursor reads and two general RLP
  decodes per level.
- **Extensions from the key.** An extension's bytes up to its hash follow from
  the key and its path length, so it is compared against the key instead of
  decoded and path-matched.
- **Leaf framing at field level.** The at-most-11-byte RLP framing is built
  from selectors and the value is shifted into place in four stages. ERC-20
  and native leaves share this general encoder.
- **Authenticated transaction and receipt parsing.** Both are leaf values the
  trie has bound to a block the escrow selected, so consensus already
  guarantees canonical encoding. The transaction gadget checks the envelope
  type, the list closing at the length, the prefix of each item walked up to
  `to`, a 20-byte `to`, a minimal value of at most 32 bytes compared
  right-aligned, and empty `data`; it no longer re-counts trailing items. The
  receipt check reads the status at its fixed offset behind a positively
  tested envelope and a list closing at the length.
- **Bounds for current mainnet.** Header 679 B (a Prague header with 32 B
  extraData and eight-byte integers is 670 B), transaction 260 B (largest
  observed bare send 122 B), receipt 396 B (largest observed 393 B). Each sits
  on a Keccak block boundary; together they bring the batch to 61
  permutations, padded to 64.

### Host benchmark (2026-10-01)

One setup and one proof per circuit, Intel Core i9-14900HX, 16 Rayon threads,
release build with `+bmi2,+adx`. Setup peak is measured over constraint
counting and setup; the high-water mark is then reset, so the proving peak is
proving alone with the proving key resident. Measured at 2,046,965 native
constraints, before 14 redundant envelope constraints were removed.

| Metric | ERC-20 | Native |
|---|---:|---:|
| Constraints | 1,889,993 | 2,046,951 |
| Setup | 21.2 s | 22.5 s |
| Setup peak RSS | 8.6 GiB | 9.1 GiB |
| Proof (native includes self-verification) | 21.2 s | 22.1 s |
| Proving peak RSS | 9.8 GiB | 10.5 GiB |
| Proving key, uncompressed / compressed | 0.69 / 0.34 GiB | 0.73 / 0.37 GiB |

About 14 s of each proof and of each setup is arkworks' `Inline/Outline LCs`
pass; the witness map and multiscalar multiplications take ~6 s.

Reproduce with `RAYON_NUM_THREADS=16 cargo run -p mirage-prover --release --bin
measure-native -- --iterations 1` and `... --bin measure -- --keccacheck`.

### Validation

- All 100 bare-send native fixtures and all 100 ERC-20 fixtures satisfy the
  production Keccacheck circuits at the compiled bounds. The fixture tests run
  in parallel (`FIXTURE_JOBS`, default from available memory at 9 GiB per job)
  and print one line per fixture; each takes about 8 minutes on 9 jobs.
- Every `enforce` in the new gadgets was deleted in turn and the gadget suite
  rerun; each deletion fails at least one test. The exception is the leaf
  header's `hi`/`lo` recomposition, whose only exploit would need a full
  coherent forged witness and which the leaf hash already pins.
- Internal witness bindings (`field_to_byte`, `to_bits_bounded`,
  `prefix_mask_exact`) are tested by editing the finalized assignment directly,
  since honest witness generation never exercises them. Symbolic linear
  combinations cache their values, so such tests must finalize and clear
  `lc_assignment` before checking.
- `EscrowNativeZK` and `EscrowERC20` derive `witnessBlockHash` from
  `blockhash(witnessBlockNumber)` on-chain, which is what the authenticated
  transaction and receipt parsing relies on.

### Remaining cost

The Keccacheck verifier is now 85% of the circuit, and ~90% of the verifier is
its Poseidon2 transcript: 2,836 width-16 permutations at ~550 constraints.
Reducing that needs a different transcript hash or sponge width on both
sides, i.e. a fork of the pinned prover. The relation itself is ~308k, mostly
the 61 permutation output states (1,600 boolean witnesses each) and their
absorb XORs.


## Structural optimizations (2026-09-22, superseded)

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

## Fresh before/after host benchmark (2026-09-22 UTC)

Both executables were rebuilt with rustc 1.97.1, release profile, and
`-C target-feature=+bmi2,+adx`, on the same Intel Core i9-14900HX host
(24 CPUs, 93 GiB RAM), with 16 Rayon threads. Before is `3d78fb8`;
after is implementation `fc3f905`. Each ran in a fresh process, sequentially,
after all local builds and tests finished. Both use the same fixture, setup
seed, and proof seeds 0/1/2. CPU affinity and desktop activity were not controlled.

| Metric | Before (depth 4) | After (depth 7) |
|---|---:|---:|
| Constraints | 11,620,286 | 7,327,757 |
| Setup | 67.398 s | 56.253 s |
| Proof 1 | 46.850 s | 44.098 s |
| Proof 2 | 47.484 s | 42.525 s |
| Proof 3 | 47.379 s | 41.304 s |
| **Median verified proof** | **47.379 s** | **42.525 s** |
| Uncompressed proving key | 4.378 GiB | 2.661 GiB |
| Compressed proving key | 2.189 GiB | 1.330 GiB |
| Peak RSS after setup | 16.818 GiB | 18.770 GiB |
| **Total peak process RSS** | **24.831 GiB** | **23.298 GiB** |

All six proofs verified. The observed median is **10.2% lower**, the key is
**39.2% smaller**, and total peak RSS is **6.2% lower**, with wider trie capacity.
Setup peak memory increases because the larger GKR batch adds expression
handling cost. Total RSS includes counting, setup, and all three proofs;
it is not proving-only memory. Proving includes GKR witness generation and
Groth16 self-verification. Three host samples do not establish p95 or SGX
hardware performance.

Raw logs: [before](experiments/keccacheck-arkworks/benchmarks/native-structural-before.log),
[after](experiments/keccacheck-arkworks/benchmarks/native-structural-after.log).

Executable SHA-256:

- Before: `6ce67693ea003f2ffd66bec748c94da75f957f666ee8a14e917e554b19575fc7`
- After: `401338467a8e0424317ec52361c35412fb2fd7d90ceee7b1cec86da293adc069`

Reproduce at each revision with `nix develop --command env RAYON_NUM_THREADS=16 RELATION_PROFILE=1 cargo run --release -p mirage-prover --bin measure-native`.

## Current validation

- Native Keccacheck relation: 13 tests passed, including singleton/depth-seven
  paths and rejection of wrong roots, key, value, status,
  lease, asset kind, and unauthenticated header.
- Five selected mainnet cases passed (legacy/EIP-1559 and largest/deepest
  observed shapes); synthetic depth-seven coverage exceeds sampled depth.
- Transaction adversarial suite: 22 tests passed, including type-1 transactions
  and non-empty access lists.
- General leaf construction: 140 length/path combinations matched independently
  encoded RLP hashes, including both inner and outer prefix transitions;
  additional bare-byte and out-of-bounds-length tests passed.
- A real native Groth16 proof verified; escrow native/ ERC-20 suites: 19 passed.
- Nomad: explicit native key/proof test, 105 regular tests, Fortanix check, and
  mandatory host/Fortanix Clippy commit checks passed. The published circuit
  revision was checked again for Fortanix after pinning.
- Circuit Clippy workspace/all-targets passed with the existing
  `manual_is_multiple_of` lint allowance for the unchanged legacy leaf code.

Matching stack: circuits implementation `fc3f905`, escrow `a937a4a`,
Nomad `e4fdb24` (ISVSVN 14). Nomad's existing legacy native signal dispatcher
still needs the separately documented ZK routing work; these results validate
native proving APIs and matching verifier artifacts.

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

## Per-row batch proof fixture

Batch collection reuses the current circuits and keys. Generate the nonzero-row
ERC-20 fixture with:

```sh
nix develop --command env RAYON_NUM_THREADS=16 cargo run --release -p mirage-prover --bin export-verifier -- --keccachecheck --batch-row
```

`contracts/batch_row_proof.json` binds row 1 and a 75-block lease matching the
native fixture's lease. The ERC-20 witness block immediately precedes the native
fixture block, so both proofs can be checked in one mixed-asset collection.
The exporter self-verifies the proof. The escrow integration exercises both
verifiers, row binding, partial collection, and atomic mixed collection. This
adds no nullifier or aggregation circuit; clients still reject identical rows.
