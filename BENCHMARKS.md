# Benchmarks

Audited against `update/native-eth-keccacheck` at `abfd4e3` on 2026-10-19.
Circuit counts and prover performance are separate: matrix-free proving changed
execution after the last circuit-count update without changing the relation.

## Current native host measurement

Fresh release build at `abfd4e3`, Intel Core i9-14900HX, 93 GiB RAM,
16 Rayon threads, Nix flake toolchain (rustc 1.97.1), BMI2/ADX enabled.
One setup followed by three sequential seeded proofs of `fixture::genuine()`.
CPU affinity and background desktop activity were not controlled. The existing
local Cargo manifest change only registers a ceremony example; that example was
not built. No prover source changes were present.

| Metric | Native Keccacheck |
|---|---:|
| Constraints | 2,046,951 |
| Setup | 21.065 s |
| Setup/counting peak RSS | 9.144 GiB |
| Proofs, including self-verification | 7.136 / 7.303 / 7.633 s |
| Median proof | 7.303 s |
| Proving peak RSS, key resident | 3.586 GiB |
| Proving key, uncompressed / compressed | 0.732 / 0.366 GiB |

All three proofs passed library self-verification and the benchmark's expected
public-signal assertion. Linux VmHWM was reset after setup; proving peak spans
all three proofs and includes resident/retained allocations. It is not allocator
live heap. Raw output: [native host run](benchmarks/native-host-2026-10-19.log).
This synthetic witness run does not establish mainnet latency distribution,
p95, native/ERC-20 timing privacy, or SGX performance.

## Freshness of older claims

| Evidence | What it establishes | Status at this revision |
|---|---|---|
| October 1 field-level parsing notes (`fa6178d`) | Native 2,046,951 and ERC-20 1,889,993 constraints | Native count reconfirmed above; ERC-20 not remeasured here |
| October 1 host notes | Native 22.1 s / 10.5 GiB proving RSS; ERC-20 21.2 s / 9.8 GiB | Predates matrix-free production proving; one sample each, no committed raw log |
| October 2 commit `078c431` | Reports native host about 25 to 7 s and 10.46 to 2.11 GiB | Commit-message evidence; no committed run metadata/log for those figures |
| October 2 commit `abfd4e3` | Reports SGX `sgx1` 132.7 to about 84 s with chunked MSMs | Commit-message evidence; not reproduced here, no committed SGX raw log |
| September native comparisons | Earlier batching and structural optimizations | Historical; [tables and raw logs](experiments/keccacheck-arkworks/RESULTS.md) |
| August synthetic backend sweep | Multiplication/Boolean circuit throughput | Historical; [report and raw data](bench-arkworks/RESULTS.md) |

The October 1 native timing was actually measured at 2,046,965 constraints,
before 14 redundant constraints were removed; its old table paired that timing
with the later 2,046,951 count. The new run removes that provenance mismatch.
The earlier 2.11 GiB memory report is not reconfirmed by this run's 3.586 GiB;
without its raw evidence, the reason for the difference is unresolved.

## Reproduction

Run in a fresh process after compilation, with a quiet host and fixed thread
count. Record the Git revision, dirty diff, CPU/RAM, compiler, flags and raw output.

```sh
nix develop
RAYON_NUM_THREADS=16 cargo run -p mirage-prover --release --bin measure-native -- --iterations 3
# Direct-Keccak control, using identical native bounds and witness:
RAYON_NUM_THREADS=16 cargo run -p mirage-prover --release --bin measure-native -- --direct --iterations 3
```

`measure-native` exercises the library's current matrix-free Keccacheck prover.
`measure --keccacheck` instead calls standard `Groth16::prove` directly, so it
is a baseline measurement, not current ERC-20 library performance.

Use the existing host/enclave harness to compare proof strategies:

```sh
cargo run -p mirage-sgx-bench --release -- --circuit native --setup-threads 16 --plan standard:16,prover:16,chunked-262144:16
cargo run -p mirage-sgx-bench --release -- --circuit erc20 --setup-threads 16 --plan prover:16
cargo run -p mirage-sgx-bench --release -- --circuit native --census
```

`prover` selects matrix-free whole-key MSMs explicitly; `chunked-262144`
selects the SGX library's default chunk size. The harness default is `standard`,
so choose the plan explicitly. Each proof is verified after its timed section.
The counting allocator reports requested live heap, excluding stack, allocator
metadata and EPC paging; do not label it RSS. Host runs of this binary are not
SGX measurements. Target-enclave latency and a fresh ERC-20 production-path
measurement remain outstanding.
