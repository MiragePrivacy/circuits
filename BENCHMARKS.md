# Benchmarks

Native ETH and ERC-20 Keccacheck, rerun on 2026-10-20. Both use the matrix-free
production prover. Each timing run performs one setup and three sequential
proofs of the circuit's synthetic `fixture::genuine()` witness in a fresh process.
Every proof is verified after its timed section; verification time is excluded.
Timing precision is 0.1 seconds, as printed by the existing harness.

These runs predate the statement-bound Keccacheck transcript (`b7484ee`), which
lowers the counts to 1,860,578 (ERC-20) and 2,017,536 (native). Commit hashes
below are from `update/native-eth-keccacheck`; on this branch `abfd4e3` is
`031908d` and `fa6178d` is `b6b5d13`. `sgx-bench` and the streaming prover are
unchanged between the two.

## Host: both circuits

Intel Core i9-14900HX, 93 GiB RAM, 16 Rayon threads, release build, rustc 1.97.1,
`-C target-feature=+bmi2,+adx`. Built from `755c455` (prover implementation
`abfd4e3`). The only pre-existing local code-related change registers a ceremony
example; that example was not built. CPU affinity and desktop activity were not
controlled. Runs were sequential, with no concurrent compilation or census.

| Metric | ERC-20 | Native ETH |
|---|---:|---:|
| Constraints, separately recounted | 1,889,993 | 2,046,951 |
| Setup | 20.6 s | 23.7 s |
| Setup peak heap | 9.36 GiB | 9.67 GiB |
| Proof 1 / 2 / 3 | 7.3 / 7.5 / 7.7 s | 7.8 / 8.1 / 8.1 s |
| Median proving | 7.5 s | 8.1 s |
| Proving peak heap, key resident | 2.06 GiB | 2.11 GiB |
| Resident key heap after setup | 0.69 GiB | 0.73 GiB |
| Verified proofs | 3/3 | 3/3 |

Raw logs: [ERC-20](benchmarks/erc20-host-2026-10-20.log),
[native](benchmarks/native-host-2026-10-20.log).
Count/matrix census: [ERC-20](benchmarks/erc20-census-2026-10-20.log),
[native](benchmarks/native-census-2026-10-20.log).
[Host environment and executable hash](benchmarks/host-environment-2026-10-20.txt).

## SGX hardware: sgx1

Intel Xeon E-2386G at 3.50 GHz, 62 GiB RAM, six online cores (SMT siblings
offline), 16 Rayon workers. Runs use sequential 262,144-base MSM chunks, the
production SGX default. The `sepolia-fela3` test node was stopped during each
run and restarted by the existing `bench/run-chunked.sh` exit trap. Other host
workloads were not stopped, and CPU affinity was not pinned.

| Metric | ERC-20 | Native ETH |
|---|---:|---:|
| Setup | 338.6 s | 358.7 s |
| Setup peak heap | 9.36 GiB | 9.67 GiB |
| Proof 1 / 2 / 3 | 83.4 / 83.1 / 82.2 s | 85.5 / 84.4 / 85.2 s |
| Median proving | 83.1 s | 85.2 s |
| Proving peak heap, key resident | 2.06 GiB | 2.11 GiB |
| Resident key heap after setup | 0.69 GiB | 0.73 GiB |
| Verified proofs | 3/3 | 3/3 |

The existing `sgx-bench-chunked.sgxs` artifact was run through
`mirage-sgx-bench-runner:0.6.1` on actual SGX hardware. The project's deployment
record associates this October 2 artifact with circuits `abfd4e3`; it was not
rebuilt during this run. Its accompanying signature enables SGX debug mode;
this is a benchmark enclave, not the production Nomad deployment. The host's
`755c455` adds documentation/comment changes to that prover revision. These two machines differ in CPU and available cores,
so their timing ratio is not an isolated measurement of SGX overhead.

Raw logs: [ERC-20](benchmarks/erc20-sgx1-2026-10-20.log),
[native](benchmarks/native-sgx1-2026-10-20.log).
[SGX environment, enclave/signature hashes and runner image ID](benchmarks/sgx1-environment-2026-10-20.txt).
The enclave SHA-256 is
`b76951a0d9975f89453ce354b4b87fdc8d846afff44d65ec9b14512f5159ec42`.

## Memory scope and interpretation

The common `sgx-bench` counting allocator measures requested live **heap**,
including the resident key, separately for setup and each proof. It excludes
thread stacks, allocator metadata/retained pages, enclave image overhead and
EPC paging. It is not RSS, total enclave reservation, or total machine memory.
The instrumented allocator itself can affect timing.

The October 19 native `measure-native` run measured **3.586 GiB proving RSS**
and 9.144 GiB setup/counting RSS, with median proving 7.303 s including library
self-verification. Its key serialized to 0.732 GiB uncompressed / 0.366 GiB
compressed. [Raw RSS run](benchmarks/native-host-2026-10-19.log).
Those numbers are retained as a different measurement, not mixed into the heap
tables above. The previously unexplained 2.11 versus 3.586 GiB difference was a
heap-versus-RSS comparison: the recovered [October 2 SGX log](benchmarks/native-sgx1-2026-10-02.log)
explicitly labels 2.11 GiB as heap, and the new host harness reproduces it.

These samples do not establish mainnet p95 or native/ERC-20 timing privacy.
The one-key proving peak does not include a second resident circuit key or the
rest of Nomad. Provisioning an enclave must account for those costs and, if
setup runs inside it, the much larger setup peak.

## Reproduction

```sh
nix develop
cargo build --release -p mirage-sgx-bench
# Run sequentially, with compilation complete and the host otherwise idle.
target/release/sgx-bench --circuit erc20 --setup-threads 16 --plan prover:16,prover:16,prover:16
target/release/sgx-bench --circuit native --setup-threads 16 --plan prover:16,prover:16,prover:16
# Separate synthesis diagnostics, outside the timing runs:
target/release/sgx-bench --circuit erc20 --census
target/release/sgx-bench --circuit native --census
```

`prover` selects matrix-free whole-key MSMs. On SGX, use
`--plan chunked-262144:16,chunked-262144:16,chunked-262144:16`, matching the
library's SGX default. The harness defaults to the older `standard` prover,
so specify the plan explicitly. Run the SGX-target executable through the
Fortanix runner on actual hardware; a host invocation is not an SGX measurement.

`measure-native --iterations 3` exercises the current library and reports
Linux RSS separately for counting/setup and proving. `measure --keccacheck`
calls standard `Groth16::prove` directly and remains an ERC-20 baseline rather
than a measurement of the production matrix-free path.

## Historical evidence

- October 1 notes at `fa6178d`: ERC-20 21.2 s / 9.8 GiB proving RSS; native
  22.1 s / 10.5 GiB. These predate matrix-free proving and had one sample each.
  Native timing was measured at 2,046,965 constraints before 14 were removed.
- October 2 `sgx1` chunk-size sweep: native 84.3 / 84.2 / 93.2 s at chunk sizes
  262,144 / 524,288 / 1,048,576, each at 2.11 GiB heap. This is three different
  configurations, not three repetitions of one configuration.
- [September integration comparisons](experiments/keccacheck-arkworks/RESULTS.md)
  retain raw logs for the older batching and structural optimizations.
- [August synthetic backend sweep](bench-arkworks/RESULTS.md) retains its raw
  data; it does not measure the current relation or prover.
