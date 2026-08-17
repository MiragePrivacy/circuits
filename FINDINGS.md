# Backend feasibility findings

Recorded 2026-08-12, before any relation code was written. This is the
"measure first" gate from spec Section 25 step 1, and it returned a bad number
for the assumed toolchain.

The backend conclusions stand. The projections have since been checked against
the built relation and real mainnet data; where a section has been superseded by
a measurement, an update note says so inline rather than editing the original
reasoning.

## Circom + snarkjs: does not fit the Section 12.9 bounds

Spec Section 12.1 freezes Circom 2 + snarkjs. The arithmetic does not support
that choice at the bounds Section 12.9 specifies.

### The number

**~150,000 R1CS constraints per Keccak-256 block (136 bytes).** Three
independent sources agree:

| Source | Figure |
|---|---|
| vocdoni/keccak256-circom | 150,848 per block |
| IACR ePrint 2023/681, Table 3 | 151,357 |
| bkomuves/hash-circuits | ~146,000 per permutation |

For contrast: circomlib SHA-256 is 29,891, Poseidon is 240.

This is structural, not an implementation weakness. Keccak is bit-oriented and
R1CS/Groth16 has no lookup argument, so each of the 1600 state bits costs
constraints per round. halo2's lookup-based Keccak is ~300 rows per
permutation, a ~500x gap. That gap is why Axiom, PSE, and Scroll moved
Keccak-heavy work off Circom.

### Applied to this design

| Component | Blocks | Constraints |
|---|---|---|
| 2KB receipt hash | ~16 | ~2.4M |
| 16-deep MPT node hashes | ~16+ | ~2.4M+ |
| Commitment + statement hash | ~3 | ~450k |
| **Step 2 subtotal** | | **~5M** |
| Step 5 header chain, 10 headers | ~80 | ~12M |

Calibration: zk-attestor measured `eth_tx_proof` at **16.5M constraints** for
the *transaction* trie, needed `pot24_final.ptau`, and never finished the
receipt version. Its author went on to rebuild the same work in halo2 at Axiom.

### Two further blockers

- **vocdoni's Keccak is single-block only.** `Final()` instantiates `Absorb()`
  exactly once with `blockSize = 136*8` hardcoded. It cannot hash a 2KB receipt
  at all. The multi-block sponge would be ours to write, on top of an unaudited
  circuit last touched in 2021.
- **No Circom MPT or RLP library exists.** A GitHub code search for a Circom
  MPT returns zero results. All three parsers are from-scratch work.

### Ecosystem context

- circomlib is maintenance-only; no real circuit work in years, no Keccak in it.
- Circomspect is ~2 years stale and does not understand circom 2.2.x features.
- PSE, the lab behind much Circom tooling, was shut down 2026-06-23.
- Two 2026 exploits (Foom ~$1.4M, Veil 2.9 ETH) came from skipping Groth16
  Phase 2, leaving the setup forgeable. Operational, not a compiler bug, but
  Circom's model puts that entirely on the deployer.

## The cheapest lever, whichever backend wins

Section 12.9's bounds are worst-case padding, and cost scales with them
directly:

- `MAX_RECEIPT_BYTES = 2048` — a real ERC-20 transfer receipt is often 200-400
  bytes.
- `MAX_MPT_DEPTH = 16` — mainnet receipt tries run ~6-9 deep.

Halving both roughly quarters the Keccak cost. This does not rescue Circom on
its own, because the step-5 header chain still dominates, but it applies to
every backend and should be measured against real mainnet receipts before the
bounds are frozen.

Note the privacy coupling: bounds are public circuit parameters, and a receipt
that exceeds them is unprovable. Tightening them narrows which tokens are
supportable, which is a Section 17.8 input, not purely an optimization.

## zkVM (SP1 / RISC Zero): rejected on latency and fingerprinting

Researched 2026-08-12. The constraint expected to be fatal was not; two others
were.

### The no-shared-contract rule is satisfiable

SP1's `Groth16Verifier.sol` has zero imports, hardcodes its VK as constants,
and touches only precompiles `0x05`, `0x06`, `0x07`, `0x08`. No DELEGATECALL,
no linked libraries, no storage. Gateways and routers are explicitly optional
in both SP1 and RISC Zero. Compiled at `--optimize runs=200`:

| Verifier | Deployed size |
|---|---|
| SP1 `Groth16Verifier` | 4,857 B |
| SP1 `SP1Verifier` full wrapper | 6,127 B |
| `RiscZeroGroth16Verifier` | 4,815 B |

Comfortably inside the 20,000 B target. Section 7.2 satisfied.

### Blocker 1: a fixed proving floor the workload cannot amortize

SP1's Groth16 wrap costs a flat ~60-65 seconds regardless of workload, because
the wrap circuit proves "a valid core proof exists" and is the same size for
1,000 cycles or 100 million. Measured on AMD EPYC 8534P, 64 cores, AVX-512,
bare metal:

| Workload | Core only | With Groth16 wrap |
|---|---|---|
| Fibonacci 10k | 16.0s | 1m18.5s |
| Keccak x100 | 53.8s | 1m56.0s |
| Keccak x10,000 | 54.6s | 1m56.3s |

Keccak x100 and x10,000 cost the same: proof-system overhead dominates
entirely. This relation is smaller than either, so it pays roughly the same
~116s. That is 1.5x the Section 19.7 budget of 75s p95, on better hardware than
an enclave, before SGX overhead. The wrap step also wants ~14GB, which must fit
the enclave allocation or page at roughly 5x penalty.

### Blocker 2: the recursion VK is a worse fingerprint than a shared contract

SP1's verifier hardcodes the same BN254 verification key in every deployment,
because it verifies SP1's recursion circuit rather than the guest program. The
same ~30 field constants appear verbatim in every escrow. One 32-byte grep
recovers the entire population.

This is structurally unavoidable: SP1 proofs cannot be verified without that
key. It inverts the Section 15.2 assumption in the wrong direction. A
hand-written circuit has a per-circuit VK, and Section 15.3's reparameterization
can vary the raw points further; a zkVM has neither. Avoiding a shared verifier
contract by embedding a shared verifier constant is not progress.

Also fixed across deployments: the 4-byte `VERIFIER_HASH()` selector check,
which additionally puts an identifying prefix in every proof's calldata.

### Not blockers

- Local proving works with no network dependency.
- Docker is avoidable: `sp1-recursion-gnark-ffi` has a `native` feature using
  cgo/bindgen. Untravelled path, and a cgo Go runtime under Gramine is its own
  risk, but not a hard stop.
- Program-ID versioning is a non-issue here. Escrows are deployed fresh and are
  short-lived, so each bakes in the vkey current at deploy time. The old prover
  must be retained for the lifetime of escrows pinning it.

### Why the mismatch

zkVMs are built to amortize a large fixed overhead across a large workload.
Proving a whole Ethereum block is an excellent trade; proving a 20-hash receipt
check is a terrible one. This design would pay for an entire RISC-V machine plus
a recursion layer to run a fixed 500-line computation of known shape.

## Why lookup arguments are the actual dividing line

Keccak is expensive in R1CS because theta and chi are bitwise over 1600 state
bits, and R1CS expresses only field multiplication and addition. Decomposing to
bits costs a constraint per bit per round, and no amount of careful Circom
avoids it.

PLONKish systems have lookup arguments: constrain a witness to be some row of a
precomputed table rather than deriving it arithmetically. Scroll's halo2 keccak
reaches roughly 300 rows per permutation against Circom's ~150,000 constraints.
Custom gates compound this, since halo2 permits higher-degree constraints where
R1CS is fixed at degree 2.

This is a proof-system property, not a library gap. A lookup argument requires
the protocol to commit to a table and prove set membership, which cannot be
expressed inside an R1CS instance. It is why Axiom, Scroll, and PSE moved
keccak-heavy work off Circom rather than optimizing it.

What does not transfer from Scroll: they amortize one proof over thousands of
transactions, prove on GPU fleets, and wrap to Groth16 anyway for on-chain
verification. Their zkTrie is also irrelevant here, being a binary Poseidon
sparse trie rather than Ethereum's hexary keccak MPT. An L2 that controls its
own state format picks Poseidon at ~240 constraints; this design is verifying
mainnet receipt tries and has no such freedom.

That last point is the root of the whole problem. This circuit must speak
keccak-MPT because it verifies someone else's data structure. Every system that
made keccak cheap either changed the data structure or changed the proof
system. Only the second option is available here.

## halo2: rejected on verifier gas and size

Researched 2026-08-13. The predicted failure mode did not occur; a different
one did.

Proving is halo2's strength: this workload proves in **2-3 seconds at k=13-15**,
the fastest of any candidate measured. The keccak lookup table's fixed overhead,
which was the expected blocker by analogy with SP1's Groth16 wrap, is not a
problem at this scale.

It fails on the verifier:

| | halo2-KZG |
|---|---|
| Deployed size | 13,253 B (24 advice columns) |
| Verify gas | 965,625 |
| Self-contained | yes |
| Per-circuit VK | yes, but deterministic (see below) |
| Status | last commit Oct 2024, unaudited |

13.3KB against a ~14KB budget leaves nothing for the state machine, and 965k
gas is 4.4x the Groth16 baseline on every collection. The tooling is also
unmaintained since Oct 2024 and unaudited.

`axiom-eth` does not rescue this. It is archived at ~2024-08 against an older
halo2-lib, and its receipt circuits do not port to any other backend.

## gnark Groth16: right proof system, unusable implementation

**Blocked by the runtime.** Nomad's enclave is built with Fortanix EDP
(`sgx-isa`, `enclave-runner`, `sgxs-loaders` in `crates/node`;
`[package.metadata.sgx] isvsvn = 4` on `crates/enclave`), which targets
`x86_64-fortanix-unknown-sgx`. That target is Rust-only: no libc, no `fork`, no
arbitrary syscalls, no foreign runtime. A Go prover cannot run inside it. This
is not a difficulty, it is an incompatibility.

The evaluation below is retained because the **proof-system** findings transfer
to any correct Groth16 implementation; only the proving numbers are specific to
gnark.

### What transfers: the proof system

Independently built and measured, not quoted from documentation.

| | gnark Groth16 | gnark PLONK | halo2-KZG |
|---|---|---|---|
| Deployed size | **4,093 B** | 6,177 B | 13,253 B |
| Verify gas | **220,629** | 314,463 | 965,625 |
| Self-contained, no delegatecall | yes | yes | yes |
| Per-circuit VK | yes | yes | yes |
| Status | v0.15.0 (May 2026), audited | same | Oct 2024, unaudited |

Same proof system Section 12.1 already freezes: Groth16 over BN254. A different
implementation and toolchain from snarkjs, but Section 15.1's inlined verifier,
Section 15.5's precompile trace, and the gas arithmetic all hold as written.

### The per-setup VK inverts Section 15.2

Groth16's verification key varies per **trusted-setup run**, not merely per
circuit. Two escrows with byte-identical circuits receive distinct VKs if setup
is run separately for each.

Section 15.2 assumes the opposite. It calls the shared semantic VK "likely the
strongest family fingerprint," expects it to fail classification until proven
otherwise, and Section 15.3 exists only to vary the raw points through an exact
equivalence transform that earns no anonymity credit.

halo2 would have been worse on this axis despite its universal SRS: deterministic
keygen means identical circuits produce identical VKs, so every escrow carries
the same constants. Groth16's per-setup randomness is what breaks the 32-byte
grep. The per-circuit Phase 2 ceremony that Section 18.2 treats as a release
burden is the mechanism buying the privacy property.

This needs deliberate review before it is banked. Section 15.2 forbids ad hoc
per-instance VK mutation for sound reasons, and per-deployment ceremonies at
production scale is an operational question the spec never contemplated. But
the lever is real and was not visible before this evaluation.

### Proving time (gnark-specific, for calibration only)

Measured with gnark's native keccak on an i9-14900HX:

| Workload | Constraints | 1 thread | 4 threads |
|---|---|---|---|
| 20 keccak permutations | 2.38M | 52.7s | 14.7s |
| 30 keccak permutations | 3.50M | 63.7s | 19.5s |

Single-threaded, 30 permutations is 63.7s against the Section 19.7 budget of
75s p95, before any RLP or MPT logic. This relation is ~20-40 permutations, so
single-threaded it fails.

**The enclave runs with 16 cores.** At 4 threads this workload is already
15-20s, so latency is not the constraint it appeared to be. Treat these figures
as an order-of-magnitude reference for what a mature Groth16 implementation
achieves on ~2-3.5M constraints; a Rust prover's numbers will differ and must be
measured separately.

### Consequence: the search narrowed to Rust Groth16

Groth16 verifier properties are fixed by the proof system, so the size, gas, and
per-setup VK findings above transfer to any correct implementation. Only the
proving numbers and toolchain are gnark's. The requirement became a pure-Rust
Groth16/BN254 prover that builds for `x86_64-fortanix-unknown-sgx`.

### Process note

The gnark evaluation reached a recommendation before checking language
compatibility with the enclave runtime, which was determinable from nomad's
Cargo.toml at the outset. Backend evaluation criteria must include the target
runtime, not only verifier properties and proving speed.

## arkworks under EDP: viable stack, hostile circuit-authoring surface

Researched 2026-08-13.

### What works

- **Pure-Rust dependency tree**, no C runtime. arkworks 0.6.0 is live, shipped
  2026-04-26.
- **`taceo-groth16-sol` exports a Solidity verifier from arkworks VKs**, at
  gnark's measured profile: ~4KB deployed, ~220k gas, self-contained. The
  exporter risk flagged earlier is resolved; it does not need writing.
- **Per-deployment VK variation confirmed at source**, so the Section 15.2
  inversion above holds on this stack.
- **Debugging is better than Circom's.** `which_is_unsatisfied()` returns the
  failing constraint's label and `ConstraintLayer` captures source locations.
  Circom has no equivalent.

EDP compatibility and the verifier are both satisfied.

### What does not work

**There is no usable keccak gadget.** The only arkworks implementation,
`natharyan/arkworks-keccak`, is defective twice over:

1. Its `Keccak256` mode pads with a plain `1` bit rather than Ethereum's `0x01`
   domain separator, so the one mode this design needs computes the wrong hash.
   Only its NIST SHA3 variants pad correctly.
2. It is unsound as a circuit. `keccak_gadget` calls `assert_eq!` on `.value()`
   against a native reference hash inside the constraint-generation path. That
   is a native panic during proving and a **silent no-op during setup** — not an
   enforced constraint. It is a gadget-shaped native function, not a gadget.

Its own benchmark reports 152,448 constraints per block, confirming no
improvement over vocdoni's 150,848. The R1CS keccak cost is structural, as
recorded above.

**arkworks is the worst-equipped mainstream option for byte parsing**, which is
what this circuit mostly does:

| | arkworks | gnark |
|---|---|---|
| Byte representation | `UInt8` is 8 `Boolean`s | `uints` via lookup tables, 1-3 constraints |
| Dynamic indexing | **none** — hand-rolled `CondSelectGadget` trees | supported |
| Ethereum gadgets | none | `std/hash/sha3`, `evmprecompiles`, `rangecheck` |
| Static analysis | **no Picus frontend** | Picus supported |
| Circuit verbosity (Veridise) | 227 LoC | 101 LoC |

Dynamic indexing is exactly the primitive RLP parsing needs, because offsets are
witness-dependent. Losing Picus matters more than usual here: `ark-r1cs-std` has
live underconstraining bugs of its own (#212, #213, #216).

### Performance concerns, unmeasured

- **Constraint synthesis is serial by construction.** `ConstraintSystemRef<F>`
  wraps `Rc<RefCell<ConstraintSystem<F>>>`; `Rc` is `!Send`/`!Sync` and cannot
  cross a rayon boundary. No core count fixes this. The R1CS-to-QAP witness map
  *is* parallel; FFT scales poorly at early and late stages; MSM parallelizes
  near-embarrassingly.
- **Parallel efficiency roughly half of gnark's**: Celer measured arkworks at
  935% CPU on 20 cores (46.75%/core) against gnark's 1624% (81.2%).
- **No published wall-clock for ark-groth16 at >=1M constraints on BN254
  exists.** The upstream bench targets BLS12-381 and MNT4-298, so it does not
  produce a BN254 figure without modification. The frequently cited claim that
  gnark is 5-10x faster than arkworks comes from Celer's Pantheon post, whose
  figures are log-scale and not constraint-controlled (32M Circom vs 43M
  arkworks vs 45M gnark for the same SHA-256). zk-Bench does **not** support
  that claim: its Groth16 comparison uses bellman, and arkworks appears there
  only in arithmetic microbenchmarks.
- **Memory is extrapolated, not measured.** At 3.1M constraints a measured
  snarkjs zkey is 1.75 GB, and rapidsnark peaked at ~4x key size at 1.2M
  constraints. The resulting 6-8 GB estimate rests on a single datapoint.
  Note the widely repeated "rapidsnark needs 2-3 GB" traces to a HackMD that
  explicitly disclaims it as modeling rather than measurement.
- **ISA**: the only relevant lever is `ark-ff`'s `asm` feature (ADX/BMI2,
  documented 30-70% on field and EC ops). Those are general-purpose integer
  instructions with no extended xsave state, so they should be usable in-enclave
  unlike AVX, which is gated by enclave XFRM attributes. No Intel document
  confirms this explicitly; it is architectural reasoning and should be probed.
  CPUID traps in-enclave, so feature detection must be pinned at compile time.

### ZoKrates as a reference, not a dependency

ZoKrates is the only Rust-adjacent stack shipping a **correct** Ethereum
keccak256: `hashes/keccak/256bit.zok` uses delimiter `0x01` and
`sha3/256bit.zok` uses `0x06`, correctly distinguished, with a genuine
multi-block absorb loop. That solves the single-block limitation that
disqualified vocdoni's circuit.

It is dead as a dependency: last commit 2024-04-15, 0.8.8 released 2023-11, 115
open issues, and its ark-groth16 pin is `^0.3.0`, three majors behind. Worth
porting from rather than depending on. Porting a known-correct sponge is
preferable to writing one.

## The decision has moved up a level

This is no longer a library choice. Everything distinctive about the arkworks
path — hand-rolled keccak, hand-rolled indexing, no static analysis, half the
parallel efficiency — is a consequence of the Rust-only constraint, not a
property of the library. Switching Circom to arkworks buys no keccak win and
costs ecosystem.

The real question is what the EDP runtime is worth:

| | EDP + arkworks | Gramine + gnark |
|---|---|---|
| Verifier | ~4KB, 220k gas | same |
| Keccak gadget | none usable; port from ZoKrates | `std/hash/sha3` |
| Byte operations | 8 Booleans, no dynamic index | lookup tables |
| Static analysis | none | Picus |
| Parallel efficiency | ~47%/core | ~81%/core |
| Circuit verbosity | 227 LoC | 101 LoC |
| Enclave migration | none | attestation, sealing, build all change |
| TCB | minimal | larger |

Gramine runs unmodified Linux binaries under SGX, so gnark works there. The cost
is migrating nomad's enclave off EDP, which touches attestation and sealing —
load-bearing for the trust model — and enlarges the TCB.

## Measured: arkworks Groth16 BN254 throughput

Run 2026-08-13. Full report and re-runnable project in `bench-arkworks/`.
Hardware: Intel i9-14900HX, 24 cores (8 P + 16 E, SMT off), 94 GiB RAM,
rustc 1.97.1, arkworks 0.5.x. 27 configurations, all proofs verified.

### The headline: ~3M constraints proves in ~21s at 16 threads

| Constraints | 16 threads |
|---|---|
| 2.1M (2^21) | 14.5s |
| 3.0M (interpolated) | **~21s**, ~17s with asm |
| 4.2M (2^22) | 28.6s |

Against the Section 19.7 budget of 75s p95, that is roughly 3.5x margin.
Scaling is near-linear (exponent 0.978), so the interpolation sits between two
measured points rather than extrapolating. Nothing OOMed or timed out; 2^22
completed at every thread count. Verification is 0.85-1.20ms throughout.

### Serial synthesis: real, not yet binding

Constraint synthesis plus LC inlining takes ~6.6s at 4.2M **regardless of
thread count**, and is marginally slower at 16 threads (0.90x) from allocator
contention. That is 4.0% of prove time at 1 thread but **23% at 16**.

The resulting Amdahl ceiling is ~23x speedup. Only 5.3x is observed, because
the parallel MSM phases themselves reach just ~6.6x. So the serial phase is not
the binding constraint at this core count — it becomes one at higher counts.

### Measured memory

**~8.1 GB peak at 3M constraints**, from 5.42 GB at 2.1M and 11.63 GB at 4.2M
(`VmHWM`). Roughly 2.8 GB per million constraints. The earlier 6-8 GB
extrapolation was close and slightly low. This is the figure to check against
enclave allocation.

### Parallel efficiency and asm

- **33-35% at 16 threads**, below Celer's ~47%. Two caveats from the run: only
  8 of 24 cores are P-cores, and the governor was `powersave` on a thermally
  limited laptop. The 8-thread figure of 55% is closer to Celer's.
- **`+bmi2,+adx` gives 9-26%, about 14% at the largest sizes.** Real but well
  short of the quoted 30-70%, which describes isolated field-op microbenchmarks
  rather than end-to-end proving.

### The caveat that governs how much to trust this

Neither synthetic circuit substitutes for the real one.

The boolean-heavy circuit came out **faster** than the multiplication chain
(12.95s vs 28.59s at 4.2M). That is a benchmark artifact, not good news: every
witness is 0 or 1, so Pippenger's MSM nearly skips them and the MSMs collapse
~19x. Real keccak has arbitrary field coefficients in its constraint matrices,
so its MSMs will behave like the multiplication chain's.

What the boolean circuit does show usefully is direction: serial fraction rises
to 28% and parallel efficiency drops to 25%. Real keccak likely sits **above**
the multiplication chain — inheriting mul-like MSM cost together with bool-like
elevated synthesis cost.

Exceeding 75s would require roughly a 3.5x blowup over this measurement, which
is not the expected magnitude. But that gap is exactly why the real circuit must
be benchmarked before the backend is finally committed.

### Operational consequences

- **Proving key is ~224 bytes per constraint**, so roughly **640 MiB compressed
  at 3M**. It must be distributed to and loaded by every prover, and it is
  resident during proving. This compounds the 8.1 GB working set.
- `circuit_specific_setup` as used in the benchmark is a toy setup. The real
  per-deployment ceremony is a separate and significant problem under Section
  18.2, made larger by the per-setup VK property this design now depends on.

### What this settles

EDP plus arkworks is **viable on performance**. That removes the principal
reason to migrate the enclave to Gramine, and returns the decision to a library
choice whose cost is circuit-authoring effort — no keccak gadget, no dynamic
indexing, no Picus — rather than latency.

## Confirmed in our own code: ~153k constraints per keccak block

Measured 2026-08-13 against `crates/gadgets`, ported from ZoKrates.

| Input | Blocks | Constraints | Per block |
|---|---|---|---|
| 100 B | 1 | 152,000 | 152,000 |
| 200 B | 2 | 306,688 | 153,344 |
| 400 B | 3 | 461,888 | 153,962 |

`keccak_f1600` alone is 155,200. Reproduce with
`cargo test -p mirage-gadgets --release -- --nocapture cost`.

This lands on the ~150k figure that drove every backend rejection above
(vocdoni 150,848; IACR ePrint 2023/681 measures 151,357; bkomuves ~146,000).
The estimate is no longer inherited — it holds on our own implementation, which
means the cost projections for the full relation can be trusted.

The gadget agrees with `mirage_encoding::keccak256` on the empty input, both
preimage lengths, and every block boundary (134/135/136/137/271/272/273 bytes).
Differential testing against a native reference, never against itself.

### What this implies for the relation

At ~153k per block:

| Component | Blocks | Constraints |
|---|---|---|
| Commitment preimage, 226 B | 2 | ~306k |
| Statement preimage, 285 B | 3 | ~460k |
| Receipt hash, bounded 2048 B | 16 | ~2.45M |
| MPT node hashes, 16 deep | 16+ | ~2.45M+ |

**This table understates the MPT term and is superseded** by the corrected
projection below: the 16 MPT nodes are each independently bounded, so the row
is ~40.9M rather than ~2.45M. Retained because the per-component figures are
correct; only the MPT multiplication was wrong.

The two bounded components dominate, and both are witnessed-length: they pay
their maximum regardless of real input size. **Tightening spec 12.9's bounds
against measured mainnet receipts is now the largest single lever available**,
and it is a measurement rather than an argument.

## Measured: witness-dependent byte reads are the second cost centre

Measured 2026-08-13 against `crates/gadgets/src/bytes.rs`.

| Buffer | `select_byte` cost |
|---|---|
| 64 B | 640 |
| 256 B | 2,560 |
| 1024 B | 10,240 |

**~9-10 constraints per buffer byte, per read.** Two optimizations were tried:

- Sharing indicators across a multi-byte read: 81,920 to 62,080 for 32 bytes
  from a 256-byte buffer, a 24% saving.
- Replacing per-position `is_eq` with a jointly constrained one-hot vector:
  10,240 to 9,218 over 1024 bytes, a 10% saving.

Both are smaller than they look, and the reason is the same. The cost is
dominated by the `conditionally_select` chain — one constraint per bit per
buffer position, so 8N — and neither optimization touches it. A dot-product
formulation was attempted and abandoned: it has the same asymptotic cost, since
the AND products are themselves one constraint each.

The honest conclusion is that **witness-indexed byte access in R1CS is ~8-10
constraints per buffer byte and does not optimize away.** Design the parsers to
avoid it rather than to make it cheaper.

Extrapolated to the compiled bounds: one 32-byte read from a 2048-byte receipt
is on the order of 500k constraints, more than three keccak blocks for a single
field.

### Why this matters more than the raw number

Unlike keccak, this cost scales with the **compiled buffer bound**, not the
real input size. A 300-byte receipt in a 2048-byte buffer pays the 2048-byte
price on every witness-dependent read. RLP parsing is built almost entirely
from such reads, because offsets depend on the length prefixes being parsed.

Two consequences for how the parsers must be written:

1. Read a fixed offset wherever the format fixes one. The receipt's outer list
   prefix, the four-item payload structure, and the 256-byte `logsBloom` are
   all at computable positions once the envelope type is known.
2. Prefer one `select_bytes` run over repeated `select_byte` calls, and prefer
   selecting a *parsed value* once over re-reading its bytes.

This reinforces the tightening lever already recorded above: shrinking spec
12.9's `MAX_RECEIPT_BYTES` and `MAX_MPT_NODE_BYTES` reduces both the keccak
cost and, linearly, every witness-dependent read.

## Measured: variable-length keccak, and a correction to the relation projection

Measured 2026-08-13 against `crates/gadgets/src/keccak/sponge.rs`.

`keccak256_var` hashes a bounded buffer with a witnessed length. It
zero-constrains the tail, assembles the padding in-circuit at witness-dependent
positions, runs every permutation unconditionally, and selects the state after
the block containing the padding.

| Buffer | Blocks | Constraints | Per block |
|---|---|---|---|
| 256 B | 2 | 317,307 | 158,654 |
| 512 B | 4 | 638,337 | 159,584 |

**~159.6k per block**, against the fixed-length version's ~153k. The padding
assembly and state selection cost only about 4% on top of the permutations
themselves — cheaper than expected, because the selection logic is small
relative to what it selects among.

Correctness is checked against the native reference at **every length from 0 to
272** in a two-block buffer, which exercises every block-selection branch and
both padding placements, plus short messages in a 512-byte buffer and agreement
with `keccak256_fixed` on the same input. A dirty-tail case confirms
`assert_zero_tail` rejects nonzero bytes past the claimed length.

### The correction: ~43.7M constraints, not ~5.7M

The earlier projection of ~5.7M was wrong. It treated the MPT node hashes as a
single bounded hash. They are **16 separate nodes, each independently bounded at
`MAX_MPT_NODE_BYTES`**, and each needs its own variable-length keccak.

At the measured ~159.6k per block, with spec 12.9's bounds as written:

| Component | Constraints |
|---|---|
| Commitment + statement preimages | ~0.26M |
| Receipt hash, bounded 2048 B | ~2.55M |
| **MPT node hashes, 16 nodes x 2048 B** | **~40.86M** |
| **Total** | **~43.7M** |

The MPT node hashing dominates by an order of magnitude and is the only term
that matters.

### Latency is a product decision; memory is a wall

At the measured ~21s per 3M constraints, 43.7M extrapolates to roughly **5
minutes**. That is 4x over Section 19.7's 75s p95, but a latency target is a
product decision and can be amended.

Memory cannot. At the measured ~2.8 GB per million constraints:

| Constraints | Peak memory | Proving key |
|---|---|---|
| 43.7M (bounds as written) | ~120 GB | ~9.8 GB |
| 23.0M (depth 9, 2048 B nodes) | ~64 GB | ~5.2 GB |
| 12.8M (depth 16, 640 B nodes) | ~36 GB | ~2.9 GB |
| 7.2M (depth 9, 640 B nodes) | ~20 GB | ~1.6 GB |

120 GB exceeds the 94 GB machine the benchmark ran on, let alone an enclave
allocation. Groth16 requires the full witness and proving key resident with no
streaming path, so constraint count sets a hard memory floor rather than a time
cost that can be traded against. This is why bounded-buffer circuits do not
degrade gracefully: latency scales linearly and can be waited out, memory
scales linearly and hits a ceiling.

### Depth 16 is not the problem

`MAX_MPT_DEPTH = 16` at a realistic 640-byte node bound is ~12.8M constraints
and ~36 GB — workable. The node-size term is what breaks the budget, and real
mainnet branch nodes are ~530-570 bytes rather than 2048.

Tightening should therefore target `MAX_MPT_NODE_BYTES` first, where the risk
is structural and low, before touching depth.

### Why the bounds are now the whole problem

Every MPT node pays its compiled bound regardless of its real size. Cost scales
linearly with `MAX_MPT_NODE_BYTES` and with `MAX_MPT_DEPTH`, so the product is
what governs:

| `MAX_MPT_NODE_BYTES` | Blocks/node | 16 nodes | 9 nodes |
|---|---|---|---|
| 2048 | 16 | ~40.9M | ~23.0M |
| 1024 | 8 | ~20.4M | ~11.5M |
| 512 | 4 | ~10.2M | ~5.7M |
| 384 | 3 | ~7.7M | ~4.3M |

Real mainnet receipt-trie nodes are far below 2048 bytes: a branch node is 17
RLP items of which most are 32-byte hashes, so roughly 530-570 bytes, and
tries run 6-9 deep rather than 16. Bounds of 640 bytes and depth 9 would put
the MPT term near ~7M and the whole relation within reach.

**Update: measured, and the projection held.** `crates/fixtures` collected 100
mainnet direct-transfer settlements; maxima were 532-byte nodes at depth 3,
428-byte receipts and 655-byte headers. The relation compiled against those
bounds is **10,426,684 constraints** — roughly 29 GB at ~2.8 GB per million,
within a provisioned enclave. The estimate above was right about which term
dominates and conservative about its magnitude.

Depth was the biggest surprise: real receipt tries run 2-3 levels, not the 6-9
guessed here, because a block's receipt count is only a few hundred. The
compiled bound is 4.

The measurement did not block gadget work, as predicted — bounds are
compile-time constants and the parser code is identical whichever values they
take.

Note the coupling: bounds are public circuit parameters, and a receipt whose
proof exceeds them is unprovable. Tightening them narrows which settlements are
supportable, which is a Section 17.8 input rather than a free optimization.

## Bounds are a fund-loss surface, not a tuning knob

A proof whose witness exceeds a compiled bound cannot be produced. The escrow
is safe in that case — no proof means no payout, the bond expires, the
requester cancels and is refunded — but the executor has already paid the
recipient and cannot collect. **The loss falls entirely on the executor.**

Spec 12.9 states the consequence plainly: "If a reviewed token's receipt
exceeds a bound, that token is unsupported by this circuit version."

### What is and is not bounded

Transactions per block is **not** a bound. The relation proves inclusion of one
receipt at one index and never enumerates the block, so block size is
irrelevant. What block size affects is trie depth, and only logarithmically: a
receipt trie over N entries is roughly log16(N) deep, so a few hundred
transactions is ~3 levels and 10,000 is ~4. `MAX_MPT_DEPTH = 16` would
accommodate 16^16 entries and is enormously conservative.

The bounds that can actually be exceeded in practice:

| Bound | Exceeded when | Realistic risk |
|---|---|---|
| `MAX_RECEIPT_BYTES` | a token emits many or large logs | real for hook-heavy tokens |
| `MAX_LOGS` | more than 8 logs in one receipt | real; currently 8 |
| `MAX_MPT_NODE_BYTES` | branch node with long inline children | low; nodes are ~530-570 B |
| `MAX_MPT_DEPTH` | implausibly large receipt trie | negligible |

### The consequence for tightening

Shrinking bounds is therefore **not free optimization**. Every byte removed
from `MAX_RECEIPT_BYTES` or `MAX_MPT_NODE_BYTES` narrows the set of provable
settlements, and each unprovable settlement is an executor loss.

The target is the measured distribution **plus real headroom**, not the
tightest bound that fits the proving budget. The measurement must therefore
report tail percentiles and maxima, not just medians.

There is also a Section 17.8 coupling: a narrow supported-token set is itself a
fingerprint, since it shrinks the candidate universe an analyst must search.

### The protection has to be operational

Spec 12.6.2 and 6.2 already place token review in the enclave before
commitment. The bounds make that check load-bearing rather than advisory: the
enclave must confirm, before settling, that this token's receipts fit the
compiled bounds, and refuse the row otherwise.

One residual gap: receipt size is not fully knowable before the transaction
lands, because log count depends on token behaviour at execution time. A token
with a transfer hook can emit more logs than the reviewed sample did.
Mitigations are a generous `MAX_LOGS` (cheap, since logs sit inside the receipt
buffer that is already bounded), review against observed receipts rather than
source, and executor verification of provability before treating a settlement
as complete.

## Measured: RLP decoding, and the optimization that worked

Measured 2026-08-13 against `crates/gadgets/src/rlp/`.

A cursor-walking decoder was built first as the safe-by-construction baseline:
every offset is derived from bytes read out of the buffer, so there is nothing
for a prover to forge structurally. A witness-supplied-layout decoder was
planned as the affordable alternative.

**The layout decoder turned out to be unnecessary.** Breaking down where the
cursor's cost went:

| | Constraints |
|---|---|
| One byte read (`one_hot` + select) | 9,218 |
| Full `decode_item`, initial | 102,630 |

Byte reads were only ~9% of it. A layout hint saves the *walking* between
items, but every item still needs its prefix decoded to verify the hint, so
~103k was the floor either way.

### What actually worked: shrinking `MAX_LEN_BYTES`

`read_long_length` performed 8 witness-indexed reads on **every**
`decode_item`, regardless of form, because RLP permits up to 8 length bytes
(payloads to 2^64). Every buffer in this relation is bounded at a few
kilobytes, so 2 length bytes covers everything that can physically fit; a
larger claim fails the containment check regardless.

| | Before | After |
|---|---|---|
| `decode_item` | 102,630 | **41,485** |
| 4-item list in 1KB buffer | 509,082 | **210,887** |

2.4x, with a range check added so an over-long `len_of_len` is rejected rather
than silently truncated.

Two failed attempts are worth recording so they are not retried:

- Replacing per-position `is_eq` in the prefix classifier with bit tests on the
  byte's existing decomposition: 1.5%. The range checks were not the cost.
- A dot-product formulation of `select_byte`: no improvement. The AND products
  are one constraint each, the same as the conditional selects they replace.

The pattern across all three: the cost was never cleverness-shaped. It was
unconditional work done for cases the compiled bounds already make impossible.
In R1CS every branch executes, so "handle the general case" silently means "pay
for the general case on every input."

### Adversarial suite

Ten forgery cases, written before either implementation and run against both
through a shared trait so neither is graded on its own terms: non-minimal
single byte, long form where short fits, leading-zero length, payload past
buffer, wrong child count, untiled list, child escaping parent, string as list.

One case was reframed rather than fixed. A zero byte is a canonically valid
empty string, so a decoder given only a buffer cannot distinguish padding from
data. That is the caller's responsibility, and it is now a documented
requirement: **the relation must never call `decode_item` at a free offset —
every offset must descend from the root**, with `assert_zero_tail` and
containment doing the work.

## MPT: adversarial suite first, verifier in progress

The suite is written and validated; the verifier is partially built.

### The suite has teeth, mechanically

Nine forgery cases, each taking a genuine two-node proof and corrupting exactly
one thing: unlinked node, wrong root, wrong nibble child, leaf path mismatch,
extension path mismatch, hex-prefix flag confusion, active slot past depth,
value mismatch, partial key consumption.

Every one is a distinct route to proving a receipt that is not in the trie,
which is a route to collecting an escrow without settling.

A `Null` verifier that enforces nothing is included, and a meta-test asserts
that **every forgery case fails against it**. A case that passes against `Null`
is not testing anything. This exists because a forgery test written after the
implementation tends to encode what the code does rather than what it must do,
and this is the axis where that failure is most expensive.

### Built so far

- `harness.rs` — native fixtures to circuit witness, with `verify()` and
  `cost()`
- `path.rs` — hex-prefix flags, canonical-form checks, nibble access; 5 tests

The two negative path tests protect something subtle. A hex-prefix byte has two
spare bits and, on even paths, a spare low nibble. None affect the decoded
path, but all affect the node's bytes and therefore its keccak hash. Leaving
them unconstrained would not let a prover change a path — it would let them
grind a node hash, which is a different attack on the same link. **Canonical
form is load-bearing in a hash-linked structure in a way it is not in ordinary
parsing.**

### A correction to the branch-node size estimate

The fixture-sanity test caught an error in the ~530-570 byte figure quoted
earlier for branch nodes. Measured:

| Branch fill | Size | Prefix |
|---|---|---|
| One hash child, 15 empty | 50 B | `0xf1`, short form |
| All 16 hash children | 532 B | `0xf9`, two length bytes |

Node size scales sharply with fill. Receipt tries have mostly-full branches
near the root and sparse ones deeper, so `MAX_MPT_NODE_BYTES` cannot be set
from a structural estimate. It needs the real distribution, and the binding
figure is the **worst node per proof**, not the average: all nodes in a proof
share one compiled buffer size, so a single dense root branch raises the bound
for every node beneath it.

### Still to build

`node.rs` — branch, extension, and leaf decoding, including the specialized
16-child branch reader — and the traversal: keccak link per level,
nibble-indexed child selection, termination.

### The open cost question

The current projection of ~12.4M constraints **excludes MPT node RLP
decoding**, estimated at roughly 9M more. The specialized branch decoder is the
thing most likely to change that materially: branch children are almost
entirely fixed-shape, either `0x80` (empty) or `0xa0` followed by 32 bytes, so
the layout is derivable from 16 one-byte reads rather than 16 full item
decodes. `report_cost` is wired to measure it as soon as the verifier exists.

## MPT traversal works, and costs 4.8x the projection

Measured 2026-08-13. The adversarial suite passes: genuine proof accepted, all
nine forgeries rejected.

**5.31M constraints per traversal level** at a 640-byte node bound, against a
projected 1.11M. The gap is that conditional enforcement made it necessary to
run *both* node decoders at every level, not just the one matching the node's
shape.

| Depth | Total | Memory | Time |
|---|---|---|---|
| 6 | 36.0M | ~101 GB | ~252s |
| 9 | 51.9M | ~145 GB | ~363s |
| 16 | 89.1M | ~249 GB | ~624s |

Even depth 6 exceeds any plausible enclave allocation. **The relation as built
does not fit**, and the gap is too large for bounds tightening alone to close:
the per-level cost scales with the node bound, so halving it to 320 bytes still
leaves depth 9 near 26M and ~73 GB.

### Why both decoders run

A circuit cannot branch. A caller that does not know a node's shape must run
both interpretations and select, and that only works when each is total —
computing a possibly-wrong answer rather than emitting a false constraint. The
decoders assert, so each needs an `active` gate, and both still execute.

The measured split per level: keccak link ~0.80M, `is_branch` ~0.08M, both
decoders ~0.26M, child hash ~0.16M, path match ~0.44M, tail read ~0.16M, and
the remainder in value matching and the per-level selects.

### The obvious lever, unexplored

Node shape is knowable off-circuit: the witness builder knows whether each
level is a branch, extension, or leaf. Supplying that as a witness flag and
gating the decoders on it would let one decoder's constraints bind while the
other's are skipped — but *both would still be emitted*, since R1CS has no
dynamic dispatch. The saving would come only from work that can be made
constant, not from skipping constraint generation.

The real lever is reducing what each level does at all. Candidates, in
descending expected value:

1. **Separate the leaf level from the interior levels.** Only the last level can
   terminate, and only interior levels need branch handling. A circuit with
   `MAX_DEPTH - 1` interior levels plus one leaf level halves the decoder work.
2. **Drop extension-node support.** Receipt tries built over sequential integer
   keys rarely produce extensions. If the witness builder can guarantee their
   absence, the short-node decoder disappears from interior levels entirely.
3. **Shrink the node bound.** Linear in cost, but bounded by the fund-loss
   consideration recorded above.

None of these is speculative work: each is measurable against the existing
suite, which now provides a correctness oracle.

### What the debugging cost

Four wrong guesses preceded the actual bug. The failure was `total_nibbles`
computed from the padded key buffer's width rather than a witnessed length, so
the exact-consumption invariant could never be satisfied. The trait had no
`key_len` parameter at all — a genuine interface gap, since the real key is
`rlp(transactionIndex)` whose length varies.

What found it was mechanical, not clever: `harness::stage_map` reports the
constraint index where each phase ends, and per-sub-step markers narrowed the
failure to two constraints past the level-1 tail read. That named the culprit
exactly. Reach for the constraint map before reasoning about which invariant
looks suspicious.

## Optimization phase: 21.25M to 15.75M, and where the cost actually is

Measured 2026-08-13, depth 4 at a 640-byte node bound.

The profiler (`MPT_PROFILE=1`, kept in `traverse.rs` rather than deleted) gives
the per-level breakdown that made this tractable:

| Sub-step | Constraints | Share |
|---|---|---|
| **value comparison** | **2,018,951** | **51%** |
| keccak link hash | 798,884 | 20% |
| path match | 443,392 | 11% |
| both node decoders | 259,999 | 7% |
| child hash read | 160,860 | 4% |
| tail read | 160,514 | 4% |
| `is_branch` | 82,993 | 2% |
| flags, advance, finish | ~6,300 | <1% |

This contradicts the optimization plan recorded in the previous section, which
targeted the decoders. **The decoders are 7%.** Running both per level, which
conditional enforcement forced, was never the problem.

### What worked: share indicators across the value read

The value comparison called `one_hot` inside a per-byte loop, costing
`value.len() * node.len() * ~10`. Reading the run once with `select_bytes`,
which computes the indicators once and reuses them, took it from 3.39M to
2.02M. Total dropped 21.25M to 15.75M.

### What failed: comparing by hash

Hashing both sides and comparing 32 bytes looks like it should win, replacing a
long comparison with a fixed one. Measured at 3.08M, worse than the 2.02M it
replaced.

It loses because reading the node's tail as a bounded buffer needs
`select_bytes(node, offset, node.len())` — 640 bytes at 640 offsets, *larger*
than the 512-byte read it replaces — and then pays two variable-length keccaks
on top.

The recurring lesson, now three times over: **the cost is the windowed read,
not what you do with the bytes afterwards.** Any rewrite that still reads a
witness-positioned run of a buffer pays the same price regardless.

### The value bound is a direct lever

Cost scales linearly with `MAX_RECEIPT_BYTES`, at roughly 5.8k constraints per
value byte:

| Value bound | Total | Per level |
|---|---|---|
| 512 B | 15.75M | 3.94M |
| 256 B | 12.76M | 3.19M |
| 128 B | 10.48M | 2.62M |
| 64 B | 9.14M | 2.29M |

This couples the receipt-size bound to the traversal cost, which was not
previously visible: the leaf's value *is* the receipt, so `MAX_RECEIPT_BYTES`
appears in the MPT term as well as the receipt-hash term.

### Remaining levers, revised

The old list targeted the wrong term. In descending expected value now:

1. **Run value comparison only at the terminating level.** It is 51% of every
   level but is meaningful only at the leaf. A circuit with `MAX_DEPTH - 1`
   interior levels plus one leaf level removes it from all but one.
2. **Shrink `MAX_RECEIPT_BYTES`,** at ~5.8k per byte, bounded by the fund-loss
   consideration recorded above.
3. **Shrink `MAX_MPT_NODE_BYTES`,** which scales the keccak link and every
   windowed read.
4. Decoder work is 7% and not worth restructuring.

## Hoisting the value comparison: 15.75M to 9.72M

Measured 2026-08-13, depth 4 at 640-byte nodes and a 512-byte value bound.

The value comparison was 51% of every level but is meaningful only at the
terminating leaf. It now runs **once**, after the level loop, against a node
buffer and tail bounds selected across levels by the `terminates` flag.

| | Per level | Total |
|---|---|---|
| before | 2,018,951 | 15.75M |
| after | 5,126 | **9.72M** |

The per-level residue is the handful of selects that carry the terminating
level's node and tail forward. A 394x reduction on that sub-step, and 38% off
the whole traversal.

### The soundness question this raises

Hoisting a per-level invariant to a single post-loop check is exactly where a
subtle hole appears. The existing `rejects_value_mismatch` case does **not**
cover it: it corrupts the claimed value, which any sane implementation catches.

What it could miss is a wrong *selection* — if the hoisted check binds against
the last active level, or the first, rather than the terminating one, a prover
places the claimed value in a branch node's value slot and satisfies invariant 6
without any leaf holding it.

`rejects_value_at_a_non_terminating_level` covers this directly: the root
branch's value slot holds the claimed value while the leaf holds something else.
It is validated against the null verifier like every other forgery case, so it
is known to have teeth.

**General rule for this kind of optimization: hoisting an invariant out of a
loop needs a new forgery case aimed at the selection, not just the existing case
aimed at the value.**

### Revised remaining levers

| Sub-step | Was | Now | Share |
|---|---|---|---|
| keccak link hash | 798,884 | 798,884 | 33% |
| path match | 443,392 | 443,392 | 18% |
| both node decoders | 259,999 | 259,999 | 11% |
| child hash read | 160,860 | 160,860 | 7% |
| tail read | 160,514 | 160,514 | 7% |
| `is_branch` | 82,993 | 82,993 | 3% |
| value comparison | 2,018,951 | 5,126 | <1% |

The keccak link is now the largest term at 33%, and it is irreducible: every
node must be hashed to authenticate it against its parent. Its cost scales with
`MAX_MPT_NODE_BYTES` at five blocks per 640-byte node.

Path matching at 18% is the next candidate. It loops `MAX_PATH_NIBBLES = 64`
times calling `nibble_at` on both the node and the key, where a real receipt-key
path is at most 8 nibbles. Bounding it by the key length rather than a
worst-case constant should cut it substantially.

## Bounds, not code: 9.72M to 7.33M

Measured 2026-08-13. Two changes, both to compiled bounds rather than logic.

### The key buffer was 8x larger than anything real

Path matching iterates `key.len() * 2` times, calling `nibble_at` on both the
node and the key each iteration. The harness allocated a 32-byte key buffer,
giving 64 iterations.

A receipt-trie key is `rlp(transactionIndex)`. The index fits in three bytes for
any plausible block, so the encoding is at most four. At a 4-byte bound:

| | Constraints |
|---|---|
| path match, 32-byte key | 443,392 |
| path match, 4-byte key | **53,408** |

8.3x, and the total fell 9.72M to 8.15M.

Worth noting the first attempt here changed nothing: replacing the hardcoded
`MAX_PATH_NIBBLES = 64` with `key.len() * 2` was a no-op, because the buffer was
32 bytes and the derived bound equalled the constant. The lever was the harness
bound, not the loop.

### The node bound had unusable headroom

Cost against `MAX_MPT_NODE_BYTES`, depth 4:

| Node bound | Total | Per level |
|---|---|---|
| 640 B | 8.15M | 2,038k |
| **544 B** | **7.33M** | **1,833k** |
| 320 B | 4.31M | 1,079k |
| 192 B | 2.86M | 714k |

Super-linear, because both the keccak block count and every windowed read shrink
together.

544 is the structurally correct bound: a fully-populated branch node is 532
bytes — 16 hash references at 33 bytes, an empty value slot, a 3-byte list
header — so nothing larger can occur in a receipt trie. The previous 640 was
paying for headroom that cannot be used.

Below 544 the bound stops being free: it excludes node shapes that genuinely
occur, and an unprovable node means an executor who has already paid cannot
collect. That is the fund-loss boundary recorded above, and it is where the
mainnet distribution measurement becomes necessary rather than merely useful.

### Where the traversal stands

Per level at 544-byte nodes and a 4-byte key:

| Sub-step | Constraints | Share |
|---|---|---|
| **keccak link hash** | **798,884** | **44%** |
| both node decoders | 259,999 | 14% |
| child hash read | 160,608 | 9% |
| tail read | 160,514 | 9% |
| `is_branch` | 82,993 | 5% |
| path match | 53,408 | 3% |
| value comparison | 5,126 | <1% |

Full relation, adding 4.06M for RLP parsing, receipt hash, and the two
commitment hashes:

| Depth | Total | Peak RAM | Proving key | Time |
|---|---|---|---|---|
| 4 | 11.4M | 32 GB | 2.6 GB | 80s |
| 6 | 15.1M | 42 GB | 3.4 GB | 105s |
| 9 | 20.6M | 58 GB | 4.6 GB | 144s |
| 16 | 33.4M | 94 GB | 7.5 GB | 234s |

Cumulative from the start of the optimization phase: **21.25M to 7.33M on the
traversal, 2.9x.** Depth 4 is now within a plausible enclave allocation and
close to the 75s target.

### What is left

The keccak link is 44% and irreducible: every node must be hashed to
authenticate it against its parent, and the only lever is the node bound, which
is now at its structural floor.

Real receipt tries for typical blocks are 3-4 levels deep, so depth 4 covering
most blocks is the practical question rather than depth 9 or 16. That reframes
the bounds measurement: not "what depth do we support" but "what fraction of
blocks does depth N cover, and what does an unprovable settlement cost."

## Merging the two windowed reads: 7.33M to 6.79M

Measured 2026-08-13.

Each level performed two separate 32-byte windowed reads of the same node
buffer: the branch child reference at one offset, the extension tail at another.
At ~10 constraints per buffer byte over a 544-byte node, each was ~160k.

Selecting the *offset* first and reading once removes one of them.
`branch_child_hash` is split into `branch_child_offset` plus a read, so the
traversal can pick between the branch offset and the tail offset before
touching the buffer.

| Sub-step | Before | After |
|---|---|---|
| child hash read | 160,608 | **94** |
| tail read | 160,514 | 135,843 |

The child read collapses to nothing because it merged into the tail read, which
is now the single windowed read per level.

### An estimate that was wrong by 4x

The interior/leaf split was proposed earlier as the largest remaining lever,
worth "roughly halving decoder work." Computed against the current profile it is
**6%**:

- Interior levels save 10,895 by skipping flag reads and value selects.
- The leaf level saves 373,601 once by skipping the branch machinery.

The reason is that hoisting the value comparison already captured most of what
the split would have given. Termination logic is no longer per-level, so
separating terminating from non-terminating levels has little left to remove.

Recorded because the mistake is instructive: an optimization's value is
relative to the current profile, not the one that motivated it. Re-measure
before implementing a plan made two optimizations ago.

### Where the traversal stands

Per level at 544-byte nodes and a 4-byte key:

| Sub-step | Constraints | Share |
|---|---|---|
| **keccak link hash** | **795,524** | **47%** |
| both node decoders | 225,439 | 13% |
| tail read | 135,843 | 8% |
| `is_branch` | 72,625 | 4% |
| path match | 46,496 | 3% |
| flags, value, advance | ~9,600 | <1% |

Traversal total at depth 4: **6.79M**. Cumulative for the optimization phase:
**21.25M to 6.79M, 3.1x.**

The keccak link is 47% and irreducible. Everything else combined is now smaller
than it. Further circuit-level work has sharply diminishing returns; the
remaining levers are the node bound, which is at its structural floor, and the
depth bound, which is a product decision about block coverage.

## The ERC-20 receipt relation, measured

Built and measured 2026-08-13. The adversarial suite passes on the first
attempt: four positive cases and twelve forgeries.

| Receipt bound | Constraints |
|---|---|
| 512 B | 996,809 |
| 1024 B | 1,888,713 |
| 2048 B | 3,672,521 |

Roughly 1,790 constraints per bounded byte, linear as expected.

**This is the first projection in the project that was approximately right.**
The 4.06M estimate for the non-MPT terms, made before any relation code existed,
lands against a measured 3.93M at a 2048-byte bound. Every earlier projection
was wrong by a large factor — 8x on the MPT term, 4.8x on per-level cost, and
51%-versus-7% on which sub-step dominated.

The difference is that the receipt estimate was extrapolated from an already
measured decoder benchmark, while the earlier ones were derived from structure
alone. Worth remembering when the native relation is costed.

### Full step-2 relation

MPT traversal at 1.70M per level, plus the receipt relation, plus 0.26M for the
commitment and statement hashes:

| Depth | Receipt bound | Total | Peak RAM | Time |
|---|---|---|---|---|
| 4 | 512 B | 8.0M | 23 GB | 56s |
| 4 | 1024 B | 8.9M | 25 GB | 63s |
| 4 | 2048 B | 10.7M | 30 GB | 75s |
| 6 | 1024 B | 12.3M | 35 GB | 86s |
| 9 | 1024 B | 17.4M | 49 GB | 122s |

**Depth 4 with a 2048-byte receipt bound lands exactly at the 75s target**, and
depth 4 with a 1024-byte bound has real margin. Memory is comfortable at every
row.

These remain derived rather than observed: RAM extrapolates the arkworks
benchmark's 2.8 GB per million, and time extrapolates 21s per 3M measured on a
multiplication chain, which is the prover's best case. No proof has been
generated for this circuit.

### What the suite covers

Twelve forgeries, each validated against a null relation so it is known to have
teeth: failed status, wrong emitter, wrong recipient, wrong amount,
Approval-instead-of-Transfer, wrong topic count, dirty recipient padding, wrong
data length, out-of-range log index, unsupported envelope, wrong bloom length,
wrong payload field count.

Two are worth naming.

**Approval has the identical three-topic shape to Transfer** — signature, two
addresses, value in data. Without a topic-0 check, an allowance change satisfies
a commitment to a payment. It is the cheapest possible forgery and the easiest
check to omit.

**Any sender must be accepted.** Spec 12.4 leaves topic 1 unconstrained and
spec 9 records why binding it is unreachable, so a relation that rejects an
unusual sender is *wrong* rather than merely strict. The positive case tests
four senders including the recipient and the token contract itself.

### Envelope handling

The check is positive on both branches: either an RLP list header, meaning bits
7 and 6 set, or a type prefix in `0x01`-`0x04`. The tempting alternative — test
for a valid prefix, treat everything else as legacy — accepts a receipt
beginning `0x7f` as a legacy payload whose RLP header is nonsense.

## MEASURED: a real proof, 36.6s and 23.7 GB

Generated 2026-08-13 on an i9-14900HX, 24 cores, 94 GB, at
`RAYON_NUM_THREADS=16`. Reproduce with
`cargo run -p mirage-prover --release --bin measure`.

**Every memory and timing figure before this point was derived. These are
measured.**

Circuit: MPT inclusion (depth 4, 544-byte nodes, 4-byte key) plus the full
spec 12.6 ERC-20 receipt relation (1024-byte bound). **9,129,599 constraints**,
satisfied by a genuine witness.

| Metric | Derived estimate | Measured | Error |
|---|---|---|---|
| Prove time | ~64s | **36.6s** | 1.7x pessimistic |
| Peak RSS | ~26 GB | **23.7 GB** | 1.1x pessimistic |
| Proving key | ~2.0 GB | 3.66 GB (1.83 compressed) | 1.8x optimistic |
| Verify | — | 1.47 ms | — |
| Proof size | — | 128 bytes | — |
| Setup | — | 44.8s | — |

**36.6s against the Section 19.7 budget of 75s p95: within, with 2x margin.**

### Where the proving time goes

| Phase | Time | Share |
|---|---|---|
| R1CS to QAP witness map | 10.5s | 29% |
| Compute C | 10.1s | 28% |
| Inlining LCs | 8.1s | 23% |
| Constraint synthesis | 3.5s | 10% |
| Compute B in G2 | 1.9s | 5% |
| Compute B in G1 | 0.9s | 3% |
| Compute A | 0.7s | 2% |

Constraint synthesis plus LC inlining is 11.6s, **32% of proving time**, and
both are serial: `ConstraintSystemRef` wraps `Rc<RefCell<_>>`, which is `!Send`
and cannot cross a rayon boundary. That is the Amdahl ceiling recorded earlier,
now measured rather than predicted. More cores will not help those phases.

### Why the derived figures were wrong

The time estimate extrapolated 21s per 3M from a multiplication chain, which is
the prover's best case, so it should have been *optimistic*. It was
**pessimistic by 1.7x** instead.

The reason is that the earlier benchmark measured a circuit dominated by MSM
over dense witness values. This relation is boolean-heavy — keccak is bit
operations throughout — and Pippenger's MSM nearly skips 0/1 scalars. That is
the same effect that made the earlier `bool` benchmark circuit look
artificially fast, recorded above as a benchmark artifact. Here it is not an
artifact: the real circuit genuinely is boolean-dense, so it genuinely gets the
speedup.

The memory estimate was close, 1.1x pessimistic, which retrospectively
validates the 2.8 GB per million figure from the arkworks benchmark for this
class of circuit.

The proving key was underestimated by 1.8x: 224 bytes per constraint was the
snarkjs zkey figure, and arkworks' uncompressed serialization is larger. The
compressed figure of 1.83 GB is the one that matters for distribution.

### What is not yet in the circuit

The header parse (spec 12.7.1) and the statement hash (10.2), roughly 1.4M
constraints between them, and the delayed-witness ancestry chain (12.7), which
is step 5 and deliberately out of scope.

Scaling the measured figures by constraint count, the complete step-2 relation
at ~10.5M constraints projects to roughly **42s and 27 GB** — still comfortably
inside budget.

### Operational note

Setup takes 44.8s and produces a 3.66 GB key. That is `circuit_specific_setup`,
a toy setup, not a ceremony: spec 18.2 requires a multiparty Phase 2 producing
the same artifact through a sound process. Two 2026 exploits came from skipping
exactly that step.

## MEASURED: the complete step-2 relation, 43.4s and 26.0 GB

Generated 2026-08-13, same machine and thread count as the previous run.

Circuit: header parse + MPT inclusion + ERC-20 receipt relation + statement
hash. **10,622,266 constraints**, two public signals, satisfied by a genuine
witness and rejecting a proof presented against a different statement.

| Metric | Derived | Measured |
|---|---|---|
| Prove | ~74s | **43.4s** |
| Peak RSS | ~30 GB | **26.0 GB** |
| Verify | — | 1.65 ms |
| Proof | — | 128 bytes |
| Public inputs | — | 2 |

**43.4s against the Section 19.7 budget of 75s p95, with 1.7x margin.**

The scaling from the previous run is close to linear: 9.13M constraints at
36.6s and 23.7 GB, versus 10.62M at 43.4s and 26.0 GB. Constraints rose 16%,
time 19%, memory 10%.

### What the relation now binds

The earlier proof checked pieces independently. This one closes a chain:

```text
header -> receiptsRoot -> MPT inclusion -> receipt -> Transfer log
```

The header supplies the root rather than the caller. A caller-supplied root
would let a prover invent an entire trie containing whatever it liked, which
makes every other check decorative.

The statement hash is the only public output, so the proof is bound to one
chain, escrow, request, row, bond attempt, collector, payout, and witness
block. The measurement binary checks that a proof presented against a modified
statement is rejected, which is the property the whole two-signal design exists
to provide.

### The two new gadgets

| Gadget | Constraints |
|---|---|
| Header parse, 640 B bound | 1,024,577 |
| Header parse, 1024 B bound | 1,564,865 |
| Statement hash, 285 B preimage | 460,952 |

A real mainnet post-Prague header is 612 bytes, so a 640-byte bound carries
almost no waste while 1024 costs an extra 540k for headroom that cannot occur.
That is the same lever as the node and key bounds, and it is now measured
rather than assumed.

The statement hash's `every_field_is_bound` test mutates all fourteen context
fields and requires each to change the digest. Spec 10.1 calls a dropped field
a critical soundness bug, and this is what would catch one.

### What remains unmeasured

The intent commitment (spec 8.3) is not yet in the circuit, roughly 300k
constraints. The delayed-witness ancestry chain (12.7) is step 5 and out of
scope for this build; at ~800k constraints per header hashed it is the largest
remaining term in the full design.

## MEASURED: step 2 complete, 43.8s and 26.4 GB

Generated 2026-08-13. **10,930,880 constraints**, two public signals.

| Metric | Derived | Measured |
|---|---|---|
| Prove | ~77s | **43.8s** (41.4s on a repeat run) |
| Peak RSS | ~31 GB | **26.4 GB** |
| Setup | — | 51.7s |
| Proving key | — | **4.19 GB, 2.09 GB compressed** |
| Verify | — | 1.60 ms |
| Proof | — | 128 bytes |

Two runs of the identical circuit gave 43.8s and 41.4s, so single measurements
carry roughly 5% variance. Treat any one figure accordingly.

The proving key scales linearly from the 9.13M run's 3.66 GB / 1.83 GB, within
5% of prediction. That is worth noting because the *original* estimate for this
metric, 224 bytes per constraint taken from a snarkjs zkey, was off by 1.8x:
arkworks' serialization is larger. Extrapolating from a measurement of the same
implementation works; extrapolating from a different one did not.

The 2.09 GB compressed figure is the operationally significant one. Every prover
needs the key resident, and spec 18.2 requires it come from a multiparty
ceremony rather than `circuit_specific_setup`. So it is 2 GB whose provenance
must be auditable, not merely 2 GB to distribute — both 2026 exploits recorded
above came from keys generated without a sound Phase 2.

**43.8s against the Section 19.7 budget of 75s p95, with 1.7x margin.**

### The commitment gap, closed

Until this point the relation proved *a* Transfer, not *the committed*
Transfer. `token`, `recipient` and `amount` were free witnesses: a prover could
supply any triple and prove a Transfer matching it, anywhere in the trie.

The commitment gadget opens the escrow's stored `intentCommitment` and the
opened values become the intent the receipt relation checks. Two tests
demonstrate the gap is closed rather than merely addressed:

- `rejects_a_substituted_recipient` redirects the settlement while leaving the
  commitment, and therefore the public signals, untouched.
- `rejects_a_substituted_amount` does the same for the value.

Both were satisfiable before the gadget was wired.

The gadget costs **307,134 constraints** for a 226-byte preimage, and adds
0.4s and 0.4 GB to the proof — cheap relative to what it closes.

Twelve gadget-level tests cover the openings and the spec 12.3 intent
assertions: a mismatched opening, a substituted recipient, a native row
carrying a token, an ERC-20 row without one, zero recipient, zero amount, an
out-of-range asset kind, and proof portability between escrows.

### The complete binding chain

```text
commitment  ->  token / recipient / amount
header      ->  receiptsRoot -> MPT inclusion -> receipt -> Transfer log
statement   ->  two public signals
```

Each link was absent at some point and each absence made everything downstream
decorative. A caller-supplied receipts root lets a prover invent a trie; free
intent witnesses let a prover pick the settlement; no statement hash leaves the
proof unbound to any escrow, row, or attempt.

### Cost breakdown

| Component | Constraints |
|---|---|
| MPT traversal, depth 4 | 6.79M |
| ERC-20 receipt relation, 1024 B | 1.89M |
| Header parse, 640 B | 1.02M |
| Statement hash | 0.46M |
| Commitment open | 0.31M |
| Allocation and glue | ~0.46M |
| **Total** | **10.93M** |

### What step 2 does not include

The delayed-witness ancestry chain (spec 12.7), which is step 5. The
transaction block is public in this build, which spec 5.3 marks testnet-only
for exactly that reason. At roughly 800k constraints per header hashed and
`MIN_WITNESS_DISTANCE = 8`, ancestry is ~6.4M constraints — comparable to
everything currently in the circuit, and it would roughly double the proof.

Also outstanding: no proof has been generated against a real mainnet receipt,
and no Solidity verifier has been exported or run. The fixture is structurally
valid Ethereum encoding but hand-built.

## MEASURED: 100 real mainnet fixtures, and a bound that was wrong

Collected 2026-08-13 from `eth.drpc.org`. Every fixture's receipt trie was
rebuilt locally and its root checked against the block header's
`receiptsRoot`, so each corresponds to real chain state rather than to my
understanding of the encoding.

100 fixtures, 16 distinct tokens, 34 blocks, transaction indices 0 to 75.

| Metric | p50 | p90 | max | Bound | |
|---|---|---|---|---|---|
| depth | 3 | 3 | **3** | 4 | fits |
| node bytes | 500 | 532 | **532** | 544 | fits |
| receipt bytes | — | — | **428** | 1024 | fits, with room |
| header bytes | 649 | 652 | **655** | 640 | **EXCEEDS** |

Receipt types: 92 EIP-1559 (type 2), 8 legacy (type 0).

### The header bound was wrong

640 was set from a hand-built fixture measuring 612 bytes, on the reasoning
that it gave margin without unusable headroom. Real headers run 632 to 655.

The cause is `extraData`, which is builder-controlled and up to 32 bytes. My
synthetic header had an empty one. **A bound derived from a single synthetic
sample was wrong within five real blocks.**

Widening to 1024 costs about 540k constraints, measured earlier, which is
affordable against 10.93M. It is also the cheap direction to be wrong in: an
over-tight bound makes a settlement unprovable, and spec 12.9 puts that loss on
an executor who has already paid.

### The other three bounds hold, with an important caveat

Node bytes max at 532 against a 544 bound is a 2% margin, which is tighter than
it looks safe to run. But 532 is the *structural* worst case computed earlier —
16 hash references at 33 bytes plus an empty value slot plus a 3-byte header —
so a receipt-trie branch node cannot exceed it. The margin is small because the
bound was derived from the structure rather than guessed, and the data confirms
the structure.

Depth 3 against a bound of 4 is more comfortable, but this sample spans only 34
blocks near the tip. Receipt-trie depth grows with transaction count, so a
larger block would go deeper. The free endpoint's timeout on archive blocks kept
sampling near the tip, and that is a real limitation of this dataset rather than
evidence that depth 4 always suffices.

Receipt bytes max at 428 against 1024 is comfortable, but this is deliberately
the easy case: the scope is direct ERC-20 transfers with exactly one log. A
token with transfer hooks emitting several events would be larger, and spec
12.9's `MAX_LOGS` is what bounds that.

### What the dataset enables

Each fixture carries the header, the trie key, the receipt, the inclusion path,
and a spec 8.3 commitment derived from the real Transfer. That is everything the
relation consumes, so the circuit can now be run end to end against real chain
data rather than a hand-built fixture.

Only `settlementToken`, `recipient` and `settlementAmount` are real. The
escrow-side commitment fields do not exist for a historical transaction and are
derived from the transaction hash, which keeps fixtures reproducible while
making each commitment distinct.

## END TO END: the circuit satisfies 100 real mainnet transactions

Run 2026-08-13. All 100 fixtures satisfied, in 889 seconds of constraint
synthesis.

This is the difference between "works on a fixture I built" and "works on data
Ethereum built". Every prior test, including the 105 unit tests and the proving
runs, used a hand-constructed witness. Those prove the gadgets do what I think
they do; this proves the relation matches what the chain actually produces.

Coverage: 16 distinct tokens, 34 blocks, transaction indices 0 to 75, receipt
types 0 (legacy, 8 fixtures) and 2 (EIP-1559, 92).

The test synthesises rather than proves. A full Groth16 proof per fixture would
be roughly 70 minutes at the measured 43.8s each; satisfaction is what
correctness turns on, and proving cost is measured separately.

### What it validates that unit tests could not

- **Real RLP.** Mainnet receipts carry log data, bloom filters and gas values
  the fixture generator did not choose. Any disagreement between the circuit's
  decoder and the chain's encoder shows up here.
- **Real trie shapes.** Node fill, inline-versus-hash child references, and
  extension nodes appear as the chain produces them, not as a fixture builder
  arranges them.
- **Real header layouts.** Which is how the 640-byte bound was caught.
- **Both envelope types.** Legacy receipts have no type prefix; the positive
  branch check in `envelope::parse` is exercised on real instances of each.

### Caveats worth carrying

The dataset spans 34 blocks near the chain tip, because the free RPC endpoint
times out on `eth_getBlockReceipts` for archive blocks. Receipt-trie depth grows
with a block's transaction count, so the observed max of 3 is not evidence that
depth 4 suffices in general. A run against an archive node with a wide block
stride would settle that.

Scope is also deliberately narrow: direct ERC-20 transfer calls, one Transfer
log, status 1. That is what spec 20.3 requires executors to produce, but it
means the dataset says nothing about tokens with transfer hooks, which is what
`MAX_LOGS` bounds.

## Single-log receipts: 16% off the receipt relation

Measured 2026-08-13.

The log walk exists to reach log `k` of up to `MAX_LOGS = 8`, decoding every log
before it. Spec 20.3 requires production settlements be a direct `transfer()`
call, whose receipt carries exactly one event, so the walk reaches index 0 of a
one-element list.

| Receipt bound | General | Single-log | Saved |
|---|---|---|---|
| 512 B | 996,809 | 828,453 | 17% |
| 1024 B | 1,888,713 | 1,591,333 | **16%** |
| 2048 B | 3,672,521 | 3,117,093 | 15% |

The walk alone measured 338,867 constraints at the 1024-byte bound, 18% of the
whole receipt relation.

### What it trades

A receipt with any second event becomes unprovable: a token with a transfer
hook, a fee-on-transfer token emitting a second Transfer, or anything that logs
alongside its transfer.

That is the same class of decision as the compiled bounds, and it carries the
same asymmetry recorded above. Spec 12.9 puts the cost of an unprovable
settlement on the executor, who has already paid, so **the enclave's
pre-settlement token review becomes load-bearing rather than advisory**. A
token that passes review but emits a second event at execution time produces a
receipt this circuit cannot prove.

`sole_log` enforces the restriction rather than assuming it: the log must fill
the logs list exactly. Without that check a prover appends a second event whose
contents the relation never inspects, which would defeat the point.

### How it is validated

Both relations exist and both run the same adversarial suite. Three tests cover
the change specifically:

- `single_log_adversarial_suite` runs all twelve forgeries plus the positive
  cases against the variant.
- `single_log_rejects_a_second_event` asserts the general relation *accepts* a
  two-log receipt and the variant rejects it, which pins the narrowing rather
  than leaving it implicit.
- `variants_agree_on_single_log_receipts` checks both give the same verdict on
  four single-log cases including a legacy envelope and a failed status, so the
  optimization changed cost rather than the relation.

### Net effect on the circuit

The relation is now **11,176,860 constraints**, up from 10,930,880. The log walk
saved ~297k while the header bound widening, forced by real mainnet data, cost
~540k. Net +246k for a circuit that handles real headers and skips work that
cannot occur.

## Bounds tightened from the real distribution: 11.18M to 9.46M

Measured 2026-08-13, then verified: all 100 mainnet fixtures still satisfy the
circuit at the tightened bounds.

| Bound | Was | Observed across 100 fixtures | Now |
|---|---|---|---|
| receipt bytes | 1024 | 425 to 428 | **512** |
| key bytes | 4 | 1, all of them | **3** |
| header bytes | 1024 | 632 to 655 | **704** |
| node bytes | 544 | 115 to 532 | 544, unchanged |
| depth | 4 | 2 to 3 | 4, unchanged |

**11,176,860 to 9,463,224 constraints, 15%.**

### How much headroom each keeps, and why they differ

The right margin is not a fixed percentage. It is proportional to how much of
the variation can be *derived* versus merely *observed*.

- **Key at 3** is the structural maximum. `rlp(transactionIndex)` is one byte
  below index 128, two below 256, three below 65,536, and no block carries 65k
  transactions. All 100 fixtures had a 1-byte key; the bound is set from the
  encoding rule rather than the sample.
- **Header at 704** keeps 49 bytes over the observed 655. The 23-byte spread
  across the sample comes entirely from `extraData`, which consensus caps at 32
  bytes, and this sample spans 34 blocks near the tip. A builder not sampled
  could use the full cap.
- **Receipt at 512** keeps about 20%. Direct-transfer receipt size is dominated
  by the fixed 256-byte bloom plus one three-topic log, so there is little room
  to vary within the single-log scope, but the margin covers a wider
  `cumulativeGasUsed` or a marginally larger log.
- **Node at 544** is unchanged: 532 is the structural worst case for a
  fully-populated branch, so the 2% margin is small because the bound was
  derived, and the data confirms the derivation.
- **Depth at 4** is unchanged despite an observed max of 3. Receipt-trie depth
  grows with a block's transaction count, and this sample sits near the tip
  because the free endpoint times out on archive blocks. Tightening to 3 on
  this evidence would be exactly the mistake the 640-byte header bound already
  made once.

### A derivation that lost to the data

Computing the structural header maximum from field widths gave 630 bytes, below
the observed 655. Rather than debug the arithmetic against data that already
contradicted it, the bound was set from the empirical maximum plus the known
`extraData` cap.

Worth recording as a habit: when a derivation disagrees with measurement, the
measurement is the authority until the derivation is understood.

### Cumulative

| Stage | Constraints |
|---|---|
| First working relation | 10,930,880 |
| Header widened for real data | 11,176,860 |
| Single-log receipt relation | (included above) |
| Bounds tightened from the distribution | **9,463,224** |

Down 13% from the first working version, while handling real mainnet headers
that the original bound rejected.

## MEASURED: the Solidity verifier, 4,858 bytes deployed

Exported 2026-08-13 from this circuit's own verification key, then compiled with
solc `--optimize --optimize-runs 200`.

| | |
|---|---|
| Solidity source | 24,979 bytes, 540 lines |
| **Deployed runtime** | **4,858 bytes** |
| EIP-170 limit | 24,576, leaving 19,718 spare |
| Internal budget (spec 15.4) | 20,000, leaving 15,142 for the state machine |

The backend evaluation's independently-built figure was 4,857. Measuring our own
gives 4,858 — a one-byte difference, which retrospectively validates that whole
comparison. It was the last number in the evaluation still inherited rather than
measured.

The escrow's state machine is roughly 3-4KB, so verifier plus state machine lands
near 9KB against a 20,000-byte budget. Spec 15.4's warning about padding into a
rare size band is the live concern at that margin, not the limit itself.

### What the contract is

Remco Bloemen's Groth16 template, rendered by `taceo-groth16-sol` from gnark's
version. It is self-contained Solidity: no imports, no linked library, no
DELEGATECALL, and its only external interactions are staticcalls to precompiles
`0x05`, `0x06`, `0x07` and `0x08`. That is what spec 7.2 and 15.1 require, and
it is now checkable in the file rather than taken from a summary.

### The serialization trap

The exporter emits the proof as eight field elements in the order the EVM
pairing precompile expects: `[a.x, a.y, b.x1, b.x0, b.y1, b.y0, c.x, c.y]`.

Note the G2 coordinates are reversed relative to arkworks' natural
serialization, and arkworks writes little-endian where the EVM wants big-endian
words. Getting either wrong produces a verifier that rejects every valid proof
with no diagnostic beyond `false`. The exporter verifies the proof natively
before writing it, so a failing contract test isolates to serialization rather
than to the circuit or the key.

### On-chain: verified, 222,707 gas

A Foundry project under `circuits/` runs the contract against the exported
proof. **All six tests pass.**

| Metric | Measured |
|---|---|
| Verification gas | **222,707** |
| Deployed size, on-chain | 4,858 bytes |
| Storage reads / writes | zero |
| Proof rejected when tampered | yes |
| Proof rejected against a modified statement | yes |

222,707 sits right where spec 15.5 predicts: roughly 193,300 in curve
operations at 0x06, 0x07 and 0x08, plus decoding, calldata and dispatch. The
figure inherited from the backend evaluation was ~220k, so that estimate holds
too.

Zero storage access confirms spec 7.2's no-shared-contract property in execution
rather than only in the source: the contract reaches nothing but precompiles.

### The bug, and why three hypotheses missed it

The first run rejected every valid proof. Three candidates were checked and all
three were wrong:

1. G2 coordinate order — the template stores `X_1` before `X_0`, which the
   exporter already did.
2. The ABI — `verifyProof(uint256[8], uint256[2])` takes a flat array, which the
   test passed.
3. The negation convention — arkworks negates gamma and delta, the same as the
   template.

The actual fault was in slicing serialized bytes: the emitted values were not
valid field elements at all. Comparing before and after, `0xa236...` became
`0x2236...` and `0x99e0...` became `0x19e0...` — the originals exceeded the
BN254 base-field modulus, which is why the pairing precompile rejected them.

Rather than test a fourth hypothesis, the exporter was rewritten to read `x` and
`y` directly off the affine points and convert through `BigUint::to_bytes_be`.
That removes three assumptions at once — arkworks' byte order, its endianness,
and coordinate placement — leaving only G2 ordering, which is confirmed against
the generated assembly.

**The lesson is about the shape of the fix, not the bug.** After three wrong
guesses in the same area, the productive move was eliminating the guessing
surface rather than guessing better. Slicing serialized bytes couples you to a
library's internal layout; reading named fields couples you only to its types,
which the compiler checks.

### A second mistake worth recording

The exported source was first written to `circuits/out/`. Forge treats its `out`
directory as build output and cleared it, destroying the export mid-session.

Generated *source* and build *artifacts* both feel like "output", and any tool
that owns a directory will assume it may clear it. The artifacts now live in
`contracts/`, a name that claims them.

## Also disqualified

- **SP1** fails twice: the shared recursion VK constant, and
  `verifyProof(bytes32 programVKey, ...)` placing a plaintext program ID in
  calldata.
- **UltraHonk**: non-`--optimized` output puts `accumulateRelationEvaluations`
  in an externally linked library reached by delegatecall, breaching Section
  7.2. Third-party sizes 16.9-18.6KB, 731k-2.5M gas. External audit not
  started.
- **plonky3**: no EVM verifier path; issue #511 open since Oct 2024.
- **Sonobe**: Solidity verifiers deleted in the rewrite.

## What no backend choice solves

Every candidate leaves the same work outstanding: the RLP parser, MPT
traversal, and receipt relation must be written from scratch. No maintained
library implements Ethereum receipt-trie inclusion in any framework that also
satisfies the verifier constraints. `axiom-eth` is the closest and is archived,
halo2-only, and does not port.

The backend choice determines the language and the per-constraint cost of that
work, not its existence. Circom would need it in Circom, gnark in Go, arkworks
in Rust with the fewest available primitives.

Two artifacts are worth porting rather than writing:

- **ZoKrates' keccak** for a correct Ethereum sponge with multi-block absorb.
- **`axiom-eth`'s receipt circuits** as a specification of the relation's
  structure, even though the halo2 code itself does not transfer.

## Status

| Decision | State |
|---|---|
| Proof system | **Groth16 / BN254** — settled. Verifier ~4KB, ~220k gas, per-setup VK |
| Implementation | **arkworks (`ark-groth16`, `ark-bn254`)** — settled on measurement |
| Enclave platform | **Fortanix EDP, unchanged** — no migration needed |
| Solidity verifier | `taceo-groth16-sol` exports from arkworks VKs |
| Circuit language | Rust, `ark-r1cs-std` |
| Keccak gadget | **done** — ported from ZoKrates, 153k/block measured |
| Variable-length keccak | **done** — 159.6k/block measured, exhaustively tested |
| Byte primitives | **done** — `prefix_mask`, `assert_zero_tail`, `select_byte(s)`, `one_hot` |
| RLP decoder | **done** — adversarial suite green, 41.5k per `decode_item` |
| MPT adversarial suite | **done** — 9 forgeries, validated against a null verifier |
| MPT hex-prefix paths | **done** — flags, canonical form, nibble access |
| MPT node decode + traversal | in progress |
| Receipt envelope, log selection, header | not started |
| Relation assembly | not started |
| Prover crate | not started |
| Bounds measurement | high value — sets the constants; does not block gadget work |
| Section 12.1 amendment | required — the spec freezes Circom + snarkjs |
| Section 15.2 amendment | required — record the per-setup VK finding |
| Real-circuit benchmark | **open** — synthetic results do not substitute |

### The remaining risk, restated

With spec 12.9's bounds as written the relation is **~43.7M constraints, about
4x over budget**, and the MPT node hashing is ~94% of it. The earlier ~5.7M
figure was an arithmetic error: it counted the MPT term as one bounded hash
rather than 16 independently bounded nodes.

This is not a backend problem and no further backend comparison addresses it.
Cost scales linearly with `MAX_MPT_NODE_BYTES` times `MAX_MPT_DEPTH`, and real
mainnet nodes and depths are far below the compiled worst case. Bounds of ~640
bytes and depth 9 would put the relation within reach.

The binding constraint is memory, not latency: 43.7M constraints is ~120 GB,
which exceeds any plausible enclave allocation, while the ~5 minute proving
time would merely be a spec amendment. Depth 16 at a realistic 640-byte node
bound is ~12.8M and ~36 GB, which is workable — the node-size term is what
breaks it.

Those constants have since been measured against 100 mainnet fixtures: the
relation is 10,426,684 constraints at ~29 GB, confirming this section's
reasoning. See "Update: measured, and the projection held" above.

Proving at those bounds measures **22.6s** (setup 41.7s), inside spec 19.7's 75s
p95. The ~5 minute figure above was for the 43.7M-constraint worst case, so
latency never became the spec amendment this section anticipated.

Two facts to hold onto while building:

- The R1CS keccak cost of ~150-160k constraints per block is structural, and
  every bounded buffer pays its compiled maximum regardless of real input size.
  Section 12.9's bounds are therefore the dominant cost term in the design, not
  a detail.
- `ark-r1cs-std` has live underconstraining bugs (#212, #213, #216) and no
  Picus frontend. Every gadget written here carries its own soundness burden
  with no static analysis to catch a missing constraint.

## Placeholder witness values defeat the tests that would catch them

Recorded 2026-08-17, from `ead0999` ("fix: bind settlement circuit context").

That commit added the constraints binding the parsed header to the statement's
`witnessBlockHash` and `witnessBlockNumber`. Two places still carried a
hardcoded `[0x66; 32]` placeholder for that hash:

- `contracts/proof.json`, left stale because the artifacts were not regenerated
- `crates/relation/tests/mainnet.rs`, in the fixture builder

A fixed placeholder can never equal a real header keccak, so **all 100 mainnet
fixtures failed** at a single constraint index. The commit landed anyway.

Three lessons, in order of how much time each would have saved:

- **A placeholder that a new constraint makes unsatisfiable is not a stub, it is
  a broken test.** Both sites should derive the value the way
  `fixture::genuine()` does: hash the header the fixture already carries.
- **Uniform failure at one constraint index across varied inputs means one
  systematic bug, not bad data.** 100 fixtures spanning different blocks, tx
  indices and receipt types all failing identically is a strong signal, and it
  is visible in the first failure message.
- **Diagnostics dominate runtime when everything fails.**
  `which_is_unsatisfied()` walks the full constraint system per failing fixture,
  so a uniformly broken relation turns an 8-minute suite into hours. A long run
  should raise "is it failing?" before "is it just big?". Flat RSS during a loop
  that builds and drops constraint systems is the tell.

The general form: when a commit adds a constraint, every witness source feeding
that constraint is part of the change. Grepping the new field name for literal
placeholders is a cheap complete check.
