# ark-groth16 BN254 proving benchmark

Every timing, memory and size figure below is measured on the machine described
in [Environment](#environment). The only derived numbers are the ~3M constraint
interpolations, which sit between two measured points and are always marked
"interpolated".

**Headline: yes, ~3M constraints fits in 75 seconds at 16 threads, with room to
spare.** 2.1M constraints proves in **14.5s** and 4.2M in **28.6s**, both at 16
threads on the multiplication-chain circuit. Interpolating to 3.0M gives
**~21s**, roughly 3.5x inside the budget; with `+bmi2,+adx` assembly enabled,
**~17s**. Even the largest circuit measured (4.19M) finishes in 28.6s, or 24.5s
with asm.

Headline numbers at 16 threads:

| circuit | 2.1M constraints | 4.2M constraints | 3.0M (interpolated) |
|---|---|---|---|
| `mul` baseline | 14.51 s | 28.59 s | ~20.6 s |
| `mul` + asm | 12.01 s | 24.49 s | ~17.4 s |
| `bool` (see caveat) | 6.54 s | 12.95 s | ~9.3 s |

All 27 configurations completed successfully. **Nothing OOMed and nothing timed
out**, including 2^22 at every thread count; peak memory was 11.6 GB against
94 GiB available.

The caveats in [Interpretation](#interpretation) matter a lot: the
multiplication chain is the *best case* for the prover's serial phases, the
`bool` circuit is an unrealistically *good* case for its MSM phases, and the
real keccak-heavy workload will be worse than `mul` on both counts.

## Environment

| item | value |
|---|---|
| CPU | Intel Core i9-14900HX, 24 logical CPUs (8 P-cores + 16 E-cores, SMT off: `Thread(s) per core: 1`) |
| CPU max clock | 5.8 GHz, `scaling_governor = powersave` |
| Cache | L1d 896 KiB, L2 32 MiB, L3 36 MiB |
| RAM | 98,507,840 kB total (~94 GiB) |
| Kernel | 6.12.101, NixOS |
| rustc | 1.97.1 (8bab26f4f 2026-07-14) |
| cargo | 1.97.0 (c980f4866 2026-06-30) |
| profile | `opt-level=3`, `lto="fat"`, `codegen-units=1`, `panic="abort"` |

`nproc` is **24**, so the requested sweep to 16 threads fits without capping.

Important for reading the parallel-efficiency numbers: this is a hybrid CPU with
only **8 P-cores**; the other 16 are slower E-cores. The 16-thread
configurations therefore run on 8 P-cores plus 8 E-cores, not 16 equal cores.
Some of the efficiency falloff past 8 threads is core heterogeneity rather than
Amdahl's law, and a server with 16 homogeneous cores would score better.

Crate versions resolved (from `Cargo.lock`):

| crate | version |
|---|---|
| ark-groth16 | 0.5.0 |
| ark-bn254 | 0.5.0 |
| ark-ec | 0.5.0 |
| ark-ff | 0.5.0 |
| ark-poly | 0.5.0 |
| ark-r1cs-std | 0.5.0 |
| ark-relations | 0.5.1 |
| ark-serialize | 0.5.0 |
| ark-snark | 0.5.1 |
| ark-std | 0.5.0 |
| ark-crypto-primitives | 0.5.0 |

0.6.x does not exist on crates.io for these; 0.5.x is the current release line.
Features: `parallel` on ark-groth16/ark-ec/ark-ff/ark-r1cs-std/ark-std, plus
`ark-std/print-trace` for the per-phase timers.

### Measurement method

- **Peak RSS**: `VmHWM` read from `/proc/self/status` at the end of the process.
  `/usr/bin/time -v` is not present on this NixOS host. Each (constraints,
  threads) configuration runs as its own process, so `VmHWM` is per-config and
  covers setup + both proofs + verification. It is therefore an upper bound on
  proving-only memory: setup allocates more than proving does.
- **Timing**: `std::time::Instant` around `circuit_specific_setup`, `prove`, and
  `verify_with_processed_vk`. Proving runs **twice** per config; both runs are
  reported. Verification runs 3x, median reported.
- **Constraint count**: `cs.num_constraints()` after `cs.finalize()` on a
  separately synthesized `ConstraintSystem`, and `cs.is_satisfied()` is asserted.
  Realized counts are reported, not the target parameter.
- **Correctness**: every configuration verified its own proof (`verified: true`
  in `results.jsonl`). A benchmark that proves garbage is worthless, so this is
  checked rather than assumed.

## The circuits

Two shapes, both with a tunable size parameter.

**`mul`** - the priority circuit. `x = x*x + c` repeated `steps` times, seeded
from a random field element, with the final value bound to a public input so the
chain cannot be optimized away. Exactly **one R1CS constraint per step** (the
squaring; the `+ c` folds into a linear combination). Realized count is
`2^k - 1`, one short of the target, which is the output-binding accounting.

**`bool`** - the keccak-shaped approximation. A 64-bit state of `Boolean`
witnesses; each iteration does one AND (1 multiplication constraint), one XOR
(linear, free), and allocates a fresh `Boolean` witness (booleanity constraint)
bound by an equality. Measured at **4 constraints per iteration**, so the driver
divides the target by 4. This produces the many-small-constraints, wide-LC shape
that boolean circuits have, as opposed to the dense chain of `mul`.

## Results: `mul` (multiplication chain)

Two proving runs shown per row; "best" is the minimum. Speedup and parallel
efficiency are relative to the 1-thread row of the same size.

### 1,048,575 constraints (2^20)

| threads | prove run1 (s) | prove run2 (s) | best (s) | speedup vs 1t | par. efficiency | setup (s) | verify (ms) | peak RSS (GB) |
|---|---|---|---|---|---|---|---|---|
| 1 | 41.67 | 40.42 | 40.42 | 1.00x | 100% | 52.1 | 0.89 | 2.75 |
| 2 | 23.14 | 23.53 | 23.14 | 1.75x | 87% | 26.5 | 0.86 | 2.85 |
| 4 | 16.20 | 16.86 | 16.20 | 2.50x | 62% | 16.2 | 0.99 | 2.71 |
| 8 | 12.65 | 12.61 | 12.61 | 3.21x | 40% | 10.9 | 1.14 | 2.71 |
| 16 | 9.64 | 9.83 | 9.64 | 4.19x | 26% | 8.3 | 1.20 | 2.73 |

Proving key: 234,881,488 B compressed / 469,762,928 B uncompressed.
Witness vars 1,048,574, instance vars 3.

### 2,097,151 constraints (2^21)

| threads | prove run1 (s) | prove run2 (s) | best (s) | speedup vs 1t | par. efficiency | setup (s) | verify (ms) | peak RSS (GB) |
|---|---|---|---|---|---|---|---|---|
| 1 | 95.23 | 80.18 | 80.18 | 1.00x | 100% | 121.9 | 0.86 | 5.45 |
| 2 | 43.36 | 43.95 | 43.36 | 1.85x | 92% | 50.8 | 0.85 | 5.49 |
| 4 | 25.71 | 25.98 | 25.71 | 3.12x | 78% | 28.4 | 0.87 | 5.38 |
| 8 | 18.14 | 18.70 | 18.14 | 4.42x | 55% | 17.6 | 0.85 | 5.39 |
| 16 | 14.51 | 14.54 | 14.51 | 5.53x | 35% | 12.9 | 0.87 | 5.42 |

Proving key: 469,762,512 B compressed / 939,524,976 B uncompressed.
Witness vars 2,097,150, instance vars 3.

Note the 1-thread row: 95.23s then 80.18s, an 19% spread. That is the largest
run-to-run variance in the sweep and is almost certainly thermal/frequency
drift on a laptop part. Treat single-thread numbers as +/- 15%.

### 4,194,303 constraints (2^22)

| threads | prove run1 (s) | prove run2 (s) | best (s) | speedup vs 1t | par. efficiency | setup (s) | verify (ms) | peak RSS (GB) |
|---|---|---|---|---|---|---|---|---|
| 1 | 153.11 | 152.11 | 152.11 | 1.00x | 100% | 181.9 | 0.87 | 10.89 |
| 2 | 86.34 | 86.60 | 86.34 | 1.76x | 88% | 96.1 | 0.85 | 10.90 |
| 4 | 52.48 | 51.24 | 51.24 | 2.97x | 74% | 53.8 | 0.87 | 11.22 |
| 8 | 34.86 | 34.47 | 34.47 | 4.41x | 55% | 33.8 | 0.86 | 11.43 |
| 16 | 29.45 | 28.59 | 28.59 | 5.32x | 33% | 24.9 | 0.89 | 11.63 |

Proving key: 939,524,560 B compressed / 1,879,049,072 B uncompressed.
Witness vars 4,194,302, instance vars 3.

**2^22 did not OOM and did not time out.** It completed all five thread counts.
Peak RSS 11.6 GB against 94 GiB available.

### Does 3M fit in 75s?

Proving time scales almost exactly linearly in constraint count at 16 threads:
fitting a power law between the 2^21 and 2^22 points gives an exponent of
**0.978**, i.e. very slightly sublinear.

| target | 16-thread prove | source |
|---|---|---|
| 2,097,151 | 14.51 s | measured |
| **3,000,000** | **~20.6 s** | interpolated (both log-log and linear-in-n agree) |
| 4,194,303 | 28.59 s | measured |

~21s against a 75s budget. Even the measured 4.2M point (28.6s) is comfortably
inside. **At 8 threads** 4.2M takes 34.5s, so the budget survives losing half
the cores too.

## Per-phase breakdown

This is the part that explains the scaling. `print-trace` output, prover only.

### 4,194,303 constraints, 16 threads (total 28.85 s)

| phase | time (s) | % of prove | parallel? |
|---|---|---|---|
| Constraint synthesis | 2.218 | 7.7% | **no** |
| Inlining LCs | 4.420 | 15.3% | **no** |
| R1CS to QAP witness map | 4.621 | 16.0% | yes |
| Compute C | 6.581 | 22.8% | yes (MSM) |
| Compute A | 2.327 | 8.1% | yes (MSM) |
| Compute B in G1 | 2.342 | 8.1% | yes (MSM) |
| Compute B in G2 | 6.325 | 21.9% | yes (MSM) |
| **total** | **28.845** | 100% | |

### 4,194,303 constraints, 1 thread (total 152.50 s)

| phase | time (s) | % of prove |
|---|---|---|
| Constraint synthesis | 1.991 | 1.3% |
| Inlining LCs | 4.125 | 2.7% |
| R1CS to QAP witness map | 22.412 | 14.7% |
| Compute C | 46.209 | 30.3% |
| Compute A | 15.239 | 10.0% |
| Compute B in G1 | 15.041 | 9.9% |
| Compute B in G2 | 47.471 | 31.1% |
| **total** | **152.498** | 100% |

### The serial phases, isolated

Putting the two side by side answers the `!Send` question directly. Synthesis
and LC inlining are the phases that cannot be parallelized, because
`ConstraintSystemRef` is `Rc<RefCell<...>>`:

| phase | 1 thread | 16 threads | speedup |
|---|---|---|---|
| Constraint synthesis | 1.991 s | 2.218 s | **0.90x** (slower) |
| Inlining LCs | 4.125 s | 4.420 s | **0.93x** (slower) |
| everything else | 146.38 s | 22.21 s | 6.59x |
| total | 152.50 s | 28.85 s | 5.29x |

The serial phases are **not just un-accelerated, they are slightly slower** at
16 threads - consistent with allocator contention and cache pressure from the
rayon pool existing alongside them. Absolute cost is flat at ~6.6s regardless of
core count.

**At 4.2M constraints, synthesis + inlining = 6.64 s = 23.0% of the 16-thread
prove time.** At 1 thread the same work is 4.0%. This is textbook Amdahl: the
serial fraction is invisible when everything is slow and dominant when
everything else has been accelerated.

Amdahl ceiling from these measurements: with 6.64s irreducible and 146.4s
parallelizable, even with infinite cores the floor is ~6.6s, i.e. a maximum
speedup of ~23x. The observed 5.32x at 16 threads is well below that ceiling, so
**Amdahl is not yet the binding constraint at 16 threads** - the parallel phases
themselves are only achieving ~6.6x on 16 threads. Memory bandwidth and the
P-core/E-core split are the more likely explanation for that gap.

Extrapolating the serial fraction to ~3M constraints: synthesis + inlining
scales linearly in constraints (2^20: 1.89s, 2^21: 3.32s, 2^22: 6.64s), so at
3.0M expect ~4.8s serial out of ~20.6s total, i.e. **~23% serial** - the same
fraction. More cores past 16 will buy progressively less, but the phase is not
the wall at this size.

## Parallel efficiency

| constraints | 1t | 2t | 4t | 8t | 16t |
|---|---|---|---|---|---|
| 1,048,575 | 100% | 87% | 62% | 40% | 26% |
| 2,097,151 | 100% | 92% | 78% | 55% | 35% |
| 4,194,303 | 100% | 88% | 74% | 55% | 33% |

**~33-35% per-core efficiency at 16 threads**, i.e. a 5.3x speedup on 16 cores.
That is *worse* than the ~47% Celer reported for arkworks. Two honest caveats
before concluding arkworks is worse than advertised:

1. Only 8 of these 16 threads are P-cores. E-cores are substantially slower per
   core, so a chunk of the deficit is hardware heterogeneity, not library
   quality. On 16 homogeneous cores the number would be higher.
2. `powersave` governor with a laptop thermal envelope; sustained all-core work
   downclocks.

Efficiency at 8 threads is **55%**, which is closer to the Celer figure and is
the more meaningful comparison point on this machine: 8 threads plausibly maps
onto the 8 P-cores (thread placement was not pinned or verified, so this is an
assumption about the scheduler, not a measurement). The qualitative claim -
arkworks parallelizes noticeably worse than gnark's ~81% - is consistent with
what is measured here, but this hardware cannot cleanly confirm the specific
47% number.

## Setup cost and proving key size

Setup is a per-deployment ceremony cost, not per-proof, but it is not small.

| constraints | setup @16t (s) | setup @1t (s) | pk compressed | pk uncompressed |
|---|---|---|---|---|
| 1,048,575 | 8.3 | 52.1 | 234,881,488 B (224 MiB) | 469,762,928 B (448 MiB) |
| 2,097,151 | 12.9 | 121.9 | 469,762,512 B (448 MiB) | 939,524,976 B (896 MiB) |
| 4,194,303 | 24.9 | 181.9 | 939,524,560 B (896 MiB) | 1,879,049,072 B (1.75 GiB) |

Proving key size is **~224 bytes per constraint compressed**, dead linear. At
3M constraints expect a **~640 MiB compressed / ~1.25 GiB uncompressed** proving
key. That is a real operational cost: it has to be distributed to and loaded by
every prover. Note `circuit_specific_setup` is a toy trusted setup - a real
deployment needs a proper MPC ceremony, which is a different and much larger
cost than the numbers here.

Verification is **0.85-1.20 ms** everywhere, independent of circuit size, as
expected for Groth16.

## Results: `+bmi2,+adx` assembly field arithmetic

Built with `--features asm` and `RUSTFLAGS="-C target-feature=+bmi2,+adx"`. The
CPU supports both flags (`bmi2 adx` present in `/proc/cpuinfo`), and the two
binaries differ, so the comparison is real. Swept at 1 and 16 threads only, to
keep total runtime manageable.

| constraints | threads | base prove (s) | asm prove (s) | asm gain | base setup (s) | asm setup (s) |
|---|---|---|---|---|---|---|
| 1,048,575 | 1 | 40.42 | 36.76 | **+9.1%** | 52.1 | 46.9 |
| 1,048,575 | 16 | 9.64 | 7.12 | **+26.2%** | 8.3 | 5.9 |
| 2,097,151 | 1 | 80.18 | 68.46 | **+14.6%** | 121.9 | 91.1 |
| 2,097,151 | 16 | 14.51 | 12.01 | **+17.2%** | 12.9 | 11.1 |
| 4,194,303 | 1 | 152.11 | 130.87 | **+14.0%** | 181.9 | 161.9 |
| 4,194,303 | 16 | 28.59 | 24.49 | **+14.3%** | 24.9 | 21.7 |

**Yes, `asm` helps: consistently 9-26% faster proving, ~14% at the largest
size.** It is free to enable and should be on in production. The gain is real
but well short of the "30-70%" figure sometimes quoted - that range describes
isolated field-operation microbenchmarks, whereas end-to-end proving spends much
of its time in MSM point arithmetic and memory traffic that assembly field
multiplication does not accelerate. The 26.2% outlier at 2^20/16t is the
smallest and noisiest configuration; the three largest-size measurements cluster
tightly at 14%.

With asm enabled, **4.19M constraints proves in 24.5s at 16 threads.**

## Results: `bool` (keccak-shaped, boolean/XOR heavy)

Swept at 1 and 16 threads.

| constraints | threads | prove best (s) | speedup | setup (s) | verify (ms) | peak RSS (GB) | pk compressed |
|---|---|---|---|---|---|---|---|
| 1,048,656 | 1 | 13.43 | 1.00x | 28.2 | 0.73 | 2.29 | 192,949,968 B |
| 1,048,656 | 16 | 3.35 | 4.01x (25%) | 3.8 | 0.74 | 2.46 | |
| 2,097,232 | 1 | 26.51 | 1.00x | 52.1 | 0.72 | 4.52 | 385,887,952 B |
| 2,097,232 | 16 | 6.54 | 4.06x (25%) | 7.5 | 0.74 | 4.74 | |
| 4,194,384 | 1 | 52.15 | 1.00x | 106.9 | 0.75 | 9.04 | 771,763,920 B |
| 4,194,384 | 16 | 12.95 | 4.03x (25%) | 14.9 | 0.76 | 9.80 | |

### This circuit is faster than `mul`, and that is misleading

At 4.2M constraints / 16 threads, `bool` proves in **12.95s** against `mul`'s
**28.59s** - less than half. **Do not read this as "keccak circuits are cheap."**
The phase breakdown shows exactly where the difference comes from:

| phase | `mul` 4.2M @16t | `bool` 4.2M @16t |
|---|---|---|
| Constraint synthesis | 2.218 s | 1.428 s |
| Inlining LCs | 4.420 s | 2.207 s |
| R1CS to QAP witness map | 4.621 s | 4.349 s |
| Compute C | 6.581 s | 4.222 s |
| Compute A | 2.327 s | **0.188 s** |
| Compute B in G1 | 2.342 s | **0.120 s** |
| Compute B in G2 | 6.325 s | **0.287 s** |
| total | 28.845 s | 12.809 s |

The A / B-G1 / B-G2 multi-scalar multiplications collapse from 11.0s to 0.6s, a
~19x drop. The cause is that **every witness in this circuit is 0 or 1**.
Arkworks' MSM (Pippenger) buckets by scalar value, and scalars that are zero or
one are nearly free - no bucket accumulation work. A real keccak circuit has the
same boolean *constraint* shape but its A/B/C matrices contain arbitrary field
coefficients from the XOR/rotation linear combinations, so its MSMs will behave
much more like `mul`'s than like this circuit's.

`bool` also has 25% fewer witness variables per constraint (0.75 vs 1.00), which
accounts for a smaller part of the gap and is itself a realistic feature of
boolean circuits.

**What `bool` does usefully show**: the serial fraction is *worse* for
boolean-shaped circuits. Synthesis + inlining is **28.3%** of prove time at
4.2M/16t (3.64s of 12.81s), versus 23.0% for `mul`, and parallel efficiency is
**25%** versus 33%. Gadget-heavy synthesis is more expensive per constraint, and
that cost is entirely serial. This is the direction the real workload will move
in, even though the absolute total here is optimistically low.

## Interpretation

**Does ~3M constraints fit in 75 seconds at 16 threads? Yes - measured 14.5s at
2.1M and 28.6s at 4.2M, interpolating to ~21s at 3.0M.** That is a 3.5x margin.
The margin survives at 8 threads (4.2M in 34.5s) and even 4 threads (4.2M in
51.2s) stays inside 75s.

**What dominates?** At 16 threads, roughly: MSMs 61% (Compute A/B/C), QAP
witness map 16%, serial synthesis + LC inlining 23%. The MSM work parallelizes
but only achieved ~6.6x on 16 threads.

**Peak memory at 3M: ~8.1 GB** (interpolated between the measured 5.42 GB at
2.1M and 11.63 GB at 4.2M, both of which include the more memory-hungry setup
phase in the same process). The earlier 6-8 GB estimate was in the right range,
slightly low at the top end. Memory scales linearly at **~2.8 GB per million
constraints**. This is not a constraint on a 94 GiB box but it does rule out
small containers - a 4 GB prover container will not hold a 3M circuit.

**Does `+bmi2,+adx` help?** Yes, ~14% at the largest sizes (9-26% across the
sweep). Enabling it brings 4.19M constraints to 24.5s and the interpolated 3M
figure to **~18s**. It costs nothing to turn on.

### Caveats, stated plainly

- **The multiplication chain is the best case for synthesis, and the real
  workload is worse.** `x = x*x + c` produces the densest, simplest possible
  R1CS: every constraint has 2-3 terms, linear combinations are trivial to
  inline, and the witness is a simple sequential computation. This flatters two
  phases specifically: *constraint synthesis* (no gadget overhead, no `Boolean`
  allocation churn) and *inlining LCs* (nothing to inline). A keccak-heavy
  circuit allocates hundreds of thousands of `Boolean`s through `ark-r1cs-std`
  gadgets, each carrying `LinearCombination` construction, `Rc` traffic, and
  wide LCs that inlining must actually flatten. **Expect the serial phases to be
  meaningfully more expensive per constraint** on the real circuit - the `bool`
  measurements already show the serial fraction rising from 23% to 28% and
  parallel efficiency dropping from 33% to 25%.
- **Neither synthetic circuit is a substitute for benchmarking the real one.**
  `mul` understates synthesis cost; `bool` badly understates MSM cost because
  its all-0/1 witness makes multi-scalar multiplication nearly free (see the
  `bool` section). The honest read is that real keccak sits **above `mul`** on
  total time: it inherits `mul`-like MSM cost from its arbitrary field
  coefficients *and* `bool`-like elevated synthesis cost from gadget overhead.
  A 3M-constraint keccak circuit taking somewhat more than the ~21s measured
  here would not be surprising; taking 3.5x more, enough to breach 75s, would
  be. That gap is the reason to benchmark the actual circuit before committing.
- The 75s verdict rests on an *interpolation* to 3M, not a measurement at
  exactly 3M. The two bracketing points are measured and the scaling is
  near-linear (exponent 0.978), so the interpolation is well-constrained, but it
  is still an interpolation.
- Laptop CPU with heterogeneous cores, `powersave` governor, thermal limits. A
  server with 16 homogeneous cores would likely do better on the parallel
  phases and would change the efficiency numbers.
- Single-thread timings carry ~15% run-to-run variance (see 2^21).
- `circuit_specific_setup` is not a real trusted setup ceremony.
- Peak RSS is per-process and includes setup, so proving-only peak memory is
  somewhat lower than reported.

## Reproducing

```sh
nix shell nixpkgs#cargo nixpkgs#rustc nixpkgs#gcc
cargo build --release

# baseline mul sweep (full thread ladder)
SHAPES="mul" SIZES="20 21 22" THREADS="1 2 4 8 16" LABEL=base ./run_sweep.sh

# keccak-shaped boolean circuit
SHAPES="bool" SIZES="20 21 22" THREADS="1 16" LABEL=base ./run_sweep.sh

# asm variant
RUSTFLAGS="-C target-feature=+bmi2,+adx" \
  cargo build --release --features asm --target-dir target-asm
BIN=./target-asm/release/bench-arkworks \
  SHAPES="mul" SIZES="20 21 22" THREADS="1 16" LABEL=asm ./run_sweep.sh

python3 summarize.py results.jsonl                  # sweep tables
python3 phases.py traces/base_mul_22_16.trace.out   # per-phase breakdown
```

Single run: `RAYON_NUM_THREADS=16 ./target/release/bench-arkworks mul 22 mylabel`
(arguments: shape, log2 of target constraints, label).

Raw data is in `results.jsonl` (one JSON object per configuration); full
`print-trace` output per configuration is in `traces/`.
