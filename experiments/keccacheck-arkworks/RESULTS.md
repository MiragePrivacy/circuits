# Arkworks Keccacheck exploration results

Reference: Reilabs Keccacheck commit
[`15f00e3da5622f1c7155b02d1f9c00bd2416c282`](https://github.com/reilabs/keccacheck/tree/15f00e3da5622f1c7155b02d1f9c00bd2416c282),
with WHIR disabled. Measurements are from this branch's arkworks 0.6 R1CS port.
They use native proof generation followed by constraint synthesis and
`is_satisfied`; no Groth16 setup was run during the optimization loop.

## Measured comparison

The direct control is Mirage's Boolean Keccak-f construction. It costs 155,200
constraints per independently allocated permutation: 1,600 input-bit
booleanity constraints and 153,600 permutation constraints.

| permutations | GKR proof Fr elements | proof bytes | arkworks GKR constraints | direct constraints | direct / GKR |
|---:|---:|---:|---:|---:|---:|
| 1 | 6,255 | 200,160 | 989,228 | 155,200 | 0.157x |
| 2 | 6,809 | 217,888 | 1,093,992 | 310,400 | 0.284x |
| 4 | 7,363 | 235,616 | 1,201,330 | 620,800 | 0.517x |
| 8 | 7,917 | 253,344 | 1,321,223 | 1,241,600 | 0.940x |
| 16 | 8,471 | 271,072 | 1,466,226 | 2,483,200 | 1.694x |
| 32 | 9,025 | 288,800 | 1,661,449 | 4,966,400 | 2.989x |
| 64 | 9,579 | 306,528 | 1,957,112 | 9,932,800 | 5.075x |

The crossover in this port is between 8 and 16 permutations. Keccacheck is a
regression for small isolated hashes and becomes compelling only when many
permutations share one GKR proof.

At 64 independently witnessed permutations, the 1,957,112 constraints break
down as follows:

| component | constraints |
|---|---:|
| input and output Boolean allocation | 204,800 |
| output Fiat-Shamir binding | 88,800 |
| output word/bit reduction | 10,083 |
| 24 Keccak round reductions | 1,546,910 |
| final input binding | 106,519 |

The upstream README reports 638,682 gnark constraints for one permutation and
791,597 for eight. This arkworks port is respectively 55% and 67% larger. The
port intentionally uses ordinary `FpVar`
operations with no custom compiler optimization pass, so closing that gap is a
separate optimization opportunity; the present numbers are the safe comparison
for Mirage's backend.

## Measured universal-circuit integration

The universal depth-seven relation is 8,095,727 constraints. Its bounded
Keccak calls compile 38 Keccak-f permutations:

- commitment: 2;
- statement: 3;
- header: 6;
- six MPT ancestors: 23;
- constructed leaf: 4.

The integrated backend allocates each real output state as Boolean witnesses,
preserves the existing sponge chaining and variable-length state selection,
and pads the batch with 26 constant zero-input permutations. The complete
genuine relation synthesized and satisfied with this measured breakdown:

```text
non-GKR relation constraints: 2,330,003
64-way GKR verifier:          1,704,924
complete relation:            4,034,927
```

This is 4,060,800 fewer constraints than the 8,095,727 direct-Keccak relation,
a measured 50.2% reduction. The integrated verifier is smaller than the fully
witnessed standalone 64-way case because the 26 padding states are constants.

## Correctness checks

- Poseidon2 permutation values are differential-tested against the pinned
  native implementation.
- Direct arkworks Keccak is differential-tested against native `keccak::f1600`
  and locks the 155,200-constraint control cost.
- A native Keccacheck proof satisfies the full 24-round arkworks verifier.
- Mutating either a proof element or an output word makes the R1CS
  unsatisfied.
- The complete genuine Mirage relation satisfies with 38 recorded and 64
  padded permutations.
- The batched relation rejects an incorrect authenticated header hash.
- The deepest fixture in the 100-case mainnet dataset satisfies the batched
  circuit as a fast real-data integration gate.
- All tests use the reference's corrected late-round Keccak constants.

## Feasibility and remaining work

The integration now has an alternate `KeccacheckReceiptCircuit` and Rust
`setup_keccacheck`/`prove_keccacheck` APIs. Remaining finalist work is:

1. Run the complete existing mutation and mainnet-fixture suites through the
   batched circuit, rather than only the genuine fixture and header mutation.
2. Audit the Poseidon-derived output challenge and transcript domain separation.
3. Vendor or migrate the upstream Rust GKR prover to arkworks 0.6, removing the
   temporary dual-version scalar conversion.
4. Investigate the arkworks overhead relative to gnark, principally
   in the round verifier and transcript expression lowering.
5. Only after those checks, run one full Groth16 setup/prove/
   verify benchmark and evaluate the larger witness-generation path.

The GKR proof occupies about 307 KiB at 64 permutations, but it is private
Groth16 witness data, not calldata and not an additional on-chain proof.
