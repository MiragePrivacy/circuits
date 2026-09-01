# Arkworks Keccacheck exploration results

Reference: Reilabs Keccacheck commit
[`15f00e3da5622f1c7155b02d1f9c00bd2416c282`](https://github.com/reilabs/keccacheck/tree/15f00e3da5622f1c7155b02d1f9c00bd2416c282),
with WHIR disabled. Measurements are from this branch's arkworks 0.5 R1CS port.
They use native proof generation followed by constraint synthesis and
`is_satisfied`; no Groth16 setup was run during the optimization loop.

## Measured comparison

The direct control is Mirage's Boolean Keccak-f construction. It costs 155,200
constraints per independently allocated permutation: 1,600 input-bit
booleanity constraints and 153,600 permutation constraints.

| permutations | GKR proof Fr elements | proof bytes | arkworks GKR constraints | direct constraints | direct / GKR |
|---:|---:|---:|---:|---:|---:|
| 1 | 6,255 | 200,160 | 987,628 | 155,200 | 0.157x |
| 2 | 6,809 | 217,888 | 1,090,792 | 310,400 | 0.285x |
| 4 | 7,363 | 235,616 | 1,194,930 | 620,800 | 0.520x |
| 8 | 7,917 | 253,344 | 1,308,423 | 1,241,600 | 0.949x |
| 16 | 8,471 | 271,072 | 1,440,626 | 2,483,200 | 1.724x |
| 32 | 9,025 | 288,800 | 1,610,249 | 4,966,400 | 3.084x |
| 64 | 9,579 | 306,528 | 1,854,712 | 9,932,800 | 5.355x |
| 128 | 10,133 | 324,256 | 2,248,855 | 19,865,600 | 8.834x |

The crossover in this port is between 8 and 16 permutations. Keccacheck is a
regression for small isolated hashes and becomes compelling only when many
permutations share one GKR proof.

At 64 permutations, the 1,854,712 constraints break down as follows:

| component | constraints |
|---|---:|
| input Boolean allocation | 102,400 |
| output Fiat-Shamir binding | 88,800 |
| output word/bit reduction | 10,083 |
| 24 Keccak round reductions | 1,546,910 |
| final input binding | 106,519 |

The upstream README reports 638,682 gnark constraints for one permutation,
791,597 for eight, and 1,379,176 for 128. This arkworks port is respectively
55%, 65%, and 63% larger. The port intentionally uses ordinary `FpVar`
operations with no custom compiler optimization pass, so closing that gap is a
separate optimization opportunity; the present numbers are the safe comparison
for Mirage's backend.

## Projection for the universal circuit

The universal depth-seven relation is 8,095,727 constraints. Its bounded
Keccak calls compile 38 Keccak-f permutations:

- commitment: 2;
- statement: 3;
- header: 6;
- six MPT ancestors: 23;
- constructed leaf: 4.

Those permutation cores cost `38 * 153,600 = 5,836,800` constraints. A fixed
64-way Keccacheck batch costs 1,854,712 in this standalone model. Replacing only
the permutation cores therefore gives the preliminary projection:

```text
8,095,727 - 5,836,800 + 1,854,712 = 4,113,639 constraints
```

That is 3,982,088 fewer constraints, or 49.2% of the whole universal relation.
The standalone input-bit allocation is a reasonable placeholder for the output
bits that integration must expose: caller input bits can be reused, while GKR
outputs need Boolean variables for sponge chaining and digest extraction. The
exact integrated count may move by roughly this 102,400-constraint boundary and
must be measured on an integration branch.

## Correctness checks

- Poseidon2 permutation values are differential-tested against the pinned
  native implementation.
- Direct arkworks Keccak is differential-tested against native `keccak::f1600`
  and locks the 155,200-constraint control cost.
- A native Keccacheck proof satisfies the full 24-round arkworks verifier.
- Mutating either a proof element or an output word makes the R1CS
  unsatisfied.
- All tests use the reference's corrected late-round Keccak constants.

## Feasibility and remaining work

This is promising for the universal circuit, but it is not yet drop-in code.

1. Refactor the verifier to accept and return caller-owned Boolean state bits,
   rather than allocating standalone `u64` witnesses.
2. Flatten every sponge invocation into one 64-way batch, including inactive
   padding permutations, while preserving each sponge's chaining and
   variable-length state selection.
3. Differential-test the integrated circuit against every existing relation
   fixture and mutation test.
4. Audit the Poseidon-derived output challenge and transcript domain separation.
5. Investigate the roughly 60% arkworks overhead relative to gnark, principally
   in the round verifier and transcript expression lowering.
6. Only after the integrated count is stable, run one full Groth16 setup/prove/
   verify benchmark and evaluate the larger witness-generation path.

The GKR proof occupies about 307 KiB at 64 permutations, but it is private
Groth16 witness data, not calldata and not an additional on-chain proof.
