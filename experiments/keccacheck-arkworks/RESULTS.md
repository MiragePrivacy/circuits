# Historical Keccacheck measurements

These measurements describe the initial arkworks 0.6 port of Reilabs commit
`15f00e3da5622f1c7155b02d1f9c00bd2416c282`, with WHIR disabled. They predate
field-level parsing and the matrix-free prover. For the current relation and
measurement status, see [BENCHMARKS.md](../../BENCHMARKS.md).

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

## Earlier relation measurements

| Revision / stage | Circuit | Constraints | Proof time | Memory scope |
|---|---|---:|---:|---|
| `8b60d00`, initial integration | ERC-20 | 4,034,927 | 24.9 s, one sample | 12.6 GiB total peak RSS |
| September 16 batching port | Native direct | 17,635,451 | 44.871 s median, 3 samples | 27.272 GiB total peak RSS |
| September 16 batching port | Native Keccacheck | 11,620,286 | 45.439 s median, 3 samples | 24.831 GiB total peak RSS |
| September 22 structural optimization | Native Keccacheck | 7,327,757 | 42.525 s median, 3 samples | 23.298 GiB total peak RSS |

These ran on an i9-14900HX with 16 Rayon threads. The native runs included
self-verification. Total peak RSS includes counting/setup/proving and cannot
be compared directly with proving-only RSS or allocator heap measurements.
No row establishes p95 or SGX performance.

Raw native logs:

- [September 16 direct](benchmarks/native-direct.log)
- [September 16 Keccacheck](benchmarks/native-keccacheck.log)
- [September 22 before](benchmarks/native-structural-before.log)
- [September 22 after](benchmarks/native-structural-after.log)

The September 22 comparison used `3d78fb8` before and `fc3f905` after; its
before median was 47.379 s. It is a separate run from September 16.
Historical implementation and validation chronology remains in Git history.
