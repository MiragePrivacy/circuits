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
non-GKR relation constraints: 2,331,459
64-way GKR verifier:          1,704,924
complete relation:            4,036,383
```

This is 4,060,800 fewer constraints than the 8,097,183 direct-Keccak relation,
a measured 50.2% reduction. The integrated verifier is smaller than the fully
witnessed standalone 64-way case because the 26 padding states are constants.

Both figures include the 1,456 constraints added by the one-hot in-range
assertions and buffer bounds in `b5192b4`. The timings below predate that
commit and were not re-measured; the delta is 0.04% of the relation.

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
- The batched relation rejects an incorrect authenticated header hash, and
  rejects every mutation the direct relation rejects: substituted recipient and
  amount, a commitment from another context, a native-asset opening, a block
  number outside the statement, both lease-window boundaries, and a tampered
  receipt byte.
- A one-permutation batch, whose zero-round sumcheck is a distinct code path,
  verifies a genuine permutation and rejects a flipped output bit.
- The deepest fixture in the 100-case mainnet dataset satisfies the batched
  circuit as a fast real-data integration gate.
- All tests use the reference's corrected late-round Keccak constants.

## Feasibility and remaining work

The integration now has an alternate `KeccacheckReceiptCircuit` and Rust
`setup_keccacheck`/`prove_keccacheck` APIs. Remaining finalist work is:

1. Run the remaining mainnet-fixture suite through the batched circuit. The
   mutation suite now runs there (`batched_keccacheck_rejects_every_direct_mutation`).
2. Obtain cryptographic sign-off on the Poseidon-derived output challenge and
   the absent transcript domain separation. Reviewed adversarially and no
   exploitable gap was found; see "Open security items" below for what a
   reviewer still needs to confirm.
3. Vendor or migrate the upstream Rust GKR prover to arkworks 0.6, removing the
   temporary dual-version scalar conversion.
4. Investigate the arkworks overhead relative to gnark, principally
   in the round verifier and transcript expression lowering.
5. Measure a latency distribution and peak proving-only memory on the target
   enclave after the native GKR dependency is made enclave-compatible.

The GKR proof occupies about 307 KiB at 64 permutations, but it is private
Groth16 witness data, not calldata and not an additional on-chain proof.

## End-to-end Groth16 measurement

Commit `8b60d00` was measured in release mode on an Intel Core i9-14900HX with
16 Rayon threads. This is one complete local sample, not a latency
distribution or an enclave measurement.

| Stage | Measurement |
|---|---:|
| Constraints | 4,034,927 (now 4,036,383) |
| Satisfying diagnostic synthesis | 35.7 s |
| Circuit-specific Groth16 setup | 28.8 s |
| Groth16 proving | 24.9 s |
| Groth16 verification | 1.52 ms |
| Peak process RSS across synthesis, setup, and proving | 12.6 GiB |
| Proving key | 1.44 GiB uncompressed / 0.72 GiB compressed |
| Compressed proof | 128 bytes |

The 24.9-second proving measurement includes native GKR witness generation,
outer-circuit synthesis, witness mapping, and the Groth16 multiexponentiations.
The generated proof verified against its two public statement-hash limbs and
was rejected after mutating one limb. The 28.8-second deterministic setup is a
measurement stand-in, not a production ceremony.

## Open security items

An adversarial review of the integrated relation ran five independent attack
surfaces: the GKR verifier, MPT inclusion and the constructed leaf, the receipt
and ERC-20 log relation, the header parse and variable-length sponge, and the
commitment, statement hash and protocol replay surface. One in-circuit forgery
was found and fixed in `b5192b4`. The items below remain open and are not
fixable in this crate.

### Needs cryptographic sign-off

The output challenge `r` is derived in-circuit with Poseidon2 over the claimed
output words, replacing gnark's Groth16 commitment API. Transcript ordering was
checked and is correct: outputs are absorbed before `r` is squeezed, `r` is
absorbed before `beta`, and every proof value is absorbed before the challenge
that tests it. The residual difference from upstream is that a
commitment-derived challenge also binds the witness commitment, whereas this
binds only the output words.

`derive_r_var` and the main transcript are separate sponge instances started
from the same `INITIAL_STATE`, with no domain separation tag. Their absorb
sequences differ, so no collision is reachable, and upstream has no tag either.
Adding one would fork the transcript from the pinned native prover at
`15f00e3`, so it is a protocol change rather than a local fix.

The singleton batch is a distinct code path: with one permutation
`log_instances` is zero, the first sumcheck runs zero rounds, and the output
claim reduces to a transcript-derived linear combination of the output words.
`batch::tests` now covers it in both directions.

### Carried by out-of-circuit policy

Nothing in the statement or the commitment binds the transaction hash,
`transactionIndex`, or log position. The MPT key is a free witness. The
relation therefore proves that a matching Transfer exists somewhere in the
block, not that a particular transaction produced it.

Consequently one on-chain Transfer satisfies every live row whose intent has
the same token, recipient and amount. Two requests for the same payment can be
settled by a single transfer. The log's sender is also unconstrained, so an
executor can claim a coincidental third-party transfer that lands inside its
lease.

This is closed by policy rather than by the circuit. **The nomad must never
hold two live requests whose intents share `(token, recipient, amount)`**,
enforced by rejecting or jittering a duplicate at request creation. That keeps
the constraint count and the privacy properties unchanged, at the cost of
making settlement soundness depend on an off-chain invariant: a nomad bug that
admits duplicate live intents silently reintroduces the double-settle, and
nothing on-chain will catch it. The invariant therefore belongs in the nomad's
own test suite, not only in its request path.

The alternatives, if that invariant ever becomes untenable: bind
`transactionIndex` into the statement preimage (a relation version bump, and
the escrow must then store the settled index per row), or expose a receipt
nullifier as a third public signal (strongest, enforced on-chain, but adds a
public input and a linkable per-settlement tag). If `transactionIndex` is ever
bound, note that the one-hot in-range assertions in `b5192b4` are what make
that binding meaningful: without them a prover could suppress a key nibble read
and prove a genuine receipt at a fabricated index.

## Native ETH integration

The native dual-trie relation now batches all 51 permutations into one private
64-way Keccacheck proof. At unchanged bounds it falls from 17,635,451 to
11,620,286 constraints. A sequential three-proof host comparison measured
44.871 s direct versus 45.439 s Keccacheck median proving, with peak process
RSS falling from 27.272 to 24.831 GiB and the uncompressed key from 7.168 to
4.378 GiB. This port reduces constraints and memory, but the sample shows no
proving-time improvement because GKR expression inlining offsets the savings.
See [native implementation, validation, and full benchmark](../../NATIVE_ETH_STACK.md).
