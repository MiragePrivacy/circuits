# Mirage settlement circuits

These Rust circuits let a Mirage escrow verify delivery without seeing the payment receipt or exact transaction block. A client commits to the expected payment. The prover opens that commitment privately and proves delivery against Ethereum block data. The verifier checks two public field elements that encode the statement hash.

- **ERC-20:** the circuit proves receipt inclusion and checks that a successful receipt contains the expected token’s `Transfer` log.
- **Native ETH:** the circuit proves inclusion of the transaction and its successful receipt at the same transaction index, then checks the recipient and value in the transaction.
- **Both paths:** the circuit proves ancestry from the later public witness block to the private settlement block and enforces the reservation window. Batch escrows verify one proof for each row they pay out.

The backend is Groth16 over BN254 using arkworks. Native and ERC-20 use separate proving and verifying keys. For integration, match the circuit revision, ceremony keys, and [escrow verifier artifacts](https://github.com/MiragePrivacy/escrow). See [Beta SGX ceremony](#beta-sgx-ceremony) for key provenance and [Native ETH stack](NATIVE_ETH_STACK.md) for optimization measurements.

## Development history

The figures below capture several stages of development. The direct-Keccak counts and seeded-setup measurements describe earlier builds. The checkout and its pinned keys determine the constraints and artifact compatibility for any particular release.

## Build order

Section 25 of the spec is deliberate about sequencing. Each step is
independently reviewable, which matters because a missing constraint is silent:
the proof still verifies, the contract still pays, and nothing looks broken.

| Step | What | State |
|---|---|---|
| 1 | Byte-exact encoders and deterministic vectors | **done** — `crates/encoding` |
| 2a | Keccak and byte primitives | **done** — `crates/gadgets` |
| 2b | RLP, MPT, receipt relation | **done** — `crates/relation` |
| 3 | Transaction parser + native dual-trie relation | **done** — `crates/gadgets/src/transaction`, `crates/relation/src/native.rs` |
| 4 | Canonical escrow with embedded verifier | verifier exported and measured; escrow lives in the escrow repo |
| 5 | Positive delayed-witness ancestry | **done** -- `crates/gadgets/src/ancestry.rs`, distance 8..=39; exported verifiers regenerated |

Step 2's relation closes the whole binding chain:

```
commitment            -> settlement token / recipient / amount
H[d] -> receiptsRoot   -> MPT inclusion -> receipt -> Transfer log
H[d] -> parent hashes  -> H[0] -> statement's witnessBlockHash
H[d].number            -> bondStartBlock < n <= bondDeadline
statement context      -> keccak -> the two public signals
```

The setup is `circuit_specific_setup` with a seeded RNG, which spec 18.2 marks
as a placeholder for a multiparty Phase 2. The verifier is structurally
identical either way, so the size and gas figures hold; only the key's
provenance differs.

Step 5 hides the transaction block: the statement names a later witness block
`H[0]`, and the circuit walks parent hashes back to the private transaction
header `H[d]` for `8 <= d <= 39`. Every one of the 40 header slots is hashed
whatever `d` is, at five Keccak-f permutations each, which keeps both relations
inside a 256-permutation Keccacheck batch. Headers are witnessed as their
absorbed sponge states and must be 544 to 679 bytes, so a chain header costs
~14k constraints and only `parentHash` is read from it; the transaction header
alone is parsed. ERC-20: 3,074,926 constraints; native: 3,235,943.

## Native ETH

A native settlement moves ETH in the transaction itself and emits no log, so
there is no `Transfer` event to read. The recipient and amount are the
transaction's own `to` and `value`, which means a second trie:

```
commitment                 -> recipient / amount, asset kind native
header -> transactionsRoot -> MPT inclusion -> transaction -> to / value
header -> receiptsRoot     -> MPT inclusion -> receipt     -> status == 1
```

Both tries are keyed by the same `rlp(transactionIndex)`, so one key serves both
walks. The receipt half is not redundant: **a reverted transaction is still in
the transactions trie** and still names a `to` and a `value`, so a
transaction-only proof proves an attempt to pay rather than a payment.

`crates/gadgets/src/transaction` parses the three envelope shapes spec 12.6.1
admits. Note the asymmetry with receipts, which is easy to get wrong by copying:

| Type | Items | `to` | `value` | `data` |
|---|---|---|---|---|
| legacy (no prefix) | 9 | 3 | 4 | 5 |
| EIP-2930 (`0x01`) | 11 | 4 | 5 | 6 |
| EIP-1559 (`0x02`) | 12 | 5 | 6 | 7 |

Blob (`0x03`) and set-code (`0x04`) transactions are rejected, while the
*receipt* envelope set accepts both. The item counts differ per shape and
`decode_list` enforces an exact count, so all three are decoded speculatively
under their own `active` flags and the fields selected — the same pattern the
MPT traversal uses for branch versus short nodes, and for the same reason: a
false constraint does not select away.

### Two soundness bugs the tests caught

Both were written, both passed a naive reading, and both were found only by
negative tests. Worth knowing because the shapes recur:

- **A zero-value transaction satisfied any commitment.** Comparing the *read*
  byte against zero outside the value payload is vacuous, because an
  out-of-range read already yields zero. The assertion has to be about the
  commitment byte, not the read.
- **A non-canonical value let a prover choose the amount.** RLP's canonical-form
  rules govern length bytes and the one-byte-string case; an integer field's
  payload is arbitrary bytes as far as the decoder is concerned. Minimality is
  the relation's own obligation, and without it `0x82 0x00 0x01` and `0x01` both
  encode 1 while the right-alignment reads them a byte apart.

### Proving time leaks the asset kind

**This is a release gate, not a detail.** Spec 12.9 requires the native path
cost the same as the ERC-20 path, because a settlement whose proving time
identifies its asset kind splits the anonymity set: an observer timing a
`collect` learns whether it was ETH or a token before any other analysis.

This build is a separate circuit with its own verification key:

| Relation | Constraints |
|---|---|
| ERC-20 (`ReceiptCircuit`) | 10,426,684 |
| native (`NativeCircuit`) | 17,842,866 |

A 71% difference is not subtle. The second trie array is the whole of it — the
transaction relation itself is only 1,171,628 constraints at a 512-byte bound,
which is cheap because the buffer is small.

It also moves the memory ceiling. At the benchmark's ~2.8 GB per million, 17.8M
is roughly **50 GB** against the ERC-20 path's ~29 GB, with a proportionally
larger proving key. Groth16 needs the full witness and key resident with no
streaming path, so an enclave provisioned for the ERC-20 relation will not hold
this one. Proving time has not been measured; the ~22.6s ERC-20 figure scaled
linearly would be ~39s, still inside spec 19.7's 75s p95, but that is a
projection and the setup cost is not yet paid.

Building it standalone was deliberate: it gets the transaction parser reviewed
in isolation, and it produces the measurement any unification has to be designed
against. Closing the gap means either padding the ERC-20 relation up to the
native one's count, or merging both into one circuit whose asset kind selects
which assertions bind. The latter costs every ERC-20 proof the transaction-trie
walk it does not need, which is what the measurement above is for.

### Bare sends only, and why the circuit enforces it

A node settles by sending ETH directly, so `data` must be empty. The relation
enforces that rather than trusting the enclave to produce it, and the reason is
measured rather than stylistic.

143 native value transfers collected across 49 mainnet blocks
(`test/vectors/mainnet-native.json`), with **both** tries rebuilt and checked
against the header at collection time. They fall into two populations that are
not comparable:

| | Transaction | Receipt | Max node |
|---|---|---|---|
| Bare send (100) | ≤ 122 | ≤ 393 | ≤ 532 |
| Value-carrying call (43) | ≤ 7,225 | ≤ 21,501 | ≤ 21,508 |

A call carrying value delivers ETH exactly as a bare send does, so an earlier
draft left `data` unconstrained on the reasoning that what the escrow owes is
delivery. That was wrong, and the distribution is why. Cost scales with every
buffer bound and the native relation pays two trie arrays, so the tail is not a
dearer proof but a different order of magnitude — measured by
`cost_scales_with_the_observed_distribution`:

| Bound | Constraints | Memory at 2.8 GB/M |
|---|---|---|
| 320 (p50) | 12,631,645 | ~35 GB |
| 448 (bare-send max) | 13,383,133 | ~37 GB |
| 1,088 (p75) | 30,817,207 | ~86 GB |
| 4,224 (p90) | 213,399,317 | **~598 GB** |

Synthesizing the largest fixture — a 21,501-byte receipt — was OOM-killed on a
94 GB machine. Not slow: impossible. An unconstrained `data` therefore means a
relation that *accepts* settlements no machine can prove, which is the worst
failure shape available: the escrow pays out on a proof the executor can never
produce. Constraining it moves the failure to where spec 12.9 already puts it,
and makes the compiled bounds structural rather than a policy the circuit trusts
someone else to keep.

**All 100 bare sends satisfy `NativeCircuit` at the compiled bounds** on real
chain data, and all sampled calls are rejected. The 43 calls are kept in the
dataset as rejection fixtures: they are the evidence the constraint binds
against transactions the chain actually produced, not only against a synthetic
case.

The trade is that a settlement attaching calldata becomes unprovable, and spec
12.9 puts that on the executor. That is the right side to fail on, because the
alternative fails after the executor has already paid.

### Where the constraints are, and what is recoverable

Measured, not projected. Per traversal level at a 544-byte node bound:

| Sub-step | Constraints | Share |
|---|---|---|
| `link-hash` (keccak of the node) | 795,524 | 62% |
| `decoders` (branch + short) | 225,519 | 18% |
| `tail-read` | 135,845 | 11% |
| `is_branch` | 72,649 | 6% |
| everything else | ~57,000 | 4% |

The native relation walks two tries, so the traversal is ~76% of the whole
circuit and node hashing is ~47% of it. Reproduce with
`MPT_PROFILE=1 cargo test -p mirage-gadgets --release traverse::tests::profile
-- --nocapture`.

**The bounds are misaligned with the keccak rate, and fixing that is free.**
`keccak256_var` runs `max / 136 + 1` permutations regardless of the real length,
so cost *steps* at every multiple of 136 rather than rising smoothly. A bound is
therefore cheapest at the **largest** value inside its block — headroom up to
the next boundary costs nothing. The compiled bounds are round decimal numbers,
so each sits just past a step:

| Bound | Now | Blocks | Aligned | Same blocks |
|---|---|---|---|---|
| `node_bytes` | 544 | 5 | **543** | 4 |
| `receipt_bytes` | 512 | 4 | **407** | 3 |
| `header_bytes` | 704 | 6 | **679** | 5 |
| `transaction_bytes` | 512 | 4 | **407** | 3 |

`node_bytes = 544` is exactly `4 x 136`, landing one byte into a fifth block and
paying a whole extra permutation per node per trie for no headroom at all.

Measured by `keccak_aligned_bounds`, with all 100 bare sends still inside every
aligned bound:

| | Constraints | |
|---|---|---|
| compiled today | 17,842,875 | |
| keccak-aligned | 15,839,284 | **-11.2%**, ~6 GB |
| and depth 4 → 3 | 13,595,528 | **-24%** total |

The alignment is free: no soundness change, no new gadget code, no headroom
lost. The depth reduction is **not** recommended on this evidence — depth 4
holds 65,536 trie entries against depth 3's 4,096, and this is exactly the bound
where being wrong makes a settlement unprovable at the executor's expense. It is
measured so the price of that headroom is known, not to argue for spending it.

Neither is applied here: changing a compiled bound is a new circuit version
under spec 18.4, so it belongs with the setup and verifier regeneration rather
than in a measurement commit.

Beyond the bounds, node hashing is the only term large enough to matter. Two
things that look like savings and are not:

- **Sharing work between the two tries.** They are keyed identically and always
  have the same depth, so the nibble path, flags, and consumption tracking are
  computed twice. That is only 56,551 per level — 4.4% — so deduplicating it
  saves ~226k, roughly 1.3%. Real but not worth the coupling.
- **Sharing digests.** Not available at all: the tries hold different values, so
  no node is common to both.

What would actually move the number is a cheaper variable-length keccak, since
the 795k per node is ~153k per block times five blocks plus selection overhead.
That is a gadget-level project against a primitive already checked against
ZoKrates' reference, not a bounds change.

### What is not done

- **No exported verifier.** `contracts/` holds the ERC-20 verifier only.
- **Bounds not re-frozen.** `NativeBounds::default()` still carries the reasoned
  values, and every bare send fits them: transaction 122 against 512, receipt
  393 against 512, node 532 against 544, depth 3 against 4. The node figure
  looks tight but is not sampled — 532 is the structural size of a full
  16-child branch node, which is why the fixtures pile up on exactly that value
  rather than scattering below it. Confirming that before freezing under spec
  18.4 is still worth doing.
- **`asset_kind` is pinned in the native relation but not the ERC-20 one.**
  `NativeCircuit` enforces `assetKind == 0`, without which an escrow holding a
  token row could be collected by sending the same amount of ETH to the same
  recipient. `ReceiptCircuit` still does not enforce `assetKind == 1`; it fails
  closed only by accident, because a native row's all-zero token would require a
  `Transfer` emitted by the zero address.

## The bounds decide the memory ceiling

With spec 12.9's bounds as written the relation is **~43.7M constraints**. The
MPT node hashing is ~94% of that: 16 nodes, each independently bounded at 2048
bytes, each needing its own variable-length keccak at ~159.6k constraints per
block.

Latency is the lesser problem. At the measured ~21s per 3M that is roughly five
minutes, which is over spec 19.7's 75s p95 but is a product decision rather
than a wall. (At the bounds actually shipped, proving measures 22.6s — inside
the budget. See "End-to-end proving".)

**Memory is the wall.** At the measured ~2.8 GB per million constraints, 43.7M
is about **120 GB**, with a ~9.8 GB proving key on top. That exceeds the 94 GB
machine the benchmark ran on, let alone an enclave allocation. Groth16 needs
the full witness and proving key resident with no streaming path, so constraint
count sets a hard memory floor rather than a time cost that can be traded
against.

At ~12.8M the same figures give ~36 GB and a ~2.9 GB key, which is plausible
for a provisioned enclave.

Cost scales linearly with `MAX_MPT_NODE_BYTES` times `MAX_MPT_DEPTH`:

| Node bound | Depth 16 | Depth 9 |
|---|---|---|
| 2048 | ~40.9M | ~23.0M |
| 1024 | ~20.4M | ~11.5M |
| 640 | ~12.8M | ~7.2M |

Note that depth 16 is not itself the problem: at a realistic 640-byte node
bound it is ~12.8M, entirely workable. The node-size term dominates, and real
mainnet branch nodes are ~530-570 bytes rather than 2048.

### The distribution has been measured

100 mainnet direct-transfer settlements (`test/vectors/mainnet.json`), maxima:

| Quantity | Observed max | Compiled bound |
|---|---|---|
| MPT node bytes | 532 | 544 |
| Trie depth | 3 | 4 |
| Receipt bytes | 428 | 512 |
| Header bytes | 655 | 704 |

The resulting relation is **10,426,684 constraints**, which at the benchmark's
~2.8 GB per million is roughly 29 GB — within a provisioned enclave. The
projection above was right about which term dominates and conservative about
its size.

Each bound keeps deliberate headroom over the observed maximum, for the reason
in the next section. `crates/relation/src/lib.rs` records the justification per
field.

### Tightening is not free

A proof whose witness exceeds a bound cannot be produced. The escrow stays safe
— no proof, no payout, the bond expires and the requester is refunded — but the
executor has already paid the recipient and cannot collect. **The loss falls on
the executor.**

So the target is the measured distribution **plus real headroom**, not the
tightest bound that fits the budget. The measurement must report tail
percentiles and maxima, not medians.

Two things worth knowing about which bounds can actually bite:

- **Transactions per block is not a bound.** The relation proves one receipt at
  one index and never enumerates the block. Block size only affects trie depth,
  logarithmically: a few hundred transactions is ~3 levels, 10,000 is ~4.
  `MAX_MPT_DEPTH = 16` would hold 16^16 entries.
- **`MAX_RECEIPT_BYTES` and `MAX_LOGS` are the real risk**, from tokens that
  emit many or large logs. Receipt size is not fully knowable before the
  transaction lands, so the enclave's pre-settlement token check is
  load-bearing rather than advisory.

There is also a spec 17.8 coupling: a narrow supported-token set is itself a
fingerprint, since it shrinks the candidate universe an analyst must search.

## Layout

```
circuits/
  crates/
    encoding/   native reference encoders + vector generation (step 1)
    gadgets/    in-circuit primitives: keccak, bytes, RLP, MPT, transaction
    relation/   the ERC-20 receipt relation and the native dual-trie relation
    prover/     setup, prove, verify, Solidity verifier export
    fixtures/   mainnet collection: receipt- and transaction-trie rebuild
  contracts/    the exported verifier, a real proof, and its calldata
  test/         VerifierTest.sol plus the deterministic vectors
  test/vectors/ deterministic fixtures shared with nomad and Solidity
  bench-arkworks/  the backend benchmark that settled the decision
```

## The encoding crate is the authority

`crates/encoding` runs natively, never in-circuit. It is the reference the
gadgets and the Solidity contract are both checked against. Spec sections 8.3
and 10.2 define both preimages as fixed-width and byte-exact.

If a vector disagrees with an implementation, **the implementation is wrong.**
Fix the encoder, never the vector. A one-byte disagreement surfaces only as
"proof rejected" with no indication of which side erred, which is why the
vectors carry the packed preimage alongside the digest.

## What had to be written from scratch

No maintained library implements Ethereum receipt-trie inclusion in any
framework that also satisfies the verifier constraints. All of the following
was absent from arkworks and is now implemented in `crates/gadgets`:

- **A correct keccak-256 gadget.** The only existing one
  (`natharyan/arkworks-keccak`) pads with a plain `1` bit instead of Ethereum's
  `0x01` delimiter, and its `assert_eq!` on `.value()` is a native panic during
  proving and a silent no-op during setup — not an enforced constraint. Port
  from ZoKrates' `hashes/keccak/256bit.zok`, which has the correct delimiter and
  a genuine multi-block absorb loop.
- **Dynamic indexing.** `UInt8` is 8 `Boolean`s and there is no random-access
  gadget. RLP needs one because offsets are witness-dependent; it must be built
  from `CondSelectGadget` trees.
- **RLP, MPT traversal, and receipt parsing.** Nothing existed to start from.

`ark-r1cs-std` also has live underconstraining bugs (#212, #213, #216) and there
is no Picus frontend for arkworks, so no static analysis will catch a missing
constraint. Every gadget carries its own soundness burden.

## Development

```sh
nix develop
cargo test
```

The dev shell sets `RUSTFLAGS="-C target-feature=+bmi2,+adx"` for `ark-ff`'s asm
path, measured at 9-26% end-to-end.

### Changing the circuit invalidates the checked-in artifacts

Any change to the constraint system produces a new proving and verification key,
so `contracts/` must be regenerated in the same commit:

```sh
cargo run -p mirage-prover --release --bin export-verifier
forge test --match-path test/VerifierTest.sol -vv
```

Skipping this is silent in the worst way. The Foundry suite reads
`contracts/proof.json`, so it keeps passing against the *old* relation while
proofs from the new circuit fail to verify. Under spec 18.4 a key change is a
new circuit version requiring a new setup and audit delta.

## Measured costs

Everything below is measured on this code, not inherited. Reproduce with
`cargo test -p mirage-gadgets --release -- --nocapture cost`.

| Primitive | Cost |
|---|---|
| `keccak_f1600` | 155,200 |
| `keccak256_fixed` | ~153k per 136-byte block |
| `keccak256_var` | ~159.6k per block (+4% for padding and state selection) |
| `select_byte` | ~10 per buffer byte, per read |

The ~153k confirms the figure that drove the backend evaluation (vocdoni
150,848; IACR ePrint 2023/681 measures 151,357).

### End-to-end proving

At 10,426,684 constraints, from `export-verifier` on an i9-14900HX (24 cores):

| Phase | Time |
|---|---|
| `circuit_specific_setup` | 41.7s |
| **prove** | **22.6s** |
| verify (native) | instant |
| verify (on-chain) | ~222.7k gas |

Within the prove phase: constraint synthesis 1.9s, R1CS-to-QAP witness map 9.7s,
`Compute C` 7.9s. Setup is a one-time cost per circuit version, and this seeded
`circuit_specific_setup` is a placeholder for spec 18.2's multiparty Phase 2.

**22.6s is comfortably inside spec 19.7's 75s p95 budget** — the earlier
projection of roughly five minutes assumed the 43.7M-constraint bounds, which
the measured mainnet distribution superseded.

Two properties worth internalising:

- **Bounded buffers pay their compiled maximum**, regardless of real input
  size. A 300-byte receipt in a 2048-byte buffer costs the same as a 2048-byte
  one.
- **Witness-dependent reads scale with the bound too.** One 32-byte read from a
  2048-byte buffer is ~500k constraints. Read fixed offsets wherever the format
  fixes one.

## Testing

Release-mode runtimes, which are wildly uneven — budget for the long ones:

| Suite | Time |
|---|---|
| `encoding`, `fixtures` | instant |
| `relation` (unit, both relations) | ~13s |
| `gadgets` | ~10min |
| `relation --test mainnet` | ~8min (100 fixtures, one full system each) |
| `relation --test mainnet_native` | ~13min (57 bare sends + 8 sampled calls) |

Two traps worth knowing before you wait on a run:

- **The mainnet suite prints nothing per fixture.** A stalled run and a healthy
  one look identical from outside. Watch RSS instead: it should sawtooth as each
  system is built and dropped. Flat RSS means it is not advancing.
- **A failing fixture is far slower than a passing one**, because
  `which_is_unsatisfied()` scans every constraint to name the culprit. A
  uniformly broken relation turns an 8-minute suite into hours. If it runs long,
  suspect failure before suspecting size.

One exhaustive test is gated:

```sh
cargo test -p mirage-gadgets --release -- --ignored
```

That sweeps every message length in a two-block buffer (~90s release, ~11min
debug). Run it after touching the padding or state-selection logic.

Every gadget test checks against `mirage-encoding`'s native implementation
rather than against itself, and the negative tests matter most: a gadget that
only passes on valid inputs proves nothing.

## Beta SGX ceremony

The [standalone SGX ceremony](crates/sgx-ceremony/README.md) derives fresh
Phase 2 keys from public Phase 1 genesis, binds them to an SGX quote, and
provides a prepare/build/run/verify flow to repeat after circuit updates.
