# Mirage settlement circuits

Rust/arkworks circuits for the ZK receipt relation in
`../docs/standalone-zk-receipt-protocol-v1.2.md`.

**Backend: Groth16 over BN254 via `ark-groth16`.** This overrides spec section
12.1, which freezes Circom + snarkjs. `FINDINGS.md` records why, with measured
evidence for each rejected alternative — read it before proposing a change.

Status: **step 2 complete.** The relation synthesizes at ~10.4M constraints,
is satisfied by all 100 mainnet fixtures, and a real proof verifies through the
exported Solidity verifier on-chain (4,858 bytes, ~222.7k gas).

## Build order

Section 25 of the spec is deliberate about sequencing. Each step is
independently reviewable, which matters because a missing constraint is silent:
the proof still verifies, the contract still pays, and nothing looks broken.

| Step | What | State |
|---|---|---|
| 1 | Byte-exact encoders and deterministic vectors | **done** — `crates/encoding` |
| 2a | Keccak and byte primitives | **done** — `crates/gadgets` |
| 2b | RLP, MPT, receipt relation | **done** — `crates/relation` |
| 3 | Transaction parser + native dual-trie relation | not started |
| 4 | Canonical escrow with embedded verifier | verifier exported and measured; escrow lives in the escrow repo |
| 5 | Positive delayed-witness ancestry | not started |

Step 2's relation closes the whole binding chain:

```
commitment            -> settlement token / recipient / amount
header -> receiptsRoot -> MPT inclusion -> receipt -> Transfer log
header -> keccak       -> statement's witnessBlockHash
header.number          -> bondStartBlock < n <= bondDeadline
statement context      -> keccak -> the two public signals
```

The setup is `circuit_specific_setup` with a seeded RNG, which spec 18.2 marks
as a placeholder for a multiparty Phase 2. The verifier is structurally
identical either way, so the size and gas figures hold; only the key's
provenance differs.

Step 2 deliberately reveals the transaction block; ancestry is step 5. Building
them together would make it impossible to tell which half causes a constraint
blowup.

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
    gadgets/    in-circuit primitives: keccak, bytes, RLP, MPT
    relation/   the ERC-20 receipt relation built from those gadgets
    prover/     setup, prove, verify, Solidity verifier export
    fixtures/   mainnet collection: receipt-trie rebuild and proof extraction
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
| `relation` (unit) | ~10s |
| `gadgets` | ~10min |
| `relation --test mainnet` | ~8min (100 fixtures, one full system each) |

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
