# Mirage settlement circuits

Rust/arkworks circuits for the ZK receipt relation in
`../docs/standalone-zk-receipt-protocol-v1.2.md`.

**Backend: Groth16 over BN254 via `ark-groth16`.** This overrides spec section
12.1, which freezes Circom + snarkjs. `FINDINGS.md` records why, with measured
evidence for each rejected alternative — read it before proposing a change.

Status: **step 2 in progress.** The encoding reference is written and tested;
the gadgets and relation are not.

## Build order

Section 25 of the spec is deliberate about sequencing. Each step is
independently reviewable, which matters because a missing constraint is silent:
the proof still verifies, the contract still pays, and nothing looks broken.

| Step | What | State |
|---|---|---|
| 1 | Byte-exact encoders and deterministic vectors | **done** — `crates/encoding` |
| 2a | Keccak and byte primitives | **done** — `crates/gadgets` |
| 2b | RLP, MPT, receipt relation | next; bounds are a separate decision |
| 3 | Transaction parser + native dual-trie relation | not started |
| 4 | Canonical escrow with embedded verifier | not started |
| 5 | Positive delayed-witness ancestry | not started |

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
than a wall.

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

Measuring that distribution against nomad's `generate_proof` path is what sets
the constants. It does not block writing the gadgets — bounds are compile-time
values and the parser code is identical either way.

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

## What has to be written from scratch

No maintained library implements Ethereum receipt-trie inclusion in any
framework that also satisfies the verifier constraints. Specifically missing
from arkworks:

- **A correct keccak-256 gadget.** The only existing one
  (`natharyan/arkworks-keccak`) pads with a plain `1` bit instead of Ethereum's
  `0x01` delimiter, and its `assert_eq!` on `.value()` is a native panic during
  proving and a silent no-op during setup — not an enforced constraint. Port
  from ZoKrates' `hashes/keccak/256bit.zok`, which has the correct delimiter and
  a genuine multi-block absorb loop.
- **Dynamic indexing.** `UInt8` is 8 `Boolean`s and there is no random-access
  gadget. RLP needs one because offsets are witness-dependent; it must be built
  from `CondSelectGadget` trees.
- **RLP, MPT traversal, and receipt parsing.** Nothing exists.

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

Two properties worth internalising:

- **Bounded buffers pay their compiled maximum**, regardless of real input
  size. A 300-byte receipt in a 2048-byte buffer costs the same as a 2048-byte
  one.
- **Witness-dependent reads scale with the bound too.** One 32-byte read from a
  2048-byte buffer is ~500k constraints. Read fixed offsets wherever the format
  fixes one.

## Testing

`cargo test` runs in ~25 seconds. One exhaustive test is gated:

```sh
cargo test -p mirage-gadgets --release -- --ignored
```

That sweeps every message length in a two-block buffer (~90s release, ~11min
debug). Run it after touching the padding or state-selection logic.

Every gadget test checks against `mirage-encoding`'s native implementation
rather than against itself, and the negative tests matter most: a gadget that
only passes on valid inputs proves nothing.
