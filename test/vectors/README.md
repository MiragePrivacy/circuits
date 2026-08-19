# Deterministic vectors

The shared interface between three independent implementations of the same
encoding: the Circom circuit, the nomad Rust client, and the Solidity escrow.

Spec Section 19.1 requires these. They exist because the commitment preimage
and statement hash are byte-exact, and a one-byte disagreement between the
three implementations surfaces only as "proof rejected" with no indication of
which side is wrong. Debugging that through a Groth16 verifier is miserable;
debugging it against a vector file is trivial.

**If a vector disagrees with an implementation, the implementation is wrong.**
Fix the encoder, never the vector.

## Files

| File | Covers | Spec |
|---|---|---|
| `commitment.json` | Section 8.3 preimage and digest, both asset kinds | 8.3, 19.1 |
| `statement.json` | Section 10.2 preimage, digest, and the two 128-bit limbs | 10.2, 19.1 |
| `mainnet.json` | 100 real ERC-20 settlements: receipt RLP, MPT path, commitment | 12.5, 12.6 |
| `mainnet-native.json` | 100 real native ETH settlements: transaction and receipt RLP, both MPT paths, commitment | 12.5, 12.6 |

The two `mainnet*.json` files are collected rather than generated, by
`cargo run -p mirage-fixtures --release --bin collect` and `--bin
collect-native`. Every fixture had its trie reconstruction checked against the
block header at collection time, so a fixture that does not correspond to real
chain state was dropped rather than written.

`mainnet-native.json` carries both shapes the native relation accepts, tagged by
`bare_send`: 57 direct sends and 43 calls carrying value. The two differ by an
order of magnitude in size and the difference decides the compiled bounds, so a
collection that dropped either would be misleading. See the top-level README's
"Native ETH" section.

## Format

Every file is a JSON object with a `cases` array. Each case carries a `name`, a
`description` of what it exercises, the inputs, and the expected outputs. All
byte strings are `0x`-prefixed lowercase hex with no separators. All integers
that could exceed 2^53 are hex strings, never JSON numbers.

```json
{
  "spec_section": "8.3",
  "description": "Intent commitment preimage and digest",
  "cases": [
    {
      "name": "erc20_row_zero_minimal",
      "description": "Smallest valid ERC-20 row: index 0, amount 1",
      "input": {
        "relationVersion": 2,
        "instanceDomain": "0x...32 bytes...",
        "chainId": "0x1",
        "escrow": "0x...20 bytes...",
        "requestId": "0x...32 bytes...",
        "rowIndex": 0,
        "assetKind": 1,
        "settlementToken": "0x...20 bytes...",
        "recipient": "0x...20 bytes...",
        "settlementAmount": "0x1",
        "salt": "0x...32 bytes..."
      },
      "expected": {
        "preimage": "0x...the exact packed bytes...",
        "preimageLength": 193,
        "commitment": "0x...32 bytes..."
      }
    }
  ]
}
```

Emitting `preimage` alongside the digest is deliberate. When a digest mismatches
the preimage tells you immediately whether the disagreement is in the packing
or in the hash, which is otherwise a bisection.

## Required coverage

Spec 19.1 and 19.3. A vector set that omits these is not sufficient:

- both asset kinds, including the native case where `settlementToken` must be
  exactly zero and the ERC-20 case where it must be nonzero
- row index 0, 31, and a rejected 32
- `settlementAmount` at 1, at `2^128` (limb boundary), and at `2^256 - 1`
- chain IDs 1, and a value near `2^64 - 1`
- an amount whose hi/lo split is only equal modulo the BN254 field order, which
  must be rejected: this is the alias case Section 8.1 exists to prevent
- a statement hash for bond attempt 1 and for attempt 2 on the same row, which
  must differ

## Generating

Vectors are produced by nomad (the Rust encoder is the reference) and consumed
here and by the Solidity tests. See the nomad-side generator; this directory
holds only the committed output.
