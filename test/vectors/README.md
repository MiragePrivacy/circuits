# Test vectors

The native Rust encoders, arkworks circuits, client and Solidity escrow share
byte-exact commitment and statement encodings. Deterministic vectors include
packed preimages so packing errors can be distinguished from hash errors.

| File | Contents |
|---|---|
| `commitment.json` | Intent preimages and digests for both asset kinds |
| `statement.json` | Statement preimages, digests and two 128-bit limbs |
| `mainnet.json` | 100 collected ERC-20 receipt-trie fixtures |
| `mainnet-native.json` | 100 native bare sends and 43 value-carrying calls |

Native bare sends are acceptance fixtures; calls exercise empty-calldata
rejection. Collection reconstructs tries and checks them against block-header
roots. Sampled maxima do not establish protocol bounds; see the
[native relation](../../NATIVE_ETH_STACK.md).

## Generation

```sh
nix develop
cargo run -p mirage-encoding --bin gen-vectors
cargo run -p mirage-fixtures --release --bin collect
cargo run -p mirage-fixtures --release --bin collect-native
```

The first command regenerates deterministic encoding vectors. The collection
commands require network access and refresh separate mainnet datasets; they
are not needed to run tests against committed fixtures.

Deterministic files contain a `cases` array with inputs and expected outputs.
Consult the committed JSON for the collected datasets' schema. Preserve hex
encoding for byte strings and large integers. Resolve disagreements against
the protocol and reference encoder before regenerating expected outputs.
