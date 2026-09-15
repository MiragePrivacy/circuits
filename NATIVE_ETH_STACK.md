# Native ETH on the Keccacheck base

This branch builds on the optimized ERC-20 Keccacheck circuit (circuits PR #2), including the in-range selector checks in c43d92e's history.

- ERC-20 uses the Keccacheck setup/prove APIs and its generated verifier.
- Native ETH retains the separate dual-trie circuit, native setup/prove APIs, and native verifier. It does not yet use the batched Keccacheck backend.
- Native bounds are explicit (544-byte nodes, 3-byte keys, 512-byte receipts, 704-byte headers, depth 4, 512-byte transactions). Changes to ERC-20 defaults must not silently alter the native circuit.
- Shared gadget changes require regenerated verifier/proof artifacts. The matching escrow branch vendors both pairs, and Nomad pins this branch's exact commit.

Generate artifacts with:

```sh
RAYON_NUM_THREADS=16 cargo run -p mirage-prover --release --features export --bin export-verifier -- --keccachecheck
RAYON_NUM_THREADS=16 cargo run -p mirage-prover --release --features export --bin export-native-verifier
```

The existing native timing/privacy and trusted-setup limitations still apply; see crates/relation/src/native.rs.
