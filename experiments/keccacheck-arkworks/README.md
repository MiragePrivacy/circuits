# Keccacheck arkworks experiment

This excluded standalone crate ports the recursive Keccacheck verifier from
gnark to arkworks R1CS. It deliberately consumes the native proof produced by
Reilabs' Rust `gkr` crate at pinned commit
`15f00e3da5622f1c7155b02d1f9c00bd2416c282` with WHIR disabled, matching the
reference's direct input-bit verification mode.

The experiment is isolated because the reference currently uses arkworks 0.5
while Mirage uses 0.6. It is not production code and does not alter Mirage's
existing Keccak gadget or relation.

Upstream Keccacheck is licensed Apache-2.0. The verifier formulas and Poseidon2
transcript parameters ported here retain that provenance; see
<https://github.com/reilabs/keccacheck> and ePrint 2025/1764.

Run the fast comparison with:

```sh
nix develop -c cargo run --release --manifest-path \
  experiments/keccacheck-arkworks/Cargo.toml -- compare 1 2 8
```

The comparison reports native proof construction, arkworks synthesis,
constraint satisfaction, and the direct bit-level Keccak control cost. Full
Groth16 setup/proving is deliberately excluded from this exploration because
constraint synthesis is the fast iteration gate. See [RESULTS.md](RESULTS.md)
for the measurements and integration assessment.

## Protocol shape

The native witness generator runs Keccacheck's GKR prover over a power-of-two
batch of Keccak-f permutations. The arkworks gadget verifies that proof *inside*
the surrounding R1CS and binds the claimed inputs and outputs. It is therefore
not a second proof checked alongside Groth16 and does not move Keccak checking
on-chain. The final deployment would still expose one ordinary Groth16 proof.

The upstream gnark wrapper derives an output challenge using gnark's extended
Groth16 commitment API. Stock arkworks Groth16 has no equivalent API, so this
experiment derives that challenge in-circuit with the pinned Poseidon2
transcript after absorbing every claimed output word. This is a protocol
adaptation and must receive cryptographic review before production use.
