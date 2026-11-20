# Arkworks Keccacheck circuit backend

This crate ports the recursive Keccacheck verifier from
gnark to arkworks R1CS. It deliberately consumes the native proof produced by
Reilabs' Rust `gkr` crate at pinned commit
`15f00e3da5622f1c7155b02d1f9c00bd2416c282` with WHIR disabled, matching the
reference's direct input-bit verification mode. The circuit side now uses
arkworks 0.6, matching Mirage; the pinned native Rust prover remains on 0.5 and
crosses that boundary through canonical BN254 scalar values.

The backend supplies the deferred verifier used by the Mirage relations and an
alternate Rust prover API.

The runtime path is Rust-only. The gnark source is neither linked nor executed;
it was used as a readable reference for the circuit formulas. Cargo currently
fetches the pinned Rust `gkr` source at build time, so a production enclave
build should vendor that dependency, but the resulting enclave does not need
Go or network access.

Upstream Keccacheck is licensed Apache-2.0. The verifier formulas and Poseidon2
transcript parameters ported here retain that provenance; see
<https://github.com/reilabs/keccacheck> and ePrint 2025/1764.

Run the fast comparison with:

```sh
nix develop -c cargo run --release --manifest-path \
  crates/keccacheck/Cargo.toml -- compare 2 8
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
transcript after absorbing the full claimed statement: every input and output
word. This is a protocol adaptation and must receive cryptographic review
before production use.

## Review requirements

The output challenge `r` absorbs a domain tag, the instance count, then every
claimed input and output word (three 64-bit words per field element) before it
is squeezed. The main transcript absorbs `r` before any other challenge and
absorbs proof values before the challenges testing them, so every challenge
depends on the whole statement. Binding only the outputs would leave the
final input check at an already-fixed point (weak Fiat-Shamir). Unlike the
upstream commitment API, this construction binds the statement words rather
than a Groth16 witness commitment; equivalence requires cryptographic sign-off.

Batches have at least `MIN_INSTANCES = 2` permutations. A singleton batch has
no `r`, so its `beta` challenges are constants and an LLL-short kernel vector
of them forges outputs; `KeccacheckBatch` pads one permutation to two.

`r` is computed by Mirage and passed to the unmodified upstream prover, so
its derivation can change without forking the protocol. Any transcript change
still requires new circuit keys.
