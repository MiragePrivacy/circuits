# Standalone beta SGX ceremony

This executable performs one private Groth16 Phase 2 delta update per circuit
inside a non-debug Fortanix SGX enclave. It uses the public Hermez Phase 1 and
existing arkworks genesis derivation. It does not start Nomad, seal secrets,
accept a host-provided contribution seed, or fall back to host setup.

This is a beta TEE ceremony, not a multiparty ceremony. The output is an
attested arkworks key update, not a Bellman/snarkjs participant transcript.
The public browser ceremony remains a separate workflow. There is no beacon.

## Repeat after a circuit update

Commit the circuit and ceremony implementation first. The preparation/build
commands reject a dirty tree and bind the source revision into the input
manifest. Keep run directories outside the repository. Never reuse a directory
for another run; a failure leaves incomplete evidence for inspection.

From the circuits repository:

```sh
nix develop
python3 scripts/sgx-ceremony.py prepare /absolute/path/beta-v1 \
  /absolute/path/powersOfTau28_hez_final_22.ptau --id beta-v1
python3 scripts/sgx-ceremony.py build /absolute/path/beta-v1 \
  --signing-key /absolute/path/ceremony-signing-key.pem
```

Preparation checks the published BLAKE2b-512 hash of the power-21 or power-22 transcript
(the same hash pinned in the ceremony repository), runs the existing `ceremony
export` for both current relations, and records their R1CS digests and exact
uncompressed genesis hashes. The current native circuit requires power 22. If a circuit outgrows the selected transcript, export fails;
review and pin a larger published transcript before proceeding. Preparation is
expensive: it synthesizes both complete circuits and derives both genesis keys.

Build embeds `inputs.json` into the enclave. Changing a circuit, genesis,
ceremony ID, or source revision requires a new build and measurement. The SGX
shell pins the Fortanix toolchain, enables LVI mitigation during compilation,
and provisions 32 thread slots, 2 MiB stacks, and a 16 GiB heap. The enclave
uses 16 Rayon workers. These limits still need validation on the target machine.
The signing key is an operator-supplied 3072-bit RSA key, as with Nomad's existing
`sgxs-sign` flow. It is not a ceremony secret. The script never creates or
publishes it. The build never enables SGX debug mode.

Transfer the complete run directory and the built `ceremony-host` executable
to the SGX machine. The host requires SGX device access, AESM with ECDSA quote
support, and network access to Intel PCS for collateral. Run:

```sh
RUN=/absolute/path/beta-v1
MEASUREMENT=$(cat "$RUN/build/mrenclave.txt")
target/release/ceremony-host run "$RUN" "$MEASUREMENT" \
  "$RUN/build/ceremony.sgxs" "$RUN/build/ceremony.sig"
```

Use the MRENCLAVE from your reviewed build. Do not obtain the expected
measurement from the untrusted output quote. Rebuild independently from the
same commit, lockfiles, input manifest, and build settings when auditing it.

The host runs the two circuits sequentially. Each enclave reads only a genesis
matching its measured manifest, validates its encoding, samples a fresh scalar
with `OsRng` (Fortanix's RDRAND backend), updates delta/H/L, and exports keys.
It hashes those exact serialized bytes inside the enclave. A domain-separated
SHA-256 commitment to `output.json` occupies the first 32 REPORTDATA bytes;
the remaining 32 are zero. `output.json` binds the exact `inputs.json` bytes.
No host JSON serialization or output re-encoding is trusted by the enclave.

## Verification and outputs

```sh
target/release/ceremony-host verify "$RUN" "$MEASUREMENT"
```

Verification checks the DCAP signature chain and current collateral validity,
requires `UpToDate` TCB status, rejects debug enclaves and other measurements,
and compares REPORTDATA. There is deliberately no advisory override switch.
Platforms reporting a non-UpToDate status require a reviewed policy change,
not bypassing verification. The verifier then checks artifact hashes, parses
keys with point validation and exact EOF, checks every fixed section and batched
H/L pairing relations against genesis, checks PK/VK agreement, and generates
and self-verifies a full circuit fixture proof. It renders the existing Solidity
verifier template from the resulting VK. Existing verifier source must match.

Each circuit directory contains:

- `final.pk`, `final.vk`: uncompressed arkworks serialization.
- `output.json`: the exact manifest committed by the quote.
- `quote.bin`, `collateral.json`: attestation evidence.
- `Verifier.sol`, `proof.json`: derived verifier source and a self-verified fixture.

`verified.json` is written only after both circuits pass. It is a local receipt,
not a trusted signature or a substitute for verification. An interrupted run
must not be published as complete. Verification regenerates fixture proofs;
those randomized proofs are not committed by the quote. Verifier source is
verified by regeneration from the attested VK. Publish inputs, both genesis
keys, build records, and both complete output directories together.

Collateral expires. Verification uses current time and fails closed when it
expires; obtain fresh authentic collateral for the original quote to reverify.
The stored verification timestamp is not a trusted historical timestamp. This
workflow does not implement archival acceptance of expired/revoked collateral.

## Trust and integration

The assurance depends on public Phase 1 security, the reviewed build, Intel SGX
and its TCB, enclave entropy, and the scalar multiplication implementation.
Explicit zeroization clears the owned delta and inverse; it is not proof that
compiler temporaries or worker-stack copies were erased. An enclave quote
cannot prove physical erasure or eliminate microarchitectural side channels.
Audit the cryptographic implementation and the target host before funding beta
escrows. No actual hardware run is implied by a host test or cross-compilation.

After verification, use the exact keys to regenerate escrow's native/ERC20 and
batch verifiers and provision Nomad with pinned full PK hashes and VK hashes.
This crate does not change Nomad's production provisioning or downstream
contracts. Never use its outputs with old embedded verifier constants.
A circuit update or public ceremony requires new keys and new escrow deployments;
retain old keys until outstanding escrows have settled or refunded.

## Development checks

The contribution walks sequential windows of `streaming::SGX_MSM_CHUNK` points,
reusing the prover's 256K-point locality window. Workers multiply contiguous
1024-point chunks and batch-normalize them with arkworks, bounding temporary
projective storage instead of spreading work across the whole key.

Socket reads and writes are bounded to 64 KiB. This avoids repeatedly copying a
whole remaining key through Fortanix's untrusted I/O buffer on partial writes.
The enclave serializes the final key directly through a buffered hashing writer;
the manifest commits the exact bytes sent without retaining another full key
buffer. Genesis remains hash-checked before parsing. Stage logs report elapsed
time for diagnosis; they are not attested evidence or trusted timing.

These choices preserve the key encoding and contribution equations. The prover's
window size is a starting point, not a measured optimum for ceremony workloads.
Benchmark the full ceremony on the target host before claiming a speedup.

For ceremony-only fixes, copy the prepared `inputs.json` and `inputs/` into a
new run directory and build with `--reuse-inputs`. The script verifies genesis
hashes and rejects any source differences outside this crate and its build
script. The original input revision stays in the manifest, and `build.json`
records both input and enclave source revisions. Circuit or dependency changes
require fresh preparation. Never overwrite an earlier run's build or outputs.

```sh
nix develop -c cargo test -p mirage-sgx-ceremony --features host
nix develop -c cargo clippy -p mirage-sgx-ceremony --features host --all-targets --no-deps -- -D warnings
```

Tests exercise a real small Groth16 circuit, independent contribution checks,
invalid query updates, unchanged delta, wrong public signals, serialization
trailing bytes, partial I/O, streamed-key compatibility, locality-window
boundaries, frame bounds, and input/output manifest binding. The non-SGX
`ceremony-enclave` binary always exits unsuccessfully.
