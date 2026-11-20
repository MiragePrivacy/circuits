# 05: Implementation correspondence and tests

Agent: implementation. Code under test: PR 3 head cc59207. Written in an agent worktree, since consolidated into the main tree.

Status: complete except where marked. Section 12 lists commands and results.

Later change: under CR-1 (MIN_INSTANCES = 4) the tests were consolidated into the main tree and every 2-instance case
moved to 4, and every 4-instance case to 8. The coverage statements below refer to the sizes as originally run;
the consolidated run is recorded in NOTES.md.

No forgery was found against the production circuit. Every named check is individually enforced and
individually necessary. The premises 02 and 03 hand to this document are tested. Nothing here proves the
R1CS equals the spec symbolically; that part is evidence by evaluation at random points, plus a structural
argument about what the rows can restrict.

## 1. Method

- `src/matrix.rs`: evaluates A, B, C directly against instance and witness assignments. No test verdict
  below comes from `is_satisfied` alone, because it reads cached LC values
  (`matrix_evaluation_sees_what_the_cache_hides` demonstrates the pitfall).
- `src/testkit.rs` (test-only): cheating prover. It runs the transcript honestly over the claimed statement,
  including `derive_r`. A lie is one break in the layered trace: layers above the break are consistent with the
  false claim, layers below are genuine, so exactly one check sees a contradiction. In honest mode its proof is
  element-for-element equal to upstream's prover at 2, 4, 8, 16 instances.
- `src/spec_model.rs` (test-only): native model written from the text of 01-spec.md, shares only the sponge
  with upstream.
- Removal: `#[cfg(test)]` hooks in `enforce_named` and `verify_sumcheck`. They do not exist in a non-test build of
  the crate, which is what `crates/relation` links.
- `enforce_named` now logs `(label, rows)` to `VerificationProfile.checks`. This is side data. Digests of both
  production relations are unchanged by it (section 6), so the matrices are unchanged.

## 2. Each check

"Fails alone" means: the cheating transcript with all else honest has exactly one unsatisfied matrix row, and it is
this check. "Upstream" means upstream's native `verify` panics at the corresponding assert. "Forgery without it"
means: with this one check removed, a false Keccak-f statement has a fully satisfying assignment.

| Check | Fails alone | Upstream same assert | Forgery without it | Coverage |
|---|---|---|---|---|
| output sum | yes | V:28 | yes | 2, 4, 8 instances |
| output word reduction | yes | V:38 | yes | 2, 4, 8 instances |
| output bit reduction | yes | V:46 | yes | 2, 4, 8 instances |
| iota | yes | V:107 | yes | all 24 rounds at 2; rounds 23, 22, 12, 1, 0 at 4 |
| chi | yes | V:126 | yes | same |
| rho | yes | V:146 | yes | same |
| theta | yes | V:166 | yes | same |
| theta_d | yes | V:186 | yes | same |
| theta_c | yes | V:216 | yes | same |
| theta_a | yes | V:244 | yes | same |
| input lane i | yes | V:80 | yes | all 25 lanes at 2; 0, 12, 24 at 4 |
| sumcheck round relation | no such row, see below | end-check assert | yes | see below |

V: here means upstream rust/gkr/src/keccacheck_og/verifier.rs.

Sumcheck round relation: there is no such constraint. p(0) is derived from the running claim, so p(0) + p(1) = claim holds
by construction (01-spec section 1). So:

- A tampered round polynomial fails only the end check of that same sumcheck, and no earlier row
  (`a_tampered_round_polynomial_fails_only_its_end_check`, rounds 23, 12, 0, every layer, every sumcheck round).
- "Removing" it means the test hook replaces the chained claim with a free value at one sumcheck round.
  That gives a forgery for each sumcheck round of the output reductions at 2 and 4 instances, and of every layer in
  rounds 23, 12, 0 at 2 instances.

No removal failed to enable a forgery.

## 3. R1CS against 01-spec

- Residuals: for each of the 196 check rows, `A.z * B.z - C.z` equals the model's `left - right`. Run on honest, cheating, and
  uniformly random proofs with random and edge statements, at 2, 4, 8 instances. Random proofs make all 196 residuals
  unrelated non-zero values, so this compares the two functions at random points.
- What rows can restrict: forward substitution from (proof, statement bits). Every other witness column is a function of them. Every row except
  the 196 named checks and one Booleanity row per statement bit only defines a fresh column
  (`the_only_restricting_rows_are_named_checks_and_booleanity`, 2 and 4 instances). So satisfaction is exactly: all named checks hold and all bits are Boolean.
- Together: for a given (proof, statement) the unique candidate witness satisfies the R1CS iff the spec verifier accepts, up to the strength of
  random-point comparison. Not a symbolic identity.

## 4. Premises handed to this document

Boolean inputs and outputs (02 section 8.1, 03 section 3):

- Row level: `booleanity_alone_stops_a_non_boolean_output_decomposition`: rewriting (b0, b1) to (b0 + 2, b1 - 1) in an output word fails exactly the two
  Booleanity rows and nothing else. So those rows are the whole defense for outputs, consistent with 02.
- Allocation: every witness bit of `verify_witness`, of `permute` outputs, and of caller-owned inputs has a row over that column alone that vanishes on {0,1} and
  not on 2, -1, 3, 1/2.
- Production: `Compiled::boolean_columns` runs over the deployed matrices of both relations. A column enters through x(1-x)=0, or if it is the sole unknown,
  in C only, of a row whose other columns are known Boolean, and takes a value in {0,1} for all Boolean choices of those (at most 8). All witness statement
  bits pass: 717,296 erc20 and 790,512 native. Each is `x` or `1 - x` over such a column. The rest are constants.
- Static: `new_witness_without_booleanity_check` has no call site in crates/ or experiments/ (grep); `AllocatedBool` fields are private to r1cs-std.
- Padding: `Boolean::constant`, so it has no witness column and is compiled into the rows. `padding_states_are_constants_in_the_statement`: a proof for any other padding
  state fails; a false padding output fails.

Not done here: an accepting run with a non-Boolean input at matrix level with the Booleanity rows removed. 02 section 10 ran that in its Python model.

Every recorded permutation reaches finish:

- `finish` is inside both `generate_constraints` (crates/relation/src/lib.rs:262-268, native.rs:239-245). Digest of synthesizer output equals digest of backend plus explicit `finish`,
  and both equal the ceremony's, under setup with no witness. All production callers (crates/prover lib.rs:63, 117, 460, 511; bin/ceremony.rs; streaming) go through these two synthesizers. sgx-bench `census` calls finish itself and is measurement only.
- Recorded counts: erc20 232, native 256, both padded to 256 (`Recording` wrapper; agrees with the Direct backend's call counts). Native sits exactly at capacity: one more permutation moves to 512 instances.
- An output bit can reach a caller only through `permute`, which records it before returning. `finish` consumes the batch, so no permute can follow it.
- Under a genuine witness: every witness statement bit has a row in the verifier region; flipping one output bit of each permutation fails a verifier row (`assert_statement_wiring`).
- Non-`_with` Keccak helpers default to `DirectPermutation` (sponge.rs:100,171, commitment.rs:142, statement.rs:127, traverse.rs:133, constructed_traverse.rs:47). Each is used only by tests or the direct relation, per grep. A bypass through them would be direct constraints, so sound anyway.

The unguarded edge: nothing stops a future caller dropping a `KeccacheckBatch` without calling `finish`, which would silently leave outputs free. No `#[must_use]` or Drop guard. Not a bug today. The digest pin catches it for the deployed relations.

## 5. Other wiring results

| Item | Result | Test |
|---|---|---|
| Batch order: transpose, derive_r_var, native | agree at 2, 4, 8; swap changes r | batch_order_agrees_across_transpose_derive_and_native |
| Setup vs prove matrices | identical at 1, 2, 3, 4, 5, 8 recorded; setup never evaluates a witness closure | setup_and_prove_compile_identical_matrices |
| Setup vs prove, relations | same digest as ceremony in both modes | *_prove_mode_compiles_the_ceremony_circuit |
| Wrong proof length | short, empty, long: Err(Unsatisfiable) at synthesis | proof_length_behavior_differs_from_upstream |
| Batch sizes | 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32 satisfied, flip rejected | batch_sizes_up_to_thirty_two |
| Each check is exactly one row | yes, also on an all-constant statement | no_check_collapses_to_constants_on_a_constant_statement |

Note on the library: `FpVar::enforce_equal` on two constants returns Ok, emits nothing, and never compares (ark-r1cs-std 0.6.0 fields/fp/mod.rs:1089). The verifier cannot hit this because proof elements are always witnesses, and the test above holds even on a constant statement. Other relation gadgets calling `enforce_equal` were not audited for it; that is outside this document's scope but worth knowing.

## 6. Circuit identity

Feasible, and it holds. Chain, each link checked by running it:

    reviewed source -> R1cs::digest -> inputs.json r1cs_digest -> sha256(inputs.json) = release inputs_sha256
    inputs.json genesis_sha256 = sha256(inputs/*/genesis.pk)
    release proving_key_sha256, verifying_key_sha256 = sha256(*/final.pk, final.vk)

| Circuit | r1cs_digest | Rows | Variables |
|---|---|---|---|
| native-keccacheck | de23e3afaeb9a14f461eed444f9e2de1f5b3d4b6f60adfc190e71122a667b6bb | 3,235,943 | 3,218,720 |
| erc20-keccacheck | 2a689108a5035269d6e5471facf96e2f45e4e27cd6f2be9970a69e9efbb272f0 | 3,074,926 | 3,062,519 |

I reused the existing `R1cs::digest` rather than adding one. The digests are pinned in crates/prover/tests/keccacheck_identity.rs. inputs.json is in the run directory, not the repo, and the release file only has its hash. Between input revision 09ad94c and cc59207, no file changed under crates/relation, gadgets, encoding, or keccacheck-arkworks.

The digest proves the label change did not alter matrices: `ceremony digest` from the unmodified tree, and these tests from the modified tree, give the same values.

Key link, by running a proof: `erc20_ceremony_key_proves_the_reviewed_relation` and `native_ceremony_key_proves_the_reviewed_relation` synthesize a fixture witness from the reviewed source, prove with the ceremony's final.pk, and verify with its final.vk. Both pass. A wrong matrix would make this fail with overwhelming probability. The negative control uses the other relation's key, which fails. I did not test a key for a circuit that differs in only one row.

Not done: re-deriving genesis.pk from the matrices and the public ptau, which would make the matrices-to-genesis link an exact hash equality. I started it for erc20 and stopped it after about an hour; at 10 threads it needs roughly two hours per circuit on this host, and the proof above covers the same link probabilistically. To run: `CEREMONY_CIRCUIT=<circuit> ceremony export DIR /home/oz/Code/mirage/ceremony-runs/phase1/powersOfTau28_hez_final_22.ptau`, then compare sha256 of DIR/genesis.pk. Delta updates from genesis to final were checked by `ceremony-host verify` at the time (verified.json); I did not rerun that.

## 7. R1CS-level gadgets

All by matrix evaluation.

| Item | Result | Test |
|---|---|---|
| Constant folding: +, -, *, negate, +=, *=, by-constant, for Var/Const pairs, specials 0, 1, -1, 2, 1/2 and random | bound row holds at expected value and fails at expected + 1 | constant_folding_preserves_field_operations |
| Boolean to FpVar | correct for constant, witness, negated, scaled | boolean_conversion_preserves_the_bit |
| `.sum()` vs fold (6e1b2e8) | same inlined linear form, with repeats, cancellation, zero terms, all-constant | flat_sum_matches_a_fold |
| Verifier sums | words up to u64::MAX do not wrap; MLE over mixed constant and witness tables | verifier_sums_lower_correctly |
| Statement packing | 192-bit top value does not wrap; word-boundary edits distinct | statement_packing_does_not_wrap |
| inline_all_lcs | every cached LC equals its inlined form evaluated on the witness, row and variable counts unchanged | inlining_preserves_every_linear_combination |
| Under-constraint | every aux column determined by (proof, bits) | proof_and_statement_determine_every_witness |

## 8. Differential with upstream

Run: the table in section 2, single-element proof edits at stride 41 at 2 and 4 instances, statement edits. First failing check agrees each time.

Behaviour differences beyond the deliberate transcript change, each tested unless marked:

| # | Upstream native | Circuit | Test |
|---|---|---|---|
| 1 | Takes `r` from the caller, accepts any | Derives r from tag, 2^L, input, output | upstream_accepts_any_r_and_the_circuit_derives_it |
| 2 | Ignores trailing proof elements (never checks `remaining`) | Err at `finish` | proof_length_behavior_differs_from_upstream |
| 3 | Short proof: panic in the transcript | Err(Unsatisfiable) at synthesis | same |
| 4 | Accepts a singleton batch | Native assert refuses | singleton_behavior_differs_from_upstream, batch.rs singleton_batch_is_refused |
| 5 | Takes u64, so bits are Boolean by type | Takes field variables, needs Booleanity rows | section 4 |
| 6 | Stops at the first failing assert | Emits all rows regardless | every test here reads only rows |
| 7 | Rejects by panic | Rejects by unsatisfied row; shape errors are Err | - |

Line-by-line reading against upstream verifier.rs, poseidon/mod.rs, sumcheck/util.rs. No semantic divergence besides the above. Syntactic ones:
eq as 2xy + 1 - x - y vs xy + (1-x)(1-y), same polynomial. eval_mle as c0 + x(c1 - c0) vs (1-x)c0 + x c1, same. Output and input MLEs via eval_eq plus flat sum vs recursive eval_mle, same. rot via a precomputed suffix eq, same formula. mat_partial via DIAG multiply vs in-place doubling chains, equal by test. Constants: RC, RHO, PI are exercised through residual equality at each round and lane.

## 9. Production batch size (256 instances)

All ran and passed, one at a time, about 22 GB resident when sampled:

- `production_batch_soundness`: honest proof equals upstream's; for output bit reduction, round 12 chi, input lane 17: fails alone, upstream agrees, forgery without it.
- `r1cs_equals_spec_at_production_size`: all 196 residuals equal the model's, honest and random proof.
- `the_only_restricting_rows_at_production_size`: determinism and row classification.
- `setup_and_prove_match_at_production_size`: at 232 and 256 recorded.
- `batch_sizes_up_to_production`: 33, 63, 64, 65, 127, 128, 129, 232, 255, 256 recorded.
- Both relations at 256: section 4 and section 6.

Not all checks and rounds were repeated at 256, only those three lies. Nothing in the verifier branches on size other than loop bounds.

## 10. Not covered

- Symbolic equality of R1CS and spec. Random-point evaluation plus row classification only.
- Groth16 soundness, ceremony QAP derivation, Solidity verifier.
- The rest of the relation: only its interface with the batch (statement bits, counts, finish). Receipt and header logic not reviewed.
- Removal tests at 256 instances beyond the listed cases; all layers in all rounds at 2 only.
- Row classification and determinism for whole relations; run on the verifier alone at 2, 4, 256.
- The Boolean pass is sound only as far as its row rule. It proves what it passes, but does not by itself show r1cs-std gadgets are intended.
- Exact re-derivation of genesis.pk for either circuit (section 6).
- An accepting run with a non-Boolean input at matrix level (section 4); 02 section 10 has it in its Python model.

## 11. Findings and change requests

No soundness finding and no CHANGE-REQUEST from this document so far.

Advisory, no constraint change: add `#[must_use]` to `KeccacheckBatch`, or a Drop guard panicking if not finished.

## 12. Commands and results

The crate must be reached through a path outside `.claude/worktrees`, because cargo otherwise walks up to the main checkout's workspace manifest, which does not exclude the nested path. I used a symlink `$WT` to the worktree:

    nix develop -c cargo test --manifest-path $WT/crates/keccacheck/Cargo.toml --release --lib -- --test-threads=12
    nix develop -c cargo test --manifest-path $WT/crates/keccacheck/Cargo.toml --release --lib -- --ignored --test-threads=1
    nix develop -c cargo test -p mirage-prover --release --test keccacheck_identity -- --ignored --test-threads=1
    nix develop -c cargo test -p mirage-relation --release --lib -- --test-threads=1 keccacheck_records batched_setup native::tests::cost
    CEREMONY_CIRCUIT=<circuit> ceremony digest

| Run | Result |
|---|---|
| crate, default set, before spec tests existed | 53 passed, 0 failed, 3 ignored, 5311 s |
| crate, spec, classification, honest subset, on the final source | 6 passed, 0 failed, 180 s |
| crate, ignored production set | 4 passed, 0 failed, 1056 s |
| keccacheck_identity | 9 passed, 0 failed, 359 s |
| keccacheck_identity ceremony_key, with MIRAGE_CEREMONY_RUN set to the beta run | 3 passed, 0 failed, 245 s |
| relation, existing Keccacheck tests | 3 passed, 0 failed, 42 s |

The 53-test run and the production run predate later `rustfmt` and one refactor of a test helper into a function. The source otherwise did not change; I did not repeat the 88-minute run after that. Memory: the default set at 12 threads held up to 73 GB resident, so do not run it alongside the relation tests on this host.

Worktree changes, none committed:

- Production source: `verifier.rs` (`enforce_named` logs labels, `NamedCheck`, `VerificationProfile.checks`, `#[cfg(test)]` hooks, three helpers `pub(crate)`), `batch.rs` (two helpers `pub(crate)`), `lib.rs`, new read-only `matrix.rs`.
- Test only: `soundness.rs`, `testkit.rs`, `spec_model.rs`, `crates/prover/tests/keccacheck_identity.rs`.
- Manifests: dev-dependencies in the crate and in `crates/prover`, with both lockfiles.

Any constraint change, such as CR-1 to CR-4, changes the pinned digests in keccacheck_identity.rs, by design.
