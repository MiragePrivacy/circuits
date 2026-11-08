# Keccacheck batch: independent forgery attempt

Commit reviewed: cc59207bef6d59347d82e2f2266df6051f72fa58 (worktree agent-ae2a51469f1562a3f).
Not read: docs/, other worktrees, ~/.claude/projects, RESULTS.md conclusions.

## Result

No forgery found. Every false Keccak-f statement I built, at 2, 4 and 256
instances, left at least one R1CS row unsatisfied. I evaluated each row
directly as A*B=C over the finalized matrices, not through cached LC values.
Most of these runs left exactly one row unsatisfied.

## Tests run (all code in the worktree, uncommitted)

Files:
- experiments/keccacheck-arkworks/tests/forgery_common.rs: matrix extraction,
  direct A*B=C evaluation, a fixpoint "is every variable pinned" propagator,
  and `prove_layers`. `prove_layers` is upstream `prove` driven by
  caller-supplied round layers and round constants.
- experiments/keccacheck-arkworks/tests/forgery_batch.rs
- crates/relation/tests/forgery_relation.rs. Its dev-deps (gkr,
  ark-bn254-05, keccak) were added to crates/relation/Cargo.toml, which also
  changed Cargo.lock. Both are uncommitted.

1. Alternate permutations with transcript-consistent proofs
   (`alternate_functions_with_consistent_proofs`, 2 and 4 instances, 360 cases).
   - What it does: each case swaps one round for a self-consistent but wrong
     function, then proves it honestly with Fiat-Shamir r derived from its own
     false statement. The wrong functions were:
     - a different round constant (all instances, or one instance only)
     - a different rho offset for lane 0, 1, 7, 13 or 24
     - swapped pi lanes
     - chi using x+3 in place of x+2
     - one flipped chi bit
     - a theta D rotation of 2 in place of 1
     - a flipped C or D bit in each column
     - a flipped theta output bit
     - round k+1 input different from round k output
   - Rounds covered: 0, 1, 11, 22 and 23.
   - Prover: the run used a scratch copy of upstream gkr with the prover's own
     consistency assertions removed, because those assertions panic on
     inconsistent layers. Reproduce with
     `--config 'patch."https://github.com/reilabs/keccacheck.git".gkr.path="<copy>/gkr"'`, where `<copy>` is
     upstream `rust/` at 15f00e3 with scripts/forgery/gkr-no-asserts.patch applied (`patch -p0`). The test is
     `#[ignore]` for that reason.
   - Result: all 360 were rejected, each with exactly one unsatisfied row,
     the check for the mutated layer.
2. True layers with a false statement (output, input or both flipped) and r
   re-derived (`honest_layers_false_statement`): 1 or 2 rows unsatisfied.
3. Every statement word at 2 instances (`every_statement_word_is_bound`): 50
   words, input and output side, bit 0 and bit 63, r re-derived, true-layer
   proof. All 200 were rejected.
4. Production end-to-end, ERC-20 relation, 232 recorded and padded to 256
   (`fabricated_receipt_with_forged_leaf_hash`).
   - Setup: the intent and receipt pay 999. The block's trie holds the genuine
     receipt. The only lie is the output of the leaf-hash permutation, which
     is set to keccak(real leaf).
   - Proof: r is derived from the false statement and the proof follows the
     true layers.
   - Result: all 724,487 relation rows are satisfied and exactly 1 of the
     3,074,926 rows is unsatisfied, row 969216 in the batch verifier. So the
     GKR batch is the only barrier, and it holds.
5. Free-witness analysis.
   - Verifier gadget at 2, 4 and 8 instances: seeded with the statement bits
     and proof elements, every other variable is pinned. There are no unused
     variables, and every statement bit occurs in at least 3 constraints.
   - Production ERC-20 and native relations: seeded with boolean-constrained
     variables and the GKR proof elements, the free variables number 35 and
     52 respectively. All are single-use `is_neq` multipliers multiplied by
     zero, none of them in the verifier. No variable is unused.
6. Setup and prove matrices are identical for both production relations
   (hash of all A/B/C entries, row and variable counts), and for the batch
   alone with 1, 3, 4 and 5 recorded permutations.
7. Constant-on-constant equality no-ops.
   - Background: in ark-r1cs-std 0.6, `FpVar` `conditional_enforce_equal`,
     `mul_equals` and `square_equals` silently return Ok on two constants.
     This also covers `UInt8::enforce_equal`, which goes through `FpVar`.
   - Test: I instrumented a scratch copy of the crate to log every such call,
     then synthesized both production relations in setup and prove mode.
   - Result: zero calls.
8. Smaller cases: a random proof, instance reordering, and an all-zero state
   with a false output were all rejected.

## Read only (not exercised beyond the above)

- verifier.rs compared line by line with upstream keccacheck_og/verifier.rs
  and sumcheck/util.rs (sumcheck, eq, rot, strip_pi, iota/chi/rho/theta/
  theta_d/theta_c/theta_a checks, beta combinations). The port is faithful.
  The only intentional difference is the statement binding.
- Layer-by-layer GKR reasoning, including the reduction from claimed words to
  the true bits:
  - Each reduction is a sumcheck of the right degree.
  - Every proof element is absorbed before the next challenge.
  - The sumcheck p0 is derived from the claim.
  - The challenges from r onward come from a sponge that has absorbed the
    whole statement:
    - statement absorption is tag, instance count, then 192-bit packed chunks
      (injective below 254 bits, lane-major, inputs then outputs);
    - the second sponge absorbs all log n of the r values.
- Padding: the padded states are constant zero inputs with a constant
  f(0) output, so they cannot replace a recorded permutation. Both circuits'
  `generate_constraints` call `finish`, and the ceremony uses
  `Keccacheck*Circuit::setup`.
- Sponge consumers: keccak256_fixed/var (padding, zero tail, final-block
  selection), AbsorbedMessage (`enforce_padding`, capacity sharing, `byte`),
  the ancestry chain links, the constructed-leaf framing and its length
  bounds, and the MPT branch layout checks. Input and output states are
  clones of the same Boolean variables used elsewhere, so they are never
  re-allocated copies.
- r1cs-std XOR, AND, select, `is_neq` and `enforce_in_field_le`.
  ark-relations `new_lc`, `inline_all_lcs`, `compactify` and `make_row`.

## Suspected issues / hazards (none exploitable as found)

- Low: the FpVar/UInt8 constant-on-constant equality is a silent no-op
  (upstream ark-r1cs-std). It is not reached today (test 7). It is latent in
  `parse_authenticated_prefix`, whose `view` fills unread offsets with
  `UInt8::constant(0)`: a future check placed outside
  `AUTHENTICATED_PREFIX_READS` would pass vacuously.
- Informational: the statement sponge and the GKR transcript sponge share
  INITIAL_STATE. The statement sponge's first absorb is a constant tag and the
  GKR sponge's is r[0], so I see no cross-use. No explicit domain tag
  separates them.
- Informational: Poseidon2 parameters (width 16, 4+57+4 rounds, diagonal
  0..17 with d0=0) are taken from upstream and were not assessed (out of
  scope).

## Not done

- No cheating prover that adapts sumcheck polynomials beyond following
  alternate layers. I relied on the standard Schwartz-Zippel argument.
- The mutation sweep covered rounds 0, 1, 11, 22 and 23, not all 24, and only
  sizes 2 and 4. Production size was covered by test 4 only.
- The native relation had no end-to-end forgery run (only tests 5-7).
- The parser logic in receipt/log.rs and transaction/envelope.rs, and the
  semantics of the RLP cursor, were only skimmed. They are outside the
  Keccak-f statement.
- No review of the streaming prover, Groth16, the Solidity verifier or the
  ceremony.
