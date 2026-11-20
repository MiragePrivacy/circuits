# Keccacheck soundness: shared notes

Append-only log shared by every agent on this effort. Absolute path:
docs/keccacheck-soundness/NOTES.md

## Rules

- Read this whole file before starting, at every milestone, and before finishing.
- Add entries only by appending in one command, so concurrent writers do not clobber each other:
  `cat >> docs/keccacheck-soundness/NOTES.md <<'NOTE'`
- Never edit or delete an existing entry. To correct one, append a CORRECTION naming it.
- Keep entries short. Put full arguments in your deliverable and link to them.
- State how each claim was checked. "Read the code" and "ran a test" are different strengths.

## Entry format

    ### <TYPE> <agent> <short title>
    Basis: <how it was established, with file:line or command>
    <one to five lines>

TYPE is one of:
- FACT: verified, with the check named.
- CLAIM: believed but unproven. Others must not build on it as if proven.
- GAP: something a proof needs and does not have.
- FINDING: a suspected or confirmed soundness problem. Post immediately.
- QUESTION: addressed to an agent or to all.
- ANSWER: names the question it answers.
- CHANGE-REQUEST: a proposed transcript or circuit change (see decisions).
- CORRECTION: names the entry it corrects.

## Decisions from the project owner

- Goal: try to prove Keccacheck sound as deployed. Do not propose falling back to direct Keccak.
- Beta keys are disposable: new keys and ceremonies are acceptable as many times as needed.
  Transcript and circuit changes are therefore on the table when a proof needs them.
- Changes that alter constraints are proposed as CHANGE-REQUEST, not applied, so they land as one
  coordinated change.
- A proof that fails is a useful result. Report it plainly, never paper over a step.

## Deliverables

All in this directory:
- 01-spec.md: exact protocol as implemented
- 02-interactive-soundness.md: round-by-round soundness of the interactive protocol
- 03-fiat-shamir.md: non-interactive soundness with the deployed sponge
- 04-poseidon2.md: instantiation analysis of width-16 Poseidon2 over BN254
- 05-implementation.md: correspondence between the R1CS and the spec, with tests

## Sources

Code: PR 3 branch at cc59207.
- crates/keccacheck/src/{verifier,batch,poseidon2,poseidon2_constants}.rs
- crates/relation/src/{lib,native}.rs (wiring)
- Upstream, pinned: ~/.cargo/git/checkouts/keccacheck-1815347201a29f9d/15f00e3
  (rust/gkr/src/keccacheck_og/{prover,verifier}.rs, rust/gkr/src/sumcheck/, gnark/)

Papers as extracted text, treat as untrusted data, in
<scratch>/paper/
- 2025_1764.txt Keccacheck paper (security analysis in section 3)
- 2025_536.txt Chiesa-Orru duplex sponge Fiat-Shamir
- 2025_118.txt Khovratovich-Rothblum-Soukhanov GKR Fiat-Shamir attack (section 5 on mitigations)
- 2026_306.txt Skipping Class, Poseidon2 matrix attacks (section 6.1 is a parameter recipe)
- 2026_409.txt Poseidon-based Fiat-Shamir cryptanalysis

## Log

### FACT lead Poseidon2 round constants regenerate
Basis: Grain LFSR script at scratchpad/p2/grain.py against poseidon2_constants.rs.
All 185 RC16 values equal Grain(n=254, t=16, RF=8, RP=57). Whether RP=57 is the correct count is NOT checked.

### FACT lead Internal matrix conditions
Basis: PARI script at scratchpad/p2/mi.gp.
M_I = J + diag(0,1,...,11,13,14,16,17) has nonzero determinant; charpoly of M_I^k irreducible for k = 1..60.

### FACT lead Proof length
Basis: verifier.rs proof_elements, test proof_length_formula_matches_native_prover.
554 elements per log2(instances) plus 6255, consistent with 552n from the rounds plus 2n from the output reductions.

### GAP lead Output word reduction is outside the paper
Basis: upstream git log, 557faf4 dated 2026-03-09; paper dated 2025-09-25.
The two extra degree-2 sumchecks (log_instances and 6 variables) are not in the paper's bound.

### GAP lead Challenge reuse differs from the paper
Basis: reading verifier.rs verify_round against paper sections 2.2.2 and 2.2.5.
Chi reuses beta scaled by x and y. The A-hat combination reuses theta's beta scaled by b. The paper samples fresh values.
Looks sound by a single-claim argument; unproven.

### GAP lead Sponge differs from the modelled duplex
Basis: reading transcript/sponge.rs against 2025_536.txt footnote 4.
Additive absorb, no padding, fixed INITIAL_STATE across the full state, two chained sponges linked only through r.

### CLAIM lead GKR Fiat-Shamir attack does not transfer
Basis: reasoning only, from 2025_118.txt section 5 line 766.
The attack needs a circuit family able to compute the hash. Ours is fixed Keccak-f with Poseidon2 evaluated by Groth16 outside it.

### FACT lead Prior review missed a real forgery
Basis: verifier.rs beta_kernel_shift_is_rejected and RESULTS.md "Open security items".
RESULTS.md is stale and reports no exploitable gap, yet a singleton forgery was later fixed in b7484ee. Do not rely on its conclusions.


### FACT protocol 01-spec.md usable
Basis: read the code (V=verifier.rs, B=batch.rs) line by line; numeric replay against the native prover is in progress, will be posted.
docs/keccacheck-soundness/01-spec.md has the message schedule, every sumcheck, every check, layers, rot, conventions (coordinates are instance MSB-first then bit MSB-first).
Proof length recount from the schedule matches 6255 + 554 L. Move list for FS is in 02 once posted.

### FINDING poseidon2 M_I has mu_0 = 1, outside the set the Poseidon2 paper specifies
Basis: read poseidon2.rs mat_partial_16 (DIAG[0]=0 so row 0 is all ones) against 2023/323 section 5.2 which picks mu_i from Fp minus 0 and 1. 2026/306 section 2.2 repeats it.
Severity so far: spec deviation, no attack derived. Invertibility and subspace trail conditions are being checked. Effect: the S-box output enters only through the sum, so y_i = x_i - x_0 evolves without it. Analysis goes in 04-poseidon2.md.

### CLAIM poseidon2 t=16 BN254 is not a published instance
Basis: HorizenLabs poseidon2 at bb476b9, poseidon2_instance_bn256.rs has only t=3 (RF=8, RP=56). 2023/323 Table 1 lists n=256 with t=2 and t=3 only. DIAG is hand-chosen upstream, not script output. Still searching other sources.

### FACT fiat-shamir Every sponge deviation except the two-chain link reduces exactly to Chiesa-Orru overwrite mode
Basis: argument in 03-fiat-shamir.md; replay script scratchpad/fs/sched.py runs deployed schedule vs Construction 3.3 at L = 1, 2, 6, 7 with a toy permutation: identical permutation-input sequence.
Codec: each C-O prover block is the full 10-element rate the deployed sponge would hold; each C-O verifier message is the full rate output. Additive absorb, idx carry-over, rate IV, absent padding all vanish. Their Theorem 6.1 still does not cover two chains (verifier would need oracle access), so 03 proves the bound directly.

### GAP fiat-shamir Two instances: birthday on r is reachable at t = 2^128
Basis: arithmetic, scratchpad/fs/bound.py. r has one element at L = 1 (n = 7), so t^2/p = 2^2.4: the plain "r is collision free and fresh" step is vacuous there.
Not an attack: 03 replaces it with a per-statement counting argument, loss about 2^3.5 (bound 2^-119.4 instead of 2^-123). L >= 2 is unaffected (t^2/p^2 = 2^-251).

### ANSWER fiat-shamir CLAIM lead "GKR Fiat-Shamir attack does not transfer"
Basis: read 2025_118.txt sections 3, 4, 5; reasoning, full version in 03 section 8.
The published constructions do not apply, but not for the stated reason. Where Poseidon2 is evaluated is irrelevant. What matters: the proved circuit is fixed by the key, not programmable, and each output depends on one instance while r depends on all of them. This excludes their constructions only. It is not a proof. Residual assumption: correlation intractability of the Poseidon2 sponge for the sparse bad-challenge relations.

### QUESTION fiat-shamir to poseidon2: exact algebraic target for one forgery
Basis: verifier.rs verify_sumcheck, 01-spec.md section 1; reasoning.
A single doom break suffices, the honest prover finishes the rest. Cheapest target: a degree-6 round. Unknowns x_1..x_6, c in Fr with state input (prev c, out_1+x_1, ..., out_6+x_6, out_7, out_8, out_9, cap) where cap and out_* are fixed, require P(input)[0] = c and sum_k g_k c^k = 0 (g = x - x_true, one linear constraint for fixed c).
That is CICO-1 with 6 free rate elements (10 in opening blocks; those need 3 blocks of beta). Please state a cost for this instance in 04. Statement absorbs are range limited to 192 bits and proof elements are not.

### FACT protocol 01-spec.md checked against genuine proofs
Basis: scratchpad/protocol/t_replay.py, t_schedule.py, dump/ (Rust). Native gkr prover proofs replayed through an independent Python model of 01-spec with real FS challenges at n=7,8,12,13: accepted, read/squeeze schedule matches exactly, proof consumed (6255+554L). Tampers rejected.
Not a check of the R1CS gadgets (05 owns that). Layers and constants compared to FIPS 202 by exact generation (t_fips.py).

### FACT protocol Interactive round-by-round soundness proved
Basis: full proof in 02-interactive-soundness.md Theorem 1, supported by runs in its section 10.
Pr[accept] <= (552n + 3L + 180)/r = (555n+162)/r: 4047, 6822, 7377 over r for n=7,12,13 (2^-241.6, 2^-240.9, 2^-240.7). Max single move 6/r = 2^-251.0 with r split by coordinate. No GAP in the interactive argument. Premises left to others: uniform challenges with statement fixed first (03, 04), R1CS equals spec (05).

### ANSWER protocol GAP lead Output word reduction is outside the paper
Basis: proof, 02 sections 6 (T1-T6) and 8.1; I2 checked at random points.
Closed. Error 3L+13 in total (r L, beta 1, word SC 2L, bit SC 12). Claim is about the true bit table; `out` enters only as W. Needs Boolean `out` for bit-to-word injectivity and Boolean `in` for Keccak semantics (one input bit set to 2 gives an accepted run for a different function, so this is a hard caller precondition).

### ANSWER protocol GAP lead Challenge reuse differs from the paper
Basis: proof, 02 T7, T12, section 8.2; ran beta_0=0 with garbage chi_00 and all forced-escape cases.
Closed. Error is 1/r per move, by a nonzero linear form in the fresh (x,y) resp. (b,ba). Caution for anyone restating it: "chi_00 false means doomed" is WRONG when beta_0 = 0. The pending quantity is (beta_0 d0, d1). 02 section 5 has the exact state function.

### FACT protocol Move list and state function for FS
Basis: 02 sections 2 and 5; t_run.py monitors the state at 171 events per run.
Moves with no prover message between them are one move: (x,y), beta(25), bd(5), (bc,brc)(10), (b,ba)(30), r(L, or L moves at 1/r each). Pending ai_x survives through the D and C sumchecks. State is computable in poly(2^n) from statement and transcript.
MIN_INSTANCES is not needed for interactive soundness (L=0 holds at 3492/r); it only restores statement-before-beta ordering under FS, since r is the main transcript's sole statement link.

### FACT fiat-shamir Ideal-permutation soundness of the deployed transcript, proved given 02 Theorem 1
Basis: proof in 03-fiat-shamir.md sections 5, 6 (argument, self-checked, no outside review); numbers from scratchpad/fs/bound.py.
Adaptive adversary, t queries, statement and proof chosen freely. At t = 2^128: n=7 (L=1) 2^-119.4, n=12 (L=6) 2^-123.0, n=13 (L=7) 2^-122.8. Main term t max(L,6)/p, tight. L=1 uses a separate argument (coefficient 71/p). Capacity term 2^-1262.
This is a model result. It does not cover concrete Poseidon2, or the KRS class (assumption stated in 03 section 8.4). Direct proof, since C-O Theorem 6.1 does not cover two chains.

### FACT fiat-shamir Statement collision through r gives a bound, with one real but negligible strategy at L=1
Basis: 03 section 6.3; scratchpad/fs/kernel.gp ran LLL with random (r_j, beta_j): word-difference vector in 12 relations at once with entries about 2^60.7; K = 13 leaves the 64-bit box.
Precompute honest chains for (I, F(I)) at 12 values of r, then grind S = (I, F(I) + d) with d in the common kernel. Success 12 t/p, so 2^-122 at t = 2^128, and needing 2^250 for constant probability. No such gain at L >= 2 (K/p^L per query).

### CHANGE-REQUEST fiat-shamir CR-1 MIN_INSTANCES = 4
Basis: 03 section 13. Change: verifier.rs:399, constant 2 to 4.
Class: simplifies the proof, NOT required. Removes the L=1 case and its strategy. Keys at 64 and 128 instances do not change.

### CHANGE-REQUEST fiat-shamir CR-2 Single sponge for statement and transcript
Basis: 03 section 13. Change: derive_r_var returns its sponge after squeezing r; TranscriptVar starts from it; delete the r absorb loop at verifier.rs:584-586; same natively, which needs a seeded Prover in gkr (prover.rs:32-33 constructs and absorbs itself).
Class: simplifies the proof, NOT required. Removes B2, B3, B4 and Theorem B. Bound t max(L+1,6)/p for all L >= 1: n=7 2^-123.0, n=12 2^-122.8, n=13 2^-122.6. Alters constraints, new keys.

### ANSWER poseidon2 QUESTION fiat-shamir exact algebraic target for one forgery
Basis: arithmetic and reasoning in 04 section 5; scratchpad/p2/feasible.py enumerated every first-layer skip on all deployed block position sets; transcript.py block sets, schedule cross-checked by test against the native prover count; degree growth checked only on a 31-bit toy field up to 5^6.
Best attack I can derive: fix c, restrict to a line in the hyperplane g(c) = 0, solve univariately. Degree exactly 5^65 = 2^150.9 if no degeneracy (expected, not proven at full size). Time at least 2^151 field operations and about 2^151 words of memory as usually modelled, realistically above 2^160 time. Generic grinding is t*6/p, about 2^251.4 for one success.
No round skip applies: on {1..6} a skip needs 6 conditions in 5 free offsets, on {0..5} the alignment rows are rank deficient over fixed positions, and no challenge block has more than 6 free positions (the Lemma 3.2 skip needs 0..7). Cost does not depend on sumcheck degree. Full 10-element blocks are never followed directly by a challenge; going through them costs 5^130 or more.
So the margin over 128 bits is about 23 bits (9.9 S-box layers). This is an upper bound on attack cost only: it does not establish hardness. The ideal-permutation bound in 03 is known false near t = 2^151.

### FINDING poseidon2 mu_0 = 1 outcome: no effect on trails, degree, or the forgery target
Basis: scratchpad/p2/mu0.py, weights.py (run), mi3.gp (run), reasoning. Updates my earlier FINDING on mu_0.
Trail dimensions are 15,14,...,1,0, identical for DIAG, DIAG+1 and d0=18. No invariant subspace from e0 for M^k, k<=64. M^k irreducible for all k<=100000. Toy degree exactly 5^r up to r=6. The S-box-free projection I reported is NOT special: x_i' - x_0'/mu_0 is S-box free for every mu_0.
The only measured difference: branch number of M_I is 3, against 4 for a conforming diagonal, since M_I(e0 - e_i) = -d_i e_i. The designers' statistical argument does not use M_I, and using it costs a 2^-252 S-box event. Severity: spec deviation, no known attack. Not required to fix. Absence of an attack here is not a proof.

### CORRECTION poseidon2 CLAIM t=16 BN254 is not a published instance
Basis: gnark-crypto master ecc/bn254/fr/poseidon2/poseidon2_constants.go read and compared by gnark_cmp.py (run); 2023/323 Table 1.
RF=8, RP=57 at t=16 over BN254 IS used by gnark-crypto, with the same 185 round constants as ours, and taceo-poseidon2 also lists t=16 (crate page only, values not compared). Neither is a paper parameter table entry. Our instance differs from gnark in M_I (small hand-picked DIAG against random large values), so this exact permutation is specific to Reilabs keccacheck as far as I can find, and I found no cryptanalysis of it.

### FACT implementation Reviewed source compiles to the ceremony's circuit
Basis: ran `ceremony digest` (crates/prover/src/bin/ceremony.rs, existing R1cs::digest) built from unmodified cc59207, both circuits.
native-keccacheck de23e3af..., 3,235,943 rows; erc20-keccacheck 2a689108..., 3,074,926 rows. Both equal r1cs_digest in ceremony-runs/beta-sgx-20261104-63a107c/inputs.json, and sha256(inputs.json) equals inputs_sha256 in releases/beta-20261104.json. final.vk hashes also match that release.
No diff in crates/relation, gadgets, encoding, keccacheck-arkworks between input revision 09ad94c and cc59207 (git diff). So a review of cc59207 applies to the deployed circuit. The matrices to genesis.pk step was not re-derived.

### FACT implementation Cheating prover reproduces upstream's honest proof
Basis: test honest_cheater_reproduces_upstream_proof, 2, 4, 8, 16 instances, ran.
The test-only prover (src/testkit.rs) in honest mode is element-for-element equal to gkr::keccacheck_og::prover and accepted by the circuit and by upstream's verify.
Cheating results follow in 05 once the full run ends.

### FACT implementation R1CS equals 01-spec at random points, and checks nothing else
Basis: ran soundness tests r1cs_equals_spec_at_random_points, r1cs_equals_spec_on_honest_and_cheating_transcripts, the_only_restricting_rows_are_named_checks_and_booleanity. Matrices evaluated directly, no cached LC values.
src/spec_model.rs is written from 01-spec text and shares only the upstream sponge. Each of 196 rows has residual equal to the model's left - right on uniformly random proofs and statements (2, 4, 8 instances), edge statements, and cheating transcripts. This is evidence by random evaluation, not a symbolic identity.
Forward substitution from (proof, statement bits): every other witness column is a function of them, and every row except the 196 named checks and the Booleanity rows only defines a fresh column. Production size pending.

### FACT poseidon2 Round counts and tests
Basis: rounds.py port of the reference script (not run under Sage), validated at t=3 and t=16; gnark_cmp.py; cargo test, 26 lib and 1 integration pass from a scratch mirror.
RF=8, RP=57 is the script result with margin; bare point RF=6, RP=53; 2023/323 eq. (1) gives 56. Recipe 2026/306 section 6.1 at c=6, d=1: (2,[1]), 5^63 = 2^146.3, not reachable on the deployed schedule. 2783 permutations at 64 instances, confirmed against the native prover count.
04-poseidon2.md is at docs/keccacheck-soundness/04-poseidon2.md because the harness refused a write to this directory. Coordinator needs to copy it here.

### CHANGE-REQUEST poseidon2 CR-3 DIAG + 1
Basis: 04 section 9; mi3.gp, mu0.py, weights.py (run).
Class: spec conformance, NOT required. All mu_i >= 2. 0 constraints per permutation, new keys, round constants unchanged. Needs a gkr change: shares the fork CR-2 needs, otherwise forces one alone. Independent of CR-1. Not analyzed by anyone else either.

### CHANGE-REQUEST poseidon2 CR-4 RP = 64
Basis: 04 section 9; arithmetic on the tested 555 per permutation and 2783 permutations.
Class: extra margin, NOT required. +21 constraints per permutation, +58,443 at 64 instances (3.0% of 1,957,112). Attack degree 2^150.9 to 2^167.2. New Grain constants, gkr fork shared with CR-2. RP=61 costs +33,396 for 2^160.2; RF=10 costs +267,168 for 2^155.6. Independent of CR-1; CR-2 changes the permutation count slightly.

### CLAIM poseidon2 Schedule property the cost depends on
Basis: feasible.py and transcript.py (run); reasoning for the rest.
No challenge block has free positions covering 0..6 or more. A transcript change that does this enables a round skip, cost toward 5^63. Any later schedule change should rerun those two scripts. CR-1 and CR-2 do not appear to do this (reasoned, not rerun).

### FACT implementation Premises discharged at production size in both deployed relations
Basis: ran crates/prover/tests/keccacheck_identity.rs under a genuine witness (matrices evaluated directly), plus Compiled::boolean_columns forward pass over the matrices. Digest in the same tests equals the ceremony r1cs_digest, so the result is about the deployed matrices.
Booleanity (spec P1): all witness statement bits, 717,296 erc20 and 790,512 native, are in {0,1} in every satisfying assignment, by a row-level pass (x(1-x)=0, or a column whose value is {0,1} for every Boolean choice of its row's other columns). The remaining bits are constants. Static: no new_witness_without_booleanity_check in crates/ or experiments/ (grep).
Wiring: finish runs inside both synthesizers, also under setup (digest equals synthesizer plus finish). Recorded 232 erc20, 256 native (both padded 256; native has no padding slack). Every output is a fresh witness whose bits reach verifier rows; flipping one output bit of each permutation fails a verifier row. Direct-backend call counts agree.
Also: both digests are unchanged by the enforce_named label change, so the test instrumentation did not alter the circuit.

### FACT implementation Each named check is enforced and necessary
Basis: ran soundness tests (src/soundness.rs) with src/testkit.rs, verdicts from direct matrix evaluation; upstream native verify run on the same transcripts.
Output sum, word, bit (2, 4, 8 instances), seven layer checks in all 24 rounds at 2 and five rounds at 4, all 25 input lanes: a cheating transcript over a false Keccak-f statement fails exactly that one row and upstream panics at the matching assert. Removing that check in a test build gives a fully satisfying assignment. No removal failed to give a forgery.
Round relations: no such constraint exists, p(0) is derived. A tampered polynomial fails only that sumcheck's end check. Replacing the chained claim at one round (test hook) gives a forgery, checked at each round of the output reductions and of all layers in rounds 23, 12, 0.
At 256 instances: production_batch_soundness passed for output bit reduction, round 12 chi, input lane 17; batch sizes up to 256 passed.
No forgery against the production circuit found.

### FACT implementation Differential with upstream agrees, list of differences final
Basis: ran single_element_edits_agree_with_upstream (stride 41, 2 and 4 instances), statement_edits_agree_with_upstream, section 2 table; read verifier.rs, poseidon2.rs line by line against upstream. Full list: 05-implementation.md section 8.
First failing check equals upstream's first failing assert in every case. Differences beyond derive_r: upstream ignores trailing proof elements and the circuit refuses them; short proof is a panic vs Err; upstream accepts singletons; u64 vs field bits; no early exit. No semantic divergence in the checks.

### FACT implementation Ceremony keys prove the reviewed relations
Basis: ran erc20_ceremony_key_proves_the_reviewed_relation and native_ceremony_key_proves_the_reviewed_relation in crates/prover/tests/keccacheck_identity.rs against the beta run's final.pk and final.vk; sha256 of those files and of genesis.pk match the release and inputs.json.
Fixture witness from cc59207, proof from the ceremony key, verified with its vk. Other-relation key rejected as a control. Exact re-derivation of genesis.pk from the matrices and ptau was NOT completed.

### GAP implementation No guard against dropping a KeccacheckBatch without finish
Basis: read batch.rs: no Drop guard or must_use.
A future caller who forgets finish leaves outputs free. Not reachable today: both synthesizers call it, and the digest pins catch a regression in them. No constraint change needed; advisory only.
Full report for this agent: worktree agent-a6b91512d506ae210, docs/keccacheck-soundness/05-implementation.md (the shared path refused a direct write).

### CORRECTION lead Production batch is 256 instances, not 64
Basis: implementation's run of crates/prover/tests/keccacheck_identity.rs (232 erc20, 256 native, both padded 256); lead ran scratchpad/recon/l8.py over p2/transcript.py and the formulas of 02 and 03.
03 line 9 ("records 38 permutations and pads to 64") and the 64-instance figures in 03 and 04 describe the wrong size; the 38 traces to a stale comment at crates/relation/src/lib.rs:247. Production is L=8, n=14, 10687 proof elements, 3441 permutations.
Recomputed at L=8: interactive 7932/r = 2^-240.64; FS main term at t=2^128 8t/p = 2^-122.60. Free-position sets before challenges are identical at L=6,7,8,9, max 6, none covering 0..6, so the first-layer skip enumeration in 04 still applies (script rerun; feasible.py itself takes position sets, not L).
CR-4 at 256: +72,261 constraints (21 x 3441), about 2.2% of the native relation. RP=61: +41,292. RF=10: +330,336. CR-1 still leaves the 256-instance keys unchanged (reasoned: padded size unaffected; not rebuilt).

### FACT lead 05-implementation.md copied into place
Basis: cp -n from the implementation worktree. 04 was copied the same way. Test code remains uncommitted in those two worktrees.

### FACT lead Independent review started, blind to this log
Basis: reviewers review-forgery, review-fs, review-rbr run from clean worktrees of cc59207 and write to scratchpad/review/. They are told not to read this directory. Do not message them with results from here.

### CORRECTION lead Independent review started, blind to this log
Basis: the prompts as sent.
review-forgery reads nothing in this directory. review-fs and review-rbr write a blind analysis first, then referee only 03 (review-fs) or 01 and 02 (review-rbr), with 01 and 02 available to review-fs for definitions. None reads this log. 04 and 05 are not being refereed by this round.

### GAP review-fs Statement-final block is a separate forgery target that 04 has not costed (posted by lead)
Basis: scratchpad/review/fs.md R2 (reasoned; kernels from rl.gp run); lead read derive_r_var and p2/transcript.py, whose position sets model the statement sponge with no prover-set positions.
At the r move one wrong instance j vanishes if any r_k equals the complement of j's bit k: CICO-1 on the block that yields r, no main chain needed, 8 choices of k at L=8, then the honest proof verifies. At L=8 that block has 9 absorbed elements (2 + 4267 absorbs = 4269), covering positions 0..8, so the "no block covers 0..6" property does not hold for it. Each element is limited to 192 bits, the last to 128. Cost not established. 03 line 390 "cheapest structural target is one sumcheck round" is unsupported until this is done.
Other results of review-fs: Theorems A and B correct in the ideal permutation model given 02 Theorem 1; no fatal error; CI as stated in 03 is not sparse and needs restating (R1); KRS reasons 3, 4, 5 are weak or wrong, conclusion rests on reasons 1, 2 (R3). Report: scratchpad/review/fs.md.

### CORRECTION poseidon2 GAP review-fs Statement-final block layout
Basis: stmt_block.py implements derive_r_var; stmt_replay.py with it reproduces Rust derive_r_native r_0 at L=1,2,8 (run). I read derive_r_var; 05 owns gadget equivalence.
At L=8 there are 4270 absorbs, not 4269: input and output are chunked separately, 2134 chunks each. The final block is positions 0..9 with 9 elements of 192 bits and the last of 64, holding output lane 24 of instances 228..255. The r_0..r_7 are positions 0..7 of the next permutation output. At L=1: positions 0..5, last 128 bits. At L=2: 0..9, last 64 bits.
My transcript.py merged the streams; permutation counts were unaffected (427 statement permutations, 3441 total at L=8, rerun), only the layout. Fixed.

### FACT poseidon2 Statement-final block forgery cost
Basis: 04 section 12; stmt_block.py (run) for free bits and usable k; cost model reasoned.
With other instances true, the best single element holds 3 wrong instances (192 free bits), which agree on 6 of 8 bits, so T=6 usable k. Univariate line in the box: degree 5^65, with a root in the box with probability 2^-62.
Cost: L=8 2^210.3 floor. L=1 and L=2: the algebraic route costs 2^276.9, so generic grinding at about 2^253.6 and 2^252.6 is cheaper. The beta-move variant (CICO-L plus lattice) is worse at every L, about 2^351 at L=1.

### CLAIM poseidon2 The 192-bit box defeats the skip on the statement block
Basis: reasoning, 04 section 12.2.
Positions 0..9 meet Lemma 3.2 in position terms, but skip parametrizations pin free inputs to specific field values (2^-62 each, 2^-248 for the balance alone). No box-structure route found that beats the univariate line.
The main-chain target, 2^150.9, stays the cheapest, so the 22.9-bit margin stands at L=8.
If statement elements became full field elements, this block would drop to about 2^143.7 (5^63/6). Keep the 192-bit packing, or rerun the analysis.

### FACT review-rbr 02 Theorem 1 independently re-derived and refereed (posted by lead)
Basis: scratchpad/review/rbr.md; blind count in rbr-phase1.md; identity checks on real Keccak traces, replay of native proofs at L=1,2,3, forced-challenge cheating prover, 5,600 small-field fuzz runs at p=7..101 (run). General lemmas and union bound reasoned.
Blind count equals (555n+162)/r term by term. No fatal or repairable errors; cosmetic C1-C6. C1: under 02's own move definition r and initial beta form one interactive move, (L+1)/r. Lead: this does not change 03, because under FS r comes from the statement sponge and beta from the main sponge, so they are separate queries (review-fs computed 8t/p at L=8 independently). C3: the non-Boolean statement in 8.1 should be phrased with arithmetized layers. C6: Booleanity is also what makes the 192-bit packing injective.

### FACT review-forgery Blind forgery hunt found no forgery (posted by lead)
Basis: scratchpad/review/forgery.md; tests in worktree agent-ae2a51469f1562a3f (crates/keccacheck/tests/, crates/relation/tests/forgery_relation.rs), matrices evaluated directly.
End-to-end false ERC-20 payment at 256 instances: all relation rows satisfied except exactly 1 of 3,074,926, in the batch verifier. 360 consistent wrong-function mutations (rounds 0,1,11,22,23 at 2 and 4 instances) each fail exactly one row. All 200 statement word flips rejected. No free verifier witnesses; setup and prove matrices identical. No constant-vs-constant enforce_equal calls while building either relation.
Latent: header parser fills unread bytes with constant zeros, so a future check outside its read ranges would be a silent no-op. Informational: both sponges share INITIAL_STATE with no domain tag; first absorbs differ.

### FACT lead Change-request disposition
Basis: all five deliverables and three reviews.
CR-1 adopt (no key change at 256 expected; being verified by digest). CR-2 decline: the two-chain proof was refereed and holds, CR-2 gives 2^-122.4 vs 2^-122.6, and it changes statement absorption, which 04 section 12 depends on. CR-3 decline: no attack found from mu_0 = 1, and the replacement matrix is equally unanalysed. CR-4 decline for beta: deployed RF/RP are the reference-script values; the margin question goes to external cryptanalysts. Revisit CR-3/CR-4 together if external review asks for either.

### FACT protocol 01 and 02 revised for referee review-rbr C1-C6 and CR-1
Basis: edits to 01-spec.md and 02-interactive-soundness.md (both now have a Review history section naming scratchpad/review/rbr.md); arithmetic rechecked by script.
No bound changed; agree with all six items. Primary result now n=14 (L=8): 7932/r = 2^-240.64; min reachable n=8: 4602/r = 2^-241.43.
C1: move = one squeeze run of one sponge; r block L/r, beta 1/r separate; largest single move max(6,L)/r, 8/r = 2^-250.60 at L=8 ((L+1)/r only under the maximal-run definition, which 02 now explains and does not use).
C2: d/r per round is attained by a cheater, not by the honest poly (iota instance rounds have honest degree 2). C3: non-Boolean in proves word equality to the arithmetized map, via (1-2a)(1-2b) = 1-2xor(a,b) for all field a,b. C4: T3/T5/T6 fold into the next challenge move. C6: Booleanity also gives 192-bit packing injectivity, cross-referenced for 03.
MIN_INSTANCES = 4 stated as deployed (2 at cc59207). L=0 and L=1 results kept as facts, marked unreachable.

### FACT lead CR-1 applied, production digests unchanged
Basis: edit to crates/keccacheck/src/verifier.rs (MIN_INSTANCES 4, derive_r asserts, proof-length test list), uncommitted; crate lib tests 15 passed; `ceremony digest` rebuilt both circuits.
native-keccacheck de23e3af... and erc20-keccacheck 2a689108..., equal to the beta ceremony's r1cs_digest. The beta keys remain valid under CR-1.

### FACT fiat-shamir 03 revised for review-fs and review-rbr C1
Basis: 03-fiat-shamir.md revision 2 (Review history at top); scratchpad/fs/l8.py (run) for L=8 counts and K(t).
Production row is L=8 everywhere: Q_V=3441, bound 8t/p = 2^-122.6, dominant term the r move. "38 recorded, pads to 64" removed.
R1: CI restated for the composed two-sponge function with S in the input, plus multi-target term 2^128 K_L/p^L. R2: first move split into r-move and beta-move targets; costs cited from 04 section 12 (2^210.3 at L=8, conditional on 192-bit packing and Booleanity); "cheapest target is a sumcheck round" now rests on 04 sections 5 and 12. R3: KRS reason 3 scoped to r, 4 and 5 withdrawn; conclusion rests on 1 and 2, with 2 marked informal. R4: L=1 uses K(t) (52 at 2^128, 57 at 2^140).
C1-C8 applied; L=1 coefficient 71 -> 70. Section 4 says why FS splits r and beta (separate queries; 02 has a state after r). Section 13: CR-1 adopted, CR-2 declined and kept as analysed alternative (9t/p vs 8t/p at L=8).
Not adopted: referee's 23 t/p for L=1 (C7) as a lower bound, since it is a first-moment heuristic; recorded as such. No disagreement with any error the referee called repairable.

### FACT lead Consolidated into the main tree
Basis: worktree diffs applied to the main checkout (uncommitted); scratch scripts and referee reports copied.
Paths in entries above that say scratchpad/<dir>/ now live in docs/keccacheck-soundness: p2 -> scripts/poseidon2, fs -> scripts/fiat-shamir, protocol -> scripts/protocol, recon -> scripts/lead, review/*.md -> reviews/, review scripts -> scripts/review-rbr and scripts/review-fs. Paper texts are not kept. Rust tests moved from 2 instances to 4 (and 4 to 8) under CR-1.

### FACT lead Consolidated test run after CR-1
Basis: release builds in the main checkout, 2026-11-07.
keccacheck-arkworks lib: 68 passed, 5 ignored (6 tests fixed for 2-instance leftovers, then the full lib rerun); --ignored: 5 passed. Integration tests: all pass except `alternate_functions_with_consistent_proofs`, which panics in the upstream prover's own self-check on inconsistent layers (needs scripts/forgery/gkr-no-asserts.patch, as the reviewer ran it). It is now `#[ignore]`. With the patch, at 4 instances: 180 of 180 cases are rejected, each with exactly 1 unsatisfied row. The reviewer's 360 included 2 instances, which MIN_INSTANCES now forbids.
prover keccacheck_identity --ignored with the beta-sgx-20261104-63a107c run: 12 passed. relation forgery_relation: 5 passed (no ignored tests).
