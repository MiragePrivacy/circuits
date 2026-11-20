# Referee report: round-by-round soundness of interactive Keccacheck

Reviewed: `docs/keccacheck-soundness/01-spec.md` and `02-interactive-soundness.md` against `crates/keccacheck/src/verifier.rs`
at cc59207, upstream `keccacheck_og` and `sumcheck/*` at 15f00e3, and paper 2025/1764.
My blind analysis is `review/rbr-phase1.md`, sha256 4a52c56a...e418e6, unchanged after the docs were opened.
Scripts are in this directory: `model.py`, `p1_identities.py`, `p1_nonbool.py`, `p2_attacks.py`, `p2_fuzz.py`, `p2_replay.py`, `dump/`, `test.sh`, `fuzz.sh`.
Logs: `fuzz-p*.log`, `rust-tests.log`.

## Verdict

Theorem 1 of 02, Pr[accept] <= (555n + 162)/r for a fixed false Boolean statement with uniform independent challenges, is correct.
I found no fatal or repairable error in the interactive argument. The state function of section 5 is right where naive versions fail:
- At the iota opening it uses the weighted pair (beta_0 d0, d1).
- It carries AI-false through the theta D and theta C sumchecks.
- It makes failed checks sticky.

Every transition T1-T14 survived both a direct attempt to break it and a small-field fuzz in which the degenerate cases occur at rate about 1/p.
Remaining findings are cosmetic: wording, scope and an inconsistent definition. None of them changes the bound.

## Findings

### Cosmetic

C1. **"Move" definition contradicts the move table.** 02 section 2 defines a move as "a maximal run of verifier challenges with no prover message in between".
Under that definition r_1..r_L and the 25 initial beta are one move, since the prover sends nothing between them, with error (L+1)/r.
- The table instead lists L single-coordinate r moves and a separate beta move.
- Section 1 then says "Maximum error of any single move is 6/r ... treating each coordinate of r as one move", and gives the r block as L/r.

The interactive sum is unaffected. The per-move maximum is what a Fiat-Shamir transfer would use: under the stated definition it is max(6, L+1)/r, which is 9/r at L = 8, not 8/r or 6/r.
In the deployed transcript r comes from a separate sponge, and r_1..r_L are squeezed from one permutation when L <= 10.
- Repair: define a move as one squeeze run of one sponge. That gives r-block L/r and beta 1/r.
- Alternatively, state that the table splits a maximal run for accounting only.

C2. **Lemma 7 "the bound is tight: all top coefficients were nonzero".** This holds per sumcheck type but not per round.
In the iota sumcheck the first L rounds (instance variables) have honest degree 2, because RC~ is constant in them.
Run F6 (p2_attacks.py) gives honest iota round degrees [2, 3, 3, 3, 3, 3, 3] at L = 1. The error 3/r per round still stands, because V reads 3 coefficients, so p - g can have degree 3.
I realized d escapes at d distinct roots for every type (run E), so the read-degree bound is attained.
- Repair: replace "tight" with "attained by a cheating prover, since V reads d coefficients".

C3. **8.1 "All of Lemmas 5-7 and T1-T14 hold for it as written" (non-Boolean `in`) overstates.**
- T1 at m = 0 uses Lemma 1 and Lemma 8, both of which need Boolean values.
- Spec section 5 and Lemma 6 define the layers and their hat identities only "for Boolean inputs".

The conclusion is true once restated:
1. Define the layers by the field formulas.
2. Note that (1-2a)(1-2b) = 1 - 2 xor(a,b) holds for all field values, so C^ and theta^ products agree with iterated xor.
3. Take the start condition "W != Wt as field tables".

The relation then proved is words(R~^24(in)) = words(out), where R~ is the arithmetized round. That is word equality, not the "different function" on bits.
Verified by running: non-Boolean `in` with the arithmetic image is accepted (A, F1). A false word statement on non-Boolean `in` is rejected under a maximal lie (F2) and accepted only at an RLC root (F3).
- Repair: one sentence each for the field-formula definition, the hat identity, and the word-level relation.

C4. **Positions in T3, T5, T6 (02 section 6).** These say "no challenge", but the next position in the section 5 table ends at a challenge.
The real transition is (opening, first round polynomial of the next sumcheck) followed by its challenge. The proof composes them correctly (doom passes deterministically, then Lemma 5 applies), but the table has no "bit SC after 0 rounds" position.
- Repair: say explicitly that these openings fold into the next challenge move.

C5. **Section 1 table omits n = 14.** At L = 8 the bound is 7932/r, about 2^-240.64. Not an error.

C6. **Scope of Booleanity outside the interactive argument.** 8.1 says output Booleanity is used only by T1. That is right for the interactive protocol.
Under Fiat-Shamir both `in` and `out` Booleanity are also needed for the statement packing (sum 2^k bit_k over 192 bits) to be injective.
The packing note is in 01 section 3. 8.1 could cross-reference it so 03 does not miss it.

01 section 8 item 2 ("Added upstream in 557faf4") was not checked; it has no effect on soundness.

### No fatal or repairable errors

Targeted attempts and their outcomes are under "Tests" below.

## Count: mine against theirs

Phase 1 (blind): output part 3L + 13 = 3n - 5. Rounds: 24(23n + 6) + 23 = 552n + 167. Total **(555n + 162)/r**.
02 section 7: 552n + 3L + 180 = **(555n + 162)/r**.

They are identical term by term:
- r: L.
- Initial beta: 1.
- Word SC: 2L.
- Bit SC: 12.
- Main sumchecks: 24 x 23n.
- In-round RLC moves: 6 x 24, namely (x,y), beta_rho, beta_theta, bd, (bc,brc), (b,ba).
- Between-round RLCs: 23. There is none after round 0, because the final check is lane by lane.

Difference from the paper's (168 + 553n)/r is 2n - 6:
- The paper charges n for alpha. The code charges L for r plus 2L + 12 for the word and bit sumchecks.
- The paper charges 168 RLCs. The code has 1 + 167.

| n | L | numerator | log2 Pr |
|---|---|---|---|
| 7 | 1 | 4047 | -241.61 |
| 12 | 6 | 6822 | -240.86 |
| 13 | 7 | 7377 | -240.75 |
| 14 | 8 | 7932 | -240.64 |

The per-round bound cannot be tightened by the honest degree, because V reads d coefficients every round. Only the iota instance rounds have lower honest degree (C2).

## Steps checked hardest

1. **T7, the iota opening and (x,y) reuse with beta_0 scaling.** I derived independently in Phase 1 that the unweighted "chi_00 false means doomed" fails with probability 1 conditional on beta_0 = 0. 02 uses the weighted pair.
   Runs:
   - Phase 1 D: beta_0 = 0 with chi_00 lied is accepted; the naive state function disagrees at exactly that state.
   - C6: lane 0 the only false lane, with beta_0 = 0, exits at beta_next, which is charged.
   - C7: doomed with beta_0 = 0 and uniform (x,y) stays doomed. y = 0 exits at (x,y). x = 0 has no effect, as predicted.
   - C4, C5: RC~(v1) = 1/2 makes the iota check blind to chi_00. The state stays doomed and the run rejects. x = 0 then erases the lie, as predicted.
   - Fuzz: the (x,y) form vanishes on exactly p of p^2 pairs, checked exhaustively on 1,554 forms.
2. **Pending AI-false (T10-T12).**
   - D1: ai_0 and ai_1 lied with zero net effect on the theta check. Doom holds at all 16 positions of the D and C sumchecks. Rejected.
   - D2: exit only at a (b,ba) root.
   - D3: a theta-beta column all zero (true ai = 0) with ai_0 = 7 claimed. Rejected.
   - D4: ai and d both false with a bd root. Still doomed through AI-false, as T10 says.
   - D5: exits only at (b,ba).
   - D6: v4 = v6 forced. Honest accepted, liar rejected.
3. **Zero factors at openings (eq, rot, pow, RC = 1/2).**
   - C1: eq(alpha,v1) = 0 on a true statement with a lie. Doomed, rejected.
   - C2: eq = 0 while doomed with ve != 0. The check fails immediately (T5 argument).
   - C3: the prover makes p - G vanish at the eq root. That escape is an ordinary sumcheck root, charged to the round.
   - C8: rot = 0 for a lane with theta lied. Doomed, rejected.
4. **Claim true by accident.** Forced escapes at every one of the 18 move types plus an extra sumcheck round (B). Each makes a false statement accept, and the state flips at exactly that move and nowhere else.
5. **Sumcheck encoding (Lemma 4).** Exhaustive over F_p in the fuzz. In more than 60,000 doomed rounds the number of escaping challenges never exceeded the read degree, and every degree was attained.

## Spec (01) against code

I checked every protocol line and verifier.rs line citation in 01 and 02, every paper line citation in 01 section 8, and the batch.rs references. They all match.

The spec's simplifications are faithful:
- Coordinate order is instance first, MSB first.
- rot_from_eq with 64-entry suffix tables.
- strip_pi map; derived p0; in-place beta mutations.
- Separate statement sponge; proof length 6255 + 554L.
- Squeeze counts.

FIPS 202 constants were regenerated independently (LFSR, rho walk, pi map) and compared with the code's; my Keccak-f matches hashlib SHA3-256.
The paper typo noted in 01 section 8 item 8 is real.

Strongest evidence: I wrote my own verifier port and my own Poseidon2 sponge from poseidon2.rs. Real native-prover proofs from the pinned gkr crate (L = 1, 2, 3, generated in `dump/`) replay through them with the real Fiat-Shamir challenges:
- Accepted, with the proof consumed exactly and the state undoomed throughout.
- The same proofs satisfy the R1CS gadget.
- 6 random single-element tampers per L are rejected.

The crate's own 12 verifier and batch tests pass on a byte-identical copy of `src`.

## Booleanity

Verifier conditions supply none. Run B / F4 shows Boolean `in` with non-Boolean output bits of equal word value accepted. Run A / F1 shows non-Boolean `in` accepted against its arithmetic image.

Booleanity comes from the `Boolean<Fr>` type:
- `Boolean::new_witness` enforces (1 - a) a = 0 (ark-r1cs-std 0.6.0 allocated.rs:219-223).
- Constants are exact.
- `new_witness_without_booleanity_check` and `AllocatedBool` are not used in `crates/` or `experiments/` (grep).

02 section 8.1 is correct here apart from C3 and C6.

## Verified by running vs by reasoning

Running:
- Identities I1-I9 at random points on real traces.
- Per-type degrees and their attainment.
- Constants against FIPS 202.
- Honest 24-round acceptance at h = 2 and 4.
- Real-proof replay with the real FS schedule, L = 1-3.
- Rust tests.
- All attacks A-F.
- Fuzz of 5,600 runs at p = 7, 11, 13, 31, 101, h in {2, 4} (h = 2 only at p = 101), 1-3 rounds. Some statements were non-Boolean. Assertions:
  - Accept implies undoomed.
  - Reject at the input lanes implies doomed after the final openings.
  - No escape at the openings, which have no challenge.
  - Exact per-round root counts are at most d.
  - Exact (x,y) counts equal p.
  - Degenerate events (eq = 0, rot = 0, pow = 0, RC = 1/2, beta_0 = 0, x = 0, y = 0, b_x = 0) hit many times in doomed states.

Reasoning only:
- The general proofs of Lemmas 2-5 and the union bound.
- The claim that the BN254 model equals the R1CS gadget for adversarial proofs. The replay covers honest proofs and tampers only. The gadget code was read line by line against upstream.

## Not proven here

- Fiat-Shamir and Poseidon2: whether derived challenges behave as uniform with the statement fixed first (03, 04). Per-query errors are as in C1.
- That the R1CS constraints implement exactly this verifier for every witness, not just honest ones (05).
- Booleanity of caller-owned input states in Mirage's sponge integration, and that every recorded permutation reaches `finish` (05).
