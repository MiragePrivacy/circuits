# Referee report: docs/keccacheck-soundness/03-fiat-shamir.md (at cc59207)

Blind analysis: review/fs-phase1.md, unedited since Phase 2 began
(sha256 2f25ccf33c9722003337480f6b33d51bb510726ffb94849d9891fd60641b382b).
Scripts: review/fs_scripts/{nums1.py,nums2.py,sched.py,toy.py,rl.gp}. I did not read scratchpad/fs/, NOTES.md
or other documents in that directory, except excerpts of 02 (sections 5, 6 start, 7, and grep hits in 8 and 11).

## Verdict

Theorems A and B (sections 5, 6) are correct in the ideal permutation model, given 02 Theorem 1. No fatal
error. My blind bound has the same form and agrees to within 0.15 bit at L=1 and exactly at L>=2. Section 7.3 (the
C-O theorem does not apply) is also correct.

The errors are outside the two theorems, and the most serious are in section 8: the stated CI assumption is
not sparse as claimed, and three of the five "why KRS does not apply" reasons are wrong or weaker than claimed. The
conclusion that the KRS theorems do not apply survives, because line 380 rests it on reasons 1 and 2.

## Errors

### Fatal
None.

### Repairable

**R1. Line 385-388, assumption CI: R_L is not sparse.** "(s,s') in R_L if s, with some statement S, parses as a
position with a doomed prefix". A main-chain input contains no S. At a main root, the challenge output is
beta(x), and for every beta there is a false S with sum_i beta_i delta_i(x)=0, as section 9 line 426 itself says.
So "density at most e_max at each input" (line 388) is false: density is 1 at every main root.
- If "parses" does not require r=H(S), the assumption is plainly false: any root query plus LLL gives an element of R_L in
  polynomial time. rl.gp did this at L=8 for 20 random (r,beta), using 40 words, largest |d| 2^6.5.
- If it requires r=H(S), elements are hard to find, but the relation still has density about 1, so it is not in the sparse
  class the text compares it to.
- Separately, "about 2^128 e_max" fails at L=1: e_max=6/p and section 6.3's own polynomial-time strategy gets 12t/p.
Repair: state CI for the composed function, with S in the input. g_L(S,tau,a) := the challenges from running the statement
chain on S and the main chain on (r(S),tau,a). Target: no 2^128-work algorithm finds (S,tau,a) with doomed (S,tau) and an
escape, except with probability about 2^128 e_max, plus the K/p^L multi-target term. Density is then e(move) per input.
Note this is CI for a two-sponge composition, not a relation on single P calls. Doesn't affect Theorems A, B.

**R2. Lines 372 and 376, section 8.3, first move: "fixed-point condition on H alone" is wrong for two chains.** It
contradicts section 6.1. beta depends on r only, so nothing is circular: fix r*, compute beta(r*), solve for
delta by LLL, then the remaining task is a targeted partial preimage H(I,F(I)+delta)=r* with delta in a coset of a lattice box.
Also F gives a little more than "a fixed offset" suggests: Keccak-f is invertible, so F(I) can be chosen as data once
beta(r*) is known, which partly meets KRS requirement (c) (line 347) at this one move. It gains nothing over free delta.
Consequence for line 390 "the cheapest structural target is one sumcheck round": unsupported. Competing targets, both
CICO on the statement-final block (up to 10 free elements, each <2^192):
- r move, any L: single wrong instance j, target r_k = complement of j's bit k for any k. CICO-1, 8 choices of k at L=8.
  No main chain needed. Then the honest proof verifies.
- beta move: CICO-L plus the lattice constraint. Comparable at L=1, much harder at L=8.
Repair: replace the fixed-point sentence with this two-stage statement, and ask 04 to cost both targets alongside the sumcheck one.

**R3. Line 364 (reason 4) is wrong; lines 362 and 366 (reasons 3, 5) are weaker than claimed.**
- Reason 4 says full absorption of the statement removes the digest trick. Two faults. (a) KRS is not blocked by absorbing
  the input in the clear: Construction 2 step 3 computes r = h(psi, x, y*, alpha) inside the circuit with x public. The digest
  they feed in stands for the circuit, not the input. (b) In the main chain r IS a short digest standing for S, and the tree can
  precede S, as section 6.1 says. Repair: delete it, or restrict to "no witness or commitment exists".
- Reason 3 is sound for r, but says nothing about beta and inner challenges. Those depend on r and prover messages, not on
  3200*2^L bits, and r fits in one instance's 1600 bits at L<=6. KRS Theorem 2 attacks an inner challenge. Only reason 2
  (Keccak-f cannot run the hash) covers these. Repair: scope to r.
- Reason 5 is a single-lane statement at L=1. The relevant form is 25*2^L word variables under sum beta_i delta_i(r)=0,
  with solutions of size 2^10 or smaller for every (r,beta), so words impose no barrier at the beta move. At L>=2 even the
  all-lanes route reaches r_k in {0,1}. Inner-layer fakes are unrestricted field values. Repair: drop it as a barrier.

**R4. Line 17: the L=1 formula is stated for all t, but its constants hold only at about t<=2^128.** With K=52 the first term is
2^-222 at t=2^128, 2^-118 at 2^130, 2^-14 at 2^132, 2^+38 at 2^133 (nums2.py). At 2^140, K=57 is needed, so 71 is also
t-specific. Line 230 is right. Repair: say "for t<=2^128" on line 17, or cite line 230 with K a function of t.

### Cosmetic

C1. Lines 8-9, 19, 21-25, 436-442, 492 use L=6 as deployed. Production is L=8 (see below).

C2. Line 185 "lookahead blocks are never statement-final" is false, at L=6. Root x=(tag,2^L,0..) with all-zero prover messages
makes the main path identical to the statement chain of false S=(0,0), and sched.py shows main depth D_S=107 is a lookahead
at L=6. This is not B4: that root is not r(S) for any S. At L=8 depth 427 is a move-first block, so the sentence happens to
hold. The count survives: a path has one depth D_S, D_S is not depth of q0, so each non-lookahead query gives at most one
statement-final query, and the Break charge is still at most one per non-lookahead query, since q0's tree is not T_r(S').
Repair: replace the sentence with this argument.

C3. Line 302 "exactly the same sequence": true for all deployed calls (replayed L=1,2,6,8), except that Construction 4.3's
verifier also absorbs and squeezes at round k, one extra call after the last message. Deployed ends idx=6, dirty. Harmless.

C4. Line 318 fixed capacity: conjugation is valid for one instance only. With distinct instances, all mapped to IV_c, h is not a
random function. The table reads as if general. Harmless, since 7.3 and the direct proof cover the rest.

C5. Lines 58-59 "in every sumcheck round ... slots 1..d" is false for the first round of each sumcheck: after a 25-batch it
starts at slot 5, after a 10- or 30-batch the absorb wraps with a permutation and uses slot 0.

C6. Line 261 pigeonhole gives d as a difference of two box vectors, not F(I)+d in the box. Repair: choose I by inverting
Keccak-f so that F(I) words are near 2^63; half-width 2^63 gives 3150 bits, 12.42 >= 12 relations.

C7. Lines 259-265: strategy is weaker than the optimum. Prebuilt chains are not needed: only beta (3 calls per root); the honest
chain is computed after the hit. Choosing d after seeing many roots gives by first-moment count about 23 t/p = 2^-121.1
for an unbounded adversary (heuristic, not second-moment proved). "Between 12 t/p and 71 t/p" remains true; the gap narrows
if this holds. Toy: 300 random forms over q=8191 had a d in two kernels where pigeonhole on a fixed list allows one.

C8. Formal phrasing. Line 247: Pr[r(S) in N(S)] is implicitly on the query-time event |N(S)|<=K+1, while E_K is end-of-game; state
it as Pr[E_K] + sum_q Pr[hit and |N|<=K+1]. Same at line 250 for the 4-collision. Line 194 must be read as "r=r(S) for S final
before q". Trees in step 1 need "no B1 so far". K+1 could be K, so 70. None changes a bound.

## Hostile checks that passed

- Lemma 3: induction, inverse edges, order, B1 count (2j forbidden values including IV_c and own side). T(T+1)<=11t'^2 with T<=3t'.
- Exhaustiveness in section 5: no bad event and no Break implies rejection. Each q is fresh, its message fixed by input and
  ancestors. An early child would hit B1. Same in section 6: Step 2 and Step 3 split on whether the first escape edge is before or
  after S's final query, and no case is left out. Matches my EARLY and LATE.
- Conditioning. Every set used is fixed before the answer it is tested against: N(S), statements sharing r, the Break prefix. The 2^6400 union
  is over a fixed universe, not a set chosen after the randomness. Chain rule on fixed index sets holds because R2 holds for any tau.
- Double counting. At L=1 a query can serve up to 3 false statements, and is charged 3e. Statement-final and main tree are disjoint for
  T_r(S) at L>=2 (B4), and at L=1 by slot 1. Lookahead overlap: C2.
- Lookahead: blocks are fresh under not B1, and at most 3 calls per move (replayed). My own proof was weaker here, see below.
- 02's Doom after r and beta is defined for any r, so R2 at adversarial roots is fine. This was an assumption in my Phase 1.
- 7.2 full-rate codec: valid. 7.3: valid. Quoted text of C-O (Remark 2.1, Lemma 5.1 numerator, Construction 3.3) and KRS (Construction 1,
  Theorems 1, 2, 9, 10, Proposition 7, Definition 6, Remark 3, section 5) checked against the papers. Line refs spot-checked.

## Bound comparison at t=2^128

| L | theirs | mine | difference |
|---|---|---|---|
| 1 | 71 t'/p + 2^-222 + 2^-253, total 2^-119.4 | 64 t/p + 2^-125.8 + 2^-128, total 2^-119.6 | they allow 3 sharing r (18), I allow 2 (12) and pay 2^-125.8; K=52 vs m=51 |
| 2 | 6t'/p, 2^-123.0 | same | |
| 6 | 6t'/p, 2^-123.0 | not computed blind; same formula | |
| 8 | not tabulated; formula gives 8t'/p, 2^-122.6 | 8t/p, 2^-122.6 | none |

Both have CAP: theirs 11 t'^2/p^6, mine T^2/p^6, each about 2^-1262 to 2^-1266. EARLY at L>=2 is t'^2/p^L in both.
They add t'/p^2 for B4; I showed that it is avoidable by charging dual queries twice, though my table excluded it the same way.

Corrections to my Phase 1, none favouring it:
- Section 1 (c), (d), (e): I listed no h, additive absorb and index handling as mismatches, and said additive is "not a fixed codec". The
  full-rate IP* moves the state dependence into IP*'s verifier, and this works: I replayed it. Only (a), (b), the two chains, block the
  theorem, as line 326 says.
- My flip per query relied on the black box for moves spanning several blocks. Their lookahead handles it explicitly. Theirs is better.
- I did not state L<=10.

The two analyses are not independent of 02: both take the same black box.

## L=8

Nothing in the argument changes beyond arithmetic. Theorem A's range covers it, r fits one block (8<=10, slots 8, 9 zero).
Absorbs 4270, D_S=427, main 3014 calls, Q_V=3441 (above line 19's 3059), proof 10687. Table row: 8t/p=2^-122.6, 11t'^2/p^6=2^-1262,
t^2/p^8=2^-1773, t/p^2=2^-379. Section 6.3 K=1615, K/p^8 per query. CR-2 gives 9t/p=2^-122.4.
Qualitatively: from L>=7 the dominant term is the r move, not degree-6 sumcheck, so the tight ideal-model attack is statement grinding
needing no main chain, which matters for targeting 04 (R2). CR-1 is irrelevant here.

## What was run and what was reasoned

Run:
- sched.py: my own transcription of verify_allocated. Proof length 6255+554L at L=1,2,6,7,8; D_S and main calls match lines 67, 70, 436 at L=1,6,7;
  spans 3 for 25 and 30, else 1; overlap at each L (C2); DSFS full-rate replay at L=1,2,6,8 with a SHA-based toy function. Schedule logic only: no
  Poseidon2, not the R1CS.
- nums1.py, nums2.py: every figure in sections 0, 4, 6, 9, 10, 13 that I recomputed agrees (K=51 and 52, 2^-253, 2^-119.45, 2^-122.79, 2^-112.9, 2^-240.9, 2^-1262).
- toy.py, q=8191 lazy permutation with inverses, first move only. 6.3 strategy win rate per 150 draws, 1500 trials: K=1 0.0200 (predicted 0.0181), K=2 0.0407
  (0.0360), K=3 0.0500 (0.0535), within noise, sd about 0.004. 960 same-r pairs: 0 pass the sum check, expected 0.12. r-move: L=1,3,8 at q=251 rate matches L/q. Lemma 3: 19999 B1-free
  runs, 0 violations (a smoke test only: random queries rarely stress it).
- rl.gp: kernel at L=8 for random (r,beta), real p, supporting R1.

Reasoned only: Lemma 3, Theorems A and B, every grade above, KRS analysis, C7's 23 t/p estimate.

## Unproven

- 02 Theorem 1 (black box here), including T-level per-move errors.
- Poseidon2 as ideal permutation, and CI in any form (R1), which no result here implies.
- The composition with Groth16 and R1CS equivalence to V (05), Booleanity of bits.
- No KRS-class attack on this fixed circuit. Reason 2's "Keccak-f cannot run the hash" is an informal claim, and KRS section 5 calls this class of countermeasure open.
- Exact L=1 constant: between 12 t/p (polynomial time) and 71 t/p; 23 t/p heuristic for unbounded adversaries. Immaterial at L=8.
- The theorem is still self-checked plus this one review; no machine checking of sections 5, 6, 7.
