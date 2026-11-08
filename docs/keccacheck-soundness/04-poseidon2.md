# 04: Poseidon2 instantiation analysis

Width-16 Poseidon2 over BN254 Fr as used by the Keccacheck transcript. Code: PR 3 at cc59207,
experiments/keccacheck-arkworks/src/poseidon2.rs, and pinned upstream gkr 15f00e3.
Scripts are in scripts/poseidon2/ (named below by file).

Strength labels: RUN means a script or test was executed. READ means code or a paper was read.
REASONED means my own argument, with no outside review. CITED means a paper's claim that I did not reproduce.

## 1. Summary

- **Round counts.** RF=8, RP=57 is what the reference formula gives for t=16 at 128 bits, including its margin
  (RUN, port of the script). Without margin the script gives RF=6, RP=53. Eq. (1) of 2023/323 gives RP=56.
- **Best attack derived on the deployed transcript.** One forgery reduces to CICO-1 with a linear side condition. Best
  cost found: univariate degree 5^65 = 2^150.9, so at least 2^151 field operations, realistically 2^160 to 2^170.
  Generic grinding costs about 2^251. No round skip applies to any deployed challenge block (RUN for the first S-box
  layer, REASONED for the wider attack class).
- **Ideal sponge recipe.** The 2026/306 section 6.1 recipe at (t=16, c=6, d=1) gives ((2,0),[1]) and 5^63 = 2^146.3.
  The deployed schedule does not reach it, because no block before a challenge has more than 6 free positions.
- **mu_0 = 1.** A spec deviation. No effect on trails, degree or the forgery target. One measured difference: the branch
  number of M_I is 3, not 4. No known attack uses it.
- **Instance status.** RF, RP and the round constants match gnark-crypto's t=16 instance. M_I does not. I found no
  cryptanalysis of this exact permutation, and no paper table lists t=16 over a 254-bit field.
- **What this is not.** It is not a proof. It gives upper bounds on attack cost from known techniques. The assumption in
  section 7 stays an assumption. No change is required by any attack found. CR-3 and CR-4 (section 9) are optional.

## 2. Parameters as implemented

| item | value | check |
|---|---|---|
| p | BN254 Fr, 254 bits, log2 p = 253.597 | RUN, field_and_round_counts_are_pinned |
| gcd(5, p-1) | 1 (gcd(3, p-1) = 3, so 5 is the smallest valid alpha) | RUN, rounds.py and the same test |
| t, rate, capacity | 16, 10, 6 | READ, pinned by test |
| RF, RP | 8 (4+4), 57 | RUN, pinned by test |
| S-boxes per permutation | 8*16 + 57 = 185 | RUN |
| constraints per permutation | 555 on a witness state | RUN, permutation_costs_555_constraints_on_witness_state |
| round constants | Grain(n=254, t=16, RF=8, RP=57), all 185 | RUN, round_constants_regenerate_from_grain, independent of grain.py |

## 3. Round counts

Conditions implemented in rounds.py, as a port of sat_inequiv_alpha and find_FD_round_numbers from HorizenLabs
poseidon2_rust_params.sage at bb476b9, including its binomial term from 2023/537. I read the script before porting it. I
did not run it under Sage. The port was validated by reproducing two published results: (8,56) at t=3, which matches
2023/323 Table 1, and (8,57) at t=16, which matches gnark-crypto.

Results for (BN254, t=16, alpha=5, kappa=128):

| source | RF | RP |
|---|---|---|
| Script, no margin | 6 | 53 |
| Script, with margin (RF+2, RP*1.075 rounded up) | 8 | 57 |
| 2023/323 eq. (1), RF=8 fixed: 1.075 * max(51.85, 49.13, 12.24, ...) | 8 | 56 |
| gnark-crypto t=16 constants | 8 | 57 |

Terms at (RF, RP) = (6, 53), the bare point the margin is applied to:

| term | required RF | note |
|---|---|---|
| statistical | 6 | see below |
| interpolation | 6 | binding: 1 + ceil(log5(2)*128) + ceil(log5(16)) - 53 |
| Groebner 1 | 2.13 | |
| Groebner 2 | below 0 | |
| Groebner 3 | below 0 | |
| 2023/537 cost | 384 bits, at least 128 | |

At the deployed (8, 57) the 2023/537 cost is 455 bits. The script's conditions hold at (8, 57) up to kappa = 143.

The difference between 56 and 57 comes from the script's ceilings and from applying the margin to its integer RP. The
deployed value meets both. RP=57 is therefore what the formula gives, and its margin is exactly the designed one: 2 full
rounds and 4 partial rounds above the bare point.

Later corrections checked:
- 2025/954 revises the subspace-trail Groebner analysis. For p near 2^256 and d=1 it reports that univariate solving stays
  the best attack, and its Table 3 needs only RP=14 at t=16 for the trail-based Groebner model (CITED). Not binding here.
- 2023/537 is included above. 2025/2040 bounds CICO-k ideal degree by alpha^(k RF + RP), which at k=1 is the same 5^65 used
  in section 5 (CITED).
- 2026/306 did not change the Poseidon2 formula. It reports that the Poseidon2b RF was raised after its disclosure, and
  2026/1905 gives that as RF=10 (CITED). That is the binary-field design, not this one.

Statistical attacks: M4 is MDS (RUN, m4_is_mds). The paper gives branch number t/4 + 4 = 8 for M_E. I confirmed a weight 8
witness numerically (RUN, demo.py), not that no lower one exists. Three pairs of external rounds force at least 24 active
S-boxes, each with DP at most 4/p, so about 2^-6000. Margin here is very large and not the concern.

## 4. Linear layers

### 4.1 Extraction

Matrices were read from their action on basis vectors in Rust (RUN, external_matrix_is_two_circulant_tensor_m4,
internal_matrix_is_ones_plus_pinned_diagonal) and in Python on the upstream form (RUN, demo.py).

- M_E = circ(2 M4, M4, M4, M4) with M4 = [5 7 1 3; 4 6 1 1; 1 3 5 7; 1 1 4 6]. This matches the reference script.
- M_I = J + diag(0,1,2,3,4,5,6,7,8,9,10,11,13,14,16,17). So mu_i = d_i + 1 and mu_0 = 1.
- An initial M_E is applied before the first round (RUN, initial_linear_layer_and_round_order_are_as_modelled).
- Partial rounds add one constant to position 0, as in 2023/323 section 6.
- The full permutation matches the upstream test vector at inputs 0..15 (RUN). That vector is hard-coded upstream with a
  comment attributing it to the reference script. It cannot have come from a default script run, since the script draws a
  random diagonal. I treat it as an upstream regression vector, not outside confirmation of M_I.

### 4.2 Conditions on M_I

| check | result | how |
|---|---|---|
| Invertible | yes, det = 1976041267200 | RUN, mi2.gp |
| Charpoly irreducible | yes | RUN, mi2.gp |
| M_I^k irreducible | all k <= 100000 | RUN, mi3.gp (order test on lambda^(p^8-1)) |
| Direct charpoly check | k <= 64 | RUN, mi2.gp |
| Reference Algorithm 2 style test (invariant subspace from e0) on M_I^k | passes, k <= 64 = 4t | RUN, mu0.py; Algorithm 2 only, s=1 |
| Inactive S-box subspace dimension after i rounds | 15,14,...,1,0 | RUN, mu0.py |
| Krylov rank of e0 M^j | 16 | RUN, Rust test and demo.py |

Irreducibility for all relevant powers implies no eigenvalue in Fp for those powers, so the eigenspace part of Algorithm 1
is empty and no infinite trail exists through those powers. The maximum finite trail length is t-1 = 15, as 2026/967 states
for distinct diagonals (abstract read only).

### 4.3 The mu_0 = 1 deviation

2023/323 section 5.2 says mu_i are "random elements from Fp \ {0,1}" such that M_I is invertible with no arbitrarily long
trails. 2026/306 repeats this. DIAG[0]=0 gives mu_0 = 1. The paper's stated conditions are the invertibility and trail ones,
both met. It gives no reason for excluding 1 that I could find. For t=2,3 the exclusions serve the MDS requirement, which
does not apply at t >= 4.

Tested for an effect:

| question | result | strength |
|---|---|---|
| Trail dimensions change? | No: identical for DIAG, DIAG+1 and d0=18 | RUN |
| Invariant subspace appears? | No | RUN |
| Degree growth lost? | No: a_{j+1} = mu_0 a_j^5 + linear, with leading coefficient 1. Toy field 2^31-1: exact degree 5^r for up to 6 partial rounds, and for 1 or 2 full rounds plus partials, same as DIAG+1 | RUN on toy only |
| S-box free projection special? | No. My earlier log entry overstated this. x_i' - x_0'/mu_0 is S-box free for every mu_0, because the S-box output always enters along M_I e0 | RUN |
| Branch number of M_I | 3, against 4 for DIAG+1, by M_I(e0 - e_i) = -d_i e_i | RUN, exact |
| Forgery target | Unchanged: section 5 uses neither mu_0 nor the M_I branch number | REASONED |

The branch number drop does yield a truncated differential that makes the next partial S-box inactive after one round, but
only if the active S-box maps difference a to the same a, an event of about 2^-252, and the designers' statistical argument
does not count M_I at all (2023/323 section 7.1). This is too expensive to matter.

Verdict: spec deviation, no known attack, not required to fix. I cannot rule out an unknown use of it. Nobody has analyzed
this diagonal as far as I can find.

The deployed diagonal looks like a low-cost native search result, skipping 12 and 15. Its small size leaves no room for the
constant-dependent matrix selection used by the 2026/1579 and 2026/1760 attacks, which choose the matrix after seeing the
round constants. Those also target MDS Poseidon. I did not read 2026/1760 beyond its title and a citing summary.

### 4.4 Published status

- 2023/323 Table 1: n=256 only at t=2,3. HorizenLabs bn256 instance file: t=3 only (READ).
- gnark-crypto master, poseidon2_constants.go: t=16, RF=8, RP=57, with all our 185 round constants in its t=16 data
  (RUN, gnark_cmp.py). Its diagonal has random 254-bit values. Equal round constants are expected, since the Grain seed does
  not encode M_I.
- taceo-poseidon2 lists t=16 and cites the same script (crate page only; values not compared).
- My search found DIAG only in Reilabs keccacheck. A negative search result is weak evidence.

So: t=16 over BN254 is a script-generated parameter set that other libraries also use. It is not a paper-listed instance, and
this exact permutation has no published analysis that I could find. Cryptanalysis results for general t apply to it by formula.

## 5. Cost of the forgery target (answers the fiat-shamir QUESTION)

### 5.1 Target

Per 03 section 8.4, one escape suffices. In a sumcheck round of degree D, the prover sets positions {1..D} of the rate (or
another position set, below). Positions 0 and D+1..9 hold earlier outputs, and the capacity is fixed. The prover needs
P(input)[0] = c with g(c) = 0, where g is the difference from the true round polynomial. p0 is derived from the claim, so g
has D free coefficients and g(c)=0 is one linear equation in them for fixed c.

### 5.2 Best attack

1. Fix any c. The input is then restricted to an affine hyperplane of dimension D-1 in the free positions.
2. Pick a line in it (needs D >= 2).
3. Solve P(line(t))[0] = c in t.

The line polynomial has degree 5^(8+57) = 5^65 = 2^150.93. Degree is exact on toy fields at small size. At full size this is
an expectation, based on the leading coefficient analysis, and is not proven. A line has a root in Fp with probability about
1-1/e, so a few lines suffice.

Cost:
- Floor: 5^65 field elements must be handled, so 2^151 operations, plus about the same number of stored words for a
  straightforward interpolation and gcd.
- Interpolation by evaluation adds a factor of about 2^9 (555 multiplications per permutation), so 2^160.
- gcd(x^p - x, f) needs about 254 squarings modulo a degree 2^151 polynomial, so about 2^166 with FFT multiplication.
- Graeffe root finding is the current best for FFT-friendly fields. Here p-1 = 2^28 * 3^2 * 13 * 29 * 983 * 11003 * 237073 *
  405928799 * 1670836401704629 * 13818364434197438864469338081 (RUN, factor.gp). A subgroup of order at least 2^151 has to
  include the 51-bit prime factor, so that method's FFT structure does not obviously carry over. I did not work out its exact
  cost. It would not go below D by the published lower bound arguments (title of 2025/1916, not read).

Grinding comparison: t*6/p per query, so 2^251.4 for one expected success. The algebraic attack is 100 bits cheaper.

### 5.3 Why no round skip applies

Enumerated all first-layer skips of one variable (RUN, feasible.py, mu0.py). A line s + t v, with M_E v = w and support T,
crosses the first S-box layer affinely in z = (t+c)^5 only if the inputs on T are aligned with w: |T|-1 linear conditions on
the offset, solvable for arbitrary fixed data only if those rows have full rank.

| free positions | where used | min wt(M_E v) | rank-feasible skips | enough dof with g(c)=0 |
|---|---|---|---|---|
| {0}, {0,1}, {1,2}, {5,6} | degree 2 rounds, beta-c, beta-d | 12 to 16 | 0 | no |
| {1,2,3}, {5,6,7} | degree 3 rounds | 8 | 0 | no |
| {1,2,3,4}, {2,3,4,5} | degree 4 rounds | 8 | 0 | no |
| {0..5} | first degree 6 round, final block before each 25-beta move | 4 | 0 | no |
| {1..6} | other degree 6 rounds | 6 | 4 | no: 6 conditions against 5 free offsets |
| {0..6} | not in the schedule | 4 | 6 | yes |
| {0..7} | not in the schedule | 2 | 4 | yes |
| {1..9} | middle of opening reads, no challenge follows | 4 | many | n/a |
| {0..9} | middle of opening reads, no challenge follows | 2 | many | n/a |

The schedule table comes from transcript.py, whose read count matches 6255 + 554L and whose permutation count matches the
native prover at n=2,4,64 instances (RUN, tests/poseidon2_permutation_count.rs).

Two notes:
- On {0..5} a line in quad 0 has weight 4, which looks like a skip. It fails because the alignment rows are rank deficient over
  the free positions: two of the three conditions involve only fixed quads. I first assumed it worked (skip6.py asserted it and
  failed), then wrote feasible.py. Satisfying them by grinding earlier blocks costs about 2^508.
- On {1..6}, dropping the pin leaves t in the relation with t = z^(1/5) - c, which raises the degree to about 6*5^65. No gain.
  Keeping the pin leaves one 254-bit condition on fixed data, about 2^250 to grind.

Other routes considered, all REASONED:
- Going through a full 10-element block: the challenge depends on two or three permutations, degree 5^130 or more. Fixing
  positions 6..15 of the next block instead is CICO-10.
- 25-beta moves: a lie in the final block's lanes has its beta in a later permutation, so the relation contains P^2 or P^3. A
  lie confined to lanes 0..9 leaves no free variable in the final block.
- beta-c and beta-d, {0}: relation t*out_j(t) + linear in the others, degree 5^65 + 1. Same cost.
- Output-side peel: f = (a, -a, 0, 0) with a^T M4 = e_0^T gives sum f_i out_i = w_0^5 - w_4^5 (RUN, demo.py), so that linear
  relation is equivalent to w_0 = w_4 and loses one layer. It is real but needs 8 specific betas with a fixed direction, and
  that leaves no free input in the block (above). Not usable on this schedule. It would matter for a transcript whose verifier
  relation is a linear form on 8 fresh outputs with free inputs in the same block.
- Degree annihilation (2026/1254): up to 5 free directions can zero a few leading coefficients out of 625 at the first partial
  S-box input, a gain of about 0.01 bit. Making that input affine needs about 624 conditions.
- S-box skipping (2026/1692): needs linear variables at the partial layer, so only 1 initial full round (their 28 of 31 rounds
  drop 3 initial full rounds). Here 4 initial layers come first. Keeping a partial input constant through them is a degree 625
  equation, and by Bezout that raises rather than lowers the total.
- Additive absorb: absorbing is overwriting in the positions reached, since previous outputs are public. It cannot touch
  positions outside the block. Cancellation between transcripts needs a capacity collision: 2^762 generically, and d=6 algebraic
  estimates exceed 2^243 even before squaring.
- Multi-target: 288 or more equal-degree blocks do not combine into one lower-degree polynomial.
- Statement sponge: costed in section 12. Its final block does cover positions 0..9, but each free element is limited to
  192 bits. Best found is about 2^210 at L=8, so it is not cheaper than the main chain.

Cost does not depend on sumcheck degree: a degree 2 round costs the same as a degree 6 round. The degree 6 of verify_round only
affects the 6/p term of grinding.

This table proves no lower bound. It covers the skip family I could formulate.

### 5.4 Margin

128 bits corresponds to 55.13 S-box layers. The deployed 65 layers leave 9.87 layers, or 22.9 bits, against the known attack.
Against the idealized recipe below (63 layers) it is 18.3 bits. Memory near 2^151 is an extra barrier I do not count.

## 6. The 2026/306 section 6.1 recipe

Run in recipe.py. Validated: CICO-k at t=16 reproduces their Table 2 for k=1..4: (3,[1]), (3,[1]^2), (3,[1]+[a]^2), (2,[1]^4).

Inputs (t=16, c=6, RF=8, RP=57, alpha=5), and tightness assumed as they do. Note they set out=d with a rate that is fully
overwritable, which the deployed schedule is not. Round 2 skip uses ct=c, nu=10+o.

| digest d | best o | skip, second permutation | dI | dI^2 |
|---|---|---|---|---|
| 1 | 0 | (2,[1]) | 5^63 = 2^146.3 | univariate: linear in dI, so 2^146.3 |
| 2 | 0 or 1 | (2,[1]^2) | 5^69 = 2^160.2 | 2^320 (resultants are cheaper; not computed) |
| 3 | 1 | (2,[1]^3) | 5^75 = 2^174.1 | 2^348 |
| 4 | 2 | (2,[1]^4) | 5^81 = 2^188.1 | 2^376 |
| 5 | 0 | (1,[1]+[a]^4) | 5^96 = 2^222.9 | 2^446 |
| 6 | 0 | none under Lemmas 3.2 and 3.6 | 5^105 = 2^243.8 | 2^488 |
| 8 | 0 | none under the lemmas | 5^121 = 2^281.0 | 2^562 |

Using o>0 at d=1 does not help: (3,[1]) needs o=3, with dI0 = 5^82 for the first permutation.

Collisions (Lemma 5.5): d=2: 5^124 = 2^287.9, d=4: 5^134 = 2^311.1, d=6: 5^144 = 2^334.4, d=8: 5^154 = 2^357.6. All are ideal
degree only. Their target is preimage and collision on a hash. They do not address Fiat-Shamir. Only the d=1 row is relevant
to one forgery. Their 128-bit claim for their parameters does not extend here automatically, but these numbers agree with it.

The second-round part of (2,[1]) was not run numerically. The first-round balance on rate-only positions was (RUN, demo.py).

## 7. Attack model and remaining assumption

**Reduction shown:** a CICO-1 solver for P with a linear side condition on the input gives a forgery. So forgery is at most as
hard as CICO-1 on this restricted input space.

**Not shown:** the converse. CICO-1 hardness does not imply Fiat-Shamir security, as 03 section 8 and 2026/306 (on mode attacks)
make clear.

**Assumption left.** A-P2: for every sponge state reachable in the schedule and every relation in the move list of 02, no
algorithm with work 2^128 finds a block with a bad challenge, except with probability about 2^128 * 6/p. This is 03's CI
assumption, restricted to this permutation. It cannot be proven with known techniques, only analyzed. P is known not to be
ideal: forward degree 5^65 is far below p, and section 5 is a concrete distinguisher and attack at about 2^151. 03's ideal model
bound is thus false near t = 2^151. It may hold at t = 2^128. That is the assumption.

**Is evidence:**
- The bounties broke only reduced rounds. For a BN254-sized field: none reported at full rounds. Poseidon-256 on BLS12-381 was
  claimed at RP=8,9 with RP=11 and 16 unclaimed at close (t=3, CITED from the initiative slides).
- 2026/306 finds no recommended parameter below 128 bits (CITED, their parameter sets).
- My enumeration in 5.3, on this schedule.

**Weak evidence:**
- 2026/409 reports no forgeries, but tested generic Groebner on toy parameters, in sigma and FRI shapes, not sumcheck. Its
  authors suggest correlation approaches are more promising.
- Absence of an attack found by this effort, in limited time, self-checked only.

**Not evidence:**
- The 03 proof, which assumes ideality.
- The formula being met: it encodes known attacks when it was set.
- Other libraries using the same RF and RP.

**Against confidence:**
- The Ethereum Foundation initiative moved its bounty target from Poseidon2 to Poseidon1 after 2026/306 (slides, Khovratovich,
  May 2026: "Why we moved from Poseidon2"; this deck says it was AI drafted from the author's commands). The initiative gives
  no verdict that recommended Poseidon2 parameters are broken, and they are not.
- The same slides say Fiat-Shamir security is "largely unexplored", with a 2026 grant open on exactly this question.
- 2026 has seen fast improvement on reduced-round instances (CICO RP=10 and zero-test RP=12 on KoalaBear Poseidon1 by July, per
  the initiative page). Phase 2 concludes December 2026. Expect more results. Those are small-field instances and do not
  translate directly.

## 8. Survey

| paper | result | applies here? |
|---|---|---|
| 2023/323 | Spec, formula | Base |
| 2023/537 | Groebner bound | In script, 455 bits here |
| 2025/954 | Trail-based Groebner; designers' estimates near correct at 2^256 | Not binding at d=1 (CITED) |
| 2025/937, 950, 1916 | Graeffe root finding | FFT-friendly fields; 2-adicity here is 28. Titles and abstracts only |
| 2025/2040 | CheapLunch, ideal degree bounds | Consistent, k=1 same 5^65 |
| 2026/150, 2026/1905 | CICO-2 resultants on small instances | Target is CICO-2. d=1 is the relevant case here |
| 2026/306 | Matrix round skips, mode attacks | Section 6. Needs blocks the schedule lacks |
| 2026/409 | FS Groebner attempts on toy Poseidon | Weak evidence |
| 2026/967 | Finite trail bound t-1 | Consistent. Abstract only |
| 2026/1254 | Degree annihilation, cubic | Negligible gain at alpha=5 here |
| 2026/1579, 2026/1760 | Attacks with an adaptively chosen MDS matrix | Matrix is fixed and small here; targets MDS Poseidon |
| 2026/1692 | S-box skipping | Needs 1 initial full round. Not 4 |

The 2026 survey is from search and archive fetches on 2026-11-07. It may be incomplete.

## 9. Change requests

No change is required by any attack found. Details posted to the log.

**CR-3: DIAG + 1 (spec conformance, not required).** diag(1,2,...,12,14,15,17,18), so all mu_i >= 2. Conditions: det nonzero,
irreducible for k <= 100000, trail dimensions same, branch number 4, toy degree same (RUN, mi3.gp, mu0.py, weights.py). Cost: 0
constraints per permutation (multiplication by constants), new keys. Requires a matching gkr change. Round constants unchanged.
This diagonal has also had no outside analysis.

**CR-4: RP = 64 (extra margin, not required).** +21 constraints per permutation. At 64 instances: 2783 permutations, +58,443
constraints, 3.0% of the standalone 1,957,112 in RESULTS.md. Degree 5^72 = 2^167. New Grain constants since the seed includes
RP. Alternatives at 64 instances:

| option | extra per perm | total extra | layers added | deployed attack |
|---|---|---|---|---|
| keep | 0 | 0 | 0 | 2^150.9 |
| RP=61 | 12 | 33,396 | 4 | 2^160.2 |
| RP=64 | 21 | 58,443 | 7 | 2^167.2 |
| RF=10 | 96 | 267,168 | 2 | 2^155.6 |

Partial rounds buy degree at 1/16 the constraint cost of a full round, but RF is what directly counters the matrix skips. Since
those skips do not reach this schedule, RP is the better buy if the owner wants margin.

**Interaction with CR-1, CR-2.** CR-1 touches neither. CR-2 already requires a gkr fork (seeded Prover), so CR-3 and CR-4 could
share it. Without CR-2, each of these forces that fork alone, which is the main cost. CR-2 shifts the permutation count only by a
few. Update the pin. It leaves the block position table unchanged after the first sumcheck (REASONED, not rerun).

**Constraint on any future schedule change.** Section 5 depends on no challenge block having 7 or more free positions that cover
0..6, or the 1..9 style layouts with a challenge next. Absorbing a whole round polynomial at block start, or batching messages to
a block boundary before squeezing, would enable a skip. Cost then falls toward 5^63. Rerun transcript.py and feasible.py.

## 10. Tests

Test code only:
- experiments/keccacheck-arkworks/src/poseidon2.rs: only adds a cfg(test) module declaration.
- experiments/keccacheck-arkworks/src/poseidon2/params_tests.rs: Grain regeneration, extracted M_E and M_I, M4 MDS, Krylov rank,
  round counts, gcd, round order, test vector, 555 constraints, absorb positions after squeeze, sponge against native.
- experiments/keccacheck-arkworks/tests/poseidon2_permutation_count.rs: 1835, 2007, 2783 permutations at 2, 4, 64 instances.

All pass: 26 lib tests and 1 integration test. They ran from a scratch mirror (a scratch copy of the crate), because cargo in this nested
worktree resolves to the main checkout's workspace and refuses the crate. Irreducibility of M_I^k is checked by mi3.gp only, not in
Rust. DIAG is pinned, so any change fails a test and must rerun it.

## 11. Not established

- Hardness of A-P2. Not establishable by analysis.
- That 5^65 is exact at full size, or that the attack family in 5.3 is complete.
- Reference Sage script not run. A port was, validated at two points.
- Algorithms 1 and 3 of the script are covered via the irreducibility and Algorithm 2 style checks, not line for line.
- M_E branch number 8: witness run, minimality taken from the paper.
- (2,[1]) at nu=10: round 1 run, round 2 from Lemma 3.2.
- Graeffe cost on this field.
- Several 2026 sources were read only in abstract or by summary, as marked. 2026/1760 and 2026/967 especially.

## 12. Statement-final block of derive_r (r move)

Target, from review-fs R2 via NOTES. At the r move, the output claim weights instance i by eq(r, i). If some r_k equals the
complement of bit k of every wrong instance, all wrong instances drop out. The honest proof of the true trace then verifies,
and no main-chain escape is needed. Note that this works for any set of wrong instances sharing bit k, not only a single one.

### 12.1 Layout, checked against the code

stmt_block.py implements derive_r_var: tag, then 2^L, then input words in chunks of 3, then output words in chunks of 3. The
two streams are chunked separately, and words are lane-major, so word index = lane*n + instance. Each element is
w0 + 2^64 w1 + 2^128 w2. stmt_replay.py replays the sponge with this layout and the Python permutation. Its r_0 equals Rust
derive_r_native at L = 1, 2, 8 (RUN; the Rust side ran from scripts in the scratch mirror only). I read derive_r_var and it has
the same structure as derive_r_native (READ; 05 owns gadget equivalence).

| L | n | absorbs | final block | element sizes | contents |
|---|---|---|---|---|---|
| 1 | 2 | 36 | positions 0..5 | 5 x 192, last 128 | output lanes 16..24, both instances |
| 2 | 4 | 70 | positions 0..9 | 9 x 192, last 64 | output lanes 18..24 |
| 8 | 256 | 4270 | positions 0..9 | 9 x 192, last 64 | output lane 24, instances 228..255, 3 per element, 255 alone |

At every L the r_k are output positions 0..L-1 of the permutation that follows this block (RUN by replay).

This corrects the counts in the GAP entry. At L=8 there are 4270 absorbs, not 4269: each stream has 2134 chunks since 6400
words leave a 1-word last chunk. So there are 10 elements, not 9, and the last is 64 bits, not 128. My transcript.py merged
the two streams. That changed no permutation count (rerun: 427 statement permutations at L=8, total 3441) but did change this
layout. It is fixed.

Attacker freedom while every other instance stays true: only the words of wrong instances. At L=8 a wrong set inside the
final block is a subset of instances 228..255, all of whose words in that block are lane 24 outputs. The best single position
is three instances in one element, for example 228, 229, 230: 192 free bits, and they agree on 6 of the 8 bits, so 6 values
of k work with r_k = complement (RUN, stmt_block.py, maximizing free bits plus log2 of the number of usable k).

### 12.2 Cost

Same univariate method as section 5, with the free element restricted to its box:
1. Take a line along the free element, input = o + t with t in the box.
2. f(t) = P(state)[k]. Solve f(t) = target for each usable k.

Degree is 5^65 as before. Each root is a uniformly placed field element, so it lies in a 192-bit box with probability
2^(192-254) = 2^-62.

| L | best position | free bits | usable k (T) | algebraic, D * 2^(254 - bits) / T | generic grinding about p/L | best |
|---|---|---|---|---|---|---|
| 1 | pos 0, instance 1 (two words, not contiguous) | 128 | 1 | 2^276.9 | 2^253.6 | generic, 2^253.6 |
| 2 | pos 0, instances 0,1 | 128 | 1 | 2^276.9 | 2^252.6 | generic, 2^252.6 |
| 8 | pos 0 (228..230), others alike | 192 | 6 | 2^210.3 | 2^250.6 | algebraic, 2^210.3 |

The algebraic figures are floors in the same sense as section 5.2: add about 2^9 to 2^15 for interpolation and root finding.
The arithmetic is RUN. The model (uniform roots, no better route) is REASONED.

Why the box defeats the skip (REASONED): the L=8 block covers 0..7, so in position terms Lemma 3.2 applies. But every skip
parametrization fixes the free inputs to specific field values set by linear equations: U0 for the balance, alignment offsets
for the line skip. Each such value lands in a 192-bit box with probability 2^-62. The 4 balance values alone cost 2^-248, and
the skip curve then moves all 8 positions through field-random values. Grinding earlier blocks to supply fresh capacities does
not help, since each condition is a 254-bit equation.

Routes using the box structure (REASONED, none better):
- Words or bits as separate variables: the free set is still a box of 2^192 points per element. Bit variables raise the
  equation count and do not lower the degree.
- Several free elements at once: for each choice of the others, the last is univariate, with the same in-box probability.
  Finding a point of a degree-5^65 hypersurface in a box is a small-root problem, and no lattice method is known at this degree.
- Restricting t to a structured set (a subgroup or coset) to speed up root finding: the box is an interval, not an algebraic
  set, and full root finding already costs about D.
- Choosing the wrong set as a half-cube (all instances with bit k = b) adds free words in earlier blocks. Those only re-randomize
  the capacity, which grinding already allows. It does not lower the per-line cost.

### 12.3 Beta-move variant

Fix r = r* (and thereby beta*) in advance. Choose wrong words delta with sum_i beta*_i sum_inst eq(r*, inst) delta_i[inst] = 0,
which LLL solves easily for many small unknowns. Then force derive_r to output r*.

For L >= 2 that is CICO-L on the final block with a boxed input: ideal degree at least 5^(8L+57) before the box loss, and
L=2 already exceeds 2^250. At L=1 it is CICO-1 with the box and one extra linear condition. That condition involves the final
block's own delta, since those words are wrong, so the line must run along a short vector of the kernel lattice of one equation
in 27 word variables. Those vectors have norm about 2^10, which leaves about 2^54 of range per line, so about 2^-200 per root
and 2^351 in total. Words in earlier blocks cannot carry the condition, because they change the capacity and hence r.

So this variant is not cheaper: (REASONED) worse than the r move at every L. 03 already covers its generic form (12 t/p at L=1).

### 12.4 Effect on the conclusions

- The cheapest known structural target is still one main-chain sumcheck round: 5^65 = 2^150.9, independent of L. The
  statement block costs about 2^210 at L=8 and is generic at L=1, 2.
- The 22.9-bit margin conclusion stands at L=8.
- The schedule property in section 9 is false for the statement sponge, which covers 0..9. It is harmless only because of the
  192-bit box. If statement elements ever become full field elements (packing 4 words would not fit; hashing to Fr first
  would), this block becomes a 10-position CICO-1 with the (2,[1]) skip: 5^63 = 2^146.3 / T, about 2^143.7 at T=6.
- 03 line 390 "cheapest structural target is one sumcheck round" holds for the costs found here (REASONED).
