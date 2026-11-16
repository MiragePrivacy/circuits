# 01: Keccacheck as implemented

Agent: protocol. Code: PR 3 head cc59207. Paths are relative to the repo root; `V:` means
experiments/keccacheck-arkworks/src/verifier.rs and `B:` means
experiments/keccacheck-arkworks/src/batch.rs. Line numbers are at cc59207.

## Review history

- Referee review-rbr, report reviews/rbr.md.
  Every protocol line, verifier.rs citation, paper citation and batch.rs reference in this document was checked and matches.
  Not checked by the referee: section 8 item 2 ("Added upstream in 557faf4"), which has no effect on soundness.
  This revision: MIN_INSTANCES = 4 (CR-1, adopted) as the deployed minimum; layers stated by field formulas (referee C3);
  cross-reference on packing injectivity (C6).

Derived from the code, not from the paper. Section 9 records how this document was checked against
the real native prover. Section 8 lists every difference from the paper.

## 1. Notation

- F = Fr of BN254, |F| = r = 21888242871839275222246405745257275088548364400416034343698204186575808495617.
  log2(r) = 253.6.
- h = number of instances (a power of two, h >= MIN_INSTANCES = 4 deployed per CR-1; the constant is 2 at cc59207, V:399). Production h = 256, n = 14. L = log2(h). n = L + 6.
- Lane index i in 0..25, i = x + 5y, x = column, y = row. Instance index j in 0..h. Bit index b in 0..64,
  b = 0 is the least significant bit of the lane.
- HALF = (r+1)/2 = 2^{-1} mod r (V:13).
- eq(a,b) = prod_m (2 a_m b_m + 1 - a_m - b_m) (V:143-152). Equal to prod (a_m b_m + (1-a_m)(1-b_m)).
- xor(a,b) = a + b - 2ab (V:96-99).
- add_col(i,a) = same row as i, column (x+a) mod 5 (V:202-206).

### Hypercube convention (differs from the paper, see 8.1)

A point is z = (z_1, ..., z_n). Earlier coordinates are MORE significant. The table index of a Boolean
k in {0,1}^n is idx(k) = sum_m k_m 2^{n-m}, and idx(k) = 64 j + b. So:

- z_1 .. z_L index the instance j, with z_1 its most significant bit.
- z_{L+1} .. z_n index the bit b, with z_{L+1} = coefficient of 32 and z_n = coefficient of 1.

Evidence: eval_eq (V:105-122) splits every entry into (lo, hi) in order, so r[0] selects the upper half.
eval_mle (V:131-141) folds coeffs[j] with coeffs[half+j] using r[0] first. Tables are laid out as
[lane][instance][LE bit] (V:522-524, V:642-650, B:125-133).

For a table T on {0,1}^n, T~ is its multilinear extension: T~(z) = sum_k eq(z,k) T(k).

### Sumcheck subroutine SC(d, m, c) (V:175-200)

Inputs: degree d, variable count m, claim c. For each round l = 1..m:

1. P sends d elements p_1, ..., p_d (absorbed in that order). They are the coefficients of t^1, ..., t^d.
2. V derives p_0 = (c - sum_{j=1..d} p_j) * HALF (V:186-190). No check occurs here.
3. V samples r_l (squeezed AFTER the d elements were absorbed, V:191).
4. c := p(r_l) where p(t) = p_0 + p_1 t + ... + p_d t^d (Horner, V:193-197).

Output: (c, (r_1, ..., r_m)). The final equality check is done by the caller. The challenge r_l binds
coordinate z_l, so the first challenge binds the most significant coordinate.

Round sent size: d elements. p(0) is never sent. The relation p(0) + p(1) = c holds by construction.

## 2. Statement and preconditions

Statement (V:525-550): vectors of Booleans in[i][j][b], out[i][j][b], claim: for all j,
out[.][j][.] = Keccak-f[1600](in[.][j][.]). Ordered [lane][instance][LE bit] (V:522-524).

Preconditions:
- P1 Booleanity of inputs and outputs: both are `Boolean<Fr>`, taken as a precondition by
  verify_boolean_batch. It does not enforce them itself. Enforcement occurs on allocation:
  B:90-94 for outputs (`Boolean::new_witness`); inputs are whatever Boolean the caller owns. The
  top-level verify_witness_profile allocates both via new_witness (V:492-507). Constant padded bits are
  `Boolean::constant` (B:119-123).
- P2 len(in) = len(out) divisible by 1600; h = len/1600 is a power of two; h >= MIN_INSTANCES (4 deployed, 2 at cc59207). Enforced by native
  asserts at synthesis time (V:531-534), so it fixes the circuit shape.
- P3 Proof length exactly 6255 + 554 L (V:669-672, finish at V:87-93 and V:651).
- Padding (B:36-50): recorded permutations are padded to next_power_of_two().max(MIN_INSTANCES) with constant
  instances in = 0^1600, out = Keccak-f(0^1600) computed by the native keccak crate.
- Batches below MIN_INSTANCES are refused (V:399, V:534, V:484); L = 0 additionally by V:411, V:433. With CR-1 this excludes h = 1 and h = 2.
- Proof values are unconstrained witnesses `FpVar::new_witness` (V:536-539).

Derived word values: W[i][j] = sum_{b<64} 2^b out[i][j][b] in F (V:573-579).

## 3. Statement sponge (V:428-453)

A fresh sponge (separate instance from the main transcript):

    absorb STATEMENT_TAG = u128 LE of b"mirage/kcck/stmt"       (V:404, V:435)
    absorb 2^L as field element                                 (V:436)
    for each chunk of 192 bits of the input bits, in order:     (V:437-451)
        absorb packed = sum_{k} 2^k bit_k                       (3 words, first word lowest)
    the same for the output bits (chain; chunks restart at the output boundary)
    squeeze r_1, ..., r_L                                       (V:452)

Number of absorbs: 2 + 2 ceil(25 h / 3). Packed values are below 2^192 < r given P1, so packing is injective on Boolean chunks; without P1 it is not
(see 02 section 8.1, last Booleanity item).

The sponge itself: rate 10, width 16, additive absorb, idx and dirty flags (poseidon2.rs:99-146). `absorb`
adds to state[idx] and increments, permuting first when idx = 10. `squeeze` permutes if dirty or idx >= 10,
then outputs state[idx], idx += 1. Absorb after squeeze continues at the current idx without a permutation
but sets dirty. Analysis of it belongs to 03-fiat-shamir.md.

## 4. Main transcript: initialization and output reduction (V:581-618)

A second fresh sponge. Its only link to the statement is r.

| # | Actor | Element(s) | Equation / use | Line |
|---|-------|-----------|----------------|------|
| 1 | V | absorb r_1..r_L | | V:584-586 |
| 2 | V | beta_0..beta_24 (25 squeezes) | | V:587 |
| 3 | P | sum | CHECK sum = sum_i beta_i sum_j eq(r, j) W[i][j] | V:588-595 |
| 4 | SC | SC(2, L, sum) -> (c1, r_x) | | V:597 |
| 5 | P | words_r_x | CHECK c1 = words_r_x * eq(r, r_x) | V:598-603 |
| 6 | SC | SC(2, 6, words_r_x) -> (c2, r_y) | | V:605 |
| 7 | P | bit_eval | CHECK c2 = pow~(r_y) * bit_eval, where pow(b) = 2^b | V:606-614 |
| 8 | | sum := bit_eval; alpha := r_x || r_y | beta carried into round 23 | V:615-617 |

Meaning of the polynomials for an honest prover (T = true outputs, W for honest T):
- Step 4 sums over x in {0,1}^L: eq(r,x) sum_i beta_i Wt_i~(x), with Wt_i(x) the word table of T.
- words_r_x claims sum_i beta_i Wt_i~(r_x).
- Step 6 sums over y in {0,1}^6: pow~(y) sum_i beta_i T_i~(r_x, y).
- bit_eval claims sum_i beta_i T_i~(r_x, r_y).

## 5. Layers over the hypercube

For each Keccak round t in 0..24 define tables on {0,1}^n (lanes indexed as in section 1, table position 64 j + b).
XOR, NOT and AND below mean the field formulas xor(a,b) = a + b - 2ab, 1 - a and ab. For Boolean inputs every table is
Boolean and these are Keccak's bit operations; for other inputs they define the arithmetized round (02 section 8.1):

    A^0_i          := in_i
    C^t_x(k)       := XOR_{y} A^t_{x+5y}(k)
    RC1^t_x(k)     := bit b of rotl(C^t_x[j], 1)  (position k = (j,b); = C^t_x at (j, b-1 mod 64))
    D^t_x(k)       := C^t_{x-1}(k) XOR RC1^t_{x+1}(k)
    Th^t_i(k)      := A^t_i(k) XOR D^t_{i mod 5}(k)
    Rh^t_i(j,b)    := Th^t_i(j, b - rho[i] mod 64)     rho = RHO_OFFSETS (V:43-45)
    Pi^t_{P(i)}    := Rh^t_{i}                         P defined in section 6.3
    Ch^t_i(k)      := Pi^t_i(k) XOR ((1 - Pi^t_{add_col(i,1)}(k)) Pi^t_{add_col(i,2)}(k))
    Io^t_i         := Ch^t_i                           for i != 0
    Io^t_0(k)      := Ch^t_0(k) XOR RC^t(k)            RC^t(j,b) = bit b of ROUND_CONSTANTS[t] (V:16-41)
    A^{t+1}_i      := Io^t_i

Base change: for a table X, X^ := 1 - 2X (values +1 / -1 when X is Boolean), so X^~ = 1 - 2 X~ as polynomials
(multilinear extension is linear). Since (1 - 2a)(1 - 2b) = 1 - 2 xor(a,b) for all a, b in F, XOR becomes product
entrywise, for any field values. Thus:

    C^^t_x(k) = prod_y A^^t_{x+5y}(k)
    D^^t_x(k) = C^^t_{x-1}(k) * RC1^^t_{x+1}(k)
    Th^^t_i(k) = A^^t_i(k) * D^^t_{i mod 5}(k)

C^^~ denotes the multilinear extension of the +-1 table, NOT prod_y A^^~. The two agree only on the
hypercube; sumchecks are used exactly to bridge that.

### rot as evaluated (V:154-173)

For a lane offset s and points a, c in F^n:

    rot_s(a, c) = eq(a_{1..L}, c_{1..L}) * sum_{u=0..63} eq(a_{L+1..n}, u + s mod 64) eq(c_{L+1..n}, u)

where the integer u is mapped to 6 bits MSB first. Multilinear in each of a and c. On Boolean a, c it is
1 exactly when the instances agree and bit(a) = bit(c) + s mod 64. Therefore

    (rotl(X, s))~(a) = sum_{c in {0,1}^n} rot_s(a,c) X~(c)

The call rot_from_eq has `instances` = 64/64 = 1 (only 6-variable suffix tables reach it, V:274-275).
In the theta_c check the rotate-by-1 is rot_from_eq(1,..) relying on RHO_OFFSETS[1] = 1 (V:355).

## 6. Round t (V:218-393), for t = 23 down to 0

Input: alpha in F^n, beta in F^25, claim `sum`. Honest meaning: sum = sum_i beta_i Io^t_i~(alpha).
For t = 23 this is the (alpha, beta, sum) from section 4. For t < 23 see 6.9.

### 6.1 Iota: SC(3, n, sum) -> (ve, v1). V:227

Polynomial, in k over {0,1}^n:

    f_iota(k) = eq(alpha,k) [ beta_0 xor(Ch_0~(k), RC~(k)) + sum_{i != 0} beta_i Ch_i~(k) ]

P sends chi_00, chi_rlc (V:228-229). Honest: chi_00 = Ch_0~(v1), chi_rlc = sum_{i != 0} beta_i Ch_i~(v1).
RC~ depends only on the last 6 coordinates (V:231-234; table rc_bits[b]).

CHECK ve = eq(alpha,v1) * (beta_0 * xor(chi_00, RC~(v1)) + chi_rlc) (V:235-236).

### 6.2 Chi: V samples x, y (V:238-239), then IN-PLACE beta_0 *= x; beta_i *= y for i != 0 (V:240-243).
New claim: c = beta_0 chi_00 + y chi_rlc, with the UPDATED beta_0 = old beta_0 * x (V:244).

SC(4, n, c) -> (ve, v2) (V:246):

    f_chi(k) = eq(v1,k) sum_i beta_i xor(Pi_i~(k), (1 - Pi_{add_col(i,1)}~(k)) Pi_{add_col(i,2)}~(k))

P sends pi_0..pi_24 (V:247-250). Honest: pi_i = Pi_i~(v2).

CHECK ve = eq(v1,v2) sum_i beta_i xor(pi_i, (1 - pi_{add_col(i,1)}) pi_{add_col(i,2)}) (V:251-260).

### 6.3 Pi: no interaction. strip_pi (V:208-216)

rho_0 := pi_0, and with PI = the 24 element table (V:47-49), rho_{last} := pi_{target} walking
last = 1, target = PI[0], then last = target, ... So P(1) = PI[0], P(PI[m]) = PI[m+1], P(0) = 0; rho_i = pi_{P(i)}.
Honest: rho_i = Rh_i~(v2).

### 6.4 Rho: V samples fresh beta_0..24 (V:264-267), overwriting. c = sum_i beta_i rho_i.

SC(2, n, c) -> (ve, v3) (V:268):

    f_rho(k) = sum_i beta_i rot_{rho[i]}(v2, k) Th_i~(k)

P sends theta_0..24 (V:269-272). Honest: theta_i = Th_i~(v3).

CHECK ve = sum_i beta_i rot_{rho[i]}(v2, v3) theta_i (V:273-282).

### 6.5 Theta: base change theta^_i = 1 - 2 theta_i (V:284-287). V samples fresh beta_0..24, kept for 6.8
(V:289-292). c = sum_i beta_i theta^_i.

SC(3, n, c) -> (ve, v4) (V:294):

    f_th(k) = eq(v3,k) sum_{x} D^_x~(k) ( sum_{y} beta_{x+5y} A^_{x+5y}~(k) )

P sends ai_0..4 then d_0..4 (V:295-302). Honest: ai_x = sum_y beta_{x+5y} A^_{x+5y}~(v4); d_x = D^_x~(v4).

CHECK ve = eq(v3,v4) sum_x d_x ai_x (V:303-308).

### 6.6 Theta D: V samples bd_0..4 (V:310-316). c = sum_x bd_x d_x.

SC(3, n, c) -> (ve, v5) (V:317):

    f_d(k) = eq(v4,k) sum_x bd_x C^_{x-1}~(k) RC1^_{x+1}~(k)

P sends c_0..4 then rc_0..4 (`rot_c`) (V:318-325). Honest: c_x = C^_x~(v5), rc_x = RC1^_x~(v5).

CHECK ve = sum_x bd_x eq(v4,v5) c_{x+4 mod 5} rc_{x+1 mod 5} (V:326-331).

### 6.7 Theta C: V samples bc_0..4 then brc_0..4 (V:333-345). c = sum_x (bc_x c_x + brc_x rc_x).

SC(6, n, c) -> (ve, v6) (V:346):

    f_c(k) = sum_x ( bc_x eq(v5,k) + brc_x rot_1(v5,k) ) prod_y A^_{x+5y}~(k)

P sends a_0..24 (V:347-350). Honest: a_i = A^_i~(v6).

CHECK ve = sum_x (bc_x eq(v5,v6) + brc_x rot_1(v5,v6)) prod_y a_{x+5y} (V:351-361). rot_1 uses
rot_from_eq(1, ...) with RHO_OFFSETS[1] = 1.

### 6.8 Theta A: V samples b_0..4 (V:363-370), updating IN PLACE beta_{x+5y} *= b_x for all y (where beta is the
6.5 vector). Then ba_0..24 (V:371-376). c = sum_x b_x ai_x + sum_i ba_i a_i.

SC(2, n, c) -> (ve, v7) (V:377):

    f_a(k) = sum_i ( beta_i eq(v4,k) + ba_i eq(v6,k) ) A^_i~(k)

P sends ah_0..24 (V:378-381, called `iota`). Honest: ah_i = A^_i~(v7).

CHECK ve = sum_i (beta_i eq(v4,v7) + ba_i eq(v6,v7)) ah_i (V:382-388).

Output: alpha' := v7; a_i := (1 - ah_i) HALF (V:389-392). Honest: a_i = A^t_i~(v7).

### 6.9 Between rounds (V:631-637)

If t != 0: V samples fresh beta_0..24 and sets sum := sum_i beta_i a_i, alpha := v7. This is an RLC of claims on
A^t_i = Io^{t-1}_i. Rounds run t = 23, 22, ..., 0 (V:621); RC for round t is ROUND_CONSTANTS[t] (V:628).

### 6.10 End (V:641-651)

No RLC after round 0. For each lane i separately:

CHECK sum_{idx} eq(v7, idx) in_i(idx) = a_i. Then the transcript must be exhausted.

## 7. Counts

| Item | Rounds | Degree | Elements per round | Opening elements |
|---|---|---|---|---|
| output sum | - | - | - | 1 |
| word SC | L | 2 | 2 | 1 |
| bit SC | 6 | 2 | 2 | 1 |
| iota | n | 3 | 3 | 2 |
| chi | n | 4 | 4 | 25 |
| rho | n | 2 | 2 | 25 |
| theta | n | 3 | 3 | 10 |
| theta D | n | 3 | 3 | 10 |
| theta C | n | 6 | 6 | 25 |
| theta A | n | 2 | 2 | 25 |

Proof length: 3 + 2L + 12 + 24 (23 n + 122) = 6255 + 554 L, matching proof_elements (V:669-672).

Sumcheck rounds: L + 6 + 168 n. Main transcript squeezes: 25 + L + 6 + 24 (7 n + 97) + 23 * 25, with RLC vectors
(x,y):2, beta:25, beta:25, bd:5, (bc,brc):10, (b,ba):30, plus 25 between rounds. Statement sponge squeezes: L.

Sum of per-variable degrees: 2L + 12 + 24 * 23 n. Verifier challenge moves: section 2 of 02-interactive-soundness.md.

## 8. Differences from the paper (ePrint 2025/1764, dated 2025-09-25)

Line numbers are in ePrint 2025/1764.

1. Variable order. Paper (lines 264-272): x_1..x_6 index the bit, little-endian, x_7..x_n the instance. Code: instance
   first, then bit, each MSB first. Same polynomials up to a coordinate permutation; all formulas in the code are
   consistent with the code's order.
2. Output reduction. Paper (lines 331-332): V samples alpha in F^n, P provides iota_ij(alpha) for all i,j. Code:
   V samples r in F^L only, computes the word-table RLC itself and runs two degree-2 sumchecks to reach alpha = r_x || r_y.
   Paper's bound does not cover these. Added upstream in 557faf4.
3. beta is sampled once before the output sum and carried to round 23. Paper samples at 2.2.1 after evaluations.
   P sends no evaluations before beta in code: `sum` is forced, and beta comes from r only (r is the sole statement link).
4. Iota opening: paper has P providing chi_ij(alpha) for all lanes (line 349). Code: two values chi_00 and chi_rlc.
5. Chi RLC: paper samples new beta_ij (line 352). Code: reuses the iota beta multiplied by x (lane 0) and y (others).
6. Theta opening: paper claims A^_ij(alpha0) for 25 lanes and D^_i (line 399). Code: 5 values ai_x (column RLCs by theta beta)
   and 5 values d_x.
7. Theta A RLC: paper samples new beta_ij, beta'_ij (line 420). Code: reuses theta beta scaled by b_x per column, only 5 + 25 fresh.
8. Paper line 404 writes D^_i as C^_{i-1} rot(C^_{i-1}, 1). This is a typo; code and Algorithm 1 line 7 use C_{i+1}
   for the rotated factor.
9. Sumcheck encoding: paper sends full f_i and checks H = f_i(0) + f_i(1) (lines 196-207). Code sends coefficients 1..d and
   derives p(0) using HALF, so no check exists per round.
10. RLC count: paper 7 per round, 168 total (line 553). Code: 6 per round, plus 23 between rounds, plus the initial beta.
11. Statement commitment: paper mentions committing to the output vector (line 448). Code absorbs tag, h, input bits and
    output bits in a separate sponge.
12. Singleton batches: paper benchmarks 1 instance (line 609). Code refuses (MIN_INSTANCES = 2 at cc59207, 4 deployed per CR-1).
13. Soundness count: paper (168 + 553 n)/|F|. Section 7 of 02-interactive-soundness.md derives (162 + 555 n)/|F| for this
    protocol. Lines 527-534 of the paper treat each lane's false claim via a fresh beta, which the code does not always have.
14. Paper claims RBR with doomed = "any unresolved claim false" (line 570) as a sketch. Deployed pending claims include prover
    RLCs (chi_rlc, ai_x), which are not lane evaluations, so the state function must be stated with those.

## 9. How this was checked

Replay of real native-prover proofs through an independent model of this document, at n = 7, 8, 12, 13, with the real Fiat-Shamir
challenges from the pinned upstream transcript. Each proof was accepted and the read/generate schedule matched exactly. FIPS 202 constants were
regenerated and compared. Details: 02-interactive-soundness.md section 10. This checks the document against the upstream native prover, not against the R1CS
gadgets (05-implementation.md). The statement sponge in section 3 has "read the code" strength plus a copy in the replay.
