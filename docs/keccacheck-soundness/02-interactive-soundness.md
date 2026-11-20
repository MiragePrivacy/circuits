# 02: Round-by-round soundness of interactive Keccacheck

Agent: protocol. Protocol and notation are those of 01-spec.md (cited as "spec"). `V:` means
crates/keccacheck/src/verifier.rs at cc59207.

## Review history

- Referee review-rbr, report reviews/rbr.md
  (blind re-derivation then refereeing of 01 and 02). It upheld Theorem 1 and its count (555 n + 162)/r term by term, and found no fatal
  or repairable error. Cosmetic items C1-C6 are addressed in this revision:
  - C1: move definition (section 2) and largest single move (section 1).
  - C2: Lemma 7 tightness wording.
  - C3: non-Boolean statements (section 8.1).
  - C4: T3, T5, T6 fold into the next challenge move (sections 5 and 6).
  - C5: production row n = 14, now primary (sections 1 and 7).
  - C6: Booleanity and the 192-bit statement packing (section 8.1).
  I agree with all six; none changes a bound. Also in this revision: MIN_INSTANCES = 4 (CR-1, adopted) is taken as the deployed minimum,
  and the L = 0 and L = 1 results are kept but marked unreachable.

Status summary:
- Theorem 1 below is proved in full for the interactive protocol, for a statement fixed before the first
  challenge, with challenges independent and uniform in F.
- No GAP remains in the interactive argument. Section 11 lists what this document does NOT establish (the R1CS
  correspondence, the sponge, and the wiring), each owned elsewhere.
- No soundness problem was found in the interactive protocol.

## 1. Result

Let F = Fr of BN254, r = |F|, h = 2^L, n = L + 6. Fix Boolean in[i][j][b], out[i][j][b] with
out[.][j][.] != Keccak-f[1600](in[.][j][.]) for some j. Let P* be any prover, computationally unbounded, and let
all verifier challenges be independent and uniform in F.

**Theorem 1.** The state function of section 5 is a round-by-round soundness state function with per-move errors as in
section 7. Consequently

    Pr[V accepts] <= (552 n + 3 L + 180) / r = (555 n + 162) / r.

**Production (primary): n = 14, L = 8, h = 256. Pr[V accepts] <= 7932/r = 3.62e-73 = 2^-240.64.**

| n | L | h | numerator | Pr bound | log2 | status |
|---|---|---|---|---|---|---|
| 14 | 8 | 256 | 7932 | 3.62e-73 | -240.64 | production |
| 8 | 2 | 4 | 4602 | 2.10e-73 | -241.43 | smallest reachable with MIN_INSTANCES = 4 |
| 12 | 6 | 64 | 6822 | 3.12e-73 | -240.86 | reachable, not production |
| 13 | 7 | 128 | 7377 | 3.37e-73 | -240.75 | reachable, not production |
| 7 | 1 | 2 | 4047 | 1.85e-73 | -241.61 | holds, unreachable with MIN_INSTANCES = 4 |

The deployed minimum is MIN_INSTANCES = 4 (CR-1, adopted; the constant is 2 at cc59207, V:399), so L >= 2 and n >= 8.
Theorem 1 is stated and proved for every L >= 0. The L = 0 and L = 1 results below remain true statements about the
interactive protocol, but those batch sizes are no longer reachable.

Largest single move (section 2 definition: one squeeze run of one sponge): max(6, L)/r. Thus 6/r = 2^-251.01 for 2 <= L <= 6
(a degree-6 sumcheck round), and L/r for L >= 7, from the r block. Production: 8/r = 2^-250.60. Splitting r by coordinate (Lemma 2)
is a valid finer accounting, 1/r each, with the same sum. It is not a different move structure: in the deployed transcript r_1..r_L
are one squeeze run. Under the alternative definition "maximal run of challenges with no prover message between", r and the initial
beta merge into one move of error (L+1)/r, 9/r at L = 8 (referee C1). That definition ignores that they come from different sponges,
so it is not used here; FS (03) treats them as separate queries.

The paper's bound is (168 + 553 n)/r: 4039, 6804, 7357, 7910 (n = 7, 12, 13, 14). It does not apply to this protocol; the difference is
2n - 6 in the numerator and arises as in section 7. Numerically immaterial, but the argument differs structurally
(sections 8.1 and 8.2).

## 2. Verifier moves

A move is one verifier sampling step, which in the deployed transcript is one squeeze run of one sponge between prover messages.
r (statement sponge) and the initial beta (main sponge) are therefore separate moves even though no prover message lies between
them. Elements are squeezes in the deployed transcript. Errors are numerators over r. The r row is listed per coordinate as an
accounting split (Lemma 2); as one move its error is L/r.

| Move | Count | Field elements | Error each |
|---|---|---|---|
| r (statement sponge), one move; split per coordinate | 1 (L) | L (1) | L (1) |
| beta initial | 1 | 25 | 1 |
| word SC rounds | L | 1 | 2 |
| bit SC rounds | 6 | 1 | 2 |
| iota SC rounds | 24 n | 1 | 3 |
| (x, y) | 24 | 2 | 1 |
| chi SC rounds | 24 n | 1 | 4 |
| beta for rho | 24 | 25 | 1 |
| rho SC rounds | 24 n | 1 | 2 |
| beta for theta | 24 | 25 | 1 |
| theta SC rounds | 24 n | 1 | 3 |
| bd | 24 | 5 | 1 |
| theta D SC rounds | 24 n | 1 | 3 |
| (bc, brc) | 24 | 10 | 1 |
| theta C SC rounds | 24 n | 1 | 6 |
| (b, ba) | 24 | 30 | 1 |
| theta A SC rounds | 24 n | 1 | 2 |
| beta between rounds | 23 | 25 | 1 |

## 3. Lemmas

**Lemma 1 (bit recomposition).** The map {0,1}^64 -> F, (b_0..b_63) -> sum 2^k b_k is injective.
Proof: its value computed in Z lies in [0, 2^64 - 1], and 2^64 < r, so distinct bit vectors give integers whose
difference is nonzero and below r in absolute value, hence nonzero mod r. QED.
This holds only for Boolean b_k. For field-valued b_k the map is far from injective: (b_0,b_1) = (2,0) and (0,1) collide.

**Lemma 2 (partial binding).** Let g be multilinear in (x_1..x_L) over F and not identically zero. For uniform rho,
g(rho, x_2, .., x_L) is identically zero with probability at most 1/r.
Proof: g = (1 - x_1) g_0 + x_1 g_1 with g_0, g_1 multilinear in x_2.., not both zero. Pick a monomial with coefficients
a_0, a_1 in g_0, g_1, not both zero. Vanishing requires (1 - rho) a_0 + rho a_1 = 0, a nonzero affine equation in rho. QED.

**Lemma 3 (RLC).** For a fixed nonzero vector delta in F^m and uniform kappa in F^m,
Pr[sum kappa_i delta_i = 0] = 1/r. Holds for any delta depending on anything sampled before kappa.

**Lemma 4 (sumcheck message encoding).** Fix c in F and d >= 1. The map (p_1..p_d) -> p(t) = p_0 + sum p_j t^j with
p_0 = (c - sum p_j) HALF is a bijection from F^d onto {p in F[t] : deg p <= d, p(0) + p(1) = c}.
Proof: HALF = 2^{-1} (HALF * 2 = 1 mod r, checked; char F is odd). p(0) + p(1) = 2 p_0 + sum p_j = c.
Conversely any such p has p_0 = (c - sum p_j) HALF, so it is the image of its own coefficients. QED.
Therefore omitting p(0) removes the check "p(0) + p(1) = c" by making it hold identically, and the set of polynomials that P
can express equals the set that would pass the check in the textbook protocol. Nothing is lost or gained; in particular P cannot
send a polynomial of degree above d, and c is bound into p through p_0.

**Lemma 5 (sumcheck round).** Let f be a polynomial on F^m of degree at most d in each variable, fixed before the sumcheck's first
challenge. For a prefix rho = (rho_1..rho_l) write S_l = sum_{b in {0,1}^{m-l}} f(rho, b), and g_{l+1}(t) = sum_b f(rho, t, b), a
polynomial of degree at most d with g_{l+1}(0) + g_{l+1}(1) = S_l. If c != S_l then for every message p as in Lemma 4 for c:
p != g_{l+1}, so Pr over rho_{l+1} [p(rho_{l+1}) = S_{l+1}] <= d/r.
Proof: p(0) + p(1) = c != S_l = g(0) + g(1), so p - g is nonzero of degree at most d. S_{l+1} = g(rho_{l+1}). QED.

## 4. True tables and identities

Fix the inputs. Section 5 of the spec defines all round tables as functions of `in`. Let T_i := Io^23_i (Boolean) and
Wt_i(j) := sum_b 2^b T_i(j,b). Write W_i(j) := sum_b 2^b out_i(j,b).

For Boolean inputs every table in the spec's section 5 is Boolean by induction, so XOR formulas agree with field formulas on
the hypercube: for a, b in {0,1}, xor(a,b) = a XOR b, (1-a)b = NOT a AND b, and (1-2a)(1-2b) = 1 - 2 (a XOR b).

Throughout, X~ is the multilinear extension, linear in X, and X~(z) = sum_{k in {0,1}^n} eq(z,k) X(k).

**Lemma 6 (identities).** For all values of the fixed parameters, as polynomial identities over the hypercube sum:

    I1  sum_{x in {0,1}^L} eq(r,x) sum_i beta_i Wt_i~(x)                          = sum_i beta_i Wt_i~(r)
    I2  sum_{y in {0,1}^6} pow~(y) sum_i beta_i T_i~(r_x,y)                        = sum_i beta_i Wt_i~(r_x)
    I3  sum_k f_iota(k)  [spec 6.1]                                                = sum_i beta_i Io_i~(alpha)
    I4  sum_k f_chi(k)   [spec 6.2]                                                = sum_i beta'_i Ch_i~(v1)
    I5  sum_k f_rho(k)   [spec 6.4]                                                = sum_i beta_i Rh_i~(v2)
    I6  sum_k f_th(k)    [spec 6.5]                                                = sum_i beta_i (1 - 2 Th_i~(v3))
    I7  sum_k f_d(k)     [spec 6.6]                                                = sum_x bd_x D^_x~(v4)
    I8  sum_k f_c(k)     [spec 6.7]                                                = sum_x (bc_x C^_x~(v5) + brc_x RC1^_x~(v5))
    I9  sum_k f_a(k)     [spec 6.8]                                                = sum_i (beta_i A^_i~(v4) + ba_i A^_i~(v6))

Proof. Each sum has k Boolean, where every ~ polynomial equals its table value and eq(z,k) is the MLE kernel.
- I1: MLE of Wt_i at r. I2: for fixed x, Wt_i(x) = sum_y pow(y) T_i(x,y). Both sum_y pow(y) T_i~(x,y) and Wt_i~(x) are multilinear
  in x and agree on Boolean x, and pow~(y) = pow(y) on Boolean y. So they agree at r_x.
- I3: on the hypercube xor(Ch_0(k), RC(k)) = Io_0(k) and Ch_i(k) = Io_i(k), i != 0. RC~(k) = RC(k) since RC~ is the MLE of a table
  independent of the instance coordinates (eval_mle on the last 6 coordinates; such a function is multilinear in all n).
- I4: Ch_i(k) is by definition the expression in Pi at k. beta' as in spec 6.2.
- I5: by the rot identity below, Rh_i~(v2) = sum_k rot_{rho[i]}(v2,k) Th_i(k).
- I6: Th^_i(k) = A^_i(k) D^_{i mod 5}(k), Th^_i~ = 1 - 2 Th_i~; group lanes by column.
- I7: D^_x(k) = C^_{x-1}(k) RC1^_{x+1}(k). I8: C^_x(k) = prod_y A^_{x+5y}(k); RC1^_x(k) = C^_x at (j, b-1), and the rot identity with s=1.
- I9: X~(v) = sum eq(v,k) X(k), with the theta beta scaled by b_x. QED.

**rot identity.** rot_s as evaluated (V:154-173, spec section 5) is multilinear separately in a and in c: the prefix factor is
multilinear in each; the suffix sum_u eq(a_s, u+s) eq(c_s, u) is a bilinear form in the eq kernels, multilinear in a_s and in c_s.
On Boolean a, c it equals 1 iff the instance parts agree and bit(a) = bit(c) + s mod 64: eq(c_s, u) selects u = bit(c), and
eq(a_s, u+s) = 1 iff bit(a) = u+s. So it is THE multilinear extension of the rotation predicate. For X with
Y(j,b) = X(j, b-s), rotl by s in LE bit order, for Boolean a: sum_c rot_s(a,c) X(c) = X(j, bit(a) - s) = Y(a). Both sides are multilinear in a, so the
identity holds on F^n. The call uses V:274-276 and V:352-354, where the suffix tables have 64 entries and `instances` is 1. QED.

**eq.** The factor 2 x y + 1 - x - y = x y + (1-x)(1-y). On Boolean inputs it is the equality predicate, and multilinear in each
argument, so it is the kernel eq(z,k).

**Lemma 7 (degrees).** Per variable, the summands have degree at most: word 2, bit 2, iota 3, chi 4, rho 2, theta 3, theta D 3, theta C 6,
theta A 2, equal to the DEGREE const in V:227, 246, 268, 294, 317, 346, 377 and V:597, 605.
Proof, counting per variable: every ~ polynomial and eq, rot, pow~, RC~ is multilinear. iota: eq * Ch_0~ * RC~ = 3. chi: eq * (Pi*Pi*Pi) = 4.
rho: rot * Th~ = 2. theta: eq * D~ * A~ = 3. D: eq * C~ * RC1~ = 3. C: (eq or rot) * five A~ = 6. A: eq * A~ = 2. word: eq * Wt~ = 2. bit: pow~ * T~ = 2. QED.
All are fixed before the sumcheck's first challenge: their parameters are the earlier point, the beta values, and the true tables.
The bound d/r per round is attained by a cheating prover, because V reads d coefficients, so p - g can have d distinct roots
(realized by the referee for every type, run E). It is not tight per round for the honest polynomial: the first L rounds of the
iota sumcheck (instance coordinates) have honest degree 2, since RC~ is constant in them. Each of the nine sumcheck types has some
round with nonzero top coefficient (section 10).

**Lemma 8 (Keccak correspondence).** With in Boolean, T = Io^23 satisfies T[.][j][.] = Keccak-f[1600](in[.][j][.]) per FIPS 202.
Proof: by inspection the spec's section 5 layers are FIPS 202 theta (C[x], D[x] = C[x-1] XOR rotl(C[x+1],1)), rho, pi, chi, iota for
rounds in ascending order t = 0..23, with A^{t+1} = Io^t, and lane index x + 5y, LE bit z. Constants, compared by exact generation:
ROUND_CONSTANTS[t] equals FIPS 202 Algorithm 5/6; RHO_OFFSETS[x+5y] equals Algorithm 2; strip_pi's map P satisfies
P((x+3y mod 5) + 5x) = x + 5y for all lanes, which is pi: A'[x,y] = A[x+3y, x]; add_col is (x+a, y). The verifier applies rounds backward:
for t in (0..24).rev() with ROUND_CONSTANTS[t] (V:621, V:628), so the claim on output reduces to Io^23 with RC[23], and round 0 ends at in.
Also confirmed end to end: the layer tables reproduce the native keccak crate and hashlib SHA3-256 (section 10). QED.

## 5. The state function

Let delta_i := W~_i - Wt_i~ (polynomials on F^L). A partial transcript tau is **doomed** iff either a verifier check has failed on tau, or the
condition for its position below holds. Each claim "z = true value" is evaluated with the true tables, which are determined by the statement.

Positions end at a verifier challenge. c denotes the running claim of the current sumcheck, f its polynomial, S_l as in Lemma 5.

| Position | Doomed iff (or a check failed) |
|---|---|
| start | statement false |
| after r_1..r_m (m <= L) | some delta_i(r_1..r_m, .) is not identically zero |
| after beta | sum_i beta_i delta_i(r) != 0 |
| word SC after l rounds | c != S_l(f_word) |
| bit SC after l rounds | c != S_l(f_bit) |
| iota SC after l rounds | c != S_l(f_iota) |
| after (x,y) | c != sum_k f_chi(k), c = beta'_0 chi_00 + y chi_rlc (i.e. S_0) |
| chi SC after l rounds | c != S_l(f_chi) |
| after beta for rho | c != S_0(f_rho) |
| rho SC after l rounds | c != S_l(f_rho) |
| after beta for theta | c != S_0(f_th) |
| theta SC after l rounds | c != S_l(f_th) |
| after bd | c != S_0(f_d) OR AI-false |
| D SC after l rounds | c != S_l(f_d) OR AI-false |
| after (bc, brc) | c != S_0(f_c) OR AI-false |
| C SC after l rounds | c != S_l(f_c) OR AI-false |
| after (b, ba) | c != S_0(f_a) |
| A SC after l rounds | c != S_l(f_a) |
| after beta between rounds | c != S_0(f_iota for t-1) |

where AI-false means: some ai_x != sum_y beta_{x+5y} A^_{x+5y}~(v4) with the theta beta.

Sumcheck rows are for l >= 1, and "S_0" rows describe the claim before a sumcheck's first challenge. The prover-only steps T3, T5, T6
have no position of their own: each folds into the next challenge move. The move from "after beta" to "word SC after 1 round" is
(s, p_1..p_2 of round 1, rho_1); from "word SC after L rounds" to "bit SC after 1 round" it is (wr, round-1 polynomial, rho_1); from
"bit SC after 6 rounds" to "iota SC after 1 round" it is (be, round-1 polynomial, rho_1). The deterministic part passes doom on with
no error (T3, T5, T6), then Lemma 5 gives the round's d/r. At L = 0 the word SC is empty and T3 and T5 both fold into the first bit
SC move.

This is the paper's "any unresolved claim is false" made exact. It differs from the naive statement in two ways that matter:

1. At iota the pending quantities are the two values. The condition carried into the (x,y) move (Claim T7) is
   (beta_0 (chi_00 - Ch_0~(v1)), chi_rlc - sum_{i != 0} beta_i Ch_i~(v1)) != (0,0), NOT "chi_00 is false". If beta_0 = 0 then chi_00 is simply unbound
   and false values for it are harmless. The naive definition fails RBR at that point; this was exercised (section 10, degenerate run).
2. ai_x are claims on column combinations. They are never decomposed to lanes, so the true value is an RLC, not 25 evaluations.

The state function is computable from the statement and the transcript in time poly(2^n) (fold the true tables). The prover's message only enters
through c and the openings.

Initial and final conditions:
- Start is doomed by hypothesis.
- After the last sumcheck of round 0, doom forces rejection (T14).

## 6. Transitions

In each claim, tau is doomed at the given position, and a is any prover message. "Escape" means the next position is not doomed.
The checks on tau failing means tau stays doomed forever, so assume all checks pass.

**T1 r coordinate. Error 1/r.** Doom gives a lane i with delta_i(r_1..r_m, .) not identically zero. Lemma 2 applies to that lane. Doom at the
position after m=L means some delta_i(r) != 0. At m = 0 this is the statement false: by Lemma 1 (Boolean out and Boolean T) W_i(j) != Wt_i(j) for some i, j, hence delta_i != 0 since the
MLE is a bijection from tables to multilinear polynomials. Here Lemma 8 is used to equate "out != Keccak-f(in)" with "out != T".

**T2 beta. Error 1/r.** Lemma 3 on delta(r). beta is sampled after r, and delta does not depend on any prover message.

**T3 sum. No challenge of its own; folds into the first word-SC move (section 5).** V computes E = sum_i beta_i W~_i(r) (V:588-593). If s != E, V rejects at V:595. Else c = E, and by I1
E - S_0(f_word) = sum_i beta_i delta_i(r) != 0.

**T4 sumcheck rounds. Error d/r.** Lemma 5 and Lemma 7. Carried AI-false never resolves in the D and C sumchecks, so if it holds no escape exists in those moves.
By Lemma 4 the prover's message is any polynomial of the form Lemma 5 requires.

**T5 word opening. No challenge of its own; folds into the first bit-SC move.** Doom: c != eq(r,r_x) * sum_i beta_i Wt_i~(r_x). V checks c = wr eq(r,r_x) (V:599-603). If it passes, then
wr != sum_i beta_i Wt_i~(r_x) = S_0(f_bit) by I2. If eq(r,r_x) = 0 then the true S_L is 0, c != 0, and the check fails, so this introduces no error.

**T6 bit opening. No challenge of its own; folds into the first iota-SC move of round 23.** Doom: c != pow~(r_y) sum_i beta_i T_i~(r_x,r_y). The check c = pow~(r_y) be (V:610-614) passing implies be != sum_i beta_i T_i~(alpha)
= sum_i beta_i Io^23_i~(alpha) = S_0(f_iota) by I3. pow~(r_y) = 0 is handled the same way.

**T7 iota opening and (x,y). Error 1/r.** Let d0 = chi_00 - Ch_0~(v1), d1 = chi_rlc - sum_{i != 0} beta_i Ch_i~(v1). The check at V:235-236 gives, using that
xor is affine in its first argument,

    expected - f_iota(v1) = eq(alpha,v1) ( (1 - 2 RC~(v1)) beta_0 d0 + d1 ).

Doom means ve != f_iota(v1), so a passing check forces (beta_0 d0, d1) != (0,0). The new claim satisfies

    c - S_0(f_chi) = x (beta_0 d0) + y d1                        (by I4 with beta'_0 = x beta_0, beta'_i = y beta_i)

a nonzero linear form in (x,y), which vanishes with probability exactly 1/r (Lemma 3).

**T8 chi opening, beta for rho. Error 1/r.** If pi is the true vector then the V:251-260 expression equals f_chi(v2) != ve, a failed check. So pi is false. strip_pi is a
permutation (Lemma 8) with Rh_i~(v2) = Pi_{P(i)}~(v2), so rho vector is false. Lemma 3, and I5.

**T9 rho opening, beta for theta. Error 1/r.** Same, with V:273-282 and I6. Base change is bijective on the vector: the difference vector of theta^ is -2 times that of theta, nonzero because 2 is invertible.

**T10 theta opening, bd. Error 1/r.** If all ai_x and d_x are true, the V:303-308 expression equals f_th(v4). So some are false. If an ai_x is false, the next position is doomed by AI-false, with no error. Otherwise some d_x is false, and Lemma 3 with I7 gives c != S_0(f_d) except with probability 1/r.

**T11 D opening, (bc, brc). Error 1/r.** AI-false persists if it holds. Otherwise c != f_d(v5) forces (c, rc) false, as the V:326-331 expression evaluates to f_d(v5) on true values, and Lemma 3 with I8 applies.

**T12 C opening, (b, ba). Error 1/r.** If a is true (and AI not false) the V:351-361 expression equals f_c(v6), so a failing check. Thus either AI-false or a false, i.e. the vector (ai - true, a - true) is nonzero. Then by I9, with beta'_{x+5y} = b_x beta_{x+5y},

    c - S_0(f_a) = sum_x b_x (ai_x - sum_y beta_{x+5y} A^_{x+5y}~(v4)) + sum_i ba_i (a_i - A^_i~(v6))

a nonzero linear form in the 30 fresh elements. Error 1/r by Lemma 3. AI-false is consumed here.

**T13 A opening, next beta. Error 1/r.** If all ah are true, the V:382-388 expression equals f_a(v7). So some ah_i is false; hence a_i = (1 - ah_i) HALF != A^t_i~(v7) (bijective base change). Lemma 3 and I3 for t-1, with A^t = Io^{t-1}.

**T14 end. Error 0.** At t = 0 as in T13 some a_i != A^0_i~(v7) = in_i~(v7). V:642-650 checks all 25 lanes individually against the directly computed in_i~(v7), so it rejects.

**Proof of Theorem 1.** Start is doomed. An accepting transcript has no failed check and, by T14, was not doomed at the last position. So there is a first move in which it left doom, an event of probability at most that move's error regardless of P*'s strategy, by the transitions above. Union bound over moves. QED.

## 7. Error table

| Source | Moves | Numerator |
|---|---|---|
| r | L | L |
| beta initial | 1 | 1 |
| word SC | L rounds, degree 2 | 2 L |
| bit SC | 6 rounds, degree 2 | 12 |
| iota, chi, rho, theta, D, C, A SC | 7 x 24 n rounds, degrees 3,4,2,3,3,6,2 | 24 * 23 n = 552 n |
| (x,y), beta rho, beta theta, bd, (bc,brc), (b,ba) | 6 x 24 | 144 |
| beta between rounds | 23 | 23 |
| Total | | 552 n + 3 L + 180 |

With L = n - 6 the total is 555 n + 162.

| n | r | beta | word | bit | main SC | RLC | total |
|---|---|---|---|---|---|---|---|
| 7 | 1 | 1 | 2 | 12 | 3864 | 167 | 4047 |
| 12 | 6 | 1 | 12 | 12 | 6624 | 167 | 6822 |
| 13 | 7 | 1 | 14 | 12 | 7176 | 167 | 7377 |
| 14 (production) | 8 | 1 | 16 | 12 | 7728 | 167 | 7932 |
| 8 (minimum) | 2 | 1 | 4 | 12 | 4416 | 167 | 4602 |

The n = 7 row holds but is unreachable with MIN_INSTANCES = 4.

Each over r = 2^253.6. Comparison with the paper: the paper charges n/r for alpha and 168 RLCs. Here r costs only L since alpha is produced by sumchecks, charged at 2L + 12, with beta 1 and 167 RLCs in rounds.

## 8. The points the paper does not cover

### 8.1 Output word-to-bit reduction

The paper has P reveal lane values at a random n-variate point. The code computes the word RLC itself and proves its relation to bit tables by two sumchecks. Argument: T1, T2, T3, T4, T5, T6 and I1, I2. The reduction claim is about the TRUE bit table T, never about `out`. `out` enters only through W in T3. So the transcript does not bind `out` bits beyond their word values.

Why recomposition cannot wrap, and what is needed: Lemma 1 needs both sides to be 64 Boolean values. The claimed side is Boolean as P1 of the spec, because `out` is `Boolean<Fr>`. The true side is Boolean because the inputs are. Then W_i(j) and Wt_i(j) are integers below 2^64 < r. No further range reasoning exists or is needed: from this point delta_i is treated as a field polynomial, and the sums, RLCs and MLE evaluations are mod r without any integer semantics. In particular there IS no statement of the form "the RLC does not wrap". Vectors delta in [-2^64, 2^64]^25 with sum_i beta_i delta_i = 0 mod r do exist for every fixed beta, by pigeonhole on 2^1600 >> r. That is what the singleton forgery used (beta_kernel_shift_is_rejected, V:775-795). What excludes them here is only the ORDER of moves: delta is fixed before r and beta. Hence the sponge's statement binding is load-bearing, see the note for 03 in section 11.

Booleanity is needed for:
- `out`: exactly Lemma 1 on the claimed side, so that word equality means bit equality. Without it word equality is all that gets proved: bit vectors with the same recomposition are not distinguished, and downstream consumers of the bits (B:101-103, the sponge) get forged bits. In the interactive argument no step other than T1 uses it.
- `in`: Lemma 8 and Lemma 1 on the true side. Without it, the statement must be restated, and the protocol then proves word equality with an arithmetized permutation:
  1. Layers are defined by the field formulas of spec section 5, with xor(a,b) = a + b - 2ab, NOT a = 1 - a and AND = product, for any field values.
  2. The hat identity (1 - 2a)(1 - 2b) = 1 - 2 xor(a,b) holds for all a, b in F (expand both sides). So C^ = prod_y A^, D^ = C^ RC1^ and Th^ = A^ D^ agree with iterated xor as field tables, and Lemma 6 holds for these tables with the same proof.
  3. The start condition becomes "W != Wt as field tables", in place of Lemma 1 and Lemma 8 at T1 (m = 0). T1 for m >= 1 and T2-T14 do not use Booleanity and hold unchanged.
  The relation proved is then: for all i, j, W_i(j) = sum_b 2^b R~(in)_i(j,b) in F, where R~ is the arithmetized 24-round map. That is word equality against R~(in), not a statement about Keccak-f or about bits. Numerically, setting one input bit to 2 yields an accepted run against that arithmetic word table, whose 1600 output table entries are all non-Boolean (section 10). The referee also ran a false word statement on non-Boolean `in`: rejected under a maximal lie and accepted only at an RLC root (rbr.md F2, F3). Input Booleanity is not enforced by any verifier step (T14 compares MLEs only), so it is a hard precondition on the caller.
- Outside the interactive argument, Booleanity of both `in` and `out` is also what makes the statement packing injective: each absorbed element is sum_k 2^k bit_k over 192 bits (spec section 3), injective on {0,1}^192 by the argument of Lemma 1, since 2^192 < r. Without it, distinct statements could absorb identically, and the ordering that T1 and T2 rely on would not survive Fiat-Shamir. 03 must use this.
- Neither is needed for intermediate layers: prover opening values are free field elements and no Booleanity of any intermediate is checked or assumed. Truth is defined from `in`.

Enforcement in the code read here: `Boolean::new_witness` adds (1-a) a = 0 (ark-r1cs-std 0.6.0 boolean/allocated.rs:182-225); `new_witness_without_booleanity_check` is not called in crates/ or experiments/ (grep). This has read-the-code strength; 05 owns it.

### 8.2 Reuse of beta scaled by x, y and b

Claim checked and proved: no fresh coefficients are required, with exact error 1/r, because the invariant is a single claim, and not a vector of lane claims.

Proof structure: T7 and T12. Three facts make it work.
(a) Lemma 5 needs only that f is fixed before its sumcheck's first challenge. Any coefficients, however correlated with past challenges, are permitted. beta' is fixed before chi's first round, and likewise the f_a coefficients.
(b) The true value of the new sum is exactly the same linear combination of the true lanes. So only the difference form in the fresh elements matters: x (beta_0 d0) + y d1, and sum_x b_x (ai_x - true) + sum_i ba_i (...).
(c) The lanes' individual truth was never pending. At iota the pending values are 2 elements, at theta 5 + 5. If a beta_i is 0, its lane is not in the claim at all.

The attempt to break it, which fails: take beta_0 = 0. Then chi_00 is unconstrained and P can send anything. But the new claim is 0 * x * chi_00 + y chi_rlc, and chi_00's lane has zero coefficient in f_chi. The lie about chi_00 reaches nothing. Executed: with beta_0 forced 0, chi_00 garbage, the protocol accepts a TRUE statement with no doomed event; see section 10. That event is thus not a soundness failure. However it does refute the naive state function that says "chi_00 false means doomed": it is the reason for the formulation in section 5.

Other degenerate attempts: beta_i = 0 for all i != 0, x = 0, y = 0, b_x = 0: any zero coefficient that loses a false value is exactly a root of the linear form charged 1/r in T7 or T12, or a coefficient making the lane absent from both the claim and truth.

For FS: T7 and T12 are statements about one linear form in the elements of a single move, so 03 can carry them as such, with no per-lane independence assumption.

### 8.3 p without p(0), using HALF

Lemma 4 and Lemma 5. HALF was compared to the exact inverse. Coefficient order and Horner were checked by reading V:186-197 and by replay against the native prover. Note that the removal of the check means failure of p(0) + p(1) = c cannot be detected, because it is impossible: every message defines a polynomial that passes.

### 8.4 Layer polynomials versus the verifier's formulas

Each verifier check evaluates the summand of Lemma 6 at the final point, given multilinear extensions of tables at that point. Lemma 6, the rot and eq paragraphs, and coordinate order (spec section 1) establish that these are the same polynomials. Note the two different objects called C^: the table's MLE C^_x~ (the opened claim) and prod_y A^_{x+5y}~ (the summand). Likewise Th^~, D^~, RC1^~. Sumchecks equate them over the hypercube only. Checked at random points: section 10, plus the native-prover replay at n = 7, 8, 12, 13, which confirms the coordinate order and every formula on genuine proofs, since a single misplaced index would reject.

Round order, rho offsets and pi: Lemma 8, by exact generation of constants from FIPS 202.

### 8.5 Padded instances and zero-round cases

Padding (B:39-49): recorded instances are extended by constant (0, Keccak-f(0)), up to next_power_of_two().max(MIN_INSTANCES), with MIN_INSTANCES = 4 deployed (CR-1; 2 at cc59207).
- Theorem 1 applies to the padded batch as a statement. A false recorded instance makes the padded statement false: delta is nonzero regardless of the other instances, since multilinear polynomials are determined by tables. So padding neither weakens nor needs anything special. Padded entries contribute delta = 0 at their positions.
- The argument uses nothing about padded instances except that they are Boolean. If native keccak::f1600 were wrong, the padded statement would be false and honest proofs would fail, a completeness issue only. It matches (section 10).
- (h = 2, unreachable with MIN_INSTANCES = 4, kept as a fact.) r = 1 with h = 2 and only instance 0 false is a real root of delta (x_1 = 1), charged at T1. Run in section 10: it accepts a false statement. With only instance 1 false the root is x_1 = 0. Both are the expected 1/r events.

Zero rounds: with L >= 2 (deployed, MIN_INSTANCES = 4), every sumcheck has at least 1 round: L >= 2, 6, n >= 8, and the prefix L >= 2. So no zero-round sumcheck or empty eq is reachable. This already held at L >= 1.
- Theorem 1 with L = 0 also holds as written, for the interactive protocol (unreachable in deployment, kept as a fact): r is empty, delta is a vector of constants, the word SC has no rounds and wr = s, with numerator 3492. Run in section 10 (honest accepted, lying rejected).
- So neither MIN_INSTANCES = 2 nor the deployed MIN_INSTANCES = 4 is an interactive requirement; CR-1's reason is the FS proof (03). The singleton forgery was a Fiat-Shamir failure: with L = 0 nothing about the statement enters the main transcript, so beta was fixed before the statement, breaking the premise of T2 and of Lemma 3's order. MIN_INSTANCES plus the statement sponge exist to restore that order under FS.
- t = 0: no RLC follows. T14 is a direct 25-lane comparison, so there is no 24th between-round error.

## 9. Attempts to break it

Each was tried, with the result:

1. Run a maximal lie, adjusting one opening per stage to satisfy each check. Rejected only at the input lanes, with state function doomed at all 171 stage events. So no intermediate check catches a lie and none needs to; only the final input check catches it. Repeated with four seeds at L = 1.
2. Force each challenge event and continue honestly. In 19 runs covering all 18 move types of section 2 (theta A's RLC twice, by lying through a and through ai), a chosen challenge (root of the error) makes a false statement accept. This shows the accounted events are real, and that the state function flips exactly there. It also shows no event was accounted vacuously.
3. Hypothesis: beta reuse creates a linear dependence across stages or rounds that a prover could exploit. Refuted: at each round boundary beta is fresh (V:631-637), and within a round the only reuses are chi (T7) and theta A (T12). The word reduction and round 23's iota reuse beta with no fresh mix; there it is a single claim on the same combination at successive points (I1, I2, I3).
4. Correlated points: v4, v6 could coincide; f_a remains a valid fixed polynomial. eq values at points may vanish (T5). None affect the argument, since no division by a challenge-dependent value occurs on V's side (HALF is constant).
5. Unused prover value: every read value enters a check or a later claim (chi_00, chi_rlc; pi; theta; ai; d; c; rot_c; a; iota). Round 0's iota enters T14.
6. Aliased coordinates between word tables and bit tables: r is MSB-first over j, r_x prefix is MSB-first over j. Consistent; confirmed by replay.
7. Degree overrun: a degree-6 message count against the summand of theta C. Fine (Lemma 7), and a prover cannot exceed degree anyway (Lemma 4). The honest polys were tested for degree bound at d+1.
8. Mid-round beta mutation: beta_0 *= x occurs after iota's check (V:235, V:240), and theta's beta is unmodified until 6.8. Confirmed in code; no stale value.

None produced a break.

## 10. What was run

Scripts in scripts/protocol/ (Python 3.14, `nix shell nixpkgs#python3`). kc.py parses the constants from verifier.rs itself, so a constant change would show.

- t_fips.py: ROUND_CONSTANTS, RHO_OFFSETS and strip_pi map are equal to exact generation from FIPS 202 Algorithms 2, 5, 6 and the pi rule.
- t_identities.py: layer formulas reproduce the f(0) vector and hashlib SHA3-256 at six lengths. HALF * 2 = 1. eq, eval_eq, eval_mle agree. rot, as evaluated, equals brute-force MLE of the predicate and the rotl identity, for all 25 offsets at L = 1,2,3, at random points; multilinearity of rot per coordinate (second differences). Recomposition identity I2 at random points.
- t_schedule.py and dump/ (Rust, against the pinned gkr crate, with r derived by a copy of derive_r_native): the read/generate schedule of the spec model gives counts 6809, 7363, 9579, 10133 = 6255 + 554 L, and consumes exactly the proof.
- t_replay.py: a real native-prover proof, replayed through the spec model's verifier, with the real Fiat-Shamir challenges, at n = 7, 8, 12, 13: accepted, with the schedule matching. 30 random tampers and a flipped output were rejected. This is what upgrades 01-spec.md from reading the code to checked against genuine proofs of the upstream prover. It is NOT a check of the R1CS; 05 owns that.
- t_run.py, using an independent model prover with uniform challenges:
  - honest at L = 0, 1, 2: accepted; 0 of 171 state events doomed. Degree bound at d+1 asserted in every sumcheck round; top coefficient nonzero in some round of each of the nine sumcheck types (not in every round; see Lemma 7).
  - lying (constant shift plus opening solve) at L = 0, 1, 2, and four seeds at L = 1: rejected at the first input lane, 171 of 171 doomed.
  - beta_0 = 0 with garbage chi_00 on a true statement: accepted, 0 doomed.
  - non-Boolean input (one bit set to 2): accepted against the arithmetic word table; 1600 non-Boolean output table entries.
  - forced escape at each of: r, beta0, word, bit, iota, xy, chi, beta_rho, rho, beta_theta, theta, beta_d, theta_d, beta_c, theta_c, b_ba (via a), b_ba (via ai), theta_a, beta_next, at L = 1; four of those at L = 2. L = 1 is unreachable with MIN_INSTANCES = 4; the L = 2 runs are at the deployed minimum. Each: false statement accepted, state undoomed from the escape on and doomed before it, and honest thereafter.

These numeric checks support the lemmas. They do not substitute for them.

## 11. What this does not establish

No GAP in the interactive argument. The theorem has these premises, which others must discharge:

1. Challenges uniform and independent, and the statement fixed before the first challenge. FS and the sponge: 03, 04. Because the main transcript's only link to the statement is r (V:584-586), all of T1-T2's ordering rests on it. Sample attack shape to exclude in 03: any (r*, beta(r*)) admits short word differences delta(r*) in the kernel of beta; what stops the singleton forgery recurring is only that such a statement must then hash to that r*.
2. R1CS constraints equal this spec, and every recorded permutation reaches a batch whose finish runs: 05.
3. Input and output Booleanity at the circuit level: read here (section 8.1), owned by 05.

Deliverables used for FS: the move table of section 2, the state function of section 5, and the fact that it is computable from statement and transcript in time poly(2^n).
