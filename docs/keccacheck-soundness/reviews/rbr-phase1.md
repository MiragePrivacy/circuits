# Phase 1 (blind): round-by-round analysis of the Keccacheck verifier

Sources read: `experiments/keccacheck-arkworks/src/verifier.rs` at cc59207, upstream `keccacheck_og/{verifier,prover}.rs`
and `sumcheck/*` at 15f00e3, paper 2025/1764. `docs/` not opened at the time of writing.
Scripts: `review/model.py`, `review/p1_identities.py`, `review/p1_nonbool.py`.

Notation. h = 2^L >= 2, n = L + 6, F = BN254 Fr, r = |F|. Tables are indexed k = instance*64 + bit; the first L sumcheck
variables are the instance index (MSB first), the last 6 the bit index (MSB first). A lane index is i = x + 5y.
For a table T, T(z) means its MLE. T^ = 1 - 2T pointwise; on MLEs T^(z) = 1 - 2T(z).

## 1. What each sumcheck claims, and differences from the paper

Let `in`, `out` be the statement (25 lanes, h instances, 64 bits). Let T be the trace of Keccak-f on `in`:
A^t, C_x = XOR_y A_{x+5y}, D_x = C_{x-1} XOR rotl(C_{x+1},1), Th_i = A_i XOR D_{i%5}, Rho_i = rotl(Th_i, off_i),
Pi_{dst} = Rho_{src(dst)}, Chi_i = Pi_i XOR (not Pi_{i+1}) and Pi_{i+2} (same row), Iota_0 = Chi_0 XOR RC, Iota_{i>0} = Chi_i.

Output reduction:
- W_i(x) = sum_y 2^y out_i(x,y) over instance bits. V computes `expected = sum_i beta_i W^out_i(r)`, reads `sum`, enforces equality.
- Words sumcheck, L rounds, degree 2: sum_x eq(r,x) * sum_i beta_i W^T_i(x). Ends with claim `words_r_x` for sum_i beta_i W^T_i(r_x). Check `c1 = words_r_x * eq(r,r_x)`.
- Bits sumcheck, 6 rounds, degree 2: sum_y pow(y) * sum_i beta_i O_i(r_x,y) where O = Iota^23. Ends with `bit_eval` for sum_i beta_i O_i(r_x,r_y). Check `c2 = pow(r_y) * bit_eval`.
- alpha = r_x || r_y. Same `beta` goes into round 23.

Round t (alpha, beta, s), s claiming sum_i beta_i Iota_i(alpha):

| Stage | Degree read | Polynomial F(k) | Claims sent after last challenge rho | V's check |
|---|---|---|---|---|
| iota | 3 | eq(alpha,k) [beta0 xor(Chi_0(k),RC(k)) + sum_{i>=1} beta_i Chi_i(k)] | chi_00 for Chi_0(rho), chi_rlc for sum_{i>=1} beta_i Chi_i(rho) | eq * (beta0 xor(chi_00, RC(rho)) + chi_rlc) = ve |
| chi | 4 | eq(rho_iota,k) sum_i beta'_i chi(Pi)(k), beta'_0 = x beta0, beta'_i = y beta_i | pi_i for Pi_i(rho) | eq * sum beta'_i chi(pi) = ve |
| rho | 2 | sum_i beta_i rot_{off_i}(rho_chi,k) Th_i(k), fresh beta | theta_i for Th_i(rho) | sum beta_i rot_i theta_i = ve |
| theta | 3 | eq(rho_rho,k) sum_j D^_j(k) sum_y beta_{5y+j} A^_{5y+j}(k), fresh beta | ai_j for sum_y beta_{5y+j} A^(rho), d_j for D^_j(rho) | eq * sum d_j ai_j = ve |
| d | 3 | eq(rho_th,k) sum_j beta_d,j C^_{j-1}(k) rotC^_{j+1}(k) | c_j, rot_c_j | eq * sum beta_d,j c_{j-1} rot_c_{j+1} = ve |
| c | 6 | sum_j (beta_c,j eq(rho_d,k) + beta_rc,j rot_1(rho_d,k)) prod_y A^_{5y+j}(k) | a_i for A^_i(rho) | sum_j (...) prod a = ve |
| a | 2 | sum_i (b_{i%5} beta_i eq(rho_th,k) + beta_a,i eq(rho_c,k)) A^_i(k) | iota^_i for A^_i(rho) | sum_i (...) iota^_i = ve |

Reduction identities, each an equality of polynomials in z for trace tables that are Boolean on the cube:
- Iota_i(z) = sum_k eq(z,k) Iota_i(k), and Iota_0(k) = xor(Chi_0(k),RC(k)) on cube points.
- Chi_i(z) = sum_k eq(z,k) chi(Pi)(k) because chi(a,b,c) = a xor ((1-b)c) is exact on bits.
- Pi relabels: `strip_pi` of Pi evaluations is Rho evaluations.
- Rho_i(z) = sum_k rot_off(z,k) Th_i(k) with rot_off(z,k) multilinear in k and equal to eq(z, k+off in block) on cube k.
- Th^_i(z) = sum_k eq(z,k) A^_i(k) D^_{i%5}(k), since hat of xor is the product of hats.
- D^_j(z) = sum_k eq(z,k) C^_{j-1}(k) rotC^_{j+1}(k), with rotC_j the table of rotl(C_j,1).
- C^_j(z) = sum_k eq(z,k) prod_y A^_{5y+j}(k), rotC^_j(z) = sum_k rot_1(z,k) prod_y A^_{5y+j}(k).
- A^ at two points is reduced to one by the theta_a sum.

Checked at random points on real traces (rounds 0, 11, 23; h = 2, 4), both sides computed directly. Trace from an independent FIPS 202
implementation (validated against hashlib.sha3_256); RC, RHO_OFFSETS, PI and the strip_pi walk in `verifier.rs` compared to values
derived from the FIPS LFSR, rho walk and pi map. Empirical per-variable degrees of F: 3, 4, 2, 3, 3, 6, 2.

Departures from the paper:
1. Iota sumcheck does not end with 25 chi claims. It sends only chi_00 and an RLC chi_rlc, then scales old beta by (x, y) rather than
   sampling fresh beta (paper 2.2.2 samples new).
2. Theta sends ai_j (column RLC) rather than 25 A^ claims. It pends through two sumchecks and is merged in theta_a, reusing beta scaled by b_j.
3. Output is at word level (paper: evaluation of bit MLE at alpha). Extra L rounds + 6 rounds.
4. First `beta` is shared by word reduction, bit reduction, and iota of round 23.
5. r, beta drawn before the first message and r squeezed from a sponge over the statement (paper: commitment to the output).
6. rot_C is claimed independently of C rather than derived.
7. Final check is lane by lane, so there is no RLC after round 0. 23 between-round RLCs, not 24.

## 2. State function

Truth is relative to T, the trace of the stated Boolean `in`. A transcript that has failed any check is doomed forever.

Otherwise it is doomed iff one of these holds:

(a) Current sumcheck claim e differs from the true partial sum: e != sum_{b} F(rho_prefix, b).
(b) A pending weighted claim is false, where pending items are:

| After | Pending items (weight, claim - truth) |
|---|---|
| statement | out != Keccak-f(in) |
| r | exists i: W^out_i(r) != W^T_i(r) |
| beta_out | sum beta_i (W^out_i - W^T_i)(r) != 0 (that is (a) for the words sumcheck) |
| iota claims | (beta0, chi_00 - Chi_0(rho)), (1, chi_rlc - truth) |
| chi claims | (1, pi_i - Pi_i(rho)) |
| rho claims | (1, theta_i - Th_i(rho)) |
| theta claims | (1, ai_j - truth), (1, d_j - truth) |
| d sumcheck | (a) plus pending (1, ai_j - truth) |
| d claims | ai pending, plus (1, c_j - truth), (1, rot_c_j - truth) |
| c sumcheck | (a) plus ai pending |
| c claims | ai pending, plus (1, a_i - truth) |
| a claims | (1, iota^_i - truth) equivalently A_i |
| round 0 end | any lane differs from in_i(alpha): V rejects |

The beta0 weight in the iota row is required: with beta0 = 0, a false chi_00 has no effect on anything later, not on the iota check and not on the
chi claim `x beta0 chi_00 + y chi_rlc`. A state function that calls this doomed has a doomed to undoomed exit with probability 1, conditional on an earlier
beta0 = 0, which the (x,y) move cannot absorb. Run in `p1_nonbool.py` case D: beta0 = 0 at round 20, chi_00 lied about by 12345, V accepts, refined
definition never doomed, unweighted definition doomed at that one state. Same lie with beta0 != 0 rejects at the iota check (case E).

Moves, with zero cases:

- Sumcheck round, challenge c, prover polynomial g of degree <= d with g(0)+g(1) = e (structural: p0 is derived). True G has degree <= d. If doomed by (a), g != G, so Pr[g(c) = G(c)] <= d/r. c = 0 or 1 is not special. Verified the bound is met with equality by forced roots to be done in Phase 2.
- Claims message after the last challenge: no randomness. If ve != F(rho) and the check passes, then the weighted claims must differ from truth, so doom is preserved whatever the eq or rot factor is. If eq(..) = 0 or rot = 0 or pow(r_y) = 0 or RC(rho) = 1/2, F(rho) has no dependency on that claim, and the check forces nothing about it; the claim is then free but if false the state is doomed by (b). If ve = F(rho) and the prover lies, it dooms itself. In all cases no exit from doom.
  In the iota check, the difference is eq * (beta0 (1 - 2 RC(rho)) delta_00 + delta_rlc), so if ve != F(rho) then (beta0 delta_00, delta_rlc) != 0 and the weighted state is doomed.
- (x,y): new claim minus truth is x beta0 delta_00 + y delta_rlc. Nonzero linear form on (x,y) if weighted state is doomed; zero with probability 1/r. x = 0 kills only the first term and y = 0 only the second. Both are ordinary roots.
- beta RLC at chi, rho, theta (hat map is a bijection since char != 2), d, c: a nonzero linear form vanishes with probability 1/r. A zero coordinate in beta is an ordinary root.
- (b, beta_a): sum_j b_j delta_ai,j + sum_i beta_a,i delta_a,i. All coefficients fresh. 1/r. New true sum is consistent since truth of ai_j is sum_y beta_{5y+j} A^(rho_th) and new weight b_j beta_{5y+j}.
- Pending ai during d and c sumchecks: truth is fixed at rho_th, unaffected by these moves. Doom via ai is permanent until the (b,beta_a) move; those sumcheck challenges do not cause exit when ai is false.
- Next round beta: 1/r. Truth for Iota^{t-1}(r_a) is A^t(r_a).
- Output: r: fixed nonzero lane difference polynomial of degree 1 per variable, L/r. Since W are integers below 2^64 < p and `out` is Boolean, out != Keccak-f(in) implies W^out != W^T as field tables. beta: 1/r.
- Final lanes: if any A claim false at round 0, the matching check fails, no error.

Reuse and cancellation:
- Scaling beta by (x,y) is a two-coefficient linear form; it does not allow cancellation beyond the root. The prover commits to both deltas before x,y.
- ai_j and a_i: prover commits to both before (b, beta_a); same.
- Prover may choose a_i knowing ai errors and may pick d_j, ai_j so that sum d_j ai_j hits ve; this just splits an error among claims. No claim false can be repaired except via a root.
- Reusing beta between output and round 23: the iota claim is a single scalar relation for that same beta. No gain.
- The state only tracks the claims, not whether earlier layers were false. If an RLC or sumcheck root occurs, all subsequent claims are true claims about T and V accepts. This is the exit event, which is counted.

## 3. Count

| Move | Count | Error numerator |
|---|---|---|
| r (L field elements) | 1 | L |
| beta_out | 1 | 1 |
| words sumcheck | L rounds, deg 2 | 2L |
| bits sumcheck | 6 rounds, deg 2 | 12 |
| round: iota, chi, rho, theta, d, c, a | n rounds each, deg 3,4,2,3,3,6,2 | 23n |
| round: (x,y), beta_rho, beta_theta, beta_d, beta_c, (b,beta_a) | 6 | 6 |
| between rounds | 23 total | 23 |

Output part 3L + 13 = 3n - 5. Rounds 24 * (23n + 6) + 23 = 552n + 167.
Total **(555n + 162)/r**. L = 8, n = 14: 7932/r, about 2^12.95 / 2^253.6 = 2^-240.6.

Note on tightness: for instance variables F in iota has degree 2 (RC constant) and F in other stages can be lower than read degree, but V reads
d coefficients in every round, so g - G can have degree d. The per-move bound is the read degree.

Per-move maximum (for Fiat-Shamir style bound): 6/r on sumcheck moves (L/r for the r vector when L > 6, unless split coordinate by coordinate).
The sum above is the interactive bound; RBR requires the per-move numbers.

## 4. What must be true of the statement

- p > 2^64 and char != 2 (HALF, word injectivity).
- `in`, `out` Boolean, h = 2^L, L >= 1 (`MIN_INSTANCES`), lane/instance/bit layout as used.
- The verifier's equations themselves supply no Booleanity of `in` or `out`.
  - Non-Boolean `in`: the trace is well-defined over F by the arithmetized formulas, and identities hold pointwise. V accepts `out` equal in words to the arithmetized image (run: case A). Hence the equations establish words(R~^24(in)) = words(out), R~ the arithmetized round. This equals Keccak-f only if `in` is Boolean.
  - Non-Boolean `out`: V reads only words. Boolean `in` and output bits altered by (bit_j + 2, bit_{j+1} - 1) accepted (run: case B). So output Booleanity is what gives uniqueness of the bit decomposition.
  - Both are supplied by `Boolean<Fr>` in `verify_boolean_batch` / `Boolean::new_witness`, ark-r1cs-std allocated with a booleanity constraint, or by constants.
- Relation at the end: for each instance, out = Keccak-f(in), with error above. With challenges uniform and statement fixed first.
  The Fiat-Shamir step and the Poseidon2 sponge are outside this interactive claim.
