# Phase 1 (blind): Fiat-Shamir bound for the two-chain transcript

Written before opening docs/keccacheck-soundness/.
Sources: crates/keccacheck/src/{verifier.rs,poseidon2.rs} at cc59207, upstream
rust/gkr/src/transcript/, ePrint 2025/536 (Chiesa-Orru, March 2026 text).

## 0. The transcript as read from code

Sponge: state in F_p^16, rate slots 0..9, capacity 10..15, one index `idx`, flag `dirty`.
- absorb(v): if idx<10 {s[idx]+=v; idx++} else {s=P(s); s[0]+=v; idx=1}; dirty=true.
- squeeze: if dirty or idx>=10 {s=P(s); idx=0; dirty=false}; return s[idx++].
Absorb after squeeze continues at the squeeze index; earlier slots are carried unchanged ("locked").

Statement chain H_L(S), S=(I,O) in ({0,1}^64)^{2*25*2^L}: IV; absorb tag; absorb 2^L; absorb
2*ceil(25*2^L/3) packed values <2^192; squeeze L elements.
Absorbs/perms: L=1 36/4, L=2 70/7, L=8 4270/427. Length is a function of L and L is in slot 1 of
block 1; packing is injective (<2^192<p). So S -> message is injective and prefix-free across L.
Trailing-zero/padding ambiguity is excluded only by this fixed length.

Main chain from root x in F_p^L: the SAME IV; absorb x_1..x_L into slots 0..L-1; squeeze 25 beta; read
`sum`; and so on. Root query: rho(x):=P(IV_R+(x,0^{10-L}), IV_C). The map x->rho(x) is injective.
r enters only through this root and through eval_eq(r), eq(r,r_x). Nothing else of S enters the main
chain: `expected_sum = sum_i beta_i O_i(r)` and the final input check are verifier-side comparisons,
and beta is squeezed from x alone. `sum` is a prover message absorbed AFTER beta.

Hence beta and all later challenges are functions of (x, prover messages), not of S.

## 1. Is any Chiesa-Orru theorem applicable? No.

Theorems 5.1/6.1/6.2 are about NARG=DSFS[IP,cdc,delta] of Construction 4.3. Mismatches, most to least
important:
(a) Binding. In DSFS the instance reaches the sponge as s_C=h(x) in Sigma^c with h a random function
    independent of p, and all later challenges descend from that capacity. Its error is t^2/|Sigma|^c.
    Here the instance reaches the main sponge through L RATE elements, absorbed into a fixed-capacity
    root. The binding function has range p^L, not p^6. No choice of "x" in DSFS gives a capacity
    carrying S. The whole gap is the term landing on p^-L in section 2; for L=1, t=2^128, collisions
    in that binding function are expected.
(b) The two chains cannot be read as one DSFS. Reading S as a first prover message and r as the first
    verifier message would need the next absorption to continue that sponge; the deployed main chain
    discards the statement chain's capacity and restarts from IV. Reading r as the salt tau of a DSFS
    with empty instance makes the instance empty, so "false statement" is not defined for it: Def 3.5
    has a single x fed to V and to Start.
(c) No h. Start is a fixed constant shared by both chains; Definition 4.2 needs h random and
    Construction 3.3 needs rate 0^r at start.
(d) Additive absorb versus overwrite. Footnote 4 says the analysis "can be adapted"; no theorem is
    stated. Additive absorption is not a fixed codec on overwrite mode: the overwritten value would be
    state+m, which is state-dependent, while Definition 4.1 asks for fixed phi_i.
(e) Index handling. Construction 3.3 resets i_A:=0 on squeeze; deployed absorb continues at idx
    with locked slots. Different mode, again no theorem.
Not mismatches: codec bias is 0 (field-native, identity); the paper's adversary already has inverse
queries; Def 3.5 is adaptive in x.
Conclusion: the capacity-graph technique of the paper transfers and I reuse it below, but the deployed
construction is not an instance of any stated theorem. A direct proof is needed.

## 2. Theorem

Notation. p=|F_r|, log2 p=253.597. T=t+ell, ell the verifier's P-calls (append V's queries to the trace;
ell<2^12 at L=8). T_s: queries acting as final statement edges, T_m: queries acting as main-chain nodes.
A query with both roles is charged to both; see "Dual role". S_L is the statement universe,
|S_L|=2^{3200*2^L}. eps=2T/p^16.

Theorem. For k>=1, m>=0 and any (possibly computationally unbounded) t-query adversary with P and P^-1,
adaptive in S, with win = outputs (S,pi), V accepts, S false:

  Pr[win] <= (1+eps) [ T^2/p^6                       (CAP)
                     + T_s*L/p                        (R)
                     + T_s*min(m, T_m)/p^L            (EARLY)
                     + k*6*T_m/p ]                    (LATE)
             + C(T_s,k+1)/p^{Lk}                      (MC)
             + |S_L| * C(T_m,m+1) * (6(1+eps)/p)^{m+1}  (TAIL; drop if min takes T_m)

Black box. For false S and x, a state function sigma(S,x,prefix) with:
- initial state at (S,x): non-doomed iff Delta_S(x)=0, where Delta_S(x)=(Delta_i(x))_{i<25},
  Delta_i(x)=sum_j eq_x(j)(O_ij-f(I_j)_i). Words are <2^64<p so Delta_S is a nonzero polynomial vector
  for false S. This is the r-part of the first move split off explicitly; the given black box treats
  r,beta as one degree L+1 move, and the split is Schwartz-Zippel: Pr_r[Delta_S(r)=0]<=L/p, then
  Pr_beta[..]<=1/p.
- every later move: for ANY fixed x, doomed->non-doomed with prob <=d/p per query (d<=6), and an
  accepting complete transcript is non-doomed.
The bound for later moves must hold per fixed x, not random x, because x is adversarial in the main
chain. It does: eq(r,.) has the same degree for every r, beta-linearity needs only Delta_S(x)!=0,
sumcheck errors do not use the distribution of r. (Assumption checked by inspection of
verify_allocated, not reproved.)

### Proof

Step 1, capacity graph. E_cap: a fresh query's answer has output capacity (forward) or input capacity
(inverse) equal to IV_C or to a capacity seen before (in or out), including the query's own other side.
j-th fresh answer: <=2j+1 forbidden capacity values, each with mass <=p^10/(p^16-j).
Sum_j <= T^2/p^6 (1+eps).

Under not E_cap:
(i) Each non-IV capacity has a unique producing edge; a path from IV_C is unique. A query input lies on
    at most one path to the root.
(ii) Every edge on a path from IV_C was first made forward, and the edges were made in path order.
    If e_{i+1} (input capacity C) precedes e_i (output capacity C), the answer of e_i hits a seen
    capacity. If an edge was made by inverse, its input capacity was its answer, and on a path that
    capacity is IV_C or the output capacity of some edge made earlier or later: a hit each way.
    So inverse queries are never on any chain and output values on chains are forward answers.
    An inverse query cannot choose r or beta without returning a usable capacity, already in E_cap.
(iii) Parsing. Given a path from IV_C, the statement parse (fixed L, unique message) and the main parse
    (root slots L..9 equal IV_R, unique x, then fixed layout) are each unique. Rate slots outside the
    absorb window must equal the parent, otherwise the edge is on no valid parse. An edge may have both
    parses only if the root rate equals IV_R+(tag,2^L,m_3..) and IV_R+(x,0..): impossible at L=1 (slot 1
    is 2^L vs 0); for L>=2 this forces x_1=tag, x_2=2^L and zero tail words.

Dual role. No event is needed: each of R, EARLY, LATE is a union over per-answer probabilities, and one
answer may be charged in several. The bound holds with T_s+T_m>T. For numbers I exclude the event
"some H output has x_1=tag, x_2=2^L", prob<=T p^-2=2^-379 at L>=2 and impossible at L=1, and then take
T_s+T_m<=T for the queries that matter.

Step 2, H. For false S, the final edge of S's chain is the unique edge returning x=H(S). By (ii) it is
forward, made once, at a time tau(S), and S is fully determined by the query input at that time; earlier
words may depend on earlier outputs but are fixed by then. So every S gets exactly ONE draw of x. x is
the first L rate slots of the answer; its density is <=(1+eps)p^-L at every point. V's queries are
included, so an adversary who never queried the statement chain still gets one draw per output S.
Two distinct S have distinct final edges with different output capacities, so H(S)=H(S') only through
a rate coincidence, p^-L per pair.

Step 3, exhaustive decomposition. Assume win and not E_cap. Let (S,pi) be the output, x=H(S).

R: Delta_S(x)=0. Pr per final edge <=L p^{L-1}/p^L=L/p. Union over T_s final edges.

Otherwise the initial state is doomed and the final state non-doomed, so the verifier's path contains a
flip edge e*, first edge at which sigma(S,x,.) is non-doomed. By (ii) it was made forward. Then
EARLY: e* precedes or equals tau(S). LATE: e* follows tau(S).

EARLY. Lucky_tau(S) := { x' notin Z(Delta_S) : root(x') has a node at time tau, non-doomed for S }.
EARLY means H(S) in Lucky_{tau(S)}(S). Conditional on history before tau(S), Pr<=|Lucky(S)|(1+eps)/p^L.
 - Crude: |Lucky|<=T_m. Gives T_s T_m/p^L; vacuous at L=1 for t=2^128 (2^{2.4}).
 - Refined. For FIXED S, each main-tree answer flips with conditional prob <=6(1+eps)/p whatever the
   adversary does, and each x' enters Lucky(S) by one flip. So
   Pr[|Lucky(S)|>m] <= C(T_m,m+1)(6(1+eps)/p)^{m+1} (union over index sets, chain rule).
   Union over the FIXED universe S_L; the set is not chosen after randomness. That is TAIL.
   Then per final edge: Pr <= m(1+eps)/p^L.
 The false S here may be selected after seeing beta(x) and the whole tree. This is real: fix x, query
 rho(x) to get beta(x), find by lattice reduction a false (I,O') with sum_i beta_i(x)Delta_i(x)=0, and
 keep drawing H on fresh kernel vectors; each draw succeeds w.p. p^-L and on success an honest proof for
 (I,f(I)) with r=x verifies. So t*p^-L is a lower bound on any correct EARLY term, for all L, and it
 is polynomial-time. The term is not an artefact.

LATE. At e*, S is in K_x(e*) := {S': H(S')=x, tau(S')<e*} and sigma(S,x,prefix) was doomed. Each query
is on one path by (i), thus one x. Per answer: Pr[flip for some S' in K_x] <= |K_x|*6(1+eps)/p. This is
where a query serves several statements: same r, same main state, same query, for all of K_x.
MC: |K_x|>k for some x needs k+1 statements with same r, Pr<=C(T_s,k+1)p^{-Lk}.
Thus T_m k 6(1+eps)/p.

E_cap, R, EARLY, LATE, MC, TAIL cover win. QED.

Case map asked for:
- statement chosen after permutation outputs: step 2 (one draw per S), EARLY (S after tree).
- inverse queries: E_cap and (ii).
- capacity collisions: E_cap, T^2/p^6.
- main-chain state from two statements with same r: LATE with MC, the k factor.
- query landing on main root without statement chain: EARLY with x picked first; nothing relates main to
  statement before tau(S). V's own chain queries count.
- small L: crude EARLY vacuous only at L=1; L=1 needs the refined term and k=2.

## 3. Numbers, t=2^128 (log2 p=253.597)
Script: review/fs_scripts/nums1.py.

Term                        L=1           L=2          L=8
CAP T^2/p^6                 2^-1265.6     2^-1265.6    2^-1265.6
R T L/p                     2^-125.6      2^-124.6     2^-122.6
EARLY crude T^2/p^L         2^+2.4        2^-251.2     2^-1772.8
EARLY refined m T/p^L       m=51 2^-119.9 unused       unused
LATE k*6T/p                 k=2 2^-122.0  k=1 2^-123.0 k=1 2^-123.0
MC                          k=2 2^-125.8  k=1 2^-252.2 k=1 2^-1773.8
TAIL (m tuned)              <=2^-128      none         none
Total (T_s+T_m<=T)          <=2^-119.5    <=2^-123.0   <=2^-122.6

L=1: (1+51)T_s+12T_m plus small; <=64T/p is a safe figure, 2^-119.6, and MC+TAIL add <0.01 in exponent.
L=2: 2T_s+6T_m <= 6T/p, plus negligible. L=8: 8T_s+6T_m <= 8T/p, worst at T_s=T.

## 4. Remarks and limits
- Main terms are linear in t. Exponent ~ 253.6-log2(t)-log2(max(L,6)).
- At L=1 a concrete attack gives Omega(t/p). Whether the 51 factor is a union-bound artefact or a real
  unbounded-compute gain I did not determine. By counting, about 6.3*2^L roots can share a kernel for one I.
  Not relevant at L=8.
- Black box not reproved. Per-fixed-x extension checked by inspection only.
- Permutation idealised. Poseidon2's algebraic structure is out of scope.
- Fixed IV means no domain separation from other users of the same permutation and IV. Not counted here.
- MIN_INSTANCES=2 means L>=1; L=0 is not covered (r empty, S not bound at all).
