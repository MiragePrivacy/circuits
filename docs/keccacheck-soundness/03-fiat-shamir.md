# 03: Non-interactive soundness of the deployed transcript

Agent: fiat-shamir. Code: PR 3 head cc59207. `V:` means crates/keccacheck/src/verifier.rs. `SP:` means
crates/keccacheck/src/poseidon2.rs. "02", "04" and "spec" are 02-interactive-soundness.md,
04-poseidon2.md and 01-spec.md. C-O is Chiesa-Orru (2025_536.txt). KRS is Khovratovich-Rothblum-Soukhanov (2025_118.txt).

Notation: p is the BN254 scalar field order, log2 p = 253.597 (01 and 02 call it r; here r is the statement challenge).
L = log2(instances), n = L + 6, as in the spec. **Production is L = 8 (n = 14, 256 instances)**: 232 or 256 recorded
permutations, padded to 256 (lead CORRECTION in NOTES, from crates/prover/tests/keccacheck_identity.rs). The rows n = 7, 12,
13 (L = 1, 6, 7) asked for in the brief are kept as secondary rows.

## Review history

- Revision 1: first version, self-checked only.
- Revision 2 (this one): answers the referee report reviews/fs.md (review-fs, blind first phase, then refereed
  revision 1), and review-rbr's C1 (reviews/rbr.md). The referee found Theorems A and B and section 7.3 correct, no fatal
  error, and repairable errors R1 to R4 plus cosmetic C1 to C8. All were addressed. Where this revision does not follow the
  referee exactly, it says so in place: C7 (section 6.3) and C8's coefficient (section 6.2). Also updated: production size L = 8,
  change-request disposition (section 13), and 04 section 12's cost of the statement-final block (section 8.3).

## 0. Result

**Proven, in the ideal permutation model with inverse queries, given Theorem 1 of 02:** for any adversary making t
queries, which chooses the statement and proof adaptively,

    Pr[accepts a false statement] <= t' max(L, 6) / p  +  11 t'^2 / p^6  +  t'^2 / p^min(L,10)  +  t' / p^2      for 2 <= L <= 10
    Pr[accepts a false statement] <= t' (K(t) + 18) / p  +  11 t'^2 / p^6  +  2^-128  +  C(t', 4)/p^3           for L = 1

with t' = t + Q_V, Q_V the verifier's permutation calls (3441 at L = 8), and K(t) defined in section 6.2 (K = 52 at t = 2^128,
so the L = 1 coefficient is 70 there, and it grows with t).

| n | L | instances | r elements | Q_V | bound at t = 2^128 | dominant term |
|---|---|---|---|---|---|---|
| **14** | **8** | **256 (production)** | **8** | **3441** | **2^-122.6** | **r move: statement grinding, no main chain needed** |
| 7 | 1 | 2 | 1 | 1835 | 2^-119.5 | grinding statements against transcripts built before them (section 6) |
| 12 | 6 | 64 | 6 | 2783 | 2^-123.0 | degree-6 sumcheck round |
| 13 | 7 | 128 | 7 | 3059 | 2^-122.8 | r move |

Status of each part:

- The proof is direct (sections 5, 6). It is not an application of the C-O theorem, because their theorem does not
  cover the two-sponge construction (section 7). One independent referee checked it and upheld it (Review history). It is not
  machine-checked.
- Additive absorb, missing padding, rate IV, intermixed squeezes and index carry-over are each harmless: they reduce
  exactly to C-O overwrite mode (section 7.2). This reduction was also replayed numerically, by me and by the referee.
- No FINDING: no attack better than the stated bound was found. One real precomputation strategy exists at L = 1
  (section 6.3). It is negligible, and L = 1 is no longer reachable once CR-1 lands (section 13).
- No transcript change is required. CR-1 is adopted, CR-2 declined (section 13).
- The KRS constructions do not apply (section 8). That is a statement about those constructions. It is **not** a proof
  of security for the concrete Poseidon2 sponge: that step is the CI assumption of section 8.4.

## 1. Model

P is a uniformly random permutation of F^16, with oracle access to P and P^-1. An element of F^16 is split as rate
(slots 0..9) and capacity (slots 10..15). IV = INITIAL_STATE (SP:11-28), IV_c its capacity part, IV_r its rate part.
All of IV is a fixed public constant known to the adversary.

A query is counted once per distinct pair (s, P(s)), in either direction. A query's in_cap and out_cap are the capacities of
s and P(s).

## 2. The transcript as a sponge schedule

The sponge (SP:99-146, identical to upstream rust/gkr/src/transcript/sponge.rs, read side by side):

- absorb(v): if idx < 10, state[idx] += v and idx += 1. Otherwise permute, state[0] += v, idx = 1. Set dirty.
- squeeze: if dirty or idx >= 10, permute, idx = 0, clear dirty. Return state[idx], idx += 1.

Consequences used below.

- Capacity is never written except by the permutation.
- After squeezing m elements, the next absorb goes to slot m and the squeezed slots stay in the state. For sumcheck rounds after
  the first of each sumcheck, the coefficients go to slots 1..d and slot 0 still holds the previous challenge. The first round of
  a sumcheck starts wherever the preceding batch left idx: at slot 5 after a 25-element batch, and after a 10- or 30-element
  batch idx = 10, so the first absorb permutes and uses slot 0. Nothing below depends on which slots are used, only that the
  assignment is fixed (Lemma 1).
- Every squeeze after an absorb permutes first. So every verifier move starts with a fresh permutation call on a state that
  contains the complete preceding prover message. Checked by replay for all moves (section 14).
- The verifier's last prover message (25 elements of round 0) is followed by no squeeze, so part of it never enters a
  permutation. This is harmless: no challenge follows it, and 02 T14 is deterministic.

**Statement chain** (V:433-453). For a fixed L, it absorbs tag, 2^L, then C input chunks and C output chunks with
C = ceil(25 * 2^L / 3), and then squeezes r_1..r_L. It makes D_S = ceil((2 + 2C)/10) permutation calls before the first output:
427 at L = 8 (4270 absorbs), and 4, 107, 214 at L = 1, 6, 7.

**Main chain** (V:581-651). A fresh sponge, starting again from IV. It absorbs r_1..r_L into slots 0..L-1 and then follows the
move table of 02 section 2. It makes 3014 permutation calls at L = 8, and 1831, 2676, 2845 at L = 1, 6, 7. A move's challenges
span at most 3 permutation calls: 25 and 30 element moves take 3, all others take 1 (for L <= 10).

For fixed L, the schedule assigns to each chain depth d a set of active slots (possibly empty) and says which output elements
are challenges. The schedule does not depend on any value. Proof length is fixed by V:651 and the key's shape: 10687 at L = 8.

**Lemma 1 (parsing).** Fix L and a chain type. Given the rate of the block input at depth d and the rate of the previous block's
output (IV_r at depth 1), the absorbed values are the differences on active slots, and inactive slots must be equal. So a chain
of permutation calls determines at most one (statement, proof prefix) or (r, proof prefix). Distinct values produce distinct
block inputs at the first depth where they differ.

Proof. Immediate from additive absorb and the fixed slot assignment: a value is recovered by subtraction. QED.

**Lemma 2 (statement encoding).** For Boolean bits and fixed L, the map from (input bits, output bits) to the absorbed sequence is
injective.

Proof. Each chunk is at most 192 bits, packed as sum 2^k b_k with the power reset per chunk (V:441-449, matching native
V:417-423), and 2^192 < p, so a chunk decodes uniquely. Chunk positions are a fixed function of L: input and output are chunked
separately, and since 25 * 2^L mod 3 is never 0 the last chunk of each is short, with a length determined by L. QED.

Booleanity is a precondition (spec P1). It is used twice: for Lemma 2 here, and in 02 for bit-to-word injectivity. Section 8.3
adds a third use: the 192-bit box is what keeps the statement-final block expensive for algebraic attacks. 05 owns the check.

## 3. The game

Fix L, which is fixed by the verification key. Let F be Keccak-f[1600] applied per instance. Adversary A has oracle access to P
and P^-1 and makes t queries in total. It outputs S = (I, O) with I, O bit arrays of 1600 * 2^L bits, and a proof pi with
6255 + 554 L field elements. A wins if

    O != F(I)   and   V^P(S, pi) = 1

where V runs the statement chain, the main chain, and every check of spec sections 4 to 6.

Nothing else is fixed. A chooses I, O and pi jointly and adaptively, after any number of oracle queries, including queries made
to grind on the statement: changing the last statement block costs one query per attempt. A false statement here means any
instance is wrong. Knowledge of a witness is not at stake, since the statement contains everything. Soundness is what the
outer relation needs: the Groth16 extractor gives (S, pi) that satisfy the R1CS, and 05 connects the R1CS to V.

Attacking several keys is a union over L. Queries made for other L, other protocols or other chains are simply queries:
V never follows them, so Theorem A already covers them as part of t. Soundness has no honest party with secrets, so no domain
separation is needed against other uses of P.

## 4. Round-by-round soundness and the state-restoration loss

02 Theorem 1 gives a state function Doom(S, tau), defined for every S and every prefix tau, with:

- R1. Doom(S, empty) holds for every false S.
- R2. For every S, every doomed prefix tau, every prover message a, a move with uniform challenges rho leaves doom with probability
  at most e(move). This holds for any tau, so it holds whatever the adversary knows about how tau was reached.
- R3. If the last position is doomed, V rejects on any final prover message (T14).

Per move errors, from 02 section 2: sumcheck rounds d/p with d <= 6, each RLC move 1/p. With the deployed sponge one query reveals
all of r_1..r_min(L,10), so r is one move with error L/p (the coordinate bound of 02 T1, summed). Hence

    e_max(L) = max(L, 6) / p.

**r and the initial beta (review-rbr C1).** Under 02's own move definition (a maximal run of challenges with no prover message
between), r and the initial beta are one interactive move, with error (L + 1)/p. Fiat-Shamir splits them, for two reasons that
both hold here. First, they come from different queries: r from the statement chain's final call, beta from the main root, a
different permutation call made at a different time (at L >= 2, after r by B2). A query reveals one of them, not both. Second,
02's state function has a position after r_1..r_L (the row "after r_1..r_m") as well as after beta, and its transitions T1 and
T2 bound each step separately. So R2 applies to each query with its own error, L/p and 1/p, and the merged (L + 1)/p is never
charged to a single query. Under CR-2 (one sponge), r and beta would come from the same call, and that query would cost (L + 1)/p
(section 13).

**The numeric loss from RBR to state restoration is t times the maximum move error**, not t times the total interactive error:
each query tests exactly one move at one position. At L = 8 the interactive sum is 7932/p = 2^-240.6, the state-restoration figure is
t * 8/p = 2^-122.6 at t = 2^128, and t times the sum would have been 2^-112.6.

The loss is real, not an artifact. A false statement with a single wrong instance is undoomed by any r coordinate taking one
specific value (02 section 8.5), so grinding the statement succeeds with about L t / p. That needs no main chain at all, and from
L = 7 on it is the dominant term, so at production it is the tight generic attack. A false statement also gives a doomed position
at every sumcheck round. A degree-6 message can make p - g_true have 6 distinct roots, with a new message for each query, so
grinding one round succeeds with probability about 6 t / p. The main term of Theorem A is tight up to lower order terms.

Reuse of beta scaled by x, y, b does not change this. R2 for those moves is the linear form of 02 T7 and T12 in the fresh elements,
which is fixed before the query answering them. No independence between lanes is assumed anywhere.

## 5. Theorem A: L >= 2

**Theorem A.** For 2 <= L <= 10 and t' = t + Q_V, where Q_V = D_S + main chain calls,

    Pr[A wins] <= t' e_max(L) (1 + d)^3 + 11 t'^2 / p^6 + t'^2 / p^L + t' / p^2,      d <= 2^-3000.

For 10 < L <= 30 the same holds with p^10 in place of p^L, and only the block structure of r changes.

Append V's calls to A's queries, so all of them are in the table. Simulate P lazily. When a forward query is the first block of a
multi-block challenge move, also perform the remaining blocks of that move right away and show them to A. That at most triples the
number of queries, so T <= 3 t'. It only helps A.

A fresh forward answer is uniform on the unused outputs, at most T of them used, and similarly for inverse. So any specific value of
6 capacity slots has probability at most (1 + d)/p^6, and any specific rate tuple at most (1 + d)/p^10, with d <= 2T/p^16.

**Bad events.**

- B1 (capacity). A fresh answer's capacity (output of a forward query, input of an inverse query) equals IV_c, or any capacity
  seen so far as input or output of any query, or the capacity on the other side of the same query. At the j-th query there are at most
  2j forbidden values, so Pr[B1] <= sum_{j <= T} 2j (1 + d)/p^6 <= T(T+1)(1 + d)/p^6 <= 11 t'^2/p^6.

Call a query rooted if in_cap = IV_c, or in_cap = out_cap of a rooted query.

**Lemma 3 (tree).** If B1 does not occur: every rooted query was first made in the forward direction; every rooted query other than
those with in_cap = IV_c has exactly one rooted parent, made before it; and a query with in_cap = IV_c has no rooted parent.

Proof. By induction on depth, the rooted queries are forward. At depth 1, an inverse query has fresh in_cap, not equal to IV_c
by B1. At depth k, let q have rooted parent q', forward by induction, with in_cap(q) = out_cap(q'). If q was made first, the fresh
out_cap(q') equals an earlier capacity, which is B1. So q' was first. If q were inverse, its fresh in_cap would equal the earlier
out_cap(q'), which is B1. Uniqueness: two rooted, hence forward, queries with equal out_cap means the later fresh output repeats
an earlier capacity, B1. Likewise for out_cap = IV_c. QED.

Note the inverse oracle's chosen output can have any capacity. Inverse queries can therefore share an out_cap with a rooted query, but
they are not themselves rooted, and so no chain passes through them. That is why the lemma is stated for rooted queries only.

Thus rooted queries form a tree. Each one determines its whole chain back to a depth-1 query. By Lemma 1 and the fixed schedule, a
rooted query has a unique depth and a unique parse under each chain type.

Call a rooted query a statement-final query if its chain parses as a statement chain at depth D_S, for a unique S by Lemmas 1
and 2. Its output gives r(S), the rate slots 0..L-1. Call a depth-1 query with rate IV_r + (r_1..r_L, 0, ..., 0) the main root for r.

- B2 (r is not fresh). A statement-final query's r equals the r of a main root already in the table.
- B3 (r collision). Two statement-final queries with different S have the same r.
- B4 (chain overlap). A statement-final query's output has r_1 = tag and r_2 = 2^L.

Each statement-final answer is fresh. It is tested against at most T prior values on L slots, or a fixed value on 2 slots.

Counting (revised, referee C2). Revision 1 said lookahead blocks are never statement-final. That is false in general. The
statement root (tag, 2^L, 0, ...) followed by all-zero prover messages makes a main-parse path identical to the statement chain of the false
S = (0, 0), and at L = 6 depth D_S = 107 is a lookahead position of the main schedule (referee's sched.py; at L = 8 depth 427 is the first
block of a move, so the sentence happened to hold there). The count does not need the sentence. Each rooted query has one depth, and a
statement-final query is at depth D_S. A non-lookahead query q0 makes at most 3 queries (itself and its lookaheads), all at different
depths, so at most one of them is at depth D_S. Hence there are at most t' statement-final queries. The tree such a q0 lies in is a
statement root's tree, not T_r(S') for any S' (by B4), so no query is charged as a Break twice. So
Pr[B2 or B3] <= t'^2 (1 + d)/p^L and Pr[B4] <= t'(1 + d)/p^2, as before.

**Consequences if no bad event occurs.** For every r(S), the main root for r comes after S's statement-final query, S is the only
statement with that r, and the main tree T_r below it shares no query with any statement chain: a statement root has
slots (tag, 2^L) and T_r's root would need r_1, r_2 to equal them.

So each query in T_r has a well-defined S and transcript prefix tau at the moment it is made. This is the formal content of "the
statement is fixed before r and beta": it holds for the sponge even though the main chain never sees S.

**Break events.** For each query q that begins a move, and which lies in a statement chain as statement-final or in T_r for r = r(S),
where S is false and its statement-final query came before q: Break(q) holds if the state goes from doomed to not doomed. The prefix
tau and message a are determined by the input of q and its ancestors. The rate answers of q and its lookahead blocks are at most
(1 + d)^3 from uniform on the challenge elements. By R2,

    Pr[Break(q) and no bad event before q] <= e(move of q) (1 + d)^3 <= e_max(L) (1 + d)^3.

Each query has one depth, thus one move, and at most t' queries are not lookaheads. So Pr[some Break, no bad event] <= t' e_max(L) (1 + d)^3.

**Conclusion.** Suppose no bad event and no Break, and let A output false S with proof pi. The V run is a chain in the tree, by Lemma 3:
first S's statement chain, giving r(S), then a path in T_r. By R1, S is doomed at the start. Each move begins with a query that has no
Break, so doom persists to the last position. By R3 V rejects. QED.

No step uses an instance hash, a salt, or a padding rule. There is no "first query per prover message" assumption: intermediate blocks of a long
prover message can be chosen adaptively after seeing earlier block outputs, but they are not moves and carry no error, and the
message is fully determined by the time the move's query is made.

## 6. Theorem B: L = 1, where r can collide

With CR-1 adopted (section 13), L = 1 is no longer reachable. This section is kept because cc59207 allows it, and as the
analysis that motivated CR-1.

At L = 1, r has a single element, and t'^2/p is 2^2.4 at t = 2^128. B2 and B3 happen with high probability and Theorem A says
nothing. A does get many statements sharing one r and main trees built before their statement exists. This is a different case, so it is
handled separately.

### 6.1 What can go wrong

The main tree T_r depends on r only, so a tree can exist before S does. A prebuilt honest chain for some (I_c, F(I_c)) at (r, beta) is
accepted for S' = (I', O') exactly when:

    sum_i beta_i O'_i~(r) = sum_i beta_i F(I_c)_i~(r)    and    I'~(alpha) = I_c~(alpha) (25 equations)

Doom relative to S' was never in force while the chain was built, as S' did not exist. R2 still holds as a statement about the state
function for each fixed S', but S' is now selected after the fact among 2^6400 statements.

### 6.2 Theorem

For a query budget t, let K(t) be the least K with 2^6400 (6 t' (1 + d)^3/p)^K / K! <= 2^-128. Then K(2^120) = 49, K(2^128) = 52,
K(2^130) = 53, K(2^140) = 57 (scripts/fiat-shamir/l8.py).

**Theorem B.** For L = 1, any t, and K = K(t),

    Pr[A wins] <= 2^-128  +  C(t', 4)/p^3  +  t' (K + 18) (1 + d)^3 / p  +  11 t'^2/p^6.

At t = 2^128 this is 70 t'/p + 2^-128 + 2^-253 + 2^-1262 = 2^-119.5. Revision 1 stated the constants for all t; they are valid only for
t <= 2^128 (referee R4). At t = 2^130 the first term with K fixed at 52 is already 2^-118, which is why K is now a function of t. The
4-collision term C(t', 4)/p^3 is 2^-253 at 2^128 and 2^-125 at 2^160; the number 3 below would also be raised if t approached 2^170.

Proof. Keep B1 and Lemma 3, with every event below intersected with "no B1 so far". Statement roots and main roots are always
disjoint at L = 1: slot 1 is 2 in a statement root and 0 in a main root.

For every S (false or not) and r, define Broken(S, r, time) if some node in T_r, at that time, is not doomed relative to S, where
r is not in B(S) = {r : all delta_i(r) = 0}. B(S) has at most one element for false S, since delta_i is affine in r and some
delta_i is nonzero (02 T1).

Step 1, counting. Fix a false S. For r outside B(S), the root of T_r is a move with error 1/p (02 T2), and later moves have error at most 6/p. By R2, each query
causes a first break relative to S, in its tree, with conditional probability at most e = 6(1 + d)^3/p. Any K given queries all do so with probability at most e^K, by the chain rule. So

    Pr[at least K distinct r are Broken relative to S at the end] <= C(t', K) e^K <= (t' e)^K / K!.

Let E_K be the event that some false S has at least K Broken values of r at the end of the game. A union over all 2^6400 statements
gives Pr[E_K] <= 2^-128 for K = K(t). The union is over a fixed universe of statements, not over queries: this is where fixing S after the fact is paid for.

Step 2, statement-final queries. Let q be S's statement-final query, and N_q(S) the set of r that are Broken relative to S at that
moment, together with B(S). N_q(S) is fixed before the answer of q. The answer is fresh, so Pr[r(S) in N_q(S) and |N_q(S)| <= K] <=
K(1 + d)/p. If E_K does not occur, then at most K - 1 values of r are Broken relative to S at the end, hence also at time q, so
|N_q(S)| <= K. Therefore

    Pr[some statement-final q hits N_q] <= Pr[E_K] + sum_q Pr[r(S) in N_q(S) and |N_q(S)| <= K] <= 2^-128 + t' K (1 + d)/p.

(Referee C8: revision 1 bounded |N| by K + 1 and stated the probability without the query-time event. Both corrected; the coefficient
falls from 71 to 70.)

Step 3, after S exists. If r(S) is not in N_q(S), then every node of T_r(S) is doomed relative to S at that time. A later query in T_r can
break relative to any statement whose statement-final query came before it and which has this r. Let M be the event that 4 statement-final
queries share an r: Pr[M] <= C(t', 4)(1 + d)^3/p^3. Without M at most 3 false statements share an r, so later breaks cost at most 3 e per
query, or t' 18 (1 + d)^3/p in total.

If none of these occurs, the conclusion follows as in Theorem A: the first escape on V's path is either before S's statement-final query
(Step 2) or after it (Step 3), and no case is left. QED.

### 6.3 A matching strategy

The factor is not an artifact. Fix a list of K pairs (r_j, beta_j). The relations are K linear equations mod p on the difference vector
d in Z^50 of word differences: sum_i beta_i ((1 - r_j) d_{i,0} + r_j d_{i,1}) = 0.

Existence with an in-range output (revised, referee C6). Pigeonhole on box vectors gives d as a difference of two box vectors, which
does not by itself put F(I) + d in [0, 2^64). Choose I by inverting Keccak-f so that every word of F(I) lies near 2^63. Then any d with
|d_i| < 2^63 keeps F(I) + d in range, and pigeonhole over the half-width box (3150 bits) gives a nonzero d in all K kernels for
3150/253.6 = 12.42 >= 12 relations. kernel.gp found such vectors by LLL directly: at K = 12 entries are about 2^60.7, inside 2^63.

Use. If S' = (I, F(I) + d) has r(S') = r_j for some j, then the honest proof for (I, F(I)) at r_j is accepted for S', a false statement.
Prebuilt honest chains are not needed (referee C7): only beta_j is needed in advance, 3 calls per root, and the honest chain is computed
after a hit. So each statement query succeeds with probability K/p, and t statements give 12 t/p = 2^-122.0 at t = 2^128. Reaching
constant probability needs 2^250 queries.

The referee estimates, by a first-moment count, that choosing d after seeing many roots gives about 23 t/p = 2^-121.1 for an unbounded
adversary (C7). I do not adopt this figure as a lower bound: the referee marks it heuristic, without a second-moment argument, and I have
not checked it. Proven range for L = 1: at least 12 t/p is achievable, at most 70 t/p at t = 2^128. If the estimate holds, the range is
23 t/p to 70 t/p. Either way, statement collision through r gives a bound, not an attack.

At L >= 2 the same strategy has probability K/p^L per query, with K = floor(1600 * 2^L / 253.6): about 25/p^2 per query at L = 2,
and K = 1615, so 1615/p^8, at L = 8.

## 7. What Chiesa-Orru gives and what must be adapted

### 7.1 Their result

Theorem 6.1: for NARG = DSFS[IP, cdc, delta] in the (h, p, p^-1) model, e_NARG(t) <= e_sr_IP(t) + eta(t), with

    eta(t) = 25 t^2 / |Sigma|^c + t max_i e_cdc,i + sum_i e_cdc,i.

Lemma 5.1 is the exact form: the numerator of the capacity term is 7T^2 + 28(L+1)T + 14(L+1)^2 - 3T - 13(L+1) over 2 |Sigma|^c, and the 25 assumes t_p is at least the transcript's
block count. Here Sigma = F, c = 6, r = 10. The term is 25 t^2/p^6 = 2^-1261 at t = 2^128. This matches Theorem A's 11 t^2/p^6 in form.

Their model (Construction 3.3 and 4.3):

- State (s, iA, iS), starting as ((0^r, h(x)), 0, r). The capacity comes from a random function h of the instance, independent of p.
- Absorb overwrites slots from iA, starting at 0 after any squeeze; when iA = r it permutes first.
- Squeeze reads from iS; when iS = r it permutes first. Absorb resets iS to r.
- A fixed codec gives injective phi_i with fixed lengths, and no lengths or labels are hashed.
- The IP verifier is a deterministic oracle-free function of (x, alpha, rho). The language is a fixed set of instances.

Footnote 4 says the analysis "can be adapted" to XOR mode and different padding. It does not carry out that adaptation.

### 7.2 Deviations that reduce exactly

**Construction (full-rate codec).** From the keccacheck IP define IP*, public coin, per permutation call of the deployed schedule:

- The prover's message for a block is the full vector w in F^10 that the deployed sponge's rate holds just before that call.
- The verifier's message after the call is the full 10-element rate output (10 m elements for a run of m calls with no absorb).
- IP*'s verifier recomputes the original transcript: original absorbed values are w minus the previous rate output on active slots, and it rejects if an inactive slot of w differs
  from the previous rate output. Original challenges are a prefix of its messages. Then it runs the original decision.
- At depth 1, previous rate means IV_r.
- Rounds with no absorb use an empty prover message.

**Claim.** DSFS[IP*, identity codec] with capacity seed IV_c makes the same sequence of permutation inputs as the deployed sponge, for
every call the deployed sponge makes. Construction 4.3's verifier also absorbs and squeezes after the last message, so it makes one extra
call that the deployed verifier does not (the deployed sponge ends with idx = 6, dirty). The extra call carries no decision (referee C3).

Proof. Absorbing r = 10 elements leaves iA = r; Squeeze then sets iA = 0 and permutes once since iS = r (Construction 3.3 Squeeze step (c), Absorb step 1). Absorbing w overwrites the whole rate with the
same values the deployed sponge has. The capacity evolves only via p in both. An empty Absorb followed by Squeeze permutes with the rate unchanged, matching the multi-block squeeze. QED.

Replay of this claim (sched.py) at L = 1, 2, 6, 7, 8: identical input sequences, including the wrap-on-absorb case and partial blocks.
The referee replayed it independently at L = 1, 2, 6, 8.

| Deviation | Resolution |
|---|---|
| Additive absorb | Harmless. The overwrite value is previous output + x, a bijection for fixed previous output. |
| Absorb index carries over after a squeeze (slot m, not 0) | Harmless. Full-rate block rewrites slots 0..m-1 with their current values. |
| Squeezed slots stay in the state | Harmless. They are inactive slots in w, known to IP*'s verifier. |
| No padding | Harmless. C-O have none either; fixed lengths come from the codec, here the fixed schedule of section 2. |
| Rate part of INITIAL_STATE | Harmless. Overwritten by the first full-rate block; C-O's 0^r never enters a permutation. |
| Intermixed squeezes and dirty/idx logic | Harmless. Squeeze behaves identically once every read is a full-rate read. Permutation call positions are the same. |
| Permutation on absorb when idx = 10 | Harmless. Becomes a verifier message ignored by the original verifier, with zero error. |
| Fixed capacity instead of random h | Harmless for a single instance only (referee C4). Conjugating P by a fixed bijection on capacity values gives a uniform P again, and V ignores capacity values, so the advantage for one instance does not depend on IV_c. With several instances all mapped to IV_c, h is not a random function: that is the deviation of 7.3, not covered here. |
| Decoding bias | None. Challenges are field elements, decoded by identity: e_cdc = 0. The byte interface in sponge.rs is cfg(feature = "whir"); keccacheck-arkworks sets default-features = false. |

IP* inherits RBR from IP. Extend Doom to positions inside a prover message by keeping its value from the last complete position: the extra verifier messages have error 0. The final position and R3 are unchanged.
SR loss is t max_i e_i as in section 4, plus k for the game's final step (C-O Definition 3.12 re-evaluates all rounds): numerically nothing.

### 7.3 The deviation that does not reduce: two chains

Their Theorem 6.1 does not apply to the deployed protocol, for two precise reasons.

1. Their SR oracle is f_i(x, tau, alpha_1..alpha_i). Every challenge depends on the instance x. In the deployed main chain the instance is absent: two statements with equal r have identical
   challenges. If x := S with h(S) := IV_c, then f is not a function that separates instances.
2. Treating r as a prover first message with x empty is no better. The language is then empty of meaning, as false or true depends on S and not on x. And the check r = H(S) needs the oracle, while their IP verifier is oracle-free.

Lemma 5.1 alone does accept any adversary, and statement chain queries could be treated as just adversary queries. But then the false-statement predicate is not a function of (x, pi), which is what the lemma preserves.

Remark 2.1 of C-O says that st0 = Absorb^p(st*, phi0(x)) is covered "as a special case with h = p". Lemma 5.1 itself samples h independently of p, so the remark is not established by the lemma as stated, though the extension looks routine. A single sponge
(CR-2) would fit that remark, and the full-rate codec. The deployed two chains would not.

So this is closed by the direct proof of sections 5 and 6, not by citation. The tree in Lemma 3 plays the role of their BackTrack and the capacity event of their E. Soundness needs none of their machinery for rewinding, salts, or
knowledge extraction, and that is why a short argument suffices. The referee upheld this section.

## 8. The KRS attack

### 8.1 What the attack is

Construction 1 of KRS: the prover chooses a circuit C*(w) that computes alpha = comm(w), gamma = h(w, y*, alpha), and outputs (gamma, gamma - 1). Claim y* = (0, 0). With w = digest of C*, the verifier's r equals gamma, and the output MLE
gamma - X vanishes at r, so the false claim becomes true at r. From there the honest prover finishes. Circularity is avoided since the hashed claim is y*, not the output, and the circuit is hashed by digest.

Three things are required: (a) the prover chooses the circuit, adaptively after seeing h (Definition 6); (b) the circuit can compute the challenge from data available in its input; (c) the true output, a circuit computation, can be made an arbitrary function of the challenge.

Theorem 2 applies the same idea inside a phase: u_real and u_fake differ in a term that vanishes at a coordinate of the inner challenge r', which a sublayer predicts by running the transcript computation.
Section 4 removes adaptivity using a universal circuit (Turing machine with a quine, or a universal GKR circuit). Section 5 proposes that the circuit family be unable to compute the hash, and says plainly that whether this suffices is open.

### 8.2 Testing the claim in the log

The lead's CLAIM reads: "The attack needs a circuit family able to compute the hash. Ours is fixed Keccak-f with Poseidon2 evaluated by Groth16 outside it."

The conclusion holds for the published attacks, but the second sentence's reason does not stand as stated. Where the verifier evaluates the hash is irrelevant: in KRS it is also evaluated by the verifier, and that is not what the circuit computing it means. The conclusion rests on reasons 1 and 2. Revision 1 listed three more; the referee (R3) showed one wrong and two weaker than claimed, and they are scoped or withdrawn below.

1. Adaptive circuit choice is unavailable. The GKR circuit is a constant in the R1CS, fixed by the verification key: 24 rounds of Keccak-f and a shape determined by L. The prover chooses only inputs, outputs and proof. Theorems 1 and 2 do not apply: each needs a prover-built C*.

2. The circuit is not programmable. Section 4's nonadaptive attacks need a universal circuit with an interpreter. Keccak-f is a fixed permutation on 1600 bits with no instruction-like input and fixed depth. No input makes it run an interpreter. This is the only reason that covers beta and the inner challenges. It is an informal claim: "Keccak-f cannot compute the hash" is not proven, and KRS section 5 calls countermeasures of this kind open.

3. Scoped to r. O_j depends on I_j only, and r depends on all of I and O, 3200 * 2^L bits. So no part of the true output can compute r from what it can see, except by knowing a fixed point in advance. This says nothing about beta and the inner challenges: those depend on r and prover messages, not on the whole statement, and r fits within one instance's 1600 bits for L <= 6. KRS Theorem 2 targets an inner challenge, so reason 3 does not exclude it.

4. Withdrawn. Revision 1 said full absorption of the statement removes the digest trick. That is wrong on two counts: KRS Construction 2 computes r = h(psi, x, y*, alpha) inside the circuit with the input x public, so absorbing the input in the clear does not block it, and psi stands for the circuit, not the input. And in the main chain r is itself a short digest standing for S, and the tree can precede S (section 6.1). What remains true is narrower: this protocol has no witness and no commitment, so there is no comm(w) for a circuit to recompute.

5. Withdrawn as a barrier. Revision 1 argued from a single lane at L = 1 that 64-bit words keep a true output from equalling a field challenge. The relevant form is 25 * 2^L word variables under sum_i beta_i delta_i(r) = 0, which has solutions of size 2^10 or smaller for every (r, beta) (referee rl.gp at L = 8: largest |d| 2^6.5). So words impose no barrier at the beta move, and at L >= 2 the r move is reached by r_k in {0, 1} without any lane relation. Inner-layer fakes are free field values.

### 8.3 The strongest analogues for a fixed circuit, and what they reduce to

The attack shape is still meaningful for a fixed circuit, without circuit computation. The prover needs a false claim to become true at a challenge.

**First move, revised (referee R2).** Revision 1 called this "a fixed-point condition on H alone". That is wrong for two chains, and contradicts section 6.1. Beta depends on r only, so nothing is circular. The first move is two separate targets, both on the statement chain's final block, where up to 10 elements are free but each lies in a 192-bit box:

- r move, any L. Make one or more instances wrong that share bit value b at position k, and force r_k = 1 - b. Then eq(r, j) = 0 for every wrong instance, the claim is true at r, and the honest proof verifies. No main chain and no lattice is needed. This is CICO-1 on the statement-final block, with a choice of k.
- beta move. Fix r* in advance, compute beta(r*), solve for delta by LLL, then force the statement chain to output r*. This is a targeted partial preimage, H(I, F(I) + delta) = r* with delta in a coset of a lattice box, so CICO-L plus the lattice constraint.

F gives slightly more than "a fixed offset" here: Keccak-f is invertible, so once beta(r*) is known F(I) can be chosen as data, which partly meets KRS requirement (c) at this one move. It gains nothing over a free delta.

Cost, from 04 section 12, which costed both at the referee's request. At L = 8 the r move costs about 2^210.3 (floor): the best final-block element holds 3 wrong instances (192 free bits), which agree on 6 of the 8 bits, so 6 values of k work, and a univariate line of degree 5^65 has a root in the 192-bit box with probability 2^-62. At L = 1 and L = 2 the algebraic route costs 2^276.9 and generic grinding (2^253.6, 2^252.6) is cheaper. The beta-move variant is worse at every L (about 2^351 at L = 1). Both costs are 04's (arithmetic run, cost model reasoned); I have not rederived them.

The statement-final block is expensive only because of the 192-bit packing, and that packing is injective only for Boolean bits. 04 section 12.4: if statement elements became full field elements, this block would drop to about 2^143.7, below the main-chain target. So the packing is load-bearing for the CI assumption, not only for Lemma 2, and any change to statement absorption needs 04 section 12 rerun.

**Inner layer.** Choose any fake layer table, run the honest prover for the fake table, and require (fake - true)~(v) = 0 at the point v derived by H from the transcript of the fake. F contributes only a fixed offset. In KRS Proposition 7 the true table is built so this holds identically, and Keccak layer tables cannot do that (reason 2).

So, for this fixed circuit, every analogue I could construct is either impossible (needs the circuit to compute H) or is a correlation problem on the Poseidon2 sponge composition: find an input whose challenge leaves doom. That is what Theorems A and B bound by t e_max in the ideal model.

### 8.4 What this does and does not show

Shown: KRS Theorems 1, 2, 9 and 10 do not apply to this protocol, for reasons 1 and 2, and the adapted diagonalizations of section 8.3 have no planted solution.

Not shown: security of the concrete sponge. An ideal-permutation proof says nothing about KRS-class attacks: KRS's targets are also sound in the ROM. An attack could exist that uses Poseidon2's code together with the specific structure of Keccacheck. KRS section 5 says their countermeasures are unproven, and
Remark 3 makes only the informal point that their attack does not seem to apply to simple canonical circuits such as grand products. Keccak-f is a stronger circuit than a grand product, though still a fixed one.

**Remaining assumption (CI), restated (referee R1).** Revision 1 stated CI as a relation on single permutation calls, "(s, s') with s parsing,
with some statement S, as a doomed position". That relation is not sparse: a main-chain input contains no S, and for every beta some false S
has sum_i beta_i delta_i(r) = 0 (section 9), so every main root is in it, and LLL finds an element in polynomial time. CI must be stated for the
composed function, with S in the input.

For fixed L, let g_L(S, tau, a) be the challenges of the next move, computed by running the statement chain on S to get r(S) and then the main chain
on (r(S), tau, a), with P = Poseidon2. Assumption CI_L: no algorithm doing 2^128 work outputs (S, tau, a) with S false, Doom(S, tau), and
not Doom(S, tau, a, g_L(S, tau, a)), except with probability about

    2^128 e_max(L)  +  2^128 K_L / p^L,      K_L = floor(1600 * 2^L / 253.6),

where the second term is the multi-target strategy of section 6.3 (precompute beta at many r, then grind S). At L = 8 the second term is
2^128 * 1615/p^8, negligible, and the first is 8 * 2^128/p. Per fixed input (S, tau, a) the escape density is e(move) <= e_max(L), so this relation is
sparse. It is CI for a composition of two sponges, not for a relation on single P calls. For L = 1 the constant is that of Theorem B.

Like any CI statement for a concrete hash, this is a real assumption, falsifiable, efficiently decidable given (S, tau, a) (02 section 5), and in
the class where correlation intractability is known to fail for some protocols and hashes in general. No concrete hash has a CI proof. It does
not affect Theorems A and B, which are statements about an ideal P.

**A single escape suffices.** After one escape the honest prover completes the forgery. Two structural targets have been costed in 04:

- One main-chain sumcheck round: solve for x_1..x_d, c in F with P(state with x on the round's active slots)[0] = c and g(c) = 0, where g is the
  difference from the true round polynomial; g(c) = 0 is one linear equation in x for given c. CICO-1 on width-16 Poseidon2 with up to 6 free
  rate elements, which are free field elements. 04 section 5: about 2^150.9 (floor 5^65), independent of L.
- The statement-final block at the r move (section 8.3): about 2^210.3 at L = 8, generic (about 2^253) at L = 1, 2.

So at L = 8 the cheapest known target is a sumcheck round, as revision 1 asserted without support. It is now supported by 04 sections 5 and 12, and
it depends on the 192-bit packing and on Booleanity. Generic grinding (the ideal-model bound) needs about p/8 = 2^250.6 at L = 8.

Available evidence: 2026_409 reports no forgeries for reduced round Poseidon-based FS using Groebner methods, in sigma and FRI-shaped settings. It does not cover sumcheck or this parameter set, and it suggests correlation approaches as the more promising direction.

## 9. Specific questions

**Encoding injectivity.** Lemma 2. Three words per element fit in 192 bits, below p. Lane order is fixed by the slice layout, documented at V:522; any fixed order would do. The instance count is absorbed as 2^L, nonzero in slot 1. The tag is absorbed in slot 0. Inputs and outputs have fixed separate chunking; the chain at V:439 restarts chunking at the boundary. At L = 8 the final statement block (positions 0..9) holds output lane 24 of instances 228..255, 9 elements of 192 bits and a last one of 64 bits (04 section 12.1).

**Trailing zeros.** Additive absorb of 0 leaves the state unchanged, and only idx differs: absorb(x), absorb(0) has the same state as absorb(x). No padding marks this. The fixed schedule rules it out for one key: position determines slot, with no length freedom, so absorbing zero at a position is unambiguous (Lemma 1). The same holds at the end of a chain. In the statement chain all chunks exist at fixed positions. Across keys, statement chains differ deterministically at slot 1. Main chains are prefix compatible across L: at L = 7, slots 7..9 are zero, and an L = 8 r with r_8 = 0 has the same root. This is reachable with probability 1/p per statement and harmless: the chain then diverges by schedule, and each key's theorem is per key.

**Collisions between the two sponges.** Both start from IV_c. They share a query only if the first blocks coincide. So r_1 = tag, r_2 = 2^L, r_3.. equal to statement chunks: B4, probability t/p^2. At L = 1 impossible since slot 1 differs. Later collisions need a capacity collision: B1, 2^-1262. A main-parse path can coincide with a statement chain from a statement root (section 5, counting); that is not a main tree T_r(S) and is charged once. Neither would directly give a forgery. Excluding them only keeps the proof simple. The tag is not load-bearing for soundness in this argument, beyond what B4 uses.

**Statement collisions through r.**

| L | r elements | t^2/p^L at 2^128 | role |
|---|---|---|---|
| **8** | **8** | **2^-1773** | **Theorem A (production)** |
| 1 | 1 | 2^2.4 | collisions and reversed order both occur; Theorem B; loss 2^3.5 |
| 2 | 2 | 2^-251 | Theorem A |
| 6 | 6 | 2^-1266 | Theorem A |
| 7 | 7 | 2^-1519 | Theorem A |

A collision by itself gives nothing: two statements with the same r have the same challenges, but the proof must also pass the end checks of 6.1 for the false one. Only the multi-target use in section 6.3 gains anything, and it is bounded.

**Challenge distribution.** Each challenge is a slot of a permutation output in F, used directly. There is no reduction from bytes and no decoding, so no bias. Under lazy sampling each rate tuple is uniform up to a factor 1 + 2^-3000. Elements in the same output are jointly uniform. All 10 slots are independent in the model, including the squeezed values that stay in the state.

**Degenerate challenge values.** Zero is not a separate event. Every challenge enters either a Schwartz-Zippel-style polynomial (roots counted in the d/p, including 0), or a nonzero linear form (1/p, including all zeros). The factor cases:

- eq(r, r_x), pow~(r_y), eq(alpha, v1), rot = 0: doom says claim != factor * true. With factor 0 the claim is nonzero, and the check claim = 0 * value fails (02 T5, T6). There is no vacuous pass.
- RC~(v1) = 1/2 drops chi_00 from the iota check; beta_0 = 0 does as well. Pending is (beta_0 d0, d1), and it is nonzero, so the (x,y) form is nonzero (02 T7). Worked independently: if RC~ = 1/2, the passing check forces d1 != 0.
- r coordinate in {0, 1}: restricts eq to a subcube, and hides differences on the other half. Counted in L/p, and this is the tight case.
- b_x = 0: drops a column claim, a root of the (b, ba) form (02 T12).

02 section 10 ran forced versions of all of these. They are real events with the charged probability, and none costs more than charged.

**First-move binding, weak Fiat-Shamir, the singleton forgery.** Delta in Z^25 with sum beta_i delta_i = 0 mod p exist for every beta. For a known beta, LLL finds them, with entries around p^(1/25) = 2^10 (the constants at V:780 are in that range). With a singleton batch, r is empty and nothing is absorbed, so beta is a global constant. Shifting an honest output by Delta leaves `sum` unchanged, and the honest proof verifies for a false output. This was weak Fiat-Shamir in its plain form.

It is closed by two things that act together: a minimum batch size is enforced (at cc59207, V:399, V:411, V:433, V:534 and batch.rs padding, with MIN_INSTANCES = 2; 4 after CR-1), and r is derived from all of S before beta exists. The formal version is Lemma 3 plus B2: at L >= 2, the delta is fixed by S before r and beta are sampled, except with the probability of B2. At L = 1 a weaker order holds, and section 6 pays for the difference.

Note what beta_kernel_shift_is_rejected tests. It uses the old constant-beta kernel, and it fails because the shift changes S, hence r, hence beta. That is a regression test on one vector. It does not exercise the strategy of section 6.3, which is a different kernel for each target and needs a hit on r, and it does not test any bound.

Completeness of binding: every value V uses is a constant, derived from the transcript, or a statement bit bound through r. All proof elements pass through read (V:75-85), so all are absorbed except that part of the last message never enters a call (section 2). Nothing else in V is witness-dependent. Checked by reading V and by replay (02 section 10).

## 10. Concrete bounds at t = 2^128

Verifier calls per run, Q_V: 3441 at L = 8; 1835, 2783, 3059 at L = 1, 6, 7 (negligible against 2^128).

| n | L | t e_max or t c/p | 11 t^2/p^6 | t^2/p^L | t/p^2 | Total |
|---|---|---|---|---|---|---|
| **14** | **8** | **8: 2^-122.60** | **2^-1262** | **2^-1773** | **2^-379** | **2^-122.6** |
| 7 | 1 | 70: 2^-119.47 (plus 2^-128) | 2^-1262 | not used | not used | 2^-119.5 |
| 12 | 6 | 6: 2^-123.01 | 2^-1262 | 2^-1266 | 2^-379 | 2^-123.0 |
| 13 | 7 | 7: 2^-122.79 | 2^-1262 | 2^-1519 | 2^-379 | 2^-122.8 |

If "n" is instead read as L, then L = 7 is the row above, and L = 12, 13 give 12 t/p = 2^-122.0 and 13 t/p = 2^-121.9, with r spanning two blocks and p^10 in the collision term. This is a second reading, not deployed.

For reference, generic forgery at constant probability needs about p/8 = 2^250.6 queries at L = 8. These are ideal-model values. 04 finds algebraic routes that are cheaper (2^150.9 at a sumcheck round), still above 2^128.

## 11. Attacks attempted

1. Grinding the statement against a chosen delta to make beta or r vanish on it: this is the r and beta move, bound t L/p and t/p. Tight.
2. Kernel attack across r: section 6.3 at L = 1, 12 t/p. At L >= 2 needs r preimage on 2 or more elements.
3. Chosen S after r known: needs the sponge to reverse. Inverse queries have fresh input capacity: B1.
4. Attaching a prefix through inverse query or forward from a chosen state: not rooted, Lemma 3.
5. Reusing a statement block as a main root and vice versa: B4, and the coincident paths of section 5 (counting). No gain found.
6. Using the squeezed slots that stay in the state, or setting a slot to 0 by absorbing the negative of the output: this is a bijection of the block input. It gives no extra freedom beyond free choice of the absorbed value, and that freedom is what R2 already allows.
7. Using partial blocks and permutation-on-absorb to pick later message elements after seeing a block output: allowed by the game and costs nothing to the proof. R2 applies when the whole message is complete.
8. Trailing zeros, cross-L prefixes: section 9. No within-key ambiguity.
9. Cross-chain r reuse (feeding the same r to a different statement): 6.1 conditions, section 6.
10. Exploiting the last 6 or so elements never entering a permutation: no challenge after them. V's 25-lane comparison decides.
11. KRS diagonalization on a fixed circuit: section 8.3 reduces it to correlation on the Poseidon2 sponge composition, with two first-move targets and the sumcheck target costed in 04.

None gave a better than stated bound.

## 12. Proven versus assumed

| Statement | Status |
|---|---|
| Interactive RBR with the error table | Proven in 02, refereed by review-rbr |
| Each sponge deviation other than two chains reduces to C-O overwrite mode | Proven (7.2), replayed by me and by the referee |
| Tree lemma, statement order, bound in the ideal permutation model, L >= 2 | Proven here (section 5), upheld by one referee, not machine-checked |
| Same, L = 1, with counting over statements | Proven here (section 6), upheld by one referee, not machine-checked; K depends on t |
| C-O Theorem 6.1 for the deployed two chains | Does not apply (7.3). Replaced by the above |
| Statement encoding is injective | Proven, given Boolean bits |
| Boolean bits, R1CS matches the verifier, wiring | Not here, 05 |
| Poseidon2 behaves as an ideal permutation (2^128 work) | Assumption, and a heuristic in any case. 04 analyzes it; its log entries report M_I with mu_0 = 1 and that t = 16 over BN254 is not a published instance. A structural weakness there voids sections 5 and 6 for the concrete P, not their statements about ideal P |
| CI_L for the composed function (section 8.4) | Assumption. Not implied by anything else here. Known target costs in 04 (2^150.9 sumcheck, 2^210.3 statement block at L = 8), the latter conditional on 192-bit packing and Booleanity |
| KRS theorems do not apply | Proven for their constructions, by inspection of what they require (reasons 1 and 2) |
| No KRS-class attack on this fixed circuit | Open, as it is for all FS for non-trivial circuits. Reason 2 is informal |
| Composition with Groth16 | Not proven. The R1CS contains P's code, which an oracle-model proof does not model: extracting (S, pi) from Groth16 and then applying the theorem to the concrete P is the heuristic step |

## 13. Change requests

Disposition by the lead (NOTES, "Change-request disposition"): **CR-1 adopted, CR-2 declined.** No change is required for the bounds
in section 0.

**CR-1: MIN_INSTANCES = 4. Adopted.** At cc59207 the constant is at V:399. The working tree now has it at verifier.rs:400 with the
asserts in derive_r_native and derive_r_var changed to compare against MIN_INSTANCES (uncommitted; read with git diff). It removes L = 1,
so section 6 and its multi-target strategy no longer apply to any reachable key. All batches then have t^2/p^2 at worst. Batches with
1 or 2 recorded permutations pad to 4. The 256-instance production keys are expected not to change, since the padded size is unaffected
(lead: being verified by digest).

**CR-2: one sponge. Declined; kept as an analysed alternative, not a recommendation.** Change: have derive_r_var return its sponge after
squeezing r, and start TranscriptVar from that sponge instead of a new one (V:60-66, V:581-586); delete the loop absorbing r. Mirror in
native code. This alters constraints and requires a prover change, as upstream gkr::keccacheck_og::prover::prove constructs
Prover::new() and absorbs r itself (prover.rs:32-33).

Analysis:

- B2, B3, B4 and Theorem B vanish. Every main-chain node is below its unique statement. The bound is t' max(L + 1, 6)/p + 11 t'^2/p^6
  for all L >= 1: r and beta would come from the same permutation call when L <= 10, so that query's error is (L + 1)/p.
- At L = 8 the bound is 9t/p = 2^-122.4, slightly worse than the deployed 8t/p = 2^-122.6. At L = 1 it would be 2^-123.0 against
  2^-119.5, but CR-1 already removes L = 1.
- The structure would fit C-O through Remark 2.1, with the full-rate codec, up to the h = p point in 7.3.

Reasons for declining, which I agree with: the two-chain proof was refereed and holds; CR-2 is not better at L = 8; and it changes how the
statement is absorbed, which 04 section 12's cost of the statement-final block depends on (section 8.3).

Not recommended: adding a tag or length to the main chain alone. It would add nothing to the theorem. No sponge mode change (overwrite, padding) is needed, as section 7.2 shows these would change nothing.

## 14. What was run

Scripts in scripts/fiat-shamir/ (`nix shell nixpkgs#python3`, `nixpkgs#pari`).

- sched.py: regenerates the main schedule from verifier.rs by hand, asserts proof length 6255 + 554 L at L = 1, 2, 6, 7, 8, counts permutation calls, and blocks per move. It replays the deployed sponge against Construction 3.3 with the full-rate codec on a toy public function, asserting equal permutation-input sequences at each L. It tests schedule logic only: it does not use Poseidon2, and is not a check of the R1CS. 02 section 10 separately replays genuine proofs through the same schedule.
- l8.py: L = 8 counts (proof 10687, 4270 absorbs, D_S 427, main 3014, Q_V 3441), the L = 8 row, and K(t) for Theorem B. Agrees with the lead's and referee's independent L = 8 figures.
- bound.py: the revision 1 numbers for L = 1, 6, 7.
- kernel.gp: section 6.3 with uniform random (r_j, beta_j) in place of real chains. For K = 1..14, LLL on the 50 coordinates finds a vector in all K relations, each verified mod p. log2 of the largest |d| is 60.7 at K = 12 (inside the 2^63 half-width box of 6.3) and 65.3 at K = 13 (outside), in line with the pigeonhole threshold 3150/253.6 = 12.4. It does not run a proof end to end; the claim that such a hit yields an accepted proof follows from the checks in 6.1.

The referee's scripts (scripts/review-fs/) independently ran the schedule, the C-O replay, the numbers, a toy-field version of the first move and of section 6.3, and the L = 8 kernel of section 8.2.

Sections 5, 6 and 7 are arguments and not machine-checked. Everything about the code in this document has "read the code" strength, except the schedule and proof counts above.
