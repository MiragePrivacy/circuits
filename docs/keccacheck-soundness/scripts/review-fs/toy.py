"""Toy two-chain game over a small prime with a lazily sampled random permutation.

The toy IP is the first move only: accept iff H(S)=x and sum_i beta_i(x) delta_i(x)=0 for a false
S; past that point the honest prover finishes, so this is the part where the order of S and the
challenges matters. Parameters: width 6, rate 4, capacity 2, 2 instances, LANES lanes."""
import itertools, random, sys
from math import comb, log2, lgamma, log

q = 8191
RATE, WIDTH = 4, 6
LANES = 3
WBITS = 13


class Perm:
    """Lazy random permutation with forward and inverse queries and capacity-collision tracking."""

    def __init__(self, rng):
        self.f, self.b, self.rng = {}, {}, rng
        self.caps = set()
        self.B1 = False
        self.rooted = set()
        self.iv = tuple(rng.randrange(q) for _ in range(WIDTH))
        self.caps.add(self.iv[RATE:])
        self.inverse_made = set()

    def fresh(self, used):
        while True:
            v = tuple(self.rng.randrange(q) for _ in range(WIDTH))
            if v not in used:
                return v

    def fwd(self, s):
        if s in self.f:
            return self.f[s]
        o = self.fresh(self.b)
        if o[RATE:] in self.caps or o[RATE:] == s[RATE:]:
            self.B1 = True
        self.caps.update([s[RATE:], o[RATE:]])
        self.f[s], self.b[o] = o, s
        return o

    def inv(self, o):
        if o in self.b:
            return self.b[o]
        s = self.fresh(self.f)
        if s[RATE:] in self.caps or s[RATE:] == o[RATE:]:
            self.B1 = True
        self.caps.update([s[RATE:], o[RATE:]])
        self.f[s], self.b[o] = o, s
        self.inverse_made.add(s)
        return s


def eq_lane(x, a, b):
    return ((1 - x) * a + x * b) % q


def H(perm, stmt):
    """Statement chain. stmt: tuple of ints; last absorbed block is the final query."""
    s = list(perm.iv)
    idx = 0
    for v in (17, 2) + tuple(stmt):
        if idx == RATE:
            s = list(perm.fwd(tuple(s)))
            idx = 0
        s[idx] = (s[idx] + v) % q
        idx += 1
    return perm.fwd(tuple(s))[0]


def beta(perm, x):
    """Main root at L=1: absorb x, squeeze LANES elements from one block."""
    s = list(perm.iv)
    s[0] = (s[0] + x) % q
    return perm.fwd(tuple(s))[:LANES]


def kernel_vectors(rng, forms, count):
    """Random d in [-2^(WBITS-1),2^(WBITS-1))^(2*LANES) with every form zero mod q."""
    n = 2 * LANES
    k = len(forms)
    out = []
    half = 1 << (WBITS - 1)
    tries = 0
    while len(out) < count and tries < 10_000_000:
        tries += 1
        d = [rng.randrange(-half, half) for _ in range(n)]
        # Solve the last k coordinates mod q.
        A = [[f[n - k + j] % q for j in range(k)] + [(-sum(f[i] * d[i] for i in range(n - k))) % q] for f in forms]
        ok = True
        for c in range(k):
            piv = next((r for r in range(c, k) if A[r][c]), None)
            if piv is None:
                ok = False
                break
            A[c], A[piv] = A[piv], A[c]
            inv = pow(A[c][c], -1, q)
            A[c] = [v * inv % q for v in A[c]]
            for r in range(k):
                if r != c and A[r][c]:
                    A[r] = [(a - A[r][c] * b) % q for a, b in zip(A[r], A[c])]
        if not ok:
            continue
        sol = [A[j][k] if A[j][k] < q // 2 else A[j][k] - q for j in range(k)]
        if all(-half <= v < half for v in sol):
            d[n - k:] = sol
            if any(d):
                out.append(d)
    return out


def form(perm, x):
    b = beta(perm, x)
    return [b[i] * (1 - x) % q for i in range(LANES)] + [b[i] * x % q for i in range(LANES)]


def early_attack(seed, K, draws):
    """Section 6.3 strategy: K roots first, then statements in their joint kernel."""
    rng = random.Random(seed)
    perm = Perm(rng)
    roots = rng.sample(range(2, q), K)
    forms = [form(perm, x) for x in roots]
    wins = 0
    ds = kernel_vectors(rng, forms, draws)
    base = [1 << (WBITS - 1)] * (2 * LANES)  # true outputs placed mid-box
    for d in ds:
        stmt = tuple(base[i] + d[i] for i in range(2 * LANES))
        x = H(perm, stmt)
        if x in roots:
            f = forms[roots.index(x)]
            assert sum(c * v for c, v in zip(f, d)) % q == 0
            wins += 1
            break
    return wins, len(ds)


def collision_no_gain(seed, draws):
    """Statements first, with no prepared kernel. Two statements with one r, one true. Does the true
    statement's sum pass for the false one? Should be about 1/q per collision."""
    rng = random.Random(seed)
    perm = Perm(rng)
    seen = {}
    pairs = hits = 0
    for _ in range(draws):
        d = [rng.randrange(-(1 << 9), 1 << 9) for _ in range(2 * LANES)]
        x = H(perm, tuple(d))
        seen.setdefault(x, []).append(d)
    for x, ds in seen.items():
        if len(ds) < 2:
            continue
        f = form(perm, x)
        for a, b in itertools.combinations(ds, 2):
            pairs += 1
            if sum(c * (u - v) for c, u, v in zip(f, a, b)) % q == 0 and a != b:
                hits += 1
    return pairs, hits


def rooted_check(seed, n):
    """Lemma 3: absent B1, no inverse-made query is rooted and parents precede children."""
    rng = random.Random(seed)
    perm = Perm(rng)
    log = []
    outs = []
    for _ in range(n):
        c = rng.random()
        if c < 0.3:
            o = tuple(rng.randrange(q) for _ in range(WIDTH))
            perm.inv(o)
            log.append(("inv", perm.b[o], o))
        elif c < 0.5 or not outs:
            s = list(perm.iv)
            s[0] = rng.randrange(q)
            s = tuple(s)
            log.append(("fwd", s, perm.fwd(s)))
            outs.append(log[-1][2])
        else:
            o = rng.choice(outs)
            s = tuple(rng.randrange(q) for _ in range(RATE)) + o[RATE:]
            log.append(("fwd", s, perm.fwd(s)))
            outs.append(log[-1][2])
    if perm.B1:
        return None
    rooted_caps = {perm.iv[RATE:]}
    bad = 0
    for kind, s, o in log:  # time order
        if s[RATE:] in rooted_caps:
            if kind == "inv":
                bad += 1
            rooted_caps.add(o[RATE:])
    # Second pass catches a child made before its parent.
    late = 0
    caps = {perm.iv[RATE:]}
    changed = True
    order = {id(e): i for i, e in enumerate(log)}
    while changed:
        changed = False
        for e in log:
            if e[1][RATE:] in caps and e[2][RATE:] not in caps:
                caps.add(e[2][RATE:])
                changed = True
    for e in log:
        if e[1][RATE:] in caps and e[2][RATE:] not in rooted_caps:
            late += 1
    return bad, late


def rmove(seed, L, P_, n):
    """Single wrong instance: delta vanishes iff some r_k equals the complement bit of the instance."""
    rng = random.Random(seed)
    j = 0
    hit = 0
    for _ in range(n):
        r = [rng.randrange(P_) for _ in range(L)]
        e = 1
        for rk in r:
            e = e * (1 - rk) % P_  # eq_r(0)
        if e == 0:
            hit += 1
    return hit / n, L / P_


def max_lucky(seed, W, roots):
    """Exhaustive over d in a small box: largest number of roots whose form vanishes on one nonzero d.
    Compares the pigeonhole K of the fixed-list strategy with what selection over many roots gives."""
    rng = random.Random(seed)
    n = 2 * 2
    box = range(-(1 << (W - 1)), 1 << (W - 1))
    forms = [[rng.randrange(q) for _ in range(n)] for _ in range(roots)]
    best = 0
    counts = {}
    # Meet in the middle on the first two coordinates is unnecessary at this size.
    import array
    total = 0
    for d in itertools.product(box, repeat=n):
        if not any(d):
            continue
        c = 0
        for f in forms:
            if (f[0] * d[0] + f[1] * d[1] + f[2] * d[2] + f[3] * d[3]) % q == 0:
                c += 1
        best = max(best, c)
        total += 1
    return best, total


def main():
    what = sys.argv[1]
    if what == "early":
        draws, trials = 150, int(sys.argv[2])
        for K in (1, 2, 3):
            w = g = 0
            for t in range(trials):
                a, n = early_attack(1000 * K + t, K, draws)
                w += a
                g += n
            print(f"early K={K}: win rate {w/trials:.4f}; predicted 1-(1-K/q)^draws ~ "
                  f"{1-(1-K/q)**draws:.4f}; mean kernel draws {g/trials:.0f}; K*draws/q {K*draws/q:.4f}")
    if what == "coll":
        P = H_ = 0
        for t in range(int(sys.argv[2])):
            a, b = collision_no_gain(t, 400)
            P += a
            H_ += b
        print(f"same-r pairs {P}, pairs passing sum check {H_}, rate {H_/max(P,1):.5f}, 1/q {1/q:.5f}")
    if what == "rooted":
        ok = bad = late = 0
        for t in range(int(sys.argv[2])):
            r = rooted_check(t, 40)
            if r is None:
                continue
            ok += 1
            bad += r[0]
            late += r[1]
        print(f"runs without B1: {ok}; inverse-made rooted queries: {bad}; child-before-parent: {late}")
    if what == "rmove":
        for L, P_ in ((1, 251), (3, 251), (8, 251)):
            print("rmove", L, P_, rmove(L, L, P_, 400000))
    if what == "lucky":
        for roots in (3, 30, 300):
            best, total = max_lucky(roots, 4, roots)
            print(f"box 16^4={total} d, q={q}: roots={roots} max roots vanishing on one d: {best}; "
                  f"pigeonhole K={log2(total)/log2(q):.2f}")


main()
