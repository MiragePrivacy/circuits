"""Exact minimum output weight of ME on rate-position subspaces, and degree checks with mu0 = 1."""
import itertools
import random
import sys

sys.path.insert(0, sys.argv[1])
from p2lib import *

ME = basis_extract(me)


def min_weight(pos):
    pos = list(pos)
    best = 17
    best_z = None
    # v nonzero in span(pos) with zeros on Z exists iff rank(ME[Z, pos]) < len(pos)
    for size in range(15, -1, -1):
        for Z in itertools.combinations(range(16), size):
            sub = [[ME[i][j] for j in pos] for i in Z] if size else [[0] * len(pos)]
            if rank(sub, len(pos)) < len(pos):
                return 16 - size, Z
    return None


for name, pos in (
    ("sumcheck deg 6 1..6", range(1, 7)),
    ("sumcheck deg 6 first 0..5", range(0, 6)),
    ("deg 4 1..4", range(1, 5)),
    ("0..6", range(0, 7)),
    ("0..7", range(0, 8)),
    ("0..8", range(0, 9)),
    ("0..9", range(0, 10)),
    ("1..9", range(1, 10)),
):
    w, Z = min_weight(pos)
    print("%-28s nu=%2d min wt(ME v)=%2d skip feasible (wt <= nu): %s" % (name, len(pos), w, w <= len(pos)))

# degree on a toy prime with gcd(5,q-1)=1
q = 2147483647
assert (q - 1) % 5 != 0
R = random.Random(3)


def toy_perm(x, diag, rf, rp, rcs):
    def mat4q(v):
        return [sum(M4[i][j] * v[j] for j in range(4)) % q for i in range(4)]

    def meq(s):
        qs = [mat4q(s[4 * k:4 * k + 4]) for k in range(4)]
        tot = [sum(qs[k][j] for k in range(4)) % q for j in range(4)]
        return [(qs[k][j] + tot[j]) % q for k in range(4) for j in range(4)]

    def miq(s):
        t = sum(s) % q
        return [(diag[i] * s[i] + t) % q for i in range(16)]

    s = meq(x)
    k = 0
    for _ in range(rf):
        s = meq([pow((s[i] + rcs[k][i]) % q, 5, q) for i in range(16)])
        k += 1
    for _ in range(rp):
        s = list(s)
        s[0] = pow((s[0] + rcs[k][0]) % q, 5, q)
        s = miq(s)
        k += 1
    return s


def exact_degree(f, bound):
    # returns degree of f (<= bound) by binomial finite differences
    vals = [f(j) for j in range(bound + 2)]

    def nth(n):
        c = 1
        acc = 0
        for j in range(n + 1):
            acc = (acc + (1 if (n - j) % 2 == 0 else -1) * c * vals[j]) % q
            c = c * (n - j) % q * pow(j + 1, -1, q) % q
        return acc

    return nth(bound), nth(bound + 1)


rcs = [[R.randrange(q) for _ in range(16)] for _ in range(20)]
for diag, label in ((DIAG, "deployed"), ([d + 1 for d in DIAG], "deployed+1")):
    for rf, rp in ((0, 2), (0, 4), (0, 6), (1, 3), (1, 5), (2, 3)):
        D = 5 ** (rf + rp)
        base = [R.randrange(q) for _ in range(16)]
        dirn = [R.randrange(q) for _ in range(16)]
        for comp in (0, 7):
            f = lambda t: toy_perm([(b + t * d) % q for b, d in zip(base, dirn)], diag, rf, rp, rcs)[comp]
            a, b = exact_degree(f, D)
            print(label, "rf", rf, "rp", rp, "comp", comp, "D", D, "Delta^D nonzero", a != 0, "Delta^(D+1) zero", b == 0)
