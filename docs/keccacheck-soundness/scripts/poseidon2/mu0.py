"""What mu_0 = 1 changes: branch number, trail dimensions, S-box free projection; same for DIAG + 1."""
import itertools
import random
import sys

sys.path.insert(0, sys.argv[1])
from p2lib import *

R = random.Random(5)
ME = basis_extract(me)


def mi_d(d):
    return [[(1 + (d[i] if i == j else 0)) for j in range(16)] for i in range(16)]


def branch(M):
    """Exact branch number: min over x != 0 of wt(x) + wt(Mx), using rank of zero patterns."""
    best = 99
    for wx in range(1, 6):
        for S in itertools.combinations(range(16), wx):
            # x supported in S; zero as many outputs as possible
            for wy in range(0, best - wx):
                found = False
                for Y in itertools.combinations(range(16), wy):
                    Z = [i for i in range(16) if i not in Y]
                    sub = [[M[i][j] for j in S] for i in Z]
                    if rank(sub, wx) < wx:
                        found = True
                        break
                if found:
                    best = min(best, wx + wy)
                    break
            if wx + 1 >= best:
                break
        if wx + 1 >= best:
            break
    return best


def trail_dims(M):
    cons = [[1] + [0] * 15]
    Mp = [list(r) for r in M]
    out = []
    for i in range(1, 17):
        out.append(16 - rank(cons, 16))
        cons.append(Mp[0])
        Mp = mm(Mp, M)
    return out


def invariant_free(M, kmax):
    P = [list(r) for r in M]
    for k in range(1, kmax + 1):
        v = [1] + [0] * 15
        span = [v]
        while True:
            v = mv(P, v)
            rk = rank(span + [v], 16)
            if rk == 16:
                break
            if rk <= len(span):
                return False, k
            span.append(v)
        P = mm(P, M)
    return True, kmax


for name, d in (("deployed", DIAG), ("deployed+1", [x + 1 for x in DIAG]), ("distinct d0=18", [18] + DIAG[1:])):
    M = mi_d(d)
    print(name, "branch", branch(M), "trail dims", trail_dims(M), "no invariant subspace from e0 for M^k:", invariant_free(M, 64))

# projection along M e0 is free of the S-box output, for any mu_0
for name, d in (("deployed", DIAG), ("deployed+1", [x + 1 for x in DIAG])):
    M = mi_d(d)
    x = [R.randrange(p) for _ in range(16)]
    a, b = list(x), list(x)
    a[0], b[0] = R.randrange(p), R.randrange(p)
    A, B = mv(M, a), mv(M, b)
    k = pow(M[0][0], -1, p)  # (M e0)_i / (M e0)_0 = 1 / mu_0
    print(name, "x_i' - x_0'/mu_0 free of S-box output:", all((A[i] - k * A[0] - B[i] + k * B[0]) % p == 0 for i in range(1, 16)))

# low weight witness
M = mi_d(DIAG)
x = [1, p - 1] + [0] * 14
print("deployed M_I(e0 - e1) weight:", sum(1 for v in mv(M, x) if v))

# directions with nullity above one and support within nu, on deployed block sets
for name, pos in (("{0..5}", list(range(0, 6))), ("{1..6}", list(range(1, 7))), ("{1,2,3,4}", [1, 2, 3, 4]), ("{2,3,4,5}", [2, 3, 4, 5])):
    nu = len(pos)
    hits = []
    for T in itertools.chain.from_iterable(itertools.combinations(range(16), s) for s in range(2, nu + 1)):
        Z = [i for i in range(16) if i not in T]
        sub = [[ME[i][j] for j in pos] for i in Z]
        if nu - rank(sub, nu) >= 2:
            hits.append(T)
    print(name, "supports with |T|<=nu and nullity>=2:", len(hits), hits[:4])
