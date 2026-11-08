"""Exact feasibility of a single-variable first-layer skip for each controlled position set.

A line s + t v with ME v = w and support T of w passes the first S-box layer as an affine function of
z = (t + c)^5 iff the S-box inputs on T are c-aligned with w. That is |T| - 1 linear conditions on the
offset in the controlled positions. They are solvable for arbitrary fixed positions only if those
rows have full rank. This enumerates all supports with a one-dimensional direction space.
"""
import itertools
import sys

sys.path.insert(0, sys.argv[1])
from p2lib import *

ME = basis_extract(me)


def direction(sub):
    # kernel vector of sub when its nullity is exactly 1
    n = len(sub[0])
    M = [list(r) for r in sub]
    piv = []
    rk = 0
    for c in range(n):
        q = next((i for i in range(rk, len(M)) if M[i][c]), None)
        if q is None:
            continue
        M[rk], M[q] = M[q], M[rk]
        inv = pow(M[rk][c], -1, p)
        M[rk] = [x * inv % p for x in M[rk]]
        for i in range(len(M)):
            if i != rk and M[i][c]:
                f = M[i][c]
                M[i] = [(a - f * b) % p for a, b in zip(M[i], M[rk])]
        piv.append(c)
        rk += 1
    if n - rk != 1:
        return None
    fr = next(c for c in range(n) if c not in piv)
    v = [0] * n
    v[fr] = 1
    for r, c in enumerate(piv):
        v[c] = (-M[r][fr]) % p
    return v


def analyse(name, pos, pin=True):
    pos = list(pos)
    nu = len(pos)
    seen = set()
    best = None
    feasible = []
    for size in range(15, -1, -1):
        for Z in itertools.combinations(range(16), size):
            sub = [[ME[i][j] for j in pos] for i in Z] if size else [[0] * nu]
            if size and rank(sub, nu) != nu - 1:
                continue
            if not size and nu != 1:
                continue
            v = direction(sub) if size else [1]
            if v is None:
                continue
            w = [sum(ME[i][j] * v[k] for k, j in enumerate(pos)) % p for i in range(16)]
            T = tuple(i for i in range(16) if w[i])
            key = T
            if key in seen:
                continue
            seen.add(key)
            t0 = T[0]
            winv = pow(w[t0], -1, p)
            rows = [[(ME[k][j] - w[k] * winv * ME[t0][j]) % p for j in pos] for k in T[1:]]
            rk = rank(rows, nu) if rows else 0
            ok = rk == len(T) - 1
            if best is None or len(T) < best:
                best = len(T)
            if ok:
                feasible.append((len(T), T))
    feasible.sort()
    print("%-22s nu=%2d directions %5d min wt %2d feasible first-layer skips: %d; smallest %s" % (
        name, nu, len(seen), best, len(feasible), feasible[0] if feasible else None))
    if feasible:
        print("   with one pin row budget (needs |T|-1 <= nu-2):",
              any(a - 1 <= nu - 2 for a, _ in feasible))


for name, pos in (
    ("{0}", [0]),
    ("{0,1}", [0, 1]),
    ("{1,2}", [1, 2]),
    ("{5,6}", [5, 6]),
    ("{1,2,3}", [1, 2, 3]),
    ("{5,6,7}", [5, 6, 7]),
    ("{1,2,3,4}", [1, 2, 3, 4]),
    ("{2,3,4,5}", [2, 3, 4, 5]),
    ("{0..5}", range(0, 6)),
    ("{1..6}", range(1, 7)),
    ("{0..6}", range(0, 7)),
    ("{0..7}", range(0, 8)),
    ("{1..9}", range(1, 10)),
    ("{0..8}", range(0, 9)),
    ("{0..9}", range(0, 10)),
):
    analyse(name, pos)
