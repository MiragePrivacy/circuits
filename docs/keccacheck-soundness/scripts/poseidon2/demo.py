"""Numeric checks of structural claims on the real instance."""
import random
import sys

sys.path.insert(0, sys.argv[2] if len(sys.argv) > 2 else ".")
from p2lib import *

rc = load_rc(sys.argv[1])
R = random.Random(7)


def rnd():
    return R.randrange(p)


# test vector from the upstream gkr poseidon test
s = permute(list(range(16)), rc)
assert s[0] == 7913381039332130239696391099451993335431181984785002668304949494341223775274
assert s[15] == 12353300117943495010938017401947409192192248445045039923330878007229549978485
print("test vector ok")

ME = basis_extract(me)
MI = basis_extract(mi)
for i in range(16):
    for j in range(16):
        assert ME[i][j] == (2 if i // 4 == j // 4 else 1) * M4[i % 4][j % 4]
        assert MI[i][j] == (1 + (DIAG[i] if i == j else 0))
print("matrices extracted by basis vectors match spec form. rows 0 of MI:", MI[0])
M4I = mat_inv(M4)
print("M4 inverse has zero entries:", any(x == 0 for r in M4I for x in r))
MEI = mat_inv(ME)
print("ME inverse has zero entries:", any(x == 0 for r in MEI for x in r))

# branch number witness: one active quad at input, weight 4, one active per output quad
a = mv(M4I, [1, 0, 0, 0])
x = a + [0] * 12
y = me(x)
print("ME branch witness: wt(x) =", sum(1 for v in x if v), "wt(MEx) =", sum(1 for v in y if v))

# skip: (X, -X) on quads 0,1 using rate positions only, capacity fixed
cap = [rnd() for _ in range(6)]
C0 = rc[0][0]


def add(a, b):
    return [(x + y) % p for x, y in zip(a, b)]


def neg(a):
    return [(-x) % p for x in a]


def scale(k, a):
    return [k * x % p for x in a]


q3 = cap[2:6]
inv3 = pow(3, -1, p)
Cq = [C0[4 * k:4 * k + 4] for k in range(4)]


def first_round(a, b, X):
    # rate = (U0 + X, -X, a, b), capacity fixed; U0 from the 4 balance equations
    q2 = [a, b, cap[0], cap[1]]
    s23 = add(q2, q3)
    U0 = add(scale((-2 * inv3) % p, s23), scale((-inv3) % p, mv(M4I, add(Cq[0], Cq[1]))))
    inp = add(U0, X) + neg(X) + q2 + q3
    assert inp[10:] == cap
    return inp


def after_round(inp, r):
    s = me(inp)
    for k in range(r):
        s = [sb((s[i] + rc[0][k][i]) % p) for i in range(16)]
        if k < r - 1:
            s = me(s)
    return s


a, b = rnd(), rnd()
base = after_round(first_round(a, b, [rnd() for _ in range(4)]), 1)
ok = True
for _ in range(5):
    t = after_round(first_round(a, b, [rnd() for _ in range(4)]), 1)
    ok &= t[8:] == base[8:]
    ok &= all((t[i] + t[i + 4]) % p == 0 for i in range(4))
print("round 1 balance on rate only: quads 2,3 constant and quad1 = -quad0 across X:", ok)

# round 2 balance on two components needs a root of two degree 5 equations in (a,b).
# Component equations printed for PARI.
if len(sys.argv) > 3 and sys.argv[3] == "gp":
    import itertools
    print("gp input skipped")

# peel: functional on the first 8 squeezed elements equals w0^5 - w4^5
ae = mv(list(map(list, zip(*M4I))), [1, 0, 0, 0])  # a^T M = e0^T
inp = [rnd() for _ in range(16)]
tr = []
out = permute(inp, rc, tr)
w = tr[0]
lhs = sum(ae[i] * (out[i] - out[4 + i]) for i in range(4)) % p
rhs = (sb(w[0]) - sb(w[4])) % p
print("linear functional on outputs 0..7 equals w0^5 - w4^5:", lhs == rhs, " f support:", [1 if v else 0 for v in ae])

# mu0 = 1: y_i = x_i - x_0 after a partial round does not depend on the S-box output
x = [rnd() for _ in range(16)]
x2 = list(x)
v = rnd()
xa = list(x)
xb = list(x)
xa[0] = sb(x[0])
xb[0] = v
ma, mb = mi(xa), mi(xb)
print("after MI, y_i independent of S-box output:", all((ma[i] - ma[0] - mb[i] + mb[0]) % p == 0 for i in range(1, 16)))

# Krylov rank of the S-box row
row = [1] + [0] * 15
rows = []
for k in range(16):
    rows.append(row)
    row = [sum(row[i] * MI[i][j] for i in range(16)) % p for j in range(16)]
print("rank of e0 M^j, j<16:", rank(rows, 16))


# Subspace trail algorithms 1,2,3 of the reference script, s=1.
def nullspace(rows, n):
    M = [list(map(lambda v: v % p, r)) for r in rows]
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
    free = [c for c in range(n) if c not in piv]
    out = []
    for fr in free:
        v = [0] * n
        v[fr] = 1
        for r, c in enumerate(piv):
            v[c] = (-M[r][fr]) % p
        out.append(v)
    return out


def alg2(M):
    # smallest M-invariant subspace containing e0 must leave the coordinate-0-free space
    v = [1] + [0] * 15
    span = [v]
    while True:
        v = mv(M, v)
        span2 = span + [v]
        rk = rank(span2, 16)
        if rk == 16:
            return True, rk
        if rk <= len(span):
            # invariant proper subspace
            return False, rk
        span = span2


def alg1(M, t=16):
    # S_i = vectors with x0 = 0 kept inactive for i rounds; report dimension and invariance
    res = []
    Mp = [list(r) for r in M]
    constraints = [[1] + [0] * 15]
    powm = [list(r) for r in M]
    for i in range(1, 16):
        basis = nullspace(constraints, 16)
        img = [mv(powm, b) for b in basis]
        same = rank(basis + img, 16) == len(basis) if basis else False
        res.append((i, len(basis), same))
        constraints.append(powm[0])
        powm = mm(powm, M)
    return res


Mpow = [list(r) for r in MI]
okall = True
for r in range(1, 65):
    ok, rk = alg2(Mpow)
    okall &= ok
    Mpow = mm(Mpow, MI)
print("alg2 on MI^r r=1..64 (t=16 is 4t): pass =", okall)
A = alg1(MI)
print("inactive-coordinate subspace dims over rounds and invariance:", A)
print("trail: dimension after i rounds =", [d for _, d, _ in A], "invariant any:", any(s for _, _, s in A))


# Comparison: same test with a mu0 != 1 diagonal, to see if mu0=1 shortens anything
def mkmi(d):
    return [[(1 + (d[i] if i == j else 0)) for j in range(16)] for i in range(16)]


print("dims with DIAG:", [d for _, d, _ in alg1(MI)])
print("dims with d0=18:", [d for _, d, _ in alg1(mkmi([18] + DIAG[1:]))])

# minimal number of S-box-free rounds: full inactivity for 15 rounds needs a nonzero vector
print("max trail length with nonzero subspace:", max(i for i, d, _ in A if d > 0))

# weight of low-weight images of the sumcheck blocks
for name, pos in (("1..6", range(1, 7)), ("0..5", range(0, 6)), ("0..9", range(0, 10)), ("0..7", range(0, 8))):
    cols = []
    for j in pos:
        e = [0] * 16
        e[j] = 1
        cols.append(me(e))
    print("block", name, "rank of ME image:", rank(cols, 16))
