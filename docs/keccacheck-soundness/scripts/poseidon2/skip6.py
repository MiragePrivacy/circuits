"""One-layer skip on a degree-6 sumcheck block at positions 0..5, the first round of the C sumcheck.

Line direction v = M^-1 e_i in quad 0 makes ME v = (2,1,1,1) tensor e_i. Three linear conditions
align the four active S-box inputs, so they share one root and the layer output is affine in z.
The pinned challenge y* must make the line keep the verifier relation, which needs a root in Fp.
"""
import random
import sys

sys.path.insert(0, sys.argv[2])
from p2lib import *

rc = load_rc(sys.argv[1])
R = random.Random(11)
HALF = pow(2, -1, p)
M4I = mat_inv(M4)
ME = basis_extract(me)


def poly_mulmod(a, b, f):
    r = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            r[i + j] = (r[i + j] + x * y) % p
    n = len(f) - 1
    li = pow(f[-1], -1, p)
    for k in range(len(r) - 1, n - 1, -1):
        c = r[k] * li % p
        if c:
            for j in range(n + 1):
                r[k - n + j] = (r[k - n + j] - c * f[j]) % p
    return (r[:n] + [0] * n)[:n]


def poly_gcd(a, b):
    def trim(x):
        while x and x[-1] == 0:
            x = x[:-1]
        return x

    a, b = trim(a), trim(b)
    while b:
        li = pow(b[-1], -1, p)
        a = list(a)
        for k in range(len(a) - 1, len(b) - 2, -1):
            c = a[k] * li % p
            if c:
                for j in range(len(b)):
                    a[k - len(b) + 1 + j] = (a[k - len(b) + 1 + j] - c * b[j]) % p
        a, b = b, trim(a[: len(b) - 1])
    return a


def roots(f):
    """Roots of f in Fp via equal degree splitting of gcd(x^p - x, f)."""
    n = len(f) - 1
    x = ([0, 1] + [0] * n)[:n]
    acc = ([1] + [0] * n)[:n]
    e = p
    base = x
    while e:
        if e & 1:
            acc = poly_mulmod(acc, base, f)
        base = poly_mulmod(base, base, f)
        e >>= 1
    h = list(acc)
    h[1] = (h[1] - 1) % p
    g = poly_gcd(f, h)
    out = []

    def split(g):
        d = len(g) - 1
        if d <= 0:
            return
        if d == 1:
            out.append((-g[0]) * pow(g[1], -1, p) % p)
            return
        while True:
            s = R.randrange(p)
            nn = d
            base = ([s, 1] + [0] * nn)[:nn]
            acc = ([1] + [0] * nn)[:nn]
            e = (p - 1) // 2
            while e:
                if e & 1:
                    acc = poly_mulmod(acc, base, g)
                base = poly_mulmod(base, base, g)
                e >>= 1
            acc = list(acc)
            acc[0] = (acc[0] - 1) % p
            w = poly_gcd(g, acc)
            if 0 < len(w) - 1 < d:
                split(w)
                # quotient
                q = []
                rr = list(g)
                li = pow(w[-1], -1, p)
                for k in range(len(rr) - len(w), -1, -1):
                    c = rr[k + len(w) - 1] * li % p
                    q.insert(0, c)
                    for j in range(len(w)):
                        rr[k + j] = (rr[k + j] - c * w[j]) % p
                split(q)
                return

    split(g)
    return out


found = 0
for trial in range(20):
    fixed = [R.randrange(p) for _ in range(10)]  # positions 6..15 are fixed in this block
    claim = R.randrange(p)
    truth = [R.randrange(p) for _ in range(6)]  # honest coefficients, unknown to the relation form
    for i in range(4):
        a = [M4I[r][i] for r in range(4)]
        v = a + [0] * 12
        w = me(v)
        assert [w[4 * k + i] for k in range(4)] == [2, 1, 1, 1]
        assert all(w[j] == 0 for j in range(16) if j % 4 != i)
        # relation slope in t: sum_k v_k (y^(k+1) - 1/2) = 0
        coeff = [0] * 5
        for k in range(4):
            coeff[k + 1] = (coeff[k + 1] + v[k]) % p
            coeff[0] = (coeff[0] - v[k] * HALF) % p
        rs = [y for y in roots(coeff) if y]
        if not rs:
            continue
        ystar = rs[0]
        # unknowns U in positions 0..5: 3 alignment rows, 1 relation row
        S = [(me([0] * 6 + fixed)[j] + rc[0][0][j]) % p for j in range(16)]
        T = [i, 4 + i, 8 + i, 12 + i]
        rows = []
        rhs = []
        for k, c in ((1, HALF), (2, HALF), (3, HALF)):
            # S_T[k] = S_T[0] / 2
            rows.append([(ME[T[k]][j] - c * ME[T[0]][j]) % p for j in range(6)])
            rhs.append((c * S[T[0]] - S[T[k]]) % p)
        rows.append([(pow(ystar, k + 1, p) - HALF) % p for k in range(6)])
        rhs.append(R.randrange(p))  # relation constant, depends on the true polynomial
        rk = rank(rows, 6)
        # solve
        aug = [r + [b] for r, b in zip(rows, rhs)]
        n = len(aug)
        piv = []
        rr = 0
        for c in range(6):
            q = next((x for x in range(rr, n) if aug[x][c]), None)
            if q is None:
                continue
            aug[rr], aug[q] = aug[q], aug[rr]
            inv = pow(aug[rr][c], -1, p)
            aug[rr] = [x * inv % p for x in aug[rr]]
            for x in range(n):
                if x != rr and aug[x][c]:
                    f = aug[x][c]
                    aug[x] = [(u - f * z) % p for u, z in zip(aug[x], aug[rr])]
            piv.append(c)
            rr += 1
        U = [0] * 6
        for r_, c in enumerate(piv):
            U[c] = aug[r_][6]
        s0 = U + fixed
        base = [(me(s0)[j] + rc[0][0][j]) % p for j in range(16)]
        c0 = base[T[1]]  # common root offset: active input is w_i (t + c0)
        assert (base[T[0]] - 2 * c0) % p == 0 and base[T[2]] == c0 and base[T[3]] == c0

        def layer1(z):
            tau = rt(z)
            t = (tau - c0) % p
            inp = [(s0[j] + t * v[j]) % p for j in range(16)]
            assert inp[6:] == fixed
            st = me(inp)
            st = [sb((st[j] + rc[0][0][j]) % p) for j in range(16)]
            return inp, st

        zs = [R.randrange(p) for _ in range(4)]
        st = [layer1(z)[1] for z in zs]
        ok = True
        for j in range(16):
            slope = (st[1][j] - st[0][j]) * pow(zs[1] - zs[0], -1, p) % p
            for m in (2, 3):
                ok &= (st[m][j] - st[0][j]) % p == slope * (zs[m] - zs[0]) % p
        # relation slope stays zero along the curve
        rel = {
            (sum(layer1(z)[0][k] * (pow(ystar, k + 1, p) - HALF) for k in range(6))) % p for z in zs
        }
        found += 1
        print("trial", trial, "comp", i, "rank", rk, "S-box layer 1 affine in z:", ok,
              "relation constant along curve:", len(rel) == 1, "y* root found")
        break
print("instances solved", found, "of 20")
