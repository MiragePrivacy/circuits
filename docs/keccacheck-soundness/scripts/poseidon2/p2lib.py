"""Plain Poseidon2 t=16 model over BN254 Fr; constants parsed from poseidon2_constants.rs."""
import re

p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
INV5 = pow(5, -1, p - 1)
DIAG = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 16, 17]
M4 = [[5, 7, 1, 3], [4, 6, 1, 1], [1, 3, 5, 7], [1, 1, 4, 6]]


def load_rc(path):
    src = open(path).read()
    i = src.index("RC16")
    v = [int(x) for x in re.findall(r'MontFp!\(\s*"(\d+)"\s*\)', src[i:])]
    assert len(v) == 185
    return [v[16 * r:16 * r + 16] for r in range(4)], v[64:121], [v[121 + 16 * r:121 + 16 * r + 16] for r in range(4)]


def mat4(x):
    return [sum(M4[i][j] * x[j] for j in range(4)) % p for i in range(4)]


def me(s):
    q = [mat4(s[4 * k:4 * k + 4]) for k in range(4)]
    tot = [sum(q[k][j] for k in range(4)) % p for j in range(4)]
    return [(q[k][j] + tot[j]) % p for k in range(4) for j in range(4)]


def mi(s):
    t = sum(s) % p
    return [(DIAG[i] * s[i] + t) % p for i in range(16)]


def sb(x):
    return pow(x, 5, p)


def rt(x):
    return pow(x, INV5, p)


def permute(s, rc, trace=None):
    s = me(s)
    for r in rc[0]:
        s = me([sb((s[i] + r[i]) % p) for i in range(16)])
    for c in rc[1]:
        s = list(s)
        s[0] = sb((s[0] + c) % p)
        s = mi(s)
    for k, r in enumerate(rc[2]):
        w = [(s[i] + r[i]) % p for i in range(16)]
        if trace is not None and k == 3:
            trace.append(w)
        s = me([sb(x) for x in w])
    return s


def mat_inv(A):
    n = len(A)
    M = [list(map(lambda v: v % p, A[i])) + [1 if i == j else 0 for j in range(n)] for i in range(n)]
    for c in range(n):
        r = next(r for r in range(c, n) if M[r][c])
        M[c], M[r] = M[r], M[c]
        inv = pow(M[c][c], -1, p)
        M[c] = [x * inv % p for x in M[c]]
        for i in range(n):
            if i != c and M[i][c]:
                f = M[i][c]
                M[i] = [(a - f * b) % p for a, b in zip(M[i], M[c])]
    return [row[n:] for row in M]


def mv(A, x):
    return [sum(a * b for a, b in zip(row, x)) % p for row in A]


def rank(rows, n):
    M = [list(map(lambda v: v % p, r)) for r in rows]
    rk = 0
    for c in range(n):
        piv = next((i for i in range(rk, len(M)) if M[i][c]), None)
        if piv is None:
            continue
        M[rk], M[piv] = M[piv], M[rk]
        inv = pow(M[rk][c], -1, p)
        M[rk] = [x * inv % p for x in M[rk]]
        for i in range(len(M)):
            if i != rk and M[i][c]:
                f = M[i][c]
                M[i] = [(a - f * b) % p for a, b in zip(M[i], M[rk])]
        rk += 1
    return rk


def basis_extract(f):
    cols = []
    for j in range(16):
        e = [0] * 16
        e[j] = 1
        cols.append(f(e))
    return [[cols[j][i] for j in range(16)] for i in range(16)]


def mm(A, B):
    n = len(A)
    return [[sum(A[i][k] * B[k][j] for k in range(n)) % p for j in range(n)] for i in range(n)]
