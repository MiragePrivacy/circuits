"""Independent model of the Keccacheck verifier in crates/keccacheck/src/verifier.rs.

Keccak-f is written from FIPS 202 (rc LFSR, rho walk, pi map), not from the code.
The trace is computed over the field so non-Boolean inputs can be run too.
"""
import os
import random

BN254 = 21888242871839275222246405745257275088548364400416034343698204186575808495617
P = int(os.environ.get("KC_P", BN254))
HALF = (P + 1) // 2
if P == BN254:
    assert HALF == 10944121435919637611123202872628637544274182200208017171849102093287904247809


def inv(a):
    return pow(a % P, P - 2, P)


def rnd(rng=random):
    return rng.randrange(P)


# ---------------------------------------------------------------- FIPS 202
def fips_rc_bit(t):
    t %= 255
    if t == 0:
        return 1
    R = [1, 0, 0, 0, 0, 0, 0, 0]
    for _ in range(1, t + 1):
        R = [0] + R
        R[0] ^= R[8]
        R[4] ^= R[8]
        R[5] ^= R[8]
        R[6] ^= R[8]
        R = R[:8]
    return R[0]


def fips_round_constants():
    out = []
    for ir in range(24):
        rc = 0
        for j in range(7):
            rc |= fips_rc_bit(j + 7 * ir) << ((1 << j) - 1)
        out.append(rc)
    return out


def fips_rho_offsets():
    off = [0] * 25
    x, y = 1, 0
    for t in range(24):
        off[x + 5 * y] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    return off


def fips_pi_source():
    # A'[x,y] = A[(x+3y) mod 5, x]; returns src[dst]
    src = [0] * 25
    for y in range(5):
        for x in range(5):
            src[x + 5 * y] = (x + 3 * y) % 5 + 5 * x
    return src


RC = fips_round_constants()
RHO = fips_rho_offsets()
PI_SRC = fips_pi_source()


def rotl64(v, k):
    k %= 64
    return ((v << k) | (v >> (64 - k))) & (2**64 - 1) if k else v


def fips_keccak_f(state, rounds=24):
    A = list(state)
    start = 24 - rounds
    for ir in range(start, 24):
        C = [A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20] for x in range(5)]
        D = [C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1) for x in range(5)]
        th = [A[i] ^ D[i % 5] for i in range(25)]
        rh = [rotl64(th[i], RHO[i]) for i in range(25)]
        pi = [rh[PI_SRC[i]] for i in range(25)]
        ch = [0] * 25
        for y in range(5):
            for x in range(5):
                ch[x + 5 * y] = pi[x + 5 * y] ^ (
                    (pi[(x + 1) % 5 + 5 * y] ^ (2**64 - 1)) & pi[(x + 2) % 5 + 5 * y]
                )
        ch[0] ^= RC[ir]
        A = ch
    return A


def sha3_256_via_model(msg):
    rate = 136
    m = bytearray(msg) + b"\x06" + b"\x00" * ((rate - (len(msg) + 1) % rate) % rate)
    m[-1] |= 0x80
    st = [0] * 25
    for off in range(0, len(m), rate):
        for i in range(rate // 8):
            st[i] ^= int.from_bytes(m[off + 8 * i : off + 8 * i + 8], "little")
        st = fips_keccak_f(st)
    return b"".join(st[i].to_bytes(8, "little") for i in range(4))


# ---------------------------------------------------------------- polys
def eq1(x, y):
    return (x * y + (1 - x) * (1 - y)) % P


def eq(a, b):
    assert len(a) == len(b)
    out = 1
    for x, y in zip(a, b):
        out = out * eq1(x, y) % P
    return out


def eval_eq(r):
    """Table of eq(r, index) with r[0] weighting the most significant index bit."""
    out = [1]
    for ri in r:
        nxt = []
        for v in out:
            hi = v * ri % P
            nxt.append((v - hi) % P)
            nxt.append(hi)
        out = nxt
    return out


def mle(table, r):
    assert len(table) == 1 << len(r)
    t = list(table)
    for ri in r:
        h = len(t) // 2
        t = [(t[j] + ri * (t[h + j] - t[j])) % P for j in range(h)]
    return t[0]


def rot_table(z, off):
    """rot weights over k: k -> eq(z, k + off) within each 64-bit block (as derive_rot_evaluations_from_eq)."""
    e = eval_eq(z)
    n = len(e) // 64
    out = [0] * len(e)
    for inst in range(n):
        for b in range(64):
            out[inst * 64 + b] = e[inst * 64 + (b + off) % 64]
    return out


def rot_eval(off, a, b):
    """Port of rot_from_eq: prefix eq times rotated suffix eq evaluated at b."""
    pre = len(a) - 6
    return eq(a[:pre], b[:pre]) * mle(rot_table(a[pre:], off), b[pre:]) % P


def rotl_table(tab, off):
    n = len(tab) // 64
    out = [0] * len(tab)
    for inst in range(n):
        for b in range(64):
            out[inst * 64 + (b + off) % 64] = tab[inst * 64 + b]
    return out


def xor(a, b):
    return (a + b - 2 * a * b) % P


def hat(tab):
    return [(1 - 2 * v) % P for v in tab]


# ---------------------------------------------------------------- trace
class Layer:
    pass


def arith_round(a, rc, h):
    """One Keccak round on field-valued tables, using only the arithmetization."""
    N = h * 64
    L = Layer()
    L.a = a
    L.ahat = [hat(t) for t in a]
    L.chat = []
    for x in range(5):
        col = [1] * N
        for y in range(5):
            col = [c * v % P for c, v in zip(col, L.ahat[x + 5 * y])]
        L.chat.append(col)
    L.rotchat = [rotl_table(t, 1) for t in L.chat]
    L.dhat = [
        [u * v % P for u, v in zip(L.chat[(x + 4) % 5], L.rotchat[(x + 1) % 5])]
        for x in range(5)
    ]
    L.thetahat = [
        [u * v % P for u, v in zip(L.ahat[i], L.dhat[i % 5])] for i in range(25)
    ]
    L.theta = [[(1 - v) * HALF % P for v in t] for t in L.thetahat]
    L.rho = [rotl_table(L.theta[i], RHO[i]) for i in range(25)]
    L.pi = [L.rho[PI_SRC[i]] for i in range(25)]
    L.chi = [None] * 25
    for i in range(25):
        L.chi[i] = chi_expr_table(L.pi, i)
    L.rc = [0] * N
    for inst in range(h):
        for b in range(64):
            L.rc[inst * 64 + b] = (rc >> b) & 1
    L.iota = list(L.chi)
    L.iota[0] = [xor(u, v) for u, v in zip(L.chi[0], L.rc)]
    return L


def add_col(j, add):
    col = j % 5
    return (col + add) % 5 + (j - col)


def chi_expr(p, i):
    return xor(p[i], (1 - p[add_col(i, 1)]) * p[add_col(i, 2)] % P)


def chi_expr_table(pi, i):
    a, b, c = pi[i], pi[add_col(i, 1)], pi[add_col(i, 2)]
    return [xor(u, (1 - v) * w % P) for u, v, w in zip(a, b, c)]


def trace(input_tables, h, rounds=24):
    """Returns layers indexed by Keccak round index 24-rounds..23."""
    layers = {}
    cur = input_tables
    for t in range(24 - rounds, 24):
        layers[t] = arith_round(cur, RC[t], h)
        cur = layers[t].iota
    return layers


def words_to_tables(words, h):
    """words[lane][instance] -> bit tables with index instance*64+bit."""
    return [[(words[i][inst] >> b) & 1 for inst in range(h) for b in range(64)] for i in range(25)]


def strip_pi(pi):
    PI = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1]
    rho = list(pi)
    last = 1
    for target in PI:
        rho[last] = pi[target]
        last = target
    return rho


# ---------------------------------------------------------------- sumcheck engine
class SC:
    """True polynomial F = fn(tables at k) summed over the hypercube, folded MSB first."""

    def __init__(self, name, tables, fn, degree):
        self.name, self.tables, self.fn, self.degree = name, [list(t) for t in tables], fn, degree

    def evals(self, deg=None):
        d = self.degree if deg is None else deg
        size = len(self.tables[0])
        h = size // 2
        out = [0] * (d + 1)
        ts = self.tables
        lows = [t[:h] for t in ts]
        diffs = [[(t[h + j] - t[j]) for j in range(h)] for t in ts]
        for pt in range(d + 1):
            acc = 0
            for j in range(h):
                vals = [(lo[j] + pt * di[j]) % P for lo, di in zip(lows, diffs)]
                acc += self.fn(vals)
            out[pt] = acc % P
        return out

    def bind(self, r):
        h = len(self.tables[0]) // 2
        self.tables = [[(t[j] + r * (t[h + j] - t[j])) % P for j in range(h)] for t in self.tables]

    def final(self):
        assert len(self.tables[0]) == 1
        return self.fn([t[0] for t in self.tables]) % P

    def total(self):
        return sum(self.fn([t[j] for t in self.tables]) for j in range(len(self.tables[0]))) % P


def interp_eval(ys, x):
    """Evaluate the degree len(ys)-1 interpolant through (i, ys[i]) at x."""
    n = len(ys)
    acc = 0
    for i, yi in enumerate(ys):
        num, den = 1, 1
        for j in range(n):
            if j != i:
                num = num * (x - j) % P
                den = den * (i - j) % P
        acc += yi * num * inv(den)
    return acc % P


def poly_mul(a, b):
    out = [0] * (len(a) + len(b) - 1)
    for i, u in enumerate(a):
        for j, v in enumerate(b):
            out[i + j] = (out[i + j] + u * v) % P
    return out


def interp_coeffs(ys):
    n = len(ys)
    acc = [0] * n
    for i, yi in enumerate(ys):
        basis = [1]
        den = 1
        for j in range(n):
            if j != i:
                basis = poly_mul(basis, [-j % P, 1])
                den = den * (i - j) % P
        c = yi * inv(den) % P
        for k, v in enumerate(basis):
            acc[k] = (acc[k] + c * v) % P
    return acc


def horner(coeffs, x):
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % P
    return acc


# ---------------------------------------------------------------- sumcheck functions
def f_iota(beta0):
    def fn(v):
        e, c0, rl, rc = v
        return e * (beta0 * xor(c0, rc) + rl)
    return fn


def f_chi(beta):
    def fn(v):
        e, p = v[0], v[1:]
        s = 0
        for i in range(25):
            s += beta[i] * chi_expr(p, i)
        return e * (s % P)
    return fn


def f_rho(beta):
    def fn(v):
        s = 0
        for i in range(25):
            s += beta[i] * v[i] % P * v[25 + i]
        return s
    return fn


def f_theta(v):
    e = v[0]
    s = 0
    for j in range(5):
        s += v[1 + j] * v[6 + j]
    return e * (s % P)


def f_d(beta_d):
    def fn(v):
        e, c, rc = v[0], v[1:6], v[6:11]
        s = 0
        for j in range(5):
            s += beta_d[j] * c[(j + 4) % 5] % P * rc[(j + 1) % 5]
        return e * (s % P)
    return fn


def f_c(beta_c, beta_rc):
    def fn(v):
        e, ro, a = v[0], v[1], v[2:]
        s = 0
        for j in range(5):
            prod = 1
            for i in range(5):
                prod = prod * a[i * 5 + j] % P
            s += (beta_c[j] * e + beta_rc[j] * ro) % P * prod
        return s
    return fn


def f_a(beta1, beta2):
    def fn(v):
        e1, e2, a = v[0], v[1], v[2:]
        s = 0
        for i in range(25):
            s += (beta1[i] * e1 + beta2[i] * e2) % P * a[i]
        return s
    return fn


def f_prod(v):
    return v[0] * v[1]


# ---------------------------------------------------------------- run
class Reject(Exception):
    pass


class Oracle:
    """Default: uniform challenges. Override `force` to pick adversarial ones."""

    def __init__(self, rng=None):
        self.rng = rng or random.Random()

    def one(self, label, ctx=None):
        return self.rng.randrange(P)

    def vec(self, label, n, ctx=None):
        return [self.rng.randrange(P) for _ in range(n)]


class Honest:
    """Prover strategy. A subclass lies through `claims` and `round_poly`."""

    def round_poly(self, sc, claim, rnd_idx, session):
        evs = sc.evals()
        cs = interp_coeffs(evs)
        return cs

    def claims(self, stage, truth, check, ve, session):
        return list(truth)

    def first_sum(self, expected, session):
        return expected


class State:
    """Doom bookkeeping. pending[name] = (coefficient, delta)."""

    def __init__(self):
        self.pending = {}
        self.sc_err = 0
        self.log = []
        self.failed = False

    def refined(self):
        return self.failed or self.sc_err % P != 0 or any(c * d % P for c, d in self.pending.values())

    def naive(self):
        return self.failed or self.sc_err % P != 0 or any(d % P for _, d in self.pending.values())

    def note(self, where):
        self.log.append((where, self.refined(), self.naive()))


class Session:
    def __init__(self, in_tables, out_tables, h, prover=None, oracle=None, rounds=24, stop_on_reject=True):
        self.h, self.L = h, h.bit_length() - 1
        self.n = self.L + 6
        self.in_tables, self.out_tables = in_tables, out_tables
        self.rounds = rounds
        self.layers = trace(in_tables, h, rounds)
        self.prover = prover or Honest()
        self.oracle = oracle or Oracle()
        self.state = State()
        self.stop_on_reject = stop_on_reject
        self.rejected = []
        self.true_out = self.layers[23].iota
        self.dgs = {}

    def dg(self, name, cond):
        if cond % P == 0 if isinstance(cond, int) else cond:
            k = (name, self.state.refined())
            self.dgs[k] = self.dgs.get(k, 0) + 1

    def check(self, label, left, right):
        if (left - right) % P:
            self.rejected.append(label)
            self.state.failed = True
            if self.stop_on_reject:
                raise Reject(label)

    def sumcheck(self, sc, nvars, degree, claim, label):
        """verify_sumcheck: reads p1..pd, derives p0 from claim. True poly tracked in sc."""
        rs = []
        self.state.sc_err = (claim - sc.total()) % P
        self.state.note(f"{label}: start")
        for ridx in range(nvars):
            self.cur = (label, ridx)
            coeffs = self.prover.round_poly(sc, claim, ridx, self)
            # verifier sees p1..pd only
            ps = coeffs[1:]
            assert len(ps) == degree, (label, len(ps), degree)
            p0 = (claim - sum(ps)) * HALF % P
            r = self.oracle.one(f"{label}.r{ridx}", {"session": self, "sc": sc, "p": [p0] + ps, "claim": claim})
            rs.append(r)
            claim = horner([p0] + ps, r)
            sc.bind(r)
            self.state.sc_err = (claim - sc.total()) % P
            self.state.note(f"{label}.r{ridx}")
        return claim, rs

    def run(self):
        h, L, n = self.h, self.L, self.n
        st = self.state
        pows = [pow(2, i, P) for i in range(64)]
        words = lambda tabs: [
            [sum(tabs[i][inst * 64 + b] * pows[b] for b in range(64)) % P for inst in range(h)]
            for i in range(25)
        ]
        out_w = words(self.out_tables)
        true_w = words(self.true_out)
        self.out_w, self.true_w = out_w, true_w
        st.pending["stmt"] = (1, 0 if out_w == true_w else 1)
        st.note("statement")
        r = self.oracle.vec("r", L, {"session": self})
        delta_r = [mle([(a - b) % P for a, b in zip(out_w[i], true_w[i])], r) for i in range(25)]
        beta = self.oracle.vec("beta_out", 25, {"session": self, "delta": delta_r})
        expected = sum(beta[i] * mle(out_w[i], r) for i in range(25)) % P
        s = self.prover.first_sum(expected, self)
        self.check("output sum", s, expected)
        del st.pending["stmt"]
        truesum = sum(beta[i] * mle(true_w[i], r) for i in range(25)) % P
        # word reduction
        rlc_w = [sum(beta[i] * true_w[i][x] for i in range(25)) % P for x in range(h)]
        sc = SC("words", [eval_eq(r), rlc_w], f_prod, 2)
        assert sc.total() == truesum
        c, r_x = self.sumcheck(sc, L, 2, s, "words")
        tv = mle(rlc_w, r_x)
        self.dg("words.eq0", eq(r, r_x))
        chk = lambda v: v[0] * eq(r, r_x) % P
        v = self.prover.claims("words", [tv], chk, c, self)
        self.check("output word reduction", c, chk(v))
        st.pending["words_r_x"] = (1, (v[0] - tv) % P)
        st.note("words claim")
        words_r_x = v[0]
        # bit reduction
        rx_eq = eval_eq(r_x)
        bit_tab = [0] * 64
        for y in range(64):
            acc = 0
            for i in range(25):
                acc += beta[i] * sum(rx_eq[x] * self.true_out[i][x * 64 + y] for x in range(h))
            bit_tab[y] = acc % P
        sc = SC("bits", [pows, bit_tab], f_prod, 2)
        del st.pending["words_r_x"]
        c, r_y = self.sumcheck(sc, 6, 2, words_r_x, "bits")
        tv = mle(bit_tab, r_y)
        self.dg("bits.pow0", mle(pows, r_y))
        chk = lambda v: mle(pows, r_y) * v[0] % P
        v = self.prover.claims("bits", [tv], chk, c, self)
        self.check("output bit reduction", c, chk(v))
        s = v[0]
        st.sc_err = (s - tv) % P
        st.note("bits claim")
        alpha = r_x + r_y
        iota = None
        for t in range(23, 23 - self.rounds, -1):
            self.t = t
            alpha, iota = self.round(t, alpha, beta, s)
            if t != 24 - self.rounds:
                self.pending_final = iota
                # fresh RLC over the 25 lane claims
                beta = self.oracle.vec(f"t{t}.beta_next", 25, {"session": self, "delta": self.delta_iota})
                s = sum(beta[i] * iota[i] for i in range(25)) % P
                truth = sum(beta[i] * self.true_a[i] for i in range(25)) % P
                st.pending.clear()
                st.sc_err = (s - truth) % P
                st.note(f"t{t}.beta_next")
        # input check
        eq_alpha = eval_eq(alpha)
        for i in range(25):
            self.check(f"input lane {i}", sum(a * b for a, b in zip(self.in_tables[i], eq_alpha)) % P, iota[i])
        return True

    def round(self, t, alpha, beta, s):
        st = self.state
        Lr = self.layers[t]
        n = self.n
        pre = n - 6
        lab = f"t{t}"
        # iota
        rlc = [sum(beta[i] * Lr.chi[i][k] for i in range(1, 25)) % P for k in range(1 << n)]
        sc = SC(lab + ".iota", [eval_eq(alpha), Lr.chi[0], rlc, Lr.rc], f_iota(beta[0]), 3)
        ve, r_iota = self.sumcheck(sc, n, 3, s, lab + ".iota")
        truth = [mle(Lr.chi[0], r_iota), mle(rlc, r_iota)]
        e_eq = eq(alpha, r_iota)
        e_rc = mle(Lr.rc[:64], r_iota[pre:])
        self.dg("iota.eq0", e_eq)
        self.dg("iota.beta0_0", beta[0])
        self.dg("iota.rc_half", (1 - 2 * e_rc) % P)
        chk = lambda v: e_eq * (beta[0] * xor(v[0], e_rc) + v[1]) % P
        v = self.prover.claims(lab + ".iota", truth, chk, ve, self)
        self.check(lab + ".iota check", chk(v), ve)
        st.sc_err = 0
        st.pending = {"chi00": (beta[0], (v[0] - truth[0]) % P), "chi_rlc": (1, (v[1] - truth[1]) % P)}
        st.note(lab + ".iota claims")
        chi_00, chi_rlc = v
        x = self.oracle.one(lab + ".x", {"session": self, "d": st.pending, "beta0": beta[0], "role": "x"})
        y = self.oracle.one(lab + ".y", {"session": self, "d": st.pending, "beta0": beta[0], "x": x, "role": "y"})
        self.dg("xy.x0", x)
        self.dg("xy.y0", y)
        beta = [beta[0] * x % P] + [b * y % P for b in beta[1:]]
        expected = (beta[0] * chi_00 + y * chi_rlc) % P
        st.pending = {}
        # chi
        sc = SC(lab + ".chi", [eval_eq(r_iota)] + Lr.pi, f_chi(beta), 4)
        ve, r_chi = self.sumcheck(sc, n, 4, expected, lab + ".chi")
        truth = [mle(Lr.pi[i], r_chi) for i in range(25)]
        e_eq = eq(r_iota, r_chi)
        self.dg("chi.eq0", e_eq)
        chk = lambda v: e_eq * sum(beta[i] * chi_expr(v, i) for i in range(25)) % P
        pi = self.prover.claims(lab + ".chi", truth, chk, ve, self)
        self.check(lab + ".chi check", chk(pi), ve)
        st.sc_err = 0
        rho_claim = strip_pi(pi)
        rho_true = strip_pi(truth)
        delta = [(a - b) % P for a, b in zip(rho_claim, rho_true)]
        st.pending = {f"rho{i}": (1, delta[i]) for i in range(25)}
        st.note(lab + ".chi claims")
        beta = self.oracle.vec(lab + ".beta_rho", 25, {"session": self, "delta": delta})
        expected = sum(beta[i] * rho_claim[i] for i in range(25)) % P
        st.pending = {}
        # rho
        rots = [rot_table(r_chi, RHO[i]) for i in range(25)]
        sc = SC(lab + ".rho", rots + Lr.theta, f_rho(beta), 2)
        ve, r_rho = self.sumcheck(sc, n, 2, expected, lab + ".rho")
        truth = [mle(Lr.theta[i], r_rho) for i in range(25)]
        rv = [rot_eval(RHO[i], r_chi, r_rho) for i in range(25)]
        for i_ in range(25):
            self.dg("rho.rot0", rv[i_])
        chk = lambda v: sum(beta[i] * rv[i] % P * v[i] for i in range(25)) % P
        th = self.prover.claims(lab + ".rho", truth, chk, ve, self)
        self.check(lab + ".rho check", chk(th), ve)
        st.sc_err = 0
        delta = [(1 - 2 * a - (1 - 2 * b)) % P for a, b in zip(th, truth)]
        st.pending = {f"th{i}": (1, delta[i]) for i in range(25)}
        st.note(lab + ".rho claims")
        beta = self.oracle.vec(lab + ".beta_theta", 25, {"session": self, "delta": delta})
        expected = sum(beta[i] * (1 - 2 * th[i]) for i in range(25)) % P
        st.pending = {}
        # theta
        ai_tabs = [
            [sum(beta[r * 5 + j] * Lr.ahat[r * 5 + j][k] for r in range(5)) % P for k in range(1 << n)]
            for j in range(5)
        ]
        sc = SC(lab + ".theta", [eval_eq(r_rho)] + Lr.dhat + ai_tabs, f_theta, 3)
        ve, r_th = self.sumcheck(sc, n, 3, expected, lab + ".theta")
        truth = [mle(t_, r_th) for t_ in ai_tabs] + [mle(t_, r_th) for t_ in Lr.dhat]
        e_eq = eq(r_rho, r_th)
        self.dg("theta.eq0", e_eq)
        chk = lambda v: e_eq * sum(v[5 + j] * v[j] for j in range(5)) % P
        v = self.prover.claims(lab + ".theta", truth, chk, ve, self)
        self.check(lab + ".theta check", chk(v), ve)
        st.sc_err = 0
        ai, d = v[:5], v[5:]
        d_ai = [(ai[j] - truth[j]) % P for j in range(5)]
        d_d = [(d[j] - truth[5 + j]) % P for j in range(5)]
        st.pending = {**{f"ai{j}": (1, d_ai[j]) for j in range(5)}, **{f"d{j}": (1, d_d[j]) for j in range(5)}}
        st.note(lab + ".theta claims")
        beta_d = self.oracle.vec(lab + ".beta_d", 5, {"session": self, "delta": d_d})
        expected = sum(beta_d[j] * d[j] for j in range(5)) % P
        keep = {f"ai{j}": (1, d_ai[j]) for j in range(5)}
        st.pending = dict(keep)
        # theta_d
        sc = SC(lab + ".d", [eval_eq(r_th)] + Lr.chat + Lr.rotchat, f_d(beta_d), 3)
        ve, r_d = self.sumcheck(sc, n, 3, expected, lab + ".d")
        truth = [mle(t_, r_d) for t_ in Lr.chat] + [mle(t_, r_d) for t_ in Lr.rotchat]
        e_eq = eq(r_th, r_d)
        self.dg("d.eq0", e_eq)
        chk = lambda v: e_eq * sum(beta_d[j] * v[(j + 4) % 5] % P * v[5 + (j + 1) % 5] for j in range(5)) % P
        v = self.prover.claims(lab + ".d", truth, chk, ve, self)
        self.check(lab + ".d check", chk(v), ve)
        st.sc_err = 0
        delta = [(a - b) % P for a, b in zip(v, truth)]
        st.pending = {**keep, **{f"cl{j}": (1, delta[j]) for j in range(10)}}
        st.note(lab + ".d claims")
        bc = self.oracle.vec(lab + ".beta_c", 10, {"session": self, "delta": delta})
        beta_c, beta_rc = bc[:5], bc[5:]
        expected = sum(bc[j] * v[j] for j in range(10)) % P
        st.pending = dict(keep)
        # theta_c
        sc = SC(lab + ".c", [eval_eq(r_d), rot_table(r_d, 1)] + Lr.ahat, f_c(beta_c, beta_rc), 6)
        ve, r_c = self.sumcheck(sc, n, 6, expected, lab + ".c")
        truth = [mle(t_, r_c) for t_ in Lr.ahat]
        e_eq = eq(r_d, r_c)
        e_rot = rot_eval(1, r_d, r_c)
        self.dg("c.eq0", e_eq)
        self.dg("c.rot0", e_rot)
        self.dg("c.v4_eq_v6", 0 if r_c == r_th else 1)
        def chk(v):
            s_ = 0
            for j in range(5):
                prod = 1
                for i in range(5):
                    prod = prod * v[i * 5 + j] % P
                s_ += (beta_c[j] * e_eq + beta_rc[j] * e_rot) % P * prod
            return s_ % P
        a = self.prover.claims(lab + ".c", truth, chk, ve, self)
        self.check(lab + ".c check", chk(a), ve)
        st.sc_err = 0
        d_a = [(u - w) % P for u, w in zip(a, truth)]
        st.pending = {**keep, **{f"a{i}": (1, d_a[i]) for i in range(25)}}
        st.note(lab + ".c claims")
        ba = self.oracle.vec(lab + ".beta_a", 30, {"session": self, "delta": d_ai + d_a})
        b_col, beta_a = ba[:5], ba[5:]
        beta = list(beta)
        for j in range(5):
            self.dg("a.b0", b_col[j])
            for r in range(5):
                beta[r * 5 + j] = beta[r * 5 + j] * b_col[j] % P
        expected = (sum(b_col[j] * ai[j] for j in range(5)) + sum(beta_a[i] * a[i] for i in range(25))) % P
        st.pending = {}
        # theta_a
        sc = SC(lab + ".a", [eval_eq(r_th), eval_eq(r_c)] + Lr.ahat, f_a(beta, beta_a), 2)
        ve, r_a = self.sumcheck(sc, n, 2, expected, lab + ".a")
        truth = [mle(t_, r_a) for t_ in Lr.ahat]
        e1, e2 = eq(r_th, r_a), eq(r_c, r_a)
        self.dg("a.eq1_0", e1)
        self.dg("a.eq2_0", e2)
        chk = lambda v: sum((beta[j] * e1 + beta_a[j] * e2) % P * v[j] for j in range(25)) % P
        v = self.prover.claims(lab + ".a", truth, chk, ve, self)
        self.check(lab + ".a check", chk(v), ve)
        st.sc_err = 0
        iota = [(1 - u) * HALF % P for u in v]
        self.true_a = [mle(t_, r_a) for t_ in Lr.a]
        self.delta_iota = [(u - w) % P for u, w in zip(iota, self.true_a)]
        st.pending = {f"A{i}": (1, self.delta_iota[i]) for i in range(25)}
        st.note(lab + ".a claims")
        return r_a, iota
