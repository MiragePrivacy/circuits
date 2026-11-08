"""Independent model of 01-spec.md: layers, verifier, honest and lying prover."""
import re, random, sys
R = 21888242871839275222246405745257275088548364400416034343698204186575808495617
HALF = 10944121435919637611123202872628637544274182200208017171849102093287904247809
SRC = 'experiments/keccacheck-arkworks/src/verifier.rs'
_src = open(SRC).read()
def _arr(name):
    m = re.search(r'const %s: \[[^\]]+\] = \[(.*?)\];' % name, _src, re.S)
    return [int(t, 0) for t in re.findall(r'0x[0-9a-fA-F]+|\d+', m.group(1))]
RCS, RHO, PI = _arr('ROUND_CONSTANTS'), _arr('RHO_OFFSETS'), _arr('PI')
assert len(RCS) == 24 and len(RHO) == 25 and len(PI) == 24
assert int(re.search(r'const HALF: Fr =\s*MontFp!\("(\d+)"\)', _src).group(1)) == HALF
inv = lambda a: pow(a % R, R - 2, R)
rnd = lambda: random.randrange(R)
add1 = lambda i, a: (i % 5 + a) % 5 + i - i % 5

# strip_pi as a map: rho_i = pi_{P[i]}
P = list(range(25)); last = 1
for t in PI:
    P[last] = t; last = t
assert sorted(P) == list(range(25))

def xor(a, b): return (a + b - 2 * a * b) % R
def eq(a, b):
    o = 1
    for x, y in zip(a, b): o = o * ((2 * x * y + 1 - x - y) % R) % R
    return o
def eq_table(r):
    t = [1]
    for x in r:
        t = [v for w in t for v in ((w * (1 - x)) % R, (w * x) % R)]
    return t
def mle(tab, pt):
    t = list(tab)
    for x in pt:
        h = len(t) // 2
        t = [(t[j] + x * (t[h + j] - t[j])) % R for j in range(h)]
    return t[0]
def dot(a, b): return sum(x * y for x, y in zip(a, b)) % R
def rot_eval(s, a, c, L):
    ea, ec = eq_table(a[L:]), eq_table(c[L:])
    return eq(a[:L], c[:L]) * sum(ea[(u + s) % 64] * ec[u] for u in range(64)) % R
def rot_table(s, a, L):
    """rot_s(a, k) as a table in k over {0,1}^n."""
    pre, suf = eq_table(a[:L]), eq_table(a[L:])
    return [pre[j] * suf[(u + s) % 64] % R for j in range(1 << L) for u in range(64)]

def words_to_bits(words):
    """words[lane][instance] -> bits[lane] table in idx order."""
    return [[(w >> b) & 1 for w in lane for b in range(64)] for lane in words]

def layers(in_tabs, L):
    """All round tables by field arithmetic of section 5 of the spec."""
    N = 64 << L; h = 1 << L
    A = [[x % R for x in tab] for tab in in_tabs]
    out = []
    rotl = lambda T, s: [T[(i & ~63) + (((i & 63) - s) % 64)] for i in range(N)]
    for t in range(24):
        Ah = [[(1 - 2 * v) % R for v in T] for T in A]
        Ch = []
        for x in range(5):
            T = [1] * N
            for y in range(5):
                T = [u * v % R for u, v in zip(T, Ah[x + 5 * y])]
            Ch.append(T)
        Rc = [rotl(Ch[x], 1) for x in range(5)]
        Dh = [[u * v % R for u, v in zip(Ch[(x + 4) % 5], Rc[(x + 1) % 5])] for x in range(5)]
        Th = [[((1 - u * v) * HALF) % R for u, v in zip(Ah[i], Dh[i % 5])] for i in range(25)]
        Rh = [rotl(Th[i], RHO[i]) for i in range(25)]
        Pi = [None] * 25
        for i in range(25): Pi[P[i]] = Rh[i]
        Chi = [[xor(a, (1 - b) * c % R) for a, b, c in zip(Pi[i], Pi[add1(i, 1)], Pi[add1(i, 2)])] for i in range(25)]
        rc = [(RCS[t] >> b) & 1 for b in range(64)]
        Io = [list(T) for T in Chi]
        Io[0] = [xor(v, rc[i & 63]) for i, v in enumerate(Chi[0])]
        out.append(dict(A=A, Ah=Ah, Ch=Ch, Rc=Rc, Dh=Dh, Th=Th, Rh=Rh, Pi=Pi, Chi=Chi, Io=Io, rc=rc))
        A = Io
    return out

def tables_to_words(tabs, L):
    return [[sum(tab[j * 64 + b] << b for b in range(64)) % R for j in range(1 << L)] for tab in tabs]

class Reject(Exception): pass
def check(name, a, b):
    if (a - b) % R: raise Reject(name)

def sc_verify(ch, d, m, c):
    pts = []
    for _ in range(m):
        p = [ch.read() for _ in range(d)]
        p0 = (c - sum(p)) * HALF % R
        r = ch.gen(); pts.append(r)
        acc = 0
        for co in reversed(p): acc = (co + r * acc) % R
        c = (p0 + r * acc) % R
    return c, pts

def verify(ch, L, in_tabs, W, mon=None):
    """Spec sections 4 and 6. W[lane][instance] are field words. Raises Reject."""
    n = L + 6; h = 1 << L
    mon = mon or (lambda *a: None)
    r = [ch.gen() for _ in range(L)]
    beta = [ch.gen() for _ in range(25)]
    er = eq_table(r)
    s = ch.read()
    check('output sum', s, sum(beta[i] * dot(W[i], er) for i in range(25)))
    mon('sum', dict(r=r, beta=list(beta), s=s))
    c, rx = sc_verify(ch, 2, L, s)
    wr = ch.read()
    check('word', c, wr * eq(r, rx))
    mon('word', dict(rx=rx, beta=list(beta), wr=wr))
    c, ry = sc_verify(ch, 2, 6, wr)
    be = ch.read()
    check('bit', c, mle([1 << i for i in range(64)], ry) * be)
    mon('bit', dict(rx=rx, ry=ry, beta=list(beta), be=be))
    alpha = rx + ry; s = be; a = None
    for t in range(23, -1, -1):
        alpha, a = verify_round(ch, n, L, alpha, beta, s, RCS[t], t, mon)
        if t:
            s = 0
            for i in range(25):
                beta[i] = ch.gen(); s += beta[i] * a[i]
            s %= R
    eqa = eq_table(alpha)
    for i in range(25):
        check('input lane %d' % i, dot(in_tabs[i], eqa), a[i])

def verify_round(ch, n, L, alpha, beta, s, rc, t, mon):
    ve, v1 = sc_verify(ch, 3, n, s)
    c00, crl = ch.read(), ch.read()
    erc = mle([(rc >> b) & 1 for b in range(64)], v1[n - 6:])
    check('iota', eq(alpha, v1) * (beta[0] * xor(c00, erc) + crl), ve)
    mon('iota', dict(t=t, v=v1, beta=list(beta), c00=c00, crl=crl))
    x, y = ch.gen(), ch.gen()
    beta[0] = beta[0] * x % R
    for i in range(1, 25): beta[i] = beta[i] * y % R
    ve, v2 = sc_verify(ch, 4, n, (beta[0] * c00 + y * crl) % R)
    pi = [ch.read() for _ in range(25)]
    e = eq(v1, v2)
    check('chi', sum(e * beta[i] * xor(pi[i], (1 - pi[add1(i, 1)]) * pi[add1(i, 2)] % R) for i in range(25)), ve)
    mon('chi', dict(t=t, v=v2, pi=pi))
    rho = [pi[P[i]] for i in range(25)]
    c = 0
    for i in range(25):
        beta[i] = ch.gen(); c += beta[i] * rho[i]
    ve, v3 = sc_verify(ch, 2, n, c % R)
    th = [ch.read() for _ in range(25)]
    check('rho', sum(beta[i] * rot_eval(RHO[i], v2, v3, L) * th[i] for i in range(25)), ve)
    mon('rho', dict(t=t, v=v3, th=th))
    c = 0
    for i in range(25):
        beta[i] = ch.gen(); c += beta[i] * (1 - 2 * th[i])
    ve, v4 = sc_verify(ch, 3, n, c % R)
    ai = [ch.read() for _ in range(5)]; d = [ch.read() for _ in range(5)]
    check('theta', eq(v3, v4) * sum(d[j] * ai[j] for j in range(5)), ve)
    mon('theta', dict(t=t, v=v4, beta=list(beta), ai=ai, d=d))
    bd = [ch.gen() for _ in range(5)]
    ve, v5 = sc_verify(ch, 3, n, dot(bd, d))
    cc = [ch.read() for _ in range(5)]; rc_ = [ch.read() for _ in range(5)]
    check('theta_d', eq(v4, v5) * sum(bd[j] * cc[(j + 4) % 5] * rc_[(j + 1) % 5] for j in range(5)), ve)
    mon('theta_d', dict(t=t, v=v5, c=cc, rc=rc_))
    bc = [ch.gen() for _ in range(5)]; brc = [ch.gen() for _ in range(5)]
    ve, v6 = sc_verify(ch, 6, n, (dot(bc, cc) + dot(brc, rc_)) % R)
    a = [ch.read() for _ in range(25)]
    e, er = eq(v5, v6), rot_eval(1, v5, v6, L)
    cs = 0
    for j in range(5):
        pr = 1
        for i in range(5): pr = pr * a[i * 5 + j] % R
        cs += (bc[j] * e + brc[j] * er) * pr
    check('theta_c', cs, ve)
    mon('theta_c', dict(t=t, v=v6, a=a))
    c = 0
    for j in range(5):
        b = ch.gen()
        for row in range(5): beta[row * 5 + j] = beta[row * 5 + j] * b % R
        c += b * ai[j]
    ba = [ch.gen() for _ in range(25)]
    c = (c + dot(ba, a)) % R
    ve, v7 = sc_verify(ch, 2, n, c)
    ah = [ch.read() for _ in range(25)]
    e1, e2 = eq(v4, v7), eq(v6, v7)
    check('theta_a', sum((beta[j] * e1 + ba[j] * e2) * ah[j] for j in range(25)), ve)
    mon('theta_a', dict(t=t, v=v7, ah=ah))
    return v7, [(1 - v) * HALF % R for v in ah]

CHAL, END = object(), object()
class Chan:
    """Interactive channel. Prover generator yields values or CHAL."""
    def __init__(self, prover, force):
        self.p, self.force = prover, force
        self.next = next(prover)
    def read(self):
        v = self.next
        assert v is not CHAL and v is not END, 'schedule mismatch on read'
        self.next = next(self.p)
        return v
    def gen(self):
        assert self.next is CHAL, 'schedule mismatch on gen'
        c = self.force.pop(0) if self.force else rnd()
        self.next = self.p.send(c)
        return c
    def done(self): assert self.next is END

class Replay:
    """Replays a proof and a challenge list; records the schedule."""
    def __init__(self, proof, chal): self.pr, self.ch, self.ops = iter(proof), iter(chal), []
    def read(self): self.ops.append('R'); return next(self.pr)
    def gen(self): self.ops.append('G'); return next(self.ch)

class Schedule:
    """Records the read/generate schedule with no prover, all values 0-accepting."""
    def __init__(self): self.ops = []
    def read(self): self.ops.append('R'); return 0
    def gen(self): self.ops.append('G'); return 0

def interp(ys):
    """Coefficients of the degree len(ys)-1 polynomial through (t, ys[t])."""
    d = len(ys) - 1; co = [0] * (d + 1)
    for i, y in enumerate(ys):
        num = [1]; den = 1
        for j in range(d + 1):
            if j == i: continue
            num = [((num[k - 1] if k else 0) - j * (num[k] if k < len(num) else 0)) % R for k in range(len(num) + 1)]
            den = den * (i - j) % R
        f = y * inv(den) % R
        for k in range(d + 1): co[k] = (co[k] + f * num[k]) % R
    return co
def horner(co, t):
    a = 0
    for c in reversed(co): a = (c + t * a) % R
    return a

def sc_prove(tables, g, d, claim, st, label):
    """Yields p_1..p_d and challenges. Returns (final claim, point, final table values).
    A nonzero claim error is pushed along by a constant shift (the error halves) unless this
    stage is the planned escape, in which case a root of the error polynomial is forced."""
    tables = [list(T) for T in tables]; pts = []; first = True
    while len(tables[0]) > 1:
        h = len(tables[0]) // 2
        ys = [0] * (d + 2)
        for j in range(h):
            lo = [T[j] for T in tables]; hi = [T[h + j] for T in tables]
            df = [(b - a) % R for a, b in zip(lo, hi)]
            cur = lo
            for tt in range(d + 2):
                ys[tt] += g(cur)
                cur = [(u + v) % R for u, v in zip(cur, df)]
        ys = [y % R for y in ys]
        co = interp(ys[:d + 1])
        assert horner(co, d + 1) == ys[d + 1], 'degree bound exceeded at ' + label
        st['tight'][label] = st['tight'].get(label, False) or co[d] != 0
        delta = (claim - ys[0] - ys[1]) % R
        forced = None
        if delta:
            if first and st['plan'] == label:
                forced = rnd()
                kappa = delta * inv(1 - 2 * forced) % R
                q = [(-kappa * forced) % R, kappa]
                st['plan'] = None; st['escaped'] = label
            else:
                q = [delta * HALF % R]
            co = [(a + (q[i] if i < len(q) else 0)) % R for i, a in enumerate(co)]
        assert (2 * co[0] + sum(co[1:]) - claim) % R == 0
        for v in co[1:]: yield v
        if forced is not None: st['force'].append(forced)
        r = yield CHAL
        pts.append(r)
        claim = horner(co, r)
        tables = [[(T[j] + r * (T[h + j] - T[j])) % R for j in range(h)] for T in tables]
        first = False
    return claim, pts, [T[0] for T in tables]

def solve(fn, target):
    f0, f1 = fn(0), fn(1)
    return (target - f0) * inv(f1 - f0) % R

def rlc(st, label, deltas):
    """Coefficients for an RLC move: forced into the kernel when planned, else None."""
    if st['plan'] == label and any(d % R for d in deltas):
        st['plan'] = None; st['escaped'] = label
        co = [rnd() for _ in deltas]
        last = max(i for i, d in enumerate(deltas) if d % R)
        co[last] = 0
        co[last] = -dot(co, deltas) * inv(deltas[last]) % R
        st['force'].extend(co)

def prover(L, lay, W, st):
    n = L + 6; h = 1 << L
    plan_round = st.get('round', 23)
    tr = [0] * 0
    if st['plan'] == 'r':
        st['force'].extend(st['r_forced']); st['plan'] = None; st['escaped'] = 'r'
    r = []
    for _ in range(L): r.append((yield CHAL))
    T = tables_to_words(lay[23]['Io'], L)
    er = eq_table(r)
    deltas = [(dot(W[i], er) - dot(T[i], er)) % R for i in range(25)]
    rlc(st, 'beta0', deltas)
    beta = []
    for _ in range(25): beta.append((yield CHAL))
    s = sum(beta[i] * dot(W[i], er) for i in range(25)) % R
    yield s
    rlcw = [sum(beta[i] * T[i][j] for i in range(25)) % R for j in range(h)]
    ge = lambda v: v[0] * v[1] % R
    c, rx, fin = yield from sc_prove([er, rlcw], ge, 2, s, st, 'word')
    wr = fin[1]
    if (c - wr * eq(r, rx)) % R: wr = c * inv(eq(r, rx)) % R
    yield wr
    ex = eq_table(rx)
    bits = [sum(ex[j] * sum(beta[i] * lay[23]['Io'][i][j * 64 + b] for i in range(25)) for j in range(h)) % R for b in range(64)]
    pw = [1 << b for b in range(64)]
    c, ry, fin = yield from sc_prove([pw, bits], ge, 2, wr, st, 'bit')
    be = fin[1]
    if (c - fin[0] * be) % R: be = c * inv(fin[0]) % R
    yield be
    alpha = rx + ry; s = be; beta = list(beta)
    for t in range(23, -1, -1):
        alpha, s, beta = yield from prove_round(L, lay[t], alpha, beta, s, RCS[t], t, st, lay)
    yield END

def prove_round(L, Y, alpha, beta, s, rc, t, st, lay):
    n = L + 6
    here = t == st.get('round', 23)
    lab = lambda x: x if here else x + '@other'
    # iota
    Tabs = [eq_table(alpha), Y['rc'] * (1 << L)] + Y['Chi']
    def g(v):
        return v[0] * (beta[0] * xor(v[2], v[1]) + sum(beta[i] * v[2 + i] for i in range(1, 25))) % R
    c, v1, fin = yield from sc_prove(Tabs, g, 3, s, st, lab('iota'))
    c00 = fin[2]; crl = sum(beta[i] * fin[2 + i] for i in range(1, 25)) % R
    t00, trl = c00, crl
    if st.get('garbage') and beta[0] == 0:
        c00 = 12345; t00 = 12345
    e, erc = fin[0], fin[1]
    if (c - e * (beta[0] * xor(c00, erc) + crl)) % R:
        if here and st['plan'] == 'xy':
            c00 = (c00 + 1) % R
        crl = (c * inv(e) - beta[0] * xor(c00, erc)) % R
    yield c00; yield crl
    # x, y
    if here and st['plan'] == 'xy':
        st['plan'] = None; st['escaped'] = 'xy'
        x = rnd()
        dA = beta[0] * (c00 - t00) * x % R; dB = (crl - trl) % R
        st['force'] += [x, -dA * inv(dB) % R]
    x = yield CHAL; y = yield CHAL
    beta = list(beta)
    beta[0] = beta[0] * x % R
    for i in range(1, 25): beta[i] = beta[i] * y % R
    s = (beta[0] * c00 + y * crl) % R
    # chi
    def g(v):
        return v[0] * sum(beta[i] * xor(v[1 + i], (1 - v[1 + add1(i, 1)]) * v[1 + add1(i, 2)] % R) for i in range(25)) % R
    c, v2, fin = yield from sc_prove([eq_table(v1)] + Y['Pi'], g, 4, s, st, lab('chi'))
    e = fin[0]; pi = fin[1:]; tpi = list(pi)
    def cf(p): return e * sum(beta[i] * xor(p[i], (1 - p[add1(i, 1)]) * p[add1(i, 2)] % R) for i in range(25)) % R
    if (c - cf(pi)) % R:
        def fn(z):
            q = list(pi); q[0] = z; return cf(q)
        pi = list(pi); pi[0] = solve(fn, c)
    for v in pi: yield v
    rho = [pi[P[i]] for i in range(25)]; trho = [tpi[P[i]] for i in range(25)]
    if here: rlc(st, 'beta_rho', [(a - b) % R for a, b in zip(rho, trho)])
    beta = []
    for _ in range(25): beta.append((yield CHAL))
    s = dot(beta, rho)
    # rho
    rots = [rot_table(RHO[i], v2, L) for i in range(25)]
    def g(v): return sum(beta[i] * v[i] * v[25 + i] for i in range(25)) % R
    c, v3, fin = yield from sc_prove(rots + Y['Th'], g, 2, s, st, lab('rho'))
    th = fin[25:]; tth = list(th); rv = fin[:25]
    if (c - dot([beta[i] * rv[i] % R for i in range(25)], th)) % R:
        th = list(th)
        rest = sum(beta[i] * rv[i] * th[i] for i in range(1, 25))
        th[0] = (c - rest) * inv(beta[0] * rv[0]) % R
    for v in th: yield v
    if here: rlc(st, 'beta_theta', [(-2 * (a - b)) % R for a, b in zip(th, tth)])
    beta = []
    for _ in range(25): beta.append((yield CHAL))
    s = dot(beta, [(1 - 2 * v) % R for v in th])
    # theta
    def g(v):
        return v[0] * sum(v[1 + j] * sum(beta[j + 5 * y] * v[6 + j + 5 * y] for y in range(5)) for j in range(5)) % R
    c, v4, fin = yield from sc_prove([eq_table(v3)] + Y['Dh'] + Y['Ah'], g, 3, s, st, lab('theta'))
    e = fin[0]; d = list(fin[1:6]); A0 = fin[6:]
    ai = [sum(beta[j + 5 * y] * A0[j + 5 * y] for y in range(5)) % R for j in range(5)]
    tai, td = list(ai), list(d)
    if (c - e * dot(d, ai)) % R:
        if here and st.get('lie') == 'ai':
            rest = sum(d[j] * ai[j] for j in range(1, 5))
            ai[0] = (c * inv(e) - rest) * inv(d[0]) % R
        else:
            rest = sum(d[j] * ai[j] for j in range(1, 5))
            d[0] = (c * inv(e) - rest) * inv(ai[0]) % R
    for v in ai: yield v
    for v in d: yield v
    if here: rlc(st, 'beta_d', [(a - b) % R for a, b in zip(d, td)])
    bd = []
    for _ in range(5): bd.append((yield CHAL))
    s = dot(bd, d)
    # theta_d
    def g(v):
        return v[0] * sum(bd[j] * v[1 + (j + 4) % 5] * v[6 + (j + 1) % 5] for j in range(5)) % R
    c, v5, fin = yield from sc_prove([eq_table(v4)] + Y['Ch'] + Y['Rc'], g, 3, s, st, lab('theta_d'))
    e = fin[0]; cc = list(fin[1:6]); rcc = list(fin[6:11]); tcc, trcc = list(cc), list(rcc)
    def cf(cc): return e * sum(bd[j] * cc[(j + 4) % 5] * rcc[(j + 1) % 5] for j in range(5)) % R
    if (c - cf(cc)) % R:
        def fn(z):
            q = list(cc); q[4] = z; return cf(q)
        cc[4] = solve(fn, c)
    for v in cc: yield v
    for v in rcc: yield v
    if here: rlc(st, 'beta_c', [(a - b) % R for a, b in zip(cc, tcc)] + [(a - b) % R for a, b in zip(rcc, trcc)])
    bc = []
    for _ in range(5): bc.append((yield CHAL))
    brc = []
    for _ in range(5): brc.append((yield CHAL))
    s = (dot(bc, cc) + dot(brc, rcc)) % R
    # theta_c
    def col(v, j, off):
        pr = 1
        for y in range(5): pr = pr * v[off + j + 5 * y] % R
        return pr
    def g(v):
        return sum((bc[j] * v[0] + brc[j] * v[1]) * col(v, j, 2) for j in range(5)) % R
    c, v6, fin = yield from sc_prove([eq_table(v5), rot_table(1, v5, L)] + Y['Ah'], g, 6, s, st, lab('theta_c'))
    e, er = fin[0], fin[1]; a = list(fin[2:]); ta = list(a)
    def cf(a): return sum((bc[j] * e + brc[j] * er) * col(a, j, 0) for j in range(5)) % R
    if (c - cf(a)) % R:
        def fn(z):
            q = list(a); q[0] = z; return cf(q)
        a[0] = solve(fn, c)
    for v in a: yield v
    # b, ba
    if here: rlc(st, 'b_ba', [(u - w) % R for u, w in zip(ai, tai)] + [(u - w) % R for u, w in zip(a, ta)])
    beta = list(beta); bs = []
    for j in range(5):
        b = yield CHAL
        bs.append(b)
        for row in range(5): beta[row * 5 + j] = beta[row * 5 + j] * b % R
    ba = []
    for _ in range(25): ba.append((yield CHAL))
    s = (dot(bs, ai) + dot(ba, a)) % R
    # theta_a
    def g(v):
        return sum((beta[j] * v[0] + ba[j] * v[1]) * v[2 + j] for j in range(25)) % R
    c, v7, fin = yield from sc_prove([eq_table(v4), eq_table(v6)] + Y['Ah'], g, 2, s, st, lab('theta_a'))
    e1, e2 = fin[0], fin[1]; ah = list(fin[2:]); tah = list(ah)
    def cf(h): return sum((beta[j] * e1 + ba[j] * e2) * h[j] for j in range(25)) % R
    if (c - cf(ah)) % R:
        def fn(z):
            q = list(ah); q[0] = z; return cf(q)
        ah[0] = solve(fn, c)
    for v in ah: yield v
    avals = [(1 - v) * HALF % R for v in ah]
    tvals = [(1 - v) * HALF % R for v in tah]
    if t:
        if here: rlc(st, 'beta_next', [(u - w) % R for u, w in zip(avals, tvals)])
        beta = []
        for _ in range(25): beta.append((yield CHAL))
        s = dot(beta, avals)
    return v7, s, beta
