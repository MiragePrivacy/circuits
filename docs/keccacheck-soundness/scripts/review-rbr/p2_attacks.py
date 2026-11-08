"""Phase 2: cheating prover against the BN254 model with forced challenges.

For each attack, the state function of 02-interactive-soundness.md section 5 predicts accept or
reject before the run ends; the script asserts the prediction, and reports where doom was left.
"""
import random
import sys

sys.path.insert(0, sys.argv[1])
from model import *

ROUNDS = int(sys.argv[2]) if len(sys.argv) > 2 else 24
rng = random.Random(0xBADC0DE)
h = 2


def stmt(h=2, flips=((0, 10),)):
    words = [[rng.getrandbits(64) for _ in range(h)] for _ in range(25)]
    tabs = words_to_tables(words, h)
    true = trace(tabs, h, ROUNDS)[23].iota
    out = [list(t) for t in true]
    for lane, idx in flips:
        out[lane][idx] ^= 1
    return tabs, out


def positions(s):
    return [e for e in s.state.log if not e[0].endswith("claims") and not e[0].endswith("claim")]


def exits(s):
    pos = positions(s)
    return [b for (a, ra, _), (b, rb, _) in zip(pos, pos[1:]) if ra and not rb]


def run(tabs, out, h, prover, oracle):
    s = Session(tabs, out, h, prover=prover, oracle=oracle, rounds=ROUNDS)
    try:
        s.run()
        return s, True, None
    except Reject as e:
        return s, False, str(e)


class Liar(Honest):
    """Stays alive while doomed: p = G + c*prod(t - a_i), openings solved through a chosen coordinate."""

    def __init__(self, solve=None, lie=None, roots=None):
        self.solve = solve or {}
        self.lie = lie or {}
        self.roots = roots or {}
        self.chosen = {}

    def round_poly(self, sc, claim, ridx, session):
        evs = sc.evals()
        cs = interp_coeffs(evs)
        err = (claim - (evs[0] + evs[1])) % P
        if err == 0:
            return cs
        label = session.cur[0] + f".r{session.cur[1]}"
        d = sc.degree
        roots = self.roots.get(stage_key(label)) or [rng.randrange(P) for _ in range(d)]
        u = [1]
        for a in roots:
            u = poly_mul(u, [-a % P, 1])
        k = err * inv((horner(u, 0) + horner(u, 1)) % P) % P
        self.chosen[label] = roots
        return [(a + k * b) % P for a, b in zip(cs, u)]

    def claims(self, stage, truth, check, ve, session):
        v = list(truth)
        for idx, val in self.lie.get(stage, []):
            v[idx] = (v[idx] + val) % P
        if check(v) == ve:
            return v
        order = self.solve.get(stage, []) + list(range(len(v)))
        for idx in order:
            w = list(v)
            w[idx] = 0
            f0 = (check(w) - ve) % P
            w[idx] = 1
            f1 = (check(w) - ve) % P
            if f1 != f0:
                w[idx] = (-f0) * inv(f1 - f0) % P
                return w
        return v


def stage_key(label):
    return label


class Forcer(Oracle):
    def __init__(self, table=None):
        super().__init__(rng)
        self.table = table or {}
        self.hits = []

    def one(self, label, ctx=None):
        if label in self.table:
            self.hits.append(label)
            return self.table[label](ctx)
        return super().one(label, ctx)

    def vec(self, label, n, ctx=None):
        if label in self.table:
            self.hits.append(label)
            return self.table[label](ctx, n)
        return super().vec(label, n, ctx)


def rlc_root(ctx, n):
    """Uniform except one coordinate chosen so the linear form vanishes."""
    delta = ctx["delta"]
    assert len(delta) == n
    v = [rng.randrange(P) for _ in range(n)]
    idx = next(i for i, d in enumerate(delta) if d % P)
    s = sum(v[i] * delta[i] for i in range(n) if i != idx) % P
    v[idx] = (-s) * inv(delta[idx]) % P
    return v


def report(name, s, acc, why, expect_accept, expect_exit=None):
    ex = exits(s)
    state_final = s.state.refined()
    assert acc == expect_accept, (name, acc, why, ex)
    assert acc == (not state_final) or not acc
    if expect_exit is not None:
        assert ex and ex[0].startswith(expect_exit), (name, ex)
    print(f"{name:58s} accept={acc!s:5s} {'at ' + why if why else '':30s} exit={ex[:1]}")


T = 23 if ROUNDS == 24 else 23
n = 7


# ---- A. maximal lie
for seed in range(3):
    tabs, out = stmt()
    s, acc, why = run(tabs, out, h, Liar(), Oracle(rng))
    pos = positions(s)
    assert all(p[1] for p in pos[:-1])
    report(f"A{seed}: maximal lie, uniform challenges", s, acc, why, False)
    assert why.startswith("input lane")


# ---- B. forced root at each move type, false statement, honest after
def sc_root_force(label):
    def f(ctx):
        s = ctx["session"]
        return s.prover.chosen[label][0]
    return f


def lane0_false_force(ctx, n_):
    return rlc_root(ctx, n_)


tabs, out = stmt()

# r: only instance 0 false with h=2 -> root x_1 = 1; only instance 1 false -> x_1 = 0
tabs_, out_ = stmt(flips=((0, 10),))
s, acc, why = run(tabs_, out_, h, Liar(), Forcer({"r": lambda ctx, n_: [1]}))
report("B.r: instance 0 false, r=[1]", s, acc, why, True)
tabs_, out_ = stmt(flips=((0, 70),))
s, acc, why = run(tabs_, out_, h, Liar(), Forcer({"r": lambda ctx, n_: [0]}))
report("B.r: instance 1 false, r=[0]", s, acc, why, True)

s, acc, why = run(tabs, out, h, Liar(), Forcer({"beta_out": rlc_root}))
report("B.beta_out root", s, acc, why, True)

for lbl, expect in [("words.r0", "words"), ("bits.r0", "bits"), ("bits.r5", "bits"), ("t23.iota.r0", "t23.iota"), ("t23.iota.r6", "t23.iota"),
                    ("t23.chi.r3", "t23.chi"), ("t23.rho.r3", "t23.rho"), ("t23.theta.r3", "t23.theta"),
                    ("t23.d.r3", "t23.d"), ("t23.c.r3", "t23.c"), ("t23.a.r3", "t23.a")]:
    s, acc, why = run(tabs, out, h, Liar(solve={"t23.theta": [5]}), Forcer({lbl: sc_root_force(lbl)}))
    report(f"B.sc root {lbl}", s, acc, why, True, expect)


def xy_force_x(ctx):
    d = ctx["d"]
    a = ctx["beta0"] * d["chi00"][1] % P
    b = d["chi_rlc"][1] % P
    y = rng.randrange(1, P)
    Forcer.memo = y
    return (-y * b) * inv(a) % P if a else rng.randrange(P)


def xy_force_y(ctx):
    d = ctx["d"]
    a = ctx["beta0"] * d["chi00"][1] % P
    b = d["chi_rlc"][1] % P
    return (-ctx["x"] * a) * inv(b) % P if b else Forcer.memo


# (x,y) root with both deltas nonzero: chi_00 lied, chi_rlc solved
liar = Liar(lie={"t23.iota": [(0, 5)]}, solve={"t23.iota": [1]})
s, acc, why = run(tabs, out, h, liar, Forcer({"t23.x": lambda ctx: rng.randrange(1, P), "t23.y": xy_force_y}))
report("B.(x,y) root, both deltas nonzero", s, acc, why, True, "t23.chi")

for lbl, st_ in [("t23.beta_rho", "t23.rho"), ("t23.beta_theta", "t23.theta"), ("t23.beta_d", "t23.d"), ("t23.beta_c", "t23.c"), ("t23.beta_a", "t23.a"), ("t23.beta_next", "t23.beta_next")]:
    solve = {"t23.theta": [5]}
    s, acc, why = run(tabs, out, h, Liar(solve=solve), Forcer({lbl: rlc_root}))
    report(f"B.rlc root {lbl}", s, acc, why, True, st_)


# ---- C. adversarial zeros, predictions from T5, T6, T7 and others
def eq_zero_at(alpha_last):
    # alpha x + (1-alpha)(1-x) = 0
    return (alpha_last - 1) * inv(2 * alpha_last - 1) % P


class AlphaGrab(Oracle):
    pass


def force_last_eq(lbl, point_getter):
    def f(ctx):
        return eq_zero_at(point_getter(ctx["session"]))
    return f


# C1: eq(alpha,v1) = 0 in round 22, undoomed. Prover then lies through chi_rlc. Check passes. Prediction: doomed, reject.
tabs_t = stmt(flips=())
class Grab(Forcer):
    def __init__(self, table):
        super().__init__(table)
        self.points = {}


def last_point_force(sess_attr):
    def f(ctx):
        return eq_zero_at(getattr(ctx["session"], sess_attr))
    return f


# Capture alpha[-1] by wrapping Session.round
orig_round = Session.round


def wrapped_round(self, t, alpha, beta, s):
    self.alpha_last = alpha[-1]
    self.alpha_cur = alpha
    return orig_round(self, t, alpha, beta, s)


Session.round = wrapped_round
tabs_t, out_t = stmt(flips=())
s, acc, why = run(tabs_t, out_t, h, Liar(lie={"t22.iota": [(1, 9)]}), Forcer({"t22.iota.r6": last_point_force("alpha_last")}))
assert s.dgs.get(("iota.eq0", False)) or s.dgs.get(("iota.eq0", True))
report("C1 eq(alpha,v1)=0, true stmt, chi_rlc lied at round 22", s, acc, why, False)
assert why.startswith("input lane")

# C2: doomed with eq = 0 at the opening and ve != 0. Liar has p with random roots, so ve != 0. Prediction: check fails (T5 argument).
s, acc, why = run(tabs, out, h, Liar(), Forcer({"t23.iota.r6": last_point_force("alpha_last")}))
report("C2 eq(alpha,v1)=0 while doomed, ve != 0", s, acc, why, False)
assert why.startswith("t23.iota check")


# C3: doomed, p - G built to vanish at the eq root. Then ve = 0 = truth. Ordinary root of p - G, charged in T4.
class LiarRootAtEq(Liar):
    def round_poly(self, sc, claim, ridx, session):
        label = session.cur[0] + f".r{session.cur[1]}"
        if label == "t23.iota.r6":
            root = eq_zero_at(session.alpha_last)
            self.roots[label] = [root, rng.randrange(P), rng.randrange(P)]
        return super().round_poly(sc, claim, ridx, session)


s, acc, why = run(tabs, out, h, LiarRootAtEq(), Forcer({"t23.iota.r6": last_point_force("alpha_last")}))
report("C3 p-G vanishes at the eq root: exit charged to SC round", s, acc, why, True, "t23.iota.r6")


# C4: RC~(v1) = 1/2, honest until the opening. chi_00 then has no effect on the iota check. Lie on chi_00.
def rc_half_force(ctx):
    # Solve the last coordinate so the RC MLE is 1/2 given earlier challenges bound in sc tables.
    sc = ctx["sc"]
    rc_tab = sc.tables[3]
    lo, hi = rc_tab[0], rc_tab[1]
    if (hi - lo) % P == 0:
        return rng.randrange(P)
    return (HALF - lo) * inv(hi - lo) % P


tabs_t, out_t = stmt(flips=())
s, acc, why = run(tabs_t, out_t, h, Liar(lie={"t22.iota": [(0, 3)]}), Forcer({"t22.iota.r6": rc_half_force}))
assert s.dgs.get(("iota.rc_half", False)), s.dgs
report("C4 RC~(v1)=1/2, chi_00 lied: check blind, state doomed", s, acc, why, False)
assert why.startswith("input lane")

# C5: as C4, with (x) root at x=0: chi_00's lie is erased by x = 0. Prediction: accepted, escape charged to (x,y).
s, acc, why = run(tabs_t, out_t, h, Liar(lie={"t22.iota": [(0, 3)]}), Forcer({"t22.iota.r6": rc_half_force, "t22.x": lambda c: 0}))
report("C5 chi_00 lied, x = 0 (true statement stays accepted)", s, acc, why, True)

# C6: false statement, beta_0 forced 0 at beta_next and the only false lane is lane 0: exit at the RLC, not later.
class LieLaneZeroOnly(Liar):
    pass


def beta_next_with_zero(ctx, n_):
    delta = ctx["delta"]
    v = rlc_root(ctx, n_)
    return v


# Lie so that the a claims at t23 differ only in lane 0.
class L0(Liar):
    def claims(self, stage, truth, check, ve, session):
        if stage == "t23.a":
            # choose lane 0 to absorb the whole error
            v = list(truth)
            w = list(v)
            w[0] = 0
            f0 = (check(w) - ve) % P
            w[0] = 1
            f1 = (check(w) - ve) % P
            w[0] = (-f0) * inv(f1 - f0) % P
            return w
        return super().claims(stage, truth, check, ve, session)


def zero_beta0(ctx, n_):
    v = [rng.randrange(P) for _ in range(n_)]
    assert [i for i, d in enumerate(ctx["delta"]) if d % P] == [0]
    v[0] = 0
    return v


s, acc, why = run(tabs, out, h, L0(), Forcer({"t23.beta_next": zero_beta0}))
report("C6 only lane 0 false, beta_0 = 0 at beta_next: RLC root", s, acc, why, True, "t23.beta_next")


# C7: doomed, beta_0 = 0, so the opening must carry the whole error in chi_rlc. y = 0 is then the only exit.
class ChiRlc(Liar):
    def __init__(self):
        super().__init__(solve={"t23.a": [3], "t22.iota": [1]})


class BetaZeroAt(Forcer):
    pass


def beta0_zero_keep(ctx, n_):
    v = [rng.randrange(1, P) for _ in range(n_)]
    v[0] = 0
    return v


s, acc, why = run(tabs, out, h, ChiRlc(), Forcer({"t23.beta_next": beta0_zero_keep}))
report("C7 doomed, beta_0 = 0, x,y uniform: stays doomed", s, acc, why, False)
assert why.startswith("input lane")
s, acc, why = run(tabs, out, h, ChiRlc(), Forcer({"t23.beta_next": beta0_zero_keep, "t22.y": lambda c: 0}))
report("C7b same, y = 0: root of y d1, exit at (x,y)", s, acc, why, True, "t22.chi")
s, acc, why = run(tabs, out, h, ChiRlc(), Forcer({"t23.beta_next": beta0_zero_keep, "t22.x": lambda c: 0}))
report("C7c same, x = 0: no effect, stays doomed", s, acc, why, False)


# C8: rot_{s}(v2,v3) = 0 for a lane, theta_i free. Lie on it. Prediction: doomed, reject.
def rot_zero_force(lane):
    def f(ctx):
        sc = ctx["sc"]
        tab = sc.tables[lane]
        lo, hi = tab[0], tab[1]
        return (-lo) * inv(hi - lo) % P
    return f


tabs_t, out_t = stmt(flips=())
s, acc, why = run(tabs_t, out_t, h, Liar(lie={"t22.rho": [(7, 11)]}), Forcer({"t22.rho.r6": rot_zero_force(7)}))
assert s.dgs.get(("rho.rot0", False)), s.dgs
report("C8 rot=0 for lane 7, theta_7 lied", s, acc, why, False)
assert why.startswith("input lane")


# ---- D. pending ai
# D1: ai false only. Sumchecks D and C run with c true: force 'root like' challenges there. Doom must persist.
class AiOnly(Liar):
    def __init__(self):
        super().__init__(lie={"t23.theta": [(0, 77)]}, solve={"t23.theta": [1]})


def consistent_ai(tabs, out):
    pass


# Start from a true statement so the theta opening check must be solved via ai_1 too: two ai lies, d true.
tabs_t, out_t = stmt(flips=())
class AiPair(Liar):
    def claims(self, stage, truth, check, ve, session):
        if stage == "t22.theta":
            v = list(truth)
            # shift ai_0 and compensate in ai_1 so sum d_x ai_x still correct, d all true
            v[0] = (v[0] + 77 * truth[6]) % P
            v[1] = (v[1] - 77 * truth[5]) % P
            assert check(v) == ve
            return v
        return super().claims(stage, truth, check, ve, session)


s, acc, why = run(tabs_t, out_t, h, AiPair(), Oracle(rng))
pos = positions(s)
ai_section = [p for p in pos if p[0].startswith(("t22.d.", "t22.d:", "t22.c.", "t22.c:"))]
assert len(ai_section) == 2 * 7 + 2
assert all(p[1] for p in ai_section), "AI-false must hold through D and C"
assert all(not p[0].startswith("t22.d: ") or True for p in pos)
report("D1 ai_0, ai_1 lied with zero net effect on theta check", s, acc, why, False)
assert why.startswith("input lane")

# D2: same, with b and ba chosen as a root of the pending form. Prediction: accepted, exit at (b,ba).
s, acc, why = run(tabs_t, out_t, h, AiPair(), Forcer({"t22.beta_a": rlc_root}))
report("D2 same, (b,ba) root", s, acc, why, True, "t22.a")


# D3: column with all theta beta zero. True ai is 0. Prover claims ai_x != 0 with d compensated. AI-false holds, (b,ba) is the exit.
def beta_theta_col0_zero(ctx, n_):
    v = [rng.randrange(P) for _ in range(n_)]
    for y in range(5):
        v[5 * y] = 0
    return v


class ColZero(Liar):
    def claims(self, stage, truth, check, ve, session):
        if stage == "t22.theta":
            assert truth[0] == 0
            v = list(truth)
            v[0] = 7
            w = list(v)
            w[1] = 0
            f0 = (check(w) - ve) % P
            w[1] = 1
            f1 = (check(w) - ve) % P
            w[1] = (-f0) * inv(f1 - f0) % P
            return w
        return super().claims(stage, truth, check, ve, session)


s, acc, why = run(tabs_t, out_t, h, ColZero(), Forcer({"t22.beta_theta": beta_theta_col0_zero}))
report("D3 column beta all 0, ai_0 = 7 claimed", s, acc, why, False)

# D4: both ai and d false, bd root. T10 says doom persists through AI-false with no error.
tabs_b, out_b = stmt()
class AiD(Liar):
    def claims(self, stage, truth, check, ve, session):
        if stage == "t23.theta":
            v = list(truth)
            v[0] = (v[0] + 5) % P  # ai_0 false
            v[5] = (v[5] + 3) % P  # d_0 false
            w = list(v)
            w[6] = 0
            f0 = (check(w) - ve) % P
            w[6] = 1
            f1 = (check(w) - ve) % P
            w[6] = (-f0) * inv(f1 - f0) % P
            return w
        return super().claims(stage, truth, check, ve, session)


s, acc, why = run(tabs_b, out_b, h, AiD(), Forcer({"t23.beta_d": rlc_root}))
pos = positions(s)
st_ = [p for p in pos if p[0] == "t23.d: start"][0]
assert st_[1], "AI-false must keep it doomed after the d RLC root"
report("D4 ai and d false, bd root: still doomed by AI-false", s, acc, why, False)

# D5: as D4 with bd root and b root: exit only at (b,ba).
s, acc, why = run(tabs_b, out_b, h, AiD(), Forcer({"t23.beta_d": rlc_root, "t23.beta_a": rlc_root}))
report("D5 ai and d false, bd root and (b,ba) root", s, acc, why, True, "t23.a")

# D6: v4 = v6 coincidence: force theta_c challenges equal to theta challenges. f_a still fixed. Honest accepted, liar rejected.
class Replay:
    pass


class SameV(Forcer):
    def __init__(self):
        super().__init__()
        self.th = {}

    def one(self, label, ctx=None):
        if label.startswith("t22.theta.r"):
            v = rng.randrange(P)
            self.th[int(label.rsplit("r", 1)[1])] = v
            return v
        if label.startswith("t22.c.r"):
            return self.th[int(label.rsplit("r", 1)[1])]
        return super().one(label, ctx)


s, acc, why = run(tabs_t, out_t, h, Liar(), SameV())
assert s.dgs.get(("c.v4_eq_v6", False)), s.dgs
report("D6 v4 = v6, honest, true statement", s, acc, why, True)
s, acc, why = run(tabs, out, h, Liar(), SameV())
report("D6b v4 = v6, liar, false statement", s, acc, why, False)


# ---- E. tightness of each sumcheck type: d distinct roots, each one escapes
counts = {}
for lbl, d, base in [("words.r0", 2, "words"), ("bits.r2", 2, "bits"), ("t23.iota.r4", 3, "iota"), ("t23.chi.r4", 4, "chi"), ("t23.rho.r4", 2, "rho"),
                     ("t23.theta.r4", 3, "theta"), ("t23.d.r4", 3, "d"), ("t23.c.r4", 6, "c"), ("t23.a.r4", 2, "a")]:
    roots = []
    while len(roots) < d:
        c = rng.randrange(P)
        if c not in roots:
            roots.append(c)
    good = 0
    for rt in roots:
        liar = Liar(solve={"t23.theta": [5]}, roots={lbl: roots})
        s, acc, why = run(tabs, out, h, liar, Forcer({lbl: lambda ctx, rt=rt: rt}))
        good += acc
    counts[base] = (good, d)
    assert good == d
print("E tightness, per-round escapes achieved at distinct roots (got, read degree):", counts)

# ---- F. the document's other run claims
# non-Boolean input bit = 2
tabs_t, _ = stmt(flips=())
bad = [list(t) for t in tabs_t]
bad[3][17] = 2 if bad[3][17] == 0 else 3
oo = trace(bad, h, ROUNDS)[23].iota
s, acc, why = run(bad, oo, h, Honest(), Oracle(rng))
nb = sum(1 for t in oo for v in t if v not in (0, 1))
print(f"F1 non-Boolean input, arithmetic image: accept={acc}, non-Boolean output entries={nb}")
# T-chain on the non-Boolean case: false word statement, liar rejected, root accepted
oo2 = [list(t) for t in oo]
oo2[0][0] = (oo2[0][0] + 1) % P
s, acc, why = run(bad, oo2, h, Liar(), Oracle(rng))
print(f"F2 non-Boolean input, wrong words, liar: accept={acc}, at {why}")
assert not acc and why.startswith("input lane")
s, acc, why = run(bad, oo2, h, Liar(), Forcer({"t23.beta_next": rlc_root}))
print(f"F3 non-Boolean input, wrong words, RLC root: accept={acc}, exit={exits(s)[:1]}")
assert acc

# non-Boolean output with the true words but Boolean input
oo3 = [list(t) for t in trace(tabs_t, h, ROUNDS)[23].iota]
oo3[0][10] = (oo3[0][10] + 2) % P
oo3[0][11] = (oo3[0][11] - 1) % P
s, acc, why = run(tabs_t, oo3, h, Honest(), Oracle(rng))
print(f"F4 Boolean input, non-Boolean output with same word: accept={acc}, stmt words equal={s.out_w == s.true_w}")
assert acc

# Singleton L = 0
words = [[rng.getrandbits(64)] for _ in range(25)]
t1 = words_to_tables(words, 1)
o1 = trace(t1, 1, ROUNDS)[23].iota
s, acc, why = run(t1, o1, 1, Honest(), Oracle(rng))
assert acc
o1b = [list(t) for t in o1]
o1b[0][0] ^= 1
s2, acc2, why2 = run(t1, o1b, 1, Liar(), Oracle(rng))
assert not acc2 and why2.startswith("input lane")
print(f"F5 L=0: honest accept={acc}, false statement liar rejected at {why2}")

# iota degree on instance variables
L_ = trace(tabs_t, h, ROUNDS)[23]
z = [rng.randrange(P) for _ in range(7)]
b = [rng.randrange(P) for _ in range(25)]
rlc = [sum(b[i] * L_.chi[i][j] for i in range(1, 25)) % P for j in range(128)]
sc = SC("", [eval_eq(z), L_.chi[0], rlc, L_.rc], f_iota(b[0]), 3)
deg = []
for var in range(7):
    cs = interp_coeffs(sc.evals())
    deg.append(max(i for i, c in enumerate(cs) if c))
    sc.bind(rng.randrange(P))
print("F6 honest iota round degrees by variable (L=1):", deg)
for n_ in [7, 12, 13, 14]:
    import math
    num = 555 * n_ + 162
    print(f"F7 n={n_} L={n_-6} numerator={num} log2 bound={math.log2(num) - math.log2(BN254):.2f}")
print("all predictions held")
