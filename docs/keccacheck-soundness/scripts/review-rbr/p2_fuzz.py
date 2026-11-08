"""Phase 2: small-field fuzz of the document's state function.

In F_p with small p, degenerate challenges (zero coefficients, eq = 0, rot = 0, RC = 1/2,
pow = 0, x = 0, y = 0, beta_0 = 0, v4 = v6) occur at rate about 1/p rather than 2^-253.
The state tracked at positions is exactly section 5 of 02-interactive-soundness.md:
c != S_l, or AI-false during theta D and theta C, or a failed check.

Asserted on every run:
  F1  Accept implies not doomed at the last position (T14).
  F2  Reject at the input lanes implies the state after round 0's openings is doomed.
  F3  Doom is never left at a transition with no challenge (T3, T5, T6).
  F4  Per sumcheck move: exact count over all of F_p of escaping challenges <= d (Lemma 5).
  F5  (x,y) move: exact count over F_p^2 of escapes is p when the form is nonzero (T7).
Measured: escape rate by move type against the bound.
"""
import collections
import random
import re
import sys

sys.path.insert(0, sys.argv[1])
from model import *

assert P < 10**6, "run with KC_P set to a small prime"
assert P > 6, "needs p > 6 to interpolate degree 6"
SEEDS = int(sys.argv[2])
H_CHOICES = [int(x) for x in sys.argv[3].split(",")]
ROUNDS = int(sys.argv[4])
master = random.Random(int(sys.argv[5]) if len(sys.argv) > 5 else 1)

stats = collections.Counter()
degen = collections.Counter()
BOUND = {"words": 2, "bits": 2, "iota": 3, "chi": 4, "rho": 2, "theta": 3, "d": 3, "c": 6, "a": 2}


def stage_of(label):
    m = re.match(r"(?:t\d+\.)?(\w+)", label)
    return m.group(1)


class Fuzzer(Honest):
    """Lies at random. Tries to pass every check by solving one coordinate."""

    def __init__(self, rng, lie_p):
        self.rng, self.lie_p = rng, lie_p

    def round_poly(self, sc, claim, ridx, session):
        evs = sc.evals()
        cs = interp_coeffs(evs)
        err = (claim - (evs[0] + evs[1])) % P
        d = sc.degree
        if err == 0 and self.rng.random() > self.lie_p:
            return cs
        # p = G + u with u(0) + u(1) = err. Random u, or u with d chosen roots when possible.
        for _ in range(4):
            if self.rng.random() < 0.5:
                roots = [self.rng.randrange(P) for _ in range(d)]
                u = [1]
                for a in roots:
                    u = poly_mul(u, [-a % P, 1])
                s = (horner(u, 0) + horner(u, 1)) % P
                if s == 0:
                    if err == 0:
                        u = [self.rng.randrange(P) * v % P for v in u]
                    else:
                        continue
                else:
                    k = err * inv(s) % P
                    u = [k * v % P for v in u]
            else:
                u = [self.rng.randrange(P) for _ in range(d + 1)]
                u[0] = ((err - sum(u[1:])) * HALF) % P
            return [(a + b) % P for a, b in zip(cs, u)]
        u = [self.rng.randrange(P) for _ in range(d + 1)]
        u[0] = ((err - sum(u[1:])) * HALF) % P
        return [(a + b) % P for a, b in zip(cs, u)]

    def claims(self, stage, truth, check, ve, session):
        v = list(truth)
        if self.rng.random() < self.lie_p:
            for _ in range(self.rng.randint(1, 3)):
                v[self.rng.randrange(len(v))] = self.rng.randrange(P)
        if check(v) == ve:
            return v
        idxs = list(range(len(v)))
        self.rng.shuffle(idxs)
        for idx in idxs:
            w = list(v)
            w[idx] = 0
            f0 = (check(w) - ve) % P
            w[idx] = 1
            f1 = (check(w) - ve) % P
            if f1 != f0:
                w[idx] = (-f0) * inv(f1 - f0) % P
                assert check(w) == ve
                return w
        return v


class FuzzOracle(Oracle):
    def one(self, label, ctx=None):
        r = self.rng.randrange(P)
        if ctx and "sc" in ctx:
            s = ctx["session"]
            sc = ctx["sc"]
            evs = sc.evals()
            true_sum = (evs[0] + evs[1]) % P
            cl = ctx["claim"]
            stage = stage_of(label)
            stats[stage + ".rounds"] += 1
            if not s.state.failed:
                doomed_c = cl != true_sum
                if doomed_c:
                    # exact escape count over all of F_p
                    p = ctx["p"]
                    cnt = sum(1 for t in range(P) if horner(p, t) == interp_eval(evs, t))
                    assert cnt <= BOUND[stage], (label, cnt)
                    stats[stage + ".doomed_rounds"] += 1
                    stats[stage + ".exact_escapes"] += cnt
                    stats[stage + ".max_exact"] = max(stats[stage + ".max_exact"], cnt)
        if ctx and ctx.get("role") == "x":
            self.pending_xy = ctx["d"]
            self.beta0 = ctx["beta0"]
        if ctx and ctx.get("role") == "y":
            a = ctx["beta0"] * ctx["d"]["chi00"][1] % P
            b = ctx["d"]["chi_rlc"][1] % P
            if (a or b) and P < 2000:
                cnt = sum(1 for xx in range(P) for yy in range(P) if (xx * a + yy * b) % P == 0)
                assert cnt == P, cnt
                stats["xy.exact_form_checked"] += 1
        return r

    def vec(self, label, n, ctx=None):
        v = super().vec(label, n, ctx)
        if ctx and "delta" in ctx:
            stats["rlc.calls"] += 1
        return v


def degenerate_notes(s):
    pass


for seed in range(SEEDS):
    rng = random.Random(master.getrandbits(64))
    h = rng.choice(H_CHOICES)
    words = [[rng.getrandbits(64) for _ in range(h)] for _ in range(25)]
    tabs = words_to_tables(words, h)
    nonbool = rng.random() < 0.15
    if nonbool:
        tabs[rng.randrange(25)][rng.randrange(64 * h)] = rng.randrange(P)
    true = trace(tabs, h, ROUNDS)[23].iota
    out = [list(t) for t in true]
    false_stmt = rng.random() < 0.8
    if false_stmt:
        for _ in range(rng.randint(1, 3)):
            out[rng.randrange(25)][rng.randrange(64 * h)] ^= 1
    lie_p = rng.choice([0.0, 0.02, 0.1, 0.4])
    s = Session(tabs, out, h, prover=Fuzzer(rng, lie_p), oracle=FuzzOracle(rng), rounds=ROUNDS)
    accepted = False
    try:
        s.run()
        accepted = True
    except Reject:
        pass
    # Section 5 positions, in order. Openings ("... claims") are not positions.
    pos = [e for e in s.state.log if not e[0].endswith("claims") and not e[0].endswith("claim")]
    stats["runs"] += 1
    stats["accepted"] += accepted
    stats["false_stmt"] += false_stmt and s.out_w != s.true_w
    stats["false_stmt_accepted"] += accepted and s.out_w != s.true_w
    for (a, ra, _), (b, rb, _) in zip(pos, pos[1:]):
        if ra and not rb:
            stage = b
            if b.endswith(": start"):
                stage = b[: -len(": start")]
                # T3, T5, T6: start of bits or round 23 iota follow an opening with no challenge.
                base = stage_of(stage)
                if base == "bits" or stage == "t23.iota":
                    raise AssertionError(f"escape with no challenge at {b}")
                key = "rlc_before." + base
            elif "beta_next" in b:
                key = "beta_next"
            else:
                key = "sc." + stage_of(b)
            stats["escape." + key] += 1
    if accepted:
        assert not pos[-1][1], "F1 accepted while doomed at last position"
        assert not s.state.refined(), "F1 final"
    else:
        lab = s.rejected[0]
        if lab.startswith("input lane"):
            assert s.state.log[-1][0].endswith(".a claims")
            assert s.state.log[-1][1], "F2: rejected at input while state after final openings undoomed"
            stats["rej.input.last_pos_undoomed"] += not pos[-1][1]
            stats["rej.input"] += 1
        else:
            stats["rej.other"] += 1
    stats["last_doomed_and_accept"] += accepted and pos[-1][1]
    for k, v in s.dgs.items():
        degen[k] += v

print(f"p={P} runs={stats['runs']} accepted={stats['accepted']} false_stmt={stats['false_stmt']} "
      f"false_accepted={stats['false_stmt_accepted']} rej_input={stats['rej.input']} rej_other={stats['rej.other']}")
print("exact escaping challenges per doomed sumcheck round, mean and max against read degree:")
for st_, d in BOUND.items():
    n_ = stats[st_ + ".doomed_rounds"]
    if n_:
        print(f"  {st_:6s} doomed_rounds={n_:7d} mean_roots={stats[st_ + '.exact_escapes'] / n_:.3f} max_roots={stats[st_ + '.max_exact']} bound={d}")
print("(x,y) exact count over F_p^2 == p on", stats["xy.exact_form_checked"], "forms")
print("observed escapes:", {k[7:]: v for k, v in sorted(stats.items()) if k.startswith("escape.")})
print("degenerate events (name, doomed at the time):")
names = sorted({k[0] for k in degen})
for nm in names:
    print(f"  {nm:12s} undoomed={degen[(nm, False)]:6d} doomed={degen[(nm, True)]:6d}")
print("assertions F1-F5 held on every run")
