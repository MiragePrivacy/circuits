"""Phase 1: identities at random points on real Keccak-f traces, honest run, constant checks."""
import hashlib
import random
import re
import sys
import time

sys.path.insert(0, sys.argv[1])
from model import *

VER = "crates/keccacheck/src/verifier.rs"
rng = random.Random(0xC0FFEE)

# 1. FIPS implementation vs hashlib
for msg in [b"", b"abc", bytes(range(200)), b"x" * 136, b"y" * 135]:
    assert sha3_256_via_model(msg) == hashlib.sha3_256(msg).digest()
print("model keccak-f agrees with hashlib.sha3_256")

# 2. constants in the verifier vs FIPS-derived
src = open(VER).read()
rc = [int(x, 16) for x in re.findall(r"0x([0-9a-f]{16})", src)]
assert rc[:24] == RC, "round constants"
m = re.search(r"RHO_OFFSETS: \[usize; 25\] = \[(.*?)\]", src, re.S)
assert [int(x) for x in re.findall(r"\d+", m.group(1))] == RHO, "rho"
m = re.search(r"const PI: \[usize; 24\] = \[(.*?)\]", src, re.S)
PIc = [int(x) for x in re.findall(r"\d+", m.group(1))]
# strip_pi walk: rho[last] = pi[target]; compare with pi[dst] = rho[src]
walk = {}
last = 1
for target in PIc:
    walk[target] = last
    last = target
walk[0] = 0
assert all(walk[d] == PI_SRC[d] for d in range(25)), "pi"
print("verifier RC, RHO_OFFSETS, PI, strip_pi walk agree with FIPS 202 derivation")

# 3. arithmetized trace equals real Keccak
for h in [2, 4]:
    words = [[rng.getrandbits(64) for _ in range(h)] for _ in range(25)]
    tabs = words_to_tables(words, h)
    layers = trace(tabs, h)
    out = [[0] * h for _ in range(25)]
    for inst in range(h):
        res = fips_keccak_f([words[i][inst] for i in range(25)])
        for i in range(25):
            out[i][inst] = res[i]
    assert words_to_tables(out, h) == layers[23].iota
print("arithmetized trace == FIPS Keccak-f, all lanes and instances")


def identities(h):
    n = 6 + h.bit_length() - 1
    words = [[rng.getrandbits(64) for _ in range(h)] for _ in range(25)]
    layers = trace(words_to_tables(words, h), h)
    for t in [0, 11, 23]:
        L = layers[t]
        z = [rng.randrange(P) for _ in range(n)]
        beta = [rng.randrange(P) for _ in range(25)]
        k = [rng.randrange(P) for _ in range(n)]
        pre = n - 6

        # iota, per lane sum over cube then at a point
        lhs = sum(beta[i] * mle(L.iota[i], z) for i in range(25)) % P
        rlc = [sum(beta[i] * L.chi[i][j] for i in range(1, 25)) % P for j in range(1 << n)]
        sc = SC("", [eval_eq(z), L.chi[0], rlc, L.rc], f_iota(beta[0]), 3)
        assert lhs == sc.total(), "iota sum"
        rcv = mle(L.rc[:64], k[pre:])
        assert mle(L.rc, k) == rcv, "RC constant on instance variables"

        # chi
        lhs = sum(beta[i] * mle(L.chi[i], z) for i in range(25)) % P
        sc = SC("", [eval_eq(z)] + L.pi, f_chi(beta), 4)
        assert lhs == sc.total(), "chi sum"

        # pi via strip_pi
        pv = [mle(L.pi[i], z) for i in range(25)]
        assert strip_pi(pv) == [mle(L.rho[i], z) for i in range(25)], "strip_pi"

        # rho, including the closed form used by the check
        lhs = sum(beta[i] * mle(L.rho[i], z) for i in range(25)) % P
        rots = [rot_table(z, RHO[i]) for i in range(25)]
        sc = SC("", rots + L.theta, f_rho(beta), 2)
        assert lhs == sc.total(), "rho sum"
        for i in [0, 1, 7, 24]:
            assert mle(rots[i], k) == rot_eval(RHO[i], z, k), "rot closed form"

        # theta
        lhs = sum(beta[i] * (1 - 2 * mle(L.theta[i], z)) for i in range(25)) % P
        ai = [[sum(beta[r * 5 + j] * L.ahat[r * 5 + j][q] for r in range(5)) % P for q in range(1 << n)] for j in range(5)]
        sc = SC("", [eval_eq(z)] + L.dhat + ai, f_theta, 3)
        assert lhs == sc.total(), "theta sum"

        # theta_d
        bd = beta[:5]
        lhs = sum(bd[j] * mle(L.dhat[j], z) for j in range(5)) % P
        sc = SC("", [eval_eq(z)] + L.chat + L.rotchat, f_d(bd), 3)
        assert lhs == sc.total(), "theta_d sum"

        # theta_c
        bc, brc = beta[:5], beta[5:10]
        lhs = (sum(bc[j] * mle(L.chat[j], z) for j in range(5)) + sum(brc[j] * mle(L.rotchat[j], z) for j in range(5))) % P
        sc = SC("", [eval_eq(z), rot_table(z, 1)] + L.ahat, f_c(bc, brc), 6)
        assert lhs == sc.total(), "theta_c sum"
        assert mle(rot_table(z, 1), k) == rot_eval(1, z, k)

        # theta_a
        z2 = [rng.randrange(P) for _ in range(n)]
        b2 = [rng.randrange(P) for _ in range(25)]
        lhs = sum(beta[i] * mle(L.ahat[i], z) + b2[i] * mle(L.ahat[i], z2) for i in range(25)) % P
        sc = SC("", [eval_eq(z), eval_eq(z2)] + L.ahat, f_a(beta, b2), 2)
        assert lhs == sc.total(), "theta_a sum"

        # sumcheck final value vs closed form used by verifier, at a random point
        e = eq(z, k)
        vals = [mle(t_, k) for t_ in L.ahat]
        assert sc.tables[0][0] == eval_eq(z)[0]
        for r_ in k:
            sc.bind(r_)
        e1, e2 = eq(z, k), eq(z2, k)
        assert sc.final() == sum((beta[j] * e1 + b2[j] * e2) % P * vals[j] for j in range(25)) % P

        # next layer equality in hat basis
        assert [mle(L.ahat[i], z) for i in range(25)] == [(1 - 2 * mle(L.a[i], z)) % P for i in range(25)]
    # layers chain
    for t in range(0, 23):
        assert layers[t].iota == layers[t + 1].a
    print(f"identities h={h}: ok (rounds 0, 11, 23)")


identities(2)
identities(4)


def degree_of(tables, fn, nvars, claimed):
    """Empirical max degree per variable: finite differences on a random line per variable."""
    n = nvars
    pt = [rng.randrange(P) for _ in range(n)]
    worst = 0
    for var in range(n):
        ys = []
        for s in range(claimed + 3):
            q = list(pt)
            q[var] = s
            ys.append(fn([mle(t, q) for t in tables]) % P)
        cs = interp_coeffs(ys)
        deg = max((i for i, c in enumerate(cs) if c), default=0)
        worst = max(worst, deg)
    return worst


h = 2
n = 7
words = [[rng.getrandbits(64) for _ in range(h)] for _ in range(25)]
L = trace(words_to_tables(words, h), h)[5]
beta = [rng.randrange(P) for _ in range(30)]
z = [rng.randrange(P) for _ in range(n)]
rlc = [sum(beta[i] * L.chi[i][j] for i in range(1, 25)) % P for j in range(128)]
print("degree iota ", degree_of([eval_eq(z), L.chi[0], rlc, L.rc], f_iota(beta[0]), n, 3))
print("degree chi  ", degree_of([eval_eq(z)] + L.pi, f_chi(beta), n, 4))
print("degree rho  ", degree_of([rot_table(z, RHO[i]) for i in range(25)] + L.theta, f_rho(beta), n, 2))
ai = [[sum(beta[r * 5 + j] * L.ahat[r * 5 + j][q] for r in range(5)) % P for q in range(128)] for j in range(5)]
print("degree theta", degree_of([eval_eq(z)] + L.dhat + ai, f_theta, n, 3))
print("degree d    ", degree_of([eval_eq(z)] + L.chat + L.rotchat, f_d(beta[:5]), n, 3))
print("degree c    ", degree_of([eval_eq(z), rot_table(z, 1)] + L.ahat, f_c(beta[:5], beta[5:10]), n, 6))
print("degree a    ", degree_of([eval_eq(z), eval_eq(z[::-1])] + L.ahat, f_a(beta[:25], beta[5:30]), n, 2))

# 4. honest full protocol, 24 rounds, both L
for h in [2, 4]:
    words = [[rng.getrandbits(64) for _ in range(h)] for _ in range(25)]
    tabs = words_to_tables(words, h)
    outw = [[0] * h for _ in range(25)]
    for inst in range(h):
        res = fips_keccak_f([words[i][inst] for i in range(25)])
        for i in range(25):
            outw[i][inst] = res[i]
    t0 = time.time()
    s = Session(tabs, words_to_tables(outw, h), h, oracle=Oracle(rng))
    s.run()
    assert not s.state.refined(), "honest run must end undoomed"
    assert not any(l[1] for l in s.state.log)
    print(f"honest 24-round protocol accepted, h={h}, {time.time()-t0:.1f}s, state never doomed")
