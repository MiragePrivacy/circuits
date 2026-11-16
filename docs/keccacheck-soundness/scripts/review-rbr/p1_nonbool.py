"""Phase 1: what the verifier equations establish without Booleanity, and the beta0 = 0 pending claim."""
import random
import sys

sys.path.insert(0, sys.argv[1])
from model import *

rng = random.Random(7)
h = 2
words = [[rng.getrandbits(64) for _ in range(h)] for _ in range(25)]
tabs = words_to_tables(words, h)


def true_out(tabs, h, rounds=24):
    return trace(tabs, h, rounds)[23].iota


# A. Non-Boolean input, output tables = arithmetized image (non-Boolean), honest prover on that trace
bad_in = [list(t) for t in tabs]
bad_in[3][17] = 5
o = true_out(bad_in, h)
nb = sum(1 for t in o for v in t if v not in (0, 1))
s = Session(bad_in, o, h, oracle=Oracle(rng))
s.run()
print(f"A: non-Boolean input (one entry=5) accepted against arithmetized image; output has {nb} non-Boolean entries of {25*64*h}")

# B. Boolean input, non-Boolean output tables with the same 64-bit words
o = [list(t) for t in true_out(tabs, h)]
# pick lane 0 instance 0: bit j -> bit j + 2, bit j+1 -> bit j+1 - 1 keeps the word
j = 10
o[0][j] = (o[0][j] + 2) % P
o[0][j + 1] = (o[0][j + 1] - 1) % P
s = Session(tabs, o, h, oracle=Oracle(rng))
s.run()
print("B: Boolean input, output bits changed to non-Boolean with equal word value: accepted (equations only see words)")

# C. Boolean input, Boolean but wrong output word: rejected
o = [list(t) for t in true_out(tabs, h)]
o[0][10] ^= 1
s = Session(tabs, o, h, oracle=Oracle(rng), stop_on_reject=True)


class ForceSum(Honest):
    pass


try:
    s.run()
    print("C: UNEXPECTED accept")
except Reject as e:
    print("C: wrong Boolean output, honest-trace prover rejected at:", e)


# D. beta0 = 0 in some round, prover lies about chi_00: accepted, naive state says doomed, refined does not
class Lie00(Honest):
    def claims(self, stage, truth, check, ve, session):
        if stage == "t20.iota":
            return [(truth[0] + 12345) % P, truth[1]]
        return list(truth)


class Beta0Zero(Oracle):
    def vec(self, label, n, ctx=None):
        v = super().vec(label, n, ctx)
        if label == "t21.beta_next":
            v[0] = 0
        return v


o = true_out(tabs, h, 24)
s = Session(tabs, o, h, prover=Lie00(), oracle=Beta0Zero(rng))
s.run()
hits = [x for x in s.state.log if x[0] == "t20.iota claims"]
print("D: beta0=0 and false chi_00 claim: accepted; at claim (refined, naive) =", hits[0][1:], "; final doomed:", s.state.refined())
naive_ex = [x for x in s.state.log if x[1] != x[2]]
print("   states where the two definitions disagree:", [x[0] for x in naive_ex])

# E. Same lie, beta0 != 0: rejected
s = Session(tabs, o, h, prover=Lie00(), oracle=Oracle(rng))
try:
    s.run()
    print("E: UNEXPECTED accept")
except Reject as e:
    print("E: beta0 != 0, same lie: rejected at", e)
