"""Phase 2: replay real native-prover proofs through the model verifier, with the real transcript.

Poseidon2 and the sponge are written here from poseidon2.rs. Challenges come from the actual
Fiat-Shamir schedule, so acceptance confirms the model's read and squeeze order and every formula
against proofs from the pinned upstream prover. The same proof satisfies the R1CS gadget in the dump
binary. The state function must stay undoomed throughout, using the truth from the model trace.
"""
import random
import re
import sys

sys.path.insert(0, sys.argv[1])
from model import *

CONST = "experiments/keccacheck-arkworks/src/poseidon2_constants.rs"
vals = [int(x) for x in re.findall(r'MontFp!\(\s*"(\d+)"\s*\)', open(CONST).read())]
assert len(vals) == 16 * 4 + 57 + 16 * 4, len(vals)
EXT1 = [vals[i * 16 : (i + 1) * 16] for i in range(4)]
PART = vals[64:121]
EXT2 = [vals[121 + i * 16 : 121 + (i + 1) * 16] for i in range(4)]
INITIAL = [
    314159265358979323846264338327950288419716939937510582097494,
    45923078164062862089986280348253421170679821480865132823066470,
    93844609550582231725359408128481117450284102701938521105559644,
    62294895493038196442881097566593344612847564823378678316527120,
    19091456485669234603486104543266482133936072602491412737245870,
    6606315588174881520920962829254091715364367892590360011330530,
    54882046652138414695194151160943305727036575959195309218611738,
    19326117931051185480744623799627495673518857527248912279381830,
    11949129833673362440656643086021394946395224737190702179860943,
    70277053921717629317675238467481846766940513200056812714526356,
    8277857713427577896091736371787214684409012249534301465495853,
    71050792279689258923542019956112129021960864034418159813629774,
    77130996051870721134999999837297804995105973173281609631859502,
    44594553469083026425223082533446850352619311881710100031378387,
    52886587533208381420617177669147303598253490428755468731159562,
    86388235378759375195778185778053217122680661300192787661119590,
]
DIAG = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 16, 17]


def mat4(s):
    t0 = s[0] + s[1]
    t1 = s[2] + s[3]
    t2 = 2 * s[1] + t1
    t3 = 2 * s[3] + t0
    t4 = 4 * t1 + t3
    t5 = 4 * t0 + t2
    return [t3 + t5, t5, t2 + t4, t4]


def full(state):
    out = []
    sums = [0, 0, 0, 0]
    for i in range(0, 16, 4):
        c = mat4(state[i : i + 4])
        for j in range(4):
            sums[j] += c[j]
        out += c
    return [(out[i] + sums[i % 4]) % P for i in range(16)]


def partial(state):
    s = sum(state)
    return [(state[i] * DIAG[i] + s) % P for i in range(16)]


def sb(x):
    x2 = x * x % P
    return x2 * x2 % P * x % P


def permute(st):
    st = full(st)
    for rc in EXT1:
        st = [sb((st[i] + rc[i]) % P) for i in range(16)]
        st = full(st)
    for rc in PART:
        st = list(st)
        st[0] = sb((st[0] + rc) % P)
        st = partial(st)
    for rc in EXT2:
        st = [sb((st[i] + rc[i]) % P) for i in range(16)]
        st = full(st)
    return st


class Sponge:
    def __init__(self):
        self.s = [v % P for v in INITIAL]
        self.idx = 0
        self.dirty = True

    def absorb(self, v):
        if self.idx < 10:
            self.s[self.idx] = (self.s[self.idx] + v) % P
            self.idx += 1
        else:
            self.s = permute(self.s)
            self.s[0] = (self.s[0] + v) % P
            self.idx = 1
        self.dirty = True

    def squeeze(self):
        if self.dirty or self.idx >= 10:
            self.s = permute(self.s)
            self.idx = 0
            self.dirty = False
        out = self.s[self.idx]
        self.idx += 1
        return out


TAG = int.from_bytes(b"mirage/kcck/stmt", "little")


class FS(Oracle):
    def __init__(self, inp, out, L):
        self.main = Sponge()
        st = Sponge()
        st.absorb(TAG)
        st.absorb(1 << L)
        for arr in (inp, out):
            for i in range(0, len(arr), 3):
                st.absorb(sum(v << (64 * k) for k, v in enumerate(arr[i : i + 3])) % P)
        self.r = [st.squeeze() for _ in range(L)]

    def one(self, label, ctx=None):
        return self.main.squeeze()

    def vec(self, label, n, ctx=None):
        if label == "r":
            for v in self.r:
                self.main.absorb(v)
            return list(self.r)
        return [self.main.squeeze() for _ in range(n)]


class Replayer(Honest):
    def __init__(self, proof, oracle):
        self.proof, self.i, self.o = proof, 0, oracle

    def read(self):
        v = self.proof[self.i]
        self.i += 1
        self.o.main.absorb(v)
        return v

    def round_poly(self, sc, claim, ridx, session):
        return [None] + [self.read() for _ in range(sc.degree)]

    def claims(self, stage, truth, check, ve, session):
        return [self.read() for _ in truth]

    def first_sum(self, expected, session):
        return self.read()


for path in sys.argv[2:]:
    data = dict(line.split(" ", 1) for line in open(path).read().splitlines())
    inp = [int(x) for x in data["input"].split()]
    out = [int(x) for x in data["output"].split()]
    proof = [int(x) for x in data["proof"].split()]
    h = len(inp) // 25
    L = h.bit_length() - 1
    in_words = [[inp[i * h + j] for j in range(h)] for i in range(25)]
    out_words = [[out[i * h + j] for j in range(h)] for i in range(25)]
    fs = FS(inp, out, L)
    rp = Replayer(proof, fs)
    s = Session(words_to_tables(in_words, h), words_to_tables(out_words, h), h, prover=rp, oracle=fs)
    s.run()
    assert rp.i == len(proof), "proof not exhausted"
    assert len(proof) == 6255 + 554 * L
    assert not any(e[1] for e in s.state.log), "state must be undoomed on a real proof"
    print(f"L={L}: gadget_satisfied={data['gadget_satisfied']}; real proof of {len(proof)} elements accepted by model; state never doomed")

    # Tampering a single element changes the challenges; every tamper must reject.
    rng = random.Random(5)
    for k in range(6):
        pr = list(proof)
        pos = rng.randrange(len(pr))
        pr[pos] = (pr[pos] + 1) % P
        fs = FS(inp, out, L)
        s = Session(words_to_tables(in_words, h), words_to_tables(out_words, h), h, prover=Replayer(pr, fs), oracle=fs)
        try:
            s.run()
            raise SystemExit(f"tamper at {pos} accepted")
        except Reject:
            pass
    print(f"L={L}: 6 random single-element tampers rejected")
