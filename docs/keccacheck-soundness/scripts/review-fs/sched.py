"""Schedule replay, independent of the document's scripts.
ops() is transcribed from verify_allocated and verify_round in verifier.rs.
Checks proof length, P-call counts, block spans, overlap of main and statement
chains, and the DSFS full-rate replay of section 7.2 of 03-fiat-shamir.md."""
import hashlib, random
from math import ceil

p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
TAG = int.from_bytes(b"mirage/kcck/stmt", "little")


def P(s):
    # Toy public function: SHA-256 counter mode, enough for schedule logic.
    h = hashlib.sha256(",".join(map(str, s)).encode()).digest()
    return [int.from_bytes(hashlib.sha256(h + bytes([i])).digest(), "big") % p for i in range(16)]


def IV():
    return [int.from_bytes(hashlib.sha256(b"iv%d" % i).digest(), "big") % p for i in range(16)]


def ops(L):
    n = L + 6
    o = [("A", L), ("S", 25), ("R", 1)]

    def sc(d, rounds):
        for _ in range(rounds):
            o.append(("R", d))
            o.append(("S", 1))

    sc(2, L)
    o.append(("R", 1))
    sc(2, 6)
    o.append(("R", 1))
    for round_ in reversed(range(24)):
        sc(3, n)
        o += [("R", 2), ("S", 2)]
        sc(4, n)
        o += [("R", 25), ("S", 25)]
        sc(2, n)
        o += [("R", 25), ("S", 25)]
        sc(3, n)
        o += [("R", 10), ("S", 5)]
        sc(3, n)
        o += [("R", 10), ("S", 10)]
        sc(6, n)
        o += [("R", 25), ("S", 30)]
        sc(2, n)
        o += [("R", 25)]
        if round_ != 0:
            o += [("S", 25)]
    return o


class Sponge:
    def __init__(self, log=None):
        self.s = IV()
        self.idx = 0
        self.dirty = True
        self.calls = []  # (kind, input)

    def perm(self, kind):
        self.calls.append((kind, tuple(self.s)))
        self.s = P(self.s)

    def absorb(self, v):
        if self.idx < 10:
            self.s[self.idx] = (self.s[self.idx] + v) % p
            self.idx += 1
        else:
            self.perm("wrap")
            self.s[0] = (self.s[0] + v) % p
            self.idx = 1
        self.dirty = True

    def squeeze(self, first):
        if self.dirty or self.idx >= 10:
            self.perm("first" if self.dirty else "lookahead")
            self.idx = 0
            self.dirty = False
        v = self.s[self.idx]
        self.idx += 1
        return v


def run_main(L, r, msg):
    sp = Sponge()
    spans = []
    for kind, k in ops(L):
        if kind in "AR":
            for _ in range(k):
                sp.absorb(r.pop(0) if kind == "A" else msg())
        else:
            before = len(sp.calls)
            for _ in range(k):
                sp.squeeze(True)
            spans.append((k, len(sp.calls) - before))
    return sp, spans


def run_stmt(L, chunks):
    sp = Sponge()
    sp.absorb(TAG)
    sp.absorb(1 << L)
    for c in chunks:
        sp.absorb(c)
    r = [sp.squeeze(True) for _ in range(L)]
    return sp, r


def main():
    print("L | proof | 6255+554L | absorbs | D_S | main calls | Q_V | first/look/wrap | span ok")
    for L in (1, 2, 6, 7, 8):
        rng = random.Random(L)
        proof = sum(k for t, k in ops(L) if t == "R")
        C = ceil(25 * 2**L / 3)
        sp, spans = run_main(L, [rng.randrange(p) for _ in range(L)], lambda: rng.randrange(p))
        kinds = [c[0] for c in sp.calls]
        st, _ = run_stmt(L, [rng.randrange(2**192) for _ in range(2 * C)])
        span_ok = all(b == (3 if k in (25, 30) else 1) for k, b in spans)
        print(L, proof, 6255 + 554 * L, 2 + 2 * C, len(st.calls), len(sp.calls), len(st.calls) + len(sp.calls),
              (kinds.count("first"), kinds.count("lookahead"), kinds.count("wrap")), span_ok)
    # Overlap: root x=(tag,2^L,0..0) with all-zero prover messages equals the statement chain
    # of the false statement (I=0,O=0). Is the statement-final query a lookahead of the main parse?
    for L in (2, 3, 4, 5, 6, 7, 8, 9, 10):
        C = ceil(25 * 2**L / 3)
        st, _ = run_stmt(L, [0] * (2 * C))
        sp, _ = run_main(L, [TAG, 1 << L] + [0] * (L - 2), lambda: 0)
        D = len(st.calls)
        same = [c[1] for c in sp.calls[:D]] == [c[1] for c in st.calls[:D]]
        print(f"overlap L={L} D_S={D} main prefix equal={same} main parse at depth D_S: {sp.calls[D-1][0]}")
    # Sumcheck slots claim: slot of the first coefficient per round.
    # DSFS replay: Construction 3.3 with the full-rate codec, zero rate start, capacity IV_c.
    for L in (1, 2, 6, 8):
        rng = random.Random(100 + L)
        sp, _ = run_main(L, [rng.randrange(p) for _ in range(L)], lambda: rng.randrange(p))
        deployed = [c[1] for c in sp.calls]
        s = [0] * 10 + IV()[10:]
        iA, iS = 0, 10
        dsfs = []
        for inp in deployed:
            # Absorb full rate w equal to the deployed input rate; overwrite mode.
            for j in range(10):
                s[iA] = inp[j]
                iA += 1
            iS = 10
            # Squeeze: iA:=0, iS==r so permute.
            iA = 0
            dsfs.append(tuple(s))
            s = P(s)
            iS = 0
        print(f"DSFS full-rate replay L={L}: equal input sequence over {len(deployed)} calls: {dsfs == deployed}; "
              f"unpermuted trailing absorb in deployed: idx={sp.idx}, dirty={sp.dirty}")


main()
