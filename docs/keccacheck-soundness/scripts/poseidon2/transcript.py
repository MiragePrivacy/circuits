"""Models the sponge call sequence of verifier.rs and reports, for each permutation
whose output yields a challenge, which rate positions the prover set in that block."""
from collections import Counter
import sys

RATE = 10


class Model:
    def __init__(self, name):
        self.name = name
        self.idx = 0
        self.dirty = True
        self.perms = 0
        self.ctl = []  # positions the prover set since the last permutation
        self.last_block = None
        self.events = []
        self.label = ""
        self.prev_ctl = []

    def _perm(self):
        self.perms += 1
        self.prev_ctl = self.ctl
        self.ctl = []

    def absorb(self, prover=True):
        if self.idx < RATE:
            if prover:
                self.ctl.append(self.idx)
            self.idx += 1
        else:
            self._perm()
            if prover:
                self.ctl.append(0)
            self.idx = 1
        self.dirty = True

    def squeeze(self):
        fresh = False
        if self.dirty or self.idx >= RATE:
            ctl = self.ctl
            prev = list(self.ctl)
            self._perm()
            self.idx = 0
            self.dirty = False
            fresh = True
            self.last = prev
        i = self.idx
        self.idx += 1
        return fresh, i, list(self.last) if fresh else []


class V:
    def __init__(self, log_n):
        self.m = Model("main")
        self.log_n = log_n
        self.ev = []
        self.reads = 0
        self.squeezes = 0

    def read(self, k=1):
        for _ in range(k):
            self.m.absorb(True)
        self.reads += k

    def gen(self, k, label, degree_note=""):
        out = []
        for _ in range(k):
            fresh, i, ctl = self.m.squeeze()
            self.squeezes += 1
            out.append((fresh, i, ctl))
        fr = [x for x in out if x[0]]
        if fr:
            self.ev.append((label, k, fr[0][2], len(fr)))

    def sumcheck(self, deg, nv, label):
        for _ in range(nv):
            self.read(deg)
            self.gen(1, label)

    def round(self, nv, last):
        self.sumcheck(3, nv, "sc3-iota")
        self.read(2)
        self.gen(2, "x,y")
        self.sumcheck(4, nv, "sc4-chi")
        self.read(25)
        self.gen(25, "beta-rho")
        self.sumcheck(2, nv, "sc2-rho")
        self.read(25)
        self.gen(25, "beta-theta")
        self.sumcheck(3, nv, "sc3-theta")
        self.read(10)
        self.gen(5, "beta-d")
        self.sumcheck(3, nv, "sc3-d")
        self.read(10)
        self.gen(10, "beta-c")
        self.sumcheck(6, nv, "sc6-c")
        self.read(25)
        self.gen(5, "beta-ai")
        self.gen(25, "beta-a")
        self.sumcheck(2, nv, "sc2-a")
        self.read(25)
        if not last:
            self.gen(25, "beta-iota")


def perms_for_statement(instances):
    """derive_r sponge: tag, size, packed words, log_n squeezes."""
    m = Model("stmt")
    m.absorb(False)
    m.absorb(False)
    # input and output words are chunked separately, as in derive_r_var
    chunks = 2 * ((25 * instances + 2) // 3)
    for _ in range(chunks):
        m.absorb(False)
    log_n = instances.bit_length() - 1
    for _ in range(log_n):
        m.squeeze()
    return m.perms, chunks


def run(instances, verbose):
    log_n = instances.bit_length() - 1
    nv = log_n + 6
    v = V(log_n)
    for _ in range(log_n):
        v.m.absorb(False)
    v.gen(25, "beta-init")
    v.read(1)
    v.sumcheck(2, log_n, "sc2-outx")
    v.read(1)
    v.sumcheck(2, 6, "sc2-outy")
    v.read(1)
    for r in range(23, -1, -1):
        v.round(nv, r == 0)
    stmt, chunks = perms_for_statement(instances)
    return v, stmt, chunks


def main():
    for inst in (2, 4, 8, 16, 32, 64, 128, 256, 1024):
        v, st, chunks = run(inst, False)
        total = v.m.perms + st
        print("instances %5d main perms %6d stmt perms %5d total %6d reads %6d (formula %d) squeezes %6d" % (
            inst, v.m.perms, st, total, v.reads, 6255 + 554 * (inst.bit_length() - 1), v.squeezes))
    v, st, _ = run(64, True)
    print("permutations with a challenge output at 64 instances, by event and controlled final block:")
    c = Counter()
    for label, k, ctl, nf in v.ev:
        c[(label, tuple(ctl))] += 1
    for (label, ctl), n in sorted(c.items()):
        print(" %-12s count %4d positions %s (nu=%d)" % (label, n, list(ctl), len(ctl)))
    print("max nu in a final block:", max(len(e[2]) for e in v.ev))


if __name__ == "__main__":
    main()
