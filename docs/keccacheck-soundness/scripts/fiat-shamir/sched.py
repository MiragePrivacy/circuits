# Replays the deployed transcript schedule against a toy permutation, and against
# Chiesa-Orru Construction 3.3 (overwrite mode) driven by the full-rate codec.
# The schedule is regenerated from verifier.rs; proof length is checked against 6255 + 554 L.
import hashlib, math, random, sys
P = 21888242871839275222246405745257275088548364400416034343698204186575808495617
R, W = 10, 16
def perm(s):
    # toy public function on F^16: only the input-to-output call sequence matters here
    h = hashlib.sha256(",".join(map(str, s)).encode()).digest()
    rng = random.Random(h)
    return [rng.randrange(P) for _ in range(W)]

class Deployed:
    def __init__(self, iv):
        self.s, self.i, self.d = list(iv), 0, True
        self.log = []
    def p(self):
        self.log.append(tuple(self.s)); self.s = perm(self.s)
    def absorb(self, v):
        if self.i < R:
            self.s[self.i] = (self.s[self.i] + v) % P; self.i += 1
        else:
            self.p(); self.s[0] = (self.s[0] + v) % P; self.i = 1
        self.d = True
    def squeeze(self):
        if self.d or self.i >= R:
            self.p(); self.i = 0; self.d = False
        o = self.s[self.i]; self.i += 1
        return o

class CO:
    """Construction 3.3 with (s, iA, iS); h(x) replaced by the fixed capacity."""
    def __init__(self, iv):
        self.s = [0]*R + list(iv[R:]); self.ia, self.is_ = 0, R
        self.log = []
    def absorb(self, chi):
        self.is_ = R
        for x in chi:
            if self.ia == R:
                self.log.append(tuple(self.s)); self.s = perm(self.s); self.ia = 0
            self.s[self.ia] = x; self.ia += 1
    def squeeze(self, l):
        out = []
        self.ia = 0
        for _ in range(l):
            if self.is_ == R:
                self.log.append(tuple(self.s)); self.s = perm(self.s); self.is_ = 0
            out.append(self.s[self.is_]); self.is_ += 1
        return out

def main_ops(L):
    """list of ('a', k) or ('s', k) moves in schedule order, tagged."""
    n = L + 6
    ops = [('a', L, 'r'), ('s', 25, 'beta'), ('a', 1, 'sum')]
    def sc(d, m, tag):
        for _ in range(m):
            ops.append(('a', d, tag)); ops.append(('s', 1, tag+'-chal'))
    sc(2, L, 'words'); ops.append(('a', 1, 'words_r_x'))
    sc(2, 6, 'bits'); ops.append(('a', 1, 'bit_eval'))
    for t in range(23, -1, -1):
        sc(3, n, 'iota'); ops.append(('a', 2, 'chi_open')); ops.append(('s', 2, 'xy'))
        sc(4, n, 'chi'); ops.append(('a', 25, 'pi')); ops.append(('s', 25, 'rho-beta'))
        sc(2, n, 'rho'); ops.append(('a', 25, 'theta')); ops.append(('s', 25, 'theta-beta'))
        sc(3, n, 'theta'); ops.append(('a', 10, 'ai,d')); ops.append(('s', 5, 'bd'))
        sc(3, n, 'thetaD'); ops.append(('a', 10, 'c,rc')); ops.append(('s', 10, 'bc'))
        sc(6, n, 'thetaC'); ops.append(('a', 25, 'a')); ops.append(('s', 30, 'b,ba'))
        sc(2, n, 'thetaA'); ops.append(('a', 25, 'ah'))
        if t: ops.append(('s', 25, 'next-beta'))
    return ops

def stats(L):
    ops = main_ops(L)
    proof = sum(k for o, k, tag in ops if o == 'a' and tag != 'r')
    assert proof == 6255 + 554*L, (proof, L)
    # statement sponge
    A = 2 + 2*math.ceil(25*2**L/3)
    # main transcript perm count and blocks per challenge move
    s = Deployed([0]*16); blocks = 0; maxblocks = {}
    rng = random.Random(1)
    for o, k, tag in ops:
        before = len(s.log)
        for _ in range(k):
            if o == 'a': s.absorb(rng.randrange(P))
            else: s.squeeze()
        if o == 's':
            maxblocks[tag.split('-')[0]] = max(maxblocks.get(tag.split('-')[0], 0), len(s.log)-before)
    return proof, A, math.ceil(A/10), len(s.log), maxblocks

def embed(L, seed=7):
    """Run deployed sponge; then replay with C-O overwrite + full-rate blocks; compare perm inputs."""
    rng = random.Random(seed)
    iv = [rng.randrange(P) for _ in range(16)]
    ops = main_ops(L)
    d = Deployed(iv)
    # record the deployed values, then build C-O inputs online
    co = CO(iv)
    prev_rate = iv[:R]              # value the rate would hold in the deployed sponge
    transcript_ok = True
    for o, k, tag in ops:
        if o == 'a':
            vals = [rng.randrange(P) for _ in range(k)]
            for v in vals:
                # block boundary: deployed permutes on absorb when idx == 10
                if d.i == R:
                    d.p(); d.i = 0
                    # C-O: full-rate overwrite of the block that was just permuted, then squeeze(r)
                    co.absorb(list(prev_rate))
                    prev_rate = co.squeeze(R)
                    assert prev_rate == d.s[:R]
                d.s[d.i] = (d.s[d.i] + v) % P; d.i += 1; d.d = True
                prev_rate = list(d.s[:R])
        else:
            out = []
            for _ in range(k):
                if d.d or d.i >= R:
                    d.p(); d.i = 0; d.d = False
                    co.absorb(list(prev_rate))
                    prev_rate = co.squeeze(R)
                    assert prev_rate == d.s[:R]
                out.append(d.s[d.i]); d.i += 1
    assert d.log == co.log, "perm input sequences differ"
    return len(d.log)

if __name__ == '__main__':
    for L in (1, 2, 6, 7):
        pr, A, ps, pm, mb = stats(L)
        print(f"L={L} n={L+6} proof={pr} stmt_absorbs={A} stmt_perms={ps} main_perms={pm} total_V={ps+pm} max_blocks_per_challenge_move={max(mb.values())}")
        print("   blocks:", mb)
    for L in (1, 2, 6, 7):
        print("embedding identical perm-input sequence, L =", L, "perms =", embed(L))
