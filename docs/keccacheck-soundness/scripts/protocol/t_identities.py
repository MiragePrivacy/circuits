"""Keccak layer correctness and polynomial identities at random points."""
import hashlib, random, sys
from kc import *
random.seed(1)
def f1600_via_layers(state):
    tabs = words_to_bits([[w] for w in state])
    lay = layers(tabs, 0)
    return [w for [w] in tables_to_words(lay[23]['Io'], 0)]
# known test vector for f(0)
out = f1600_via_layers([0] * 25)
assert out[0] == 0xF1258F7940E1DDE7 and out[1] == 0x84D5CCF933C0478A and out[24] == 0xEAF1FF7B5CECA249, hex(out[0])
print('f(0) matches the published Keccak-f test vector (lanes 0, 1, 24)')
# sha3-256 via sponge over the layered permutation
def sha3_256(msg):
    rate = 136; m = bytearray(msg); m.append(0x06); m.extend(b'\0' * ((-len(m)) % rate)); m[-1] |= 0x80
    st = [0] * 25
    for off in range(0, len(m), rate):
        for i in range(rate // 8): st[i] ^= int.from_bytes(m[off + 8 * i:off + 8 * i + 8], 'little')
        st = f1600_via_layers(st)
    return b''.join(st[i].to_bytes(8, 'little') for i in range(4))
for k in [0, 1, 135, 136, 137, 300]:
    m = random.randbytes(k)
    assert sha3_256(m) == hashlib.sha3_256(m).digest()
print('sha3-256 via layered permutation matches hashlib for 6 message lengths')
assert HALF * 2 % R == 1
print('HALF * 2 = 1 mod r')
for L in [1, 2, 3]:
    n = L + 6; N = 1 << n
    a = [rnd() for _ in range(n)]; c = [rnd() for _ in range(n)]
    # eq, eval_eq, eval_mle against each other
    tab = [rnd() for _ in range(N)]
    assert dot(tab, eq_table(a)) == mle(tab, a)
    assert eq_table(a)[5] == eq(a, [(5 >> (n - 1 - m)) & 1 for m in range(n)])
    # rot vs brute force MLE of the predicate, every lane
    ea, ec = eq_table(a), eq_table(c)
    for s in RHO:
        brute = 0
        for idx_c in range(N):
            j, b = idx_c >> 6, idx_c & 63
            brute += ea[(j << 6) + (b + s) % 64] * ec[idx_c]
        assert brute % R == rot_eval(s, a, c, L)
        assert dot(rot_table(s, a, L), ec) == rot_eval(s, a, c, L)
        # rotl(X,s)~(a) = sum_k rot_s(a,k) X(k)
        X = [random.randrange(2) for _ in range(N)]
        Y = [X[(i & ~63) + (((i & 63) - s) % 64)] for i in range(N)]
        assert mle(Y, a) == dot(rot_table(s, a, L), X)
    # per-variable multilinearity of rot in a and in c: f(0),f(1),f(t) affine
    for pos in range(n):
        s = 1
        for which in (a, c):
            fs = []
            for v in (0, 1, 2, 3):
                z = list(which); z[pos] = v
                fs.append(rot_eval(s, z, c, L) if which is a else rot_eval(s, a, z, L))
            assert (fs[0] - 2 * fs[1] + fs[2]) % R == 0 and (fs[1] - 2 * fs[2] + fs[3]) % R == 0
    # word table vs bits
    W = [random.getrandbits(64) for _ in range(1 << L)]
    B = [(w >> b) & 1 for w in W for b in range(64)]
    rx = [rnd() for _ in range(L)]; ry = [rnd() for _ in range(6)]
    pw = [1 << b for b in range(64)]
    assert mle(W, rx) == sum(pw[b] * mle(B, rx + [(b >> (5 - m)) & 1 for m in range(6)]) for b in range(64)) % R
    # hypercube meaning of rc table index
    rc = [(RCS[3] >> b) & 1 for b in range(64)]
    assert mle(rc, [(5 >> (5 - m)) & 1 for m in range(6)]) == (RCS[3] >> 5) & 1
print('eq, eval_eq, eval_mle, rot (25 offsets, L=1,2,3), word/bit recomposition identities hold at random points')
# strip_pi is the inverse of standard rho-pi: checked through the sha3 test; show cycle structure
cur, seen = 1, []
for t in PI:
    seen.append(t)
assert sorted(seen) == list(range(1, 25))
print('PI lists each of 1..24 exactly once')
