import sys, math
from collections import Counter
sys.path.insert(0, sys.argv[1])
import transcript as T
P = 21888242871839275222246405745257275088548364400416034343698204186575808495617
lp = math.log2(P)
def sets(inst):
    v, st, ch = T.run(inst, False)
    return v, st, ch, {tuple(e[2]) for e in v.ev}, Counter((e[0], tuple(e[2])) for e in v.ev)
base = None
for inst in (64, 128, 256, 512):
    v, st, ch, s, c = sets(inst)
    L = inst.bit_length() - 1; n = L + 6
    total = v.m.perms + st
    print(f"inst={inst} L={L} n={n} main={v.m.perms} stmt={st} total={total} proof={v.reads} formula={6255+554*L}")
    print(f"  max free positions before a challenge: {max(len(x) for x in s)}; contains 0..6: {any(set(range(7))<=set(x) for x in s)}")
    print(f"  position sets equal to L=6: {base is None or s==base}")
    if base is None: base = s
    print(f"  interactive {555*n+162}/r = 2^{math.log2(555*n+162)-lp:.2f}")
    print(f"  FS main t*{max(L,6)}/p at 2^128 = 2^{128+math.log2(max(L,6))-lp:.2f}; r-coll t^2/p^{min(L,10)} = 2^{256-min(L,10)*lp:.1f}; cap = 2^{math.log2(11)+256-6*lp:.1f}")
    print(f"  CR-4 +21/perm = +{21*total}; RP=61 +12/perm = +{12*total}; RF=10 +96/perm = +{96*total}")
print("position sets at L=8:", sorted(sets(256)[3], key=lambda x:(len(x),x)))
