import math, importlib.util, sys
spec = importlib.util.spec_from_file_location("fs_sched", sys.argv[1]); sched = importlib.util.module_from_spec(spec); spec.loader.exec_module(sched)
P = sched.P; lp = math.log2(P)
for L in (1, 6, 7, 8):
    pr, A, ps, pm, mb = sched.stats(L)
    print(f"L={L} proof={pr} absorbs={A} D_S={ps} main={pm} Q_V={ps+pm} maxblocks={max(mb.values())}")
print("embed L=8", sched.embed(8))
def lt(x): return math.log2(x)
for L, Q in ((8, 3441),):
    tp = 2**128 + Q; l = lt(tp)
    print("L=8 main", l + lt(8) - lp, "cap", lt(11) + 2*l - 6*lp, "coll", 2*l - 8*lp, "b4", l - 2*lp)
    print("CR-2 9t/p", l + lt(9) - lp, "sum t*7932/p", l + lt(7932) - lp)
# L=1: K as function of t, and coefficient
for lt_ in (100, 120, 128, 130, 140, 160):
    et = lt_ + lt(6) - lp
    K = 1
    while 6400 + K*et - math.lgamma(K+1)/math.log(2) > -128: K += 1
    c = K + 1 + 18
    print(f"t=2^{lt_}: K={K} coef={c} main 2^{lt_+lt(c)-lp:.2f} E_K<=2^{6400+K*et-math.lgamma(K+1)/math.log(2):.1f} 4coll 2^{4*lt_-lt(24)-3*lp:.1f}")
