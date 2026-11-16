import math
P = 21888242871839275222246405745257275088548364400416034343698204186575808495617
lp = math.log2(P)
print("log2 p =", lp)
def lg(x): return math.log2(x)
t = 128
def show(L, Vq):
    tp = 2**t + Vq
    ltp = math.log2(tp)
    emax = max(L, 6)
    main = ltp + lg(emax) - lp
    cap = lg(10) + 2*ltp - 6*lp
    m = min(L, 10)
    coll = 2*ltp - m*lp
    b4 = ltp - 2*lp
    print(f"L={L} n={L+6}: main t*{emax}/p = 2^{main:.2f}  cap 10t^2/p^6 = 2^{cap:.1f}  r-coll t^2/p^{m} = 2^{coll:.1f}  domain t/p^2 = 2^{b4:.1f}")
for L, V in ((2, 0), (6, 0), (7, 0)):
    show(L, V)
# L = 1
for Sbits in (6400,):
    et = 128 + lg(6) - lp
    K = 1
    while Sbits + K*et - math.lgamma(K+1)/math.log(2) > -128: K += 1
    print("L=1: log2(t*eps)=", et, " K=", K, " check log2(Pr E_K)=", Sbits + K*et - math.lgamma(K+1)/math.log(2))
    multi = 4*128 - lg(24) - 3*lp
    print("     Pr[4-collision on r] = 2^", multi)
    # win <= E_K + multi + cap + t*(K+1)/p + t*3*6/p
    c = (K+1) + 18
    print(f"     coefficient {c}: t*{c}/p = 2^{128 + lg(c) - lp:.2f}; total with 2^-128 term 2^{lg(2**(128+lg(c)-lp) + 2**-128):.2f}")
    print("     naive t^2/p = 2^", 256-lp)
    print("     kernel lower bound K_attack = floor(3200/log2 p) =", int(3200/lp), "-> t*K/p = 2^", 128+lg(int(3200/lp))-lp)
