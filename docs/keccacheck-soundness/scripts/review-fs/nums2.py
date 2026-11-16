from math import log2, lgamma, log, ceil
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
lp = log2(p)
print("log2 p", lp)
lt = 128.0
def lfact(k): return lgamma(k + 1) / log(2)
print("-- Theorem B first term at t=2^128")
for K in (50, 51, 52, 53):
    print(K, 6400 + K * (log2(6) + lt - lp) - lfact(K))
print("C(t,4)/p^3", 4 * lt - log2(24) - 3 * lp)
print("71 t/p", log2(71) + lt - lp)
print("11 t^2/p^6", log2(11) + 2 * lt - 6 * lp, "25 t^2/p^6", log2(25) + 2 * lt - 6 * lp)
print("-- L>=2 rows")
for L in (2, 6, 7, 8):
    print(L, "t e_max", log2(max(L, 6)) + lt - lp, "t^2/p^L", 2 * lt - L * lp, "t/p^2", lt - 2 * lp,
          "CR-2", log2(max(L + 1, 6)) + lt - lp)
print("-- Section 4 figures")
print("6822/p", log2(6822) - lp, "t*6822/p", log2(6822) + lt - lp, "L=8 interactive sum", 555 * 14 + 162, log2(555 * 14 + 162) - lp)
print("p/6", lp - log2(6), "p/12", lp - log2(12), "p/71", lp - log2(71), "12t/p", log2(12) + lt - lp)
print("-- Section 0 L=1 formula at larger t, K=52 kept")
for l in (128, 130, 132, 133, 134, 140):
    print(l, "first term", 6400 + 52 * (log2(6) + l - lp) - lfact(52))
print("-- smallest K for term<=2^-128 at larger t")
for l in (128, 132, 140, 160):
    K = 1
    while 6400 + K * (log2(6) + l - lp) - lfact(K) > -128:
        K += 1
    print(l, K)
print("-- Lower bound for an unbounded adversary: pick d after seeing many roots (3 calls per root)")
def best_K(bits, lroots, err=lp):
    K = 1
    while bits + K * (lroots - err) - lfact(K) > 0:
        K += 1
    return K - 1
for bits, label in ((3200, "fixed I, 2^3200 d"), (3250, "I free via Keccak inverse, about 2^3250 d")):
    best = (0, None)
    for f in [2 ** -i for i in range(1, 21)]:
        lroots = lt + log2(f) - log2(3)
        K = best_K(bits, lroots)
        val = K * (1 - f)
        if val > best[0]:
            best = (val, (f, K))
    print(label, "best success factor c in c t/p:", best, "log2:", log2(best[0]) + lt - lp)
print("fixed list pigeonhole 3200/lp", 3200 / lp, "half-width box 63 bits", 50 * 63 / lp)
print("-- Doc's K at L=2,8 in section 6.3", 6400 / lp, 1600 * 256 / lp)
print("-- L=8 summary 8t/p", 3 + lt - lp, "9t/p", log2(9) + lt - lp)
