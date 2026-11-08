"""Round number conditions for Poseidon2, ported from the reference sage script
(HorizenLabs poseidon2 at bb476b9) and from 2023/323 eq. (1)."""
from math import ceil, floor, log, log2, lgamma, comb
import sys

P_BN = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def lg2(x):
    # log2 of a big int
    b = x.bit_length()
    if b < 900:
        return log2(x)
    s = b - 900
    return log2(x >> s) + s


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def logb(x, b):
    return log(x) / log(b)


def bounds(p, t, RF, RP, alpha, M, n):
    """Terms of sat_inequiv_alpha, in the script's order. RF must meet the max."""
    lp = lg2(p)
    f1 = 6 if M <= floor(lp - (alpha - 1) / 2.0) * (t + 1) else 10
    f2 = 1 + ceil(logb(2, alpha) * min(M, n)) + ceil(logb(t, alpha)) - RP
    f3 = logb(2, alpha) * min(M, lp) - RP
    f4 = t - 1 + logb(2, alpha) * min(M / float(t + 1), lp / 2.0) - RP
    f5 = (t - 2 + M / (2 * log2(alpha)) - RP) / float(t - 1)
    r = floor(t / 3.0)
    over = int((RF - 1) * t + RP + r + r * (RF / 2.0) + RP + alpha)
    under = int(r * (RF / 2.0) + RP + alpha)
    gb4 = 2 * lg2(comb(over, under))
    return dict(stat=f1, interp=f2, gb1=f3, gb2=f4, gb3=f5, gb4=gb4)


def sat(p, t, RF, RP, alpha, M, n):
    b = bounds(p, t, RF, RP, alpha, M, n)
    m = max(ceil(b["stat"]), ceil(b["interp"]), ceil(b["gb1"]), ceil(b["gb2"]), ceil(b["gb3"]))
    return RF >= m and ceil(b["gb4"]) >= M


def script_search(p, t, alpha, M, n, margin=True):
    # Mirrors find_FD_round_numbers, including its loop variable mutation.
    best = (0, 0)
    mincost = float("inf")
    maxrf = 0
    base = None
    for rp0 in range(1, 500):
        rp = rp0
        for rf0 in range(4, 100):
            rf = rf0
            if rf % 2 == 0 and sat(p, t, rf, rp, alpha, M, n):
                if base is None:
                    base = (rf, rp)
                if margin:
                    rf += 2
                    rp = int(ceil(float(rp) * 1.075))
                cost = t * rf + rp
                if cost < mincost or (cost == mincost and rf < maxrf):
                    best = (rf, rp)
                    mincost = cost
                    maxrf = rf
    return best


def eq1(p, t, alpha, kappa, rate):
    """2023/323 eq. (1), RF = 8 fixed."""
    lp = lg2(p)
    a = min(kappa, lp) / log2(alpha) + logb(t, alpha) - 5
    rgbp = 1
    while True:
        c = comb(4 * t + 5 * rate + 2 * rgbp + alpha, 3 * rate + rgbp + alpha)
        if lg2(c) >= kappa / 2:
            break
        rgbp += 1
    b = logb(2, alpha) * min(kappa, lp) - 6
    c1 = t - 7 + logb(2, alpha) * min(kappa / float(t + 1), lp / 2.0)
    c2 = kappa / (2 * log2(alpha)) - 5 * t + 4
    rgb = max(rgbp, b, c1, c2)
    return dict(interp=a, rgbp=rgbp, gb_b=b, gb_c1=c1, gb_c2=c2, RGB=rgb,
                bare=max(a, rgb), rp=ceil(1.075 * max(a, rgb)))


def main():
    p = P_BN
    print("n bits", p.bit_length(), "log2 p", lg2(p))
    print("gcd(5,p-1) =", gcd(5, p - 1), " gcd(3,p-1) =", gcd(3, p - 1))
    print("smallest alpha >=3 coprime:", next(a for a in range(3, 100) if gcd(a, p - 1) == 1))
    n = p.bit_length()
    for t in (2, 3, 4, 8, 12, 16, 20, 24):
        print("script t=%d alpha=5 kappa=128" % t, "with margin", script_search(p, t, 5, 128, n),
              "no margin", script_search(p, t, 5, 128, n, False),
              "eq1 RP", eq1(p, t, 5, 128, max(t - 6, 1))["rp"])
    print("eq1 t=16 rate=10:", eq1(p, 16, 5, 128, 10))
    for rf, rp in [(6, 53), (6, 52), (8, 51), (8, 50), (8, 57), (10, 49)]:
        print("RF,RP", rf, rp, "sat", sat(p, 16, rf, rp, 5, 128, n), bounds(p, 16, rf, rp, 5, 128, n))
    print("kappa=128 bound at 8,57:", bounds(p, 16, 8, 57, 5, 128, n))
    for kappa in (128, 140, 150, 160):
        print("kappa", kappa, "script", script_search(p, 16, 5, kappa, n), "eq1", eq1(p, 16, 5, kappa, 10)["rp"])
    # what security level does the deployed pair satisfy in each sense
    k = 128
    while sat(p, 16, 6, ceil(57 / 1.075), 5, k + 1, n) or sat(p, 16, 8, 57, 5, k + 1, n):
        k += 1
    print("largest kappa with sat(8,57):", k)
    print("log2 5^k: ", {r: r * log2(5) for r in (53, 56, 59, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70)})


if __name__ == "__main__":
    main()
