"""Recipe of 2026/306 section 6.1: round skips and ideal degrees.

A skip is ((rF, rP), [deltas]) with deltas as powers of alpha except (alpha-1)*alpha^2.
Degrees are tracked as log_5, with log_5(4) for the alpha-1 factor.
"""
from math import floor, log, log2

A = 5
T = 16
RF = 8
Rf = 4
RP = 57
L52 = log2(5)


def lem32(t, ct, out, nu):
    """Lemma 3.2. Returns (rF, rP, [log5 deltas]) or None."""
    if not (t in (12, 16, 20, 24) and out <= 4 and 8 <= t - ct and Rf >= 3):
        return None
    s = nu % 4
    f = nu // 4
    if f < Rf:
        if s == 0:
            return (f - 1, 0, [0.0] * 4)
        return (f, 0, [0.0] * s + [1.0] * (4 - s))
    if f == Rf:
        if s == 0:
            return (Rf - 1, 0, [0.0] * out)
        l = log(4 * 25, 5)
        return (Rf, s + 2, [1.0] * s + [l] * (4 - s))
    return (Rf, 6, [1.0] * 4)


def lem36(t, ct, out, nu):
    """Lemma 3.6."""
    if not (t in (16, 20, 24) and 4 < out <= 8 and Rf >= 3):
        return None
    d = t - ct
    if 4 + out < d < 8 + out:
        s1 = d - (4 + out)
        return (1, 0, [0.0] * s1 + [1.0] * (out - s1))
    if 8 + out <= d < 16:
        s2 = min(2 * (d - (8 + out)) + (nu - d), 4)
        if s2 == 0:
            return (1, 0, [0.0] * 4 + [1.0] * (out - 4))
        return (2, 0, [0.0] * s2 + [1.0] * (4 - s2) + [2.0] * (out - 4))
    if d >= 16:
        s3 = min(nu - (8 + out), 4)
        if s3 == 0:
            return (1, 0, [0.0] * 8)
        return (2, 0, [0.0] * s3 + [1.0] * (8 - s3))
    return None


def skip(t, ct, out, nu):
    r = lem32(t, ct, out, nu) if out <= 4 else lem36(t, ct, out, nu)
    if r is None:
        return (0, 0, [0.0] * out)  # trivial, only the initial layer stays linear
    rf, rp, ds = r
    ds = sorted(ds)
    if len(ds) >= out:
        ds = ds[:out]  # evaluate surplus variables at constants
    else:
        ds = ds + [1.0] * (out - len(ds))
    return (rf, rp, ds)


def thm51(d, sk):
    rf, rp, ds = sk
    return d * (RF - rf) + (RP - rp) + sum(ds)


def lem54(t, c, o, sk0, fixed_second_ct=None):
    """dI0 for the first permutation, Lemma 5.4."""
    rf, rp, ds = sk0
    nu = t - c + o
    if o <= 4:
        s = nu % 4
        rfp = (nu - s) // 4 - 1
        return o * (RF - rf) + (RP - rp) + 2 * (rfp - 1) * rfp + s * rfp + sum(ds)
    s = max(t - c + o - 16, 0)
    return o * (RF - rf) + (RP - rp) + s + sum(ds)


def fmt(e):
    return "5^%.2f = 2^%.1f" % (e, e * L52)


def recipe_preimage(c, d):
    rows = []
    for o in range(0, c + 1):
        nu = T - c + o
        sk1 = skip(T, c, d, nu)
        d1 = thm51(d, sk1)
        if o == 0:
            d0 = 0.0
            sk0 = None
        else:
            sk0 = skip(T, c, o, T - c)
            d0 = lem54(T, c, o, sk0)
        rows.append((o, sk1, d1, sk0, d0, max(d0, d1)))
    return rows


def collision(c, d):
    assert d % 2 == 0
    rows = []
    for o in range(0, c + 1):
        nu = T - (c - o) - (0)
        sk1 = skip(T, c, d // 2, nu)
        rf, rp, ds = sk1
        d1 = d * (RF - rf) + 2 * (RP - rp) + 2 * sum(ds)
        if o == 0:
            d0 = 0.0
        else:
            sk0 = skip(T, c, o, T - c)
            d0 = lem54(T, c, o, sk0)
        rows.append((o, sk1, d1, d0, max(d0, d1)))
    return rows


def main():
    print("Target recipe for (n~254, t=16, c=6), RF=8, RP=57")
    for d in (1, 2, 3, 4, 5, 6, 8):
        print("--- preimage digest d=%d" % d)
        rows = recipe_preimage(6, d)
        for o, sk1, d1, sk0, d0, m in rows:
            print(" o=%d nu=%2d skip2=%s dI1 %s | skip1=%s dI0 %s | max %s" % (
                o, 10 + o, (sk1[0], sk1[1], [round(x, 2) for x in sk1[2]]), fmt(d1),
                None if sk0 is None else (sk0[0], sk0[1], [round(x, 2) for x in sk0[2]]),
                fmt(d0), fmt(m)))
        b = min(rows, key=lambda r: r[5])
        w1 = b[5] * L52
        print(" best o=%d dI=%s  dI^2=2^%.1f dI^2.38=2^%.1f" % (b[0], fmt(b[5]), 2 * w1, 2.38 * w1))
    for d in (2, 4, 6, 8):
        print("--- collision digest d=%d" % d)
        rows = collision(6, d)
        for o, sk1, d1, d0, m in rows:
            print(" o=%d skip=%s dI1 %s dI0 %s" % (o, (sk1[0], sk1[1], [round(x, 2) for x in sk1[2]]), fmt(d1), fmt(d0)))
        b = min(rows, key=lambda r: r[4])
        print(" best o=%d %s dI^2=2^%.1f" % (b[0], fmt(b[4]), 2 * b[4] * L52))
    print("--- CICO-k with ct=k, nu=16-k (permutation only, Table 2 cross-check)")
    for k in (1, 2, 3, 4):
        sk = skip(T, k, k, 16 - k)
        print(" k=%d skip=%s dI=%s dI^2=2^%.1f" % (k, sk, fmt(thm51(k, sk)), 2 * thm51(k, sk) * L52))
    print("--- as implemented: fixed positions larger than capacity, single block, d=1")
    for nu in (1, 2, 4, 5, 6, 7, 8, 9, 10):
        sk = skip(T, 16 - nu, 1, nu)
        print(" nu=%2d ct=%2d skip=%s dI=%s (paper lemma gate: 8 <= t-ct, needs positions 0..7)" % (
            nu, 16 - nu, sk, fmt(thm51(1, sk))))


if __name__ == "__main__":
    main()
