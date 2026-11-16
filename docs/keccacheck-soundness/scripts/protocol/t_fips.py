"""Compare deployed constants with values generated from the FIPS 202 definitions."""
from kc import *
# rc: FIPS 202 Algorithm 5
def rc_bit(t):
    if t % 255 == 0: return 1
    R_ = [1, 0, 0, 0, 0, 0, 0, 0]
    for _ in range(1, t % 255 + 1):
        R_ = [0] + R_
        R_[0] ^= R_[8]; R_[4] ^= R_[8]; R_[5] ^= R_[8]; R_[6] ^= R_[8]
        R_ = R_[:8]
    return R_[0]
for ir in range(24):
    v = 0
    for j in range(7):
        v |= rc_bit(j + 7 * ir) << (2 ** j - 1)
    assert v == RCS[ir], ir
print('24 round constants equal FIPS 202 Algorithm 5/6 output; applied by index t = round')
# rho: FIPS 202 Algorithm 2
off = {(0, 0): 0}; x, y = 1, 0
for t in range(24):
    off[(x, y)] = ((t + 1) * (t + 2) // 2) % 64
    x, y = y, (2 * x + 3 * y) % 5
for yy in range(5):
    for xx in range(5):
        assert RHO[xx + 5 * yy] == off[(xx, yy)], (xx, yy)
print('RHO_OFFSETS[x+5y] equal FIPS 202 Algorithm 2 offsets')
# pi: A'[x,y] = A[(x+3y) mod 5, x]. The spec's map: Pi[P(i)] = Rh[i]; also rho_i = pi_{P(i)}.
for yy in range(5):
    for xx in range(5):
        src = ((xx + 3 * yy) % 5) + 5 * xx
        dst = xx + 5 * yy
        assert P[src] == dst, (xx, yy)
print('strip_pi map P equals FIPS 202 pi: P(src) = dst for all 25 lanes')
for i in range(25):
    assert add1(i, 1) // 5 == i // 5 and add1(i, 1) % 5 == (i % 5 + 1) % 5
print('add_col is (x+a mod 5, y)')
