"""Layout of the statement-final block of derive_r, following verifier.rs derive_r_var.

Absorb order: tag, 2^L, then input words chunked by 3, then output words chunked by 3 (separately).
Words are lane-major: word index = lane * n + instance. A packed element is w0 + 2^64 w1 + 2^128 w2.
For each L, prints the final block and, per position, the instances whose words sit there.
"""
import sys
from itertools import combinations
from math import log2

RATE = 10


def layout(L):
    n = 1 << L
    absorbs = [("tag", None), ("size", None)]
    for stream in ("in", "out"):
        words = list(range(25 * n))
        for c in range(0, len(words), 3):
            absorbs.append((stream, words[c:c + 3]))
    A = len(absorbs)
    # sponge: absorb k goes to position k % 10, a permutation runs before absorbs 10, 20, ...
    first = ((A - 1) // RATE) * RATE
    block = absorbs[first:]
    return n, A, first, block


def common_bits(insts, L):
    # number of bit positions on which all instances agree
    return sum(1 for b in range(L) if len({(i >> b) & 1 for i in insts}) == 1)


for L in ([int(x) for x in sys.argv[1:]] or [1, 2, 3, 8]) if __name__ == "__main__" else []:
    n, A, first, block = layout(L)
    print("L=%d n=%d absorbs=%d final block absorbs %d..%d positions 0..%d, r_k = output positions 0..%d of that permutation" % (
        L, n, A, first, A - 1, len(block) - 1, L - 1))
    best = None
    for pos, (stream, words) in enumerate(block):
        if words is None:
            print("  pos %d %s (constant)" % (pos, stream))
            continue
        cells = [(w // n, w % n) for w in words]
        print("  pos %d %s bits %d words (lane,inst) %s" % (pos, stream, 64 * len(words), cells))
        insts = sorted({i for _, i in cells})
        # choose a wrong set S of instances in this position; free bits = 64 per word of S
        for k in range(1, len(insts) + 1):
            for S in combinations(insts, k):
                fb = 64 * sum(1 for _, i in cells if i in S)
                T = common_bits(S, L)
                if T == 0:
                    continue
                # output words must be wrong; input words wrong means the instance claims another input,
                # which is allowed only if the claimed (input, output) pair is still false
                score = fb + log2(T)
                if best is None or score > best[0]:
                    best = (score, pos, S, fb, T, stream)
    print("  best single position: pos %d stream %s instances %s free bits %d targets T=%d" % (
        best[1], best[5], best[2], best[3], best[4]))
    D = 65 * log2(5)
    print("  univariate cost floor: 2^%.1f (D) * 2^%d (root in box) / T = 2^%.1f ; generic grinding 2^%.1f" % (
        D, 254 - best[3], D + 254 - best[3] - log2(best[4]), 253.6 - log2(best[4])))
