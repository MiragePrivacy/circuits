import sys, random
from kc import *
random.seed(3)
for L in [1, 2, 6, 7]:
    lines = open(f'dump{L}.txt').read().split('\n')
    inp, outp, proof, chal = [[int(x) for x in l.split()] for l in lines[:4]]
    h = 1 << L
    in_w = [inp[i * h:(i + 1) * h] for i in range(25)]
    W = [outp[i * h:(i + 1) * h] for i in range(25)]
    tabs = words_to_bits(in_w)
    ch = Replay(proof, chal)
    verify(ch, L, tabs, W)
    assert ''.join(ch.ops) == open(f'sched{L}.txt').read()
    print(f'L={L} n={L+6}: native prover proof ({len(proof)} elements) accepted by the spec model')
    # layers from the spec give the native output
    if L <= 2:
        lay = layers(tabs, L)
        assert tables_to_words(lay[23]['Io'], L) == W
        print(f'L={L}: layer tables reproduce the native output')
    if L == 1:
        for _ in range(30):
            pos = random.randrange(len(proof))
            bad = list(proof); bad[pos] = (bad[pos] + 1) % R
            try:
                verify(Replay(bad, chal), L, tabs, W); print('ACCEPTED TAMPERED', pos); sys.exit(1)
            except Reject: pass
        print('30 random single-element proof tampers rejected')
        bad = [list(x) for x in W]; bad[7][1] ^= 1 << 40
        try:
            verify(Replay(proof, chal), L, tabs, bad); print('ACCEPTED'); sys.exit(1)
        except Reject as e: print('flipped output rejected at', e)
