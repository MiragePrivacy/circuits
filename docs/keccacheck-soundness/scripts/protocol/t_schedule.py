import sys
from kc import *
for L in [1, 2, 6, 7]:
    s = Schedule()
    try:
        verify(s, L, [[0] * (64 << L)] * 25, [[0] * (1 << L)] * 25)
    except Reject as e:
        assert str(e).startswith('input lane'), e
    ops = ''.join(s.ops)
    open(f'sched{L}.txt', 'w').write(ops)
    print(L, 'reads', ops.count('R'), 'expected', 6255 + 554 * L, 'gens', ops.count('G'))
    assert ops.count('R') == 6255 + 554 * L
    n = L + 6
    assert ops.count('G') == L + 25 + L + 6 + 24 * (7 * n + 97) + 23 * 25
