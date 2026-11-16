"""Interactive runs: honest, lying, degenerate and forced-escape, with the state function monitored."""
import sys, random, time
from kc import *
L = int(sys.argv[1]) if len(sys.argv) > 1 else 1
mode = sys.argv[2] if len(sys.argv) > 2 else 'all'
seed = int(sys.argv[3]) if len(sys.argv) > 3 else 11
random.seed(seed)
h = 1 << L
in_w = [[random.getrandbits(64) for _ in range(h)] for _ in range(25)]
tabs = words_to_bits(in_w)
lay = layers(tabs, L)
T = tables_to_words(lay[23]['Io'], L)

def monitor(log):
    """State function of 02, section 3, evaluated by direct MLE of the true tables."""
    keep = {}
    def rlcT(beta, tabs_, pt):
        return sum(b * mle(t, pt) for b, t in zip(beta, tabs_)) % R
    def mon(ev, d):
        if ev == 'sum':
            er = eq_table(d['r'])
            bad = (d['s'] - sum(d['beta'][i] * dot(T[i], er) for i in range(25))) % R != 0
        elif ev == 'word':
            ex = eq_table(d['rx'])
            bad = (d['wr'] - sum(d['beta'][i] * dot(T[i], ex) for i in range(25))) % R != 0
        elif ev == 'bit':
            bad = (d['be'] - rlcT(d['beta'], lay[23]['Io'], d['rx'] + d['ry'])) % R != 0
        else:
            Y = lay[d['t']]; v = d['v']; ev2 = ev
            if ev == 'iota':
                d0 = (d['c00'] - mle(Y['Chi'][0], v)) % R
                d1 = (d['crl'] - rlcT([0] + d['beta'][1:], Y['Chi'], v)) % R
                bad = (d['beta'][0] * d0) % R != 0 or d1 != 0
            elif ev == 'chi':
                bad = any(d['pi'][i] != mle(Y['Pi'][i], v) for i in range(25))
            elif ev == 'rho':
                bad = any(d['th'][i] != mle(Y['Th'][i], v) for i in range(25))
            elif ev == 'theta':
                b = d['beta']
                keep['ai'] = any(d['ai'][x] != sum(b[x + 5 * y] * mle(Y['Ah'][x + 5 * y], v) for y in range(5)) % R for x in range(5))
                bad = keep['ai'] or any(d['d'][x] != mle(Y['Dh'][x], v) for x in range(5))
            elif ev == 'theta_d':
                bad = keep['ai'] or any(d['c'][x] != mle(Y['Ch'][x], v) or d['rc'][x] != mle(Y['Rc'][x], v) for x in range(5))
            elif ev == 'theta_c':
                bad = keep['ai'] or any(d['a'][i] != mle(Y['Ah'][i], v) for i in range(25))
            elif ev == 'theta_a':
                bad = any(d['ah'][i] != mle(Y['Ah'][i], v) for i in range(25))
        log.append((ev, d.get('t'), bad))
    return mon

def run(W, plan=None, **kw):
    st = dict(plan=plan, force=[], tight={}, **kw)
    if 'force0' in kw: st['force'] = list(kw['force0'])
    ch = Chan(prover(L, lay, W, st), st['force'])
    log = []
    try:
        verify(ch, L, tabs, W, monitor(log))
        ch.done()
        res = 'ACCEPT'
    except Reject as e:
        res = 'REJECT:' + str(e)
    return res, log, st

Wbad = [list(x) for x in T]
Wbad[3][0] ^= 1 << 17

if mode in ('all', 'honest'):
    t0 = time.time()
    res, log, st = run(T)
    print('honest', res, 'doomed events', sum(b for _, _, b in log), 'of', len(log), 'time %.1fs' % (time.time() - t0))
    assert res == 'ACCEPT' and not any(b for _, _, b in log)
    print('degree bound held in all rounds (asserted); top coefficient nonzero:', {k: v for k, v in st['tight'].items()})
if mode in ('all', 'lie'):
    res, log, st = run(Wbad)
    first = [e for e in log if not e[2]]
    print('lying prover on false statement:', res, 'doomed events', sum(b for _, _, b in log), 'of', len(log))
    assert res.startswith('REJECT:input') and all(b for _, _, b in log)
if mode in ('all', 'degen'):
    # true statement, beta_0 = 0: chi_00 is free and the state function does not count it
    force = [rnd() for _ in range(L)] + [0] + [rnd() for _ in range(24)]
    res, log, st = run(T, force0=force, garbage=True)
    print('beta_0=0, garbage chi_00, true statement:', res, 'doomed events', sum(b for _, _, b in log))
    assert res == 'ACCEPT' and not any(b for _, _, b in log)
    # non-Boolean input: all internal checks still pass against the arithmetic output
    tabs2 = [list(x) for x in tabs]; tabs2[5][7] = 2
    lay2 = layers(tabs2, L)
    T2 = tables_to_words(lay2[23]['Io'], L)
    nb = sum(1 for t in lay2[23]['Io'] for v in t if v not in (0, 1))
    st = dict(plan=None, force=[], tight={})
    ch = Chan(prover(L, lay2, T2, st), st['force'])
    verify(ch, L, tabs2, T2); ch.done()
    print('non-Boolean input (bit := 2): accepted against arithmetic word table; non-Boolean output table entries:', nb)
if mode in ('all', 'escape'):
    plans = sys.argv[4].split(',') if len(sys.argv) > 4 else ['r', 'beta0', 'word', 'bit', 'iota', 'xy', 'chi', 'beta_rho', 'rho', 'beta_theta',
             'theta', 'beta_d', 'theta_d', 'beta_c', 'theta_c', 'b_ba', 'b_ba:ai', 'theta_a', 'beta_next']
    for p in plans:
        kw = {}
        plan = p
        if p == 'r':
            kw['r_forced'] = [1] * L  # the differing word is in instance 0, so its MLE vanishes on x_1 = 1
        if p == 'b_ba:ai':
            plan = 'b_ba'; kw['lie'] = 'ai'
        res, log, st = run(Wbad, plan=plan, **kw)
        k = next((i for i, e in enumerate(log) if not e[2]), None)
        print(f'escape at {p:12s}: {res}; escaped={st.get("escaped")}; first undoomed event: {log[k][:2] if k is not None else None}', flush=True)
        assert res == 'ACCEPT' and st.get('escaped')
        assert all(not e[2] for e in log[k:])
