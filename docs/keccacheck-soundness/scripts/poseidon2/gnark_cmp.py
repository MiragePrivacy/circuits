import re,sys
sys.path.insert(0,sys.argv[3])
from p2lib import *
src=open(sys.argv[2]).read()
i=src.index('16: {')
vals=[int(x,16) for x in re.findall(r'mustElement\("0x([0-9a-f]+)"\)',src[i:])]
print('gnark t=16 values',len(vals))
diag=vals[:16]
rc=load_rc(sys.argv[1])
flat=[x for r in rc[0] for x in r]+rc[1]+[x for r in rc[2] for x in r]
print('our RC first in gnark list',flat[0] in vals,' all RC in gnark',all(x in set(vals) for x in flat))
print('gnark diag0',hex(diag[0]))
# Grain continuation
def grain(n,t,RF,RP):
    b=[]
    def add(v,l):
        for k in range(l-1,-1,-1): b.append((v>>k)&1)
    add(1,2);add(0,4);add(n,12);add(t,12);add(RF,10);add(RP,10)
    b+= [1]*(80-len(b))
    def step():
        nb=b[62]^b[51]^b[38]^b[23]^b[13]^b[0]
        b.pop(0);b.append(nb);return nb
    for _ in range(160): step()
    def out():
        while True:
            x=step()
            if x==1: return step()
            step()
    return out
o=grain(254,16,8,57)
def rand(n=254):
    v=0
    for _ in range(n): v=(v<<1)|o()
    return v
c=[]
while len(c)<185:
    v=rand()
    if v<p: c.append(v)
print('grain matches our RC',c==flat)
d=[rand()%p for _ in range(16)]
print('script random diag minus one first',hex((d[0]-1)%p),'matches gnark',[(x-1)%p for x in d]==diag)
