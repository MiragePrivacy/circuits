import re,sys
p=21888242871839275222246405745257275088548364400416034343698204186575808495617
src=open(sys.argv[1]).read()
i=src.index('RC16')
vals=[int(x) for x in re.findall(r'MontFp!\(\s*"(\d+)"\s*\)',src[i:])]
print('rc16 constants in file',len(vals),'expected',8*16+57)
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
def gen(n,t,RF,RP,count):
    o=grain(n,t,RF,RP);r=[]
    while len(r)<count:
        v=0
        for _ in range(n): v=(v<<1)|o()
        if v<p: r.append(v)
    return r
g=gen(254,16,8,57,8*16+57)
print('exact match with Grain(254,16,8,57):',g==vals)
print('first file',vals[0]);print('first grain',g[0])
print('set overlap',len(set(g)&set(vals)))
