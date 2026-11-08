from math import log2, lgamma, log, ceil, e
p=21888242871839275222246405745257275088548364400416034343698204186575808495617
lp=log2(p); print("log2 p",lp)
lT=128.0
def absc(L):
    w=25*2**L; ch=ceil(w/3); n=2+2*ch; return w,ch,n,(n+9)//10
for L in (1,2,6,8): print("L",L,"words/lane-side,chunks,absorbs,perms",absc(L), "|S| bits",3200*2**L)
def lchoose(lT,m): # log2 C(2^lT,m) upper bound
    return m*lT - lgamma(m+1)/log(2)
def m_for(L,tail=-128,d=6):
    s=3200*2**L; m=1
    while s+lchoose(lT,m)+m*(log2(d)-lp)>tail: m+=1
    return m-1
for L in (1,2,8):
    m=m_for(L)
    print("L",L,"m",m,"m T/p^L log2",log2(m)+lT-L*lp if m else None,"crude T^2/p^L",2*lT-L*lp)
    print("  cap",2*lT-6*lp,"B2 LT/p",log2(L)+lT-lp,"k=1 coll",2*lT-1-L*lp,"k=2 coll",3*lT-log2(6)-2*L*lp)
    print("  k*6T/p: k=1",log2(6)+lT-lp,"k=2",log2(12)+lT-lp)
print("L=1 sum (1+51+12)T/p",log2(64)+lT-lp)
print("L=2 6T/p",log2(6)+lT-lp,"8T/p",3+lT-lp)
print("L=8 8T/p",3+lT-lp)
