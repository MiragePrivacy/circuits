default(parisize,"1G");
p=21888242871839275222246405745257275088548364400416034343698204186575808495617;
d=[0,1,2,3,4,5,6,7,8,9,10,11,13,14,16,17];
M=matrix(16,16,i,j,Mod(1,p)+if(i==j,Mod(d[i],p),Mod(0,p)));
chi=charpoly(M);
print("charpoly irreducible: ",polisirreducible(chi));
print("trace ",lift(trace(M))," det ",lift(matdet(M)));
\\ lambda in F_p[x]/chi. M^k is irreducible of degree 16 iff lambda^k generates F_(p^16), i.e. lies in no
\\ maximal subfield. The only maximal subfield is F_(p^8).
X=Mod(Mod(1,p)*x,chi);
mu=X^(p^8-1);
print("mu = lambda^(p^8-1) is 1: ",mu==1);
\\ all powers k up to B
B=200000;
A=mu; bad=0; first=0;
for(k=1,B, if(A==1, bad++; if(first==0,first=k)); A=A*mu);
print("powers k<=",B," with M^k reducible: ",bad," first ",first);
\\ also confirm directly on a sample
A=M; for(k=1,64, if(!polisirreducible(charpoly(A)),print("reducible at ",k)); A=A*M);
print("direct check k<=64 done");
\\ the external matrix for context
M4=[5,7,1,3;4,6,1,1;1,3,5,7;1,1,4,6];
E=matrix(16,16,i,j,Mod(M4[(i-1)%4+1,(j-1)%4+1],p)*if((i-1)\4==(j-1)\4,2,1));
f=factormod(lift(charpoly(E)),p);
print("ME charpoly factor degrees: ",apply(poldegree,f[,1]~)," mult ",f[,2]~);
\\ variant diagonals
for(a=1,24,D=d;D[1]=a;N=matrix(16,16,i,j,Mod(1,p)+if(i==j,Mod(D[i],p),Mod(0,p)));ok=matdet(N)!=0;A=N;for(k=1,32,if(!polisirreducible(charpoly(A)),ok=0;break);A=A*N);print("d0=",a," conditions ",ok));
\\ the search rule that yields DIAG: smallest increasing nonnegative integers meeting irreducibility, greedy
cand=[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20];
chk(D)=my(N=matrix(16,16,i,j,Mod(1,p)+if(i==j,Mod(D[i],p),Mod(0,p))),A=N);if(matdet(N)==0,return(0));for(k=1,32,if(!polisirreducible(charpoly(A)),return(0));A=A*N);1;
print("d with 12: ",chk([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]));
print("d with 12 skip 15: ",chk([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,16]));
print("d no 12, with 15: ",chk([0,1,2,3,4,5,6,7,8,9,10,11,13,14,15,16]));
print("d no 12, no 15, 16,17 (deployed): ",chk(d));
print("d shifted +1: ",chk(vector(16,i,d[i]+1)));
print("d 1..16: ",chk(vector(16,i,i)));
print("d 2..17: ",chk(vector(16,i,i+1)));
quit;
