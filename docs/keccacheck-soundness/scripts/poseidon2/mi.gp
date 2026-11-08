default(parisize,"512M");
p=21888242871839275222246405745257275088548364400416034343698204186575808495617;
d=[0,1,2,3,4,5,6,7,8,9,10,11,13,14,16,17];
M=matrix(16,16,i,j,Mod(1,p)+if(i==j,Mod(d[i],p),Mod(0,p)));
print("det=",lift(matdet(M)));
A=M; bad=0;
for(k=1,60,c=charpoly(A);if(!polisirreducible(c),bad++;print("reducible at power ",k));A=A*M);
print("reducible powers among 1..60: ",bad);
\\ reference M4-based external layer
M4=[5,7,1,3;4,6,1,1;1,3,5,7;1,1,4,6];
E=matrix(16,16,i,j,my(a=(i-1)\4,b=(j-1)\4);Mod(M4[(i-1)%4+1,(j-1)%4+1],p)*if(a==b,2,1));
print("ext det nonzero=",matdet(E)!=0);
A=E;for(k=1,8,c=charpoly(A);print("ext charpoly degree-factor sizes power ",k,": ",vecsort(apply(poldegree,factormod(lift(c),p)[,1]~))); A=A*E);
quit;
