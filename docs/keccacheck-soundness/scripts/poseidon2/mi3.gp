default(parisize,"1G");
p=21888242871839275222246405745257275088548364400416034343698204186575808495617;
d=[0,1,2,3,4,5,6,7,8,9,10,11,13,14,16,17];
check(D,name)={
  my(M,chi,X,mu,A,bad,first);
  M=matrix(16,16,i,j,Mod(1,p)+if(i==j,Mod(D[i],p),Mod(0,p)));
  chi=charpoly(M);
  print(name," det nonzero ",matdet(M)!=0," irreducible ",polisirreducible(chi));
  X=Mod(Mod(1,p)*x,chi);mu=X^(p^8-1);A=mu;bad=0;first=0;
  for(k=1,100000,if(A==1,bad++;if(first==0,first=k));A=A*mu);
  print(name," reducible powers k<=100000: ",bad," first ",first);
};
check(d,"deployed");
check(vector(16,i,d[i]+1),"deployed+1");
quit;
