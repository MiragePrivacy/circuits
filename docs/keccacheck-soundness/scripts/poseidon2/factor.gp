p=21888242871839275222246405745257275088548364400416034343698204186575808495617;
f=factor(p-1);
print(f);
print(log(p-1)/log(2));
s=1;for(i=1,#f~,s*=f[i,1]^f[i,2];print(f[i,1]," cumulative log2 ",log(s)/log(2)));
quit;
