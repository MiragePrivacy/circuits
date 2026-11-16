\\ L = 1: one output-difference vector killing K independent (r_j, beta_j) relations at once.
\\ Each relation: sum_i beta_i ((1-r) d_{i,0} + r d_{i,1}) = 0 mod p, with d in Z^50.
default(parisize, 2000000000);
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
setrand(20261107);
try(K) = {
  my(n = 50, w = 2^400, B, c, T, v, best = 0, inf);
  c = matrix(K, n);
  for(j = 1, K,
    my(r = random(p), b = vector(25, i, random(p)));
    for(i = 1, 25,
      c[j, 2*i-1] = b[i] * (1 - r) % p;
      c[j, 2*i] = b[i] * r % p));
  B = matrix(n + K, n + K);
  for(i = 1, n, B[i, i] = 1; for(j = 1, K, B[n + j, i] = w * c[j, i]));
  for(j = 1, K, B[n + j, n + j] = w * p);
  T = qflll(B);
  v = B * T[, 1];
  inf = vecmax(abs(v[1..n]~));
  print("K=", K, " first LLL vector: tail zero=", vector(K, j, v[n + j]) == vector(K), " log2 max|d|=", log(inf)/log(2));
  for(j = 1, K, if(sum(i = 1, n, c[j, i] * v[i]) % p != 0, print("  relation fails")));
};
for(K = 1, 14, try(K));
