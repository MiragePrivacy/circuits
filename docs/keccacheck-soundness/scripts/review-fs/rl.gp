\\ For random (r,beta) at L=8, in the deployed field, find short integer word differences d with
\\ sum_{i,j} beta_i eq_r(j) d_ij = 0 mod p. Uses only 40 of the 6400 output words: the rest stay 0.
\\ Shows that every main-root output (s,s') admits a false S that leaves doom: R_L is not sparse.
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
setrand(20261107);
L = 8;
eqr(r, j) = prod(k = 1, L, if(bittest(j, k - 1), r[k], 1 - r[k])) % p;
trial() = {
  my(r = vector(L, k, random(p)), b = vector(25, i, random(p)), n = 40, c, M, V, d, s, m);
  c = vector(n, t, b[(t - 1) % 25 + 1] * eqr(r, (t - 1) \ 25) % p);
  M = matrix(n + 1, n + 1);
  for(i = 1, n, M[i, i] = 1; M[n + 1, i] = c[i] * 2^300);
  M[n + 1, n + 1] = p * 2^300;
  V = M * qflll(M);
  d = 0;
  for(t = 1, n + 1, if(V[n + 1, t] == 0 && vecmax(abs(V[, t])) > 0, d = V[, t]; d = d[1..n]; break));
  if(d === 0, error("no kernel vector"));
  s = sum(i = 1, n, c[i] * d[i]) % p; if(vecmax(abs(d)) == 0, error("zero"));
  m = vecmax(abs(d));
  [s, m];
}
res = vector(20, i, trial());
print("trials with form zero mod p: ", sum(i = 1, 20, res[i][1] == 0), "/20");
print("largest |d_ij| over trials, log2: ", log(vecmax(vector(20, i, res[i][2]))) / log(2));
print("word bound 2^64, so d is a valid word difference: ", vecmax(vector(20, i, res[i][2])) < 2^64);
quit;
