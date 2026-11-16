import sys
f = sys.argv[1]
s = open(f).read()
reps = [
 ("L >= 1 is enforced (V:399, V:411, V:434, V:534, batch.rs padding)", "L >= 1 is enforced (V:399, V:411, V:433, V:534, batch.rs padding)"),
 ("(the constants in V:778 are in that range)", "(the constants at V:780 are in that range)"),
 ("the chain at V:438 does not let them merge", "the chain at V:439 restarts chunking at the boundary"),
 ("The term is 25 t^2/p^6 = 2^-1257 at t = 2^128.", "The term is 25 t^2/p^6 = 2^-1261 at t = 2^128."),
 ("and t times the sum would have been\n2^-112.", "and t times the sum would have been\n2^-112.9."),
 ("t' 71 / p  +  11 t'^2 / p^6  +  2^-128 + 2^-253 ", "t' 71 / p  +  11 t'^2 / p^6  +  2^-222 + 2^-253 "),
 ("- kernel.gp: section 6.3 lattice experiment. KERNEL_RESULT", "- kernel.gp: section 6.3 with uniform random (r_j, beta_j) in place of real chains. For K = 1..14, LLL on the 50 coordinates finds a vector in all K relations, each verified mod p. log2 of the largest |d| is 60.7 at K = 12 (inside the 64-bit box) and 65.3 at K = 13 (outside), in line with the pigeonhole threshold 3200/253.6 = 12.6. So K = 12 is achievable in practice, not only by counting. It does not run a proof end to end; the claim that such a hit yields an accepted proof follows from the checks in 6.1."),
 ("Scratchpad kernel.gp ran this with LLL for K up to 14; see section 14 for the result.", "Scratchpad kernel.gp found such vectors by LLL: at K = 12 entries are about 2^60.7, in range; see section 14."),
 ("| Poseidon2 behaves as an ideal permutation (2^128 work) | Assumption. 04 analyzes; a heuristic in any case |", "| Poseidon2 behaves as an ideal permutation (2^128 work) | Assumption, and a heuristic in any case. 04 analyzes it; its log entries report M_I with mu_0 = 1 and that t = 16 over BN254 is not a published instance. A structural weakness there voids sections 5 and 6 for the concrete P, not their statements about ideal P |"),
]
for a, b in reps:
    assert s.count(a) == 1, a
    s = s.replace(a, b)
assert all(ord(c) < 128 for c in s), [c for c in s if ord(c) >= 128][:5]
open(f, 'w').write(s)
