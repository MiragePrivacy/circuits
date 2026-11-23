# Analysis scripts

Scripts behind the numbers in 01 to 05 and in the reviews. Python runs with
`nix shell nixpkgs#python3 -c python3 -I <script>`, PARI with `nix shell nixpkgs#pari -c gp -q <script>`.
Several take a directory argument for shared modules (for example `l8.py` takes the `poseidon2/` directory).
Run Python scripts from the repository root; source paths inside them are repo-relative.

| Directory | Owner | Main scripts |
|---|---|---|
| protocol/ | 01, 02 | t_replay.py (independent verifier on real proofs), t_identities.py, t_fips.py, t_schedule.py, t_run.py; dump/ prints native proofs |
| fiat-shamir/ | 03 | sched.py (schedule against Chiesa-Orru), bound.py, kernel.gp (L=1 strategy) |
| poseidon2/ | 04 | grain.py, rounds.py, gnark_cmp.py, transcript.py, feasible.py, recipe.py, mu0.py, weights.py, stmt_block.py, stmt_replay.py |
| review-rbr/ | reviews/rbr.md | model.py, p1_identities.py, p2_attacks.py, p2_fuzz.py, p2_replay.py; dump/ |
| review-fs/ | reviews/fs.md | sched.py, nums1.py, nums2.py, toy.py, rl.gp |
| forgery/ | reviews/forgery.md | gkr-no-asserts.patch (upstream prover without its self-checks) |
| lead/ | NOTES.md | l8.py (bounds and schedule at production size) |

Rust tests live with the code:

- crates/keccacheck/src/soundness.rs, testkit.rs, spec_model.rs, matrix.rs (05)
- crates/keccacheck/src/poseidon2/params_tests.rs, tests/poseidon2_permutation_count.rs (04)
- crates/keccacheck/tests/forgery_batch.rs, crates/relation/tests/forgery_relation.rs (reviews/forgery.md)
- crates/prover/tests/keccacheck_identity.rs (05, ceremony digests and keys)

Tests written for 2 instances were moved to 4 (and 4 to 8) when MIN_INSTANCES became 4.
