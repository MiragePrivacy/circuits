# Keccacheck soundness: summary

Status as of 2026-11-07, code at PR 3 head cc59207 plus CR-1 (uncommitted). Production batch: 256 instances
(L = 8, n = 14) for both relations.

## Result

No forgery was found against the deployed relations. Soundness reduces to three things:

1. **Interactive protocol: proved.** Pr[accept false statement] <= (555n + 162)/r = 2^-240.64 at n = 14, for Boolean
   statements and uniform challenges (02). An independent referee re-derived the same count blind.
2. **Fiat-Shamir with the deployed two-sponge transcript: proved in the ideal permutation model.** 8t/p = 2^-122.6
   at t = 2^128 (03). Chiesa-Orru does not cover two chained sponges, so the bound is proved directly. An independent
   referee found no fatal error and reached the same bound; its repairable points are fixed.
3. **Poseidon2 (t=16, BN254, RF=8, RP=57) behaves well enough for (2): assumed, analysed, not provable.**
   The cheapest forgery found costs about 2^151 (one main-chain sumcheck round, univariate degree 5^65), a 22.9-bit
   margin over 128. The statement-sponge route costs about 2^210, and only because statement elements are 192-bit
   packed Booleans (04 section 12). The residual assumption is correlation intractability for the composed function
   (03 section 8). These are upper bounds on attack cost, not hardness proofs.

The R1CS matches the spec at random points, and every named check is enforced and necessary (05). Two blind
reviews confirmed this: a full false-payment witness at production size fails exactly 1 of 3,074,926 rows, in the
batch verifier, and 360 wrong-function mutations each fail one row.

## Documents

| File | Content | Reviewed by |
|---|---|---|
| 01-spec.md | Protocol as implemented | review-rbr |
| 02-interactive-soundness.md | Round-by-round proof | review-rbr (blind re-derivation) |
| 03-fiat-shamir.md | Non-interactive proof, CI assumption, KRS | review-fs (blind re-derivation) |
| 04-poseidon2.md | Parameters, attacks, margin | none independent |
| 05-implementation.md | R1CS correspondence, ceremony identity, tests | review-forgery (blind) |
| NOTES.md | Append-only working log | - |

Referee reports: reviews/{rbr,fs,forgery}.md, with blind first passes in reviews/*-phase1.md. Scripts: scripts/README.md.

## Change requests

| CR | Disposition |
|---|---|
| CR-1 MIN_INSTANCES = 4 | Adopted. Removes the L = 1 case. Production digests unchanged (rebuilt), beta keys stay valid. |
| CR-2 single sponge | Declined: 2^-122.4 vs 2^-122.6, and changes the statement absorption 04 section 12 relies on. |
| CR-3 DIAG + 1 | Declined: no effect of mu_0 = 1 found; the replacement matrix is equally unanalysed. |
| CR-4 RP = 64 | Declined for beta: deployed RF/RP match the reference script. Left to external review. |

## Invariants a later change must keep

- Statement bits are Boolean-constrained (soundness of 02, and injectivity of the 192-bit packing in 03 and 04).
- Statement packing stays at 192 bits per element, or 04 section 12 is redone (full field elements drop to about 2^144).
- No challenge block in the main transcript gets free positions covering 0..6; rerun p2/transcript.py and feasible.py
  after any schedule change.
- Every recorded permutation reaches `finish` (no guard enforces this; advisory `#[must_use]`).

## Open

- External cryptanalysis of this Poseidon2 instance (M_I differs from gnark-crypto's; no published analysis found).
- External review of the 03 two-chain proof and 04.
- Groth16 composition is heuristic. genesis.pk was not re-derived from the matrices.
- Latent: `FpVar::enforce_equal` on two constants is a no-op, and the header parser fills unread bytes with constant
  zeros. Not reachable today.
- Report to Reilabs: the gnark circuit commits only to outputs and has no AssertIsBoolean, and upstream accepts singletons.
- Paper references in the deliverables point at extracted text that is not kept in the repo; the sources are
  ePrint 2025/1764, 2025/536, 2025/118, 2026/306 and 2026/409.
