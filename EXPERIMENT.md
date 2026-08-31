# Combined fixed-layout candidate

Baseline: `opt/baseline-profiling` (`6dea00a`).

This branch combines the independently measured fixed-layout receipt,
448-byte structural receipt bound, and authenticated-header-prefix experiments.
See the corresponding branches for their detailed soundness arguments and
isolated measurements.

Measured additive result:

| Optimization | Constraint delta |
|---|---:|
| Single-transfer receipt layout | -826,050 |
| 448-byte receipt bound after fixed layout | -88,896 |
| Authenticated header prefix | -1,114,749 |
| Combined | -2,029,695 (-19.5%) |

The full relation is 8,396,989 constraints. The receipt changes are high
feasibility for the existing single-log policy. The header change requires
explicit approval of the narrower authenticated-extraction responsibility.
