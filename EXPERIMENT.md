# Combined fixed-layout candidate

Baseline: `opt/baseline-profiling` (`6dea00a`).

This branch combines the independently measured fixed-layout receipt and
authenticated-header-prefix experiments. See the corresponding branches for
their detailed soundness arguments and isolated measurements.

Measured additive result:

| Optimization | Constraint delta |
|---|---:|
| Single-transfer receipt layout | -826,050 |
| Authenticated header prefix | -1,114,749 |
| Combined | -1,940,799 (-18.6%) |

The full relation is 8,485,885 constraints, exactly matching the isolated
measurements. The receipt change is
high feasibility for the existing single-log policy. The header change requires
explicit approval of the narrower authenticated-extraction responsibility.
