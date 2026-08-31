# Fixed-layout direct-transfer receipt experiment

Baseline: `opt/baseline-profiling` (`6dea00a`).

## Result

| Metric | Baseline | This branch | Delta |
|---|---:|---:|---:|
| Receipt relation | 828,585 | 2,535 | -826,050 |
| Full relation | 10,426,684 | 9,600,634 | -826,050 (-7.9%) |

The existing single-log adversarial suite passes, and all 100 mainnet fixtures
satisfy the full relation.

## Why it works

With exactly one canonical `Transfer`, only the envelope byte and encoded width
of `cumulativeGasUsed` move field boundaries. The circuit enumerates the 18
possible layouts and reads every checked byte at a compile-time offset. Layout
selectors are derived from the receipt bytes and exact length; no native parse
result is trusted.

## Feasibility

High for the already-adopted direct-transfer/single-log policy. It deliberately
does not support general multi-log receipts. Before production, add exhaustive
tests over gas widths 1 through 9 and preserve the generic parser as the
reference oracle for differential fuzzing.
