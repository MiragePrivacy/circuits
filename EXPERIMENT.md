# Combined candidate with constructed terminal leaf

Parent: `opt/combined-candidate` (`902ad3e`), 8,396,989 constraints.

This branch integrates a finite family of canonically constructed receipt-trie
leaves into the combined receipt/header candidate. The circuit constructs the
leaf from the already-bound key remainder and receipt, rather than accepting a
raw terminal-node witness and generically parsing and copying its value.

## Result

| Metric | Baseline | Parent combined | This branch |
|---|---:|---:|---:|
| MPT traversal | 6,722,724 | 6,634,340 | 3,304,933 |
| Full relation | 10,426,684 | 8,396,989 | 5,061,149 |
| Reduction from baseline | — | 19.5% | **51.5%** |

The terminal construction supports every remaining path length for the
three-byte key bound, not only the common empty path. Ancestor buffers use
structural maxima: 308 bytes for an active root branch and 532 bytes for a
fully occupied deeper branch. A root leaf is represented by zero ancestors.

The shape Boolean is an untrusted witness hint: it only selects whether the
complete 17-item branch decoder or complete two-item extension decoder must
pass. The wrong hint cannot bypass either decoder.

## Fast verification

- All seven remaining-path layouts match native RLP and Keccak.
- Genuine branch-to-leaf, extension, and root-leaf shapes satisfy.
- Wrong root, key, receipt, ancestor, extension path, and appended-node cases
  reject.
- Existing branch-as-short and short-as-branch decoder tests reject.
- The representative full relation satisfies at exactly 5,061,149 constraints.

## Feasibility

High for the current relation's existing depth-four and three-byte-key policy.
The witness API still carries a redundant raw terminal node which synthesis
ignores; remove it in a cleanup pass before merging. Full fixture and proving
tests remain final-candidate gates rather than iteration gates.
