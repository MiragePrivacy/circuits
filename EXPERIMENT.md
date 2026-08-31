# Combined candidate with constructed terminal leaf

Parent: `opt/combined-candidate` (`902ad3e`), 8,396,989 constraints.

This branch integrates a finite family of canonically constructed receipt-trie
leaves into the combined receipt/header candidate. The circuit constructs the
leaf from the already-bound key remainder and receipt, rather than accepting a
raw terminal-node witness and generically parsing and copying its value.

Measurements and final feasibility conclusions will be recorded after full
relation integration.
