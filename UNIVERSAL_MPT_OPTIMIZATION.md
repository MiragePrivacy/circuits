# Universal in-circuit MPT tier

Branch: `opt/universal-depth-7-constructed-leaf`

This is the universal circuit/VK candidate under the existing explicit bounds:

- canonical receipt-trie key at most three bytes (transaction index below
  65,536), hence at most six key nibbles;
- receipt at most 448 bytes;
- header at most 704 bytes;
- structurally bounded root and deeper MPT nodes.

Each branch consumes one key nibble and each extension consumes at least one.
Therefore a six-nibble key admits at most six ancestor nodes followed by the
constructed terminal leaf, for a maximum compiled depth of seven. All unused
slots are constrained inert, but R1CS still pays their Keccak and decoder cost.

The entire Ethereum authentication chain remains inside the circuit: full
header Keccak, receipts-root extraction, every MPT Keccak/RLP/path link,
terminal-leaf construction, receipt semantics, intent opening, and statement
hashing.

## Why ordinary preprocessing cannot shorten the proof

An MPT node authenticates only its immediate child reference. Removing an
intermediate node also removes the Keccak equation connecting the parent hash
to the descendant. Off-circuit offsets, decoded shapes, or intermediate hashes
are only hints; the circuit must recompute and constrain every omitted link.

A genuinely constant-depth input would require a succinct proof attesting to
the omitted links, or an independently authenticated non-MPT commitment. The
former is a recursive/folding architecture and the latter is not supplied by
Ethereum's current receipt commitment. Neither is a preprocessing-only change
to this Groth16 relation.

Fast verification uses exact synthesis/profile counts, one representative
satisfying relation, adversarial gadget tests already shared with the parent,
and workspace compilation. Full setup/proving/EVM export remains a finalist
gate.
