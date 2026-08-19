# Integrating circuit verification into EscrowERC20

Draft. Describes replacing the plaintext receipt-proof path in `EscrowERC20`
with the Groth16 verifier measured at 222,707 gas, and states what is blocked
until the circuit reaches spec step 5.

## 1. What changes

`EscrowERC20.collect` currently proves a Transfer happened by parsing it
on-chain:

```solidity
function collect(ReceiptProof calldata proof, uint256 targetBlockNumber) external {
    _validateBlockHeader(proof.blockHeader, targetBlockNumber);
    bytes32 receiptsRoot = BlockHeaderParser.extractReceiptsRoot(proof.blockHeader);
    if (!MPTVerifier.verifyReceiptProof(...)) revert InvalidReceiptProof();
    if (!ReceiptValidator.validateTransferInReceipt(
            proof.receiptRlp, proof.logIndex, tokenContract, expectedRecipient, expectedAmount
        )) revert InvalidTransferEvent();
    _payout();
}
```

Everything the escrow is trying to keep private is an argument to that call.
`receiptRlp` carries the token, the recipient, the amount, and the paying
address. `proofNodes` carries the sibling hashes that locate it in the block.
The escrow's own immutables `tokenContract`, `expectedRecipient` and
`expectedAmount` are readable directly from storage. An observer needs no
analysis: the settlement is in the calldata.

The circuit moves all of it behind a commitment. `collect` becomes:

```solidity
function collect(uint256[8] calldata proof, WitnessContext calldata w) external {
    _validateWitness(w);                       // 2 checks, was 6
    verifier.verifyProof(proof, _statementSignals(w));   // reverts if invalid
    _payout();
}
```

The four parser libraries, 780 lines, are no longer reachable from `collect`.

## 2. Why the escrow can stop parsing headers

The statement hash (spec 10.2) is built by the escrow from its own storage and
call context, never from caller input. Its last two fields are the hinge:

```
uint64(witnessBlockNumber),
witnessBlockHash
```

The escrow obtains `witnessBlockHash` from `blockhash(witnessBlockNumber)`,
which is EVM-supplied and cannot be forged. It hashes that into the statement.
The circuit privately holds the full header, proves `keccak256(header)` equals
that hash, extracts `receiptsRoot` from index 5 of the parsed 21-field
structure, and proves MPT inclusion of a receipt under it.

So the escrow's guarantee is transitive: it trusts the block hash because the
EVM gave it, and it trusts everything downstream because the proof binds to that
hash. The header never enters calldata, and `BlockHeaderParser` has nothing left
to do.

The current six checks in `_validateBlockHeader` reduce to two:

| Current check | After |
|---|---|
| `targetBlockNumber > block.number` | keep |
| `block.number - targetBlockNumber > MAX_BLOCK_LOOKBACK` | keep, tighten 256 to 128 |
| `blockhash(...) == 0` | keep |
| `keccak256(blockHeader) != targetBlockHash` | circuit |
| `extractBlockNumber(blockHeader) != targetBlockNumber` | circuit |
| `targetBlockNumber <= bondStartBlock` | circuit, spec 12.7 |

Spec 12.10 asks for 128 rather than Solidity's documented 256, as a reorg safety
margin.

## 3. What the escrow must store that it does not today

The commitment (spec 8.3) replaces three immutables:

```solidity
// Removed: readable, and together they identify the settlement.
address public immutable tokenContract;
address public immutable expectedRecipient;
uint256 public immutable expectedAmount;

// Added: keccak256 over those three plus a salt and binding context.
bytes32 public immutable intentCommitment;
```

`tokenContract` is load-bearing beyond `collect`, so removing it is not a pure
deletion. It is the payout asset in `fund`, `_releaseGasAdvance`, `_payout`, and
`cancelAndWithdraw`. Spec 7.3 separates these concerns: the *settlement* asset
is hidden in the commitment, and the *payout* asset is public because the escrow
must transfer it. The rename reflects that:

```solidity
address public immutable payoutAsset;   // public, what the escrow pays out in
bytes32 public immutable intentCommitment;  // hides the settlement asset
```

These are frequently the same token in practice, but the escrow must not assume
it, and the two must not share a variable.

Three fields are also needed for the statement, none of which exist yet:

```solidity
bytes32 public immutable instanceDomain;  // spec 16, per-deployment
bytes32 public immutable requestId;
uint32  public bondAttempt;               // preserved across bonds, spec 11.6
```

`bondAttempt` is a replay tag. `_tryResetBondData` currently clears bond state
wholesale; it must increment this counter instead of clearing it, so a proof
generated under an expired lease cannot be presented under the next one.

## 4. The statement, built on-chain

Spec 10.2 fixes a 285-byte packed preimage. The Rust reference is
`circuits/crates/encoding/src/statement.rs`; the Solidity must agree byte for
byte, since a mismatch yields a verifier that rejects every valid proof with no
diagnostic.

```solidity
/// Caller-supplied context. Only the block number is trusted, and only after
/// the bounds check; everything else is read from storage.
struct WitnessContext {
    uint64 witnessBlockNumber;
}

function _statementSignals(WitnessContext calldata w)
    internal view returns (uint256[2] memory)
{
    bytes32 h = keccak256(abi.encodePacked(
        uint8(2),                        // relation version
        instanceDomain,
        uint256(block.chainid),
        address(this),
        requestId,
        uint32(0),                       // rowIndex: single-row escrow
        intentCommitment,
        bondAttempt,
        uint64(bondStartBlock),
        uint64(bondDeadline),
        bondedExecutor,
        payoutAsset,
        uint256(_calculatePayout()),
        w.witnessBlockNumber,
        blockhash(w.witnessBlockNumber)
    ));
    // Two 128-bit limbs, high then low. Spec 10.1.
    return [uint256(h) >> 128, uint256(h) & type(uint128).max];
}
```

Two properties worth stating explicitly, because both are soundness-critical:

- **Every field comes from storage, `block.*`, or `msg.sender`.** The caller
  supplies one number, and it is range-checked before use. Spec 12.8 requires
  that no caller-controlled value bypass this hash.
- **`abi.encodePacked` widths must match the Rust exactly.** `uint32(0)` is 4
  bytes, `bondedExecutor` is 20, `uint256(block.chainid)` is 32 left-padded.
  Solidity packs `uint32` as 4 bytes and `address` as 20 under `encodePacked`,
  which is what the reference encoder emits. A differential test against the
  Rust vectors is the only way to be sure of this.

`bondDeadline` is a block number here, not a timestamp. The escrow currently
uses `executionDeadline = block.timestamp + 5 minutes`. Spec 12.7 requires
block-numbered bond windows, because the circuit obtains `txBlockNumber` from an
authenticated header and cannot compare it against a timestamp. This is a
breaking change to the bond lifecycle and to nomad's bonding client.

## 5. Embedding the verifier

Spec 15.1 requires the verifier be embedded with no external call, so escrows
share no deployed contract. `circuits/contracts/Verifier.sol` is a standalone
contract; embedding means inheriting or inlining it, not deploying it once and
calling it.

```solidity
contract EscrowERC20 is EscrowBase, Verifier {
```

Every contract gets **smaller**, substantially.

The parsers are `internal` libraries, so solc inlines them into each caller. The
57-byte stubs in `forge build --sizes` are empty shells; the real bytecode sits
inside the escrows. Measured by stubbing every parser call site to a constant so
solc drops the bodies as dead code, then rebuilding:

| Contract | Today | Parsers removed | Recovered | + verifier | Net |
|---|---|---|---|---|---|
| `EscrowERC20` | 9,281 | 3,812 | 5,469 | 8,670 | **-611** |
| `EscrowNative` | 8,855 | 3,463 | 5,392 | 8,321 | **-534** |
| `EscrowBatch` | 17,309 | 10,260 | **7,049** | 15,118 | **-2,191** |

The parsers cost 5.4KB in the single escrows and **7,049 bytes in
`EscrowBatch`**, more than the 4,858-byte verifier that replaces them. Margin to
EIP-170 goes the right way everywhere:

| Contract | Margin today | Margin after |
|---|---|---|
| `EscrowERC20` | 15,295 | 15,906 |
| `EscrowNative` | 15,721 | 16,255 |
| `EscrowBatch` | 7,267 | **9,458** |

`EscrowBatch` is the one to watch, but it gains 2.2KB rather than losing 4.9KB.
Spec 11.6's multi-row claim decoding and per-asset payout grouping have to fit
in 9,458 bytes instead of 7,267 — a better position than today, not a worse one.

This reverses an earlier draft of this document, which assumed the verifier was
a net addition and flagged `EscrowBatch` as at risk of breaching EIP-170. The
assumption was that 780 source lines of library code compile to less than a
pairing verifier. They do not: MPT traversal, RLP decoding, and receipt
validation are branch-heavy byte manipulation, while the verifier is mostly a
fixed table of constants plus three precompile calls.

Caveat on method: the stubbed build replaces parser calls with constants, so
solc also drops the surrounding error paths and some argument marshalling. The
recovered figures are therefore a slight overestimate of what a real migration
frees. The direction and rough magnitude hold; treat the net column as
approximate until the swap is actually built.

### Gas

The right baseline is `EscrowMPTTest.testCollectWithTransferProof_EIP1559` in
`test/Proof.t.sol`, which drives a real mainnet header, receipt, and depth-3
proof through a real `bond()` and `collect()`:

| Path | Gas |
|---|---|
| `EscrowERC20.collect`, plaintext | **724,991** |
| `Verifier.verifyProof` | **222,707** |
| ZK `collect` all-in, estimated | ~250-270k |

Roughly **2.7x** measured on `verifyProof` alone, and **2.7-2.9x** against the
all-in estimate.

For reference, `EscrowBatch.collect` in `test/BatchTempo.t.sol` costs 1,012,502
for one row and 1,095,055 for two. The 82,553 marginal cost per row means the
~1.01M is fixed overhead — header parse, trie walk, receipt decode — paid once
per call regardless of row count. The batch contract is the wrong comparison for
a single-row escrow, but it shows the same structure.

Two caveats remain, and they cut in opposite directions:

- **Token transfers are mocked** at ~2,300 against a real 30-50k. Both paths pay
  this, so it inflates the ratio slightly: adding ~40k to each side moves 2.7x
  toward 2.5x.
- **One fixture, one trie shape.** Depth 3, a 428-byte receipt, 965 bytes of
  proof nodes. On-chain MPT cost scales with depth and node size; a pairing
  check does not. A deeper trie widens the gap.

**Where the cost is.** The proof data is 2,041 bytes:

| Field | Bytes | Calldata gas |
|---|---|---|
| `blockHeader` | 647 | 9,824 |
| `receiptRlp` | 428 | 3,284 |
| `proofNodes` | 965 | 11,852 |
| `receiptPath` | 1 | 16 |
| Total | 2,041 | **24,976** |

24,976 of 724,991 is **3.4%**. The cost is execution, not calldata: hashing each
node, walking nibbles, decoding RLP in EVM code. An earlier draft of this
document treated calldata as a major term. It is not, and the drop to a fixed
264 bytes is a minor benefit rather than a headline one.

## 6. What blocks this today

**The circuit is step 2 of spec 25, not step 5.** From
`crates/relation/src/lib.rs`:

> Not wired: the delayed-witness ancestry chain (12.7), which is step 5.

The transaction block is public in this build. Spec 5.3 marks that testnet-only,
and 12.11 makes temporal anonymity a hard release gate. Concretely: an observer
who sees `collect` learns the exact block containing the settlement, which
usually narrows the candidate set to a handful of transfers. **This integration
is therefore mergeable behind a flag or on a testnet, and is not
mainnet-shippable until 12.7 lands.**

The ancestry chain is what fixes it. `H[0]` is the public witness header, `H[d]`
is the private settlement header, and the circuit proves the parent-hash chain
between them for a private `d` in a compiled range. The escrow side does not
change when this lands, which is why drafting the integration now is worthwhile:
the statement already carries `witnessBlockNumber`, and 12.7 only changes what
the circuit does with it.

Two smaller gaps:

- **Single-row only.** Spec 11.6 collects up to `MAX_ROWS_PER_COLLECT` rows and
  groups payouts by asset. `EscrowERC20` is single-row, so `rowIndex` is
  constant 0 above. `EscrowBatch` is the multi-row case and needs the grouping
  logic; it is a separate piece of work.
- **Native ETH.** The native relation now exists — `NativeCircuit` in
  `crates/relation/src/native.rs`, a second MPT array over the transaction trie
  plus a `status == 1` check on the receipt. It is **not** ready for
  `EscrowNative` to embed. Spec 12.9 requires it cost the same as the ERC-20
  path, and it does not: 17.8M constraints against 10.4M, so proving time
  identifies the asset kind and splits the anonymity set. It also has no mainnet
  fixtures and no exported verifier yet. See the README's "Native ETH" section.

## 7. Test coverage of the success path

The success path is covered, in `test/Proof.t.sol`:

- `testCollectWithTransferProof_EIP1559` — `EscrowERC20`, real mainnet header,
  receipt, and depth-3 proof, through a real `bond()` and `collect()`.
- `testCollectNativeWithTransactionProof_EIP1559` — the same for `EscrowNative`,
  which also walks the transaction trie.

Both pass. Only the ERC-20 transfers are mocked; every proof artifact is real.

Two things make this file easy to miss, and both are worth fixing while the
migration is in flight:

- **The contract is named `EscrowMPTTest`, not matching its filename.**
  `forge test --match-contract Proof` finds nothing, which reads as "no test
  exists" rather than "wrong selector".
- **`EscrowERC20.t.sol` does not cover it.** Its 36 tests all pass `_dummyProof()`
  with every field `hex""`, so they can only exercise rejection: not funded, not
  bonded, past deadline, proof before bond. The success path lives in a
  different file with a different naming convention.

For the migration this matters in a specific way. The 36 rejection tests keep
passing whatever `collect` does internally, because they assert reverts that the
guard clauses produce before any proof logic runs. `Proof.t.sol` is the only
thing that would catch a broken swap, so it is the file to port first and the
one to watch.

Porting it means replacing the four proof fields with a `uint256[8]` and
regenerating the fixture through the prover. `circuits/test/VerifierTest.sol` is
the model: it loads a real proof from `contracts/proof.json` and checks
acceptance, tampering, and statement binding.

Worth adding at the same time: the current fixture is a single depth-3 trie.
Since MPT cost scales with depth and the verifier's does not, a couple more
shapes would turn the gas comparison from one data point into a curve.

## 8. Suggested sequence

1. **Port the 285-byte statement encoder to Solidity** and differential-test it
   against the Rust reference. Do this first and alone. It is the single most
   likely source of a silent mismatch, and a mismatch presents as "every valid
   proof is rejected" with no diagnostic beyond a revert.
2. Move bond deadlines from timestamps to block numbers; preserve `bondAttempt`
   across bonds. Breaking change, coordinate with nomad.
3. Add `instanceDomain`, `requestId`, `intentCommitment`; split `tokenContract`
   into `payoutAsset` plus the commitment.
4. Port `test/Proof.t.sol` to the proof-based interface, per section 7. This is
   the test that would catch a broken swap.
5. Swap `EscrowERC20.collect`, inherit the verifier, drop the parser imports.
6. Re-measure sizes to confirm the projected net reduction.
7. Gate on the step-5 circuit before any mainnet deployment.

Step 1 is independent and can start immediately. Steps 2 and 3 change the
escrow's external interface and need nomad coordination.

Size is no longer a sequencing constraint: every contract shrinks, so the batch
work does not need a size decision before it starts.

## 9. Summary

| | Today | After |
|---|---|---|
| Settlement visible in calldata | yes | no |
| Token, recipient, amount in storage | yes | commitment only |
| Settlement block | in calldata | public until step 5, then hidden |
| Collect gas | 724,991 | ~250-270k est. |
| Calldata | 2,041 bytes | 264 bytes |
| `EscrowERC20` size | 9,281 | ~8,670 |
| `EscrowBatch` size | 17,309 | ~15,118 |

Both baselines are measured against real mainnet data. The gas figure is a
~2.7x improvement, from one trie shape with mocked token transfers; section 5
has the caveats.

The plaintext path is expensive in execution and in code size, because verifying
a receipt on-chain means both storing the code to parse it and running that
code. Calldata turned out to be a minor term, under 3% of the total.

The single blocker is the step-5 ancestry chain: without it the settlement block
stays public and spec 12.11's anonymity gate fails. Everything else is
implementation work.
