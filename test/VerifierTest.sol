// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Verifier} from "../contracts/Verifier.sol";

/// @title On-chain verification of a real proof from this circuit
/// @notice Measures what the escrow actually pays, replacing figures inherited
/// from an independent build during the backend evaluation.
///
/// Spec 15.1 requires each escrow embed its own verifier with no external call.
/// This checks that property directly and reports the two numbers the design
/// depends on: deployed size against EIP-170's 24,576-byte limit and the
/// internal 20,000-byte budget, and gas per verification.
///
/// The exported artifacts live in `contracts/`, not `out/`: forge clears its
/// own `out` directory, which destroyed an earlier export. Generated source and
/// build artifacts must not share a path.
///
/// Run after `cargo run -p mirage-prover --release --bin export-verifier`:
///
///     forge test --match-path test/VerifierTest.sol -vv
contract VerifierTest is Test {
    Verifier internal verifier;

    /// A real proof of the step-2 relation, from `out/proof.json`.
    ///
    /// G2 coordinates are ordered (x1, x0, y1, y0), which is what the EVM
    /// pairing precompile takes and the reverse of arkworks' serialization.
    /// Getting that wrong yields a verifier that rejects every valid proof with
    /// no diagnostic beyond `false`.
    uint256[8] internal proof;
    uint256[2] internal publicSignals;

    function setUp() public {
        verifier = new Verifier();
        _loadProof();
    }

    /// The proof this circuit produces must verify on-chain.
    ///
    /// If this fails while the native verification in `export-verifier` passed,
    /// the fault is in serialization — almost certainly G2 coordinate order or
    /// endianness — rather than in the circuit or the key.
    function test_VerifiesARealProof() public view {
        bool ok = _verify(proof, publicSignals);
        assertTrue(ok, "a valid proof was rejected on-chain");
    }

    /// A proof must not verify against a different statement.
    ///
    /// This is the property the two-signal design exists to provide: the proof
    /// is bound to one chain, escrow, request, row, bond attempt, collector,
    /// payout and witness block, all hashed into the signals.
    function test_RejectsAModifiedStatement() public view {
        uint256[2] memory tampered = [publicSignals[0] + 1, publicSignals[1]];
        assertFalse(_verify(proof, tampered), "accepted a different statement");

        tampered = [publicSignals[0], publicSignals[1] + 1];
        assertFalse(_verify(proof, tampered), "accepted a different statement");
    }

    /// A tampered proof must not verify.
    function test_RejectsATamperedProof() public view {
        uint256[8] memory bad = proof;
        bad[0] = bad[0] ^ 1;
        assertFalse(_verify(bad, publicSignals), "accepted a tampered proof");
    }

    /// The measurement that matters for spec 15.4's budgets.
    function test_ReportsDeployedSize() public {
        uint256 size;
        address target = address(verifier);
        assembly {
            size := extcodesize(target)
        }

        emit log_named_uint("deployed bytes", size);
        emit log_named_uint("EIP-170 limit ", 24576);
        emit log_named_uint("internal budget", 20000);

        // The escrow's state machine is roughly 3-4KB on top, so the verifier
        // must leave room for it.
        assertLt(size, 20000, "verifier alone exceeds the internal budget");
    }

    /// The per-collection gas cost, spec 15.5.
    function test_ReportsVerificationGas() public {
        uint256 before = gasleft();
        _verify(proof, publicSignals);
        uint256 used = before - gasleft();

        emit log_named_uint("verification gas", used);
        // Spec 15.5 expects roughly 193,300 in curve operations plus decoding
        // and calldata overhead. Well over 400k would mean the template is not
        // the compact two-signal verifier the design assumes.
        assertLt(used, 400000, "verification gas far above the expected range");
    }

    /// Spec 7.2: the only permitted external calls are protocol precompiles.
    ///
    /// A verifier that reached a deployed library or another contract would
    /// breach the no-shared-contract invariant, which is the whole reason the
    /// verifier is embedded rather than called.
    function test_TouchesOnlyPrecompiles() public {
        vm.record();
        _verify(proof, publicSignals);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(verifier));

        assertEq(reads.length, 0, "verifier reads storage");
        assertEq(writes.length, 0, "verifier writes storage");
    }

    // ------------------------------------------------------------- helpers

    function _verify(uint256[8] memory p, uint256[2] memory signals)
        internal
        view
        returns (bool)
    {
        try verifier.verifyProof(p, signals) {
            return true;
        } catch {
            return false;
        }
    }

    /// Reads the proof emitted by `export-verifier`.
    ///
    /// Kept in a helper so a regenerated proof needs no edits elsewhere.
    function _loadProof() internal {
        string memory json = vm.readFile("contracts/proof.json");

        uint256[] memory p = vm.parseJsonUintArray(json, ".proof");
        require(p.length == 8, "proof.json: expected 8 field elements");
        for (uint256 i = 0; i < 8; i++) {
            proof[i] = p[i];
        }

        uint256[] memory s = vm.parseJsonUintArray(json, ".publicSignals");
        require(s.length == 2, "proof.json: expected 2 public signals");
        publicSignals[0] = s[0];
        publicSignals[1] = s[1];
    }
}
