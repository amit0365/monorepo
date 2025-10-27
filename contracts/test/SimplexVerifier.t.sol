// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/SimplexVerifier.sol";

contract SimplexVerifierTest is Test {
    SimplexVerifier verifier;

    function setUp() public {
        verifier = new SimplexVerifier();
    }

    // ============ Helper Functions ============

    /// @notice Encode a varint u64
    function encodeVarintU64(uint64 value) internal pure returns (bytes memory) {
        bytes memory result = new bytes(10); // Max 10 bytes for u64
        uint256 length = 0;

        while (value >= 0x80) {
            result[length] = bytes1(uint8((value & 0x7F) | 0x80));
            value >>= 7;
            length++;
        }
        result[length] = bytes1(uint8(value));
        length++;

        // Trim to actual length
        bytes memory trimmed = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            trimmed[i] = result[i];
        }
        return trimmed;
    }

    /// @notice Build a Round (epoch, viewCounter) - both are 8-byte big-endian u64
    function buildRound(uint64 epoch, uint64 viewCounter) internal pure returns (bytes memory) {
        return abi.encodePacked(epoch, viewCounter);
    }

    /// @notice Build a Proposal
    function buildProposal(uint64 epoch, uint64 viewCounter, uint64 parent, bytes32 payload)
        internal pure returns (bytes memory)
    {
        return abi.encodePacked(
            buildRound(epoch, viewCounter),
            encodeVarintU64(parent),  // parent is varint
            payload
        );
    }

    /// @notice Build a Vote for Ed25519 - signer is 4-byte big-endian u32
    function buildVote(uint32 signer, bytes memory signature) internal pure returns (bytes memory) {
        return abi.encodePacked(signer, signature);
    }

    /// @notice Create a dummy Ed25519 signature
    function dummySignature() internal pure returns (bytes memory) {
        bytes memory sig = new bytes(64);
        for (uint i = 0; i < 64; i++) {
            sig[i] = bytes1(uint8(i));
        }
        return sig;
    }

    // ============ Varint Tests ============

    function testVarintU64SmallValue() public {
        // Value 42 should encode as single byte
        bytes memory encoded = encodeVarintU64(42);
        assertEq(encoded.length, 1);
        assertEq(uint8(encoded[0]), 42);
    }

    function testVarintU64LargeValue() public {
        // Value 300 = 0b100101100 should encode as two bytes
        // First byte: 0b10101100 (0xAC), Second byte: 0b00000010 (0x02)
        bytes memory encoded = encodeVarintU64(300);
        assertEq(encoded.length, 2);
        assertEq(uint8(encoded[0]), 0xAC);
        assertEq(uint8(encoded[1]), 0x02);
    }

    // ============ Notarize Tests ============

    function testDeserializeNotarize() public {
        uint64 epoch = 1;
        uint64 viewCounter = 100;
        uint64 parent = 99;
        bytes32 payload = bytes32(uint256(0x1234567890abcdef));
        uint32 signer = 5;

        bytes memory proof = abi.encodePacked(
            buildProposal(epoch, viewCounter, parent, payload),
            buildVote(signer, dummySignature())
        );

        (SimplexVerifier.Proposal memory proposal, SimplexVerifier.Vote memory vote) =
            verifier.deserializeNotarize(proof);

        assertEq(proposal.round.epoch, epoch);
        assertEq(proposal.round.viewCounter, viewCounter);
        assertEq(proposal.parent, parent);
        assertEq(proposal.payload, payload);
        assertEq(vote.signer, signer);
        assertEq(vote.signature.length, 64);
    }

    function test_RevertWhen_DeserializeNotarizeInvalidLength() public {
        bytes memory proof = new bytes(10); // Too short
        vm.expectRevert();
        verifier.deserializeNotarize(proof);
    }

    // ============ Nullify Tests ============

    function testDeserializeNullify() public {
        uint64 epoch = 2;
        uint64 viewCounter = 200;
        uint32 signer = 3;

        bytes memory proof = abi.encodePacked(
            buildRound(epoch, viewCounter),
            buildVote(signer, dummySignature())
        );

        (SimplexVerifier.Round memory round, SimplexVerifier.Vote memory vote) =
            verifier.deserializeNullify(proof);

        assertEq(round.epoch, epoch);
        assertEq(round.viewCounter, viewCounter);
        assertEq(vote.signer, signer);
        assertEq(vote.signature.length, 64);
    }

    // ============ Finalize Tests ============

    function testDeserializeFinalize() public {
        uint64 epoch = 1;
        uint64 viewCounter = 100;
        uint64 parent = 99;
        bytes32 payload = bytes32(uint256(0xabcdef));
        uint32 signer = 7;

        bytes memory proof = abi.encodePacked(
            buildProposal(epoch, viewCounter, parent, payload),
            buildVote(signer, dummySignature())
        );

        (SimplexVerifier.Proposal memory proposal, SimplexVerifier.Vote memory vote) =
            verifier.deserializeFinalize(proof);

        assertEq(proposal.round.epoch, epoch);
        assertEq(proposal.round.viewCounter, viewCounter);
        assertEq(proposal.parent, parent);
        assertEq(proposal.payload, payload);
        assertEq(vote.signer, signer);
    }

    // ============ Notarization Tests ============

    function testDeserializeNotarization() public {
        uint64 epoch = 1;
        uint64 viewCounter = 150;
        uint64 parent = 149;
        bytes32 payload = bytes32(uint256(0x999));
        uint32 voteCount = 3;

        bytes memory proof = abi.encodePacked(
            buildProposal(epoch, viewCounter, parent, payload),
            encodeVarintU64(voteCount)
        );

        // Add 3 votes
        for (uint32 i = 0; i < voteCount; i++) {
            proof = abi.encodePacked(proof, buildVote(i, dummySignature()));
        }

        (SimplexVerifier.Proposal memory proposal, SimplexVerifier.Vote[] memory votes) =
            verifier.deserializeNotarization(proof, 10);

        assertEq(proposal.round.epoch, epoch);
        assertEq(proposal.round.viewCounter, viewCounter);
        assertEq(votes.length, voteCount);
        assertEq(votes[0].signer, 0);
        assertEq(votes[1].signer, 1);
        assertEq(votes[2].signer, 2);
    }

    function test_RevertWhen_DeserializeNotarizationTooManySigners() public {
        bytes memory proof = abi.encodePacked(
            buildProposal(1, 100, 99, bytes32(uint256(0x123))),
            encodeVarintU64(10) // 10 votes
        );

        vm.expectRevert();
        verifier.deserializeNotarization(proof, 5); // Max 5 allowed
    }

    // ============ Nullification Tests ============

    function testDeserializeNullification() public {
        uint64 epoch = 3;
        uint64 viewCounter = 300;
        uint32 voteCount = 4;

        bytes memory proof = abi.encodePacked(
            buildRound(epoch, viewCounter),
            encodeVarintU64(voteCount)
        );

        // Add 4 votes
        for (uint32 i = 0; i < voteCount; i++) {
            proof = abi.encodePacked(proof, buildVote(i + 10, dummySignature()));
        }

        (SimplexVerifier.Round memory round, SimplexVerifier.Vote[] memory votes) =
            verifier.deserializeNullification(proof, 10);

        assertEq(round.epoch, epoch);
        assertEq(round.viewCounter, viewCounter);
        assertEq(votes.length, voteCount);
        assertEq(votes[0].signer, 10);
        assertEq(votes[3].signer, 13);
    }

    // ============ Finalization Tests ============

    function testDeserializeFinalization() public {
        uint64 epoch = 5;
        uint64 viewCounter = 500;
        uint64 parent = 499;
        bytes32 payload = bytes32(uint256(0xfff));
        uint32 voteCount = 2;

        bytes memory proof = abi.encodePacked(
            buildProposal(epoch, viewCounter, parent, payload),
            encodeVarintU64(voteCount)
        );

        for (uint32 i = 0; i < voteCount; i++) {
            proof = abi.encodePacked(proof, buildVote(i, dummySignature()));
        }

        (SimplexVerifier.Proposal memory proposal, SimplexVerifier.Vote[] memory votes) =
            verifier.deserializeFinalization(proof, 5);

        assertEq(proposal.round.epoch, epoch);
        assertEq(proposal.round.viewCounter, viewCounter);
        assertEq(votes.length, voteCount);
    }

    // ============ ConflictingNotarize Tests ============

    function testDeserializeConflictingNotarize() public {
        uint64 epoch = 10;
        uint64 viewCounter = 1000;
        uint32 signer = 5;

        // Two different proposals at same round
        bytes32 payload1 = bytes32(uint256(0x111));
        bytes32 payload2 = bytes32(uint256(0x222));

        bytes memory proof = abi.encodePacked(
            buildProposal(epoch, viewCounter, 999, payload1),
            buildVote(signer, dummySignature()),
            buildProposal(epoch, viewCounter, 999, payload2),
            buildVote(signer, dummySignature())
        );

        (
            SimplexVerifier.Proposal memory proposal1,
            SimplexVerifier.Vote memory vote1,
            SimplexVerifier.Proposal memory proposal2,
            SimplexVerifier.Vote memory vote2
        ) = verifier.deserializeConflictingNotarize(proof);

        // Verify both proposals are from same round
        assertEq(proposal1.round.epoch, epoch);
        assertEq(proposal1.round.viewCounter, viewCounter);
        assertEq(proposal2.round.epoch, epoch);
        assertEq(proposal2.round.viewCounter, viewCounter);

        // Verify same signer
        assertEq(vote1.signer, signer);
        assertEq(vote2.signer, signer);

        // Verify different payloads
        assertTrue(proposal1.payload != proposal2.payload);
    }

    function test_RevertWhen_DeserializeConflictingNotarizeEpochMismatch() public {
        bytes memory proof = abi.encodePacked(
            buildProposal(1, 100, 99, bytes32(uint256(0x111))),
            buildVote(5, dummySignature()),
            buildProposal(2, 100, 99, bytes32(uint256(0x222))), // Different epoch
            buildVote(5, dummySignature())
        );

        vm.expectRevert();
        verifier.deserializeConflictingNotarize(proof);
    }

    function test_RevertWhen_DeserializeConflictingNotarizeViewMismatch() public {
        bytes memory proof = abi.encodePacked(
            buildProposal(1, 100, 99, bytes32(uint256(0x111))),
            buildVote(5, dummySignature()),
            buildProposal(1, 101, 99, bytes32(uint256(0x222))), // Different viewCounter
            buildVote(5, dummySignature())
        );

        vm.expectRevert();
        verifier.deserializeConflictingNotarize(proof);
    }

    function test_RevertWhen_DeserializeConflictingNotarizeSignerMismatch() public {
        bytes memory proof = abi.encodePacked(
            buildProposal(1, 100, 99, bytes32(uint256(0x111))),
            buildVote(5, dummySignature()),
            buildProposal(1, 100, 99, bytes32(uint256(0x222))),
            buildVote(6, dummySignature()) // Different signer
        );

        vm.expectRevert();
        verifier.deserializeConflictingNotarize(proof);
    }

    function test_RevertWhen_DeserializeConflictingNotarizeSameProposal() public {
        bytes memory proof = abi.encodePacked(
            buildProposal(1, 100, 99, bytes32(uint256(0x111))),
            buildVote(5, dummySignature()),
            buildProposal(1, 100, 99, bytes32(uint256(0x111))), // Same payload
            buildVote(5, dummySignature())
        );

        vm.expectRevert();
        verifier.deserializeConflictingNotarize(proof);
    }

    // ============ ConflictingFinalize Tests ============

    function testDeserializeConflictingFinalize() public {
        uint64 epoch = 15;
        uint64 viewCounter = 1500;
        uint32 signer = 8;

        bytes memory proof = abi.encodePacked(
            buildProposal(epoch, viewCounter, 1499, bytes32(uint256(0xaaa))),
            buildVote(signer, dummySignature()),
            buildProposal(epoch, viewCounter, 1499, bytes32(uint256(0xbbb))),
            buildVote(signer, dummySignature())
        );

        (
            SimplexVerifier.Proposal memory proposal1,
            SimplexVerifier.Vote memory vote1,
            SimplexVerifier.Proposal memory proposal2,
            SimplexVerifier.Vote memory vote2
        ) = verifier.deserializeConflictingFinalize(proof);

        assertEq(proposal1.round.epoch, epoch);
        assertEq(proposal2.round.epoch, epoch);
        assertEq(vote1.signer, signer);
        assertEq(vote2.signer, signer);
        assertTrue(proposal1.payload != proposal2.payload);
    }

    // ============ NullifyFinalize Tests ============

    function testDeserializeNullifyFinalize() public {
        uint64 epoch = 20;
        uint64 viewCounter = 2000;
        uint32 signer = 12;

        bytes memory proof = abi.encodePacked(
            buildRound(epoch, viewCounter),
            buildVote(signer, dummySignature()),
            buildProposal(epoch, viewCounter, 1999, bytes32(uint256(0xccc))),
            buildVote(signer, dummySignature())
        );

        (
            SimplexVerifier.Round memory nullifyRound,
            SimplexVerifier.Vote memory nullifyVote,
            SimplexVerifier.Proposal memory finalizeProposal,
            SimplexVerifier.Vote memory finalizeVote
        ) = verifier.deserializeNullifyFinalize(proof);

        // Verify nullify and finalize are for same round
        assertEq(nullifyRound.epoch, epoch);
        assertEq(nullifyRound.viewCounter, viewCounter);
        assertEq(finalizeProposal.round.epoch, epoch);
        assertEq(finalizeProposal.round.viewCounter, viewCounter);

        // Verify same signer
        assertEq(nullifyVote.signer, signer);
        assertEq(finalizeVote.signer, signer);
    }

    function test_RevertWhen_DeserializeNullifyFinalizeEpochMismatch() public {
        bytes memory proof = abi.encodePacked(
            buildRound(1, 100),
            buildVote(5, dummySignature()),
            buildProposal(2, 100, 99, bytes32(uint256(0x123))), // Different epoch
            buildVote(5, dummySignature())
        );

        vm.expectRevert();
        verifier.deserializeNullifyFinalize(proof);
    }

    function test_RevertWhen_DeserializeNullifyFinalizeViewMismatch() public {
        bytes memory proof = abi.encodePacked(
            buildRound(1, 100),
            buildVote(5, dummySignature()),
            buildProposal(1, 101, 99, bytes32(uint256(0x123))), // Different viewCounter
            buildVote(5, dummySignature())
        );

        vm.expectRevert();
        verifier.deserializeNullifyFinalize(proof);
    }

    function test_RevertWhen_DeserializeNullifyFinalizeSignerMismatch() public {
        bytes memory proof = abi.encodePacked(
            buildRound(1, 100),
            buildVote(5, dummySignature()),
            buildProposal(1, 100, 99, bytes32(uint256(0x123))),
            buildVote(6, dummySignature()) // Different signer
        );

        vm.expectRevert();
        verifier.deserializeNullifyFinalize(proof);
    }

    // ============ Edge Case Tests ============

    function testVarintMaxU64() public {
        // Test maximum u64 value
        bytes memory encoded = encodeVarintU64(type(uint64).max);
        assertTrue(encoded.length <= 10); // Max 10 bytes for u64
    }

    function testMultiByteVarint() public {
        // Test various multi-byte values
        uint64[5] memory testValues = [
            uint64(127),    // 1 byte
            uint64(128),    // 2 bytes
            uint64(16383),  // 2 bytes
            uint64(16384),  // 3 bytes
            uint64(2097151) // 3 bytes
        ];

        for (uint i = 0; i < testValues.length; i++) {
            bytes memory encoded = encodeVarintU64(testValues[i]);
            assertTrue(encoded.length > 0);
            assertTrue(encoded.length <= 10);
        }
    }
}
