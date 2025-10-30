// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CodecHelpers} from "./libraries/CodecHelpers.sol";
import {HashFunction} from "./interfaces/ISignatureScheme.sol";

/// @title SimplexVerifierBase
/// @notice Abstract base contract for Simplex consensus proof verification
/// @dev Provides shared deserialization logic for extracting raw bytes from proofs
/// @dev Concrete implementations handle scheme-specific signature formats
abstract contract SimplexVerifierBase {
    // ============ Constants ============

    uint256 internal constant DIGEST_LENGTH = 32;

    // ============ Errors ============

    error Conflicting_EpochMismatch();
    error Conflicting_ViewMismatch();
    error Conflicting_SignerMismatch();
    error Conflicting_ProposalsMustDiffer();
    error UnsupportedHashFunction();

    // ============ Deserialization Helpers ============

    /// @notice Extract round bytes from proof
    /// @dev Round format: epoch (8 bytes) + view (8 bytes) = 16 bytes total
    /// @dev Rust: consensus/src/types.rs:55-59
    /// @param data The proof calldata
    /// @param offset Starting position
    /// @return roundBytes The raw round bytes (16 bytes)
    /// @return newOffset Updated offset after reading
    function extractRoundBytes(bytes calldata data, uint256 offset)
        internal pure returns (bytes calldata roundBytes, uint256 newOffset)
    {
        if (offset + 16 > data.length) revert CodecHelpers.InvalidProofLength();
        return (data[offset:offset+16], offset + 16);
    }

    /// @notice Extract proposal bytes from proof
    /// @dev Proposal format: round (16 bytes) + parent (varint) + payload (32 bytes)
    /// @dev Rust: consensus/src/simplex/types.rs:812-817
    /// @param data The proof calldata
    /// @param offset Starting position
    /// @return proposalBytes The raw proposal bytes
    /// @return newOffset Updated offset after reading
    function extractProposalBytes(bytes calldata data, uint256 offset)
        internal pure returns (bytes calldata proposalBytes, uint256 newOffset)
    {
        uint256 startOffset = offset;

        // Skip round (16 bytes)
        offset += 16;

        // Skip parent varint
        (, offset) = CodecHelpers.decodeVarintU64(data, offset);

        // Skip payload (32 bytes)
        if (offset + DIGEST_LENGTH > data.length) revert CodecHelpers.InvalidProofLength();
        offset += DIGEST_LENGTH;

        return (data[startOffset:offset], offset);
    }

    /// @notice Read epoch and view from round bytes (for validation)
    /// @param roundBytes The 16-byte round bytes
    /// @return epoch The epoch value
    /// @return viewCounter The view value
    function parseRound(bytes calldata roundBytes)
        internal pure returns (uint64 epoch, uint64 viewCounter)
    {
        require(roundBytes.length == 16, "Invalid round length");
        epoch = uint64(bytes8(roundBytes[0:8]));
        viewCounter = uint64(bytes8(roundBytes[8:16]));
    }

    /// @notice Read payload from proposal bytes (for validation)
    /// @param proposalBytes The proposal bytes
    /// @return payload The 32-byte payload digest
    function parseProposalPayload(bytes calldata proposalBytes)
        internal pure returns (bytes32 payload)
    {
        // Proposal format: round (16) + parent (varint, at least 1) + payload (32)
        require(proposalBytes.length >= 16 + 1 + 32, "Invalid proposal length");

        // Payload is always the last 32 bytes
        uint256 payloadOffset = proposalBytes.length - 32;
        payload = bytes32(proposalBytes[payloadOffset:payloadOffset+32]);
    }

    // ============ Message Encoding for Signature Verification ============

    /// @notice Encode message using union_unique format for signature verification
    /// @dev CRITICAL: The actual signed message uses union_unique format:
    ///      varint(namespace_len) + namespace + message
    /// @dev Rust: utils/src/lib.rs:136-143 (union_unique)
    ///      This prevents collision attacks by length-prefixing the namespace
    /// @param namespaceWithSuffix The full namespace (e.g., "MyApp_NOTARIZE")
    /// @param messageBytes The raw message bytes from proof (e.g., proposal bytes)
    /// @return The combined bytes: varint(namespace.len()) + namespace + message
    function encodeSignedMessage(bytes memory namespaceWithSuffix, bytes calldata messageBytes)
        internal pure returns (bytes memory)
    {
        // Encode namespace length as varint
        bytes memory lengthVarint = CodecHelpers.encodeVarintU64(uint64(namespaceWithSuffix.length));

        // Combine: varint(len) + namespace + message
        return abi.encodePacked(lengthVarint, namespaceWithSuffix, messageBytes);
    }

    /// @notice Hash a message using the specified hash function
    /// @dev Dispatches to the appropriate hash function based on the scheme's configuration
    /// @param message The message bytes to hash
    /// @param hashFunc The hash function to use (SHA256 or KECCAK256)
    /// @return The 32-byte hash digest
    function hashMessage(bytes memory message, HashFunction hashFunc)
        internal pure returns (bytes32)
    {
        if (hashFunc == HashFunction.SHA256) {
            return sha256(message);
        } else if (hashFunc == HashFunction.KECCAK256) {
            return keccak256(message);
        } else {
            revert UnsupportedHashFunction();
        }
    }

    // ============ Validation Helpers ============

    /// @notice Validate that two rounds are identical
    /// @param roundBytes1 First round bytes (16 bytes)
    /// @param roundBytes2 Second round bytes (16 bytes)
    function validateRoundsMatch(bytes calldata roundBytes1, bytes calldata roundBytes2)
        internal pure
    {
        (uint64 epoch1, uint64 viewCounter1) = parseRound(roundBytes1);
        (uint64 epoch2, uint64 viewCounter2) = parseRound(roundBytes2);

        if (epoch1 != epoch2) revert Conflicting_EpochMismatch();
        if (viewCounter1 != viewCounter2) revert Conflicting_ViewMismatch();
    }

    /// @notice Validate that two proposals differ
    /// @param proposalBytes1 First proposal bytes
    /// @param proposalBytes2 Second proposal bytes
    function validateProposalsDiffer(bytes calldata proposalBytes1, bytes calldata proposalBytes2)
        internal pure
    {
        if (keccak256(proposalBytes1) == keccak256(proposalBytes2)) {
            revert Conflicting_ProposalsMustDiffer();
        }
    }
}
