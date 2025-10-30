// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BLS2} from "bls-solidity/libraries/BLS2.sol";

/// @notice Hash function choices for message hashing
enum HashFunction {
    SHA256,
    KECCAK256
    // BLAKE2B  // Not supported yet
}

/// @title IAttributableScheme
/// @notice Interface for signature schemes with individual attributable signatures
/// @dev Used for schemes like Ed25519 where each signature can be attributed to a specific signer
/// @dev Pure cryptographic operations only - no certificate format knowledge
interface IAttributableScheme {
    /// @notice Get the unique identifier for this signature scheme
    /// @return Scheme identifier string (e.g., "ED25519")
    function SCHEME_ID() external pure returns (string memory);

    /// @notice Get the hash function used by this scheme
    /// @return Hash function enum value
    function HASH_FUNCTION() external view returns (HashFunction);

    /// @notice Get the public key for a specific signer
    /// @param signerIndex The index of the signer in the validator set
    /// @return Public key bytes for the specified signer
    function getPublicKey(uint32 signerIndex) external view returns (bytes memory);

    /// @notice Get the total number of participants in the validator set
    /// @return Number of participants
    function participantCount() external view returns (uint32);

    /// @notice Hash the message and verify all signatures
    /// @dev Hashes message using HASH_FUNCTION, then verifies each signature
    /// @param message The message bytes to verify
    /// @param signers Array of signer indices (parallel to signatures)
    /// @param signatures Array of signature bytes (parallel to signers)
    /// @return true if all signatures are valid, false otherwise
    function hashAndVerify(
        bytes calldata message,
        uint32[] calldata signers,
        bytes[] calldata signatures
    ) external view returns (bool);
}

/// @title IAggregatedScheme
/// @notice Interface for signature schemes with aggregated signatures
/// @dev Used for schemes like BLS multisig where multiple signatures combine into one
/// @dev Pure cryptographic operations only - no certificate format knowledge
interface IAggregatedScheme {
    /// @notice Get the unique identifier for this signature scheme
    /// @return Scheme identifier string (e.g., "BLS12381_MULTISIG")
    function SCHEME_ID() external pure returns (string memory);

    /// @notice Get the hash function used by this scheme
    /// @return Hash function enum value
    function HASH_FUNCTION() external view returns (HashFunction);

    /// @notice Get the public key for a specific signer
    /// @param signerIndex The index of the signer in the validator set
    /// @return Public key bytes for the specified signer
    function getPublicKey(uint32 signerIndex) external view returns (bytes memory);

    /// @notice Get the total number of participants in the validator set
    /// @return Number of participants
    function participantCount() external view returns (uint32);

    /// @notice Hash the message and verify the aggregated signature
    /// @dev Aggregates public keys for signers in bitmap, then verifies
    /// @param message The message bytes to verify
    /// @param signersBitmap Bitmap of signers who contributed to signature
    /// @param signature Aggregated signature bytes
    /// @return true if the aggregated signature is valid, false otherwise
    function hashAndVerify(
        bytes calldata message,
        bytes calldata signersBitmap,
        bytes calldata signature
    ) external view returns (bool);
}

/// @title IThresholdScheme
/// @notice Interface for threshold signature schemes
/// @dev Used for schemes like BLS threshold where t-of-n partial signatures combine
/// @dev Pure cryptographic operations only - no certificate format knowledge
/// @dev Individual signatures cannot prove faults (threshold allows forgery)
interface IThresholdScheme {
    /// @notice Get the unique identifier for this signature scheme
    /// @return Scheme identifier string (e.g., "BLS12381_THRESHOLD")
    function SCHEME_ID() external pure returns (string memory);

    /// @notice Get the hash function used by this scheme
    /// @return Hash function enum value
    function HASH_FUNCTION() external view returns (HashFunction);

    /// @notice Get the threshold public key
    /// @dev Single key shared across all participants
    /// @return Threshold public key bytes
    function getThresholdPublicKey() external view returns (bytes memory);

    /// @notice Get the total number of participants
    /// @dev Even though there's one threshold key, we track participant count
    /// @return Number of participants
    function participantCount() external view returns (uint32);

    /// @notice Hash the message and verify the threshold signature
    /// @dev Verifies against the single threshold public key
    /// @param message The message bytes to verify
    /// @param signature Threshold signature bytes
    /// @return true if the threshold signature is valid, false otherwise
    function hashAndVerify(
        bytes calldata message,
        bytes calldata signature
    ) external view returns (bool);
}
