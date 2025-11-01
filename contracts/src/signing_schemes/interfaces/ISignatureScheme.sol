// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ISignatureScheme
/// @notice Interface for signature schemes used with Simplex verifiers
/// @dev Pure cryptographic operations only - no certificate format knowledge
/// @dev Used for schemes like Ed25519, BLS where signatures can be attributed to specific signers
/// @dev Supports variable-length public keys (32 bytes for Ed25519, 48+ bytes for BLS)
interface ISignatureScheme {
    /// @notice Get the unique identifier for this signature scheme
    /// @return Scheme identifier string (e.g., "ED25519", "BLS12381")
    function schemeId() external pure returns (string memory);

    /// @notice Get the length of public keys for this scheme
    /// @return Length in bytes (32 for Ed25519, 48 for BLS G1, 96 for BLS G2)
    function publicKeyLength() external pure returns (uint256);

    /// @notice Get the length of signatures for this scheme
    /// @return Length in bytes (64 for Ed25519, 48 for BLS G1, 96 for BLS G2)
    function signatureLength() external pure returns (uint256);

    /// @notice Verify a signature
    /// @dev The message is the full signed message (NOT pre-hashed) in union_unique format
    /// @param message The message that was signed (raw bytes)
    /// @param publicKey The signer's public key (variable length: 32 bytes for Ed25519, 48+ for BLS)
    /// @param signature The signature bytes to verify
    /// @return true if the signature is valid, false otherwise
    function verifySignature(
        bytes calldata message,
        bytes calldata publicKey,
        bytes calldata signature
    ) external view returns (bool);
}
