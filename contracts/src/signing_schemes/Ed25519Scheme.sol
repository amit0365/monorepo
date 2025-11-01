// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISignatureScheme} from "./interfaces/ISignatureScheme.sol";
import {Ed25519} from "../crypto/ed25519/Ed25519.sol";

/// @title Ed25519Scheme
/// @notice Ed25519 signature scheme implementation
/// @dev Implements ISignatureScheme for individual Ed25519 signatures
/// @dev Each certificate contains individual signatures that can prove faults
contract Ed25519Scheme is ISignatureScheme {
    // ============ Constants ============

    uint256 constant ED25519_PUBLIC_KEY_LENGTH = 32;
    uint256 constant ED25519_SIGNATURE_LENGTH = 64;

    // ============ Interface Implementation ============

    /// @inheritdoc ISignatureScheme
    function SCHEME_ID() external pure returns (string memory) {
        return "ED25519";
    }

    /// @inheritdoc ISignatureScheme
    function PUBLIC_KEY_LENGTH() external pure returns (uint256) {
        return ED25519_PUBLIC_KEY_LENGTH;
    }

    /// @inheritdoc ISignatureScheme
    function SIGNATURE_LENGTH() external pure returns (uint256) {
        return ED25519_SIGNATURE_LENGTH;
    }

    /// @inheritdoc ISignatureScheme
    /// @notice Verify Ed25519 signature
    /// @dev Uses local Ed25519 library from contracts/src/libraries/
    /// @dev IMPORTANT: Ed25519 standard uses SHA-512 internally: SHA-512(R || A || M)
    /// @dev The message M is passed as RAW bytes - Ed25519 handles hashing internally
    /// @param message The raw message bytes (NOT pre-hashed)
    /// @param publicKey The Ed25519 public key (32 bytes)
    /// @param signature The Ed25519 signature (64 bytes: R || S)
    /// @return true if signature is valid, false otherwise
    function verifySignature(
        bytes calldata message,
        bytes calldata publicKey,
        bytes calldata signature
    ) external pure returns (bool) {
        // Validate lengths
        if (publicKey.length != ED25519_PUBLIC_KEY_LENGTH) return false;
        if (signature.length != ED25519_SIGNATURE_LENGTH) return false;

        // Convert publicKey bytes to bytes32
        bytes32 pk = bytes32(publicKey[0:32]);

        // Split signature into R (32 bytes) and S (32 bytes)
        bytes32 r = bytes32(signature[0:32]);
        bytes32 s = bytes32(signature[32:64]);

        // Call local Ed25519 library
        // Ed25519.verify internally computes SHA-512(R || A || M) where M is the raw message
        return Ed25519.verify(pk, r, s, message);
    }
}
