// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAttributableScheme, BLS2, HashFunction} from "../interfaces/ISignatureScheme.sol";
import {CodecHelpers} from "../libraries/CodecHelpers.sol";

/// @title Ed25519Scheme
/// @notice Ed25519 signature scheme implementation
/// @dev Implements IAttributableScheme for individual Ed25519 signatures
/// @dev This scheme owns and manages the public keys for all validators
/// @dev Each certificate contains individual signatures that can prove faults
contract Ed25519Scheme is IAttributableScheme {
    // ============ Constants ============

    uint256 constant ED25519_PUBLIC_KEY_LENGTH = 32;
    uint256 constant ED25519_SIGNATURE_LENGTH = 64;

    // ============ Errors ============

    error InvalidSignerIndex();
    error LengthMismatch();
    error EmptyPublicKeys();
    error UnknownHashFunction();

    // ============ State ============

    /// @notice Public keys for all validators (scheme owns the keys!)
    bytes32[] public publicKeys;

    /// @notice Hash function used by this scheme instance
    HashFunction public immutable hashFunction;

    // ============ Constructor ============

    /// @notice Initialize the Ed25519 scheme with public keys and hash function
    /// @param _publicKeys Array of 32-byte Ed25519 public keys
    /// @param _hashFunction Hash function to use for message hashing
    constructor(bytes32[] memory _publicKeys, HashFunction _hashFunction) {
        if (_publicKeys.length == 0) revert EmptyPublicKeys();
        publicKeys = _publicKeys;
        hashFunction = _hashFunction;
    }

    // ============ Interface Implementation ============

    /// @inheritdoc IAttributableScheme
    function SCHEME_ID() external pure returns (string memory) {
        return "ED25519";
    }

    /// @inheritdoc IAttributableScheme
    function HASH_FUNCTION() external view returns (HashFunction) {
        return hashFunction;
    }

    /// @inheritdoc IAttributableScheme
    function getPublicKey(uint32 signerIndex) external view returns (bytes memory) {
        if (signerIndex >= publicKeys.length) revert InvalidSignerIndex();
        return abi.encodePacked(publicKeys[signerIndex]);
    }

    /// @inheritdoc IAttributableScheme
    function participantCount() external view returns (uint32) {
        return uint32(publicKeys.length);
    }

    /// @inheritdoc IAttributableScheme
    function hashAndVerify(
        bytes calldata message,
        uint32[] calldata signers,
        bytes[] calldata signatures
    ) external view returns (bool) {
        if (signers.length != signatures.length) revert LengthMismatch();

        // Hash the message
        bytes32 messageHash = _hash(message);

        // Verify each signature against corresponding public key
        for (uint256 i = 0; i < signers.length; i++) {
            uint32 signerIndex = signers[i];
            if (signerIndex >= publicKeys.length) revert InvalidSignerIndex();

            if (!_verifyEd25519(messageHash, publicKeys[signerIndex], signatures[i])) {
                return false;
            }
        }

        return true;
    }

    // ============ Internal Helpers ============

    /// @notice Hash data using the configured hash function
    /// @param data Data to hash
    /// @return Hash digest (32 bytes)
    function _hash(bytes memory data) internal view returns (bytes32) {
        if (hashFunction == HashFunction.SHA256) {
            return sha256(data);
        } else if (hashFunction == HashFunction.KECCAK256) {
            return keccak256(data);
        } else if (hashFunction == HashFunction.BLAKE2B) {
            return _blake2b(data);
        }
        revert UnknownHashFunction();
    }

    /// @notice Placeholder for BLAKE2B hashing
    /// @dev To be implemented with precompile or library
    function _blake2b(bytes memory data) internal pure returns (bytes32) {
        // TODO: Implement BLAKE2B using precompile at address 0x09
        // For now, revert as not implemented
        revert("BLAKE2B not implemented");
    }

    /// @notice Verify Ed25519 signature
    /// @dev To be implemented with precompile or library
    /// @param messageHash The hash of the message (32 bytes)
    /// @param publicKey The Ed25519 public key (32 bytes)
    /// @param signature The Ed25519 signature (64 bytes)
    /// @return true if signature is valid, false otherwise
    function _verifyEd25519(
        bytes32 messageHash,
        bytes32 publicKey,
        bytes memory signature
    ) internal pure returns (bool) {
        if (signature.length != ED25519_SIGNATURE_LENGTH) return false;

        // TODO: Implement Ed25519 verification using precompile or library
        // Placeholder: always return true for now (NOT FOR PRODUCTION!)
        return true;
    }

}
