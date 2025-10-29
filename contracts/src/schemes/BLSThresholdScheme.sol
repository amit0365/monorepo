// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../interfaces/ISignatureScheme.sol";
import "../libraries/BLS2.sol";

/// @title BLSThresholdScheme
/// @notice BLS12-381 threshold signature scheme implementation
/// @dev Implements IThresholdScheme for threshold BLS signatures
/// @dev This scheme uses a single threshold public key shared by all participants
/// @dev Certificates contain only the recovered aggregate signature (no signer info)
/// @dev WARNING: Individual signatures are NOT attributable (threshold allows forgery)
/// @dev Uses MinPk variant: Threshold key in G2 (96 bytes), Signatures in G1 (48 bytes)
contract BLSThresholdScheme is IThresholdScheme {
    // ============ Constants ============

    uint256 constant BLS_SIGNATURE_LENGTH = 48; // G1 for MinPk variant

    // ============ Errors ============

    error InvalidProofLength();
    error EmptyParticipants();
    error UnknownHashFunction();

    // ============ State ============

    /// @notice Single threshold public key (G2 point, 96 bytes)
    /// @dev All participants share this key via distributed key generation
    BLS2.PointG2 public thresholdPublicKey;

    /// @notice Total number of participants in the threshold setup
    uint32 public immutable n;

    /// @notice Hash function used by this scheme instance
    HashFunction public immutable hashFunction;

    /// @notice Domain separation tag for hash-to-curve
    /// @dev Format: {application}-BLS12381G1_XMD:SHA-256_SSWU_RO_{chainid}_
    bytes public DST;

    // ============ Constructor ============

    /// @notice Initialize the BLS threshold scheme
    /// @param thresholdKeyBytes Serialized BLS G2 threshold public key (96 bytes)
    /// @param _n Total number of participants
    /// @param _hashFunction Hash function to use for message hashing
    /// @param application Application name for domain separation tag
    constructor(
        bytes memory thresholdKeyBytes,
        uint32 _n,
        HashFunction _hashFunction,
        string memory application
    ) {
        if (_n == 0) revert EmptyParticipants();

        thresholdPublicKey = BLS2.g2Unmarshal(thresholdKeyBytes);
        n = _n;
        hashFunction = _hashFunction;

        // Build domain separation tag
        DST = abi.encodePacked(
            application,
            "-BLS12381G1_XMD:SHA-256_SSWU_RO_",
            _bytes32ToHex(bytes32(block.chainid)),
            "_"
        );
    }

    // ============ Interface Implementation ============

    /// @inheritdoc IThresholdScheme
    function SCHEME_ID() external pure returns (string memory) {
        return "BLS12381_THRESHOLD";
    }

    /// @inheritdoc IThresholdScheme
    function HASH_FUNCTION() external view returns (HashFunction) {
        return hashFunction;
    }

    /// @inheritdoc IThresholdScheme
    function getThresholdPublicKey() external view returns (bytes memory) {
        return BLS2.g2Marshal(thresholdPublicKey);
    }

    /// @inheritdoc IThresholdScheme
    function participantCount() external view returns (uint32) {
        return n;
    }

    /// @inheritdoc IThresholdScheme
    function deserializeCertificate(
        bytes calldata proof,
        uint256 offset
    ) external pure returns (
        bytes memory signature,
        uint256 newOffset
    ) {
        // Read threshold signature (48 bytes for MinPk)
        if (offset + BLS_SIGNATURE_LENGTH > proof.length) revert InvalidProofLength();
        signature = proof[offset:offset + BLS_SIGNATURE_LENGTH];
        return (signature, offset + BLS_SIGNATURE_LENGTH);
    }

    /// @inheritdoc IThresholdScheme
    function hashAndVerify(
        bytes calldata message,
        bytes calldata signature
    ) external view returns (bool) {
        // Hash the message
        bytes32 messageHash = _hash(message);

        // Hash to BLS point on G1
        BLS2.PointG1 memory messagePoint = BLS2.hashToG1(messageHash, DST);

        // Verify threshold signature against threshold public key
        BLS2.PointG1 memory sig = BLS2.g1Unmarshal(signature);
        return BLS2.pairing(messagePoint, thresholdPublicKey, sig);
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
        revert("BLAKE2B not implemented");
    }

    /// @notice Convert bytes32 to hex string
    /// @param data Bytes to convert
    /// @return Hex string representation
    function _bytes32ToHex(bytes32 data) internal pure returns (string memory) {
        bytes memory hexChars = "0123456789abcdef";
        bytes memory result = new bytes(64);

        for (uint256 i = 0; i < 32; i++) {
            result[i * 2] = hexChars[uint8(data[i] >> 4)];
            result[i * 2 + 1] = hexChars[uint8(data[i] & 0x0f)];
        }

        return string(result);
    }
}
