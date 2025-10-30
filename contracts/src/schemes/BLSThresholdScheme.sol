// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IThresholdScheme, BLS2, HashFunction} from "../interfaces/ISignatureScheme.sol";

/// @title BLSThresholdScheme
/// @notice BLS12-381 threshold signature scheme implementation
/// @dev Implements IThresholdScheme for threshold BLS signatures
/// @dev This scheme uses a single threshold public key shared by all participants
/// @dev Certificates contain only the recovered aggregate signature (no signer info)
/// @dev WARNING: Individual signatures are NOT attributable (threshold allows forgery)
/// @dev Uses MinSig variant: Threshold key in G2 (96 bytes), Signatures in G1 (48 bytes)
contract BLSThresholdScheme is IThresholdScheme {
    // ============ Constants ============

    uint256 constant BLS_SIGNATURE_LENGTH = 48; // G1 for MinSig variant

    // ============ Errors ============

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

        // Build domain separation tag based on hash function
        string memory hashSpec;
        if (_hashFunction == HashFunction.SHA256) {
            hashSpec = "-BLS12381G1_XMD:SHA-256_SSWU_RO_";
        } else if (_hashFunction == HashFunction.KECCAK256) {
            hashSpec = "-BLS12381G1_XMD:KECCAK-256_SSWU_RO_";
        } else {
            revert UnknownHashFunction();
        }

        DST = abi.encodePacked(
            application,
            hashSpec,
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
    function hashAndVerify(
        bytes calldata message,
        bytes calldata signature
    ) external view returns (bool) {
        // Hash to BLS point on G1 using BLS2.hashToPoint
        // Note: BLS2.hashToPoint internally uses the hash function from DST
        BLS2.PointG1 memory messagePoint = BLS2.hashToPoint(DST, message);

        // Verify threshold signature against threshold public key
        BLS2.PointG1 memory sig = BLS2.g1Unmarshal(signature);
        (bool pairingSuccess, bool callSuccess) = BLS2.verifySingle(sig, thresholdPublicKey, messagePoint);
        return pairingSuccess && callSuccess;
    }

    // ============ Internal Helpers ============

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
