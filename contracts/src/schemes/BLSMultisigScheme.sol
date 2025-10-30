// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAggregatedScheme, BLS2, HashFunction} from "../interfaces/ISignatureScheme.sol";
import {CodecHelpers} from "../libraries/CodecHelpers.sol";

/// @title BLSMultisigScheme
/// @notice BLS12-381 multisig scheme implementation (aggregated signatures)
/// @dev Implements IAggregatedScheme for BLS signature aggregation
/// @dev This scheme owns and manages BLS public keys for all validators
/// @dev Certificates contain single aggregated signature + bitmap of signers
/// @dev Uses MinPk variant: Public keys in G2 (96 bytes), Signatures in G1 (48 bytes)
contract BLSMultisigScheme is IAggregatedScheme {
    // ============ Constants ============

    uint256 constant BLS_SIGNATURE_LENGTH = 48; // G1 for MinPk variant

    // ============ Errors ============

    error InvalidSignerIndex();
    error EmptyPublicKeys();
    error UnknownHashFunction();
    error NoSignersInBitmap();

    // ============ State ============

    /// @notice BLS public keys for all validators (G2 points, 96 bytes each)
    BLS2.PointG2[] public publicKeys;

    /// @notice Hash function used by this scheme instance
    HashFunction public immutable hashFunction;

    /// @notice Domain separation tag for hash-to-curve
    /// @dev Format: {application}-BLS12381G1_XMD:SHA-256_SSWU_RO_{chainid}_
    bytes public DST;

    // ============ Constructor ============

    /// @notice Initialize the BLS multisig scheme
    /// @param publicKeyBytes Array of serialized BLS G2 public keys (96 bytes each)
    /// @param _hashFunction Hash function to use for message hashing
    /// @param application Application name for domain separation tag
    constructor(
        bytes[] memory publicKeyBytes,
        HashFunction _hashFunction,
        string memory application
    ) {
        if (publicKeyBytes.length == 0) revert EmptyPublicKeys();

        publicKeys = new BLS2.PointG2[](publicKeyBytes.length);
        for (uint256 i = 0; i < publicKeyBytes.length; i++) {
            publicKeys[i] = BLS2.g2Unmarshal(publicKeyBytes[i]);
        }

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

    /// @inheritdoc IAggregatedScheme
    function SCHEME_ID() external pure returns (string memory) {
        return "BLS12381_MULTISIG";
    }

    /// @inheritdoc IAggregatedScheme
    function HASH_FUNCTION() external view returns (HashFunction) {
        return hashFunction;
    }

    /// @inheritdoc IAggregatedScheme
    function getPublicKey(uint32 signerIndex) external view returns (bytes memory) {
        if (signerIndex >= publicKeys.length) revert InvalidSignerIndex();
        return BLS2.g2Marshal(publicKeys[signerIndex]);
    }

    /// @inheritdoc IAggregatedScheme
    function participantCount() external view returns (uint32) {
        return uint32(publicKeys.length);
    }

    /// @inheritdoc IAggregatedScheme
    function hashAndVerify(
        bytes calldata message,
        bytes calldata signersBitmap,
        bytes calldata signature
    ) external view returns (bool) {
        // Hash message to BLS point on G1 using hash-to-curve
        // Note: BLS2.hashToPoint takes raw message bytes, not pre-hashed
        BLS2.PointG1 memory messagePoint = BLS2.hashToPoint(DST, message);

        // Aggregate public keys for signers in bitmap
        BLS2.PointG2 memory aggregatedPubKey = _aggregatePublicKeys(signersBitmap);

        // Verify aggregated signature using pairing
        BLS2.PointG1 memory sig = BLS2.g1Unmarshal(signature);
        return BLS2.pairing(messagePoint, aggregatedPubKey, sig);
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
        }
        revert UnknownHashFunction();
    }

    /// @notice Aggregate public keys for signers indicated in bitmap
    /// @param bitmap Bitmap of signers
    /// @return result Aggregated G2 public key
    function _aggregatePublicKeys(bytes memory bitmap)
        internal view returns (BLS2.PointG2 memory result)
    {
        bool first = true;

        for (uint32 i = 0; i < publicKeys.length; i++) {
            if (CodecHelpers.getBit(bitmap, i)) {
                if (first) {
                    result = publicKeys[i];
                    first = false;
                } else {
                    result = BLS2.g2Add(result, publicKeys[i]);
                }
            }
        }

        if (first) revert NoSignersInBitmap();
        return result;
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
