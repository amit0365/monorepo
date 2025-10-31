// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISignatureScheme} from "../interfaces/ISignatureScheme.sol";
import {BLS2} from "../libraries/BLS2Extensions.sol";
import {CodecHelpers} from "../libraries/CodecHelpers.sol";

/// @title BLSMultisigScheme
/// @notice BLS12-381 multisig scheme implementation (aggregated signatures)
/// @dev Implements ISignatureScheme for BLS signature aggregation
/// @dev This scheme manages BLS public keys for all validators
/// @dev Signature format: bitmap (variable length) || aggregated_signature (48 bytes)
/// @dev publicKey parameter contains all validator public keys concatenated
/// @dev Uses MinPk variant: Public keys in G2 (96 bytes), Signatures in G1 (48 bytes)
contract BLSMultisigScheme is ISignatureScheme {
    // ============ Constants ============

    uint256 constant BLS_PUBLIC_KEY_LENGTH = 96; // G2 for MinPk variant
    uint256 constant BLS_SIGNATURE_LENGTH = 48; // G1 for MinPk variant

    // ============ Errors ============

    error NoSignersInBitmap();

    // ============ State ============

    /// @notice Domain separation tag for hash-to-curve
    /// @dev Format: {application}-BLS12381G1_XMD:SHA-256_SSWU_RO_{chainid}_
    bytes public immutable DST;

    // ============ Constructor ============

    /// @notice Initialize the BLS multisig scheme
    /// @param application Application name for domain separation tag
    constructor(string memory application) {
        // Build domain separation tag
        string memory hashSpec = "-BLS12381G1_XMD:SHA-256_SSWU_RO_";

        DST = abi.encodePacked(
            application,
            hashSpec,
            _bytes32ToHex(bytes32(block.chainid)),
            "_"
        );
    }

    // ============ Interface Implementation ============

    /// @inheritdoc ISignatureScheme
    function SCHEME_ID() external pure returns (string memory) {
        return "BLS12381_MULTISIG";
    }

    /// @inheritdoc ISignatureScheme
    /// @notice For multisig, this returns the length of a single public key
    /// @dev The publicKey parameter in verifySignature contains N concatenated keys
    function PUBLIC_KEY_LENGTH() external pure returns (uint256) {
        return BLS_PUBLIC_KEY_LENGTH;
    }

    /// @inheritdoc ISignatureScheme
    /// @notice For multisig, this returns the base signature length (not including bitmap)
    /// @dev The actual signature includes: bitmap || 48-byte aggregated signature
    function SIGNATURE_LENGTH() external pure returns (uint256) {
        return BLS_SIGNATURE_LENGTH;
    }

    /// @inheritdoc ISignatureScheme
    /// @notice Verify aggregated BLS multisig signature
    /// @dev publicKey contains N concatenated 96-byte G2 public keys (total: N * 96 bytes)
    /// @dev signature format: bitmap (ceil(N/8) bytes) || aggregated_sig (48 bytes)
    /// @param message The raw message bytes that was signed
    /// @param publicKey Concatenated public keys of all N validators (N * 96 bytes)
    /// @param signature Bitmap concatenated with aggregated signature
    /// @return true if signature is valid, false otherwise
    function verifySignature(
        bytes calldata message,
        bytes calldata publicKey,
        bytes calldata signature
    ) external view returns (bool) {
        // Validate publicKey is a multiple of BLS_PUBLIC_KEY_LENGTH
        if (publicKey.length % BLS_PUBLIC_KEY_LENGTH != 0) return false;
        if (publicKey.length == 0) return false;

        uint256 numValidators = publicKey.length / BLS_PUBLIC_KEY_LENGTH;
        uint256 bitmapLength = (numValidators + 7) / 8; // ceil(N/8)

        // Validate signature format: bitmap || 48-byte sig
        if (signature.length != bitmapLength + BLS_SIGNATURE_LENGTH) return false;

        // Extract bitmap and aggregated signature
        bytes calldata bitmap = signature[0:bitmapLength];
        bytes calldata aggSig = signature[bitmapLength:signature.length];

        // Hash message to BLS point on G1
        BLS2.PointG1 memory messagePoint = BLS2.hashToPoint(DST, message);

        // Aggregate public keys for signers in bitmap
        BLS2.PointG2 memory aggregatedPubKey = _aggregatePublicKeysFromBytes(publicKey, bitmap, numValidators);

        // Verify aggregated signature using pairing
        BLS2.PointG1 memory sig = BLS2.g1Unmarshal(aggSig);
        return BLS2.pairing(messagePoint, aggregatedPubKey, sig);
    }

    // ============ Internal Helpers ============
    /// TODO refactor this into simplex
    /// @notice Aggregate public keys from concatenated bytes based on bitmap
    /// @param publicKeyBytes Concatenated public keys (N * 96 bytes)
    /// @param bitmap Bitmap indicating which keys to aggregate
    /// @param numValidators Number of validators (N)
    /// @return result Aggregated G2 public key
    function _aggregatePublicKeysFromBytes(
        bytes calldata publicKeyBytes,
        bytes calldata bitmap,
        uint256 numValidators
    ) internal view returns (BLS2.PointG2 memory result) {
        bool first = true;

        for (uint32 i = 0; i < numValidators; i++) {
            if (CodecHelpers.getBit(bitmap, i)) {
                // Extract the i-th public key (96 bytes)
                uint256 offset = i * BLS_PUBLIC_KEY_LENGTH;
                bytes calldata pkBytes = publicKeyBytes[offset:offset + BLS_PUBLIC_KEY_LENGTH];
                BLS2.PointG2 memory pk = BLS2.g2Unmarshal(pkBytes);

                if (first) {
                    result = pk;
                    first = false;
                } else {
                    result = BLS2.g2Add(result, pk);
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
