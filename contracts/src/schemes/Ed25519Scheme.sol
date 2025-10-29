// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../interfaces/ISignatureScheme.sol";

/// @title Ed25519Scheme
/// @notice Ed25519 signature scheme implementation
/// @dev Implements IAttributableScheme for individual Ed25519 signatures
/// @dev This scheme owns and manages the public keys for all validators
/// @dev Each certificate contains individual signatures that can prove faults
contract Ed25519Scheme is IAttributableScheme {
    // ============ Constants ============

    uint256 constant ED25519_PUBLIC_KEY_LENGTH = 32;
    uint256 constant ED25519_SIGNATURE_LENGTH = 64;

    // Varint decoding constants (LEB128 format)
    uint8 internal constant DATA_BITS_MASK = 0x7F;
    uint8 internal constant CONTINUATION_BIT_MASK = 0x80;
    uint256 internal constant DATA_BITS_PER_BYTE = 7;
    uint256 internal constant MAX_U64_BITS = 64;
    uint256 internal constant U64_LAST_BYTE_SHIFT = 63;

    // ============ Errors ============

    error InvalidProofLength();
    error InvalidVarint();
    error InvalidSignerIndex();
    error TooManySigners();
    error InvalidBitmapTrailingBits();
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
    function deserializeCertificate(
        bytes calldata proof,
        uint256 offset,
        uint32 maxSigners
    ) external pure returns (
        uint32[] memory signers,
        bytes[] memory signatures,
        uint256 newOffset
    ) {
        // Read bitmap
        uint64 bitmapLengthInBits;
        bytes memory signersBitmap;
        (bitmapLengthInBits, signersBitmap, offset) =
            _deserializeSignersBitmap(proof, offset, maxSigners);

        // Read signatures
        (signers, signatures, offset) =
            _deserializeSignatures(proof, offset, signersBitmap, maxSigners);

        return (signers, signatures, offset);
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

    /// @notice Deserialize signers bitmap from proof data
    /// @dev Format: u64 length (8 bytes big-endian) + bitmap bytes
    /// @param proof The encoded proof bytes
    /// @param offset Starting position in proof
    /// @param maxParticipants Maximum allowed participants
    /// @return bitmapLengthInBits Number of bits in bitmap
    /// @return signersBitmap Bitmap bytes
    /// @return newOffset Updated offset
    function _deserializeSignersBitmap(
        bytes calldata proof,
        uint256 offset,
        uint32 maxParticipants
    ) internal pure returns (
        uint64 bitmapLengthInBits,
        bytes memory signersBitmap,
        uint256 newOffset
    ) {
        // Read bitmap length (8 bytes big-endian u64)
        if (offset + 8 > proof.length) revert InvalidProofLength();
        bitmapLengthInBits = uint64(bytes8(proof[offset:offset+8]));
        offset += 8;

        // Bound the bitmap length
        if (bitmapLengthInBits > maxParticipants) revert TooManySigners();

        // Calculate number of bytes needed
        uint256 numBitmapBytes = (bitmapLengthInBits + 7) >> 3;

        // Read bitmap bytes
        if (offset + numBitmapBytes > proof.length) revert InvalidProofLength();
        signersBitmap = proof[offset:offset + numBitmapBytes];
        offset += numBitmapBytes;

        // Validate trailing bits are zero
        uint256 fullBytes = bitmapLengthInBits >> 3;
        uint256 remainder = bitmapLengthInBits & 7;
        if (remainder != 0 && numBitmapBytes > 0) {
            uint8 lastByte = uint8(signersBitmap[fullBytes]);
            uint8 allowedLower = uint8((1 << remainder) - 1);
            if ((lastByte & ~allowedLower) != 0) revert InvalidBitmapTrailingBits();
        }

        return (bitmapLengthInBits, signersBitmap, offset);
    }

    /// @notice Deserialize signatures from proof data
    /// @dev Format: varint count + signature bytes
    /// @param proof The encoded proof bytes
    /// @param offset Starting position in proof
    /// @param signersBitmap Bitmap of signers
    /// @param maxSigners Maximum allowed signers
    /// @return signers Array of signer indices
    /// @return signatures Array of signature bytes
    /// @return newOffset Updated offset
    function _deserializeSignatures(
        bytes calldata proof,
        uint256 offset,
        bytes memory signersBitmap,
        uint32 maxSigners
    ) internal pure returns (
        uint32[] memory signers,
        bytes[] memory signatures,
        uint256 newOffset
    ) {
        // Read signature count
        uint32 signatureCount;
        (signatureCount, offset) = _decodeVarintU32(proof, offset);

        if (signatureCount > maxSigners) revert TooManySigners();

        // Extract signer indices from bitmap
        signers = new uint32[](signatureCount);
        signatures = new bytes[](signatureCount);

        uint256 signerIdx = 0;
        for (uint32 i = 0; i < signersBitmap.length * 8 && signerIdx < signatureCount; i++) {
            if (_getBit(signersBitmap, i)) {
                signers[signerIdx] = i;
                signerIdx++;
            }
        }

        // Read signatures
        for (uint32 i = 0; i < signatureCount; i++) {
            if (offset + ED25519_SIGNATURE_LENGTH > proof.length) revert InvalidProofLength();
            signatures[i] = proof[offset:offset + ED25519_SIGNATURE_LENGTH];
            offset += ED25519_SIGNATURE_LENGTH;
        }

        return (signers, signatures, offset);
    }

    /// @notice Get bit value from bitmap
    /// @param bitmap Bitmap bytes
    /// @param bitIndex Index of bit to retrieve
    /// @return true if bit is set
    function _getBit(bytes memory bitmap, uint256 bitIndex) internal pure returns (bool) {
        uint256 byteIndex = bitIndex >> 3;
        uint256 bitInByte = bitIndex & 7;
        if (byteIndex >= bitmap.length) return false;
        uint8 byteValue = uint8(bitmap[byteIndex]);
        uint8 mask = uint8(1 << bitInByte);
        return (byteValue & mask) != 0;
    }

    /// @notice Decode varint as u32
    /// @param data Calldata containing varint
    /// @param offset Starting position
    /// @return value Decoded u32 value
    /// @return newOffset Updated offset
    function _decodeVarintU32(bytes calldata data, uint256 offset)
        internal pure returns (uint32 value, uint256 newOffset)
    {
        uint64 val64;
        (val64, newOffset) = _decodeVarintU64(data, offset);

        if (val64 & 0xFFFFFFFF00000000 != 0) {
            revert InvalidVarint();
        }

        value = uint32(val64);
    }

    /// @notice Decode varint-encoded u64 (LEB128 format)
    /// @param data Calldata containing varint
    /// @param offset Starting position
    /// @return value Decoded u64 value
    /// @return newOffset Updated offset
    function _decodeVarintU64(bytes calldata data, uint256 offset)
        internal pure returns (uint64 value, uint256 newOffset)
    {
        uint256 shift = 0;
        uint256 currentOffset = offset;
        uint256 bytesRead = 0;

        while (true) {
            if (currentOffset >= data.length) revert InvalidVarint();

            uint8 b = uint8(data[currentOffset]);
            currentOffset++;
            bytesRead++;

            // Check for non-canonical encoding
            if (bytesRead > 1 && b == 0) {
                revert InvalidVarint();
            }

            // Extract 7 data bits
            uint8 dataBits = b & DATA_BITS_MASK;

            // Check for overflow on last byte
            if (shift == U64_LAST_BYTE_SHIFT) {
                if (b > 1) revert InvalidVarint();
            }

            value |= uint64((uint256(dataBits) << shift));

            // Check continuation bit
            if ((b & CONTINUATION_BIT_MASK) == 0) {
                break;
            }

            shift += DATA_BITS_PER_BYTE;
            if (shift >= MAX_U64_BITS) revert InvalidVarint();
        }

        return (value, currentOffset);
    }
}
