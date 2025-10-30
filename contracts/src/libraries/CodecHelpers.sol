// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title CodecHelpers
/// @notice Shared encoding/decoding utilities for Simplex verification and signature schemes
/// @dev Provides varint decoding and bitmap operations used across multiple contracts
library CodecHelpers {
    // ============ Constants ============

    // Varint decoding constants (LEB128 format)
    uint8 internal constant DATA_BITS_MASK = 0x7F;        // 0111_1111 - Extract 7 data bits
    uint8 internal constant CONTINUATION_BIT_MASK = 0x80; // 1000_0000 - Check continuation bit
    uint256 internal constant DATA_BITS_PER_BYTE = 7;     // Number of data bits per byte
    uint256 internal constant MAX_U64_BITS = 64;          // Maximum bits in u64
    uint256 internal constant U64_LAST_BYTE_SHIFT = 63;   // Shift value for 10th byte (9*7=63)

    // ============ Errors ============

    error InvalidVarint();
    error InvalidProofLength();
    error InvalidBitmapTrailingBits();
    error TooManySigners();

    // ============ Varint Encoding ============

    /// @notice Encode a u64 value as varint (LEB128 format)
    /// @dev Implements canonical LEB128 encoding matching Rust implementation
    /// @dev Used for encoding parent view in proposals
    /// @param value The u64 value to encode
    /// @return Encoded varint bytes
    function encodeVarintU64(uint64 value) internal pure returns (bytes memory) {
        // Special case: value 0 encodes as single byte 0x00
        if (value == 0) {
            return hex"00";
        }

        // Calculate maximum bytes needed (10 bytes for u64)
        bytes memory result = new bytes(10);
        uint256 length = 0;

        while (value > 0) {
            // Extract 7 data bits
            uint8 dataBits = uint8(value & DATA_BITS_MASK);

            // Shift value right by 7 bits for next iteration
            value >>= DATA_BITS_PER_BYTE;

            // Set continuation bit if more bytes follow
            if (value > 0) {
                dataBits |= CONTINUATION_BIT_MASK;
            }

            result[length] = bytes1(dataBits);
            length++;
        }

        // Resize to actual length
        assembly {
            mstore(result, length)
        }

        return result;
    }

    // ============ Varint Decoding ============

    /// @notice Decode a varint-encoded u64 (LEB128 format)
    /// @dev Implements strict canonical encoding validation matching Rust implementation
    /// @dev Used for: parent view, epoch, view counter, signature counts
    /// @param data Calldata containing varint
    /// @param offset Starting position
    /// @return value Decoded u64 value
    /// @return newOffset Updated offset after reading the varint
    function decodeVarintU64(bytes calldata data, uint256 offset)
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

            // [STRICT] Check for non-canonical encoding (zero byte after first)
            // Prevents encodings like [0x80, 0x00] for value 0
            // A zero byte means no data bits and no continuation, which is redundant
            // This ensures every value has exactly one unique, valid encoding
            if (bytesRead > 1 && b == 0) {
                revert InvalidVarint();
            }

            // Extract 7 data bits using mask
            uint8 dataBits = b & DATA_BITS_MASK;

            // [STRICT] Check for overflow on the last possible byte
            // For u64, after 9 bytes (63 bits), only 1 bit remains
            // The 10th byte must be at most 0x01
            if (shift == U64_LAST_BYTE_SHIFT) {
                if (b > 1) revert InvalidVarint();
            }

            value |= uint64((uint256(dataBits) << shift));

            // Check continuation bit to see if more bytes follow
            if ((b & CONTINUATION_BIT_MASK) == 0) {
                break;
            }

            shift += DATA_BITS_PER_BYTE;
            if (shift >= MAX_U64_BITS) revert InvalidVarint();
        }

        return (value, currentOffset);
    }

    /// @notice Decode a varint as u32 by validating a u64 varint fits in 32 bits
    /// @dev Decodes using decodeVarintU64 then validates upper 32 bits are zero
    /// @dev This enforces strict canonical encoding: values > u32::MAX must fail
    /// @param data The calldata containing the varint-encoded value
    /// @param offset The starting position in data
    /// @return value The decoded u32 value
    /// @return newOffset The position after the decoded varint
    function decodeVarintU32(bytes calldata data, uint256 offset)
        internal pure returns (uint32 value, uint256 newOffset)
    {
        // Decode as u64 first
        uint64 val64;
        (val64, newOffset) = decodeVarintU64(data, offset);

        // [STRICT] Validate that highest 32 bits are zero
        // This ensures the value fits in u32 range [0, 2^32-1]
        if (val64 & 0xFFFFFFFF00000000 != 0) {
            revert InvalidVarint();
        }

        // Safe to cast since we verified upper bits are zero
        value = uint32(val64);
    }

    // ============ Bitmap Operations ============

    /// @notice Get bit value from bitmap
    /// @dev Matches Rust BitMap implementation (utils/src/bitmap/mod.rs)
    /// @dev Bits are stored with lowest order bits first within each byte
    /// @param bitmap Bitmap bytes
    /// @param bitIndex Index of bit to retrieve
    /// @return true if bit is set, false otherwise
    function getBit(bytes memory bitmap, uint256 bitIndex) internal pure returns (bool) {
        uint256 byteIndex = bitIndex >> 3; // divide by 8
        uint256 bitInByte = bitIndex & 7;  // modulo 8

        if (byteIndex >= bitmap.length) return false;

        uint8 byteValue = uint8(bitmap[byteIndex]);
        uint8 mask = uint8(1 << bitInByte);
        return (byteValue & mask) != 0;
    }

    /// @notice Deserialize signers bitmap from proof data
    /// @dev Encoding format:
    ///      - bitmap_length: u64 (8 bytes big-endian)
    ///      - bitmap_bytes: (bitmap_length + 7) / 8 bytes
    /// @dev Validates trailing bits in the last byte are zero
    /// @param proof The encoded proof bytes
    /// @param offset The starting offset in the proof
    /// @param maxParticipants Maximum allowed participants (for DoS protection)
    /// @return bitmapLengthInBits The number of bits in the bitmap
    /// @return signersBitmap The bitmap bytes
    /// @return newOffset Updated offset after reading the bitmap
    function deserializeSignersBitmap(
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

        // Bound the bitmap length by the maximum participants
        if (bitmapLengthInBits > maxParticipants) revert TooManySigners();

        // Calculate number of bytes needed for bitmap
        uint256 numBitmapBytes = (bitmapLengthInBits + 7) >> 3; // divide by 8, round up

        // Read bitmap bytes
        if (offset + numBitmapBytes > proof.length) revert InvalidProofLength();
        signersBitmap = proof[offset:offset + numBitmapBytes];
        offset += numBitmapBytes;

        // Validate trailing bits are zero in the last byte
        // This ensures canonical encoding - extra bits must not be set
        uint256 fullBytes = bitmapLengthInBits >> 3;
        uint256 remainder = bitmapLengthInBits & 7;
        if (remainder != 0 && numBitmapBytes > 0) {
            uint8 lastByte = uint8(signersBitmap[fullBytes]);
            // Allowed lower bits mask: (1 << remainder) - 1
            uint8 allowedLower = uint8((1 << remainder) - 1);
            // Upper bits (beyond bitmap length) must be zero
            if ((lastByte & ~allowedLower) != 0) revert InvalidBitmapTrailingBits();
        }

        return (bitmapLengthInBits, signersBitmap, offset);
    }
}
