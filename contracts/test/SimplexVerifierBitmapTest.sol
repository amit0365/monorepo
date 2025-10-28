// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/SimplexVerifierEd25519.sol";

/// @title TestableSimplexVerifier
/// @notice Test wrapper that exposes internal functions for testing
contract TestableSimplexVerifier is SimplexVerifierEd25519 {
    /// @notice Expose getBit for testing
    function getBit_exposed(bytes memory bitmap, uint256 bitIndex) public pure returns (bool) {
        return getBit(bitmap, bitIndex);
    }
}

/// @title SimplexVerifierBitmapTest
/// @notice Comprehensive tests for bitmap and signature deserialization helpers
/// @dev Tests getBit, deserializeSignersBitmap, and deserializeSignatures functions
contract SimplexVerifierBitmapTest is Test {
    TestableSimplexVerifier verifier;

    function setUp() public {
        verifier = new TestableSimplexVerifier();
    }

    // ============ Helper Functions ============

    /// @notice Encode a varint u64
    function encodeVarintU64(uint64 value) internal pure returns (bytes memory) {
        bytes memory result = new bytes(10); // Max 10 bytes for u64
        uint256 length = 0;

        while (value >= 0x80) {
            result[length] = bytes1(uint8((value & 0x7F) | 0x80));
            value >>= 7;
            length++;
        }
        result[length] = bytes1(uint8(value));
        length++;

        // Trim to actual length
        bytes memory trimmed = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            trimmed[i] = result[i];
        }
        return trimmed;
    }

    /// @notice Create a dummy Ed25519 signature with specific pattern
    function dummySignatureWithIndex(uint8 index) internal pure returns (bytes memory) {
        bytes memory sig = new bytes(64);
        for (uint i = 0; i < 64; i++) {
            sig[i] = bytes1(index + uint8(i));
        }
        return sig;
    }

    /// @notice Create a bitmap with specific bits set
    function createBitmap(uint256 numBits, bool[] memory setBits) internal pure returns (bytes memory) {
        uint256 numBytes = (numBits + 7) / 8;
        bytes memory bitmap = new bytes(numBytes);

        for (uint256 i = 0; i < setBits.length && i < numBits; i++) {
            if (setBits[i]) {
                uint256 byteIndex = i / 8;
                uint256 bitInByte = i % 8;
                bitmap[byteIndex] = bytes1(uint8(bitmap[byteIndex]) | uint8(1 << bitInByte));
            }
        }

        return bitmap;
    }

    // ============ getBit Tests ============

    function testGetBit_FirstBit() public {
        // Bitmap: 0b00000001 (0x01)
        bytes memory bitmap = hex"01";

        assertTrue(verifier.getBit_exposed(bitmap, 0));
        assertFalse(verifier.getBit_exposed(bitmap, 1));
        assertFalse(verifier.getBit_exposed(bitmap, 7));
    }

    function testGetBit_LastBitInByte() public {
        // Bitmap: 0b10000000 (0x80)
        bytes memory bitmap = hex"80";

        assertFalse(verifier.getBit_exposed(bitmap, 0));
        assertTrue(verifier.getBit_exposed(bitmap, 7));
    }

    function testGetBit_MultipleBitsInSingleByte() public {
        // Bitmap: 0b10101010 (0xAA)
        bytes memory bitmap = hex"AA";

        assertFalse(verifier.getBit_exposed(bitmap, 0));
        assertTrue(verifier.getBit_exposed(bitmap, 1));
        assertFalse(verifier.getBit_exposed(bitmap, 2));
        assertTrue(verifier.getBit_exposed(bitmap, 3));
        assertFalse(verifier.getBit_exposed(bitmap, 4));
        assertTrue(verifier.getBit_exposed(bitmap, 5));
        assertFalse(verifier.getBit_exposed(bitmap, 6));
        assertTrue(verifier.getBit_exposed(bitmap, 7));
    }

    function testGetBit_AllBitsSet() public {
        // Bitmap: 0b11111111 (0xFF)
        bytes memory bitmap = hex"FF";

        for (uint256 i = 0; i < 8; i++) {
            assertTrue(verifier.getBit_exposed(bitmap, i));
        }
    }

    function testGetBit_NoBitsSet() public {
        // Bitmap: 0b00000000 (0x00)
        bytes memory bitmap = hex"00";

        for (uint256 i = 0; i < 8; i++) {
            assertFalse(verifier.getBit_exposed(bitmap, i));
        }
    }

    function testGetBit_MultipleBytes() public {
        // Bitmap: 0x01 0x80 (first bit of first byte, last bit of second byte)
        bytes memory bitmap = hex"0180";

        // First byte
        assertTrue(verifier.getBit_exposed(bitmap, 0));
        assertFalse(verifier.getBit_exposed(bitmap, 1));
        assertFalse(verifier.getBit_exposed(bitmap, 7));

        // Second byte
        assertFalse(verifier.getBit_exposed(bitmap, 8));
        assertTrue(verifier.getBit_exposed(bitmap, 15));
    }

    function testGetBit_OutOfBounds() public {
        bytes memory bitmap = hex"FF";

        // Index 8 is beyond the single byte
        assertFalse(verifier.getBit_exposed(bitmap, 8));
        assertFalse(verifier.getBit_exposed(bitmap, 100));
        assertFalse(verifier.getBit_exposed(bitmap, type(uint256).max));
    }

    function testGetBit_EmptyBitmap() public {
        bytes memory bitmap = new bytes(0);

        assertFalse(verifier.getBit_exposed(bitmap, 0));
        assertFalse(verifier.getBit_exposed(bitmap, 1));
    }

    function testGetBit_ComplexPattern() public {
        // Bitmap: 0x5A 0xA5 0x3C (0b01011010 0b10100101 0b00111100)
        bytes memory bitmap = hex"5AA53C";

        // First byte: 0b01011010
        assertFalse(verifier.getBit_exposed(bitmap, 0));
        assertTrue(verifier.getBit_exposed(bitmap, 1));
        assertFalse(verifier.getBit_exposed(bitmap, 2));
        assertTrue(verifier.getBit_exposed(bitmap, 3));
        assertTrue(verifier.getBit_exposed(bitmap, 4));
        assertFalse(verifier.getBit_exposed(bitmap, 5));
        assertTrue(verifier.getBit_exposed(bitmap, 6));
        assertFalse(verifier.getBit_exposed(bitmap, 7));

        // Second byte: 0b10100101
        assertTrue(verifier.getBit_exposed(bitmap, 8));
        assertFalse(verifier.getBit_exposed(bitmap, 9));
        assertTrue(verifier.getBit_exposed(bitmap, 10));

        // Third byte: 0b00111100
        assertFalse(verifier.getBit_exposed(bitmap, 16));
        assertFalse(verifier.getBit_exposed(bitmap, 17));
        assertTrue(verifier.getBit_exposed(bitmap, 18));
        assertTrue(verifier.getBit_exposed(bitmap, 19));
        assertTrue(verifier.getBit_exposed(bitmap, 20));
        assertTrue(verifier.getBit_exposed(bitmap, 21));
    }

    function testGetBit_LargeBitmap() public {
        // Create a large bitmap with specific pattern
        bytes memory bitmap = new bytes(100);

        // Set bits at indices: 0, 10, 50, 99, 200, 500, 799
        bitmap[0] = bytes1(uint8(0x01));   // Bit 0
        bitmap[1] = bytes1(uint8(0x04));   // Bit 10
        bitmap[6] = bytes1(uint8(0x04));   // Bit 50
        bitmap[12] = bytes1(uint8(0x08)); // Bit 99

        assertTrue(verifier.getBit_exposed(bitmap, 0));
        assertTrue(verifier.getBit_exposed(bitmap, 10));
        assertTrue(verifier.getBit_exposed(bitmap, 50));
        assertTrue(verifier.getBit_exposed(bitmap, 99));
        assertFalse(verifier.getBit_exposed(bitmap, 1));
        assertFalse(verifier.getBit_exposed(bitmap, 51));
    }

    // ============ deserializeSignersBitmap Tests ============

    function testDeserializeSignersBitmap_EmptyBitmap() public {
        // Bitmap length: 0
        // Bitmap bytes: (none)
        bytes memory proof = abi.encodePacked(uint64(0));

        (uint64 bitmapLength, bytes memory bitmap, uint256 newOffset) =
            verifier.deserializeSignersBitmap(proof, 0, 0);

        assertEq(bitmapLength, 0);
        assertEq(bitmap.length, 0);
        assertEq(newOffset, 8);
    }

    function testDeserializeSignersBitmap_SingleBit() public {
        // Bitmap length: 1 bit
        // Bitmap bytes: 0x01 (1 byte for 1 bit)
        bytes memory proof = abi.encodePacked(uint64(1), hex"01");

        (uint64 bitmapLength, bytes memory bitmap, uint256 newOffset) =
            verifier.deserializeSignersBitmap(proof, 0, 1);

        assertEq(bitmapLength, 1);
        assertEq(bitmap.length, 1);
        assertEq(uint8(bitmap[0]), 0x01);
        assertEq(newOffset, 9);
    }

    function testDeserializeSignersBitmap_EightBits() public {
        // Bitmap length: 8 bits
        // Bitmap bytes: 0xFF (1 byte for 8 bits)
        bytes memory proof = abi.encodePacked(uint64(8), hex"FF");

        (uint64 bitmapLength, bytes memory bitmap, uint256 newOffset) =
            verifier.deserializeSignersBitmap(proof, 0, 8);

        assertEq(bitmapLength, 8);
        assertEq(bitmap.length, 1);
        assertEq(uint8(bitmap[0]), 0xFF);
        assertEq(newOffset, 9);
    }

    function testDeserializeSignersBitmap_NineBits() public {
        // Bitmap length: 9 bits
        // Bitmap bytes: 0xFF 0x01 (2 bytes for 9 bits)
        bytes memory proof = abi.encodePacked(uint64(9), hex"FF01");

        (uint64 bitmapLength, bytes memory bitmap, uint256 newOffset) =
            verifier.deserializeSignersBitmap(proof, 0, 9);

        assertEq(bitmapLength, 9);
        assertEq(bitmap.length, 2);
        assertEq(uint8(bitmap[0]), 0xFF);
        assertEq(uint8(bitmap[1]), 0x01);
        assertEq(newOffset, 10);
    }

    function testDeserializeSignersBitmap_MultipleBytes() public {
        // Bitmap length: 64 bits
        // Bitmap bytes: 8 bytes
        bytes memory bitmapData = hex"0123456789ABCDEF";
        bytes memory proof = abi.encodePacked(uint64(64), bitmapData);

        (uint64 bitmapLength, bytes memory bitmap, uint256 newOffset) =
            verifier.deserializeSignersBitmap(proof, 0, 64);

        assertEq(bitmapLength, 64);
        assertEq(bitmap.length, 8);
        assertEq(bitmap, bitmapData);
        assertEq(newOffset, 16);
    }

    function testDeserializeSignersBitmap_NonZeroOffset() public {
        // Add some prefix data before the bitmap
        bytes memory prefix = hex"DEADBEEF";
        bytes memory bitmapData = hex"AA55";
        bytes memory proof = abi.encodePacked(prefix, uint64(16), bitmapData);

        (uint64 bitmapLength, bytes memory bitmap, uint256 newOffset) =
            verifier.deserializeSignersBitmap(proof, 4, 16);

        assertEq(bitmapLength, 16);
        assertEq(bitmap.length, 2);
        assertEq(bitmap, bitmapData);
        assertEq(newOffset, 14); // 4 (prefix) + 8 (length) + 2 (bitmap)
    }

    function testDeserializeSignersBitmap_LargeBitmap() public {
        // Bitmap length: 1000 bits = 125 bytes
        bytes memory bitmapData = new bytes(125);
        for (uint i = 0; i < 125; i++) {
            bitmapData[i] = bytes1(uint8(i % 256));
        }
        bytes memory proof = abi.encodePacked(uint64(1000), bitmapData);

        (uint64 bitmapLength, bytes memory bitmap, uint256 newOffset) =
            verifier.deserializeSignersBitmap(proof, 0, 1000);

        assertEq(bitmapLength, 1000);
        assertEq(bitmap.length, 125);
        assertEq(bitmap, bitmapData);
        assertEq(newOffset, 133);
    }

    function testDeserializeSignersBitmap_OddBitCount() public {
        // Test various odd bit counts to verify (length + 7) / 8 calculation

        // 7 bits = 1 byte
        bytes memory proof7 = abi.encodePacked(uint64(7), hex"7F");
        (uint64 len7, bytes memory bitmap7,) = verifier.deserializeSignersBitmap(proof7, 0, 7);
        assertEq(len7, 7);
        assertEq(bitmap7.length, 1);

        // 15 bits = 2 bytes
        bytes memory proof15 = abi.encodePacked(uint64(15), hex"FFFF");
        (uint64 len15, bytes memory bitmap15,) = verifier.deserializeSignersBitmap(proof15, 0, 15);
        assertEq(len15, 15);
        assertEq(bitmap15.length, 2);

        // 17 bits = 3 bytes
        bytes memory proof17 = abi.encodePacked(uint64(17), hex"FFFFFF");
        (uint64 len17, bytes memory bitmap17,) = verifier.deserializeSignersBitmap(proof17, 0, 17);
        assertEq(len17, 17);
        assertEq(bitmap17.length, 3);
    }

    function test_RevertWhen_DeserializeSignersBitmapInsufficientLength() public {
        // Only 4 bytes when we need 8 for length
        bytes memory proof = hex"12345678";

        vm.expectRevert();
        verifier.deserializeSignersBitmap(proof, 0, 0);
    }

    function test_RevertWhen_DeserializeSignersBitmapInsufficientBitmapBytes() public {
        // Bitmap length says 16 bits (2 bytes) but only 1 byte provided
        bytes memory proof = abi.encodePacked(uint64(16), hex"FF");

        vm.expectRevert();
        verifier.deserializeSignersBitmap(proof, 0, 16);
    }

    function test_RevertWhen_DeserializeSignersBitmapOffsetTooLarge() public {
        bytes memory proof = abi.encodePacked(uint64(8), hex"FF");

        vm.expectRevert();
        verifier.deserializeSignersBitmap(proof, 100, 8);
    }

    // ============ deserializeSignatures Tests ============

    function testDeserializeSignatures_EmptySignatures() public {
        // Bitmap with 0 bits set, 0 signatures
        bytes memory signersBitmap = hex"00";
        bytes memory proof = abi.encodePacked(encodeVarintU64(0));

        (TestableSimplexVerifier.Vote[] memory votes, uint256 newOffset) =
            verifier.deserializeSignatures(proof, 0, signersBitmap, 10);

        assertEq(votes.length, 0);
        assertEq(newOffset, 1); // Just the varint byte
    }

    function testDeserializeSignatures_SingleSignature() public {
        // Bitmap: 0x01 (bit 0 set)
        bytes memory signersBitmap = hex"01";
        bytes memory signature = dummySignatureWithIndex(1);
        bytes memory proof = abi.encodePacked(encodeVarintU64(1), signature);

        (TestableSimplexVerifier.Vote[] memory votes, uint256 newOffset) =
            verifier.deserializeSignatures(proof, 0, signersBitmap, 10);

        assertEq(votes.length, 1);
        assertEq(votes[0].signer, 0);
        assertEq(votes[0].signature, signature);
        assertEq(newOffset, 1 + 64); // varint + signature
    }

    function testDeserializeSignatures_MultipleConsecutiveSigners() public {
        // Bitmap: 0x07 (bits 0, 1, 2 set)
        bytes memory signersBitmap = hex"07";
        bytes memory sig1 = dummySignatureWithIndex(1);
        bytes memory sig2 = dummySignatureWithIndex(2);
        bytes memory sig3 = dummySignatureWithIndex(3);
        bytes memory proof = abi.encodePacked(encodeVarintU64(3), sig1, sig2, sig3);

        (TestableSimplexVerifier.Vote[] memory votes, uint256 newOffset) =
            verifier.deserializeSignatures(proof, 0, signersBitmap, 10);

        assertEq(votes.length, 3);
        assertEq(votes[0].signer, 0);
        assertEq(votes[0].signature, sig1);
        assertEq(votes[1].signer, 1);
        assertEq(votes[1].signature, sig2);
        assertEq(votes[2].signer, 2);
        assertEq(votes[2].signature, sig3);
        assertEq(newOffset, 1 + 192); // varint + 3 signatures
    }

    function testDeserializeSignatures_NonConsecutiveSigners() public {
        // Bitmap: 0x15 (bits 0, 2, 4 set = 0b00010101)
        bytes memory signersBitmap = hex"15";
        bytes memory sig1 = dummySignatureWithIndex(10);
        bytes memory sig2 = dummySignatureWithIndex(20);
        bytes memory sig3 = dummySignatureWithIndex(30);
        bytes memory proof = abi.encodePacked(encodeVarintU64(3), sig1, sig2, sig3);

        (TestableSimplexVerifier.Vote[] memory votes, uint256 newOffset) =
            verifier.deserializeSignatures(proof, 0, signersBitmap, 10);

        assertEq(votes.length, 3);
        assertEq(votes[0].signer, 0); // First bit set
        assertEq(votes[1].signer, 2); // Third bit set
        assertEq(votes[2].signer, 4); // Fifth bit set
    }

    function testDeserializeSignatures_SignersInSecondByte() public {
        // Bitmap: 0x00 0x03 (bits 8, 9 set in second byte)
        bytes memory signersBitmap = hex"0003";
        bytes memory sig1 = dummySignatureWithIndex(5);
        bytes memory sig2 = dummySignatureWithIndex(6);
        bytes memory proof = abi.encodePacked(encodeVarintU64(2), sig1, sig2);

        (TestableSimplexVerifier.Vote[] memory votes, uint256 newOffset) =
            verifier.deserializeSignatures(proof, 0, signersBitmap, 10);

        assertEq(votes.length, 2);
        assertEq(votes[0].signer, 8);
        assertEq(votes[1].signer, 9);
    }

    function testDeserializeSignatures_SparseBitmap() public {
        // Bitmap: 0x01 0x00 0x00 0x80 (bit 0 and bit 31 set)
        bytes memory signersBitmap = hex"01000080";
        bytes memory sig1 = dummySignatureWithIndex(7);
        bytes memory sig2 = dummySignatureWithIndex(8);
        bytes memory proof = abi.encodePacked(encodeVarintU64(2), sig1, sig2);

        (TestableSimplexVerifier.Vote[] memory votes, uint256 newOffset) =
            verifier.deserializeSignatures(proof, 0, signersBitmap, 100);

        assertEq(votes.length, 2);
        assertEq(votes[0].signer, 0);
        assertEq(votes[1].signer, 31);
    }

    function testDeserializeSignatures_AllBitsSet() public {
        // Bitmap: 0xFF (all 8 bits set)
        bytes memory signersBitmap = hex"FF";
        bytes memory proof = encodeVarintU64(8);

        // Add 8 signatures
        for (uint8 i = 0; i < 8; i++) {
            proof = abi.encodePacked(proof, dummySignatureWithIndex(i));
        }

        (TestableSimplexVerifier.Vote[] memory votes, uint256 newOffset) =
            verifier.deserializeSignatures(proof, 0, signersBitmap, 10);

        assertEq(votes.length, 8);
        for (uint32 i = 0; i < 8; i++) {
            assertEq(votes[i].signer, i);
        }
        assertEq(newOffset, 1 + 512); // varint + 8 signatures
    }

    function testDeserializeSignatures_WithNonZeroOffset() public {
        bytes memory prefix = hex"DEADBEEF";
        bytes memory signersBitmap = hex"03";
        bytes memory sig1 = dummySignatureWithIndex(11);
        bytes memory sig2 = dummySignatureWithIndex(22);
        bytes memory proof = abi.encodePacked(prefix, encodeVarintU64(2), sig1, sig2);

        (TestableSimplexVerifier.Vote[] memory votes, uint256 newOffset) =
            verifier.deserializeSignatures(proof, 4, signersBitmap, 10);

        assertEq(votes.length, 2);
        assertEq(votes[0].signer, 0);
        assertEq(votes[1].signer, 1);
        assertEq(newOffset, 4 + 1 + 128); // prefix + varint + 2 signatures
    }

    function testDeserializeSignatures_MaxSignersAtLimit() public {
        // Test exactly at the max signer limit
        bytes memory signersBitmap = hex"0F"; // 4 bits set
        bytes memory proof = encodeVarintU64(4);

        for (uint8 i = 0; i < 4; i++) {
            proof = abi.encodePacked(proof, dummySignatureWithIndex(i));
        }

        (TestableSimplexVerifier.Vote[] memory votes,) =
            verifier.deserializeSignatures(proof, 0, signersBitmap, 4);

        assertEq(votes.length, 4);
    }

    function testDeserializeSignatures_LargeSignerIndex() public {
        // Create a bitmap with bit 100 set
        bytes memory signersBitmap = new bytes(13); // Need at least 101 bits = 13 bytes
        signersBitmap[12] = bytes1(uint8(0x10)); // Bit 100 (byte 12, bit 4)

        bytes memory sig = dummySignatureWithIndex(99);
        bytes memory proof = abi.encodePacked(encodeVarintU64(1), sig);

        (TestableSimplexVerifier.Vote[] memory votes,) =
            verifier.deserializeSignatures(proof, 0, signersBitmap, 200);

        assertEq(votes.length, 1);
        assertEq(votes[0].signer, 100);
    }

    function testDeserializeSignatures_MultiByteVarint() public {
        // Use a large signature count that requires multi-byte varint
        bytes memory signersBitmap = new bytes(20); // 160 bits
        for (uint i = 0; i < 20; i++) {
            signersBitmap[i] = bytes1(uint8(0xFF)); // All bits set
        }

        uint64 signatureCount = 160;
        bytes memory proof = encodeVarintU64(signatureCount);

        for (uint8 i = 0; i < 160; i++) {
            proof = abi.encodePacked(proof, dummySignatureWithIndex(i % 64));
        }

        (TestableSimplexVerifier.Vote[] memory votes,) =
            verifier.deserializeSignatures(proof, 0, signersBitmap, 200);

        assertEq(votes.length, 160);
        assertEq(votes[0].signer, 0);
        assertEq(votes[159].signer, 159);
    }

    function testDeserializeSignatures_AlternatingPattern() public {
        // Bitmap: 0xAA (0b10101010 - bits 1, 3, 5, 7 set)
        bytes memory signersBitmap = hex"AA";
        bytes memory proof = encodeVarintU64(4);

        for (uint8 i = 0; i < 4; i++) {
            proof = abi.encodePacked(proof, dummySignatureWithIndex(i * 10));
        }

        (TestableSimplexVerifier.Vote[] memory votes,) =
            verifier.deserializeSignatures(proof, 0, signersBitmap, 10);

        assertEq(votes.length, 4);
        assertEq(votes[0].signer, 1);
        assertEq(votes[1].signer, 3);
        assertEq(votes[2].signer, 5);
        assertEq(votes[3].signer, 7);
    }

    function test_RevertWhen_DeserializeSignaturesTooManySigners() public {
        bytes memory signersBitmap = hex"FF";
        bytes memory proof = encodeVarintU64(10);

        vm.expectRevert();
        verifier.deserializeSignatures(proof, 0, signersBitmap, 5); // Max 5, trying 10
    }

    function test_RevertWhen_DeserializeSignaturesExactlyOverLimit() public {
        bytes memory signersBitmap = hex"FF";
        bytes memory proof = encodeVarintU64(11);

        vm.expectRevert();
        verifier.deserializeSignatures(proof, 0, signersBitmap, 10); // Max 10, trying 11
    }

    function test_RevertWhen_DeserializeSignaturesInsufficientData() public {
        // Says 3 signatures but only provides 2
        bytes memory signersBitmap = hex"07";
        bytes memory sig1 = dummySignatureWithIndex(1);
        bytes memory sig2 = dummySignatureWithIndex(2);
        bytes memory proof = abi.encodePacked(encodeVarintU64(3), sig1, sig2);

        vm.expectRevert(); // Will fail when trying to read 3rd signature
        verifier.deserializeSignatures(proof, 0, signersBitmap, 10);
    }

    function test_RevertWhen_DeserializeSignaturesPartialSignature() public {
        // Signature is only 50 bytes instead of 64
        bytes memory signersBitmap = hex"01";
        bytes memory partialSig = new bytes(50);
        bytes memory proof = abi.encodePacked(encodeVarintU64(1), partialSig);

        vm.expectRevert(); // Will fail when trying to read 64 bytes
        verifier.deserializeSignatures(proof, 0, signersBitmap, 10);
    }

    function test_RevertWhen_DeserializeSignaturesInvalidVarint() public {
        // Invalid varint (continuation bit set but no more bytes)
        bytes memory signersBitmap = hex"01";
        bytes memory proof = hex"80"; // 0x80 has continuation bit but no next byte

        vm.expectRevert(); // Should fail in varint decoding
        verifier.deserializeSignatures(proof, 0, signersBitmap, 10);
    }

    // ============ Integration Tests ============

    function testIntegration_BitmapToSignatures() public {
        // Complete flow: bitmap with specific pattern -> deserialize signatures

        // Setup: 4 signers, indices 0, 5, 10, 15
        bool[] memory setBits = new bool[](16);
        setBits[0] = true;
        setBits[5] = true;
        setBits[10] = true;
        setBits[15] = true;

        bytes memory bitmap = createBitmap(16, setBits);

        // Verify bitmap construction
        assertTrue(verifier.getBit_exposed(bitmap, 0));
        assertTrue(verifier.getBit_exposed(bitmap, 5));
        assertTrue(verifier.getBit_exposed(bitmap, 10));
        assertTrue(verifier.getBit_exposed(bitmap, 15));
        assertFalse(verifier.getBit_exposed(bitmap, 1));
        assertFalse(verifier.getBit_exposed(bitmap, 6));

        // Build proof with bitmap and signatures
        bytes memory proof = abi.encodePacked(
            uint64(16), // bitmap length
            bitmap,
            encodeVarintU64(4) // 4 signatures
        );

        for (uint8 i = 0; i < 4; i++) {
            proof = abi.encodePacked(proof, dummySignatureWithIndex(i));
        }

        // Deserialize bitmap
        (uint64 bitmapLength, bytes memory deserializedBitmap, uint256 offset) =
            verifier.deserializeSignersBitmap(proof, 0, 16);

        assertEq(bitmapLength, 16);
        assertEq(deserializedBitmap, bitmap);

        // Deserialize signatures
        (TestableSimplexVerifier.Vote[] memory votes,) =
            verifier.deserializeSignatures(proof, offset, deserializedBitmap, 20);

        assertEq(votes.length, 4);
        assertEq(votes[0].signer, 0);
        assertEq(votes[1].signer, 5);
        assertEq(votes[2].signer, 10);
        assertEq(votes[3].signer, 15);
    }

    function testIntegration_CompleteNotarizationFlow() public {
        // Simulate a complete notarization certificate deserialization

        // Setup bitmap: 10 signers, 7 signed (indices: 0, 1, 3, 5, 6, 8, 9)
        bool[] memory setBits = new bool[](10);
        setBits[0] = true;
        setBits[1] = true;
        setBits[3] = true;
        setBits[5] = true;
        setBits[6] = true;
        setBits[8] = true;
        setBits[9] = true;

        bytes memory bitmap = createBitmap(10, setBits);

        bytes memory proof = abi.encodePacked(
            uint64(10), // bitmap length
            bitmap,
            encodeVarintU64(7) // 7 signatures
        );

        for (uint8 i = 0; i < 7; i++) {
            proof = abi.encodePacked(proof, dummySignatureWithIndex(i * 7));
        }

        // Step 1: Deserialize bitmap
        (uint64 bitmapLength, bytes memory deserializedBitmap, uint256 offset) =
            verifier.deserializeSignersBitmap(proof, 0, 10);

        assertEq(bitmapLength, 10);

        // Step 2: Verify bitmap bits
        assertTrue(verifier.getBit_exposed(deserializedBitmap, 0));
        assertTrue(verifier.getBit_exposed(deserializedBitmap, 1));
        assertFalse(verifier.getBit_exposed(deserializedBitmap, 2));
        assertTrue(verifier.getBit_exposed(deserializedBitmap, 3));

        // Step 3: Deserialize signatures and match to signers
        (TestableSimplexVerifier.Vote[] memory votes, uint256 finalOffset) =
            verifier.deserializeSignatures(proof, offset, deserializedBitmap, 20);

        assertEq(votes.length, 7);

        // Verify correct signer indices
        uint32[7] memory expectedSigners = [uint32(0), 1, 3, 5, 6, 8, 9];
        for (uint i = 0; i < 7; i++) {
            assertEq(votes[i].signer, expectedSigners[i]);
            assertEq(votes[i].signature.length, 64);
        }

        assertEq(finalOffset, proof.length);
    }

    function testIntegration_EdgeCaseMaxU32Signer() public {
        // Test with a very large signer index near uint32 max
        // This would require a huge bitmap, so we test the indexing logic

        bytes memory signersBitmap = new bytes(100);
        // Set bit at index 799 (byte 99, bit 7)
        signersBitmap[99] = bytes1(uint8(0x80));

        bytes memory sig = dummySignatureWithIndex(42);
        bytes memory proof = abi.encodePacked(encodeVarintU64(1), sig);

        (TestableSimplexVerifier.Vote[] memory votes,) =
            verifier.deserializeSignatures(proof, 0, signersBitmap, 1000);

        assertEq(votes.length, 1);
        assertEq(votes[0].signer, 799);
    }

    function testIntegration_RealWorldScenario() public {
        // Simulate a real consensus scenario with 21 validators, 14 signed (2/3 threshold)

        bool[] memory setBits = new bool[](21);
        uint8 signedCount = 0;

        // Set bits for signers: 0, 2, 3, 5, 7, 8, 9, 11, 13, 15, 16, 17, 19, 20
        uint8[14] memory signerIndices = [0, 2, 3, 5, 7, 8, 9, 11, 13, 15, 16, 17, 19, 20];
        for (uint8 i = 0; i < 14; i++) {
            setBits[signerIndices[i]] = true;
        }

        bytes memory bitmap = createBitmap(21, setBits);

        bytes memory proof = abi.encodePacked(
            uint64(21),
            bitmap,
            encodeVarintU64(14)
        );

        for (uint8 i = 0; i < 14; i++) {
            proof = abi.encodePacked(proof, dummySignatureWithIndex(i));
        }

        (uint64 bitmapLength, bytes memory deserializedBitmap, uint256 offset) =
            verifier.deserializeSignersBitmap(proof, 0, 21);

        (TestableSimplexVerifier.Vote[] memory votes,) =
            verifier.deserializeSignatures(proof, offset, deserializedBitmap, 30);

        assertEq(votes.length, 14);

        // Verify each signer index matches expected
        for (uint8 i = 0; i < 14; i++) {
            assertEq(votes[i].signer, signerIndices[i]);
        }
    }
}
