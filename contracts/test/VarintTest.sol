// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/SimplexVerifierBase.sol";

/// @title VarintTest
/// @notice Comprehensive test suite for varint encoding/decoding
/// @dev Tests match the Rust varint implementation test cases from commonware_codec
contract VarintTest is Test, SimplexVerifierBase {

    // ============ Test Helpers ============

    /// @notice Public wrapper for decodeVarintU32 to allow external calls in tests
    /// @dev Calls the internal function from SimplexVerifierBase
    function decodeVarintU32Wrapper(bytes calldata data, uint256 offset)
        public pure returns (uint32 value, uint256 newOffset)
    {
        return super.decodeVarintU32(data, offset);
    }

    /// @notice Public wrapper for decodeVarintU64 to allow external calls in tests
    /// @dev Calls the internal function from SimplexVerifierBase
    function decodeVarintU64Wrapper(bytes calldata data, uint256 offset)
        public pure returns (uint64 value, uint256 newOffset)
    {
        return super.decodeVarintU64(data, offset);
    }

    /// @notice Encode a varint u32 (LEB128 format)
    /// @dev Matches Rust's UInt(u32) wrapper encoding (used for usize)
    function encodeVarintU32(uint32 value) internal pure returns (bytes memory) {
        bytes memory result = new bytes(5); // Max 5 bytes for u32
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

    /// @notice Encode a varint u64 (LEB128 format)
    /// @dev Matches Rust's UInt wrapper encoding
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

    /// @notice Test helper to verify encoding/decoding round trip
    function testRoundTrip(uint64 value) internal view {
        bytes memory encoded = encodeVarintU64(value);
        (uint64 decoded, uint256 bytesRead) = this.decodeVarintU64Wrapper(encoded, 0);

        assertEq(decoded, value, "Round trip failed: decoded value mismatch");
        assertEq(bytesRead, encoded.length, "Round trip failed: bytes read mismatch");
    }

    // ============ U32 Tests ============

    /// @notice Test helper to verify encoding/decoding round trip for u32
    function testRoundTripU32(uint32 value) internal view {
        bytes memory encoded = encodeVarintU32(value);
        (uint32 decoded, uint256 bytesRead) = this.decodeVarintU32Wrapper(encoded, 0);

        assertEq(decoded, value, "Round trip failed: decoded value mismatch");
        assertEq(bytesRead, encoded.length, "Round trip failed: bytes read mismatch");
    }

    /// @notice Test u32 single byte values (0-127)
    function testU32SingleByteValues() public view {
        // Test value 0
        bytes memory data = hex"00";
        (uint32 value, uint256 offset) = this.decodeVarintU32Wrapper(data, 0);
        assertEq(value, 0);
        assertEq(offset, 1);

        // Test value 1
        data = hex"01";
        (value, offset) = this.decodeVarintU32Wrapper(data, 0);
        assertEq(value, 1);
        assertEq(offset, 1);

        // Test value 127 (0x7F - maximum single byte)
        data = hex"7F";
        (value, offset) = this.decodeVarintU32Wrapper(data, 0);
        assertEq(value, 127);
        assertEq(offset, 1);
    }

    /// @notice Test u32 two byte values
    function testU32TwoByteValues() public {
        // Test value 128 (0x80, 0x01)
        bytes memory data = hex"8001";
        (uint32 value, uint256 offset) = this.decodeVarintU32Wrapper(data, 0);
        assertEq(value, 128);
        assertEq(offset, 2);

        // Test value 300
        data = hex"AC02";
        (value, offset) = this.decodeVarintU32Wrapper(data, 0);
        assertEq(value, 300);
        assertEq(offset, 2);

        // Test value 16383 (0xFF, 0x7F)
        data = hex"FF7F";
        (value, offset) = this.decodeVarintU32Wrapper(data, 0);
        assertEq(value, 16383);
        assertEq(offset, 2);
    }

    /// @notice Test u32 maximum value
    function testU32MaxValue() public {
        // u32::MAX = 4294967295 (0xFF, 0xFF, 0xFF, 0xFF, 0x0F)
        bytes memory data = hex"FFFFFFFF0F";
        (uint32 value, uint256 offset) = this.decodeVarintU32Wrapper(data, 0);
        assertEq(value, type(uint32).max);
        assertEq(offset, 5);
    }

    /// @notice Test u32 round trips for common values
    function testU32RoundTrips() public {
        // Test common values used for Vec lengths
        testRoundTripU32(0);
        testRoundTripU32(1);
        testRoundTripU32(10);
        testRoundTripU32(100);
        testRoundTripU32(127);
        testRoundTripU32(128);
        testRoundTripU32(255);
        testRoundTripU32(256);
        testRoundTripU32(1000);
        testRoundTripU32(10000);
        testRoundTripU32(65535); // u16::MAX
        testRoundTripU32(type(uint32).max);
    }

    /// @notice Test u32 overflow detection on 5th byte
    function testU32RejectOverflow() public {
        // 5th byte must be at most 0x0F for u32
        // Test 0x10 on 5th byte (would overflow u32)
        bytes memory data = hex"FFFFFFFF10";
        vm.expectRevert(InvalidVarint.selector);
        this.decodeVarintU32Wrapper(data, 0);

        // Test 0xFF on 5th byte (definitely overflows)
        data = hex"FFFFFFFF7F";
        vm.expectRevert(InvalidVarint.selector);
        this.decodeVarintU32Wrapper(data, 0);
    }

    /// @notice Test u32 rejects non-canonical encoding
    function testU32RejectNonCanonical() public {
        // [0x80, 0x00] is non-canonical for 0
        bytes memory data = hex"8000";
        vm.expectRevert(InvalidVarint.selector);
        this.decodeVarintU32Wrapper(data, 0);

        // [0xFF, 0x00] is non-canonical
        data = hex"FF00";
        vm.expectRevert(InvalidVarint.selector);
        this.decodeVarintU32Wrapper(data, 0);
    }

    /// @notice Test u32 empty buffer
    function testU32EmptyBuffer() public {
        bytes memory data = "";
        vm.expectRevert(InvalidVarint.selector);
        this.decodeVarintU32Wrapper(data, 0);
    }

    /// @notice Test u32 incomplete varint
    function testU32IncompleteVarint() public {
        bytes memory data = hex"80"; // Continuation bit set but no following byte
        vm.expectRevert(InvalidVarint.selector);
        this.decodeVarintU32Wrapper(data, 0);
    }

    /// @notice Test u32 conformity with Rust encoding
    function testU32ConformityValues() public {
        // These should match Rust codec/src/types/primitives.rs:437-444
        bytes memory encoded = encodeVarintU32(0);
        assertEq(encoded, hex"00");

        encoded = encodeVarintU32(1);
        assertEq(encoded, hex"01");

        encoded = encodeVarintU32(127);
        assertEq(encoded, hex"7F");

        encoded = encodeVarintU32(128);
        assertEq(encoded, hex"8001");

        // u32::MAX as usize
        encoded = encodeVarintU32(type(uint32).max);
        assertEq(encoded, hex"FFFFFFFF0F");
    }

    /// @notice Fuzz test for u32 round-trip encoding/decoding
    /// @param value Any u32 value to test
    function testFuzzU32RoundTrip(uint32 value) public {
        testRoundTripU32(value);
    }

    /// @notice Test u32 multiple varints in sequence (simulating Vec<Vec<T>>)
    function testU32MultipleVarints() public {
        // Encode three Vec lengths: 5, 100, 1000
        bytes memory data = abi.encodePacked(
            encodeVarintU32(5),
            encodeVarintU32(100),
            encodeVarintU32(1000)
        );

        uint256 offset = 0;
        uint32 value;

        // Decode first length
        (value, offset) = this.decodeVarintU32Wrapper(data, offset);
        assertEq(value, 5);

        // Decode second length
        (value, offset) = this.decodeVarintU32Wrapper(data, offset);
        assertEq(value, 100);

        // Decode third length
        (value, offset) = this.decodeVarintU32Wrapper(data, offset);
        assertEq(value, 1000);

        // Should have consumed all data
        assertEq(offset, data.length);
    }

    // ============ Basic Tests ============

    /// @notice Test decoding single byte values (0-127)
    function testSingleByteValues() public view {
        // Test value 0
        bytes memory data = hex"00";
        (uint64 value, uint256 offset) = this.decodeVarintU64Wrapper(data, 0);
        assertEq(value, 0);
        assertEq(offset, 1);

        // Test value 1
        data = hex"01";
        (value, offset) = this.decodeVarintU64Wrapper(data, 0);
        assertEq(value, 1);
        assertEq(offset, 1);

        // Test value 127 (0x7F - maximum single byte)
        data = hex"7F";
        (value, offset) = this.decodeVarintU64Wrapper(data, 0);
        assertEq(value, 127);
        assertEq(offset, 1);
    }

    /// @notice Test decoding two byte values
    function testTwoByteValues() public {
        // Test value 128 (0x80, 0x01)
        bytes memory data = hex"8001";
        (uint64 value, uint256 offset) = this.decodeVarintU64Wrapper(data, 0);
        assertEq(value, 128);
        assertEq(offset, 2);

        // Test value 129 (0x81, 0x01)
        data = hex"8101";
        (value, offset) = this.decodeVarintU64Wrapper(data, 0);
        assertEq(value, 129);
        assertEq(offset, 2);

        // Test value 255 (0xFF, 0x01)
        data = hex"FF01";
        (value, offset) = this.decodeVarintU64Wrapper(data, 0);
        assertEq(value, 255);
        assertEq(offset, 2);

        // Test value 16383 (0xFF, 0x7F)
        data = hex"FF7F";
        (value, offset) = this.decodeVarintU64Wrapper(data, 0);
        assertEq(value, 16383);
        assertEq(offset, 2);
    }

    /// @notice Test decoding three byte values
    function testThreeByteValues() public {
        // Test value 16384 (0x80, 0x80, 0x01)
        bytes memory data = hex"808001";
        (uint64 value, uint256 offset) = this.decodeVarintU64Wrapper(data, 0);
        assertEq(value, 16384);
        assertEq(offset, 3);

        // Test value 2097151 (0xFF, 0xFF, 0x7F)
        data = hex"FFFF7F";
        (value, offset) = this.decodeVarintU64Wrapper(data, 0);
        assertEq(value, 2097151);
        assertEq(offset, 3);
    }

    /// @notice Test decoding four byte values
    function testFourByteValues() public {
        // Test value 2097152 (0x80, 0x80, 0x80, 0x01)
        bytes memory data = hex"80808001";
        (uint64 value, uint256 offset) = this.decodeVarintU64Wrapper(data, 0);
        assertEq(value, 2097152);
        assertEq(offset, 4);
    }

    /// @notice Test decoding maximum u32 value
    function testMaxU32() public {
        // u32::MAX = 4294967295 (0xFF, 0xFF, 0xFF, 0xFF, 0x0F)
        bytes memory data = hex"FFFFFFFF0F";
        (uint64 value, uint256 offset) = this.decodeVarintU64Wrapper(data, 0);
        assertEq(value, type(uint32).max);
        assertEq(offset, 5);
    }

    /// @notice Test decoding maximum u64 value
    function testMaxU64() public {
        // u64::MAX requires 10 bytes in varint encoding
        // All bytes except last have continuation bit set
        bytes memory data = hex"FFFFFFFFFFFFFFFFFF01";
        (uint64 value, uint256 offset) = this.decodeVarintU64Wrapper(data, 0);
        assertEq(value, type(uint64).max);
        assertEq(offset, 10);
    }

    // ============ Round Trip Tests ============

    /// @notice Test encoding/decoding round trips for Rust test case values
    function testRustTestCaseRoundTrips() public {
        // Values from Rust test suite (codec/src/varint.rs:388)
        testRoundTrip(0);
        testRoundTrip(1);
        testRoundTrip(127);
        testRoundTrip(128);
        testRoundTrip(129);
        testRoundTrip(255);
        testRoundTrip(256);
        testRoundTrip(16383);
        testRoundTrip(16384);
        testRoundTrip(131071);   // 0x1FFFF
        testRoundTrip(16777215); // 0xFFFFFF
        testRoundTrip(8589934591); // 0x1FFFFFFFF

        // Test type maximums
        testRoundTrip(type(uint16).max);
        testRoundTrip(type(uint32).max);
        testRoundTrip(type(uint64).max);
    }

    // ============ Edge Cases and Error Tests ============

    /// @notice Test decoding with offset
    function testDecodeWithOffset() public {
        // Create data with varint starting at offset 3
        bytes memory data = hex"FFFFFF8001"; // 3 padding bytes, then 128 encoded
        (uint64 value, uint256 offset) = this.decodeVarintU64Wrapper(data, 3);
        assertEq(value, 128);
        assertEq(offset, 5);
    }

    /// @notice Test multiple varints in sequence
    function testMultipleVarints() public {
        // Encode three values: 42, 300, 1000000
        bytes memory data = abi.encodePacked(
            encodeVarintU64(42),      // 1 byte
            encodeVarintU64(300),     // 2 bytes
            encodeVarintU64(1000000)  // 3 bytes
        );

        uint256 offset = 0;
        uint64 value;

        // Decode first varint
        (value, offset) = this.decodeVarintU64Wrapper(data, offset);
        assertEq(value, 42);

        // Decode second varint
        (value, offset) = this.decodeVarintU64Wrapper(data, offset);
        assertEq(value, 300);

        // Decode third varint
        (value, offset) = this.decodeVarintU64Wrapper(data, offset);
        assertEq(value, 1000000);
    }

    /// @notice Test that decoding fails on empty input
    function testEmptyInput() public {
        bytes memory data = "";
        vm.expectRevert(InvalidVarint.selector);
        this.decodeVarintU64Wrapper(data, 0);
    }

    /// @notice Test that decoding fails when offset exceeds data length
    function testOffsetOutOfBounds() public {
        bytes memory data = hex"01";
        vm.expectRevert(InvalidVarint.selector);
        this.decodeVarintU64Wrapper(data, 1);
    }

    /// @notice Test that decoding fails on incomplete varint (continuation bit set but no next byte)
    function testIncompleteVarint() public {
        bytes memory data = hex"80"; // Continuation bit set but no following byte
        vm.expectRevert(InvalidVarint.selector);
        this.decodeVarintU64Wrapper(data, 0);
    }

    /// @notice Test that decoding fails when shift would overflow u64
    function testShiftOverflow() public {
        // Create a varint that would require > 64 bits
        // 10 bytes with continuation bits would overflow
        bytes memory data = hex"80808080808080808080"; // 10 bytes all with continuation
        vm.expectRevert(InvalidVarint.selector);
        this.decodeVarintU64Wrapper(data, 0);
    }

    /// @notice Test that decoding fails when reading past buffer end
    /// @dev JS test: "fail: reading past buffer end"
    function testReadingPastBufferEnd() public {
        // Try to read varint starting at position 5 in a 2-byte buffer
        bytes memory data = hex"0102";
        vm.expectRevert(InvalidVarint.selector);
        this.decodeVarintU64Wrapper(data, 5);

        // Try to read at position 2 (exactly at end)
        vm.expectRevert(InvalidVarint.selector);
        this.decodeVarintU64Wrapper(data, 2);

        // Try to read at position 3 (beyond end)
        vm.expectRevert(InvalidVarint.selector);
        this.decodeVarintU64Wrapper(data, 3);
    }

    // ============ Strict Validation Tests ============

    /// @notice Test that non-canonical zero continuation is rejected
    /// @dev Matches Rust check: if byte == 0 && bits_read > 0
    /// @dev Simplified to: if bytesRead > 1 && b == 0
    function testRejectZeroContinuation() public {
        // Encoding [0x80, 0x00] represents value 0 in non-canonical form
        // Canonical form is just [0x00]
        bytes memory data = hex"8000";
        vm.expectRevert(InvalidVarint.selector);
        this.decodeVarintU64Wrapper(data, 0);
    }

    /// @notice Test that the simplified zero check works for 0x80 continuation too
    /// @dev This verifies that b == 0 catches both 0x00 and 0x80 cases correctly
    function testZeroCheckCatchesAllCases() public {
        // Case 1: [0x80, 0x00] - Zero byte, no continuation (caught)
        bytes memory data1 = hex"8000";
        vm.expectRevert(InvalidVarint.selector);
        this.decodeVarintU64Wrapper(data1, 0);

        // Case 2: [0x80, 0x80, 0x00] - Zero byte after two bytes (caught)
        bytes memory data2 = hex"808000";
        vm.expectRevert(InvalidVarint.selector);
        this.decodeVarintU64Wrapper(data2, 0);

        // Case 3: [0x00] - Single zero byte (valid - canonical encoding of 0)
        bytes memory data3 = hex"00";
        (uint64 value,) = this.decodeVarintU64Wrapper(data3, 0);
        assertEq(value, 0);
    }

    /// @notice Test that canonical zero encoding is accepted
    function testAcceptCanonicalZero() public {
        bytes memory data = hex"00";
        (uint64 value, uint256 offset) = this.decodeVarintU64Wrapper(data, 0);
        assertEq(value, 0);
        assertEq(offset, 1);
    }

    /// @notice Test that non-canonical encoding with trailing zero is rejected
    function testRejectTrailingZero() public {
        // Value 5 should be [0x05], not [0x85, 0x00]
        bytes memory data = hex"8500";
        vm.expectRevert(InvalidVarint.selector);
        this.decodeVarintU64Wrapper(data, 0);
    }

    /// @notice Test that 10th byte overflow is caught (value > 1 on last byte)
    /// @dev Matches Rust overflow check for remaining_bits
    function testReject10thByteOverflow() public {
        // 10 bytes where the last byte is 0x02 (needs 2 bits, but only 1 bit remains)
        // This would try to set bit 64, which doesn't exist in u64
        bytes memory data = hex"FFFFFFFFFFFFFFFFFF02";
        vm.expectRevert(InvalidVarint.selector);
        this.decodeVarintU64Wrapper(data, 0);
    }

    /// @notice Test that 10th byte with value 0x01 is accepted (u64::MAX)
    function testAccept10thByteValid() public {
        // u64::MAX = [0xFF]*9 + [0x01]
        bytes memory data = hex"FFFFFFFFFFFFFFFFFF01";
        (uint64 value, uint256 offset) = this.decodeVarintU64Wrapper(data, 0);
        assertEq(value, type(uint64).max);
        assertEq(offset, 10);
    }

    /// @notice Test that 10th byte with continuation bit set and value 0x81 is rejected
    function testReject10thByteContinuation() public {
        // Even with continuation bit, 0x81 has data bits that overflow
        bytes memory data = hex"FFFFFFFFFFFFFFFFFF81";
        vm.expectRevert(InvalidVarint.selector);
        this.decodeVarintU64Wrapper(data, 0);
    }

    /// @notice Test various non-canonical multi-byte encodings
    function testRejectVariousNonCanonical() public {
        // [0x80, 0x80, 0x00] for value 0
        bytes memory data1 = hex"808000";
        vm.expectRevert(InvalidVarint.selector);
        this.decodeVarintU64Wrapper(data1, 0);

        // [0xFF, 0x00] for value 127
        bytes memory data2 = hex"FF00";
        vm.expectRevert(InvalidVarint.selector);
        this.decodeVarintU64Wrapper(data2, 0);
    }

    // ============ JS Test Suite: Decode Varint - Passing Tests ============

    /// @notice JS test: "decode varint - value 300"
    function testDecodeVarint300() public {
        // Protobuf encoding of field 1 with value 300: 08ac02
        // 08 = field number 1, wire type 0
        // ac02 = varint encoding of 300
        bytes memory data = hex"08ac02";
        (uint64 value, uint256 offset) = this.decodeVarintU64Wrapper(data, 1); // Skip field key
        assertEq(value, 300, "Should decode 300");
        assertEq(offset, 3, "Position should be 3 (after field key + varint)");
    }

    /// @notice JS test: "decode varint - value 0"
    function testDecodeVarint0() public {
        bytes memory data = hex"00";
        (uint64 value, uint256 offset) = this.decodeVarintU64Wrapper(data, 0);
        assertEq(value, 0);
        assertEq(offset, 1);
    }

    /// @notice JS test: "decode varint - value 1"
    function testDecodeVarint1() public {
        bytes memory data = hex"01";
        (uint64 value, uint256 offset) = this.decodeVarintU64Wrapper(data, 0);
        assertEq(value, 1);
        assertEq(offset, 1);
    }

    /// @notice JS test: "decode varint - value 127 (max single byte)"
    function testDecodeVarint127() public {
        bytes memory data = hex"7F";
        (uint64 value, uint256 offset) = this.decodeVarintU64Wrapper(data, 0);
        assertEq(value, 127);
        assertEq(offset, 1);
    }

    /// @notice JS test: "decode varint - value 128 (min two bytes)"
    function testDecodeVarint128() public {
        bytes memory data = hex"8001";
        (uint64 value, uint256 offset) = this.decodeVarintU64Wrapper(data, 0);
        assertEq(value, 128);
        assertEq(offset, 2);
    }

    /// @notice JS test: "decode varint - large value (uint64 max)"
    function testDecodeVarintUint64Max() public {
        bytes memory data = hex"FFFFFFFFFFFFFFFFFF01";
        (uint64 value, uint256 offset) = this.decodeVarintU64Wrapper(data, 0);
        assertEq(value, type(uint64).max);
        assertEq(offset, 10);
    }

    // ============ JS Test Suite: Decode Varint - Failing Tests ============

    /// @notice JS test: "fail: varint index out of bounds"
    function testVarintIndexOutOfBounds() public {
        // 0x80 has continuation bit set but no next byte
        bytes memory data = hex"80";
        vm.expectRevert(InvalidVarint.selector);
        this.decodeVarintU64Wrapper(data, 0);
    }

    /// @notice JS test: "fail: varint trailing zeroes"
    function testVarintTrailingZeroes() public {
        // 0x8000 = value 0 with unnecessary continuation byte
        // This is non-canonical encoding
        bytes memory data = hex"8000";
        vm.expectRevert(InvalidVarint.selector);
        this.decodeVarintU64Wrapper(data, 0);
    }

    /// @notice JS test: "fail: varint more than 64 bits"
    function testVarintMoreThan64Bits() public {
        // 10 bytes of 0xFF with final 0x7F = exceeds 64 bits
        bytes memory data = hex"FFFFFFFFFFFFFFFFFF7F";
        vm.expectRevert(InvalidVarint.selector);
        this.decodeVarintU64Wrapper(data, 0);
    }

    /// @notice JS test: "fail: varint exceeds uint64 max"
    function testVarintExceedsUint64Max() public {
        // This encoding would represent a value > 2^64-1
        bytes memory data = hex"FFFFFFFFFFFFFFFFFFFF01";
        vm.expectRevert(InvalidVarint.selector);
        this.decodeVarintU64Wrapper(data, 0);
    }

    /// @notice JS test: "fail: empty buffer"
    function testEmptyBuffer() public {
        bytes memory data = "";
        vm.expectRevert(InvalidVarint.selector);
        this.decodeVarintU64Wrapper(data, 0);
    }

    // ============ JS Test Suite: Encode Varint - Passing Tests ============

    /// @notice JS test: "encode varint - value 300"
    function testEncodeVarint300() public {
        bytes memory encoded = encodeVarintU64(300);
        assertEq(encoded, hex"ac02", "300 should encode to ac02");
    }

    /// @notice JS test: "encode varint - value 0"
    function testEncodeVarint0() public {
        bytes memory encoded = encodeVarintU64(0);
        assertEq(encoded, hex"00", "0 should encode to 00");
    }

    /// @notice JS test: "encode varint - value 1"
    function testEncodeVarint1() public {
        bytes memory encoded = encodeVarintU64(1);
        assertEq(encoded, hex"01", "1 should encode to 01");
    }

    /// @notice JS test: "encode varint - value 127 (max single byte)"
    function testEncodeVarint127() public {
        bytes memory encoded = encodeVarintU64(127);
        assertEq(encoded, hex"7f", "127 should encode to 7f");
    }

    /// @notice JS test: "encode varint - value 128 (min two bytes)"
    function testEncodeVarint128() public {
        bytes memory encoded = encodeVarintU64(128);
        assertEq(encoded, hex"8001", "128 should encode to 8001");
    }

    /// @notice JS test: "encode varint - value 16383 (max two bytes)"
    function testEncodeVarint16383() public {
        bytes memory encoded = encodeVarintU64(16383);
        assertEq(encoded, hex"ff7f", "16383 should encode to ff7f");
    }

    /// @notice JS test: "encode varint - value 16384 (min three bytes)"
    function testEncodeVarint16384() public {
        bytes memory encoded = encodeVarintU64(16384);
        assertEq(encoded, hex"808001", "16384 should encode to 808001");
    }

    /// @notice JS test: "encode varint - large value (uint64 max)"
    function testEncodeVarintUint64Max() public {
        bytes memory encoded = encodeVarintU64(type(uint64).max);
        assertEq(encoded, hex"ffffffffffffffffff01", "uint64 max should encode correctly");
    }

    // ============ JS Test Suite: Roundtrip Tests ============

    /// @notice JS test: "roundtrip: value 0"
    function testRoundtripValue0() public {
        bytes memory encoded = encodeVarintU64(0);
        (uint64 decoded, uint256 offset) = this.decodeVarintU64Wrapper(encoded, 0);
        assertEq(decoded, 0);
        assertEq(offset, encoded.length);
    }

    /// @notice JS test: "roundtrip: value 1"
    function testRoundtripValue1() public {
        bytes memory encoded = encodeVarintU64(1);
        (uint64 decoded, uint256 offset) = this.decodeVarintU64Wrapper(encoded, 0);
        assertEq(decoded, 1);
        assertEq(offset, encoded.length);
    }

    /// @notice JS test: "roundtrip: value 127"
    function testRoundtripValue127() public {
        bytes memory encoded = encodeVarintU64(127);
        (uint64 decoded, uint256 offset) = this.decodeVarintU64Wrapper(encoded, 0);
        assertEq(decoded, 127);
        assertEq(offset, encoded.length);
    }

    /// @notice JS test: "roundtrip: value 128"
    function testRoundtripValue128() public {
        bytes memory encoded = encodeVarintU64(128);
        (uint64 decoded, uint256 offset) = this.decodeVarintU64Wrapper(encoded, 0);
        assertEq(decoded, 128);
        assertEq(offset, encoded.length);
    }

    /// @notice JS test: "roundtrip: value 300"
    function testRoundtripValue300() public {
        bytes memory encoded = encodeVarintU64(300);
        (uint64 decoded, uint256 offset) = this.decodeVarintU64Wrapper(encoded, 0);
        assertEq(decoded, 300);
        assertEq(offset, encoded.length);
    }

    /// @notice JS test: "roundtrip: value 16383"
    function testRoundtripValue16383() public {
        bytes memory encoded = encodeVarintU64(16383);
        (uint64 decoded, uint256 offset) = this.decodeVarintU64Wrapper(encoded, 0);
        assertEq(decoded, 16383);
        assertEq(offset, encoded.length);
    }

    /// @notice JS test: "roundtrip: value 16384"
    function testRoundtripValue16384() public {
        bytes memory encoded = encodeVarintU64(16384);
        (uint64 decoded, uint256 offset) = this.decodeVarintU64Wrapper(encoded, 0);
        assertEq(decoded, 16384);
        assertEq(offset, encoded.length);
    }

    /// @notice JS test: "roundtrip: large value (uint32 max)"
    function testRoundtripValueUint32Max() public {
        bytes memory encoded = encodeVarintU64(type(uint32).max);
        (uint64 decoded, uint256 offset) = this.decodeVarintU64Wrapper(encoded, 0);
        assertEq(decoded, type(uint32).max);
        assertEq(offset, encoded.length);
    }

    /// @notice JS test: "roundtrip: large value (uint64 max)"
    function testRoundtripValueUint64Max() public {
        bytes memory encoded = encodeVarintU64(type(uint64).max);
        (uint64 decoded, uint256 offset) = this.decodeVarintU64Wrapper(encoded, 0);
        assertEq(decoded, type(uint64).max);
        assertEq(offset, encoded.length);
    }

    // ============ Specific Value Tests (matching Rust conformity tests) ============

    /// @notice Test specific encoded values match expected bytes
    function testConformityValues() public {
        // From Rust test_conformity (codec/src/varint.rs:517)

        // 0 encodes as [0x00]
        bytes memory encoded = encodeVarintU64(0);
        assertEq(encoded, hex"00");

        // 1 encodes as [0x01]
        encoded = encodeVarintU64(1);
        assertEq(encoded, hex"01");

        // 127 encodes as [0x7F]
        encoded = encodeVarintU64(127);
        assertEq(encoded, hex"7F");

        // 128 encodes as [0x80, 0x01]
        encoded = encodeVarintU64(128);
        assertEq(encoded, hex"8001");

        // 16383 encodes as [0xFF, 0x7F]
        encoded = encodeVarintU64(16383);
        assertEq(encoded, hex"FF7F");

        // 16384 encodes as [0x80, 0x80, 0x01]
        encoded = encodeVarintU64(16384);
        assertEq(encoded, hex"808001");

        // 2097151 encodes as [0xFF, 0xFF, 0x7F]
        encoded = encodeVarintU64(2097151);
        assertEq(encoded, hex"FFFF7F");

        // 2097152 encodes as [0x80, 0x80, 0x80, 0x01]
        encoded = encodeVarintU64(2097152);
        assertEq(encoded, hex"80808001");

        // u32::MAX encodes as [0xFF, 0xFF, 0xFF, 0xFF, 0x0F]
        encoded = encodeVarintU64(type(uint32).max);
        assertEq(encoded, hex"FFFFFFFF0F");
    }

    // ============ Fuzz Tests ============

    /// @notice Fuzz test for round-trip encoding/decoding
    /// @param value Any u64 value to test
    function testFuzzRoundTrip(uint64 value) public {
        testRoundTrip(value);
    }

    /// @notice Fuzz test for proper length calculation
    /// @param value Any u64 value to test
    function testFuzzEncodingLength(uint64 value) public {
        bytes memory encoded = encodeVarintU64(value);

        // Calculate expected length based on number of bits
        uint256 bits = 64 - countLeadingZeros(value);
        if (bits == 0) bits = 1; // Special case for 0
        uint256 expectedLength = (bits + 6) / 7; // Ceiling division by 7

        assertEq(encoded.length, expectedLength, "Encoding length mismatch");
    }

    /// @notice Helper function to count leading zeros in a u64
    function countLeadingZeros(uint64 value) internal pure returns (uint256) {
        if (value == 0) return 64;

        uint256 count = 0;
        uint64 mask = 0x8000000000000000;

        while ((value & mask) == 0) {
            count++;
            mask >>= 1;
        }

        return count;
    }
}

/**
 * TEST COVERAGE SUMMARY
 * =====================
 *
 * This test suite provides comprehensive coverage matching both:
 * 1. JavaScript test suite (varint-tests-complete.js)
 * 2. Rust test suite (commonware_codec/src/varint.rs)
 *
 * Total Test Categories:
 * - Basic Value Tests: Single/multi-byte values
 * - JS Decode Tests (Passing): 6 tests
 * - JS Decode Tests (Failing): 6 tests
 * - JS Encode Tests (Passing): 8 tests
 * - JS Roundtrip Tests: 9 tests
 * - Rust Test Case Roundtrips: 15 values
 * - Strict Validation Tests: Non-canonical encoding rejection
 * - Conformity Tests: Exact byte pattern verification
 * - Edge Case Tests: Offsets, sequences, boundaries
 * - Fuzz Tests: Property-based testing
 *
 * Key Test Coverage:
 * ------------------
 *
 * DECODE TESTS:
 * ✓ Value 0 (single byte: 0x00)
 * ✓ Value 1 (single byte: 0x01)
 * ✓ Value 127 (max single byte: 0x7F)
 * ✓ Value 128 (min two bytes: 0x8001)
 * ✓ Value 300 (two bytes: 0xac02)
 * ✓ Value uint64::MAX (10 bytes: 0xFFFFFFFFFFFFFFFF01)
 * ✓ Decode with offset (field key prefix)
 * ✓ Multiple varints in sequence
 *
 * ERROR CASES:
 * ✓ Empty input buffer
 * ✓ Offset out of bounds
 * ✓ Reading past buffer end
 * ✓ Incomplete varint (continuation bit but no next byte)
 * ✓ Shift overflow (exceeds 64 bits)
 * ✓ Non-canonical zero continuation (0x8000)
 * ✓ Trailing zero bytes (0x8500)
 * ✓ 10th byte overflow (value > uint64::MAX)
 * ✓ More than 64 bits encoded
 *
 * ENCODE TESTS:
 * ✓ Value 0 → 0x00
 * ✓ Value 1 → 0x01
 * ✓ Value 127 → 0x7f
 * ✓ Value 128 → 0x8001
 * ✓ Value 300 → 0xac02
 * ✓ Value 16383 → 0xff7f (max 2 bytes)
 * ✓ Value 16384 → 0x808001 (min 3 bytes)
 * ✓ Value uint64::MAX → 0xffffffffffffffffff01
 *
 * ROUNDTRIP TESTS:
 * ✓ All boundary values: 0, 1, 127, 128, 300, 16383, 16384
 * ✓ Type maximums: uint16::MAX, uint32::MAX, uint64::MAX
 * ✓ Rust test suite values: 131071, 16777215, 8589934591
 *
 * VALIDATION TESTS:
 * ✓ Canonical zero (0x00) accepted
 * ✓ Non-canonical zero (0x8000) rejected
 * ✓ Various non-canonical encodings rejected
 * ✓ 10th byte with value 0x01 accepted (uint64::MAX)
 * ✓ 10th byte with value 0x02 rejected (overflow)
 * ✓ 10th byte with continuation bit rejected
 *
 * CONFORMITY TESTS:
 * ✓ Exact byte patterns match protobuf specification
 * ✓ Encoding produces canonical (minimal) representation
 * ✓ No unnecessary continuation bytes
 *
 * FUZZ TESTS:
 * ✓ Round-trip property for all uint64 values
 * ✓ Encoding length calculation correctness
 *
 * This test suite ensures that the Solidity varint implementation:
 * 1. Is compatible with protobuf3 varint encoding
 * 2. Rejects all non-canonical encodings
 * 3. Handles all edge cases and boundary conditions
 * 4. Matches behavior of the Rust reference implementation
 * 5. Produces minimal (canonical) encodings
 */