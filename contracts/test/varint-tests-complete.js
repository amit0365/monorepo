/**
 * Direct Varint Test Cases Only
 * Extracted from protobuf3-solidity-lib test suite
 *
 * This file contains ONLY the direct varint encoding/decoding tests,
 * not the higher-level types (int32, uint64, bool, etc.) that use varint internally.
 */

const BN = web3.utils.BN;
const protobuf = require("protobufjs/light");
const TestFixture = artifacts.require("TestFixture");

contract("Direct Varint Tests Only", async (accounts) => {

  // ============================================================================
  // PROTOBUFJS VARINT BEHAVIOR
  // ============================================================================

  describe("protobufjs varint behavior", async () => {

    it("protobufjs encoding - basic varint", async () => {
      const Message = new protobuf.Type("Message").add(new protobuf.Field("field", 1, "uint64"));
      const message = Message.create({ field: 300 });
      const encoded = Message.encode(message).finish().toString("hex");

      // field 1 -> 08 (field number 1, wire type 0)
      // 300 -> ac 02 (varint encoding)
      assert.equal(encoded, "08ac02");
    });

    it("protobufjs not bijective - accepts non-canonical varint", async () => {
      // Show protobufjs is not bijective - it accepts non-canonical encodings
      const Message = new protobuf.Type("Message").add(new protobuf.Field("field", 1, "uint64"));
      const decoded = Message.decode(Buffer.from("08FFFFFFFFFFFFFFFFFF7F", "hex"));
      const field = decoded.toJSON().field;

      assert.equal(field, "18446744073709551615");
    });

    it("protobufjs accepts extra bytes in varint", async () => {
      // Show protobufjs accepts up to 8 bytes for 4-byte ints
      const Message = new protobuf.Type("Message").add(new protobuf.Field("field", 1, "uint32"));
      const decoded = Message.decode(Buffer.from("08FFFFFFFFFFFFFFFFFF01", "hex"));
      const field = decoded.toJSON().field;

      assert.equal(field, "4294967295");
    });
  });

  // ============================================================================
  // DECODE VARINT - PASSING TESTS
  // ============================================================================

  describe("decode_varint - passing", async () => {

    it("decode varint - value 300", async () => {
      const instance = await TestFixture.new();

      const Message = new protobuf.Type("Message").add(new protobuf.Field("field", 1, "uint64"));
      const message = Message.create({ field: 300 });
      const encoded = Message.encode(message).finish().toString("hex");

      // Call the decode_varint function
      const result = await instance.decode_varint.call(1, "0x" + encoded);
      const { 0: success, 1: pos, 2: val } = result;

      // Assertions
      assert.equal(success, true, "Should successfully decode");
      assert.equal(pos, 3, "Position should be 3 (after field key + varint)");
      assert.equal(val, 300, "Decoded value should be 300");

      // Actually execute the transaction (for gas measurement)
      await instance.decode_varint(1, "0x" + encoded);
    });

    it("decode varint - value 0", async () => {
      const instance = await TestFixture.new();

      const Message = new protobuf.Type("Message").add(new protobuf.Field("field", 1, "uint64"));
      const message = Message.create({ field: 0 });
      const encoded = Message.encode(message).finish().toString("hex");

      const result = await instance.decode_varint.call(1, "0x" + encoded);
      const { 0: success, 1: pos, 2: val } = result;

      assert.equal(success, true);
      assert.equal(val, 0);

      await instance.decode_varint(1, "0x" + encoded);
    });

    it("decode varint - value 1", async () => {
      const instance = await TestFixture.new();

      const Message = new protobuf.Type("Message").add(new protobuf.Field("field", 1, "uint64"));
      const message = Message.create({ field: 1 });
      const encoded = Message.encode(message).finish().toString("hex");

      const result = await instance.decode_varint.call(1, "0x" + encoded);
      const { 0: success, 1: pos, 2: val } = result;

      assert.equal(success, true);
      assert.equal(val, 1);

      await instance.decode_varint(1, "0x" + encoded);
    });

    it("decode varint - value 127 (max single byte)", async () => {
      const instance = await TestFixture.new();

      const Message = new protobuf.Type("Message").add(new protobuf.Field("field", 1, "uint64"));
      const message = Message.create({ field: 127 });
      const encoded = Message.encode(message).finish().toString("hex");

      const result = await instance.decode_varint.call(1, "0x" + encoded);
      const { 0: success, 1: pos, 2: val } = result;

      assert.equal(success, true);
      assert.equal(val, 127);

      await instance.decode_varint(1, "0x" + encoded);
    });

    it("decode varint - value 128 (min two bytes)", async () => {
      const instance = await TestFixture.new();

      const Message = new protobuf.Type("Message").add(new protobuf.Field("field", 1, "uint64"));
      const message = Message.create({ field: 128 });
      const encoded = Message.encode(message).finish().toString("hex");

      const result = await instance.decode_varint.call(1, "0x" + encoded);
      const { 0: success, 1: pos, 2: val } = result;

      assert.equal(success, true);
      assert.equal(val, 128);

      await instance.decode_varint(1, "0x" + encoded);
    });

    it("decode varint - large value (uint64 max)", async () => {
      const instance = await TestFixture.new();

      const v = "18446744073709551615"; // 2^64 - 1

      const Message = new protobuf.Type("Message").add(new protobuf.Field("field", 1, "uint64"));
      const message = Message.create({ field: v });
      const encoded = Message.encode(message).finish().toString("hex");

      const result = await instance.decode_varint.call(1, "0x" + encoded);
      const { 0: success, 1: pos, 2: val } = result;

      assert.equal(success, true);
      assert.equal(val.toString(), v);

      await instance.decode_varint(1, "0x" + encoded);
    });
  });

  // ============================================================================
  // DECODE VARINT - FAILING TESTS
  // ============================================================================

  describe("decode_varint - failing", async () => {

    it("fail: varint index out of bounds", async () => {
      const instance = await TestFixture.new();

      // 0x80 has continuation bit set but no next byte
      const result = await instance.decode_varint.call(0, "0x80");
      const { 0: success, 1: pos, 2: val } = result;

      assert.equal(success, false, "Should fail - incomplete varint");
    });

    it("fail: varint trailing zeroes", async () => {
      const instance = await TestFixture.new();

      // 0x8000 = value 0 with unnecessary continuation byte
      // This is non-canonical encoding
      const result = await instance.decode_varint.call(0, "0x8000");
      const { 0: success, 1: pos, 2: val } = result;

      assert.equal(success, false, "Should fail - non-canonical encoding");
    });

    it("fail: varint more than 64 bits", async () => {
      const instance = await TestFixture.new();

      // 10 bytes of 0xFF with final 0x7F = exceeds 64 bits
      const result = await instance.decode_varint.call(0, "0xFFFFFFFFFFFFFFFFFF7F");
      const { 0: success, 1: pos, 2: val } = result;

      assert.equal(success, false, "Should fail - exceeds 64 bits");
    });

    it("fail: varint exceeds uint64 max", async () => {
      const instance = await TestFixture.new();

      // This encoding would represent a value > 2^64-1
      const result = await instance.decode_varint.call(0, "0xFFFFFFFFFFFFFFFFFFFF01");
      const { 0: success, 1: pos, 2: val } = result;

      assert.equal(success, false, "Should fail - value overflow");
    });

    it("fail: empty buffer", async () => {
      const instance = await TestFixture.new();

      const result = await instance.decode_varint.call(0, "0x");
      const { 0: success, 1: pos, 2: val } = result;

      assert.equal(success, false, "Should fail - empty buffer");
    });

    it("fail: reading past buffer end", async () => {
      const instance = await TestFixture.new();

      // Try to read varint starting at position 5 in a 2-byte buffer
      const result = await instance.decode_varint.call(5, "0x0102");
      const { 0: success, 1: pos, 2: val } = result;

      assert.equal(success, false, "Should fail - position out of bounds");
    });
  });

  // ============================================================================
  // ENCODE VARINT - PASSING TESTS
  // ============================================================================

  describe("encode_varint - passing", async () => {

    it("encode varint - value 300", async () => {
      const instance = await TestFixture.new();

      const v = 300;

      const Message = new protobuf.Type("Message").add(new protobuf.Field("field", 1, "uint64"));
      const message = Message.create({ field: v });
      const encoded = Message.encode(message).finish().toString("hex");

      // Call the encode_varint function
      const result = await instance.encode_varint.call(v);

      // The result should match protobufjs encoding (without the field key)
      assert.equal(result, "0x" + encoded.slice(2));

      // Actually execute the transaction (for gas measurement)
      await instance.encode_varint(v);
    });

    it("encode varint - value 0", async () => {
      const instance = await TestFixture.new();

      const v = 0;

      const Message = new protobuf.Type("Message").add(new protobuf.Field("field", 1, "uint64"));
      const message = Message.create({ field: v });
      const encoded = Message.encode(message).finish().toString("hex");

      const result = await instance.encode_varint.call(v);
      assert.equal(result, "0x" + encoded.slice(2));
      assert.equal(result, "0x00");

      await instance.encode_varint(v);
    });

    it("encode varint - value 1", async () => {
      const instance = await TestFixture.new();

      const v = 1;

      const Message = new protobuf.Type("Message").add(new protobuf.Field("field", 1, "uint64"));
      const message = Message.create({ field: v });
      const encoded = Message.encode(message).finish().toString("hex");

      const result = await instance.encode_varint.call(v);
      assert.equal(result, "0x" + encoded.slice(2));
      assert.equal(result, "0x01");

      await instance.encode_varint(v);
    });

    it("encode varint - value 127 (max single byte)", async () => {
      const instance = await TestFixture.new();

      const v = 127;

      const Message = new protobuf.Type("Message").add(new protobuf.Field("field", 1, "uint64"));
      const message = Message.create({ field: v });
      const encoded = Message.encode(message).finish().toString("hex");

      const result = await instance.encode_varint.call(v);
      assert.equal(result, "0x" + encoded.slice(2));
      assert.equal(result, "0x7f");

      await instance.encode_varint(v);
    });

    it("encode varint - value 128 (min two bytes)", async () => {
      const instance = await TestFixture.new();

      const v = 128;

      const Message = new protobuf.Type("Message").add(new protobuf.Field("field", 1, "uint64"));
      const message = Message.create({ field: v });
      const encoded = Message.encode(message).finish().toString("hex");

      const result = await instance.encode_varint.call(v);
      assert.equal(result, "0x" + encoded.slice(2));
      assert.equal(result, "0x8001");

      await instance.encode_varint(v);
    });

    it("encode varint - value 16383 (max two bytes)", async () => {
      const instance = await TestFixture.new();

      const v = 16383; // 0b11111111111111 = 2^14 - 1

      const Message = new protobuf.Type("Message").add(new protobuf.Field("field", 1, "uint64"));
      const message = Message.create({ field: v });
      const encoded = Message.encode(message).finish().toString("hex");

      const result = await instance.encode_varint.call(v);
      assert.equal(result, "0x" + encoded.slice(2));

      await instance.encode_varint(v);
    });

    it("encode varint - value 16384 (min three bytes)", async () => {
      const instance = await TestFixture.new();

      const v = 16384; // 2^14

      const Message = new protobuf.Type("Message").add(new protobuf.Field("field", 1, "uint64"));
      const message = Message.create({ field: v });
      const encoded = Message.encode(message).finish().toString("hex");

      const result = await instance.encode_varint.call(v);
      assert.equal(result, "0x" + encoded.slice(2));

      await instance.encode_varint(v);
    });

    it("encode varint - large value (uint64 max)", async () => {
      const instance = await TestFixture.new();

      const v = "18446744073709551615"; // 2^64 - 1

      const Message = new protobuf.Type("Message").add(new protobuf.Field("field", 1, "uint64"));
      const message = Message.create({ field: v });
      const encoded = Message.encode(message).finish().toString("hex");

      const result = await instance.encode_varint.call(v);
      assert.equal(result, "0x" + encoded.slice(2));

      await instance.encode_varint(v);
    });
  });

  // ============================================================================
  // ROUNDTRIP TESTS
  // ============================================================================

  describe("encode/decode roundtrip", async () => {

    it("roundtrip: value 0", async () => {
      const instance = await TestFixture.new();
      const v = 0;

      const encoded = await instance.encode_varint.call(v);
      const decoded = await instance.decode_varint.call(0, encoded);

      assert.equal(decoded[0], true); // success
      assert.equal(decoded[2], v); // value
    });

    it("roundtrip: value 1", async () => {
      const instance = await TestFixture.new();
      const v = 1;

      const encoded = await instance.encode_varint.call(v);
      const decoded = await instance.decode_varint.call(0, encoded);

      assert.equal(decoded[0], true);
      assert.equal(decoded[2], v);
    });

    it("roundtrip: value 127", async () => {
      const instance = await TestFixture.new();
      const v = 127;

      const encoded = await instance.encode_varint.call(v);
      const decoded = await instance.decode_varint.call(0, encoded);

      assert.equal(decoded[0], true);
      assert.equal(decoded[2], v);
    });

    it("roundtrip: value 128", async () => {
      const instance = await TestFixture.new();
      const v = 128;

      const encoded = await instance.encode_varint.call(v);
      const decoded = await instance.decode_varint.call(0, encoded);

      assert.equal(decoded[0], true);
      assert.equal(decoded[2], v);
    });

    it("roundtrip: value 300", async () => {
      const instance = await TestFixture.new();
      const v = 300;

      const encoded = await instance.encode_varint.call(v);
      const decoded = await instance.decode_varint.call(0, encoded);

      assert.equal(decoded[0], true);
      assert.equal(decoded[2], v);
    });

    it("roundtrip: value 16383", async () => {
      const instance = await TestFixture.new();
      const v = 16383;

      const encoded = await instance.encode_varint.call(v);
      const decoded = await instance.decode_varint.call(0, encoded);

      assert.equal(decoded[0], true);
      assert.equal(decoded[2], v);
    });

    it("roundtrip: value 16384", async () => {
      const instance = await TestFixture.new();
      const v = 16384;

      const encoded = await instance.encode_varint.call(v);
      const decoded = await instance.decode_varint.call(0, encoded);

      assert.equal(decoded[0], true);
      assert.equal(decoded[2], v);
    });

    it("roundtrip: large value (uint32 max)", async () => {
      const instance = await TestFixture.new();
      const v = 4294967295; // 2^32 - 1

      const encoded = await instance.encode_varint.call(v);
      const decoded = await instance.decode_varint.call(0, encoded);

      assert.equal(decoded[0], true);
      assert.equal(decoded[2].toString(), v.toString());
    });

    it("roundtrip: large value (uint64 max)", async () => {
      const instance = await TestFixture.new();
      const v = "18446744073709551615"; // 2^64 - 1

      const encoded = await instance.encode_varint.call(v);
      const decoded = await instance.decode_varint.call(0, encoded);

      assert.equal(decoded[0], true);
      assert.equal(decoded[2].toString(), v);
    });
  });
});

/**
 * TEST SUMMARY
 * ============
 *
 * Total Direct Varint Tests: 35
 *
 * Breakdown:
 * - Protobufjs Varint Behavior: 3
 * - Decode Varint (Passing): 6
 * - Decode Varint (Failing): 6
 * - Encode Varint (Passing): 8
 * - Encode/Decode Roundtrip: 9
 *
 * VARINT ENCODING EXPLAINED
 * =========================
 *
 * Varint is a variable-length encoding for unsigned integers.
 *
 * Format Rules:
 * 1. Each byte uses 7 bits for data and 1 bit (MSB) for continuation
 * 2. MSB = 1 means "more bytes follow"
 * 3. MSB = 0 means "this is the last byte"
 * 4. Values are encoded in little-endian order (LSB first)
 * 5. Only canonical encodings are valid (no unnecessary leading bytes)
 *
 * Size Ranges:
 * - 1 byte:  0 to 127 (2^7 - 1)
 * - 2 bytes: 128 to 16383 (2^14 - 1)
 * - 3 bytes: 16384 to 2097151 (2^21 - 1)
 * - ...
 * - 10 bytes max for 64-bit values
 *
 * Example: Encoding 300
 *
 * Step 1: Convert to binary
 *   300 = 0b100101100
 *
 * Step 2: Split into 7-bit chunks (right to left)
 *   0b100101100
 *   = 0b0000010 | 0b0101100
 *
 * Step 3: Reverse order (little-endian)
 *   0b0101100 | 0b0000010
 *
 * Step 4: Add continuation bits
 *   First byte (has more): 0b1_0101100 = 0xAC
 *   Last byte (no more):   0b0_0000010 = 0x02
 *
 * Result: 0xAC02
 *
 * Decoding 0xAC02:
 *
 * Step 1: Check continuation bits
 *   0xAC = 0b10101100 -> MSB=1, value=0b0101100
 *   0x02 = 0b00000010 -> MSB=0, value=0b0000010
 *
 * Step 2: Combine (little-endian)
 *   0b0000010_0101100
 *   = 0b100101100
 *   = 300
 *
 * VALIDATION RULES
 * ================
 *
 * The Solidity implementation enforces strict validation:
 *
 * 1. No trailing zeros (non-canonical encoding)
 *    ❌ 0x8000 (encodes 0 with unnecessary byte)
 *    ✅ 0x00 (canonical encoding of 0)
 *
 * 2. Maximum 10 bytes for 64-bit values
 *    ❌ 0xFFFFFFFFFFFFFFFFFF7F (10 bytes, valid length)
 *    ❌ 0xFFFFFFFFFFFFFFFFFFFF01 (11 bytes, invalid)
 *
 * 3. No overflow beyond uint64
 *    ❌ 0xFFFFFFFFFFFFFFFFFFFF01 (value > 2^64-1)
 *    ✅ 0xFFFFFFFFFFFFFFFFFF01 (value = 2^64-1, canonical)
 *
 * 4. Must have complete bytes
 *    ❌ 0x80 (continuation bit set but no next byte)
 *    ✅ 0x8001 (complete 2-byte encoding of 128)
 */
