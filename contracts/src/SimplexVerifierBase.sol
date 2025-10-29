// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title SimplexVerifierBase
/// @notice Abstract base contract for Simplex consensus proof verification
/// @dev Provides shared structures and deserialization logic across all signing schemes
/// @dev Concrete implementations handle scheme-specific signature formats
abstract contract SimplexVerifierBase {
    // ============ Constants ============

    uint256 internal constant DIGEST_LENGTH = 32;

    // Varint decoding constants (LEB128 format)
    uint8 internal constant DATA_BITS_MASK = 0x7F;        // 0111_1111 - Extract 7 data bits
    uint8 internal constant CONTINUATION_BIT_MASK = 0x80; // 1000_0000 - Check continuation bit
    uint256 internal constant DATA_BITS_PER_BYTE = 7;     // Number of data bits per byte
    uint256 internal constant MAX_U64_BITS = 64;          // Maximum bits in u64
    uint256 internal constant U64_LAST_BYTE_SHIFT = 63;   // Shift value for 10th byte (9*7=63)

    // ============ Errors ============

    error InvalidProofLength();
    error InvalidVarint();
    error InvalidBitmapTrailingBits();
    error InvalidBitmapSignatureCount();
    error TooManySigners();
    error Conflicting_EpochMismatch();
    error Conflicting_ViewMismatch();
    error Conflicting_SignerMismatch();
    error Conflicting_ProposalsMustDiffer();

    // ============ Structs ============

    /// @notice Round is a tuple of (Epoch, View)
    /// @dev Rust: pub struct Round(Epoch, View) where Epoch = u64, View = u64
    /// @dev Write impl (consensus/src/types.rs:55-59):
    ///      self.epoch().write(buf);  // 8 bytes big-endian
    ///      self.view().write(buf);   // 8 bytes big-endian
    struct Round {
        uint64 epoch;
        uint64 viewCounter;  // 'view' renamed to avoid Solidity keyword conflict
    }

    /// @notice Proposal contains a Round, parent View, and payload Digest
    /// @dev Rust: pub struct Proposal<D: Digest> { round: Round, parent: View, payload: D }
    /// @dev Write impl (consensus/src/simplex/types.rs:812-817):
    ///      self.round.write(writer);           // 16 bytes (Round)
    ///      UInt(self.parent).write(writer);    // varint (parent view)
    ///      self.payload.write(writer);         // 32 bytes (SHA256 digest)
    struct Proposal {
        Round round;
        uint64 parent;
        bytes32 payload;
    }

    // ============ Shared Helper Functions ============

    /// @notice Decode a varint-encoded u64 (LEB128 format)
    /// @dev Used for: parent view, epoch, view counter
    /// @dev Rust uses varint via UInt wrapper (commonware_codec::varint::UInt)
    /// @dev Implements strict canonical encoding validation matching Rust implementation
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

    /// @notice Deserialize a Round
    /// @dev Rust Read impl (consensus/src/types.rs:47-52):
    ///      Ok(Self(Epoch::read(buf)?, View::read(buf)?))
    /// @dev Epoch and View both use u64::read() which is 8 bytes big-endian
    function deserializeRound(bytes calldata data, uint256 offset)
        internal pure returns (Round memory round, uint256 newOffset)
    {
        if (offset + 16 > data.length) revert InvalidProofLength();

        // Read epoch: 8 bytes big-endian (primitives.rs:54)
        round.epoch = uint64(bytes8(data[offset:offset+8]));
        // Read view: 8 bytes big-endian (primitives.rs:54)
        round.viewCounter = uint64(bytes8(data[offset+8:offset+16]));

        return (round, offset + 16);
    }

    /// @notice Deserialize a Proposal
    /// @dev Rust Write impl (consensus/src/simplex/types.rs:812-817):
    ///      self.round.write(writer);           // Round (16 bytes)
    ///      UInt(self.parent).write(writer);    // varint
    ///      self.payload.write(writer);         // Digest (32 bytes) - fixed for now
    function deserializeProposal(bytes calldata data, uint256 offset)
        internal pure returns (Proposal memory proposal, uint256 newOffset)
    {
        // Read Round (16 bytes fixed)
        (proposal.round, offset) = deserializeRound(data, offset);

        // Read parent (varint u64)
        (proposal.parent, offset) = decodeVarintU64(data, offset);

        // Read payload digest (32 bytes fixed)
        if (offset + DIGEST_LENGTH > data.length) revert InvalidProofLength();
        proposal.payload = bytes32(data[offset:offset+DIGEST_LENGTH]);
        offset += DIGEST_LENGTH;

        return (proposal, offset);
    }

    // ============ Validation Helpers ============

    /// @notice Validate that two rounds are identical
    function validateRoundsMatch(Round memory r1, Round memory r2) internal pure {
        if (r1.epoch != r2.epoch) revert Conflicting_EpochMismatch();
        if (r1.viewCounter != r2.viewCounter) revert Conflicting_ViewMismatch();
    }

    /// @notice Validate that two proposals differ
    function validateProposalsDiffer(Proposal memory p1, Proposal memory p2) internal pure {
        if (keccak256(abi.encode(p1)) == keccak256(abi.encode(p2))) {
            revert Conflicting_ProposalsMustDiffer();
        }
    }
}
