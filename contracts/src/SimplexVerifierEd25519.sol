// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./SimplexVerifierBase.sol";

/// @title SimplexVerifierEd25519
/// @notice Ed25519 signing scheme implementation for Simplex consensus proofs
/// @dev Handles individual Ed25519 signatures (64 bytes each)
/// @dev This is an ATTRIBUTABLE scheme - individual signatures can prove liveness/faults
/// @dev See: consensus/src/simplex/signing_scheme/ed25519.rs
contract SimplexVerifierEd25519 is SimplexVerifierBase {
    // ============ Constants ============

    uint256 constant ED25519_SIGNATURE_LENGTH = 64;

    // ============ Structs ============

    /// @notice Vote contains a signer index and Ed25519 signature
    /// @dev Rust: pub struct Vote<S: Scheme> { signer: u32, signature: S::Signature }
    /// @dev Write impl (consensus/src/simplex/types.rs:103-107):
    ///      self.signer.write(writer);      // 4 bytes big-endian u32
    ///      self.signature.write(writer);   // 64 bytes (Ed25519)
    struct Vote {
        uint32 signer;
        bytes signature;  // 64 bytes, raw signature bytes , we do not reconstruct the rust struct here
    }

    /// @notice Certificate formed by collecting Ed25519 signatures plus their signer indices
    /// @dev Rust: pub struct Certificate { signers: Signers, signatures: Vec<Ed25519Signature> }
    /// @dev Rust impl: consensus/src/simplex/signing_scheme/ed25519.rs:102-107
    /// @dev Write impl (ed25519.rs:110-114):
    ///      self.signers.write(writer);     // Bitmap (u64 length + bytes)
    ///      self.signatures.write(writer);  // Vec<Signature> (varint count + 64 bytes each)
    struct Certificate {
        bytes signersBitmap;      // Bitmap of validator indices that signed
        bytes[] signatures;       // Ed25519 signatures ordered by signer index
    }

    /// @notice Notarization certificate (quorum of Notarize votes on a proposal)
    /// @dev Rust: pub struct Notarization<S: Scheme, D: Digest> { proposal: Proposal<D>, certificate: S::Certificate }
    /// @dev For Ed25519: Certificate = { signers: Signers, signatures: Vec<Ed25519Signature> }
    struct Notarization {
        Proposal proposal;
        Certificate certificate;
    }

    /// @notice Nullification certificate (quorum of Nullify votes on a round)
    /// @dev Rust: pub struct Nullification<S: Scheme> { round: Round, certificate: S::Certificate }
    /// @dev For Ed25519: Certificate = { signers: Signers, signatures: Vec<Ed25519Signature> }
    struct Nullification {
        Round round;
        Certificate certificate;
    }

    /// @notice Finalization certificate (quorum of Finalize votes on a proposal)
    /// @dev Rust: pub struct Finalization<S: Scheme, D: Digest> { proposal: Proposal<D>, certificate: S::Certificate }
    /// @dev For Ed25519: Certificate = { signers: Signers, signatures: Vec<Ed25519Signature> }
    struct Finalization {
        Proposal proposal;
        Certificate certificate;
    }

    // ============ Vote Deserialization ============

    /// @notice Deserialize a single Ed25519 vote
    /// @dev Rust Write impl (consensus/src/simplex/types.rs:103-107)
    function deserializeVote(bytes calldata data, uint256 offset)
        internal pure returns (Vote memory vote, uint256 newOffset)
    {
        // Read signer: 4 bytes big-endian (primitives.rs:53)
        if (offset + 4 > data.length) revert InvalidProofLength();
        vote.signer = uint32(bytes4(data[offset:offset+4]));
        offset += 4; 

        // Read Ed25519 signature: 64 bytes
        if (offset + ED25519_SIGNATURE_LENGTH > data.length) revert InvalidProofLength();
        vote.signature = data[offset:offset+ED25519_SIGNATURE_LENGTH];
        offset += ED25519_SIGNATURE_LENGTH;

        return (vote, offset);
    }

    // ============ Individual Activity Deserialization ============

    /// @notice Deserialize a Notarize message
    /// @dev Rust: pub struct Notarize<S, D> { proposal: Proposal<D>, vote: Vote<S> }
    /// @dev Write impl (consensus/src/simplex/types.rs:915-919):
    ///      self.proposal.write(writer);  // Proposal
    ///      self.vote.write(writer);      // Vote
    function deserializeNotarize(bytes calldata proof)
        public pure returns (Proposal memory proposal, Vote memory vote)
    {
        uint256 offset = 0;
        (proposal, offset) = deserializeProposal(proof, offset);
        (vote, offset) = deserializeVote(proof, offset);

        if (offset != proof.length) revert InvalidProofLength();
        return (proposal, vote);
    }

    /// @notice Deserialize a Nullify message
    /// @dev Rust: pub struct Nullify<S> { round: Round, vote: Vote<S> }
    /// @dev Write impl (consensus/src/simplex/types.rs:1122-1126):
    ///      self.round.write(writer);  // Round
    ///      self.vote.write(writer);   // Vote
    function deserializeNullify(bytes calldata proof)
        public pure returns (Round memory round, Vote memory vote)
    {
        uint256 offset = 0;
        (round, offset) = deserializeRound(proof, offset);
        (vote, offset) = deserializeVote(proof, offset);

        if (offset != proof.length) revert InvalidProofLength();
        return (round, vote);
    }

    /// @notice Deserialize a Finalize message
    /// @dev Rust: pub struct Finalize<S, D> { proposal: Proposal<D>, vote: Vote<S> }
    /// @dev Identical structure to Notarize
    function deserializeFinalize(bytes calldata proof)
        public pure returns (Proposal memory proposal, Vote memory vote)
    {
        return deserializeNotarize(proof);
    }

    // ============ Bitmap Helper ============

    /// @notice Get the value of a bit in a bitmap
    /// @dev Matches Rust BitMap implementation (utils/src/bitmap/mod.rs)
    /// @dev Bits are stored with lowest order bits first within each byte
    /// @param bitmap The bitmap bytes
    /// @param bitIndex The index of the bit to retrieve
    /// @return true if the bit is set, false otherwise
    /// TODO: To be used in signature verification.
    function getBit(bytes memory bitmap, uint256 bitIndex) internal pure returns (bool) {
        uint256 byteIndex = bitIndex >> 3; // divide by 8
        uint256 bitInByte = bitIndex & 7;  // modulo 8

        if (byteIndex >= bitmap.length) return false;

        uint8 byteValue = uint8(bitmap[byteIndex]);
        uint8 mask = uint8(1 << bitInByte);
        return (byteValue & mask) != 0;
    }

    // ============ Deserialization Helpers ============

    /// @notice Deserialize signers bitmap from proof data
    /// @dev Encoding format (consensus/src/simplex/signing_scheme/ed25519.rs:110-114):
    ///      - bitmap_length: u64 (8 bytes big-endian)
    ///      - bitmap_bytes: (bitmap_length + 7) / 8 bytes
    /// @param proof The encoded proof bytes
    /// @param offset The starting offset in the proof
    /// @return bitmapLengthInBits The number of bits in the bitmap
    /// @return signersBitmap The bitmap bytes
    /// @return newOffset Updated offset after reading the bitmap
    function deserializeSignersBitmap(bytes calldata proof, uint256 offset, uint32 maxParticipants)
        public pure returns (uint64 bitmapLengthInBits, bytes memory signersBitmap, uint256 newOffset)
    {
        // Read bitmap length (8 bytes big-endian u64)
        if (offset + 8 > proof.length) revert InvalidProofLength();
        bitmapLengthInBits = uint64(bytes8(proof[offset:offset+8]));
        offset += 8;

        // Bound the bitmap length by the maximum participants (upper bound)
        if (bitmapLengthInBits > maxParticipants) revert TooManySigners();

        // Calculate number of bytes needed for bitmap
        uint256 numBitmapBytes = (bitmapLengthInBits + 7) >> 3; // divide by 8

        // Read bitmap bytes
        if (offset + numBitmapBytes > proof.length) revert InvalidProofLength();
        signersBitmap = proof[offset:offset + numBitmapBytes];
        offset += numBitmapBytes;

        // Count set bits and enforce trailing-zero bits validation
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


    // ============ Certificate Deserialization ============

    /// @notice Deserialize an Ed25519 Certificate (bitmap + signatures)
    /// @dev This is the core Certificate deserialization shared by all certificate types
    /// @dev Uses helper functions for modularity and testability:
    ///      - deserializeSignersBitmap: Reads bitmap indicating which signers are present
    ///      - deserializeSignatures: Reads signatures (not votes!)
    /// @dev Full encoding structure (consensus/src/simplex/signing_scheme/ed25519.rs:110-114):
    ///      1. Signers bitmap (u64 length + raw bytes)
    ///      2. Signatures (varint count + 64 bytes each)
    /// @dev Rust: pub struct Certificate { signers: Signers, signatures: Vec<Ed25519Signature> }
    /// @param proof The encoded proof bytes
    /// @param offset The current offset in the proof
    /// @param maxSigners Maximum allowed signers (for DoS protection)
    /// @return certificate The deserialized certificate
    /// @return newOffset Updated offset after reading the certificate
    function deserializeCertificate(bytes calldata proof, uint256 offset, uint32 maxSigners)
        internal pure returns (Certificate memory certificate, uint256 newOffset)
    {
        // Read signers bitmap
        uint64 bitmapLengthInBits;
        (bitmapLengthInBits, certificate.signersBitmap, offset) = deserializeSignersBitmap(proof, offset, maxSigners);

        // Read signatures (varint count + raw signature bytes)
        uint32 signatureCount;
        (signatureCount, offset) = decodeVarintU32(proof, offset);

        if (signatureCount > maxSigners) revert TooManySigners();

        certificate.signatures = new bytes[](signatureCount);
        for (uint32 i = 0; i < signatureCount; i++) {
            if (offset + ED25519_SIGNATURE_LENGTH > proof.length) revert InvalidProofLength();
            certificate.signatures[i] = proof[offset:offset + ED25519_SIGNATURE_LENGTH];
            offset += ED25519_SIGNATURE_LENGTH;
        }

        return (certificate, offset);
    }

    /// @notice Deserialize a Notarization certificate (quorum of Notarize votes)
    /// @dev Encoding: Proposal + Certificate (bitmap + signatures)
    /// @dev Rust: Notarization { proposal: Proposal, certificate: Certificate }
    function deserializeNotarization(bytes calldata proof, uint32 maxSigners)
        public pure returns (Notarization memory notarization)
    {
        uint256 offset = 0;

        (notarization.proposal, offset) = deserializeProposal(proof, offset);
        (notarization.certificate, offset) = deserializeCertificate(proof, offset, maxSigners);

        if (offset != proof.length) revert InvalidProofLength();
        return notarization;
    }

    /// @notice Deserialize a Nullification certificate (quorum of Nullify votes)
    /// @dev Encoding: Round + Certificate (bitmap + signatures)
    /// @dev Rust: Nullification { round: Round, certificate: Certificate }
    function deserializeNullification(bytes calldata proof, uint32 maxSigners)
        public pure returns (Nullification memory nullification)
    {
        uint256 offset = 0;

        (nullification.round, offset) = deserializeRound(proof, offset);
        (nullification.certificate, offset) = deserializeCertificate(proof, offset, maxSigners);

        if (offset != proof.length) revert InvalidProofLength();
        return nullification;
    }

    /// @notice Deserialize a Finalization certificate
    /// @dev Identical structure to Notarization
    function deserializeFinalization(bytes calldata proof, uint32 maxSigners)
        public pure returns (Finalization memory finalization)
    {
        Notarization memory notarization = deserializeNotarization(proof, maxSigners);
        finalization.proposal = notarization.proposal;
        finalization.certificate = notarization.certificate;
        return finalization;
    }


    /// @notice Deserialize ConflictingNotarize proof
    /// @dev Rust: pub struct ConflictingNotarize<S, D> { first: Notarize, second: Notarize }
    /// @dev Proves a validator signed two different proposals at the same round
    function deserializeConflictingNotarize(bytes calldata proof)
        public pure returns (
            Proposal memory proposal1,
            Vote memory vote1,
            Proposal memory proposal2,
            Vote memory vote2
        )
    {
        uint256 offset = 0;

        // Deserialize first Notarize
        (proposal1, offset) = deserializeProposal(proof, offset);
        (vote1, offset) = deserializeVote(proof, offset);

        // Deserialize second Notarize
        (proposal2, offset) = deserializeProposal(proof, offset);
        (vote2, offset) = deserializeVote(proof, offset);

        if (offset != proof.length) revert InvalidProofLength();

        // Validate Byzantine behavior: same round, same signer, different proposals
        validateRoundsMatch(proposal1.round, proposal2.round);
        if (vote1.signer != vote2.signer) revert Conflicting_SignerMismatch();
        validateProposalsDiffer(proposal1, proposal2);

        return (proposal1, vote1, proposal2, vote2);
    }

    /// @notice Deserialize ConflictingFinalize proof
    /// @dev Rust: pub struct ConflictingFinalize<S, D> { first: Finalize, second: Finalize }
    /// @dev Identical to ConflictingNotarize but for Finalize.
    function deserializeConflictingFinalize(bytes calldata proof)
        public pure returns (
            Proposal memory proposal1,
            Vote memory vote1,
            Proposal memory proposal2,
            Vote memory vote2
        )
    {
        return deserializeConflictingNotarize(proof);
    }

    /// @notice Deserialize NullifyFinalize proof
    /// @dev Rust: pub struct NullifyFinalize<S, D> { nullify: Nullify<S>, finalize: Finalize<S, D> }
    /// @dev Write impl (consensus/src/simplex/types.rs:2281-2285):
    ///      self.nullify.write(writer);   // Nullify
    ///      self.finalize.write(writer);  // Finalize
    /// @dev Proves a validator voted both to skip AND finalize the same round
    function deserializeNullifyFinalize(bytes calldata proof)
        public pure returns (
            Round memory nullifyRound,
            Vote memory nullifyVote,
            Proposal memory finalizeProposal,
            Vote memory finalizeVote
        )
    {
        uint256 offset = 0;

        // Deserialize Nullify
        (nullifyRound, offset) = deserializeRound(proof, offset);
        (nullifyVote, offset) = deserializeVote(proof, offset);

        // Deserialize Finalize
        (finalizeProposal, offset) = deserializeProposal(proof, offset);
        (finalizeVote, offset) = deserializeVote(proof, offset);

        if (offset != proof.length) revert InvalidProofLength();

        // Validate Byzantine behavior: same round, same signer
        validateRoundsMatch(nullifyRound, finalizeProposal.round);
        if (nullifyVote.signer != finalizeVote.signer) revert Conflicting_SignerMismatch();

        return (nullifyRound, nullifyVote, finalizeProposal, finalizeVote);
    }
}
