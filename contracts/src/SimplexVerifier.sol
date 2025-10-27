// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title SimplexVerifier
/// @notice Deserializes Simplex consensus proofs from the commonware library
/// @dev Matches the exact byte-level serialization from Rust Write implementations
/// @dev See: consensus/src/types.rs and consensus/src/simplex/types.rs
contract SimplexVerifier {
    // ============ Constants ============

    uint256 constant DIGEST_LENGTH = 32;         // SHA256 digest size
    uint256 constant ED25519_SIGNATURE_LENGTH = 64;

    // ============ Errors ============

    error InvalidProofLength();
    error InvalidVarint();
    error TooManySigners();
    error EpochMismatch();
    error ViewMismatch();
    error SignerMismatch();
    error ProposalsMustDiffer();

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

    /// @notice Vote contains a signer index and Ed25519 signature
    /// @dev Rust: pub struct Vote<S: Scheme> { signer: u32, signature: S::Signature }
    /// @dev Write impl (consensus/src/simplex/types.rs:103-107):
    ///      self.signer.write(writer);      // 4 bytes big-endian u32
    ///      self.signature.write(writer);   // 64 bytes (Ed25519)
    struct Vote {
        uint32 signer;
        bytes signature;
    }

    // ============ Internal Helpers ============

    /// @notice Decode a varint-encoded u64 (LEB128 format)
    /// @dev Used for: parent view, vote counts
    /// @dev Rust uses varint via UInt wrapper (commonware_codec::varint::UInt)
    function decodeVarintU64(bytes calldata data, uint256 offset)
        internal pure returns (uint64 value, uint256 newOffset)
    {
        uint256 shift = 0;
        uint256 currentOffset = offset;

        while (true) {
            if (currentOffset >= data.length) revert InvalidVarint();

            uint8 b = uint8(data[currentOffset]);
            currentOffset++;

            value |= uint64((uint256(b & 0x7F) << shift));

            if ((b & 0x80) == 0) {
                break;
            }

            shift += 7;
            if (shift >= 64) revert InvalidVarint();
        }

        return (value, currentOffset);
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
    ///      self.payload.write(writer);         // Digest (32 bytes)
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

    /// @notice Deserialize a Vote for Ed25519 scheme
    /// @dev Rust Write impl (consensus/src/simplex/types.rs:103-107):
    ///      self.signer.write(writer);      // u32 (4 bytes big-endian)
    ///      self.signature.write(writer);   // Ed25519 (64 bytes)
    function deserializeVoteEd25519(bytes calldata data, uint256 offset)
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
        (vote, offset) = deserializeVoteEd25519(proof, offset);

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
        (vote, offset) = deserializeVoteEd25519(proof, offset);

        if (offset != proof.length) revert InvalidProofLength();
        return (round, vote);
    }

    /// @notice Deserialize a Finalize message
    /// @dev Rust: pub struct Finalize<S, D> { proposal: Proposal<D>, vote: Vote<S> }
    /// @dev Identical structure to Notarize, so reuse the same deserialization
    function deserializeFinalize(bytes calldata proof)
        public pure returns (Proposal memory proposal, Vote memory vote)
    {
        return deserializeNotarize(proof);
    }

    // ============ Certificate Deserialization ============

    /// @notice Deserialize a Notarization certificate (quorum of Notarize votes)
    /// @dev For Ed25519, certificate is Vec<Vote> encoded as:
    ///      - vote_count: varint (usize as u32)
    ///      - votes: vote_count * Vote
    function deserializeNotarization(bytes calldata proof, uint32 maxSigners)
        public pure returns (Proposal memory proposal, Vote[] memory votes)
    {
        uint256 offset = 0;
        (proposal, offset) = deserializeProposal(proof, offset);

        // Read vote count (varint)
        uint64 voteCountU64;
        (voteCountU64, offset) = decodeVarintU64(proof, offset);
        uint32 voteCount = uint32(voteCountU64);

        if (voteCount > maxSigners) revert TooManySigners();

        // Read all votes
        votes = new Vote[](voteCount);
        for (uint32 i = 0; i < voteCount; i++) {
            (votes[i], offset) = deserializeVoteEd25519(proof, offset);
        }

        if (offset != proof.length) revert InvalidProofLength();
        return (proposal, votes);
    }

    /// @notice Deserialize a Nullification certificate (quorum of Nullify votes)
    /// @dev Similar to Notarization but with Round instead of Proposal
    function deserializeNullification(bytes calldata proof, uint32 maxSigners)
        public pure returns (Round memory round, Vote[] memory votes)
    {
        uint256 offset = 0;
        (round, offset) = deserializeRound(proof, offset);

        // Read vote count (varint)
        uint64 voteCountU64;
        (voteCountU64, offset) = decodeVarintU64(proof, offset);
        uint32 voteCount = uint32(voteCountU64);

        if (voteCount > maxSigners) revert TooManySigners();

        // Read all votes
        votes = new Vote[](voteCount);
        for (uint32 i = 0; i < voteCount; i++) {
            (votes[i], offset) = deserializeVoteEd25519(proof, offset);
        }

        if (offset != proof.length) revert InvalidProofLength();
        return (round, votes);
    }

    /// @notice Deserialize a Finalization certificate
    /// @dev Identical structure to Notarization
    function deserializeFinalization(bytes calldata proof, uint32 maxSigners)
        public pure returns (Proposal memory proposal, Vote[] memory votes)
    {
        return deserializeNotarization(proof, maxSigners);
    }

    // ============ Fraud Proof Deserialization ============

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
        (vote1, offset) = deserializeVoteEd25519(proof, offset);

        // Deserialize second Notarize
        (proposal2, offset) = deserializeProposal(proof, offset);
        (vote2, offset) = deserializeVoteEd25519(proof, offset);

        if (offset != proof.length) revert InvalidProofLength();

        // Validate Byzantine behavior: same round, same signer, different proposals
        if (proposal1.round.epoch != proposal2.round.epoch) revert EpochMismatch();
        if (proposal1.round.viewCounter != proposal2.round.viewCounter) revert ViewMismatch();
        if (vote1.signer != vote2.signer) revert SignerMismatch();
        if (keccak256(abi.encode(proposal1)) == keccak256(abi.encode(proposal2))) revert ProposalsMustDiffer();

        return (proposal1, vote1, proposal2, vote2);
    }

    /// @notice Deserialize ConflictingFinalize proof
    /// @dev Rust: pub struct ConflictingFinalize<S, D> { first: Finalize, second: Finalize }
    /// @dev Identical structure to ConflictingNotarize
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
        (nullifyVote, offset) = deserializeVoteEd25519(proof, offset);

        // Deserialize Finalize
        (finalizeProposal, offset) = deserializeProposal(proof, offset);
        (finalizeVote, offset) = deserializeVoteEd25519(proof, offset);

        if (offset != proof.length) revert InvalidProofLength();

        // Validate Byzantine behavior: same round, same signer
        if (nullifyRound.epoch != finalizeProposal.round.epoch) revert EpochMismatch();
        if (nullifyRound.viewCounter != finalizeProposal.round.viewCounter) revert ViewMismatch();
        if (nullifyVote.signer != finalizeVote.signer) revert SignerMismatch();

        return (nullifyRound, nullifyVote, finalizeProposal, finalizeVote);
    }
}
