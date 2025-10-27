// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./SimplexVerifierBase.sol";

/// @title SimplexVerifierBLS12381Threshold
/// @notice BLS12-381 threshold signing scheme for Simplex consensus proofs
/// @dev Handles threshold signatures with vote + seed components
/// @dev This is a NON-ATTRIBUTABLE scheme - individual signatures cannot prove faults
/// @dev With threshold sigs, any t valid partial signatures can forge others
/// @dev See: consensus/src/simplex/signing_scheme/bls12381_threshold.rs
contract SimplexVerifierBLS12381Threshold is SimplexVerifierBase {
    // ============ Constants ============

    // BLS12-381 signature sizes depend on variant (MinPk vs MinSig)
    // MinPk (most common): Public keys in G1 (48 bytes), Signatures in G2 (96 bytes)
    // MinSig: Public keys in G2 (96 bytes), Signatures in G1 (48 bytes)

    /// @dev For MinPk variant (default): G2 signatures = 96 bytes each
    uint256 constant MINPK_VOTE_SIGNATURE_LENGTH = 96;
    uint256 constant MINPK_SEED_SIGNATURE_LENGTH = 96;
    uint256 constant MINPK_TOTAL_SIGNATURE_LENGTH = 192;  // vote + seed

    /// @dev For MinSig variant: G1 signatures = 48 bytes each
    uint256 constant MINSIG_VOTE_SIGNATURE_LENGTH = 48;
    uint256 constant MINSIG_SEED_SIGNATURE_LENGTH = 48;
    uint256 constant MINSIG_TOTAL_SIGNATURE_LENGTH = 96;  // vote + seed

    // ============ Structs ============

    /// @notice Individual threshold vote (partial signature)
    /// @dev Rust: pub struct Vote<S: Scheme> { signer: u32, signature: Signature<V> }
    /// @dev Rust Signature: { vote_signature: V::Signature, seed_signature: V::Signature }
    /// @dev Write impl (consensus/src/simplex/signing_scheme/bls12381_threshold.rs:154-158):
    ///      self.vote_signature.write(writer);  // 96 bytes (MinPk) or 48 bytes (MinSig)
    ///      self.seed_signature.write(writer);  // 96 bytes (MinPk) or 48 bytes (MinSig)
    struct ThresholdVote {
        uint32 signer;
        bytes voteSignature;  // Partial signature over vote message
        bytes seedSignature;  // Partial signature over seed message
    }

    /// @notice Threshold certificate (recovered aggregate signature)
    /// @dev CRITICAL: Unlike Ed25519, certificates DON'T contain individual votes!
    /// @dev Only the recovered aggregate signatures are transmitted
    /// @dev Rust: type Certificate = Signature<V> (bls12381_threshold.rs:274)
    /// @dev This makes certificates constant size regardless of validator count
    struct ThresholdCertificate {
        bytes voteSignature;  // Recovered aggregate vote signature
        bytes seedSignature;  // Recovered aggregate seed signature
    }

    /// @notice Randomness seed derived from threshold signature
    /// @dev Rust: pub struct Seed<V> { round: Round, signature: V::Signature }
    /// @dev Write impl (bls12381_threshold.rs:230-234)
    struct Seed {
        Round round;
        bytes signature;  // Threshold signature on the round
    }

    // ============ Vote Deserialization (MinPk Variant) ============

    /// @notice Deserialize a single threshold vote for MinPk variant
    /// @dev Vote format: signer (4 bytes) + vote_sig (96 bytes) + seed_sig (96 bytes)
    function deserializeVoteMinPk(bytes calldata data, uint256 offset)
        internal pure returns (ThresholdVote memory vote, uint256 newOffset)
    {
        // Read signer: 4 bytes big-endian
        if (offset + 4 > data.length) revert InvalidProofLength();
        vote.signer = uint32(bytes4(data[offset:offset+4]));
        offset += 4;

        // Read vote signature: 96 bytes (G2)
        if (offset + MINPK_VOTE_SIGNATURE_LENGTH > data.length) revert InvalidProofLength();
        vote.voteSignature = data[offset:offset+MINPK_VOTE_SIGNATURE_LENGTH];
        offset += MINPK_VOTE_SIGNATURE_LENGTH;

        // Read seed signature: 96 bytes (G2)
        if (offset + MINPK_SEED_SIGNATURE_LENGTH > data.length) revert InvalidProofLength();
        vote.seedSignature = data[offset:offset+MINPK_SEED_SIGNATURE_LENGTH];
        offset += MINPK_SEED_SIGNATURE_LENGTH;

        return (vote, offset);
    }

    /// @notice Deserialize a threshold certificate for MinPk variant
    /// @dev Certificate is just the recovered signatures, NO vote array!
    function deserializeCertificateMinPk(bytes calldata data, uint256 offset)
        internal pure returns (ThresholdCertificate memory cert, uint256 newOffset)
    {
        // Read vote signature: 96 bytes (G2)
        if (offset + MINPK_VOTE_SIGNATURE_LENGTH > data.length) revert InvalidProofLength();
        cert.voteSignature = data[offset:offset+MINPK_VOTE_SIGNATURE_LENGTH];
        offset += MINPK_VOTE_SIGNATURE_LENGTH;

        // Read seed signature: 96 bytes (G2)
        if (offset + MINPK_SEED_SIGNATURE_LENGTH > data.length) revert InvalidProofLength();
        cert.seedSignature = data[offset:offset+MINPK_SEED_SIGNATURE_LENGTH];
        offset += MINPK_SEED_SIGNATURE_LENGTH;

        return (cert, offset);
    }

    // ============ Individual Activity Deserialization (MinPk) ============

    /// @notice Deserialize a Notarize message (individual threshold vote)
    /// @dev Rust: pub struct Notarize<S, D> { proposal: Proposal<D>, vote: Vote<S> }
    function deserializeNotarizeMinPk(bytes calldata proof)
        public pure returns (Proposal memory proposal, ThresholdVote memory vote)
    {
        uint256 offset = 0;
        (proposal, offset) = deserializeProposal(proof, offset);
        (vote, offset) = deserializeVoteMinPk(proof, offset);

        if (offset != proof.length) revert InvalidProofLength();
        return (proposal, vote);
    }

    /// @notice Deserialize a Nullify message (individual threshold vote)
    /// @dev Rust: pub struct Nullify<S> { round: Round, vote: Vote<S> }
    function deserializeNullifyMinPk(bytes calldata proof)
        public pure returns (Round memory round, ThresholdVote memory vote)
    {
        uint256 offset = 0;
        (round, offset) = deserializeRound(proof, offset);
        (vote, offset) = deserializeVoteMinPk(proof, offset);

        if (offset != proof.length) revert InvalidProofLength();
        return (round, vote);
    }

    /// @notice Deserialize a Finalize message (individual threshold vote)
    /// @dev Identical structure to Notarize
    function deserializeFinalizeMinPk(bytes calldata proof)
        public pure returns (Proposal memory proposal, ThresholdVote memory vote)
    {
        return deserializeNotarizeMinPk(proof);
    }

    // ============ Certificate Deserialization (MinPk) ============

    /// @notice Deserialize a Notarization certificate
    /// @dev CRITICAL DIFFERENCE: Certificate contains ONLY recovered aggregate signatures
    /// @dev No individual votes! Fixed 192 bytes regardless of validator count
    /// @dev Format: Proposal + ThresholdCertificate (vote_sig + seed_sig)
    function deserializeNotarizationMinPk(bytes calldata proof)
        public pure returns (Proposal memory proposal, ThresholdCertificate memory cert)
    {
        uint256 offset = 0;
        (proposal, offset) = deserializeProposal(proof, offset);
        (cert, offset) = deserializeCertificateMinPk(proof, offset);

        if (offset != proof.length) revert InvalidProofLength();
        return (proposal, cert);
    }

    /// @notice Deserialize a Nullification certificate
    /// @dev Format: Round + ThresholdCertificate
    function deserializeNullificationMinPk(bytes calldata proof)
        public pure returns (Round memory round, ThresholdCertificate memory cert)
    {
        uint256 offset = 0;
        (round, offset) = deserializeRound(proof, offset);
        (cert, offset) = deserializeCertificateMinPk(proof, offset);

        if (offset != proof.length) revert InvalidProofLength();
        return (round, cert);
    }

    /// @notice Deserialize a Finalization certificate
    /// @dev Identical structure to Notarization
    function deserializeFinalizationMinPk(bytes calldata proof)
        public pure returns (Proposal memory proposal, ThresholdCertificate memory cert)
    {
        return deserializeNotarizationMinPk(proof);
    }

    /// @notice Deserialize a Seed (randomness beacon)
    /// @dev Rust: pub struct Seed<V> { round: Round, signature: V::Signature }
    /// @dev Used for bias-resistant leader election
    function deserializeSeedMinPk(bytes calldata proof)
        public pure returns (Seed memory seed)
    {
        uint256 offset = 0;
        (seed.round, offset) = deserializeRound(proof, offset);

        // Read threshold signature: 96 bytes (G2 for MinPk)
        if (offset + MINPK_VOTE_SIGNATURE_LENGTH > proof.length) revert InvalidProofLength();
        seed.signature = proof[offset:offset+MINPK_VOTE_SIGNATURE_LENGTH];
        offset += MINPK_VOTE_SIGNATURE_LENGTH;

        if (offset != proof.length) revert InvalidProofLength();
        return seed;
    }

    // ============ Fraud Proof Deserialization (MinPk) ============

    /// @notice Deserialize ConflictingNotarize proof
    /// @dev WARNING: With threshold signatures, this proof can be FORGED!
    /// @dev Any t valid partial signatures can create a forged partial for any signer
    /// @dev Only safe to use locally (from authenticated peer), NOT as external evidence
    function deserializeConflictingNotarizeMinPk(bytes calldata proof)
        public pure returns (
            Proposal memory proposal1,
            ThresholdVote memory vote1,
            Proposal memory proposal2,
            ThresholdVote memory vote2
        )
    {
        uint256 offset = 0;

        // Deserialize first Notarize
        (proposal1, offset) = deserializeProposal(proof, offset);
        (vote1, offset) = deserializeVoteMinPk(proof, offset);

        // Deserialize second Notarize
        (proposal2, offset) = deserializeProposal(proof, offset);
        (vote2, offset) = deserializeVoteMinPk(proof, offset);

        if (offset != proof.length) revert InvalidProofLength();

        // Validate Byzantine behavior
        validateRoundsMatch(proposal1.round, proposal2.round);
        if (vote1.signer != vote2.signer) revert SignerMismatch();
        validateProposalsDiffer(proposal1, proposal2);

        return (proposal1, vote1, proposal2, vote2);
    }

    /// @notice Deserialize ConflictingFinalize proof
    /// @dev WARNING: Not attributable - can be forged with threshold signatures
    function deserializeConflictingFinalizeMinPk(bytes calldata proof)
        public pure returns (
            Proposal memory proposal1,
            ThresholdVote memory vote1,
            Proposal memory proposal2,
            ThresholdVote memory vote2
        )
    {
        return deserializeConflictingNotarizeMinPk(proof);
    }

    /// @notice Deserialize NullifyFinalize proof
    /// @dev WARNING: Not attributable - can be forged with threshold signatures
    function deserializeNullifyFinalizeMinPk(bytes calldata proof)
        public pure returns (
            Round memory nullifyRound,
            ThresholdVote memory nullifyVote,
            Proposal memory finalizeProposal,
            ThresholdVote memory finalizeVote
        )
    {
        uint256 offset = 0;

        // Deserialize Nullify
        (nullifyRound, offset) = deserializeRound(proof, offset);
        (nullifyVote, offset) = deserializeVoteMinPk(proof, offset);

        // Deserialize Finalize
        (finalizeProposal, offset) = deserializeProposal(proof, offset);
        (finalizeVote, offset) = deserializeVoteMinPk(proof, offset);

        if (offset != proof.length) revert InvalidProofLength();

        // Validate Byzantine behavior
        validateRoundsMatch(nullifyRound, finalizeProposal.round);
        if (nullifyVote.signer != finalizeVote.signer) revert SignerMismatch();

        return (nullifyRound, nullifyVote, finalizeProposal, finalizeVote);
    }

    // ============ Gas Optimization Notes ============

    /// @dev Certificate Size Comparison (100 validators, 67 quorum):
    /// - Ed25519: ~4,600 bytes (67 votes × 68 bytes each)
    /// - BLS Threshold MinPk: 192 bytes (fixed, regardless of validator count!)
    ///
    /// @dev Verification Cost Comparison:
    /// - Ed25519: 67 signature checks via precompile (~3,000 gas each = ~200k gas)
    /// - BLS Threshold: 1 pairing check (~200k gas)
    ///
    /// @dev Threshold breaks even around 3-4 validators, becomes significantly
    ///      cheaper for larger validator sets due to constant certificate size
}
