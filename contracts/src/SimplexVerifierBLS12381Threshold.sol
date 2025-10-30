// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./SimplexVerifierBase.sol";
import {CodecHelpers} from "./libraries/CodecHelpers.sol";
import {HashFunction, BLS2} from "./interfaces/ISignatureScheme.sol";

/// @title SimplexVerifierBLS12381Threshold
/// @notice BLS12-381 threshold signing scheme for Simplex consensus proofs
/// @dev Handles threshold signatures with vote + seed components
/// @dev This is a NON-ATTRIBUTABLE scheme - individual signatures cannot prove faults
/// @dev With threshold sigs, any t valid partial signatures can forge others
/// @dev See: consensus/src/simplex/signing_scheme/bls12381_threshold.rs
contract SimplexVerifierBLS12381Threshold is SimplexVerifierBase {
    // ============ Constants ============

    // BLS12-381 signature sizes depend on variant (MinPk vs MinSig)
    // MinPk: Public keys in G1 (48 bytes), Signatures in G2 (96 bytes)
    // MinSig (Simplex uses this): Public keys in G2 (96 bytes), Signatures in G1 (48 bytes)

    /// @dev Simplex uses MinSig variant: G1 signatures = 48 bytes each (compressed)
    uint256 constant SIGNATURE_LENGTH = 48;
    uint256 constant SIGNATURE_TOTAL_LENGTH = 96;  // vote + seed

    /// @dev Threshold public key is G2 = 96 bytes (compressed)
    uint256 constant PUBLIC_KEY_LENGTH = 96;

    // ============ Individual Activity Deserialization ============

    /// @notice Deserialize a Notarize message (individual threshold vote)
    /// @dev Format: proposal_bytes + signer (4 bytes) + vote_sig (96 bytes) + seed_sig (96 bytes)
    /// @param proof The serialized proof bytes
    /// @return proposalBytes Raw proposal bytes for verification
    /// @return signer The signer index
    /// @return voteSignature Vote signature bytes (96 bytes for )
    /// @return seedSignature Seed signature bytes (96 bytes for )
    function deserializeNotarize(bytes calldata proof)
        public pure returns (
            bytes calldata proposalBytes,
            uint32 signer,
            bytes calldata voteSignature,
            bytes calldata seedSignature
        )
    {
        uint256 offset = 0;

        // Extract proposal bytes
        (proposalBytes, offset) = extractProposalBytes(proof, offset);

        // Read signer: 4 bytes big-endian
        if (offset + 4 > proof.length) revert CodecHelpers.InvalidProofLength();
        signer = uint32(bytes4(proof[offset:offset+4]));
        offset += 4;

        // Read vote signature: 48 bytes (G1)
        if (offset + SIGNATURE_LENGTH > proof.length) revert CodecHelpers.InvalidProofLength();
        voteSignature = proof[offset:offset+SIGNATURE_LENGTH];
        offset += SIGNATURE_LENGTH;

        // Read seed signature: 48 bytes (G1)
        if (offset + SIGNATURE_LENGTH > proof.length) revert CodecHelpers.InvalidProofLength();
        seedSignature = proof[offset:offset+SIGNATURE_LENGTH];
        offset += SIGNATURE_LENGTH;

        if (offset != proof.length) revert CodecHelpers.InvalidProofLength();
        return (proposalBytes, signer, voteSignature, seedSignature);
    }

    /// @notice Deserialize a Nullify message (individual threshold vote)
    /// @dev Format: round_bytes (16 bytes) + signer (4 bytes) + vote_sig (96 bytes) + seed_sig (96 bytes)
    /// @param proof The serialized proof bytes
    /// @return roundBytes Raw round bytes for verification
    /// @return signer The signer index
    /// @return voteSignature Vote signature bytes (96 bytes for )
    /// @return seedSignature Seed signature bytes (96 bytes for )
    function deserializeNullify(bytes calldata proof)
        public pure returns (
            bytes calldata roundBytes,
            uint32 signer,
            bytes calldata voteSignature,
            bytes calldata seedSignature
        )
    {
        uint256 offset = 0;

        // Extract round bytes
        (roundBytes, offset) = extractRoundBytes(proof, offset);

        // Read signer: 4 bytes big-endian
        if (offset + 4 > proof.length) revert CodecHelpers.InvalidProofLength();
        signer = uint32(bytes4(proof[offset:offset+4]));
        offset += 4;

        // Read vote signature: 48 bytes (G1)
        if (offset + SIGNATURE_LENGTH > proof.length) revert CodecHelpers.InvalidProofLength();
        voteSignature = proof[offset:offset+SIGNATURE_LENGTH];
        offset += SIGNATURE_LENGTH;

        // Read seed signature: 48 bytes (G1)
        if (offset + SIGNATURE_LENGTH > proof.length) revert CodecHelpers.InvalidProofLength();
        seedSignature = proof[offset:offset+SIGNATURE_LENGTH];
        offset += SIGNATURE_LENGTH;

        if (offset != proof.length) revert CodecHelpers.InvalidProofLength();
        return (roundBytes, signer, voteSignature, seedSignature);
    }

    /// @notice Deserialize a Finalize message (individual threshold vote)
    /// @dev Identical structure to Notarize
    function deserializeFinalize(bytes calldata proof)
        public pure returns (
            bytes calldata proposalBytes,
            uint32 signer,
            bytes calldata voteSignature,
            bytes calldata seedSignature
        )
    {
        return deserializeNotarize(proof);
    }

    // ============ Certificate Deserialization () ============

    /// @notice Deserialize a Notarization certificate
    /// @dev CRITICAL: Certificate contains ONLY recovered aggregate signatures (no bitmap, no votes!)
    /// @dev Format: proposal_bytes + vote_sig (96 bytes) + seed_sig (96 bytes)
    /// @param proof The serialized proof bytes
    /// @return proposalBytes Raw proposal bytes for verification
    /// @return voteSignature Aggregate vote signature (96 bytes for )
    /// @return seedSignature Aggregate seed signature (96 bytes for )
    function deserializeNotarization(bytes calldata proof)
        public pure returns (
            bytes calldata proposalBytes,
            bytes calldata voteSignature,
            bytes calldata seedSignature
        )
    {
        uint256 offset = 0;

        // Extract proposal bytes
        (proposalBytes, offset) = extractProposalBytes(proof, offset);

        // Read vote signature: 48 bytes (G1)
        if (offset + SIGNATURE_LENGTH > proof.length) revert CodecHelpers.InvalidProofLength();
        voteSignature = proof[offset:offset+SIGNATURE_LENGTH];
        offset += SIGNATURE_LENGTH;

        // Read seed signature: 48 bytes (G1)
        if (offset + SIGNATURE_LENGTH > proof.length) revert CodecHelpers.InvalidProofLength();
        seedSignature = proof[offset:offset+SIGNATURE_LENGTH];
        offset += SIGNATURE_LENGTH;

        if (offset != proof.length) revert CodecHelpers.InvalidProofLength();
        return (proposalBytes, voteSignature, seedSignature);
    }

    /// @notice Deserialize a Nullification certificate
    /// @dev Format: round_bytes (16 bytes) + vote_sig (96 bytes) + seed_sig (96 bytes)
    /// @param proof The serialized proof bytes
    /// @return roundBytes Raw round bytes for verification
    /// @return voteSignature Aggregate vote signature (96 bytes for )
    /// @return seedSignature Aggregate seed signature (96 bytes for )
    function deserializeNullification(bytes calldata proof)
        public pure returns (
            bytes calldata roundBytes,
            bytes calldata voteSignature,
            bytes calldata seedSignature
        )
    {
        uint256 offset = 0;

        // Extract round bytes
        (roundBytes, offset) = extractRoundBytes(proof, offset);

        // Read vote signature: 48 bytes (G1)
        if (offset + SIGNATURE_LENGTH > proof.length) revert CodecHelpers.InvalidProofLength();
        voteSignature = proof[offset:offset+SIGNATURE_LENGTH];
        offset += SIGNATURE_LENGTH;

        // Read seed signature: 48 bytes (G1)
        if (offset + SIGNATURE_LENGTH > proof.length) revert CodecHelpers.InvalidProofLength();
        seedSignature = proof[offset:offset+SIGNATURE_LENGTH];
        offset += SIGNATURE_LENGTH;

        if (offset != proof.length) revert CodecHelpers.InvalidProofLength();
        return (roundBytes, voteSignature, seedSignature);
    }

    /// @notice Deserialize a Finalization certificate
    /// @dev Identical structure to Notarization
    function deserializeFinalization(bytes calldata proof)
        public pure returns (
            bytes calldata proposalBytes,
            bytes calldata voteSignature,
            bytes calldata seedSignature
        )
    {
        return deserializeNotarization(proof);
    }

    /// @notice Deserialize a Seed (randomness beacon)
    /// @dev Format: round_bytes (16 bytes) + seed_sig (96 bytes)
    /// @dev Used for bias-resistant leader election
    /// @param proof The serialized proof bytes
    /// @return roundBytes Raw round bytes for verification
    /// @return seedSignature Threshold signature on the round (96 bytes for )
    function deserializeSeed(bytes calldata proof)
        public pure returns (
            bytes calldata roundBytes,
            bytes calldata seedSignature
        )
    {
        uint256 offset = 0;

        // Extract round bytes
        (roundBytes, offset) = extractRoundBytes(proof, offset);

        // Read threshold signature: 96 bytes (G2 for )
        if (offset + SIGNATURE_LENGTH > proof.length) revert CodecHelpers.InvalidProofLength();
        seedSignature = proof[offset:offset+SIGNATURE_LENGTH];
        offset += SIGNATURE_LENGTH;

        if (offset != proof.length) revert CodecHelpers.InvalidProofLength();
        return (roundBytes, seedSignature);
    }

    // ============ Fraud Proof Deserialization () ============
    // WARNING: These proofs can be FORGED with threshold signatures!
    // Any t valid partial signatures can create a forged partial for any signer
    // Only safe to use locally (from authenticated peer), NOT as external evidence

    /// @notice Deserialize ConflictingNotarize proof
    /// @dev WARNING: With threshold signatures, this proof can be FORGED!
    function deserializeConflictingNotarize(bytes calldata proof)
        public pure returns (
            bytes calldata proposalBytes1,
            uint32 signer1,
            bytes calldata voteSignature1,
            bytes calldata seedSignature1,
            bytes calldata proposalBytes2,
            uint32 signer2,
            bytes calldata voteSignature2,
            bytes calldata seedSignature2
        )
    {
        uint256 offset = 0;

        // Deserialize first Notarize
        (proposalBytes1, offset) = extractProposalBytes(proof, offset);

        if (offset + 4 > proof.length) revert CodecHelpers.InvalidProofLength();
        signer1 = uint32(bytes4(proof[offset:offset+4]));
        offset += 4;

        if (offset + SIGNATURE_LENGTH > proof.length) revert CodecHelpers.InvalidProofLength();
        voteSignature1 = proof[offset:offset+SIGNATURE_LENGTH];
        offset += SIGNATURE_LENGTH;

        if (offset + SIGNATURE_LENGTH > proof.length) revert CodecHelpers.InvalidProofLength();
        seedSignature1 = proof[offset:offset+SIGNATURE_LENGTH];
        offset += SIGNATURE_LENGTH;

        // Deserialize second Notarize
        (proposalBytes2, offset) = extractProposalBytes(proof, offset);

        if (offset + 4 > proof.length) revert CodecHelpers.InvalidProofLength();
        signer2 = uint32(bytes4(proof[offset:offset+4]));
        offset += 4;

        if (offset + SIGNATURE_LENGTH > proof.length) revert CodecHelpers.InvalidProofLength();
        voteSignature2 = proof[offset:offset+SIGNATURE_LENGTH];
        offset += SIGNATURE_LENGTH;

        if (offset + SIGNATURE_LENGTH > proof.length) revert CodecHelpers.InvalidProofLength();
        seedSignature2 = proof[offset:offset+SIGNATURE_LENGTH];
        offset += SIGNATURE_LENGTH;

        if (offset != proof.length) revert CodecHelpers.InvalidProofLength();

        // Validate Byzantine behavior
        bytes calldata round1 = proposalBytes1[0:16];
        bytes calldata round2 = proposalBytes2[0:16];
        validateRoundsMatch(round1, round2);
        if (signer1 != signer2) revert Conflicting_SignerMismatch();
        validateProposalsDiffer(proposalBytes1, proposalBytes2);

        return (proposalBytes1, signer1, voteSignature1, seedSignature1,
                proposalBytes2, signer2, voteSignature2, seedSignature2);
    }

    /// @notice Deserialize ConflictingFinalize proof
    /// @dev WARNING: Not attributable - can be forged with threshold signatures
    function deserializeConflictingFinalize(bytes calldata proof)
        public pure returns (
            bytes calldata proposalBytes1,
            uint32 signer1,
            bytes calldata voteSignature1,
            bytes calldata seedSignature1,
            bytes calldata proposalBytes2,
            uint32 signer2,
            bytes calldata voteSignature2,
            bytes calldata seedSignature2
        )
    {
        return deserializeConflictingNotarize(proof);
    }

    /// @notice Deserialize NullifyFinalize proof
    /// @dev WARNING: Not attributable - can be forged with threshold signatures
    function deserializeNullifyFinalize(bytes calldata proof)
        public pure returns (
            bytes calldata nullifyRoundBytes,
            uint32 nullifySigner,
            bytes calldata nullifyVoteSignature,
            bytes calldata nullifySeedSignature,
            bytes calldata finalizeProposalBytes,
            uint32 finalizeSigner,
            bytes calldata finalizeVoteSignature,
            bytes calldata finalizeSeedSignature
        )
    {
        uint256 offset = 0;

        // Deserialize Nullify
        (nullifyRoundBytes, offset) = extractRoundBytes(proof, offset);

        if (offset + 4 > proof.length) revert CodecHelpers.InvalidProofLength();
        nullifySigner = uint32(bytes4(proof[offset:offset+4]));
        offset += 4;

        if (offset + SIGNATURE_LENGTH > proof.length) revert CodecHelpers.InvalidProofLength();
        nullifyVoteSignature = proof[offset:offset+SIGNATURE_LENGTH];
        offset += SIGNATURE_LENGTH;

        if (offset + SIGNATURE_LENGTH > proof.length) revert CodecHelpers.InvalidProofLength();
        nullifySeedSignature = proof[offset:offset+SIGNATURE_LENGTH];
        offset += SIGNATURE_LENGTH;

        // Deserialize Finalize
        (finalizeProposalBytes, offset) = extractProposalBytes(proof, offset);

        if (offset + 4 > proof.length) revert CodecHelpers.InvalidProofLength();
        finalizeSigner = uint32(bytes4(proof[offset:offset+4]));
        offset += 4;

        if (offset + SIGNATURE_LENGTH > proof.length) revert CodecHelpers.InvalidProofLength();
        finalizeVoteSignature = proof[offset:offset+SIGNATURE_LENGTH];
        offset += SIGNATURE_LENGTH;

        if (offset + SIGNATURE_LENGTH > proof.length) revert CodecHelpers.InvalidProofLength();
        finalizeSeedSignature = proof[offset:offset+SIGNATURE_LENGTH];
        offset += SIGNATURE_LENGTH;

        if (offset != proof.length) revert CodecHelpers.InvalidProofLength();

        // Validate Byzantine behavior
        bytes calldata finalizeRoundBytes = finalizeProposalBytes[0:16];
        validateRoundsMatch(nullifyRoundBytes, finalizeRoundBytes);
        if (nullifySigner != finalizeSigner) revert Conflicting_SignerMismatch();

        return (nullifyRoundBytes, nullifySigner, nullifyVoteSignature, nullifySeedSignature,
                finalizeProposalBytes, finalizeSigner, finalizeVoteSignature, finalizeSeedSignature);
    }

    // ============ Verification Functions ============

    /// @notice Verify a Notarize message (individual threshold vote)
    /// @dev Verifies both vote and seed signatures against threshold public key
    /// @param namespace Application namespace for domain separation
    /// @param proposalBytes Raw proposal bytes from deserialization
    /// @param voteSignature Vote signature bytes (48 bytes for )
    /// @param seedSignature Seed signature bytes (48 bytes for )
    /// @param thresholdPublicKey Threshold public key bytes (96 bytes G2 for )
    /// @param hashFunc Hash function to use for message hashing
    /// @return true if both signatures are valid
    function verifyNotarize(
        bytes memory namespace,
        bytes calldata proposalBytes,
        bytes calldata voteSignature,
        bytes calldata seedSignature,
        bytes memory thresholdPublicKey,
        HashFunction hashFunc
    ) public pure returns (bool) {
        // Build DST for hash-to-curve
        bytes memory dst = _buildDST(namespace, hashFunc);

        // Verify vote signature
        bytes memory voteNamespace = abi.encodePacked(namespace, "_NOTARIZE");
        bytes memory voteMessage = encodeSignedMessage(voteNamespace, proposalBytes);

        if (!_verifyBLSThreshold(voteMessage, voteSignature, thresholdPublicKey, dst)) {
            return false;
        }

        // Verify seed signature (on round bytes only)
        bytes calldata roundBytes = proposalBytes[0:16];
        bytes memory seedNamespace = abi.encodePacked(namespace, "_SEED");
        bytes memory seedMessage = encodeSignedMessage(seedNamespace, roundBytes);

        return _verifyBLSThreshold(seedMessage, seedSignature, thresholdPublicKey, dst);
    }

    /// @notice Verify a Nullify message (individual threshold vote)
    /// @param namespace Application namespace for domain separation
    /// @param roundBytes Raw round bytes from deserialization (16 bytes)
    /// @param voteSignature Vote signature bytes (48 bytes for )
    /// @param seedSignature Seed signature bytes (48 bytes for )
    /// @param thresholdPublicKey Threshold public key bytes (96 bytes G2 for )
    /// @param hashFunc Hash function to use for message hashing
    /// @return true if both signatures are valid
    function verifyNullify(
        bytes memory namespace,
        bytes calldata roundBytes,
        bytes calldata voteSignature,
        bytes calldata seedSignature,
        bytes memory thresholdPublicKey,
        HashFunction hashFunc
    ) public pure returns (bool) {
        // Build DST for hash-to-curve
        bytes memory dst = _buildDST(namespace, hashFunc);

        // Verify vote signature
        bytes memory voteNamespace = abi.encodePacked(namespace, "_NULLIFY");
        bytes memory voteMessage = encodeSignedMessage(voteNamespace, roundBytes);

        if (!_verifyBLSThreshold(voteMessage, voteSignature, thresholdPublicKey, dst)) {
            return false;
        }

        // Verify seed signature
        bytes memory seedNamespace = abi.encodePacked(namespace, "_SEED");
        bytes memory seedMessage = encodeSignedMessage(seedNamespace, roundBytes);

        return _verifyBLSThreshold(seedMessage, seedSignature, thresholdPublicKey, dst);
    }

    /// @notice Verify a Finalize message (individual threshold vote)
    /// @dev Identical verification logic to Notarize
    function verifyFinalize(
        bytes memory namespace,
        bytes calldata proposalBytes,
        bytes calldata voteSignature,
        bytes calldata seedSignature,
        bytes memory thresholdPublicKey,
        HashFunction hashFunc
    ) public pure returns (bool) {
        // Build DST for hash-to-curve
        bytes memory dst = _buildDST(namespace, hashFunc);

        // Verify vote signature
        bytes memory voteNamespace = abi.encodePacked(namespace, "_FINALIZE");
        bytes memory voteMessage = encodeSignedMessage(voteNamespace, proposalBytes);

        if (!_verifyBLSThreshold(voteMessage, voteSignature, thresholdPublicKey, dst)) {
            return false;
        }

        // Verify seed signature (on round bytes only)
        bytes calldata roundBytes = proposalBytes[0:16];
        bytes memory seedNamespace = abi.encodePacked(namespace, "_SEED");
        bytes memory seedMessage = encodeSignedMessage(seedNamespace, roundBytes);

        return _verifyBLSThreshold(seedMessage, seedSignature, thresholdPublicKey, dst);
    }

    /// @notice Verify a Notarization certificate
    /// @dev Verifies both aggregate vote and seed signatures
    /// @param namespace Application namespace for domain separation
    /// @param proposalBytes Raw proposal bytes from deserialization
    /// @param voteSignature Aggregate vote signature (48 bytes for )
    /// @param seedSignature Aggregate seed signature (48 bytes for )
    /// @param thresholdPublicKey Threshold public key bytes (96 bytes G2 for )
    /// @param hashFunc Hash function to use for message hashing
    /// @return true if both aggregate signatures are valid
    function verifyNotarization(
        bytes memory namespace,
        bytes calldata proposalBytes,
        bytes calldata voteSignature,
        bytes calldata seedSignature,
        bytes memory thresholdPublicKey,
        HashFunction hashFunc
    ) public pure returns (bool) {
        return verifyNotarize(
            namespace,
            proposalBytes,
            voteSignature,
            seedSignature,
            thresholdPublicKey,
            hashFunc
        );
    }

    /// @notice Verify a Nullification certificate
    /// @param namespace Application namespace for domain separation
    /// @param roundBytes Raw round bytes from deserialization (16 bytes)
    /// @param voteSignature Aggregate vote signature (48 bytes for )
    /// @param seedSignature Aggregate seed signature (48 bytes for )
    /// @param thresholdPublicKey Threshold public key bytes (96 bytes G2 for )
    /// @param hashFunc Hash function to use for message hashing
    /// @return true if both aggregate signatures are valid
    function verifyNullification(
        bytes memory namespace,
        bytes calldata roundBytes,
        bytes calldata voteSignature,
        bytes calldata seedSignature,
        bytes memory thresholdPublicKey,
        HashFunction hashFunc
    ) public pure returns (bool) {
        return verifyNullify(
            namespace,
            roundBytes,
            voteSignature,
            seedSignature,
            thresholdPublicKey,
            hashFunc
        );
    }

    /// @notice Verify a Finalization certificate
    /// @dev Identical verification logic to Notarization
    function verifyFinalization(
        bytes memory namespace,
        bytes calldata proposalBytes,
        bytes calldata voteSignature,
        bytes calldata seedSignature,
        bytes memory thresholdPublicKey,
        HashFunction hashFunc
    ) public pure returns (bool) {
        return verifyFinalize(
            namespace,
            proposalBytes,
            voteSignature,
            seedSignature,
            thresholdPublicKey,
            hashFunc
        );
    }

    /// @notice Verify a Seed (randomness beacon)
    /// @param namespace Application namespace for domain separation
    /// @param roundBytes Raw round bytes from deserialization (16 bytes)
    /// @param seedSignature Threshold signature on the round (48 bytes for )
    /// @param thresholdPublicKey Threshold public key bytes (96 bytes G2 for )
    /// @param hashFunc Hash function to use for message hashing
    /// @return true if the seed signature is valid
    function verifySeed(
        bytes memory namespace,
        bytes calldata roundBytes,
        bytes calldata seedSignature,
        bytes memory thresholdPublicKey,
        HashFunction hashFunc
    ) public pure returns (bool) {
        // Build DST for hash-to-curve
        bytes memory dst = _buildDST(namespace, hashFunc);

        bytes memory seedNamespace = abi.encodePacked(namespace, "_SEED");
        bytes memory seedMessage = encodeSignedMessage(seedNamespace, roundBytes);

        return _verifyBLSThreshold(seedMessage, seedSignature, thresholdPublicKey, dst);
    }

    // ============ Internal Helpers ============

    /// @notice Build domain separation tag for BLS hash-to-curve
    /// @dev Format: {namespace}-BLS12381G1_XMD:{hash}_SSWU_RO_
    /// @param namespace Application namespace
    /// @param hashFunc Hash function to use
    /// @return Domain separation tag bytes
    function _buildDST(bytes memory namespace, HashFunction hashFunc)
        internal pure returns (bytes memory)
    {
        string memory hashSpec;
        if (hashFunc == HashFunction.SHA256) {
            hashSpec = "-BLS12381G1_XMD:SHA-256_SSWU_RO_";
        } else if (hashFunc == HashFunction.KECCAK256) {
            hashSpec = "-BLS12381G1_XMD:KECCAK-256_SSWU_RO_";
        } else {
            revert UnsupportedHashFunction();
        }

        return abi.encodePacked(namespace, hashSpec);
    }

    /// @notice Verify a BLS threshold signature (MinSig variant)
    /// @dev Uses BLS2 library for pairing verification with G1 signatures and G2 public keys
    /// @param message The signed message bytes (union_unique format)
    /// @param signature Signature bytes (48 bytes G1 compressed)
    /// @param thresholdPublicKey Threshold public key bytes (96 bytes G2 compressed)
    /// @param dst Domain separation tag for hash-to-curve
    /// @return true if signature is valid
    function _verifyBLSThreshold(
        bytes memory message,
        bytes calldata signature,
        bytes memory thresholdPublicKey,
        bytes memory dst
    ) internal pure returns (bool) {
        // Hash message to G1 point using BLS2.hashToPoint (includes hash-to-curve)
        BLS2.PointG1 memory messagePoint = BLS2.hashToPoint(dst, message);

        // Unmarshal signature to G1 point
        BLS2.PointG1 memory sig = BLS2.g1Unmarshal(signature);

        // Unmarshal threshold public key to G2 point
        BLS2.PointG2 memory pubkey = BLS2.g2Unmarshal(thresholdPublicKey);

        // Verify using pairing
        (bool pairingSuccess, bool callSuccess) = BLS2.verifySingle(sig, pubkey, messagePoint);
        return pairingSuccess && callSuccess;
    }
}
