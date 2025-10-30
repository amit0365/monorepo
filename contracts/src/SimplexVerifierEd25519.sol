// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./SimplexVerifierBase.sol";
import {CodecHelpers} from "./libraries/CodecHelpers.sol";
import {HashFunction} from "./interfaces/ISignatureScheme.sol";

/// @title SimplexVerifierEd25519
/// @notice Ed25519 signing scheme implementation for Simplex consensus proofs
/// @dev Handles individual Ed25519 signatures (64 bytes each)
/// @dev This is an ATTRIBUTABLE scheme - individual signatures can prove liveness/faults
/// @dev See: consensus/src/simplex/signing_scheme/ed25519.rs
contract SimplexVerifierEd25519 is SimplexVerifierBase {
    // ============ Constants ============

    uint256 constant ED25519_SIGNATURE_LENGTH = 64;

    // ============ Individual Activity Deserialization ============

    /// @notice Deserialize a Notarize message
    /// @dev Rust: pub struct Notarize<S, D> { proposal: Proposal<D>, vote: Vote<S> }
    /// @dev Format: proposal_bytes + signer (4 bytes) + signature (64 bytes)
    /// @param proof The serialized proof bytes
    /// @return proposalBytes Raw proposal bytes for verification
    /// @return signer The signer index
    /// @return signature The Ed25519 signature bytes
    function deserializeNotarize(bytes calldata proof)
        public pure returns (
            bytes calldata proposalBytes,
            uint32 signer,
            bytes calldata signature
        )
    {
        uint256 offset = 0;

        // Extract proposal bytes
        (proposalBytes, offset) = extractProposalBytes(proof, offset);

        // Read signer: 4 bytes big-endian
        if (offset + 4 > proof.length) revert CodecHelpers.InvalidProofLength();
        signer = uint32(bytes4(proof[offset:offset+4]));
        offset += 4;

        // Read signature: 64 bytes
        if (offset + ED25519_SIGNATURE_LENGTH > proof.length) revert CodecHelpers.InvalidProofLength();
        signature = proof[offset:offset+ED25519_SIGNATURE_LENGTH];
        offset += ED25519_SIGNATURE_LENGTH;

        if (offset != proof.length) revert CodecHelpers.InvalidProofLength();
        return (proposalBytes, signer, signature);
    }

    /// @notice Deserialize a Nullify message
    /// @dev Rust: pub struct Nullify<S> { round: Round, vote: Vote<S> }
    /// @dev Format: round_bytes (16 bytes) + signer (4 bytes) + signature (64 bytes)
    /// @param proof The serialized proof bytes
    /// @return roundBytes Raw round bytes for verification
    /// @return signer The signer index
    /// @return signature The Ed25519 signature bytes
    function deserializeNullify(bytes calldata proof)
        public pure returns (
            bytes calldata roundBytes,
            uint32 signer,
            bytes calldata signature
        )
    {
        uint256 offset = 0;

        // Extract round bytes
        (roundBytes, offset) = extractRoundBytes(proof, offset);

        // Read signer: 4 bytes big-endian
        if (offset + 4 > proof.length) revert CodecHelpers.InvalidProofLength();
        signer = uint32(bytes4(proof[offset:offset+4]));
        offset += 4;

        // Read signature: 64 bytes
        if (offset + ED25519_SIGNATURE_LENGTH > proof.length) revert CodecHelpers.InvalidProofLength();
        signature = proof[offset:offset+ED25519_SIGNATURE_LENGTH];
        offset += ED25519_SIGNATURE_LENGTH;

        if (offset != proof.length) revert CodecHelpers.InvalidProofLength();
        return (roundBytes, signer, signature);
    }

    /// @notice Deserialize a Finalize message
    /// @dev Identical structure to Notarize
    function deserializeFinalize(bytes calldata proof)
        public pure returns (
            bytes calldata proposalBytes,
            uint32 signer,
            bytes calldata signature
        )
    {
        return deserializeNotarize(proof);
    }

    // ============ Certificate Deserialization ============

    /// @notice Deserialize a Notarization certificate (quorum of Notarize votes)
    /// @dev Encoding: Proposal + Certificate (bitmap + signatures)
    /// @dev Rust: Notarization { proposal: Proposal, certificate: Certificate }
    /// @param proof The serialized proof bytes
    /// @param maxSigners Maximum allowed signers (for DoS protection)
    /// @return proposalBytes Raw proposal bytes for verification
    /// @return signersBitmap Bitmap of validator indices that signed
    /// @return signatureCount Number of signatures
    function deserializeNotarization(bytes calldata proof, uint32 maxSigners)
        public pure returns (
            bytes calldata proposalBytes,
            bytes memory signersBitmap,
            uint32 signatureCount
        )
    {
        uint256 offset = 0;

        // Extract proposal bytes
        (proposalBytes, offset) = extractProposalBytes(proof, offset);

        // Read signers bitmap
        uint64 bitmapLengthInBits;
        (bitmapLengthInBits, signersBitmap, offset) = CodecHelpers.deserializeSignersBitmap(proof, offset, maxSigners);

        // Read signature count (varint)
        (signatureCount, offset) = CodecHelpers.decodeVarintU32(proof, offset);

        if (signatureCount > maxSigners) revert CodecHelpers.TooManySigners();

        // Validate remaining length matches signature count
        uint256 expectedRemaining = signatureCount * ED25519_SIGNATURE_LENGTH;
        if (offset + expectedRemaining != proof.length) revert CodecHelpers.InvalidProofLength();

        return (proposalBytes, signersBitmap, signatureCount);
    }

    /// @notice Deserialize a Nullification certificate (quorum of Nullify votes)
    /// @dev Encoding: Round + Certificate (bitmap + signatures)
    /// @dev Rust: Nullification { round: Round, certificate: Certificate }
    /// @param proof The serialized proof bytes
    /// @param maxSigners Maximum allowed signers (for DoS protection)
    /// @return roundBytes Raw round bytes for verification
    /// @return signersBitmap Bitmap of validator indices that signed
    /// @return signatureCount Number of signatures
    function deserializeNullification(bytes calldata proof, uint32 maxSigners)
        public pure returns (
            bytes calldata roundBytes,
            bytes memory signersBitmap,
            uint32 signatureCount
        )
    {
        uint256 offset = 0;

        // Extract round bytes
        (roundBytes, offset) = extractRoundBytes(proof, offset);

        // Read signers bitmap
        uint64 bitmapLengthInBits;
        (bitmapLengthInBits, signersBitmap, offset) = CodecHelpers.deserializeSignersBitmap(proof, offset, maxSigners);

        // Read signature count (varint)
        (signatureCount, offset) = CodecHelpers.decodeVarintU32(proof, offset);

        if (signatureCount > maxSigners) revert CodecHelpers.TooManySigners();

        // Validate remaining length matches signature count
        uint256 expectedRemaining = signatureCount * ED25519_SIGNATURE_LENGTH;
        if (offset + expectedRemaining != proof.length) revert CodecHelpers.InvalidProofLength();

        return (roundBytes, signersBitmap, signatureCount);
    }

    /// @notice Deserialize a Finalization certificate
    /// @dev Identical structure to Notarization
    function deserializeFinalization(bytes calldata proof, uint32 maxSigners)
        public pure returns (
            bytes calldata proposalBytes,
            bytes memory signersBitmap,
            uint32 signatureCount
        )
    {
        return deserializeNotarization(proof, maxSigners);
    }


    // ============ Fraud Proof Deserialization ============

    /// @notice Deserialize ConflictingNotarize proof
    /// @dev Rust: pub struct ConflictingNotarize<S, D> { notarize_1, notarize_2 }
    /// @dev Proves a validator signed two different proposals at the same round
    /// @param proof The serialized proof bytes
    /// @return proposalBytes1 First proposal bytes for verification
    /// @return signer1 First signer index
    /// @return signature1 First signature bytes
    /// @return proposalBytes2 Second proposal bytes for verification
    /// @return signer2 Second signer index (should equal signer1)
    /// @return signature2 Second signature bytes
    function deserializeConflictingNotarize(bytes calldata proof)
        public pure returns (
            bytes calldata proposalBytes1,
            uint32 signer1,
            bytes calldata signature1,
            bytes calldata proposalBytes2,
            uint32 signer2,
            bytes calldata signature2
        )
    {
        uint256 offset = 0;

        // Deserialize first Notarize
        (proposalBytes1, offset) = extractProposalBytes(proof, offset);

        if (offset + 4 > proof.length) revert CodecHelpers.InvalidProofLength();
        signer1 = uint32(bytes4(proof[offset:offset+4]));
        offset += 4;

        if (offset + ED25519_SIGNATURE_LENGTH > proof.length) revert CodecHelpers.InvalidProofLength();
        signature1 = proof[offset:offset+ED25519_SIGNATURE_LENGTH];
        offset += ED25519_SIGNATURE_LENGTH;

        // Deserialize second Notarize
        (proposalBytes2, offset) = extractProposalBytes(proof, offset);

        if (offset + 4 > proof.length) revert CodecHelpers.InvalidProofLength();
        signer2 = uint32(bytes4(proof[offset:offset+4]));
        offset += 4;

        if (offset + ED25519_SIGNATURE_LENGTH > proof.length) revert CodecHelpers.InvalidProofLength();
        signature2 = proof[offset:offset+ED25519_SIGNATURE_LENGTH];
        offset += ED25519_SIGNATURE_LENGTH;

        if (offset != proof.length) revert CodecHelpers.InvalidProofLength();

        // Validate Byzantine behavior: same round, same signer, different proposals
        bytes calldata round1 = proposalBytes1[0:16];
        bytes calldata round2 = proposalBytes2[0:16];
        validateRoundsMatch(round1, round2);
        if (signer1 != signer2) revert Conflicting_SignerMismatch();
        validateProposalsDiffer(proposalBytes1, proposalBytes2);

        return (proposalBytes1, signer1, signature1, proposalBytes2, signer2, signature2);
    }

    /// @notice Deserialize ConflictingFinalize proof
    /// @dev Identical structure to ConflictingNotarize
    function deserializeConflictingFinalize(bytes calldata proof)
        public pure returns (
            bytes calldata proposalBytes1,
            uint32 signer1,
            bytes calldata signature1,
            bytes calldata proposalBytes2,
            uint32 signer2,
            bytes calldata signature2
        )
    {
        return deserializeConflictingNotarize(proof);
    }

    /// @notice Deserialize NullifyFinalize proof
    /// @dev Rust: pub struct NullifyFinalize<S, D> { nullify: Nullify<S>, finalize: Finalize<S, D> }
    /// @dev Proves a validator voted both to skip AND finalize the same round
    /// @param proof The serialized proof bytes
    /// @return nullifyRoundBytes Nullify round bytes for verification
    /// @return nullifySigner Nullify signer index
    /// @return nullifySignature Nullify signature bytes
    /// @return finalizeProposalBytes Finalize proposal bytes for verification
    /// @return finalizeSigner Finalize signer index (should equal nullifySigner)
    /// @return finalizeSignature Finalize signature bytes
    function deserializeNullifyFinalize(bytes calldata proof)
        public pure returns (
            bytes calldata nullifyRoundBytes,
            uint32 nullifySigner,
            bytes calldata nullifySignature,
            bytes calldata finalizeProposalBytes,
            uint32 finalizeSigner,
            bytes calldata finalizeSignature
        )
    {
        uint256 offset = 0;

        // Deserialize Nullify
        (nullifyRoundBytes, offset) = extractRoundBytes(proof, offset);

        if (offset + 4 > proof.length) revert CodecHelpers.InvalidProofLength();
        nullifySigner = uint32(bytes4(proof[offset:offset+4]));
        offset += 4;

        if (offset + ED25519_SIGNATURE_LENGTH > proof.length) revert CodecHelpers.InvalidProofLength();
        nullifySignature = proof[offset:offset+ED25519_SIGNATURE_LENGTH];
        offset += ED25519_SIGNATURE_LENGTH;

        // Deserialize Finalize
        (finalizeProposalBytes, offset) = extractProposalBytes(proof, offset);

        if (offset + 4 > proof.length) revert CodecHelpers.InvalidProofLength();
        finalizeSigner = uint32(bytes4(proof[offset:offset+4]));
        offset += 4;

        if (offset + ED25519_SIGNATURE_LENGTH > proof.length) revert CodecHelpers.InvalidProofLength();
        finalizeSignature = proof[offset:offset+ED25519_SIGNATURE_LENGTH];
        offset += ED25519_SIGNATURE_LENGTH;

        if (offset != proof.length) revert CodecHelpers.InvalidProofLength();

        // Validate Byzantine behavior: same round, same signer
        bytes calldata finalizeRoundBytes = finalizeProposalBytes[0:16];
        validateRoundsMatch(nullifyRoundBytes, finalizeRoundBytes);
        if (nullifySigner != finalizeSigner) revert Conflicting_SignerMismatch();

        return (nullifyRoundBytes, nullifySigner, nullifySignature, finalizeProposalBytes, finalizeSigner, finalizeSignature);
    }

    // ============ Verification Functions ============

    /// @notice Verify a Notarize vote (individual signature)
    /// @dev Constructs the signed message using union_unique format and verifies the signature
    /// @param namespace The application namespace (e.g., "MyApp")
    /// @param proposalBytes The proposal bytes from deserialization
    /// @param signer The signer index
    /// @param signature The Ed25519 signature bytes
    /// @param publicKey The signer's Ed25519 public key (32 bytes)
    /// @param hashFunc The hash function to use (SHA256 or KECCAK256)
    /// @return true if the signature is valid, false otherwise
    function verifyNotarize(
        bytes memory namespace,
        bytes calldata proposalBytes,
        uint32 signer,
        bytes calldata signature,
        bytes32 publicKey,
        HashFunction hashFunc
    ) public pure returns (bool) {
        // Construct the signed message: varint(len) + "namespace_NOTARIZE" + proposal_bytes
        bytes memory namespaceWithSuffix = abi.encodePacked(namespace, "_NOTARIZE");
        bytes memory signedMessage = encodeSignedMessage(namespaceWithSuffix, proposalBytes);

        // Hash the signed message using the specified hash function
        bytes32 messageHash = hashMessage(signedMessage, hashFunc);

        // Verify the Ed25519 signature
        return _verifyEd25519(messageHash, publicKey, signature);
    }

    /// @notice Verify a Nullify vote (individual signature)
    /// @dev Constructs the signed message using union_unique format and verifies the signature
    /// @param namespace The application namespace (e.g., "MyApp")
    /// @param roundBytes The round bytes from deserialization (16 bytes)
    /// @param signer The signer index
    /// @param signature The Ed25519 signature bytes
    /// @param publicKey The signer's Ed25519 public key (32 bytes)
    /// @param hashFunc The hash function to use (SHA256 or KECCAK256)
    /// @return true if the signature is valid, false otherwise
    function verifyNullify(
        bytes memory namespace,
        bytes calldata roundBytes,
        uint32 signer,
        bytes calldata signature,
        bytes32 publicKey,
        HashFunction hashFunc
    ) public pure returns (bool) {
        // Construct the signed message: varint(len) + "namespace_NULLIFY" + round_bytes
        bytes memory namespaceWithSuffix = abi.encodePacked(namespace, "_NULLIFY");
        bytes memory signedMessage = encodeSignedMessage(namespaceWithSuffix, roundBytes);

        // Hash the signed message using the specified hash function
        bytes32 messageHash = hashMessage(signedMessage, hashFunc);

        // Verify the Ed25519 signature
        return _verifyEd25519(messageHash, publicKey, signature);
    }

    /// @notice Verify a Finalize vote (individual signature)
    /// @dev Identical to verifyNotarize (same message format)
    /// @param namespace The application namespace (e.g., "MyApp")
    /// @param proposalBytes The proposal bytes from deserialization
    /// @param signer The signer index
    /// @param signature The Ed25519 signature bytes
    /// @param publicKey The signer's Ed25519 public key (32 bytes)
    /// @param hashFunc The hash function to use (SHA256 or KECCAK256)
    /// @return true if the signature is valid, false otherwise
    function verifyFinalize(
        bytes memory namespace,
        bytes calldata proposalBytes,
        uint32 signer,
        bytes calldata signature,
        bytes32 publicKey,
        HashFunction hashFunc
    ) public pure returns (bool) {
        // Construct the signed message: varint(len) + "namespace_FINALIZE" + proposal_bytes
        bytes memory namespaceWithSuffix = abi.encodePacked(namespace, "_FINALIZE");
        bytes memory signedMessage = encodeSignedMessage(namespaceWithSuffix, proposalBytes);

        // Hash the signed message using the specified hash function
        bytes32 messageHash = hashMessage(signedMessage, hashFunc);

        // Verify the Ed25519 signature
        return _verifyEd25519(messageHash, publicKey, signature);
    }

    /// @notice Verify a Notarization certificate (batch signature verification)
    /// @dev Verifies all signatures in the certificate and checks quorum requirements
    /// @param namespace The application namespace (e.g., "MyApp")
    /// @param proof The complete proof bytes (contains proposal + certificate)
    /// @param maxSigners Maximum allowed signers (for DoS protection)
    /// @param quorum Required quorum percentage (e.g., 67 for 67%)
    /// @param publicKeys All validator public keys (indexed by signer)
    /// @param hashFunc The hash function to use (SHA256 or KECCAK256)
    /// @return true if the certificate is valid, false otherwise
    function verifyNotarization(
        bytes memory namespace,
        bytes calldata proof,
        uint32 maxSigners,
        uint32 quorum,
        bytes32[] memory publicKeys,
        HashFunction hashFunc
    ) public pure returns (bool) {
        // Deserialize the notarization
        (bytes calldata proposalBytes, bytes memory signersBitmap, uint32 signatureCount) =
            deserializeNotarization(proof, maxSigners);

        // Validate quorum: signatureCount >= (publicKeys.length * quorum + 99) / 100
        uint32 requiredSigners = uint32((uint256(publicKeys.length) * quorum + 99) / 100);
        if (signatureCount < requiredSigners) return false;

        // Construct the signed message
        bytes memory namespaceWithSuffix = abi.encodePacked(namespace, "_NOTARIZE");
        bytes memory signedMessage = encodeSignedMessage(namespaceWithSuffix, proposalBytes);
        bytes32 messageHash = hashMessage(signedMessage, hashFunc);

        // Calculate offset to start of signatures
        uint256 offset = proposalBytes.length;
        // Skip bitmap (u64 length + bytes)
        offset += 8; // bitmap length
        uint256 bitmapByteLength = (signersBitmap.length);
        offset += bitmapByteLength;
        // Skip signature count varint
        (, uint256 afterVarint) = CodecHelpers.decodeVarintU32(proof, offset);
        offset = afterVarint;

        // Verify each signature
        uint32 sigIndex = 0;
        for (uint32 i = 0; i < publicKeys.length && sigIndex < signatureCount; i++) {
            if (CodecHelpers.getBit(signersBitmap, i)) {
                bytes calldata sig = proof[offset:offset+ED25519_SIGNATURE_LENGTH];
                if (!_verifyEd25519(messageHash, publicKeys[i], sig)) {
                    return false;
                }
                offset += ED25519_SIGNATURE_LENGTH;
                sigIndex++;
            }
        }

        return sigIndex == signatureCount;
    }

    /// @notice Verify a Nullification certificate (batch signature verification)
    /// @dev Verifies all signatures in the certificate and checks quorum requirements
    /// @param namespace The application namespace (e.g., "MyApp")
    /// @param proof The complete proof bytes (contains round + certificate)
    /// @param maxSigners Maximum allowed signers (for DoS protection)
    /// @param quorum Required quorum percentage (e.g., 67 for 67%)
    /// @param publicKeys All validator public keys (indexed by signer)
    /// @param hashFunc The hash function to use (SHA256 or KECCAK256)
    /// @return true if the certificate is valid, false otherwise
    function verifyNullification(
        bytes memory namespace,
        bytes calldata proof,
        uint32 maxSigners,
        uint32 quorum,
        bytes32[] memory publicKeys,
        HashFunction hashFunc
    ) public pure returns (bool) {
        // Deserialize the nullification
        (bytes calldata roundBytes, bytes memory signersBitmap, uint32 signatureCount) =
            deserializeNullification(proof, maxSigners);

        // Validate quorum
        uint32 requiredSigners = uint32((uint256(publicKeys.length) * quorum + 99) / 100);
        if (signatureCount < requiredSigners) return false;

        // Construct the signed message
        bytes memory namespaceWithSuffix = abi.encodePacked(namespace, "_NULLIFY");
        bytes memory signedMessage = encodeSignedMessage(namespaceWithSuffix, roundBytes);
        bytes32 messageHash = hashMessage(signedMessage, hashFunc);

        // Calculate offset to start of signatures
        uint256 offset = roundBytes.length; // 16 bytes
        // Skip bitmap
        offset += 8;
        offset += signersBitmap.length;
        // Skip signature count varint
        (, uint256 afterVarint) = CodecHelpers.decodeVarintU32(proof, offset);
        offset = afterVarint;

        // Verify each signature
        uint32 sigIndex = 0;
        for (uint32 i = 0; i < publicKeys.length && sigIndex < signatureCount; i++) {
            if (CodecHelpers.getBit(signersBitmap, i)) {
                bytes calldata sig = proof[offset:offset+ED25519_SIGNATURE_LENGTH];
                if (!_verifyEd25519(messageHash, publicKeys[i], sig)) {
                    return false;
                }
                offset += ED25519_SIGNATURE_LENGTH;
                sigIndex++;
            }
        }

        return sigIndex == signatureCount;
    }

    /// @notice Verify a Finalization certificate (batch signature verification)
    /// @dev Identical to verifyNotarization (same message format with _FINALIZE suffix)
    /// @param namespace The application namespace (e.g., "MyApp")
    /// @param proof The complete proof bytes (contains proposal + certificate)
    /// @param maxSigners Maximum allowed signers (for DoS protection)
    /// @param quorum Required quorum percentage (e.g., 67 for 67%)
    /// @param publicKeys All validator public keys (indexed by signer)
    /// @param hashFunc The hash function to use (SHA256 or KECCAK256)
    /// @return true if the certificate is valid, false otherwise
    function verifyFinalization(
        bytes memory namespace,
        bytes calldata proof,
        uint32 maxSigners,
        uint32 quorum,
        bytes32[] memory publicKeys,
        HashFunction hashFunc
    ) public pure returns (bool) {
        // Deserialize the finalization
        (bytes calldata proposalBytes, bytes memory signersBitmap, uint32 signatureCount) =
            deserializeFinalization(proof, maxSigners);

        // Validate quorum
        uint32 requiredSigners = uint32((uint256(publicKeys.length) * quorum + 99) / 100);
        if (signatureCount < requiredSigners) return false;

        // Construct the signed message (note: _FINALIZE suffix, not _NOTARIZE)
        bytes memory namespaceWithSuffix = abi.encodePacked(namespace, "_FINALIZE");
        bytes memory signedMessage = encodeSignedMessage(namespaceWithSuffix, proposalBytes);
        bytes32 messageHash = hashMessage(signedMessage, hashFunc);

        // Calculate offset to start of signatures
        uint256 offset = proposalBytes.length;
        offset += 8;
        offset += signersBitmap.length;
        (, uint256 afterVarint) = CodecHelpers.decodeVarintU32(proof, offset);
        offset = afterVarint;

        // Verify each signature
        uint32 sigIndex = 0;
        for (uint32 i = 0; i < publicKeys.length && sigIndex < signatureCount; i++) {
            if (CodecHelpers.getBit(signersBitmap, i)) {
                bytes calldata sig = proof[offset:offset+ED25519_SIGNATURE_LENGTH];
                if (!_verifyEd25519(messageHash, publicKeys[i], sig)) {
                    return false;
                }
                offset += ED25519_SIGNATURE_LENGTH;
                sigIndex++;
            }
        }

        return sigIndex == signatureCount;
    }

    /// @notice Verify a ConflictingNotarize fraud proof
    /// @dev Verifies BOTH notarize signatures to prove Byzantine behavior
    /// @param namespace The application namespace (e.g., "MyApp")
    /// @param proof The complete proof bytes
    /// @param publicKey The Byzantine validator's public key
    /// @param hashFunc The hash function to use (SHA256 or KECCAK256)
    /// @return true if both signatures are valid (proving the conflict), false otherwise
    function verifyConflictingNotarize(
        bytes memory namespace,
        bytes calldata proof,
        bytes32 publicKey,
        HashFunction hashFunc
    ) public pure returns (bool) {
        (
            bytes calldata proposalBytes1,
            uint32 signer1,
            bytes calldata signature1,
            bytes calldata proposalBytes2,
            uint32 signer2,
            bytes calldata signature2
        ) = deserializeConflictingNotarize(proof);

        // Verify both notarize signatures
        bool valid1 = verifyNotarize(namespace, proposalBytes1, signer1, signature1, publicKey, hashFunc);
        bool valid2 = verifyNotarize(namespace, proposalBytes2, signer2, signature2, publicKey, hashFunc);

        return valid1 && valid2;
    }

    /// @notice Verify a ConflictingFinalize fraud proof
    /// @dev Verifies BOTH finalize signatures to prove Byzantine behavior
    /// @param namespace The application namespace (e.g., "MyApp")
    /// @param proof The complete proof bytes
    /// @param publicKey The Byzantine validator's public key
    /// @param hashFunc The hash function to use (SHA256 or KECCAK256)
    /// @return true if both signatures are valid (proving the conflict), false otherwise
    function verifyConflictingFinalize(
        bytes memory namespace,
        bytes calldata proof,
        bytes32 publicKey,
        HashFunction hashFunc
    ) public pure returns (bool) {
        (
            bytes calldata proposalBytes1,
            uint32 signer1,
            bytes calldata signature1,
            bytes calldata proposalBytes2,
            uint32 signer2,
            bytes calldata signature2
        ) = deserializeConflictingFinalize(proof);

        // Verify both finalize signatures
        bool valid1 = verifyFinalize(namespace, proposalBytes1, signer1, signature1, publicKey, hashFunc);
        bool valid2 = verifyFinalize(namespace, proposalBytes2, signer2, signature2, publicKey, hashFunc);

        return valid1 && valid2;
    }

    /// @notice Verify a NullifyFinalize fraud proof
    /// @dev Verifies BOTH nullify and finalize signatures to prove Byzantine behavior
    /// @param namespace The application namespace (e.g., "MyApp")
    /// @param proof The complete proof bytes
    /// @param publicKey The Byzantine validator's public key
    /// @param hashFunc The hash function to use (SHA256 or KECCAK256)
    /// @return true if both signatures are valid (proving the conflict), false otherwise
    function verifyNullifyFinalize(
        bytes memory namespace,
        bytes calldata proof,
        bytes32 publicKey,
        HashFunction hashFunc
    ) public pure returns (bool) {
        (
            bytes calldata nullifyRoundBytes,
            uint32 nullifySigner,
            bytes calldata nullifySignature,
            bytes calldata finalizeProposalBytes,
            uint32 finalizeSigner,
            bytes calldata finalizeSignature
        ) = deserializeNullifyFinalize(proof);

        // Verify both signatures
        bool validNullify = verifyNullify(namespace, nullifyRoundBytes, nullifySigner, nullifySignature, publicKey, hashFunc);
        bool validFinalize = verifyFinalize(namespace, finalizeProposalBytes, finalizeSigner, finalizeSignature, publicKey, hashFunc);

        return validNullify && validFinalize;
    }

    // ============ Internal Helpers ============

    /// @notice Verify Ed25519 signature
    /// @dev To be implemented with precompile or library
    /// @param messageHash The hash of the message (32 bytes)
    /// @param publicKey The Ed25519 public key (32 bytes)
    /// @param signature The Ed25519 signature (64 bytes)
    /// @return true if signature is valid, false otherwise
    function _verifyEd25519(
        bytes32 messageHash,
        bytes32 publicKey,
        bytes calldata signature
    ) internal pure returns (bool) {
        if (signature.length != ED25519_SIGNATURE_LENGTH) return false;

        // TODO: Implement Ed25519 verification using precompile or library
        // Placeholder: always return true for now (NOT FOR PRODUCTION!)
        return true;
    }
}
