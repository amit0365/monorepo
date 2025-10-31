// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./SimplexVerifierBase.sol";
import {CodecHelpers} from "./libraries/CodecHelpers.sol";
import {ISignatureScheme} from "./interfaces/ISignatureScheme.sol";

/// @title SimplexVerifierAttributable
/// @notice Concrete verifier for attributable signature schemes (Ed25519, BLS Multisig)
/// @dev Provides shared deserialization and verification logic for schemes with individual signatures
/// @dev Delegates signature verification to an ISignatureScheme implementation
contract SimplexVerifierAttributable is SimplexVerifierBase {
    // ============ Immutable Configuration ============

    /// @notice The signature scheme used for verification
    ISignatureScheme public immutable scheme;

    /// @notice Digest length used by the application (32 for SHA256/KECCAK256, 64 for SHA512)
    DigestLength public immutable DIGEST_LENGTH;

    // ============ Constructor ============

    /// @param _scheme The signature scheme to use for verification
    /// @param _digestLength Length of payload digests in proposals
    constructor(
        ISignatureScheme _scheme,
        DigestLength _digestLength
    ) {
        scheme = _scheme;
        DIGEST_LENGTH = _digestLength;
    }

    // ============ Scheme Properties ============

    /// @notice Get the signature length from the scheme
    /// @return Length of signatures in bytes (64 for Ed25519, 96 for BLS)
    function SIGNATURE_LENGTH() public view returns (uint256) {
        return scheme.SIGNATURE_LENGTH();
    }

    /// @notice Get the public key length from the scheme
    /// @return Length of public keys in bytes (32 for Ed25519, 48+ for BLS)
    function PUBLIC_KEY_LENGTH() public view returns (uint256) {
        return scheme.PUBLIC_KEY_LENGTH();
    }

    // ============ Signature Verification ============

    /// @notice Verify a signature using the configured scheme
    /// @dev Delegates to the ISignatureScheme implementation
    /// @param message The full message bytes (NOT a hash - raw union_unique output)
    /// @param publicKey The signer's public key (32 bytes for Ed25519, variable for BLS)
    /// @param signature The signature bytes
    /// @return true if signature is valid, false otherwise
    function _verifySignature(
        bytes memory message,
        bytes32 publicKey,
        bytes memory signature
    ) internal view returns (bool) {
        // Convert bytes32 public key to bytes for the interface
        bytes memory publicKeyBytes = abi.encodePacked(publicKey);
        return scheme.verifySignature(message, publicKeyBytes, signature);
    }

    // ============ Individual Activity Deserialization ============

    /// @notice Deserialize a Notarize message
    /// @dev Rust: pub struct Notarize<S, D> { proposal: Proposal<D>, vote: Vote<S> }
    /// @dev Format: proposal_bytes + signer (4 bytes) + signature (SIGNATURE_LENGTH bytes)
    /// @param proof The serialized proof bytes
    /// @return proposalBytes Raw proposal bytes for verification
    /// @return signer The signer index
    /// @return signature The signature bytes
    function deserializeNotarize(bytes calldata proof)
        public view returns (
            bytes calldata proposalBytes,
            uint32 signer,
            bytes calldata signature
        )
    {
        uint256 offset;
        (proposalBytes, offset) = extractProposalBytes(proof, 0, DIGEST_LENGTH);
        (signer, signature, offset) = CodecHelpers.deserializeSignerAndSignature(proof, offset, SIGNATURE_LENGTH());
        if (offset != proof.length) revert CodecHelpers.InvalidProofLength();
        return (proposalBytes, signer, signature);
    }

    /// @notice Deserialize a Nullify message
    /// @dev Rust: pub struct Nullify<S> { round: Round, vote: Vote<S> }
    /// @dev Format: round_bytes (16 bytes) + signer (4 bytes) + signature (SIGNATURE_LENGTH bytes)
    /// @param proof The serialized proof bytes
    /// @return roundBytes Raw round bytes for verification
    /// @return signer The signer index
    /// @return signature The signature bytes
    function deserializeNullify(bytes calldata proof)
        public view returns (
            bytes calldata roundBytes,
            uint32 signer,
            bytes calldata signature
        )
    {
        uint256 offset;
        (roundBytes, offset) = extractRoundBytes(proof, 0);
        (signer, signature, offset) = CodecHelpers.deserializeSignerAndSignature(proof, offset, SIGNATURE_LENGTH());
        if (offset != proof.length) revert CodecHelpers.InvalidProofLength();
        return (roundBytes, signer, signature);
    }

    /// @notice Deserialize a Finalize message
    /// @dev Identical structure to Notarize
    function deserializeFinalize(bytes calldata proof)
        public view returns (
            bytes calldata proposalBytes,
            uint32 signer,
            bytes calldata signature
        )
    {
        return deserializeNotarize(proof);
    }

    // ============ Individual Vote Verification ============

    /// @notice Verify a Notarize vote (individual signature)
    /// @param namespace The application namespace (e.g., "MyApp")
    /// @param proposalBytes The proposal bytes from deserialization
    /// @param signer The signer index (unused in verification, for API compatibility)
    /// @param signature The signature bytes
    /// @param publicKey The signer's public key
    /// @return true if the signature is valid, false otherwise
    function verifyNotarize(
        bytes memory namespace,
        bytes calldata proposalBytes,
        uint32 signer,
        bytes calldata signature,
        bytes32 publicKey
    ) public view returns (bool) {
        bytes memory namespaceWithSuffix = abi.encodePacked(namespace, "_NOTARIZE");
        bytes memory signedMessage = encodeSignedMessage(namespaceWithSuffix, proposalBytes);
        return _verifySignature(signedMessage, publicKey, bytes(signature));
    }

    /// @notice Verify a Nullify vote (individual signature)
    /// @param namespace The application namespace (e.g., "MyApp")
    /// @param roundBytes The round bytes from deserialization (16 bytes)
    /// @param signer The signer index (unused in verification, for API compatibility)
    /// @param signature The signature bytes
    /// @param publicKey The signer's public key
    /// @return true if the signature is valid, false otherwise
    function verifyNullify(
        bytes memory namespace,
        bytes calldata roundBytes,
        uint32 signer,
        bytes calldata signature,
        bytes32 publicKey
    ) public view returns (bool) {
        bytes memory namespaceWithSuffix = abi.encodePacked(namespace, "_NULLIFY");
        bytes memory signedMessage = encodeSignedMessage(namespaceWithSuffix, roundBytes);
        return _verifySignature(signedMessage, publicKey, bytes(signature));
    }

    /// @notice Verify a Finalize vote (individual signature)
    /// @param namespace The application namespace (e.g., "MyApp")
    /// @param proposalBytes The proposal bytes from deserialization
    /// @param signer The signer index (unused in verification, for API compatibility)
    /// @param signature The signature bytes
    /// @param publicKey The signer's public key
    /// @return true if the signature is valid, false otherwise
    function verifyFinalize(
        bytes memory namespace,
        bytes calldata proposalBytes,
        uint32 signer,
        bytes calldata signature,
        bytes32 publicKey
    ) public view returns (bool) {
        bytes memory namespaceWithSuffix = abi.encodePacked(namespace, "_FINALIZE");
        bytes memory signedMessage = encodeSignedMessage(namespaceWithSuffix, proposalBytes);
        return _verifySignature(signedMessage, publicKey, bytes(signature));
    }

    // ============ Certificate Deserialization ============

    /// @notice Deserialize a Notarization certificate
    /// @dev Format: proposal_bytes + bitmap + signature_count (varint) + signatures
    /// @param proof The serialized certificate bytes
    /// @param maxParticipants Maximum participants for DoS protection
    /// @return proposalBytes Raw proposal bytes
    /// @return signersBitmap Bitmap indicating which validators signed
    /// @return signatures Array of signature bytes
    function deserializeNotarization(bytes calldata proof, uint32 maxParticipants)
        public view returns (
            bytes calldata proposalBytes,
            bytes memory signersBitmap,
            bytes[] memory signatures
        )
    {
        uint256 offset = 0;
        bytes memory bitmapMem;
        uint64 signatureCount;
        uint256 messageEndOffset;

        // Extract proposal bytes first
        (proposalBytes, offset) = extractProposalBytes(proof, 0, DIGEST_LENGTH);
        messageEndOffset = offset;

        // Deserialize bitmap and signature count
        uint64 bitmapLengthInBits;
        (bitmapLengthInBits, bitmapMem, offset) =
            CodecHelpers.deserializeSignersBitmap(proof, offset, maxParticipants);
        (signatureCount, offset) = CodecHelpers.decodeVarintU64(proof, offset);

        // Read all signatures
        signatures = new bytes[](signatureCount);
        uint256 sigLen = SIGNATURE_LENGTH();
        for (uint64 i = 0; i < signatureCount; i++) {
            if (offset + sigLen > proof.length) revert CodecHelpers.InvalidProofLength();
            signatures[i] = proof[offset:offset+sigLen];
            offset += sigLen;
        }

        if (offset != proof.length) revert CodecHelpers.InvalidProofLength();

        signersBitmap = bitmapMem;
        return (proposalBytes, signersBitmap, signatures);
    }

    /// @notice Deserialize a Nullification certificate
    /// @dev Format: round_bytes (16 bytes) + bitmap + signature_count (varint) + signatures
    /// @param proof The serialized certificate bytes
    /// @param maxParticipants Maximum participants for DoS protection
    /// @return roundBytes Raw round bytes (16 bytes)
    /// @return signersBitmap Bitmap indicating which validators signed
    /// @return signatures Array of signature bytes
    function deserializeNullification(bytes calldata proof, uint32 maxParticipants)
        public view returns (
            bytes calldata roundBytes,
            bytes memory signersBitmap,
            bytes[] memory signatures
        )
    {
        uint256 offset = 0;
        bytes memory bitmapMem;
        uint64 signatureCount;

        // Extract round bytes (16 bytes)
        (roundBytes, offset) = extractRoundBytes(proof, 0);

        // Deserialize bitmap and signature count
        uint64 bitmapLengthInBits;
        (bitmapLengthInBits, bitmapMem, offset) =
            CodecHelpers.deserializeSignersBitmap(proof, offset, maxParticipants);
        (signatureCount, offset) = CodecHelpers.decodeVarintU64(proof, offset);

        // Read all signatures
        signatures = new bytes[](signatureCount);
        uint256 sigLen = SIGNATURE_LENGTH();
        for (uint64 i = 0; i < signatureCount; i++) {
            if (offset + sigLen > proof.length) revert CodecHelpers.InvalidProofLength();
            signatures[i] = proof[offset:offset+sigLen];
            offset += sigLen;
        }

        if (offset != proof.length) revert CodecHelpers.InvalidProofLength();

        signersBitmap = bitmapMem;
        return (roundBytes, signersBitmap, signatures);
    }

    /// @notice Deserialize a Finalization certificate
    /// @dev Identical structure to Notarization
    function deserializeFinalization(bytes calldata proof, uint32 maxParticipants)
        public view returns (
            bytes calldata proposalBytes,
            bytes memory signersBitmap,
            bytes[] memory signatures
        )
    {
        return deserializeNotarization(proof, maxParticipants);
    }

    // ============ Certificate Verification ============

    /// @notice Verify certificate signatures
    /// @dev Helper that verifies all signatures in a certificate
    /// @param signedMessage The full message that was signed (union_unique format)
    /// @param signatures Array of signature bytes
    /// @param publicKeys Array of public keys corresponding to signatures
    /// @return true if all signatures are valid, false otherwise
    function _verifyCertificateSignatures(
        bytes memory signedMessage,
        bytes[] memory signatures,
        bytes32[] memory publicKeys
    ) internal view returns (bool) {
        if (signatures.length != publicKeys.length) return false;

        for (uint256 i = 0; i < signatures.length; i++) {
            if (!_verifySignature(signedMessage, publicKeys[i], signatures[i])) {
                return false;
            }
        }

        return true;
    }

    /// @notice Verify a certificate (helper for Notarization/Nullification/Finalization)
    /// @param namespace The application namespace
    /// @param namespaceWithSuffix The full namespace with activity suffix
    /// @param messageBytes The message bytes (proposal or round)
    /// @param signersBitmap Bitmap of signers
    /// @param signatures Array of signatures
    /// @param publicKeys Array of all public keys
    /// @param quorum Required quorum (number of signatures needed)
    /// @return true if the certificate is valid, false otherwise
    function _verifyCertificate(
        bytes memory namespace,
        bytes memory namespaceWithSuffix,
        bytes calldata messageBytes,
        bytes memory signersBitmap,
        bytes[] memory signatures,
        bytes32[] memory publicKeys,
        uint32 quorum
    ) internal view returns (bool) {
        // Validate quorum
        if (signatures.length < quorum) return false;

        // Build signed message
        bytes memory signedMessage = encodeSignedMessage(namespaceWithSuffix, messageBytes);

        // Extract public keys for signers from bitmap
        bytes32[] memory signerPublicKeys = new bytes32[](signatures.length);
        uint256 signerIndex = 0;
        uint256 bitmapBitIndex = 0;

        for (uint256 i = 0; i < publicKeys.length && signerIndex < signatures.length; i++) {
            if (CodecHelpers.getBit(signersBitmap, bitmapBitIndex)) {
                signerPublicKeys[signerIndex] = publicKeys[i];
                signerIndex++;
            }
            bitmapBitIndex++;
        }

        // Verify all signatures
        return _verifyCertificateSignatures(signedMessage, signatures, signerPublicKeys);
    }

    /// @notice Verify a Notarization certificate
    /// @param namespace The application namespace (e.g., "MyApp")
    /// @param proposalBytes The proposal bytes from deserialization
    /// @param signersBitmap Bitmap of signers
    /// @param signatures Array of signatures
    /// @param publicKeys Array of all validator public keys
    /// @param quorum Required quorum
    /// @return true if the certificate is valid, false otherwise
    function verifyNotarization(
        bytes memory namespace,
        bytes calldata proposalBytes,
        bytes memory signersBitmap,
        bytes[] memory signatures,
        bytes32[] memory publicKeys,
        uint32 quorum
    ) public view returns (bool) {
        bytes memory namespaceWithSuffix = abi.encodePacked(namespace, "_NOTARIZE");
        return _verifyCertificate(
            namespace,
            namespaceWithSuffix,
            proposalBytes,
            signersBitmap,
            signatures,
            publicKeys,
            quorum
        );
    }

    /// @notice Verify a Nullification certificate
    /// @param namespace The application namespace (e.g., "MyApp")
    /// @param roundBytes The round bytes from deserialization (16 bytes)
    /// @param signersBitmap Bitmap of signers
    /// @param signatures Array of signatures
    /// @param publicKeys Array of all validator public keys
    /// @param quorum Required quorum
    /// @return true if the certificate is valid, false otherwise
    function verifyNullification(
        bytes memory namespace,
        bytes calldata roundBytes,
        bytes memory signersBitmap,
        bytes[] memory signatures,
        bytes32[] memory publicKeys,
        uint32 quorum
    ) public view returns (bool) {
        bytes memory namespaceWithSuffix = abi.encodePacked(namespace, "_NULLIFY");
        return _verifyCertificate(
            namespace,
            namespaceWithSuffix,
            roundBytes,
            signersBitmap,
            signatures,
            publicKeys,
            quorum
        );
    }

    /// @notice Verify a Finalization certificate
    /// @param namespace The application namespace (e.g., "MyApp")
    /// @param proposalBytes The proposal bytes from deserialization
    /// @param signersBitmap Bitmap of signers
    /// @param signatures Array of signatures
    /// @param publicKeys Array of all validator public keys
    /// @param quorum Required quorum
    /// @return true if the certificate is valid, false otherwise
    function verifyFinalization(
        bytes memory namespace,
        bytes calldata proposalBytes,
        bytes memory signersBitmap,
        bytes[] memory signatures,
        bytes32[] memory publicKeys,
        uint32 quorum
    ) public view returns (bool) {
        bytes memory namespaceWithSuffix = abi.encodePacked(namespace, "_FINALIZE");
        return _verifyCertificate(
            namespace,
            namespaceWithSuffix,
            proposalBytes,
            signersBitmap,
            signatures,
            publicKeys,
            quorum
        );
    }

    // ============ Fraud Proof Deserialization ============

    /// @notice Deserialize ConflictingNotarize proof
    /// @dev Two notarize votes for different proposals in the same round
    /// @param proof The serialized fraud proof bytes
    /// @return proposalBytes1 First proposal bytes
    /// @return signer1 First signer index
    /// @return signature1 First signature
    /// @return proposalBytes2 Second proposal bytes
    /// @return signer2 Second signer index (must equal signer1)
    /// @return signature2 Second signature
    function deserializeConflictingNotarize(bytes calldata proof)
        public view returns (
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
        (proposalBytes1, offset) = extractProposalBytes(proof, offset, DIGEST_LENGTH);
        (signer1, signature1, offset) = CodecHelpers.deserializeSignerAndSignature(proof, offset, SIGNATURE_LENGTH());

        // Deserialize second Notarize
        (proposalBytes2, offset) = extractProposalBytes(proof, offset, DIGEST_LENGTH);
        (signer2, signature2, offset) = CodecHelpers.deserializeSignerAndSignature(proof, offset, SIGNATURE_LENGTH());

        if (offset != proof.length) revert CodecHelpers.InvalidProofLength();

        // Validate Byzantine behavior
        bytes calldata round1 = proposalBytes1[0:16];
        bytes calldata round2 = proposalBytes2[0:16];
        validateRoundsMatch(round1, round2);
        if (signer1 != signer2) revert Conflicting_SignerMismatch();
        validateProposalsDiffer(proposalBytes1, proposalBytes2);

        return (proposalBytes1, signer1, signature1, proposalBytes2, signer2, signature2);
    }

    /// @notice Deserialize ConflictingFinalize proof
    /// @dev Two finalize votes for different proposals in the same round
    function deserializeConflictingFinalize(bytes calldata proof)
        public view returns (
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
    /// @dev A nullify vote and finalize vote in the same round (Byzantine behavior)
    /// @param proof The serialized fraud proof bytes
    /// @return nullifyRoundBytes Round bytes from nullify vote
    /// @return nullifySigner Signer index for nullify
    /// @return nullifySignature Signature for nullify
    /// @return finalizeProposalBytes Proposal bytes from finalize vote
    /// @return finalizeSigner Signer index for finalize (must equal nullifySigner)
    /// @return finalizeSignature Signature for finalize
    function deserializeNullifyFinalize(bytes calldata proof)
        public view returns (
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
        (nullifySigner, nullifySignature, offset) = CodecHelpers.deserializeSignerAndSignature(proof, offset, SIGNATURE_LENGTH());

        // Deserialize Finalize
        (finalizeProposalBytes, offset) = extractProposalBytes(proof, offset, DIGEST_LENGTH);
        (finalizeSigner, finalizeSignature, offset) = CodecHelpers.deserializeSignerAndSignature(proof, offset, SIGNATURE_LENGTH());

        if (offset != proof.length) revert CodecHelpers.InvalidProofLength();

        // Validate Byzantine behavior
        bytes calldata finalizeRoundBytes = finalizeProposalBytes[0:16];
        validateRoundsMatch(nullifyRoundBytes, finalizeRoundBytes);
        if (nullifySigner != finalizeSigner) revert Conflicting_SignerMismatch();

        return (nullifyRoundBytes, nullifySigner, nullifySignature, finalizeProposalBytes, finalizeSigner, finalizeSignature);
    }

    // ============ Fraud Proof Verification ============

    /// @notice Verify ConflictingNotarize fraud proof
    /// @param namespace The application namespace
    /// @param proposalBytes1 First proposal bytes
    /// @param signer First signer index
    /// @param signature1 First signature
    /// @param proposalBytes2 Second proposal bytes
    /// @param signature2 Second signature
    /// @param publicKey The signer's public key
    /// @return true if both signatures are valid (proving Byzantine behavior)
    function verifyConflictingNotarize(
        bytes memory namespace,
        bytes calldata proposalBytes1,
        uint32 signer,
        bytes calldata signature1,
        bytes calldata proposalBytes2,
        bytes calldata signature2,
        bytes32 publicKey
    ) public view returns (bool) {
        bytes memory namespaceWithSuffix = abi.encodePacked(namespace, "_NOTARIZE");

        // Verify first signature
        bytes memory signedMessage1 = encodeSignedMessage(namespaceWithSuffix, proposalBytes1);
        if (!_verifySignature(signedMessage1, publicKey, bytes(signature1))) {
            return false;
        }

        // Verify second signature
        bytes memory signedMessage2 = encodeSignedMessage(namespaceWithSuffix, proposalBytes2);
        return _verifySignature(signedMessage2, publicKey, bytes(signature2));
    }

    /// @notice Verify ConflictingFinalize fraud proof
    function verifyConflictingFinalize(
        bytes memory namespace,
        bytes calldata proposalBytes1,
        uint32 signer,
        bytes calldata signature1,
        bytes calldata proposalBytes2,
        bytes calldata signature2,
        bytes32 publicKey
    ) public view returns (bool) {
        bytes memory namespaceWithSuffix = abi.encodePacked(namespace, "_FINALIZE");

        // Verify first signature
        bytes memory signedMessage1 = encodeSignedMessage(namespaceWithSuffix, proposalBytes1);
        if (!_verifySignature(signedMessage1, publicKey, bytes(signature1))) {
            return false;
        }

        // Verify second signature
        bytes memory signedMessage2 = encodeSignedMessage(namespaceWithSuffix, proposalBytes2);
        return _verifySignature(signedMessage2, publicKey, bytes(signature2));
    }

    /// @notice Verify NullifyFinalize fraud proof
    /// @param namespace The application namespace
    /// @param nullifyRoundBytes Round bytes from nullify
    /// @param signer Signer index
    /// @param nullifySignature Nullify signature
    /// @param finalizeProposalBytes Proposal bytes from finalize
    /// @param finalizeSignature Finalize signature
    /// @param publicKey The signer's public key
    /// @return true if both signatures are valid (proving Byzantine behavior)
    function verifyNullifyFinalize(
        bytes memory namespace,
        bytes calldata nullifyRoundBytes,
        uint32 signer,
        bytes calldata nullifySignature,
        bytes calldata finalizeProposalBytes,
        bytes calldata finalizeSignature,
        bytes32 publicKey
    ) public view returns (bool) {
        // Verify nullify signature
        bytes memory nullifyNamespaceWithSuffix = abi.encodePacked(namespace, "_NULLIFY");
        bytes memory nullifySignedMessage = encodeSignedMessage(nullifyNamespaceWithSuffix, nullifyRoundBytes);
        if (!_verifySignature(nullifySignedMessage, publicKey, bytes(nullifySignature))) {
            return false;
        }

        // Verify finalize signature
        bytes memory finalizeNamespaceWithSuffix = abi.encodePacked(namespace, "_FINALIZE");
        bytes memory finalizeSignedMessage = encodeSignedMessage(finalizeNamespaceWithSuffix, finalizeProposalBytes);
        return _verifySignature(finalizeSignedMessage, publicKey, bytes(finalizeSignature));
    }
}
