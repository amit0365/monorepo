// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./SimplexVerifierBase.sol";
import {CodecHelpers} from "../lib/CodecHelpers.sol";
import {IKeyStore} from "../keystore/IKeyStore.sol";
import {ISignatureScheme} from "../signing_schemes/interfaces/ISignatureScheme.sol";

/// @title SimplexVerifierAttributable
/// @notice Concrete verifier for attributable signature schemes (Ed25519, BLS Multisig)
/// @dev Provides shared deserialization and verification logic for schemes with individual signatures
/// @dev Delegates signature verification to an ISignatureScheme implementation
/// @dev Uses IKeyStore for participant management, which owns the scheme reference
contract SimplexVerifierAttributable is SimplexVerifierBase {
    // ============ Immutable Configuration ============

    /// @notice The keystore that manages validator keys and owns the scheme
    IKeyStore public immutable keyStore;

    /// @notice Digest length in bytes (use DigestLengths constants)
    uint256 public immutable digestLength;

    // ============ Constructor ============

    /// @param _keyStore The keystore managing validator keys (contains scheme reference)
    /// @param _digestLength Length of payload digests in bytes (use DigestLengths.SHA256 or DigestLengths.BLAKE3)
    constructor(
        IKeyStore _keyStore,
        uint256 _digestLength
    ) {
        keyStore = _keyStore;
        digestLength = _digestLength;
    }

    // ============ Scheme Properties ============

    /// @notice Get the signature scheme from the keystore
    /// @return The signature scheme instance
    function scheme() public view returns (ISignatureScheme) {
        return keyStore.scheme();
    }

    /// @notice Get the signature length from the scheme
    /// @return Length of signatures in bytes (64 for Ed25519, 96 for BLS)
    function SIGNATURE_LENGTH() public view returns (uint256) {
        return keyStore.scheme().SIGNATURE_LENGTH();
    }

    /// @notice Get the public key length from the scheme
    /// @return Length of public keys in bytes (32 for Ed25519, 48+ for BLS)
    function PUBLIC_KEY_LENGTH() public view returns (uint256) {
        return keyStore.scheme().PUBLIC_KEY_LENGTH();
    }

    // ============ Deserialisation helper ============

    /// @notice Deserialize bitmap and signatures from certificate proof
    /// @dev Format: bitmap + signature_count (varint) + signatures
    /// @dev Used by both Notarization and Nullification deserialization
    /// @param proof The serialized certificate bytes
    /// @param offset Starting offset (after proposal/round bytes)
    /// @param maxParticipants Maximum participants for DoS protection
    /// @param signatureLength Length of each signature in bytes
    /// @return signersBitmap Bitmap indicating which validators signed
    /// @return signatures Array of signature bytes
    /// @return newOffset Updated offset after reading all signatures
    function deserializeBitmapAndSignatures(
        bytes calldata proof,
        uint256 offset,
        uint32 maxParticipants,
        uint256 signatureLength
    ) internal pure returns (
        bytes calldata signersBitmap,
        bytes[] memory signatures,
        uint256 newOffset
    ) {
        // Deserialize bitmap
        uint64 bitmapLengthInBits;
        (bitmapLengthInBits, signersBitmap, offset) =
            deserializeSignersBitmap(proof, offset, maxParticipants);

        // Deserialize signature count
        uint64 signatureCount;
        (signatureCount, offset) = CodecHelpers.decodeVarintU64(proof, offset);

        // Read all signatures
        signatures = new bytes[](signatureCount);
        for (uint64 i = 0; i < signatureCount; i++) {
            if (offset + signatureLength > proof.length) revert InvalidProofLength();
            signatures[i] = proof[offset:offset+signatureLength];
            offset += signatureLength;
        }

        return (signersBitmap, signatures, offset);
    }

    // ============ Internal Certificate Verification ============

    /// @notice Verify certificate signatures
    /// @dev Helper that verifies all signatures in a certificate
    /// @param signedMessage The full message that was signed (union_unique format)
    /// @param signatures Array of signature bytes
    /// @param publicKeys Array of public keys corresponding to signatures
    /// @return true if all signatures are valid, false otherwise
    function _verifyCertificateSignatures(
        bytes memory signedMessage,
        bytes[] memory signatures,
        bytes[] memory publicKeys
    ) internal view returns (bool) {
        if (signatures.length != publicKeys.length) return false;

        for (uint256 i = 0; i < signatures.length; i++) {
            if (!keyStore.scheme().verifySignature(signedMessage, publicKeys[i], signatures[i])) {
                return false;
            }
        }

        return true;
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
        (proposalBytes, offset) = extractProposalBytes(proof, 0, digestLength);
        (signer, signature, offset) = deserializeSignerAndSignature(proof, offset, SIGNATURE_LENGTH());
        if (offset != proof.length) revert InvalidProofLength();
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
        (signer, signature, offset) = deserializeSignerAndSignature(proof, offset, SIGNATURE_LENGTH());
        if (offset != proof.length) revert InvalidProofLength();
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

    /// @notice Verify a Notarize vote using stored participants
    /// @dev Deserializes proof and verifies signature using participant public key
    /// @param namespace The application namespace (e.g., "MyApp")
    /// @param proof The serialized Notarize proof bytes
    /// @return true if the signature is valid, false otherwise
    function verifyNotarize(
        bytes memory namespace,
        bytes calldata proof
    ) public view returns (bool) {
        // Deserialize proof
        (bytes calldata proposalBytes, uint32 signer, bytes calldata signature) = deserializeNotarize(proof);

        // Validate signer index
        require(signer < keyStore.getParticipantCount(), "Invalid signer index");

        // Verify signature
        return keyStore.scheme().verifySignature(
            encodeSignedMessage(abi.encodePacked(namespace, "_NOTARIZE"), proposalBytes),
            keyStore.getParticipant(signer),
            signature
        );
    }

    /// @notice Verify a Nullify vote using stored participants
    /// @dev Deserializes proof and verifies signature using participant public key
    /// @param namespace The application namespace (e.g., "MyApp")
    /// @param proof The serialized Nullify proof bytes
    /// @return true if the signature is valid, false otherwise
    function verifyNullify(
        bytes memory namespace,
        bytes calldata proof
    ) public view returns (bool) {
        // Deserialize proof
        (bytes calldata roundBytes, uint32 signer, bytes calldata signature) = deserializeNullify(proof);

        // Validate signer index
        require(signer < keyStore.getParticipantCount(), "Invalid signer index");

        // Verify signature
        return keyStore.scheme().verifySignature(
            encodeSignedMessage(abi.encodePacked(namespace, "_NULLIFY"), roundBytes),
            keyStore.getParticipant(signer),
            signature
        );
    }

    /// @notice Verify a Finalize vote using stored participants
    /// @dev Deserializes proof and verifies signature using participant public key
    /// @param namespace The application namespace (e.g., "MyApp")
    /// @param proof The serialized Finalize proof bytes
    /// @return true if the signature is valid, false otherwise
    function verifyFinalize(
        bytes memory namespace,
        bytes calldata proof
    ) public view returns (bool) {
        // Deserialize proof
        (bytes calldata proposalBytes, uint32 signer, bytes calldata signature) = deserializeFinalize(proof);

        // Validate signer index
        require(signer < keyStore.getParticipantCount(), "Invalid signer index");

        // Verify signature
        return keyStore.scheme().verifySignature(
            encodeSignedMessage(abi.encodePacked(namespace, "_FINALIZE"), proposalBytes),
            keyStore.getParticipant(signer),
            signature
        );
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
            bytes calldata signersBitmap,
            bytes[] memory signatures
        )
    {
        uint256 offset = 0;

        // Extract proposal bytes first
        (proposalBytes, offset) = extractProposalBytes(proof, 0, digestLength);

        // Deserialize bitmap and signatures
        (signersBitmap, signatures, offset) =
            deserializeBitmapAndSignatures(
                proof,
                offset,
                maxParticipants,
                SIGNATURE_LENGTH()
            );

        if (offset != proof.length) revert InvalidProofLength();

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
            bytes calldata signersBitmap,
            bytes[] memory signatures
        )
    {
        uint256 offset = 0;

        // Extract round bytes (16 bytes)
        (roundBytes, offset) = extractRoundBytes(proof, 0);

        // Deserialize bitmap and signatures
        (signersBitmap, signatures, offset) =
            deserializeBitmapAndSignatures(
                proof,
                offset,
                maxParticipants,
                SIGNATURE_LENGTH()
            );

        if (offset != proof.length) revert InvalidProofLength();

        return (roundBytes, signersBitmap, signatures);
    }

    /// @notice Deserialize a Finalization certificate
    /// @dev Identical structure to Notarization
    function deserializeFinalization(bytes calldata proof, uint32 maxParticipants)
        public view returns (
            bytes calldata proposalBytes,
            bytes calldata signersBitmap,
            bytes[] memory signatures
        )
    {
        return deserializeNotarization(proof, maxParticipants);
    }

    // ============ Certificate Verification ============

    /// @notice Verify a certificate using stored participants
    /// @dev Helper for Notarization/Nullification/Finalization verification
    /// @param namespace The base namespace (e.g., "MyApp")
    /// @param suffix The activity suffix (e.g., "_NOTARIZE", "_NULLIFY", "_FINALIZE")
    /// @param messageBytes The message bytes (proposal or round)
    /// @param signersBitmap Bitmap of signers
    /// @param signatures Array of signatures
    /// @param quorum Required quorum (number of signatures needed)
    /// @return true if the certificate is valid, false otherwise
    function _verifyCertificate(
        bytes memory namespace,
        bytes memory suffix,
        bytes calldata messageBytes,
        bytes calldata signersBitmap,
        bytes[] memory signatures,
        uint32 quorum
    ) internal view returns (bool) {
        // Validate quorum
        if (signatures.length < quorum) return false;

        // Extract public keys for signers from bitmap
        bytes[] memory signerPublicKeys = new bytes[](signatures.length);
        uint256 signerIndex = 0;
        uint256 bitmapBitIndex = 0;
        uint256 participantCount = keyStore.getParticipantCount();

        for (uint256 i = 0; i < participantCount && signerIndex < signatures.length; i++) {
            if (CodecHelpers.getBit(signersBitmap, bitmapBitIndex)) {
                signerPublicKeys[signerIndex] = keyStore.getParticipant(i);
                signerIndex++;
            }
            bitmapBitIndex++;
        }

        // Verify all signatures
        return _verifyCertificateSignatures(
            encodeSignedMessage(abi.encodePacked(namespace, suffix), messageBytes), // Build signed message
            signatures,
            signerPublicKeys
        );
    }

    /// @notice Verify a Notarization certificate using stored participants
    /// @dev Deserializes proof and verifies all signatures meet quorum
    /// @param namespace The application namespace (e.g., "MyApp")
    /// @param proof The serialized certificate bytes
    /// @param maxParticipants Maximum participants for DoS protection
    /// @param quorum Required quorum
    /// @return true if the certificate is valid, false otherwise
    function verifyNotarization(
        bytes memory namespace,
        bytes calldata proof,
        uint32 maxParticipants,
        uint32 quorum
    ) public view returns (bool) {
        // Deserialize certificate
        (bytes calldata proposalBytes, bytes calldata signersBitmap, bytes[] memory signatures) =
            deserializeNotarization(proof, maxParticipants);

        // Verify certificate
        return _verifyCertificate(
            namespace,
            "_NOTARIZE",
            proposalBytes,
            signersBitmap,
            signatures,
            quorum
        );
    }

    /// @notice Verify a Nullification certificate using stored participants
    /// @dev Deserializes proof and verifies all signatures meet quorum
    /// @param namespace The application namespace (e.g., "MyApp")
    /// @param proof The serialized certificate bytes
    /// @param maxParticipants Maximum participants for DoS protection
    /// @param quorum Required quorum
    /// @return true if the certificate is valid, false otherwise
    function verifyNullification(
        bytes memory namespace,
        bytes calldata proof,
        uint32 maxParticipants,
        uint32 quorum
    ) public view returns (bool) {
        // Deserialize certificate
        (bytes calldata roundBytes, bytes calldata signersBitmap, bytes[] memory signatures) =
            deserializeNullification(proof, maxParticipants);

        // Verify certificate
        return _verifyCertificate(
            namespace,
            "_NULLIFY",
            roundBytes,
            signersBitmap,
            signatures,
            quorum
        );
    }

    /// @notice Verify a Finalization certificate using stored participants
    /// @dev Deserializes proof and verifies all signatures meet quorum
    /// @param namespace The application namespace (e.g., "MyApp")
    /// @param proof The serialized certificate bytes
    /// @param maxParticipants Maximum participants for DoS protection
    /// @param quorum Required quorum
    /// @return true if the certificate is valid, false otherwise
    function verifyFinalization(
        bytes memory namespace,
        bytes calldata proof,
        uint32 maxParticipants,
        uint32 quorum
    ) public view returns (bool) {
        // Deserialize certificate
        (bytes calldata proposalBytes, bytes calldata signersBitmap, bytes[] memory signatures) =
            deserializeFinalization(proof, maxParticipants);

        // Verify certificate
        return _verifyCertificate(
            namespace,
            "_FINALIZE",
            proposalBytes,
            signersBitmap,
            signatures,
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
        (proposalBytes1, offset) = extractProposalBytes(proof, offset, digestLength);
        (signer1, signature1, offset) = deserializeSignerAndSignature(proof, offset, SIGNATURE_LENGTH());

        // Deserialize second Notarize
        (proposalBytes2, offset) = extractProposalBytes(proof, offset, digestLength);
        (signer2, signature2, offset) = deserializeSignerAndSignature(proof, offset, SIGNATURE_LENGTH());

        if (offset != proof.length) revert InvalidProofLength();

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
        (nullifySigner, nullifySignature, offset) = deserializeSignerAndSignature(proof, offset, SIGNATURE_LENGTH());

        // Deserialize Finalize
        (finalizeProposalBytes, offset) = extractProposalBytes(proof, offset, digestLength);
        (finalizeSigner, finalizeSignature, offset) = deserializeSignerAndSignature(proof, offset, SIGNATURE_LENGTH());

        if (offset != proof.length) revert InvalidProofLength();

        // Validate Byzantine behavior
        bytes calldata finalizeRoundBytes = finalizeProposalBytes[0:16];
        validateRoundsMatch(nullifyRoundBytes, finalizeRoundBytes);
        if (nullifySigner != finalizeSigner) revert Conflicting_SignerMismatch();

        return (nullifyRoundBytes, nullifySigner, nullifySignature, finalizeProposalBytes, finalizeSigner, finalizeSignature);
    }

    // ============ Fraud Proof Verification ============

    /// @notice Verify ConflictingNotarize fraud proof using stored participants
    /// @dev Deserializes proof and verifies both signatures are valid (proving Byzantine behavior)
    /// @param namespace The application namespace
    /// @param proof The serialized fraud proof bytes
    /// @return true if both signatures are valid (proving Byzantine behavior)
    function verifyConflictingNotarize(
        bytes memory namespace,
        bytes calldata proof
    ) public view returns (bool) {
        // Deserialize fraud proof
        (
            bytes calldata proposalBytes1,
            uint32 signer,
            bytes calldata signature1,
            bytes calldata proposalBytes2,
            ,
            bytes calldata signature2
        ) = deserializeConflictingNotarize(proof);

        // Validate signer index
        require(signer < keyStore.getParticipantCount(), "Invalid signer index");

        // Verify first signature
        if (!keyStore.scheme().verifySignature(
            encodeSignedMessage(abi.encodePacked(namespace, "_NOTARIZE"), proposalBytes1),
            keyStore.getParticipant(signer),
            signature1
        )) {
            return false;
        }

        // Verify second signature
        return keyStore.scheme().verifySignature(
            encodeSignedMessage(abi.encodePacked(namespace, "_NOTARIZE"), proposalBytes2),
            keyStore.getParticipant(signer),
            signature2
        );
    }

    /// @notice Verify ConflictingFinalize fraud proof using stored participants
    /// @dev Deserializes proof and verifies both signatures are valid (proving Byzantine behavior)
    /// @param namespace The application namespace
    /// @param proof The serialized fraud proof bytes
    /// @return true if both signatures are valid (proving Byzantine behavior)
    function verifyConflictingFinalize(
        bytes memory namespace,
        bytes calldata proof
    ) public view returns (bool) {
        // Deserialize fraud proof
        (
            bytes calldata proposalBytes1,
            uint32 signer,
            bytes calldata signature1,
            bytes calldata proposalBytes2,
            ,
            bytes calldata signature2
        ) = deserializeConflictingFinalize(proof);

        // Validate signer index
        require(signer < keyStore.getParticipantCount(), "Invalid signer index");

        // Verify first signature
        if (!keyStore.scheme().verifySignature(
            encodeSignedMessage(abi.encodePacked(namespace, "_FINALIZE"), proposalBytes1),
            keyStore.getParticipant(signer),
            signature1
        )) {
            return false;
        }

        // Verify second signature
        return keyStore.scheme().verifySignature(
            encodeSignedMessage(abi.encodePacked(namespace, "_FINALIZE"), proposalBytes2),
            keyStore.getParticipant(signer),
            signature2
        );
    }

    /// @notice Verify NullifyFinalize fraud proof using stored participants
    /// @dev Deserializes proof and verifies both signatures are valid (proving Byzantine behavior)
    /// @param namespace The application namespace
    /// @param proof The serialized fraud proof bytes
    /// @return true if both signatures are valid (proving Byzantine behavior)
    function verifyNullifyFinalize(
        bytes memory namespace,
        bytes calldata proof
    ) public view returns (bool) {
        // Deserialize fraud proof
        (
            bytes calldata nullifyRoundBytes,
            uint32 signer,
            bytes calldata nullifySignature,
            bytes calldata finalizeProposalBytes,
            ,
            bytes calldata finalizeSignature
        ) = deserializeNullifyFinalize(proof);

        // Validate signer index
        require(signer < keyStore.getParticipantCount(), "Invalid signer index");

        // Verify nullify signature
        if (!keyStore.scheme().verifySignature(
            encodeSignedMessage(abi.encodePacked(namespace, "_NULLIFY"), nullifyRoundBytes),
            keyStore.getParticipant(signer),
            nullifySignature
        )) {
            return false;
        }

        // Verify finalize signature
        return keyStore.scheme().verifySignature(
            encodeSignedMessage(abi.encodePacked(namespace, "_FINALIZE"), finalizeProposalBytes),
            keyStore.getParticipant(signer),
            finalizeSignature
        );
    }
}
