// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// import "./SimplexVerifierBase.sol";
// import {CodecHelpers} from "../lib/CodecHelpers.sol";
// import {IMultisigScheme} from "../signing_schemes/interfaces/IMultisigScheme.sol";

// /// @title SimplexVerifierMultisig
// /// @notice Concrete verifier for multisignature schemes with aggregated signatures
// /// @dev Handles consensus format logic (bitmap extraction, validator management)
// /// @dev Delegates pure cryptographic operations to an IMultisigScheme implementation
// contract SimplexVerifierMultisig is SimplexVerifierBase {
//     // ============ Immutable Configuration ============

//     /// @notice The multisig scheme used for verification
//     IMultisigScheme public immutable scheme;

//     /// @notice Digest length in bytes (use DigestLengths constants)
//     uint256 public immutable digestLength;

//     // ============ State Variables ============

//     /// @notice Array of validator public keys (similar to Rust's participants)
//     /// @dev Each key is stored as bytes to support different key lengths
//     bytes[] public participants;

//     // ============ Events ============

//     /// @notice Emitted when participants are updated
//     event ParticipantsUpdated(uint256 count);

//     // ============ Constructor ============

//     /// @param _scheme The multisig scheme for cryptographic operations
//     /// @param _digestLength Length of payload digests in bytes (use DigestLengths.SHA256 or DigestLengths.BLAKE3)
//     constructor(
//         IMultisigScheme _scheme,
//         uint256 _digestLength
//     ) {
//         scheme = _scheme;
//         digestLength = _digestLength;
//     }

//     // ============ Scheme Properties ============

//     /// @notice Get the signature length from the scheme
//     /// @return Length of aggregated signatures in bytes
//     function SIGNATURE_LENGTH() public view returns (uint256) {
//         return scheme.SIGNATURE_LENGTH();
//     }

//     /// @notice Get the public key length from the scheme
//     /// @return Length of public keys in bytes
//     function PUBLIC_KEY_LENGTH() public view returns (uint256) {
//         return scheme.PUBLIC_KEY_LENGTH();
//     }

//     // ============ Participant Management ============

//     /// @notice Initialize or update the validator public keys
//     /// @dev Only callable by contract owner/governance (add access control as needed)
//     /// @param _participants Array of public keys for all validators
//     function setParticipants(bytes[] calldata _participants) external {
//         // Validate all keys have correct length
//         uint256 expectedLength = PUBLIC_KEY_LENGTH();
//         for (uint256 i = 0; i < _participants.length; i++) {
//             require(_participants[i].length == expectedLength, "Invalid public key length");
//         }

//         // Clear existing participants
//         delete participants;

//         // Set new participants
//         for (uint256 i = 0; i < _participants.length; i++) {
//             participants.push(_participants[i]);
//         }

//         emit ParticipantsUpdated(_participants.length);
//     }

//     /// @notice Get a participant's public key by index
//     /// @param index The participant index
//     /// @return The public key bytes
//     function getParticipant(uint256 index) external view returns (bytes memory) {
//         require(index < participants.length, "Invalid participant index");
//         return participants[index];
//     }

//     /// @notice Get the total number of participants
//     /// @return The number of participants
//     function getParticipantCount() external view returns (uint256) {
//         return participants.length;
//     }

//     /// @notice Get all participants as concatenated bytes (for certificate verification)
//     /// @return Concatenated public keys of all participants
//     function getParticipantsBytes() external view returns (bytes memory) {
//         uint256 count = participants.length;
//         uint256 keyLength = PUBLIC_KEY_LENGTH();
//         bytes memory result = new bytes(count * keyLength);

//         for (uint256 i = 0; i < count; i++) {
//             for (uint256 j = 0; j < keyLength; j++) {
//                 result[i * keyLength + j] = participants[i][j];
//             }
//         }

//         return result;
//     }

//     // ============ Certificate Deserialization ============

//     /// @notice Extract bitmap and aggregated signature from certificate bytes
//     /// @dev Common logic for deserializing the bitmap + aggregated signature portion
//     /// @param proof The serialized certificate bytes
//     /// @param startOffset Starting offset after message bytes
//     /// @param maxParticipants Maximum participants for DoS protection
//     /// @return signersBitmap Bitmap indicating which validators signed
//     /// @return aggregatedSignature The aggregated signature
//     /// @return endOffset Final offset after extraction
//     function _extractBitmapAndSignature(
//         bytes calldata proof,
//         uint256 startOffset,
//         uint32 maxParticipants
//     ) internal view returns (
//         bytes memory signersBitmap,
//         bytes memory aggregatedSignature,
//         uint256 endOffset
//     ) {
//         // Deserialize bitmap
//         uint64 bitmapLengthInBits;
//         (bitmapLengthInBits, signersBitmap, endOffset) =
//             deserializeSignersBitmap(proof, startOffset, maxParticipants);

//         // Extract aggregated signature
//         uint256 sigLen = SIGNATURE_LENGTH();
//         if (endOffset + sigLen > proof.length) revert InvalidProofLength();
//         aggregatedSignature = proof[endOffset:endOffset + sigLen];
//         endOffset += sigLen;

//         return (signersBitmap, aggregatedSignature, endOffset);
//     }

//     /// @notice Deserialize a Notarization certificate with aggregated signature
//     /// @dev Format: proposal_bytes + bitmap (8 bytes length + data) + aggregated_signature
//     /// @dev This differs from attributable which has: bitmap + signature_count + individual_signatures
//     /// @param proof The serialized certificate bytes
//     /// @param maxParticipants Maximum participants for DoS protection
//     /// @return proposalBytes Raw proposal bytes
//     /// @return signersBitmap Bitmap indicating which validators signed
//     /// @return aggregatedSignature The aggregated BLS signature (48 bytes)
//     function deserializeNotarization(bytes calldata proof, uint32 maxParticipants)
//         public view returns (
//             bytes calldata proposalBytes,
//             bytes memory signersBitmap,
//             bytes memory aggregatedSignature
//         )
//     {
//         uint256 offset;

//         // Extract proposal bytes
//         (proposalBytes, offset) = extractProposalBytes(proof, 0, digestLength);

//         // Extract bitmap and signature using helper
//         (signersBitmap, aggregatedSignature, offset) = _extractBitmapAndSignature(proof, offset, maxParticipants);

//         if (offset != proof.length) revert InvalidProofLength();
//         return (proposalBytes, signersBitmap, aggregatedSignature);
//     }

//     /// @notice Deserialize a Nullification certificate with aggregated signature
//     /// @dev Format: round_bytes (16 bytes) + bitmap (8 bytes length + data) + aggregated_signature
//     /// @param proof The serialized certificate bytes
//     /// @param maxParticipants Maximum participants for DoS protection
//     /// @return roundBytes Raw round bytes (16 bytes)
//     /// @return signersBitmap Bitmap indicating which validators signed
//     /// @return aggregatedSignature The aggregated BLS signature (48 bytes)
//     function deserializeNullification(bytes calldata proof, uint32 maxParticipants)
//         public view returns (
//             bytes calldata roundBytes,
//             bytes memory signersBitmap,
//             bytes memory aggregatedSignature
//         )
//     {
//         uint256 offset;

//         // Extract round bytes
//         (roundBytes, offset) = extractRoundBytes(proof, 0);

//         // Extract bitmap and signature using helper
//         (signersBitmap, aggregatedSignature, offset) = _extractBitmapAndSignature(proof, offset, maxParticipants);

//         if (offset != proof.length) revert InvalidProofLength();
//         return (roundBytes, signersBitmap, aggregatedSignature);
//     }

//     /// @notice Deserialize a Finalization certificate with aggregated BLS signature
//     /// @dev Identical structure to Notarization
//     function deserializeFinalization(bytes calldata proof, uint32 maxParticipants)
//         public view returns (
//             bytes calldata proposalBytes,
//             bytes memory signersBitmap,
//             bytes memory aggregatedSignature
//         )
//     {
//         return deserializeNotarization(proof, maxParticipants);
//     }

//     // ============ Certificate Verification ============

//     /// @notice Verify a certificate with aggregated BLS signature
//     /// @dev Overloaded version for gas efficiency when public keys are provided externally
//     /// @param namespace The base namespace (e.g., "MyApp")
//     /// @param suffix The activity suffix (e.g., "_NOTARIZE", "_NULLIFY", "_FINALIZE")
//     /// @param messageBytes The message bytes (proposal or round)
//     /// @param signersBitmap Bitmap of signers
//     /// @param aggregatedSignature The aggregated signature
//     /// @param publicKeys Concatenated public keys of all validators (N * 96 bytes)
//     /// @param quorum Required quorum (number of signatures needed)
//     /// @return true if the certificate is valid, false otherwise
//     function _verifyCertificate(
//         bytes memory namespace,
//         bytes memory suffix,
//         bytes calldata messageBytes,
//         bytes memory signersBitmap,
//         bytes memory aggregatedSignature,
//         bytes memory publicKeys,
//         uint32 quorum
//     ) internal view returns (bool) {
//         // Calculate number of validators from public keys length
//         uint256 numValidators = publicKeys.length / PUBLIC_KEY_LENGTH();
//         if (publicKeys.length % PUBLIC_KEY_LENGTH() != 0) return false;

//         // Count signers in bitmap and validate quorum
//         uint256 signerCount = 0;
//         for (uint256 i = 0; i < numValidators; i++) {
//             if (CodecHelpers.getBit(signersBitmap, i)) {
//                 signerCount++;
//             }
//         }
//         if (signerCount < quorum) return false;

//         // Aggregate the public keys of signers using the multisig scheme
//         bytes memory aggregatedPublicKey = scheme.aggregatePublicKeys(
//             publicKeys,
//             signersBitmap,
//             numValidators
//         );

//         // Build signed message using union_unique format and verify
//         return scheme.verifySignature(
//             encodeSignedMessage(abi.encodePacked(namespace, suffix), messageBytes),
//             aggregatedPublicKey,
//             aggregatedSignature
//         );
//     }

//     /// @notice Verify a Notarization certificate with aggregated signature using stored participants
//     /// @param namespace The application namespace (e.g., "MyApp")
//     /// @param proposalBytes The proposal bytes from deserialization
//     /// @param signersBitmap Bitmap of signers
//     /// @param aggregatedSignature The aggregated signature
//     /// @param quorum Required quorum
//     /// @return true if the certificate is valid, false otherwise
//     function verifyNotarizationWithParticipants(
//         bytes memory namespace,
//         bytes calldata proposalBytes,
//         bytes memory signersBitmap,
//         bytes memory aggregatedSignature,
//         uint32 quorum
//     ) public view returns (bool) {
//         bytes memory publicKeys = this.getParticipantsBytes();
//         return _verifyCertificate(
//             namespace,
//             "_NOTARIZE",
//             proposalBytes,
//             signersBitmap,
//             aggregatedSignature,
//             publicKeys,
//             quorum
//         );
//     }

//     /// @notice Verify a Notarization certificate with aggregated signature (explicit keys)
//     /// @param namespace The application namespace (e.g., "MyApp")
//     /// @param proposalBytes The proposal bytes from deserialization
//     /// @param signersBitmap Bitmap of signers
//     /// @param aggregatedSignature The aggregated signature
//     /// @param publicKeys Concatenated public keys of all validators (N * 96 bytes)
//     /// @param quorum Required quorum
//     /// @return true if the certificate is valid, false otherwise
//     function verifyNotarization(
//         bytes memory namespace,
//         bytes calldata proposalBytes,
//         bytes memory signersBitmap,
//         bytes memory aggregatedSignature,
//         bytes memory publicKeys,
//         uint32 quorum
//     ) public view returns (bool) {
//         return _verifyCertificate(
//             namespace,
//             "_NOTARIZE",
//             proposalBytes,
//             signersBitmap,
//             aggregatedSignature,
//             publicKeys,
//             quorum
//         );
//     }

//     /// @notice Verify a Nullification certificate with aggregated BLS signature using stored participants
//     /// @param namespace The application namespace (e.g., "MyApp")
//     /// @param roundBytes The round bytes from deserialization (16 bytes)
//     /// @param signersBitmap Bitmap of signers
//     /// @param aggregatedSignature The aggregated signature
//     /// @param quorum Required quorum
//     /// @return true if the certificate is valid, false otherwise
//     function verifyNullificationWithParticipants(
//         bytes memory namespace,
//         bytes calldata roundBytes,
//         bytes memory signersBitmap,
//         bytes memory aggregatedSignature,
//         uint32 quorum
//     ) public view returns (bool) {
//         bytes memory publicKeys = this.getParticipantsBytes();
//         return _verifyCertificate(
//             namespace,
//             "_NULLIFY",
//             roundBytes,
//             signersBitmap,
//             aggregatedSignature,
//             publicKeys,
//             quorum
//         );
//     }

//     /// @notice Verify a Nullification certificate with aggregated BLS signature (explicit keys)
//     /// @param namespace The application namespace (e.g., "MyApp")
//     /// @param roundBytes The round bytes from deserialization (16 bytes)
//     /// @param signersBitmap Bitmap of signers
//     /// @param aggregatedSignature The aggregated signature
//     /// @param publicKeys Concatenated public keys of all validators (N * 96 bytes)
//     /// @param quorum Required quorum
//     /// @return true if the certificate is valid, false otherwise
//     function verifyNullification(
//         bytes memory namespace,
//         bytes calldata roundBytes,
//         bytes memory signersBitmap,
//         bytes memory aggregatedSignature,
//         bytes memory publicKeys,
//         uint32 quorum
//     ) public view returns (bool) {
//         return _verifyCertificate(
//             namespace,
//             "_NULLIFY",
//             roundBytes,
//             signersBitmap,
//             aggregatedSignature,
//             publicKeys,
//             quorum
//         );
//     }

//     /// @notice Verify a Finalization certificate with aggregated BLS signature using stored participants
//     /// @param namespace The application namespace (e.g., "MyApp")
//     /// @param proposalBytes The proposal bytes from deserialization
//     /// @param signersBitmap Bitmap of signers
//     /// @param aggregatedSignature The aggregated signature
//     /// @param quorum Required quorum
//     /// @return true if the certificate is valid, false otherwise
//     function verifyFinalizationWithParticipants(
//         bytes memory namespace,
//         bytes calldata proposalBytes,
//         bytes memory signersBitmap,
//         bytes memory aggregatedSignature,
//         uint32 quorum
//     ) public view returns (bool) {
//         bytes memory publicKeys = this.getParticipantsBytes();
//         return _verifyCertificate(
//             namespace,
//             "_FINALIZE",
//             proposalBytes,
//             signersBitmap,
//             aggregatedSignature,
//             publicKeys,
//             quorum
//         );
//     }

//     /// @notice Verify a Finalization certificate with aggregated BLS signature (explicit keys)
//     /// @param namespace The application namespace (e.g., "MyApp")
//     /// @param proposalBytes The proposal bytes from deserialization
//     /// @param signersBitmap Bitmap of signers
//     /// @param aggregatedSignature The aggregated signature
//     /// @param publicKeys Concatenated public keys of all validators (N * 96 bytes)
//     /// @param quorum Required quorum
//     /// @return true if the certificate is valid, false otherwise
//     function verifyFinalization(
//         bytes memory namespace,
//         bytes calldata proposalBytes,
//         bytes memory signersBitmap,
//         bytes memory aggregatedSignature,
//         bytes memory publicKeys,
//         uint32 quorum
//     ) public view returns (bool) {
//         return _verifyCertificate(
//             namespace,
//             "_FINALIZE",
//             proposalBytes,
//             signersBitmap,
//             aggregatedSignature,
//             publicKeys,
//             quorum
//         );
//     }

//     // ============ Individual Activity Deserialization ============
//     // BLS multisig is attributable - it supports individual vote verification
//     // for fault detection alongside aggregated certificates for efficiency

//     /// @notice Deserialize a Notarize message with individual BLS signature
//     /// @dev Rust: pub struct Notarize<S, D> { proposal: Proposal<D>, vote: Vote<S> }
//     /// @dev Format: proposal_bytes + signer (4 bytes) + signature (SIGNATURE_LENGTH bytes)
//     /// @param proof The serialized proof bytes
//     /// @return proposalBytes Raw proposal bytes for verification
//     /// @return signer The signer index
//     /// @return signature The individual BLS signature bytes
//     function deserializeNotarize(bytes calldata proof)
//         public view returns (
//             bytes calldata proposalBytes,
//             uint32 signer,
//             bytes calldata signature
//         )
//     {
//         uint256 offset;
//         (proposalBytes, offset) = extractProposalBytes(proof, 0, digestLength);
//         (signer, signature, offset) = deserializeSignerAndSignature(proof, offset, SIGNATURE_LENGTH());
//         if (offset != proof.length) revert InvalidProofLength();
//         return (proposalBytes, signer, signature);
//     }

//     /// @notice Deserialize a Nullify message with individual BLS signature
//     /// @dev Rust: pub struct Nullify<S> { round: Round, vote: Vote<S> }
//     /// @dev Format: round_bytes (16 bytes) + signer (4 bytes) + signature (SIGNATURE_LENGTH bytes)
//     /// @param proof The serialized proof bytes
//     /// @return roundBytes Raw round bytes for verification
//     /// @return signer The signer index
//     /// @return signature The individual BLS signature bytes
//     function deserializeNullify(bytes calldata proof)
//         public view returns (
//             bytes calldata roundBytes,
//             uint32 signer,
//             bytes calldata signature
//         )
//     {
//         uint256 offset;
//         (roundBytes, offset) = extractRoundBytes(proof, 0);
//         (signer, signature, offset) = deserializeSignerAndSignature(proof, offset, SIGNATURE_LENGTH());
//         if (offset != proof.length) revert InvalidProofLength();
//         return (roundBytes, signer, signature);
//     }

//     /// @notice Deserialize a Finalize message with individual BLS signature
//     /// @dev Identical structure to Notarize
//     function deserializeFinalize(bytes calldata proof)
//         public view returns (
//             bytes calldata proposalBytes,
//             uint32 signer,
//             bytes calldata signature
//         )
//     {
//         return deserializeNotarize(proof);
//     }

//     // ============ Individual Vote Verification ============

//     /// @notice Verify a Notarize vote with individual BLS signature using stored participants
//     /// @param namespace The application namespace (e.g., "MyApp")
//     /// @param proposalBytes The proposal bytes from deserialization
//     /// @param signer The signer index (must be valid index in participants array)
//     /// @param signature The individual BLS signature bytes
//     /// @return true if the signature is valid, false otherwise
//     function verifyNotarizeWithIndex(
//         bytes memory namespace,
//         bytes calldata proposalBytes,
//         uint32 signer,
//         bytes calldata signature
//     ) public view returns (bool) {
//         require(signer < participants.length, "Invalid signer index");
//         return scheme.verifySignature(
//             encodeSignedMessage(abi.encodePacked(namespace, "_NOTARIZE"), proposalBytes),
//             participants[signer],
//             signature
//         );
//     }

//     /// @notice Verify a Notarize vote with individual BLS signature (explicit public key)
//     /// @param namespace The application namespace (e.g., "MyApp")
//     /// @param proposalBytes The proposal bytes from deserialization
//     /// @param signer The signer index (for API consistency, not used with explicit key)
//     /// @param signature The individual BLS signature bytes
//     /// @param publicKey The signer's public key (96 bytes for BLS)
//     /// @return true if the signature is valid, false otherwise
//     function verifyNotarize(
//         bytes memory namespace,
//         bytes calldata proposalBytes,
//         uint32 signer,
//         bytes calldata signature,
//         bytes calldata publicKey
//     ) public view returns (bool) {
//         return scheme.verifySignature(
//             encodeSignedMessage(abi.encodePacked(namespace, "_NOTARIZE"), proposalBytes),
//             publicKey,
//             signature
//         );
//     }

//     /// @notice Verify a Nullify vote with individual BLS signature using stored participants
//     /// @param namespace The application namespace (e.g., "MyApp")
//     /// @param roundBytes The round bytes from deserialization (16 bytes)
//     /// @param signer The signer index (must be valid index in participants array)
//     /// @param signature The individual BLS signature bytes
//     /// @return true if the signature is valid, false otherwise
//     function verifyNullifyWithIndex(
//         bytes memory namespace,
//         bytes calldata roundBytes,
//         uint32 signer,
//         bytes calldata signature
//     ) public view returns (bool) {
//         require(signer < participants.length, "Invalid signer index");
//         return scheme.verifySignature(
//             encodeSignedMessage(abi.encodePacked(namespace, "_NULLIFY"), roundBytes),
//             participants[signer],
//             signature
//         );
//     }

//     /// @notice Verify a Nullify vote with individual BLS signature (explicit public key)
//     /// @param namespace The application namespace (e.g., "MyApp")
//     /// @param roundBytes The round bytes from deserialization (16 bytes)
//     /// @param signer The signer index (for API consistency, not used with explicit key)
//     /// @param signature The individual BLS signature bytes
//     /// @param publicKey The signer's public key (96 bytes for BLS)
//     /// @return true if the signature is valid, false otherwise
//     function verifyNullify(
//         bytes memory namespace,
//         bytes calldata roundBytes,
//         uint32 signer,
//         bytes calldata signature,
//         bytes calldata publicKey
//     ) public view returns (bool) {
//         return scheme.verifySignature(
//             encodeSignedMessage(abi.encodePacked(namespace, "_NULLIFY"), roundBytes),
//             publicKey,
//             signature
//         );
//     }

//     /// @notice Verify a Finalize vote with individual BLS signature using stored participants
//     /// @param namespace The application namespace (e.g., "MyApp")
//     /// @param proposalBytes The proposal bytes from deserialization
//     /// @param signer The signer index (must be valid index in participants array)
//     /// @param signature The individual BLS signature bytes
//     /// @return true if the signature is valid, false otherwise
//     function verifyFinalizeWithIndex(
//         bytes memory namespace,
//         bytes calldata proposalBytes,
//         uint32 signer,
//         bytes calldata signature
//     ) public view returns (bool) {
//         require(signer < participants.length, "Invalid signer index");
//         return scheme.verifySignature(
//             encodeSignedMessage(abi.encodePacked(namespace, "_FINALIZE"), proposalBytes),
//             participants[signer],
//             signature
//         );
//     }

//     /// @notice Verify a Finalize vote with individual BLS signature (explicit public key)
//     /// @param namespace The application namespace (e.g., "MyApp")
//     /// @param proposalBytes The proposal bytes from deserialization
//     /// @param signer The signer index (for API consistency, not used with explicit key)
//     /// @param signature The individual BLS signature bytes
//     /// @param publicKey The signer's public key (96 bytes for BLS)
//     /// @return true if the signature is valid, false otherwise
//     function verifyFinalize(
//         bytes memory namespace,
//         bytes calldata proposalBytes,
//         uint32 signer,
//         bytes calldata signature,
//         bytes calldata publicKey
//     ) public view returns (bool) {
//         return scheme.verifySignature(
//             encodeSignedMessage(abi.encodePacked(namespace, "_FINALIZE"), proposalBytes),
//             publicKey,
//             signature
//         );
//     }
// }