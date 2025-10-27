// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

    // /// @notice Decode varint.
    // /// @dev https://developers.google.com/protocol-buffers/docs/encoding#varints
    // /// @param p Position
    // /// @param buf Buffer
    // /// @return Success
    // /// @return New position
    // /// @return Decoded int
    // function decode_varint(uint64 p, bytes memory buf)
    //     internal
    //     pure
    //     returns (
    //         bool,
    //         uint64,
    //         uint64
    //     )
    // {
    //     uint64 val;
    //     uint64 i;

    //     for (i = 0; i < MAX_VARINT_BYTES; i++) {
    //         // Check that index is within bounds
    //         if (i + p >= buf.length) {
    //             return (false, p, 0);
    //         }

    //         // Get byte at offset
    //         uint8 b = uint8(buf[p + i]);

    //         // Highest bit is used to indicate if there are more bytes to come
    //         // Mask to get 7-bit value: 0111 1111
    //         uint8 v = b & 0x7F;

    //         // Groups of 7 bits are ordered least significant first
    //         val |= uint64(v) << uint64(i * 7);

    //         // Mask to get keep going bit: 1000 0000
    //         if (b & 0x80 == 0) {
    //             // [STRICT]
    //             // Check for trailing zeroes if more than one byte is used
    //             // (the value 0 still uses one byte)
    //             if (i > 0 && v == 0) {
    //                 return (false, p, 0);
    //             }

    //             break;
    //         }
    //     }

    //     // Check that at most MAX_VARINT_BYTES are used
    //     if (i >= MAX_VARINT_BYTES) {
    //         return (false, p, 0);
    //     }

    //     // [STRICT]
    //     // If all 10 bytes are used, the last byte (most significant 7 bits)
    //     // must be at most 0000 0001, since 7*9 = 63
    //     if (i == MAX_VARINT_BYTES - 1) {
    //         if (uint8(buf[p + i]) > 1) {
    //             return (false, p, 0);
    //         }
    //     }

    //     return (true, p + i + 1, val);
    // }

// /// @title SimplexVerifier
// /// @notice Verifies deserialization of Simplex consensus proofs
// contract SimplexVerifier {
//     // Constants for proof sizes
//     uint256 constant DIGEST_LENGTH = 32; // SHA256 digest length
//     uint256 constant PUBLIC_KEY_LENGTH = 32; // Ed25519 public key length
//     uint256 constant SIGNATURE_LENGTH = 64; // Ed25519 signature length
    
//     /// @notice Verifies a notarize proof
//     /// @param proof The serialized proof bytes
//     /// @return (view, parent, payload, publicKey) The deserialized proof components
//     function deserializeNotarize(
//         bytes calldata proof
//     ) public pure returns (
//         uint64 view,
//         uint64 parent,
//         bytes32 payload,
//         bytes32 publicKey
//     ) {
//         // Ensure proof is big enough
//         require(
//             proof.length == 8 + 8 + DIGEST_LENGTH + PUBLIC_KEY_LENGTH + SIGNATURE_LENGTH,
//             "Invalid proof length"
//         );

//         // Decode proof components
//         view = uint64(bytes8(proof[0:8]));
//         parent = uint64(bytes8(proof[8:16]));
//         payload = bytes32(proof[16:48]);
//         publicKey = bytes32(proof[48:80]);
        
//         // Note: Signature verification is handled separately
//         return (view, parent, payload, publicKey);
//     }

//     /// @notice Verifies a notarization proof (aggregated)
//     /// @param proof The serialized proof bytes
//     /// @param maxSigners Maximum number of allowed signers
//     /// @return (view, parent, payload, signerCount) The deserialized proof components
//     function deserializeNotarization(
//         bytes calldata proof,
//         uint32 maxSigners
//     ) public pure returns (
//         uint64 view,
//         uint64 parent, 
//         bytes32 payload,
//         uint32 signerCount
//     ) {
//         // Ensure proof prefix is big enough
//         require(
//             proof.length >= 8 + 8 + DIGEST_LENGTH + 4,
//             "Invalid proof prefix length"
//         );

//         // Decode proof prefix
//         view = uint64(bytes8(proof[0:8]));
//         parent = uint64(bytes8(proof[8:16]));
//         payload = bytes32(proof[16:48]);
//         signerCount = uint32(bytes4(proof[48:52]));
        
//         // Validate signer count
//         require(signerCount <= maxSigners, "Too many signers");
        
//         // Validate total proof length
//         uint256 expectedLength = 52 + (signerCount * (PUBLIC_KEY_LENGTH + SIGNATURE_LENGTH));
//         require(proof.length == expectedLength, "Invalid proof length");

//         return (view, parent, payload, signerCount);
//     }

//     /// @notice Verifies a finalize proof
//     /// @param proof The serialized proof bytes
//     /// @return (view, parent, payload, publicKey) The deserialized proof components
//     function deserializeFinalize(
//         bytes calldata proof
//     ) public pure returns (
//         uint64 view,
//         uint64 parent,
//         bytes32 payload,
//         bytes32 publicKey
//     ) {
//         // Reuse notarize deserialization since format is identical
//         return deserializeNotarize(proof);
//     }

//     /// @notice Verifies a finalization proof (aggregated)
//     /// @param proof The serialized proof bytes
//     /// @param maxSigners Maximum number of allowed signers
//     /// @return (view, parent, payload, signerCount) The deserialized proof components
//     function deserializeFinalization(
//         bytes calldata proof,
//         uint32 maxSigners
//     ) public pure returns (
//         uint64 view,
//         uint64 parent,
//         bytes32 payload,
//         uint32 signerCount
//     ) {
//         // Reuse notarization deserialization since format is identical
//         return deserializeNotarization(proof, maxSigners);
//     }

//     /// @notice Verifies a conflicting notarize proof
//     /// @param proof The serialized proof bytes
//     /// @return (publicKey, view) The deserialized proof components
//     function deserializeConflictingNotarize(
//         bytes calldata proof
//     ) public pure returns (
//         bytes32 publicKey,
//         uint64 view
//     ) {
//         // Ensure proof is big enough
//         uint256 expectedLength = 8 + PUBLIC_KEY_LENGTH + 8 + DIGEST_LENGTH + SIGNATURE_LENGTH + 
//                                8 + DIGEST_LENGTH + SIGNATURE_LENGTH;
//         require(proof.length == expectedLength, "Invalid proof length");

//         // Decode proof components
//         view = uint64(bytes8(proof[0:8]));
//         publicKey = bytes32(proof[8:40]);
        
//         // Note: Additional proof components and signature verification handled separately
//         return (publicKey, view);
//     }

//     /// @notice Verifies a conflicting finalize proof
//     /// @param proof The serialized proof bytes  
//     /// @return (publicKey, view) The deserialized proof components
//     function deserializeConflictingFinalize(
//         bytes calldata proof
//     ) public pure returns (
//         bytes32 publicKey,
//         uint64 view
//     ) {
//         // Reuse conflicting notarize deserialization since format is identical
//         return deserializeConflictingNotarize(proof);
//     }

//     /// @notice Verifies a nullify finalize proof
//     /// @param proof The serialized proof bytes
//     /// @return (publicKey, view) The deserialized proof components
//     function deserializeNullifyFinalize(
//         bytes calldata proof
//     ) public pure returns (
//         bytes32 publicKey,
//         uint64 view
//     ) {
//         // Ensure proof is big enough
//         uint256 expectedLength = 8 + PUBLIC_KEY_LENGTH + 8 + DIGEST_LENGTH + 
//                                SIGNATURE_LENGTH + SIGNATURE_LENGTH;
//         require(proof.length == expectedLength, "Invalid proof length");

//         // Decode proof components
//         view = uint64(bytes8(proof[0:8]));
//         publicKey = bytes32(proof[8:40]);
        
//         // Note: Additional proof components and signature verification handled separately
//         return (publicKey, view);
//     }
// } 