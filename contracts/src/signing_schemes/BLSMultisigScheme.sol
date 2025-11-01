// // SPDX-License-Identifier: MIT
// pragma solidity ^0.8.24;

// import {IMultisigScheme} from "../interfaces/IMultisigScheme.sol";
// import {BLS2} from "../libraries/BLS2Extensions.sol";
// import {CodecHelpers} from "../libraries/CodecHelpers.sol";

// /// @title BLSMultisigMinSigScheme
// /// @notice BLS12-381 multisig scheme implementation (aggregated signatures)
// /// @dev Implements IMultisigScheme for BLS signature aggregation
// /// @dev Provides pure cryptographic operations for BLS signature verification
// /// @dev Also exposes public key aggregation as a utility for SimplexVerifierMultisig
// /// @dev Uses MinSig variant: Public keys in G2 (96 bytes), Signatures in G1 (48 bytes)
// ///
// /// @dev Usage pattern with SimplexVerifierMultisig:
// ///      1. SimplexVerifierMultisig deserializes consensus proof to extract bitmap and signatures
// ///      2. SimplexVerifierMultisig calls aggregatePublicKeys() with validator keys and bitmap
// ///      3. SimplexVerifierMultisig calls verifySignature() with aggregated key and signature
// ///      This separation keeps consensus format logic in SimplexVerifier, crypto logic here
// contract BLSMultisigMinSigScheme is IMultisigScheme {
//     // ============ Constants ============

//     uint256 constant BLS_PUBLIC_KEY_LENGTH = 96; // G2 for MinSig variant
//     uint256 constant BLS_SIGNATURE_LENGTH = 48; // G1 for MinSig variant

//     // ============ Errors ============

//     error NoSignersInBitmap();

//     // ============ State ============

//     /// @notice Domain separation tag for hash-to-curve
//     /// @dev Format: {application}-BLS12381G1_XMD:SHA-256_SSWU_RO_{chainid}_
//     bytes public immutable DST;

//     // ============ Constructor ============

//     /// @notice Initialize the BLS multisig scheme
//     /// @param application Application name for domain separation tag
//     constructor(string memory application) {
//         // Build domain separation tag
//         string memory hashSpec = "-BLS12381G1_XMD:SHA-256_SSWU_RO_";

//         DST = abi.encodePacked(
//             application,
//             hashSpec,
//             _bytes32ToHex(bytes32(block.chainid)),
//             "_"
//         );
//     }

//     // ============ Interface Implementation ============

//     /// @inheritdoc IMultisigScheme
//     function SCHEME_ID() external pure returns (string memory) {
//         return "BLS12381_MULTISIG";
//     }

//     /// @inheritdoc IMultisigScheme
//     /// @notice Returns the length of a single BLS public key
//     function PUBLIC_KEY_LENGTH() external pure returns (uint256) {
//         return BLS_PUBLIC_KEY_LENGTH;
//     }

//     /// @inheritdoc IMultisigScheme
//     /// @notice Returns the length of an aggregated BLS signature
//     function SIGNATURE_LENGTH() external pure returns (uint256) {
//         return BLS_SIGNATURE_LENGTH;
//     }

//     /// @inheritdoc IMultisigScheme
//     /// @notice Verify aggregated BLS multisig signature with pre-aggregated public key
//     /// @dev Pure cryptographic verification - no consensus format awareness
//     /// @dev For consensus-aware verification with bitmap extraction, SimplexVerifierMultisig
//     ///      should call aggregatePublicKeys first, then call this method
//     /// @param message The raw message bytes that was signed
//     /// @param publicKey Pre-aggregated G2 public key (96 bytes)
//     /// @param signature Pure aggregated BLS signature (48 bytes)
//     /// @return true if signature is valid, false otherwise
//     function verifySignature(
//         bytes calldata message,
//         bytes calldata publicKey,
//         bytes calldata signature
//     ) external view returns (bool) {
//         // Validate inputs
//         if (publicKey.length != BLS_PUBLIC_KEY_LENGTH) return false;
//         if (signature.length != BLS_SIGNATURE_LENGTH) return false;

//         // Hash message to BLS point on G1
//         BLS2.PointG1 memory messagePoint = BLS2.hashToPoint(DST, message);

//         // Unmarshal the pre-aggregated public key
//         BLS2.PointG2 memory aggregatedPubKey = BLS2.g2Unmarshal(publicKey);

//         // Unmarshal and verify aggregated signature using pairing
//         BLS2.PointG1 memory sig = BLS2.g1Unmarshal(signature);
//         return BLS2.pairing(messagePoint, aggregatedPubKey, sig);
//     }

//     // ============ Public Aggregation Utilities ============

//     /// @notice Aggregate public keys from concatenated bytes based on bitmap
//     /// @dev This method is exposed for use by SimplexVerifierMultisig to handle consensus logic
//     /// @dev SimplexVerifierMultisig will extract bitmap from consensus proofs and call this
//     /// @dev IMPORTANT: Caller must ensure inputs are valid - minimal validation for gas efficiency
//     /// @param publicKeyBytes Concatenated public keys (N * 96 bytes)
//     /// @param bitmap Bitmap indicating which keys to aggregate
//     /// @param numSigners Number of Signer(validators) (N)
//     /// @return result Marshaled aggregated G2 public key (96 bytes) ready for verifySignature
//     function aggregatePublicKeys(
//         bytes calldata publicKeyBytes,
//         bytes calldata bitmap,
//         uint256 numSigners
//     ) public pure returns (bytes memory result) {
//         BLS2.PointG2 memory aggregatedPoint;
//         bool first = true;

//         for (uint32 i = 0; i < numSigners; i++) {
//             if (CodecHelpers.getBit(bitmap, i)) {
//                 // Extract the i-th public key 
//                 uint256 offset = i * BLS_PUBLIC_KEY_LENGTH;
//                 bytes calldata pkBytes = publicKeyBytes[offset:offset + BLS_PUBLIC_KEY_LENGTH];
//                 BLS2.PointG2 memory pk = BLS2.g2Unmarshal(pkBytes);

//                 if (first) {
//                     aggregatedPoint = pk;
//                     first = false;
//                 } else {
//                     aggregatedPoint = BLS2.g2Add(aggregatedPoint, pk);
//                 }
//             }
//         }

//         if (first) revert NoSignersInBitmap();

//         // Marshal the aggregated point back to bytes for use in verifySignature
//         return abi.encodePacked(
//             aggregatedPoint.x.a, aggregatedPoint.x.b,
//             aggregatedPoint.y.a, aggregatedPoint.y.b
//         );
//     }

//     /// @notice Convert bytes32 to hex string
//     /// @param data Bytes to convert
//     /// @return Hex string representation
//     function _bytes32ToHex(bytes32 data) internal pure returns (string memory) {
//         bytes memory hexChars = "0123456789abcdef";
//         bytes memory result = new bytes(64);

//         for (uint256 i = 0; i < 32; i++) {
//             result[i * 2] = hexChars[uint8(data[i] >> 4)];
//             result[i * 2 + 1] = hexChars[uint8(data[i] & 0x0f)];
//         }

//         return string(result);
//     }
// }
