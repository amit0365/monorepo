// // SPDX-License-Identifier: MIT
// pragma solidity ^0.8.24;

// import {ISignatureScheme} from "./interfaces/ISignatureScheme.sol";
// import {BLS2} from "../crypto/bls12381/BLS2Extensions.sol";

    // /// @title BLSThresholdScheme
// /// @notice BLS12-381 threshold signature scheme implementation
// /// @dev Implements ISignatureScheme for threshold BLS signatures
// /// @dev This scheme uses a single threshold public key shared by all participants
// /// @dev The threshold public key is passed as the publicKey parameter in verifySignature
// /// @dev WARNING: Individual signatures are NOT attributable (threshold allows forgery)
// /// @dev Uses MinSig variant: Threshold key in G2 (96 bytes), Signatures in G1 (48 bytes)
// contract BLSMinSigThresholdScheme is ISignatureScheme {
//     // ============ Constants ============

//     uint256 constant BLS_PUBLIC_KEY_LENGTH = 96; // G2 for MinSig variant
//     uint256 constant BLS_SIGNATURE_LENGTH = 48; // G1 for MinSig variant

//     // ============ State ============

//     /// @notice Domain separation tag for hash-to-curve
//     /// @dev Format: {application}-BLS12381G1_XMD:SHA-256_SSWU_RO_{chainid}_
//     bytes public immutable DST;

//     // ============ Constructor ============

//     /// @notice Initialize the BLS threshold scheme
//     /// @param application Application name for domain separation tag
//     constructor(string memory application) {
//         // Build domain separation tag based on hash function
//         string memory hashSpec = "-BLS12381G1_XMD:SHA-256_SSWU_RO_";

//         DST = abi.encodePacked(
//             application,
//             hashSpec,
//             _bytes32ToHex(bytes32(block.chainid)),
//             "_"
//         );
//     }

//     // ============ Interface Implementation ============

//     /// @inheritdoc ISignatureScheme
//     function SCHEME_ID() external pure returns (string memory) {
//         return "BLS12381_THRESHOLD_MINSIG";
//     }

//     /// @inheritdoc ISignatureScheme
//     function PUBLIC_KEY_LENGTH() external pure returns (uint256) {
//         return BLS_PUBLIC_KEY_LENGTH;
//     }

//     /// @inheritdoc ISignatureScheme
//     function SIGNATURE_LENGTH() external pure returns (uint256) {
//         return BLS_SIGNATURE_LENGTH;
//     }

//     /// @inheritdoc ISignatureScheme
//     /// @notice Verify threshold BLS signature
//     /// @dev The publicKey parameter should be the threshold public key (96 bytes)
//     /// @dev This allows the verifier to be stateless and work with any threshold setup
//     /// @param message The raw message bytes that was signed
//     /// @param publicKey The threshold public key (96 bytes G2 point)
//     /// @param signature The threshold BLS signature (48 bytes G1 point)
//     /// @return true if signature is valid, false otherwise
//     function verifySignature(
//         bytes calldata message,
//         bytes calldata publicKey,
//         bytes calldata signature
//     ) external view returns (bool) {
//         // Validate lengths
//         if (publicKey.length != BLS_PUBLIC_KEY_LENGTH) return false;
//         if (signature.length != BLS_SIGNATURE_LENGTH) return false;

//         // Unmarshal public key and signature
//         BLS2.PointG2 memory thresholdKey = BLS2.g2Unmarshal(publicKey);
//         BLS2.PointG1 memory sig = BLS2.g1Unmarshal(signature);

//         // Hash message to BLS point on G1
//         BLS2.PointG1 memory messagePoint = BLS2.hashToPoint(DST, message);

//         // Verify threshold signature
//         (bool pairingSuccess, bool callSuccess) = BLS2.verifySingle(sig, thresholdKey, messagePoint);
//         return pairingSuccess && callSuccess;
//     }

//     // ============ Internal Helpers ============

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
