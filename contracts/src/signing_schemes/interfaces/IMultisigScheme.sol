// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {ISignatureScheme} from "./ISignatureScheme.sol";

/// @title IMultisigScheme
/// @notice Interface for multisignature schemes that support key aggregation
/// @dev Extends ISignatureScheme with aggregation capabilities for multisig consensus
interface IMultisigScheme is ISignatureScheme {
    /// @notice Aggregate multiple public keys based on a bitmap of signers
    /// @dev This method is used by SimplexVerifierMultisig to prepare keys for verification
    /// @param publicKeyBytes Concatenated public keys of all participants
    /// @param bitmap Bitmap indicating which participants signed
    /// @param numParticipants Total number of participants
    /// @return aggregatedKey The aggregated public key ready for signature verification
    function aggregatePublicKeys(
        bytes calldata publicKeyBytes,
        bytes calldata bitmap,
        uint256 numParticipants
    ) external pure returns (bytes memory aggregatedKey);
}