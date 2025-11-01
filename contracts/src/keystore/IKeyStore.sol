// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../signing_schemes/interfaces/ISignatureScheme.sol";

/// @title IKeyStore
/// @notice Interface for managing validator public keys
/// @dev KeyStore implementations handle key storage and validation
interface IKeyStore {
    /// @notice Emitted when participants are updated
    event ParticipantsUpdated(uint256 count);

    /// @notice The signature scheme this keystore manages keys for
    /// @return The signature scheme instance
    function scheme() external view returns (ISignatureScheme);

    /// @notice Get a participant's public key by index
    /// @param index The participant index
    /// @return The public key bytes
    function getParticipant(uint256 index) external view returns (bytes memory);

    /// @notice Get the total number of participants
    /// @return The number of participants
    function getParticipantCount() external view returns (uint256);

    /// @notice Update the validator public keys
    /// @param keys Array of public keys (must match scheme.publicKeyLength())
    function setParticipants(bytes[] calldata keys) external;
}
