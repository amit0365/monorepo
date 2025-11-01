// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./IKeyStore.sol";
import "../signing_schemes/interfaces/ISignatureScheme.sol";

/// @title SimpleKeyStore
/// @notice Simple key storage implementation for managing a single validator set
/// @dev Does not support epoch-based key rotation - overwrites keys on each update
/// @dev Validates all keys match the scheme's expected public key length
contract SimpleKeyStore is IKeyStore {
    // ============ Immutable Configuration ============

    /// @notice The signature scheme this keystore manages keys for
    ISignatureScheme public immutable scheme;

    // ============ State Variables ============

    /// @notice Array of validator public keys
    /// @dev Each key is validated to match scheme.PUBLIC_KEY_LENGTH()
    bytes[] public participants;

    // ============ Constructor ============

    /// @notice Create a new SimpleKeyStore for a specific signature scheme
    /// @param _scheme The signature scheme that defines key format and length
    constructor(ISignatureScheme _scheme) {
        scheme = _scheme;
    }

    // ============ Key Management ============

    /// @notice Update the validator public keys
    /// @dev Overwrites existing keys - does not support historical key sets
    /// @param keys Array of public keys (must match scheme.PUBLIC_KEY_LENGTH())
    function setParticipants(bytes[] calldata keys) external {
        uint256 expectedLength = scheme.PUBLIC_KEY_LENGTH();

        // Validate all keys have correct length for this scheme
        for (uint256 i = 0; i < keys.length; i++) {
            require(keys[i].length == expectedLength, "Invalid key length for scheme");
        }

        // Clear existing participants
        delete participants;

        // Set new participants
        for (uint256 i = 0; i < keys.length; i++) {
            participants.push(keys[i]);
        }

        emit ParticipantsUpdated(keys.length);
    }

    // ============ Key Access ============

    /// @notice Get a participant's public key by index
    /// @param index The participant index
    /// @return The public key bytes
    function getParticipant(uint256 index) external view returns (bytes memory) {
        require(index < participants.length, "Invalid participant index");
        return participants[index];
    }

    /// @notice Get the total number of participants
    /// @return The number of participants
    function getParticipantCount() external view returns (uint256) {
        return participants.length;
    }
}
