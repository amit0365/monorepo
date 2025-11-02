// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {SimplexVerifierAttributable} from "./simplex_verifiers/SimplexVerifierAttributable.sol";
import {DigestLengths} from "./simplex_verifiers/SimplexVerifierBase.sol";
import {Ed25519Scheme} from "./signing_schemes/Ed25519Scheme.sol";
import {SimpleKeyStore} from "./keystore/SimpleKeyStore.sol";

/// @title SimplexEd25519Example
/// @notice Example deployment of SimplexVerifierAttributable with Ed25519
/// @dev This shows the actual deployed size when using Ed25519 signatures
/// @dev Uses SimpleKeyStore for participant management
contract SimplexEd25519Example is SimplexVerifierAttributable {
    /// @notice Deploy SimplexVerifierAttributable with Ed25519, SimpleKeyStore, and SHA256
    constructor()
        SimplexVerifierAttributable(
            new SimpleKeyStore(new Ed25519Scheme()),
            DigestLengths.SHA256
        )
    {}
}
