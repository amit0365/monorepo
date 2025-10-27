# Commonware Solidity Contracts

Smart contracts for on-chain verification of [Commonware](https://commonware.xyz) consensus proofs.

## Overview

This directory contains Solidity verifiers that deserialize and validate consensus proofs from the Commonware library. These contracts enable on-chain verification of validator activity and Byzantine behavior, supporting use cases like:

- **Restaking protocols** - Verify uptime emissions and slash malicious validators
- **Cross-chain bridges** - Validate consensus certificates from other chains
- **On-chain governance** - Prove validator participation in consensus

## Contracts

### SimplexVerifier.sol

Deserializes and validates proofs from the [consensus::simplex](../consensus/src/simplex/) module.

**Supported Proof Types:**

#### Individual Votes (Uptime Evidence)
- `deserializeNotarize` - Validator vote to endorse a proposal
- `deserializeNullify` - Validator vote to skip a view (liveness mechanism)
- `deserializeFinalize` - Validator vote to commit a proposal

#### Certificates (Quorum Agreements)
- `deserializeNotarization` - 2f+1 validators endorsed a proposal
- `deserializeNullification` - 2f+1 validators agreed to skip a view
- `deserializeFinalization` - 2f+1 validators committed a proposal

#### Fraud Proofs (Byzantine Behavior)
- `deserializeConflictingNotarize` - Validator signed two different proposals at same view
- `deserializeConflictingFinalize` - Validator finalized two different proposals at same view
- `deserializeNullifyFinalize` - Validator voted both to skip AND finalize the same view

**Key Features:**
- ✅ Matches Rust type structure exactly (Round, Proposal, Vote)
- ✅ Proper varint decoding for compact encoding
- ✅ Complete coverage of all 9 Activity variants
- ✅ Validates Byzantine behavior (epoch/view/signer matching)
- ✅ Gas-optimized with custom errors
- ✅ Supports Ed25519 signatures (extensible to BLS12-381)

## Development

### Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation)
- Solidity ^0.8.19

### Build

```bash
forge build
```

### Test

```bash
forge test -vvv
```

### Generate Gas Report

```bash
forge test --gas-report
```

## Usage Example

```solidity
// Deploy verifier
SimplexVerifier verifier = new SimplexVerifier();

// Deserialize a notarize proof
(SimplexVerifier.Proposal memory proposal, SimplexVerifier.Vote memory vote) =
    verifier.deserializeNotarize(proofBytes);

// Check validator participated
if (vote.signer == validatorIndex) {
    // Award uptime credit
    creditUptime(validatorIndex, proposal.round.epoch);
}

// Deserialize fraud proof
(
    SimplexVerifier.Proposal memory p1,
    SimplexVerifier.Vote memory v1,
    SimplexVerifier.Proposal memory p2,
    SimplexVerifier.Vote memory v2
) = verifier.deserializeConflictingNotarize(fraudProofBytes);

// Slash Byzantine validator
if (v1.signer == byzantineValidator) {
    slashValidator(byzantineValidator);
}
```

## Encoding Format

All proofs use the same encoding as the Rust implementation:

### Fixed-Size Fields (Big-Endian)
Most numeric fields use **fixed-size big-endian encoding** (not varint):
- `epoch`: 8 bytes (u64, big-endian)
- `view`: 8 bytes (u64, big-endian)
- `signer`: 4 bytes (u32, big-endian)
- `digest`: 32 bytes (SHA256)
- `signature`: 64 bytes (Ed25519)

### Varint Fields (LEB128)
Only specific fields use varint encoding:
- `parent`: parent view (varint u64)
- `vote_count`: number of votes in certificates (varint u32)

### Structures

**Round:**
```
8 bytes: epoch (u64 BE) | 8 bytes: view (u64 BE)
Total: 16 bytes fixed
```

**Note:** In Solidity, the `view` field is named `viewCounter` to avoid conflict with the `view` function modifier keyword.

**Proposal:**
```
Round (16 bytes) | varint(parent) | 32-byte payload digest
Min: 49 bytes
```

**Vote (Ed25519):**
```
4 bytes: signer (u32 BE) | 64-byte signature
Total: 68 bytes fixed
```

**Notarize/Finalize:**
```
Proposal (49+ bytes) | Vote (68 bytes)
Min: 117 bytes
```

**Nullify:**
```
Round (16 bytes) | Vote (68 bytes)
Total: 84 bytes fixed
```

**Notarization/Finalization:**
```
Proposal (49+ bytes) | varint(vote_count) | Vote[] (68 bytes each)
Example (3 votes): 49 + 1 + 204 = 254 bytes
```

**Nullification:**
```
Round (16 bytes) | varint(vote_count) | Vote[] (68 bytes each)
Example (3 votes): 16 + 1 + 204 = 221 bytes
```

**ConflictingNotarize/ConflictingFinalize:**
```
Proposal1 (49+ bytes) | Vote1 (68 bytes) | Proposal2 (49+ bytes) | Vote2 (68 bytes)
Min: 234 bytes
```

**NullifyFinalize:**
```
Round (16 bytes) | Vote (68 bytes) | Proposal (49+ bytes) | Vote (68 bytes)
Min: 201 bytes
```

See [SERIALIZATION_FORMAT.md](SERIALIZATION_FORMAT.md) for complete encoding details.

## Testing Against Rust

The [consensus/tests/simplex_solidity_proofs.rs](../consensus/tests/simplex_solidity_proofs.rs) test suite generates real serialized proofs from the Rust implementation:

```bash
# Generate proof data
cargo test --test simplex_solidity_proofs -- --nocapture

# Copy hex output and use in Solidity tests
```

This ensures the Solidity deserializer exactly matches the Rust serialization format.

## Signature Verification

**Important:** This verifier only **deserializes** proofs. Cryptographic signature verification must be implemented separately:

- **Ed25519:** Use existing precompiles or libraries
- **BLS12-381:** Requires [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537) or verification contracts

For production use, combine deserialization with signature verification to ensure proof authenticity.

## Security Considerations

1. **Signature Verification Required** - Always verify signatures after deserialization
2. **Signer Set Validation** - Verify signer indices are in valid validator set
3. **Epoch Boundaries** - Validate proofs against correct epoch's validator set
4. **Replay Protection** - Track processed proofs to prevent replay attacks
5. **Gas Limits** - Large vote arrays (high maxSigners) can exceed block gas limit

## Extending the Verifier

### Adding BLS12-381 Support

To support [consensus::simplex with BLS12-381](../consensus/src/simplex/signing_scheme/bls12381_multisig.rs):

1. Add BLS signature length constants
2. Implement `deserializeVoteBLS` for aggregated signatures
3. Update certificate deserializers to support both schemes
4. Add scheme discriminator to proof format

### Supporting Threshold Signatures

For [consensus::threshold_simplex](../consensus/src/threshold_simplex/), certificates contain single threshold signatures instead of vote arrays. This requires:

1. Different certificate structure (single signature)
2. Threshold public key verification
3. Modified deserialization for aggregated proofs

## Contributing

When modifying the verifier:

1. Update Rust integration tests to generate new proof formats
2. Add corresponding Solidity test cases
3. Verify gas usage remains reasonable
4. Update this README with format changes

## References

- [Simplex Consensus Paper](https://eprint.iacr.org/2023/463)
- [Commonware Simplex Implementation](../consensus/src/simplex/)
- [Protocol Documentation](../consensus/src/simplex/mod.rs)
- [Threshold Simplex Blog](https://commonware.xyz/blogs/threshold-simplex.html)

## License

MIT
