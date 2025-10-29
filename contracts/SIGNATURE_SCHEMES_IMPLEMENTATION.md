# Signature Schemes Implementation

This document describes the signature scheme abstraction implementation for Simplex consensus verification.

## Overview

The implementation provides a clean separation between consensus logic and cryptographic operations by introducing signature scheme interfaces and implementations.

## Architecture

### 1. Interfaces ([src/interfaces/ISignatureScheme.sol](src/interfaces/ISignatureScheme.sol))

Three distinct interfaces for different signature scheme types:

#### `IAttributableScheme`
- For schemes with individual attributable signatures (e.g., Ed25519)
- Certificates contain arrays of individual signatures
- Can prove individual validator faults/liveness
- Methods: `deserializeCertificate()` returns `(signers[], signatures[])`

#### `IAggregatedScheme`
- For schemes with aggregated signatures (e.g., BLS multisig)
- Certificates contain single aggregated signature + bitmap
- More efficient than attributable but still allows identifying signers
- Methods: `deserializeCertificate()` returns `(signersBitmap, signature)`

#### `IThresholdScheme`
- For threshold signature schemes (e.g., BLS threshold)
- Certificates contain only recovered threshold signature
- Most efficient but NOT attributable (allows forgery)
- Methods: `deserializeCertificate()` returns `(signature)`

All interfaces include:
- `SCHEME_ID()` - Unique identifier
- `HASH_FUNCTION()` - Hash function used
- `getPublicKey()` / `getThresholdPublicKey()` - Public key management
- `participantCount()` - Number of participants
- `hashAndVerify()` - Message verification

### 2. Common Types

#### `HashFunction` enum
```solidity
enum HashFunction {
    SHA256,
    BLAKE2B,
    KECCAK256
}
```

### 3. Implementations

#### Ed25519Scheme ([src/schemes/Ed25519Scheme.sol](src/schemes/Ed25519Scheme.sol))

**Type**: Attributable
**Key Size**: 32 bytes (Ed25519 public key)
**Signature Size**: 64 bytes per signer
**Certificate Format**: Bitmap + Array of signatures

**Features**:
- Individual Ed25519 signatures
- Full attribution for fault proofs
- Stores public keys as `bytes32[]`
- Implements varint decoding for certificate deserialization
- Bitmap validation with trailing bit checks

**Constructor**:
```solidity
constructor(bytes32[] memory _publicKeys, HashFunction _hashFunction)
```

**TODO**:
- Implement `_verifyEd25519()` with Ed25519 precompile
- Implement `_blake2b()` if BLAKE2B hash is needed

#### BLSMultisigScheme ([src/schemes/BLSMultisigScheme.sol](src/schemes/BLSMultisigScheme.sol))

**Type**: Aggregated
**Key Size**: 96 bytes (G2 for MinPk variant)
**Signature Size**: 48 bytes (G1, constant regardless of signers)
**Certificate Format**: Bitmap + Single aggregated signature

**Features**:
- BLS12-381 signature aggregation
- Constant-size certificates
- Domain separation tag generation
- Public key aggregation based on bitmap
- Much more efficient for large validator sets

**Constructor**:
```solidity
constructor(
    bytes[] memory publicKeyBytes,
    HashFunction _hashFunction,
    string memory application
)
```

**TODO**:
- Complete BLS2 library implementation with precompiles
- Implement `_blake2b()` if BLAKE2B hash is needed

#### BLSThresholdScheme ([src/schemes/BLSThresholdScheme.sol](src/schemes/BLSThresholdScheme.sol))

**Type**: Threshold
**Key Size**: 96 bytes (single threshold G2 key)
**Signature Size**: 48 bytes (G1, constant)
**Certificate Format**: Just threshold signature (no signer info)

**Features**:
- Single threshold public key
- Smallest certificates possible
- Domain separation tag generation
- WARNING: Not attributable - threshold allows signature forgery

**Constructor**:
```solidity
constructor(
    bytes memory thresholdKeyBytes,
    uint32 _n,
    HashFunction _hashFunction,
    string memory application
)
```

**TODO**:
- Complete BLS2 library implementation with precompiles
- Implement `_blake2b()` if BLAKE2B hash is needed

### 4. BLS2 Library ([src/libraries/BLS2.sol](src/libraries/BLS2.sol))

**Status**: Placeholder implementation

Provides BLS12-381 operations:
- `PointG1` / `PointG2` structs
- `g1Unmarshal()` / `g2Unmarshal()` - Deserialization
- `g1Marshal()` / `g2Marshal()` - Serialization
- `g1Add()` / `g2Add()` - Point addition
- `hashToG1()` - Hash-to-curve
- `pairing()` - Pairing verification

**TODO**:
- Implement using BLS12-381 precompiles
- Add proper point validation
- Implement hash-to-curve (draft-irtf-cfrg-hash-to-curve)

## Separation of Concerns

### Signature Schemes Own:
✅ Public key storage & management
✅ Certificate deserialization (format differs by scheme)
✅ Hash function choice
✅ Signature verification logic

### SimplexVerifierBase Owns:
✅ Round, Proposal structs
✅ Consensus structure deserialization
✅ Message building (universal format)
✅ Varint helpers

### Concrete Verifiers (Future):
✅ Call Base for consensus structures
✅ Call Scheme for certificates
✅ Call Base for messages
✅ Call Scheme for verification

## Efficiency Comparison (100 validators, 67 quorum)

| Scheme | Certificate Size | Verification Cost |
|--------|-----------------|-------------------|
| Ed25519 | ~4,600 bytes | ~200k gas (67 checks) |
| BLS Multisig | ~150 bytes | ~200k gas (1 pairing) |
| BLS Threshold | ~48 bytes | ~200k gas (1 pairing) |

Threshold becomes significantly cheaper for larger validator sets due to constant certificate size.

## Next Steps

1. **Complete BLS2 Library**
   - Implement BLS12-381 precompile calls
   - Add point validation
   - Implement hash-to-curve

2. **Ed25519 Verification**
   - Implement Ed25519 precompile integration
   - Add signature validation

3. **BLAKE2B Support**
   - Implement BLAKE2B precompile (address 0x09)
   - Add proper error handling

4. **Integration Testing**
   - Create tests for each scheme
   - Test with real consensus data
   - Verify interoperability with Rust implementation

5. **Create Verifier Contracts**
   - Update existing verifiers to use scheme interfaces
   - Create example verifiers for each scheme type
   - Add orchestration contracts

## Files Created

```
contracts/
├── src/
│   ├── interfaces/
│   │   └── ISignatureScheme.sol          # All three interfaces + HashFunction enum
│   ├── schemes/
│   │   ├── Ed25519Scheme.sol             # Attributable scheme implementation
│   │   ├── BLSMultisigScheme.sol         # Aggregated scheme implementation
│   │   └── BLSThresholdScheme.sol        # Threshold scheme implementation
│   └── libraries/
│       └── BLS2.sol                      # BLS12-381 operations (placeholder)
```

## Notes

- All schemes include strict varint decoding validation
- Bitmap deserialization includes trailing bit validation
- Domain separation tags follow the format: `{app}-BLS12381G1_XMD:SHA-256_SSWU_RO_{chainid}_`
- Current implementations have placeholder crypto operations marked with TODO
- Not production-ready until crypto operations are implemented
