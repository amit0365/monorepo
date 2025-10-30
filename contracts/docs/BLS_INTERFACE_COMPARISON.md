# BLS Interface Comparison

Comparison between our signature scheme interfaces and the bls-solidity repository.

## Key Differences

### 1. **Point Representation**

**bls-solidity BLS2.sol:**
```solidity
struct PointG1 {
    uint128 x_hi;  // High 128 bits of x coordinate
    uint256 x_lo;  // Low 256 bits of x coordinate
    uint128 y_hi;  // High 128 bits of y coordinate
    uint256 y_lo;  // Low 256 bits of y coordinate
}

struct PointG2 {
    uint128 x1_hi;
    uint256 x1_lo;
    uint128 x0_hi;
    uint256 x0_lo;
    uint128 y1_hi;
    uint256 y1_lo;
    uint128 y0_hi;
    uint256 y0_lo;
}
```
- G1: 96 bytes uncompressed (48 bytes each for x and y)
- G2: 192 bytes uncompressed (96 bytes each for x and y)
- Uses split field representation for 48-byte field elements
- More gas-efficient for EVM operations

**Our BLS2.sol (placeholder):**
```solidity
struct PointG1 {
    bytes data;  // Generic bytes representation
}

struct PointG2 {
    bytes data;  // Generic bytes representation
}
```
- Simple bytes wrapper
- Less efficient but more flexible
- Not optimized for EVM

### 2. **Interface Design**

**bls-solidity ISignatureScheme:**
```solidity
interface ISignatureScheme {
    function SCHEME_ID() external view returns (string memory);
    function DST() external view returns (bytes memory);
    function verifySignature(bytes calldata message, bytes calldata signature)
        external view returns (bool isValid);
    function hashToBytes(bytes calldata message)
        external view returns (bytes memory);
    function getPublicKeyBytes()
        external view returns (bytes memory);
}
```

**Key characteristics:**
- **Single public key**: `getPublicKeyBytes()` returns ONE key (threshold scheme)
- **Pre-hashed message**: `message` parameter is already a G1 point (bytes)
- **DST exposed**: Domain separation tag is part of the interface
- **Hash helper**: `hashToBytes()` converts message to G1 point
- **Simple verify**: Single signature verification only

**Our Interfaces:**

We have THREE separate interfaces:

#### IAttributableScheme (Ed25519-style):
```solidity
interface IAttributableScheme {
    function SCHEME_ID() external pure returns (string memory);
    function HASH_FUNCTION() external view returns (HashFunction);
    function getPublicKey(uint32 signerIndex) external view returns (bytes memory);
    function participantCount() external view returns (uint32);
    function deserializeCertificate(...) external pure returns (
        uint32[] memory signers,
        bytes[] memory signatures,
        uint256 newOffset
    );
    function hashAndVerify(
        bytes calldata message,
        uint32[] calldata signers,
        bytes[] calldata signatures
    ) external view returns (bool);
}
```

#### IAggregatedScheme (BLS Multisig):
```solidity
interface IAggregatedScheme {
    // Same basics as above
    function deserializeCertificate(...) external pure returns (
        bytes memory signersBitmap,
        bytes memory signature,
        uint256 newOffset
    );
    function hashAndVerify(
        bytes calldata message,
        bytes calldata signersBitmap,
        bytes calldata signature
    ) external view returns (bool);
}
```

#### IThresholdScheme (BLS Threshold):
```solidity
interface IThresholdScheme {
    // Same basics as above
    function getThresholdPublicKey() external view returns (bytes memory);
    function deserializeCertificate(...) external pure returns (
        bytes memory signature,
        uint256 newOffset
    );
    function hashAndVerify(
        bytes calldata message,
        bytes calldata signature
    ) external view returns (bool);
}
```

**Key characteristics:**
- **Multiple keys**: `getPublicKey(index)` for attributable/aggregated schemes
- **Raw message**: `message` is raw bytes, scheme handles hashing
- **Hash function choice**: Exposed via `HASH_FUNCTION()` enum
- **Certificate deserialization**: Built into the interface
- **Multi-signer support**: Different interfaces for different certificate types

### 3. **Message Handling**

**bls-solidity:**
```solidity
// Step 1: Hash message to G1 point
bytes memory messagePoint = scheme.hashToBytes(rawMessage);

// Step 2: Verify signature
bool valid = scheme.verifySignature(messagePoint, signature);
```
- Two-step process
- Message must be converted to G1 point first
- Separation of hashing and verification

**Our approach:**
```solidity
// Single step: hash and verify
bool valid = scheme.hashAndVerify(rawMessage, signers, signatures);
```
- One-step process
- Scheme handles hashing internally
- More convenient for consensus verification

### 4. **Public Key Management**

**bls-solidity:**
```solidity
// Single threshold public key
constructor(bytes memory publicKeyBytes, string memory application)
```
- Single public key per contract
- Designed for threshold signatures only
- Public key is immutable

**Our approach:**
```solidity
// Ed25519: Array of individual keys
constructor(bytes32[] memory _publicKeys, HashFunction _hashFunction)

// BLS Multisig: Array of BLS keys
constructor(bytes[] memory publicKeyBytes, HashFunction _hashFunction, string memory application)

// BLS Threshold: Single threshold key
constructor(bytes memory thresholdKeyBytes, uint32 _n, HashFunction _hashFunction, string memory application)
```
- Different constructors for different scheme types
- Supports multiple participants (attributable/aggregated)
- Explicit participant count for threshold schemes

### 5. **Verification API**

**bls-solidity:**
```solidity
function verifySingle(
    PointG1 memory signature,
    PointG2 memory pubkey,
    PointG1 memory message
) internal view returns (bool pairingSuccess, bool callSuccess)
```
- Internal library function
- Works with structured points
- Returns both pairing result AND call success
- More low-level control

**Our approach:**
```solidity
function pairing(
    PointG1 memory messagePoint,
    PointG2 memory publicKey,
    PointG1 memory signature
) internal view returns (bool)
```
- Simpler single boolean return
- Placeholder for now (not implemented)
- Higher-level abstraction

### 6. **Hash-to-Curve**

**bls-solidity:**
```solidity
function hashToPoint(bytes memory dst, bytes memory message)
    internal view returns (PointG1 memory)
```
- Implements RFC 9380 §5 (hash-to-curve)
- Uses `expandMsg` with SHA256
- Implements full `map_fp_to_g1` via EIP-2537 precompiles
- Production-ready implementation

**Our approach:**
```solidity
function hashToG1(bytes32 messageHash, bytes memory dst)
    internal view returns (PointG1 memory)
```
- Takes pre-computed hash (not raw message)
- Placeholder implementation
- Needs RFC 9380 implementation

## Size Comparisons

### Point Sizes

| Type | bls-solidity | Our Implementation |
|------|--------------|-------------------|
| G1 (uncompressed) | 96 bytes | 48 bytes (assumed compressed) |
| G2 (uncompressed) | 192 bytes | 96 bytes (assumed compressed) |
| G1 (compressed) | 48 bytes (supported) | Not yet supported |

### Certificate Sizes (100 validators, 67 signers)

| Scheme | bls-solidity | Our Implementation |
|--------|--------------|-------------------|
| Threshold | ~48 bytes | ~48 bytes |
| Multisig | Not supported | ~150 bytes (bitmap + sig) |
| Attributable | Not supported | ~4,600 bytes |

## Integration Recommendations

### What to Adopt from bls-solidity:

1. **Point Structure**: Use their split field representation for better EVM efficiency
   ```solidity
   struct PointG1 {
       uint128 x_hi;
       uint256 x_lo;
       uint128 y_hi;
       uint256 y_lo;
   }
   ```

2. **Hash-to-Curve**: Use their RFC 9380 implementation
   ```solidity
   function hashToPoint(bytes memory dst, bytes memory message)
       internal view returns (PointG1 memory)
   ```

3. **expandMsg**: Use their domain separation implementation
   ```solidity
   function expandMsg(bytes memory DST, bytes memory message, uint8 n_bytes)
   ```

4. **verifySingle**: Use their pairing verification
   ```solidity
   function verifySingle(PointG1 memory signature, PointG2 memory pubkey, PointG1 memory message)
       returns (bool pairingSuccess, bool callSuccess)
   ```

5. **Compressed Points**: Add support for 48-byte G1 compression
   ```solidity
   function g1UnmarshalCompressed(bytes memory m) returns (PointG1 memory)
   ```

### What to Keep from Our Design:

1. **Multiple Interface Types**: Our three-interface design is better for supporting different schemes
   - `IAttributableScheme` for Ed25519
   - `IAggregatedScheme` for BLS multisig
   - `IThresholdScheme` for BLS threshold

2. **Multi-Key Support**: Our design supports multiple public keys (not just threshold)

3. **Certificate Deserialization**: Built into the interface (needed for consensus proofs)

4. **Hash Function Flexibility**: Support for SHA256/BLAKE2B/KECCAK256

5. **One-Step Verification**: `hashAndVerify()` is more convenient than two-step process

## Proposed Changes

### Update BLS2.sol to use bls-solidity implementation:

```solidity
// Copy from bls-solidity/src/libraries/BLS2.sol:
- Point structures (PointG1, PointG2)
- Marshaling functions (g1Marshal, g1Unmarshal, g2Marshal, g2Unmarshal)
- Compressed point support (g1UnmarshalCompressed)
- hashToPoint (RFC 9380)
- expandMsg
- verifySingle
```

### Update our schemes to use proper BLS2:

```solidity
// In BLSMultisigScheme.sol
function _aggregatePublicKeys(bytes memory bitmap) internal view returns (BLS2.PointG2 memory) {
    BLS2.PointG2 memory result;
    bool first = true;

    for (uint32 i = 0; i < publicKeys.length; i++) {
        if (_getBit(bitmap, i)) {
            if (first) {
                result = publicKeys[i];
                first = false;
            } else {
                // Use actual G2 addition from bls-solidity
                result = BLS2.g2Add(result, publicKeys[i]);
            }
        }
    }
    return result;
}
```

### Update hashAndVerify to use their implementation:

```solidity
function hashAndVerify(
    bytes calldata message,
    bytes calldata signersBitmap,
    bytes calldata signature
) external view returns (bool) {
    // Hash the message using configured hash function
    bytes32 messageHash = _hash(message);

    // Use bls-solidity's hashToPoint
    BLS2.PointG1 memory messagePoint = BLS2.hashToPoint(DST, abi.encodePacked(messageHash));

    // Aggregate public keys
    BLS2.PointG2 memory aggregatedPubKey = _aggregatePublicKeys(signersBitmap);

    // Use bls-solidity's verifySingle
    BLS2.PointG1 memory sig = BLS2.g1Unmarshal(signature);
    (bool pairingSuccess, bool callSuccess) = BLS2.verifySingle(sig, aggregatedPubKey, messagePoint);

    return pairingSuccess && callSuccess;
}
```

## Summary

**bls-solidity strengths:**
- Production-ready BLS implementation
- Efficient point representation
- Complete RFC 9380 hash-to-curve
- Working precompile integration

**Our design strengths:**
- Support for multiple scheme types
- Multi-key management
- Certificate deserialization
- Better suited for consensus verification

**Best path forward:**
1. Replace our placeholder BLS2.sol with bls-solidity's implementation
2. Keep our three-interface design
3. Update our schemes to use their BLS2 library
4. Add G2 addition function to their BLS2 library (for aggregation)
