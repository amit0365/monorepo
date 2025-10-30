# BLS Integration Complete

## ✅ Successfully Integrated bls-solidity Library

### Dependencies Added

1. **bls-solidity fork** (hash-enum branch)
   - Repository: `https://github.com/amit0365/bls-solidity.git`
   - Branch: `hash-enum`
   - Location: `lib/bls-solidity/`
   - Supports: SHA256, KECCAK256 hash functions in DST

2. **Remapping configured**
   ```
   bls-solidity/=lib/bls-solidity/src/
   ```

### BLSThresholdScheme Integration

**File**: [src/schemes/BLSThresholdScheme.sol](src/schemes/BLSThresholdScheme.sol)

#### Changes Made:

1. ✅ **Uses real BLS2 library functions**
   - `BLS2.g2Unmarshal()` - Deserialize threshold public key
   - `BLS2.g2Marshal()` - Serialize threshold public key
   - `BLS2.hashToPoint()` - Hash message to G1 (RFC 9380)
   - `BLS2.g1Unmarshal()` - Deserialize signature
   - `BLS2.verifySingle()` - Pairing verification

2. ✅ **Removed placeholder implementations**
   - Removed `_hash()` function (now uses BLS2.hashToPoint directly)
   - Removed `_blake2b()` placeholder
   - Removed BLAKE2B from DST generation

3. ✅ **Updated hashAndVerify()**
   ```solidity
   function hashAndVerify(
       bytes calldata message,
       bytes calldata signature
   ) external view returns (bool) {
       // Hash to BLS point on G1 using BLS2.hashToPoint
       // Note: BLS2.hashToPoint internally uses the hash function from DST
       BLS2.PointG1 memory messagePoint = BLS2.hashToPoint(DST, message);

       // Verify threshold signature against threshold public key
       BLS2.PointG1 memory sig = BLS2.g1Unmarshal(signature);
       (bool pairingSuccess, bool callSuccess) = BLS2.verifySingle(sig, thresholdPublicKey, messagePoint);
       return pairingSuccess && callSuccess;
   }
   ```

4. ✅ **Supported hash functions**
   - SHA256: `-BLS12381G1_XMD:SHA-256_SSWU_RO_`
   - KECCAK256: `-BLS12381G1_XMD:KECCAK-256_SSWU_RO_`
   - BLAKE2B: Not supported (commented out in enum)

### HashFunction Enum

**File**: [src/interfaces/ISignatureScheme.sol](src/interfaces/ISignatureScheme.sol)

```solidity
enum HashFunction {
    SHA256,
    KECCAK256
    // BLAKE2B  // Not supported yet
}
```

We kept our own enum instead of using BLS2.HashFunction for flexibility.

### Architecture

```
BLSThresholdScheme (our contract)
    ↓ imports
IThresholdScheme interface (our interface)
    ↓ imports
BLS2 library (from bls-solidity fork)
    ↓ uses
EIP-2537 precompiles (BLS12-381 operations)
```

### Why No G2 Addition Needed

Threshold signatures use a **single shared threshold public key**, so:
- ❌ No public key aggregation needed
- ❌ No G2 point addition required
- ✅ Just verify signature against one threshold key

### BLSMultisigScheme Status

**Not integrated yet** - Would require:
- G2 point addition for public key aggregation
- BLS2Extensions library with `g2Add()` function
- Uses EIP-2537 precompile at address `0x0c`

### Files Created/Modified

**Created:**
- [src/interfaces/ISignatureScheme.sol](src/interfaces/ISignatureScheme.sol) - Three signature scheme interfaces
- [src/schemes/BLSThresholdScheme.sol](src/schemes/BLSThresholdScheme.sol) - Threshold scheme (integrated)
- [src/schemes/BLSMultisigScheme.sol](src/schemes/BLSMultisigScheme.sol) - Multisig scheme (not integrated)
- [src/schemes/Ed25519Scheme.sol](src/schemes/Ed25519Scheme.sol) - Ed25519 scheme (placeholder)
- [src/libraries/BLS2Extensions.sol](src/libraries/BLS2Extensions.sol) - G2 addition (for future multisig)

**Modified:**
- [remappings.txt](remappings.txt) - Added bls-solidity remapping

### Next Steps (Optional)

1. **Complete BLSMultisigScheme integration**
   - Integrate BLS2Extensions for G2 addition
   - Update `_aggregatePublicKeys()` to use real G2 addition
   - Update `hashAndVerify()` to use BLS2 functions

2. **Ed25519Scheme integration**
   - Implement Ed25519 verification (precompile or library)
   - May not be needed if only using BLS

3. **Testing**
   - Create tests for BLSThresholdScheme
   - Test with real consensus data from Rust implementation

### Compilation Status

✅ **BLSThresholdScheme compiles successfully**

Note: There's an unrelated error in `SimplexVerifierBLS12381Threshold.sol` (uses `SignerMismatch` instead of `Conflicting_SignerMismatch`), but we were instructed not to update existing contracts.

### Usage Example

```solidity
// Deploy threshold scheme
bytes memory thresholdPubKey = hex"..."; // 192 bytes G2 point
uint32 participants = 100;
HashFunction hashFn = HashFunction.SHA256;
string memory app = "MyApp";

BLSThresholdScheme scheme = new BLSThresholdScheme(
    thresholdPubKey,
    participants,
    hashFn,
    app
);

// Verify a threshold signature
bytes memory message = hex"...";
bytes memory signature = hex"..."; // 48 bytes G1 point
bool valid = scheme.hashAndVerify(message, signature);
```

## Summary

✅ BLS12-381 threshold signature verification fully integrated
✅ Uses production-ready bls-solidity library
✅ Supports SHA256 and KECCAK256 hash functions
✅ Ready for testing with real consensus data
