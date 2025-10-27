# Addressing Patrick's Feedback on PR #412

This document addresses the three review comments from patrick-ogrady on PR #412.

## Comment 1: Scheme Configuration via Initializer

**Patrick's Comment (Line 8):**
> "I think we might want to provide these via some initializer? It is possible that Simplex is instantiated with a variety of different schemes."

**Context:**
The original PR hardcoded Ed25519 constants:
```solidity
uint256 constant DIGEST_LENGTH = 32;
uint256 constant PUBLIC_KEY_LENGTH = 32;
uint256 constant ED25519_SIGNATURE_LENGTH = 64;
```

### Analysis

Simplex supports multiple signing schemes (from [consensus/src/simplex/signing_scheme/](../consensus/src/simplex/signing_scheme/)):

1. **Ed25519** - 32-byte keys, 64-byte signatures
2. **BLS12-381 MultiSig** - 48-byte keys, 96-byte signatures
3. **BLS12-381 Threshold** - 48-byte keys, 96-byte signatures (aggregated)

### Two Approaches

#### Option A: Single Contract with Scheme Parameter

Make the verifier scheme-agnostic by passing scheme info at runtime:

```solidity
enum SignatureScheme {
    Ed25519,
    BLS12381MultiSig,
    BLS12381Threshold
}

struct SchemeConfig {
    SignatureScheme scheme;
    uint256 publicKeyLength;
    uint256 signatureLength;
}

contract SimplexVerifier {
    // State variable set via constructor
    SchemeConfig public config;

    constructor(SchemeConfig memory _config) {
        config = _config;
    }

    function deserializeVote(bytes calldata data, uint256 offset)
        internal view returns (Vote memory vote, uint256 newOffset)
    {
        uint64 signerU64;
        (signerU64, offset) = decodeVarintU64(data, offset);
        vote.signer = uint32(signerU64);

        // Use configured signature length
        if (offset + config.signatureLength > data.length) revert InvalidProofLength();
        vote.signature = data[offset:offset+config.signatureLength];
        offset += config.signatureLength;

        return (vote, offset);
    }
}
```

**Pros:**
- Single deployment for all schemes
- Runtime flexibility
- Matches Patrick's suggestion

**Cons:**
- Extra SLOAD for every vote deserialization (gas overhead)
- Can't use constants (less gas-efficient)
- Still need separate signature verification contracts

#### Option B: Separate Contracts per Scheme (Recommended)

Create specialized verifiers for each scheme:

```solidity
// Base abstract contract
abstract contract SimplexVerifierBase {
    // Common logic (varint, round, proposal deserialization)

    // Abstract methods for scheme-specific parts
    function deserializeVote(bytes calldata data, uint256 offset)
        internal virtual returns (Vote memory vote, uint256 newOffset);
}

// Ed25519 implementation
contract SimplexVerifierEd25519 is SimplexVerifierBase {
    uint256 constant SIGNATURE_LENGTH = 64;

    function deserializeVote(bytes calldata data, uint256 offset)
        internal override returns (Vote memory vote, uint256 newOffset)
    {
        // Ed25519-specific implementation
    }
}

// BLS12-381 implementation
contract SimplexVerifierBLS12381 is SimplexVerifierBase {
    uint256 constant SIGNATURE_LENGTH = 96;

    function deserializeVote(bytes calldata data, uint256 offset)
        internal override returns (Vote memory vote, uint256 newOffset)
    {
        // BLS12-381-specific implementation
    }
}
```

**Pros:**
- Gas-efficient (uses constants)
- Type-safe (each scheme has correct types)
- Simpler per-scheme logic
- Follows Solidity best practices

**Cons:**
- Multiple deployments
- Code duplication (mitigated by base contract)

### Recommendation

**Use Option B (Separate Contracts)** because:

1. **Gas efficiency matters** - This is a high-frequency verification contract
2. **Simplex instances are homogeneous** - Each Simplex instance uses ONE scheme (not mixed)
3. **Verification differs anyway** - Ed25519 vs BLS12-381 verification are completely different
4. **Type safety** - BLS keys are 48 bytes, not 32 - using wrong length is a bug

**Implementation:** Keep current structure but:
- Rename `SimplexVerifier` → `SimplexVerifierEd25519`
- Create `SimplexVerifierBLS12381` for threshold_simplex
- Extract common code to `SimplexVerifierBase` library

---

## Comment 2: Signature Verification

**Patrick's Comment (Line 71):**
> "Have you given any thought to how we should support signature verification? That being said, the idea of keeping deserialization separate from that seems reasonable."

### Analysis

**Why deserialization is separate:**

1. **Different trust models** - Some use cases only need structure validation, not crypto verification
2. **Verification is expensive** - Ed25519 batch verification is ~5000 gas/signature, BLS is ~100k gas
3. **Verification is scheme-specific** - Ed25519 precompile ≠ BLS pairing checks
4. **Verification may be deferred** - Might verify off-chain or in separate contract

### Signature Verification Strategies

#### For Ed25519

**Option 1: Use existing precompile (if available)**

Some chains have Ed25519 verification precompiles:
```solidity
interface IEd25519Verifier {
    function verify(bytes32 publicKey, bytes memory signature, bytes memory message)
        external view returns (bool);
}

contract SimplexVerifierEd25519WithSig is SimplexVerifierEd25519 {
    IEd25519Verifier immutable verifier;

    constructor(address _verifier) {
        verifier = IEd25519Verifier(_verifier);
    }

    function verifyNotarize(
        bytes calldata proof,
        bytes32 namespace
    ) external view returns (bool) {
        (Proposal memory proposal, Vote memory vote) = deserializeNotarize(proof);

        // Reconstruct message that was signed
        bytes memory message = abi.encodePacked(
            namespace,
            uint8(0), // Notarize discriminator
            proposal.round.epoch,
            proposal.round.view,
            proposal.parent,
            proposal.payload
        );

        // Get public key from validator set
        bytes32 pubkey = getValidatorKey(vote.signer);

        return verifier.verify(pubkey, vote.signature, message);
    }
}
```

**Option 2: Use Solidity library**

Deploy a Solidity Ed25519 verification library (expensive but works everywhere):
```solidity
library Ed25519 {
    function verify(bytes32 publicKey, bytes memory signature, bytes memory message)
        internal view returns (bool);
}
```

#### For BLS12-381

**Requires EIP-2537 precompiles:**

```solidity
contract SimplexVerifierBLS12381WithSig is SimplexVerifierBLS12381 {
    function verifyNotarization(
        bytes calldata proof,
        bytes memory aggregatePublicKey,
        bytes32 namespace
    ) external view returns (bool) {
        (Proposal memory proposal, Vote[] memory votes) =
            deserializeNotarization(proof, maxSigners);

        // Reconstruct signed message
        bytes memory message = encodeNotarizeMessage(namespace, proposal);

        // For multisig: aggregate all signatures
        bytes memory aggregatedSig = aggregateSignatures(votes);

        // Verify using BLS pairing (EIP-2537)
        return BLS12381.verify(aggregatePublicKey, aggregatedSig, message);
    }
}
```

### Recommendation

**Keep deserialization separate** (as Patrick agrees), then:

1. **Create optional verification extensions** as separate contracts:
   - `SimplexVerifierEd25519` (deserialization only)
   - `SimplexVerifierEd25519WithSig` (adds verification)

2. **Document verification requirements** in README

3. **Provide verification examples** for common use cases

**Rationale:**
- Flexibility: Users can plug in their own verification
- Gas optimization: Only pay for verification when needed
- Future-proof: New verification methods (ZK proofs?) can be added
- Modularity: Deserialization is universal, verification is context-specific

---

## Comment 3: Standardized Foundry Setup

**Patrick's Comment (foundry.toml:1):**
> "Hopefully, we can standardize around a Foundry setup (see #357 + #341)"

### Current State

PRs #357 and #341 are restaking PoC work. They likely have a Foundry setup for contract development.

### Recommendations

1. **Wait for restaking PR to merge** - Then align with their foundry.toml structure
2. **Keep minimal config for now** - Current foundry.toml is generic and won't conflict
3. **Use shared remappings** - If restaking has common dependencies

### Proposed Changes

Once #357/#341 merge, update foundry.toml to match:

```toml
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
test = "test"

# Match restaking settings
solc = "<same version>"
optimizer = true
optimizer_runs = <same value>

# Shared remappings (if any)
remappings = [
    "@openzeppelin/=lib/openzeppelin-contracts/",
    # ... other shared remappings
]
```

**For now:** Keep current minimal config, coordinate with restaking team after merge.

---

## Summary of Recommended Changes

### Immediate (Address Patrick's feedback):

1. ✅ **Keep deserialization separate from verification**
   - Add documentation on how to add verification
   - Provide verification examples in README

2. ✅ **Scheme configuration approach**
   - Rename to `SimplexVerifierEd25519` (makes scheme explicit)
   - Document extension path for BLS12-381
   - Keep constants (gas-efficient)

3. ⏳ **Foundry setup**
   - Wait for restaking PRs to merge
   - Coordinate on standard configuration
   - Update foundry.toml to match

### Future (After restaking PRs merge):

4. 📋 **Add BLS12-381 verifier** for threshold_simplex
5. 📋 **Create verification extension contracts** (optional)
6. 📋 **Align with restaking Foundry structure**

---

## Updated Implementation Plan

Based on Patrick's feedback, here's the updated structure:

```
contracts/
├── src/
│   ├── SimplexVerifierBase.sol          # Common deserialization logic
│   ├── SimplexVerifierEd25519.sol       # Ed25519 implementation
│   ├── SimplexVerifierBLS12381.sol      # BLS12-381 (future)
│   └── extensions/                       # Optional verification
│       ├── SimplexVerifierEd25519WithSig.sol
│       └── SimplexVerifierBLS12381WithSig.sol
├── test/
│   ├── SimplexVerifierEd25519.t.sol
│   └── SimplexVerifierBLS12381.t.sol
└── README.md                             # Updated with verification guide
```

This addresses all three of Patrick's concerns while maintaining gas efficiency and flexibility.
