# Simplex Verifier Usage Guide

## Architecture Overview

```
SimplexVerifierBase (abstract)
├── SimplexVerifierEd25519 (attributable)
└── SimplexVerifierBLS12381Threshold (non-attributable, compact)
```

## Flow Diagrams

### 1. Deployment Flow

```
┌─────────────────────────────────────────────────────┐
│  Step 1: Choose Your Signing Scheme                │
│                                                     │
│  Ed25519?          → Deploy SimplexVerifierEd25519 │
│  BLS Threshold?    → Deploy BLS12381Threshold      │
└─────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────┐
│  Step 2: Deploy Contract                           │
│                                                     │
│  const verifier = await deploy("SimplexVerifier[SCHEME]")
│                                                     │
│  No constructor args needed - stateless verifiers  │
└─────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────┐
│  Step 3: Store Verifier Address                    │
│                                                     │
│  bridge.setVerifier(verifierAddress);              │
│  or use as library for proof validation           │
└─────────────────────────────────────────────────────┘
```

### 2. Certificate Verification Flow (Ed25519)

```
Off-chain (Rust)                    On-chain (Solidity)
─────────────────────               ───────────────────

Consensus reaches quorum
       ↓
Collect 2f+1 votes
       ↓
Serialize Notarization:
  - Proposal (48+ bytes)
  - Vote count (varint)
  - Votes array:
    * vote[0]: signer=5, sig[64]
    * vote[1]: signer=12, sig[64]
    * ...
       ↓
bytes proof = serialize()
       ↓                                    ↓
Submit tx ──────────────────────→  verifier.deserializeNotarization(proof, maxSigners)
                                           ↓
                                    Parse proof:
                                      - Extract proposal
                                      - Extract vote count (validate ≤ maxSigners)
                                      - Loop: deserialize each vote
                                           ↓
                                    Return (Proposal, Vote[])
                                           ↓
                                    Application validates:
                                      - votes.length >= quorum
                                      - No duplicate signers
                                      - Call signature verification (Ed25519 precompile)
                                      - Store proposal.payload if valid
```

### 3. Certificate Verification Flow (BLS Threshold)

```
Off-chain (Rust)                    On-chain (Solidity)
─────────────────────               ───────────────────

Consensus reaches quorum
       ↓
Collect 2f+1 partial signatures
       ↓
RECOVER aggregate signatures:
  - vote_sig = aggregate(partials)
  - seed_sig = aggregate(partials)
       ↓
Serialize Notarization:
  - Proposal (48+ bytes)
  - vote_sig (96 bytes)              ← ONLY 192 BYTES!
  - seed_sig (96 bytes)              ← No individual votes!
       ↓
bytes proof = serialize()
       ↓                                    ↓
Submit tx ──────────────────────→  verifier.deserializeNotarizationMinPk(proof)
                                           ↓
                                    Parse proof:
                                      - Extract proposal (48+ bytes)
                                      - Extract vote_sig (96 bytes)
                                      - Extract seed_sig (96 bytes)
                                           ↓
                                    Return (Proposal, ThresholdCertificate)
                                           ↓
                                    Application validates:
                                      - Single pairing check (200k gas)
                                      - Store proposal.payload if valid
```

### 4. Fraud Proof Flow (Conflicting Notarize)

```
Off-chain Detection                 On-chain Slashing
───────────────────                 ─────────────────

Detect Byzantine behavior:
  Validator 5 signed:
    - Proposal A at (epoch=10, view=5)
    - Proposal B at (epoch=10, view=5)  ← CONFLICT!
       ↓
Collect evidence:
  - notarize1 = (proposalA, voteA)
  - notarize2 = (proposalB, voteB)
       ↓
Serialize ConflictingNotarize:
  - proposalA + voteA
  - proposalB + voteB
       ↓                                    ↓
Submit slashing tx ─────────────→  verifier.deserializeConflictingNotarize(proof)
                                           ↓
                                    Validates:
                                      ✓ proposal1.round == proposal2.round
                                      ✓ vote1.signer == vote2.signer
                                      ✓ proposal1 != proposal2
                                           ↓
                                    If valid → Slash validator 5
```

## Usage Examples

### Example 1: Bridge Contract (Ed25519)

```solidity
// Bridge.sol
import "./SimplexVerifierEd25519.sol";

contract Bridge {
    SimplexVerifierEd25519 public verifier;
    mapping(uint64 => bytes32) public finalizedPayloads; // epoch → payload hash
    uint32 public constant MAX_VALIDATORS = 1000;
    uint32 public constant QUORUM = 667; // 2/3 + 1 of 1000

    constructor(address verifierAddress) {
        verifier = SimplexVerifierEd25519(verifierAddress);
    }

    /// @notice Submit a finalization certificate to bridge payload
    function submitFinalization(bytes calldata proof) external {
        // 1. Deserialize the certificate
        (
            SimplexVerifierBase.Proposal memory proposal,
            SimplexVerifierEd25519.Vote[] memory votes
        ) = verifier.deserializeFinalization(proof, MAX_VALIDATORS);

        // 2. Validate quorum reached
        require(votes.length >= QUORUM, "Insufficient votes");

        // 3. Validate no duplicate signers
        for (uint i = 0; i < votes.length; i++) {
            for (uint j = i + 1; j < votes.length; j++) {
                require(votes[i].signer != votes[j].signer, "Duplicate signer");
            }
        }

        // 4. Verify signatures (using Ed25519 precompile or custom verifier)
        bytes32 message = keccak256(abi.encode(proposal));
        for (uint i = 0; i < votes.length; i++) {
            require(
                verifyEd25519(
                    validatorKeys[votes[i].signer],
                    message,
                    votes[i].signature
                ),
                "Invalid signature"
            );
        }

        // 5. Store finalized payload
        finalizedPayloads[proposal.round.epoch] = proposal.payload;

        emit PayloadFinalized(proposal.round.epoch, proposal.payload);
    }

    function verifyEd25519(bytes memory pubkey, bytes32 msg, bytes memory sig)
        internal view returns (bool)
    {
        // Use Ed25519 precompile or custom verification
        // Precompile not yet available on mainnet, use library
    }
}
```

### Example 2: Bridge Contract (BLS Threshold) - CHEAPER!

```solidity
// BridgeThreshold.sol
import "./SimplexVerifierBLS12381Threshold.sol";

contract BridgeThreshold {
    SimplexVerifierBLS12381Threshold public verifier;
    mapping(uint64 => bytes32) public finalizedPayloads;
    bytes public aggregatePublicKey; // Single BLS public key for committee

    constructor(address verifierAddress, bytes memory _aggregatePublicKey) {
        verifier = SimplexVerifierBLS12381Threshold(verifierAddress);
        aggregatePublicKey = _aggregatePublicKey;
    }

    /// @notice Submit a finalization certificate (only 192 bytes!)
    function submitFinalization(bytes calldata proof) external {
        // 1. Deserialize the certificate
        (
            SimplexVerifierBase.Proposal memory proposal,
            SimplexVerifierBLS12381Threshold.ThresholdCertificate memory cert
        ) = verifier.deserializeFinalizationMinPk(proof);

        // 2. Verify threshold signature (single pairing check!)
        bytes memory message = abi.encode(proposal);
        require(
            verifyBLSThreshold(
                aggregatePublicKey,
                message,
                cert.voteSignature
            ),
            "Invalid certificate"
        );

        // 3. Store finalized payload
        finalizedPayloads[proposal.round.epoch] = proposal.payload;

        emit PayloadFinalized(proposal.round.epoch, proposal.payload);
    }

    function verifyBLSThreshold(bytes memory pubkey, bytes memory msg, bytes memory sig)
        internal view returns (bool)
    {
        // Use BLS12-381 precompile (EIP-2537) or custom pairing check
        // Single pairing: e(sig, G2) == e(H(msg), pubkey)
    }
}
```

### Example 3: Slashing Contract (Fraud Proofs)

```solidity
// Slashing.sol
import "./SimplexVerifierEd25519.sol";

contract Slashing {
    SimplexVerifierEd25519 public verifier;
    mapping(uint32 => bool) public slashedValidators;

    constructor(address verifierAddress) {
        verifier = SimplexVerifierEd25519(verifierAddress);
    }

    /// @notice Submit fraud proof for double-signing
    function slashConflictingNotarize(bytes calldata proof) external {
        // Deserialize the fraud proof
        (
            SimplexVerifierBase.Proposal memory proposal1,
            SimplexVerifierEd25519.Vote memory vote1,
            SimplexVerifierBase.Proposal memory proposal2,
            SimplexVerifierEd25519.Vote memory vote2
        ) = verifier.deserializeConflictingNotarize(proof);

        // Validation already done by verifier:
        // - Same round
        // - Same signer
        // - Different proposals

        // Verify signatures
        bytes32 msg1 = keccak256(abi.encode(proposal1));
        bytes32 msg2 = keccak256(abi.encode(proposal2));
        require(verifyEd25519(validatorKeys[vote1.signer], msg1, vote1.signature));
        require(verifyEd25519(validatorKeys[vote2.signer], msg2, vote2.signature));

        // Slash the validator
        slashedValidators[vote1.signer] = true;

        emit ValidatorSlashed(vote1.signer, "ConflictingNotarize");
    }

    /// @notice Submit fraud proof for nullify-finalize conflict
    function slashNullifyFinalize(bytes calldata proof) external {
        (
            SimplexVerifierBase.Round memory nullifyRound,
            SimplexVerifierEd25519.Vote memory nullifyVote,
            SimplexVerifierBase.Proposal memory finalizeProposal,
            SimplexVerifierEd25519.Vote memory finalizeVote
        ) = verifier.deserializeNullifyFinalize(proof);

        // Validator voted to BOTH skip AND finalize same round!
        // This is Byzantine behavior

        slashedValidators[nullifyVote.signer] = true;
        emit ValidatorSlashed(nullifyVote.signer, "NullifyFinalize");
    }
}
```

### Example 4: Light Client (Dual Support)

```solidity
// LightClient.sol
import "./SimplexVerifierBase.sol";
import "./SimplexVerifierEd25519.sol";
import "./SimplexVerifierBLS12381Threshold.sol";

contract LightClient {
    enum SchemeType { Ed25519, BLSThreshold }

    SchemeType public scheme;
    SimplexVerifierEd25519 public ed25519Verifier;
    SimplexVerifierBLS12381Threshold public blsVerifier;

    constructor(
        SchemeType _scheme,
        address _verifierAddress
    ) {
        scheme = _scheme;
        if (_scheme == SchemeType.Ed25519) {
            ed25519Verifier = SimplexVerifierEd25519(_verifierAddress);
        } else {
            blsVerifier = SimplexVerifierBLS12381Threshold(_verifierAddress);
        }
    }

    function verifyFinalization(bytes calldata proof) external view returns (bytes32) {
        if (scheme == SchemeType.Ed25519) {
            (
                SimplexVerifierBase.Proposal memory proposal,
                SimplexVerifierEd25519.Vote[] memory votes
            ) = ed25519Verifier.deserializeFinalization(proof, 1000);

            // Verify signatures...
            return proposal.payload;

        } else {
            (
                SimplexVerifierBase.Proposal memory proposal,
                SimplexVerifierBLS12381Threshold.ThresholdCertificate memory cert
            ) = blsVerifier.deserializeFinalizationMinPk(proof);

            // Verify threshold signature...
            return proposal.payload;
        }
    }
}
```

## Deployment Steps

### 1. Deploy Verifiers

```javascript
// deploy.js
const { ethers } = require("hardhat");

async function main() {
    // Deploy base contracts (abstract, no deployment needed)

    // Deploy Ed25519 verifier
    const Ed25519Verifier = await ethers.getContractFactory("SimplexVerifierEd25519");
    const ed25519 = await Ed25519Verifier.deploy();
    await ed25519.deployed();
    console.log("Ed25519 Verifier:", ed25519.address);

    // Deploy BLS Threshold verifier
    const BLSVerifier = await ethers.getContractFactory("SimplexVerifierBLS12381Threshold");
    const bls = await BLSVerifier.deploy();
    await bls.deployed();
    console.log("BLS Threshold Verifier:", bls.address);

    return { ed25519: ed25519.address, bls: bls.address };
}
```

### 2. Deploy Application

```javascript
async function deployBridge(verifierAddress) {
    const Bridge = await ethers.getContractFactory("Bridge");
    const bridge = await Bridge.deploy(verifierAddress);
    await bridge.deployed();
    console.log("Bridge deployed:", bridge.address);
    return bridge;
}
```

### 3. Generate Proofs (Rust)

```rust
// Generate Ed25519 finalization proof
use commonware_consensus::simplex::types::Finalization;
use commonware_codec::Encode;

let finalization: Finalization<Ed25519Scheme, Sha256> = /* ... from consensus */;
let proof_bytes = finalization.encode();

// Submit to Ethereum
web3.eth.sendTransaction({
    to: bridge_address,
    data: encode_call("submitFinalization", [proof_bytes])
});
```

```rust
// Generate BLS Threshold finalization proof (much smaller!)
use commonware_consensus::simplex::types::Finalization;
use commonware_consensus::simplex::signing_scheme::bls12381_threshold::Scheme;

let finalization: Finalization<Scheme<MinPk>, Sha256> = /* ... from consensus */;
let proof_bytes = finalization.encode(); // Only 192 bytes for certificate!

// Much cheaper to submit on-chain
web3.eth.sendTransaction({
    to: bridge_address,
    data: encode_call("submitFinalization", [proof_bytes])
});
```

## Gas Cost Comparison

### Certificate Size (100 validators, 67 quorum)

| Scheme | Individual Vote | Certificate Size | Gas to Submit |
|--------|----------------|------------------|---------------|
| Ed25519 | 68 bytes | ~4,600 bytes | ~200k gas (calldata) |
| BLS Threshold | 196 bytes | **192 bytes** | ~15k gas (calldata) |

### Verification Cost

| Scheme | Operation | Gas Cost |
|--------|-----------|----------|
| Ed25519 | 67 signature checks | ~200k gas |
| BLS Threshold | 1 pairing check | ~200k gas |
| **Break-even point** | **~3-4 validators** | |

### Total Cost (100 validators)

| Scheme | Calldata Gas | Verification Gas | Total |
|--------|--------------|------------------|-------|
| Ed25519 | ~200k | ~200k | **~400k gas** |
| BLS Threshold | ~15k | ~200k | **~215k gas** |

**BLS Threshold saves ~46% gas for large validator sets!**

## When to Use Each Scheme

### Use Ed25519 When:
- Need attributable fraud proofs (per-validator evidence)
- Small validator sets (< 10 validators)
- Ed25519 precompile available (cheaper verification)
- Simplicity preferred over gas optimization

### Use BLS Threshold When:
- Large validator sets (> 10 validators)
- Gas costs critical (L1 Ethereum)
- Compact certificates needed (data availability)
- Don't need attributable fraud proofs
- BLS12-381 precompiles available (EIP-2537)

## Summary

The abstraction allows you to:

1. **Share common logic** (Round, Proposal deserialization) in base contract
2. **Choose scheme at deployment** based on your needs
3. **Swap schemes easily** by deploying different verifier
4. **No runtime overhead** - all signature sizes are compile-time constants
5. **Optimize for your use case** - attributability vs gas costs

The key architectural decision is **wire format compatibility** - the verifiers just parse bytes from Rust consensus, they don't perform cryptographic verification (you add that in your application layer).
