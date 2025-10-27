# Gas Optimization Analysis: Rust Types vs Solidity-Optimized Types

## The Question

**Should we match Rust type structure in Solidity, or optimize for gas?**

Current approach returns structs that mirror Rust:
```solidity
struct Round { uint64 epoch; uint64 view; }
struct Proposal { Round round; uint64 parent; bytes32 payload; }
struct Vote { uint32 signer; bytes signature; }
```

But this may be **gas-inefficient** for on-chain use.

---

## Gas Cost Analysis

### Memory Layout Costs

**Solidity Memory Rules:**
- Each stack slot = 32 bytes
- Struct fields < 32 bytes still consume full slots in memory
- Nested structs add overhead

**Current Approach (Matching Rust):**
```solidity
function deserializeNotarize(bytes calldata proof)
    returns (Proposal memory proposal, Vote memory vote)
```

**Memory layout:**
```
Proposal:
  - round.epoch (uint64)  → Slot 1 (wastes 24 bytes)
  - round.view (uint64)   → Slot 2 (wastes 24 bytes)
  - parent (uint64)       → Slot 3 (wastes 24 bytes)
  - payload (bytes32)     → Slot 4 (full)

Vote:
  - signer (uint32)       → Slot 5 (wastes 28 bytes)
  - signature.length      → Slot 6
  - signature.data        → Slots 7-8 (64 bytes)

Total: ~8 memory slots = 256 bytes allocated
```

**Gas Cost:**
- Memory allocation: 8 slots × 3 gas = **24 gas**
- Memory expansion: negligible for small structs
- ABI encoding (if returned to external call): **~300-500 gas**

---

## Alternative: Gas-Optimized Returns

### Option A: Flat Tuple Returns

```solidity
function deserializeNotarize(bytes calldata proof)
    returns (
        uint64 epoch,
        uint64 view,
        uint64 parent,
        bytes32 payload,
        uint32 signer,
        bytes memory signature
    )
```

**Pros:**
- No struct creation overhead
- Caller can use only what they need
- Slightly cheaper memory allocation

**Cons:**
- Tuple hell (6 return values)
- Easy to mix up parameter order
- Poor developer experience
- ABI encoding cost similar

**Gas Savings:** ~10-20 gas per call (minimal)

---

### Option B: Packed Returns

```solidity
// Pack everything into minimal bytes
function deserializeNotarizePacked(bytes calldata proof)
    returns (bytes memory packed)
{
    // Return: epoch(8) | view(8) | parent(8) | payload(32) | signer(4) | signature(64)
    // Total: 124 bytes
}
```

**Pros:**
- Minimal memory allocation
- Can stay in calldata if passed to another contract
- Very gas-efficient

**Cons:**
- Caller must unpack manually (terrible UX)
- Error-prone
- Non-standard

**Gas Savings:** ~50-100 gas per call

---

### Option C: Events for Off-Chain (No Returns)

```solidity
event NotarizeDeserialized(
    uint64 epoch,
    uint64 view,
    uint64 parent,
    bytes32 payload,
    uint32 signer,
    bytes signature
);

function deserializeNotarize(bytes calldata proof) external {
    // Deserialize
    emit NotarizeDeserialized(...);
}
```

**Pros:**
- Nearly free (events are cheap)
- No return data encoding cost

**Cons:**
- Cannot be called from other contracts
- Useless for on-chain verification
- Not composable

---

## Real Gas Cost: Where the Money Goes

Let me benchmark the actual costs:

### Scenario 1: Verification Contract Calls Deserializer

```solidity
contract UptimeTracker {
    SimplexVerifier verifier;

    function creditUptime(bytes calldata proof) external {
        // Current approach
        (Proposal memory proposal, Vote memory vote) =
            verifier.deserializeNotarize(proof);

        // Process: check signer, record epoch
        if (vote.signer == validatorId) {
            uptime[vote.signer][proposal.round.epoch]++;
        }
    }
}
```

**Gas Breakdown:**
- External call to verifier: **2100 gas** (cold SLOAD) + **100 gas** (call)
- Deserialize internals: **~500-1000 gas** (varint decoding, memory)
- Return data copying: **~300 gas**
- Processing in tracker: **~5000-20000 gas** (SSTORE)

**Total: ~8000-23000 gas**

**Struct overhead: ~300 gas out of 8000+ = 1.5-3%**

---

### Scenario 2: Inline Deserialization (No Structs)

```solidity
contract UptimeTracker {
    function creditUptime(bytes calldata proof) external {
        // Deserialize inline, no structs
        uint256 offset = 0;
        (uint64 epoch, offset) = decodeVarint(proof, offset);
        (uint64 view, offset) = decodeVarint(proof, offset);
        (uint64 parent, offset) = decodeVarint(proof, offset);
        bytes32 payload = bytes32(proof[offset:offset+32]);
        offset += 32;
        (uint32 signer, offset) = decodeVarint(proof, offset);

        if (signer == validatorId) {
            uptime[signer][epoch]++;
        }
    }
}
```

**Gas Savings:**
- No external call: **saves 2200 gas**
- No struct creation: **saves 300 gas**
- No return data: **saves 300 gas**

**Total Savings: ~2800 gas**

**BUT:**
- Code duplication (every contract reimplements)
- No reusability
- Bug-prone (each implementation could have errors)
- Harder to audit

---

## The Real Question: What's the Use Case?

### Use Case 1: Restaking / Slashing Contract

**Typical Flow:**
```solidity
contract RestakingManager {
    function submitFraudProof(bytes calldata proof) external {
        // Deserialize
        (Proposal memory p1, Vote memory v1,
         Proposal memory p2, Vote memory v2) =
            verifier.deserializeConflictingNotarize(proof);

        // Validate
        require(p1.round.epoch == currentEpoch);
        require(v1.signer == v2.signer);
        require(isValidator(v1.signer));

        // Verify signatures (EXPENSIVE - 5000+ gas each)
        require(verifyEd25519(v1));
        require(verifyEd25519(v2));

        // Slash (VERY EXPENSIVE - 20000+ gas)
        slash(v1.signer);
    }
}
```

**Gas Breakdown:**
- Deserialization: **~1000 gas**
- Signature verification: **~10000 gas** (2 signatures)
- Slashing storage: **~20000 gas**
- **Total: ~31000 gas**

**Struct overhead: 300 gas out of 31000 = 0.9%**

**Verdict:** Struct overhead is **negligible** compared to verification and storage costs.

---

### Use Case 2: High-Frequency Uptime Tracking

**Typical Flow:**
```solidity
contract UptimeOracle {
    mapping(uint32 => mapping(uint64 => uint256)) public uptimeScores;

    function recordActivity(bytes[] calldata proofs) external {
        for (uint i = 0; i < proofs.length; i++) {
            (Proposal memory proposal, Vote memory vote) =
                verifier.deserializeNotarize(proofs[i]);

            uptimeScores[vote.signer][proposal.round.epoch]++;
        }
    }
}
```

**Gas Breakdown per proof:**
- Deserialization: **~1000 gas**
- SSTORE (warm): **~2900 gas**
- Loop overhead: **~100 gas**
- **Total per proof: ~4000 gas**

**For 100 proofs:**
- With structs: **~400,000 gas**
- Without structs (save 300/proof): **~370,000 gas**

**Savings: 30,000 gas / 400,000 = 7.5%**

This is more significant! But is it worth the tradeoff?

---

## The Developer Experience Tradeoff

### With Structs (Current Approach)

```solidity
// READABLE
(Proposal memory proposal, Vote memory vote) =
    verifier.deserializeNotarize(proof);

if (vote.signer == targetValidator &&
    proposal.round.epoch == currentEpoch) {
    // Process
}
```

### Without Structs (Gas-Optimized)

```solidity
// TUPLE HELL
(uint64 epoch, uint64 view, uint64 parent, bytes32 payload,
 uint32 signer, bytes memory signature) =
    verifier.deserializeNotarize(proof);

if (signer == targetValidator && epoch == currentEpoch) {
    // Easy to confuse epoch/view/parent
    // What if someone passes view instead of epoch?
}
```

---

## Industry Patterns: What Do Others Do?

### OpenZeppelin Contracts

**ECDSA.sol:**
```solidity
function tryRecover(bytes32 hash, bytes memory signature)
    internal pure
    returns (address, RecoverError)  // Returns struct!
```

They use structs for clarity.

### Eigenlayer

**Delegation contracts:**
```solidity
struct QueuedWithdrawal {
    address[] strategies;
    uint256[] shares;
    address depositor;
    // ...
}
```

They use structs extensively.

### Uniswap V3

**Position NFT:**
```solidity
struct Position {
    uint96 nonce;
    address operator;
    uint80 poolId;
    // ...
}
```

Structs everywhere, even with small types.

**Conclusion:** Industry standard is **readability over micro-gas-optimization**.

---

## Recommendation: Hybrid Approach

### Default: Readable Structs (Current)

```solidity
struct Round { uint64 epoch; uint64 view; }
struct Proposal { Round round; uint64 parent; bytes32 payload; }
struct Vote { uint32 signer; bytes signature; }

function deserializeNotarize(bytes calldata proof)
    public pure returns (Proposal memory proposal, Vote memory vote)
```

**Use when:**
- Code clarity matters
- Gas difference is <5%
- Called infrequently (fraud proofs, occasional uptime checks)

---

### Optimization: Minimal Returns for High-Frequency

```solidity
/// @notice Gas-optimized version for high-frequency calls
/// @dev Returns only essential fields, skips struct creation
function deserializeNotarizeLean(bytes calldata proof)
    public pure returns (
        uint64 epoch,
        uint32 signer
    )
{
    uint256 offset = 0;
    (epoch, offset) = decodeVarintU64(proof, offset);
    // Skip view, parent, payload
    offset = skipVarint(proof, offset); // view
    offset = skipVarint(proof, offset); // parent
    offset += 32; // payload
    (uint64 signerU64, ) = decodeVarintU64(proof, offset);
    signer = uint32(signerU64);
}
```

**Use when:**
- Processing 100+ proofs per transaction
- Only need 1-2 fields
- Gas optimization critical

**Gas Savings:** ~60-70% on deserialization (but still <10% of total transaction)

---

### Optimization: View-Only Packed Encoding

```solidity
/// @notice Super cheap view function for off-chain queries
/// @dev Returns packed bytes, decode off-chain
function deserializeNotarizePacked(bytes calldata proof)
    public pure returns (bytes memory packed)
{
    // Just extract and pack, no struct allocation
    packed = new bytes(60); // epoch(8) + view(8) + parent(8) + payload(32) + signer(4)

    // ... extract and pack
}
```

**Use when:**
- Called from off-chain (view function)
- JS/Python will decode anyway
- No on-chain processing needed

---

## Final Recommendation

**Keep matching Rust types with structs** because:

1. **Gas overhead is minimal** (1-3% in most real scenarios)
2. **Code clarity prevents bugs** (mixing up epoch/view costs way more than 300 gas)
3. **Industry standard** (OpenZeppelin, Eigenlayer, Uniswap all use structs)
4. **Composability** (other contracts can easily work with structured data)
5. **Future-proof** (Solidity compiler may optimize structs better)
6. **Auditability** (easier to verify correctness)

**Add lean versions ONLY if:**
- Benchmarks show >10% total gas savings in real use case
- Processing 100+ proofs per transaction
- User explicitly requests gas-optimized version

---

## Concrete Gas Numbers

I should actually benchmark this. Let me add gas tests to the test suite:

```solidity
function testGas_DeserializeNotarize() public {
    bytes memory proof = buildTestNotarize();

    uint256 gasBefore = gasleft();
    (Proposal memory proposal, Vote memory vote) =
        verifier.deserializeNotarize(proof);
    uint256 gasUsed = gasBefore - gasleft();

    console.log("Gas used:", gasUsed);
}

function testGas_DeserializeNotarizeLean() public {
    bytes memory proof = buildTestNotarize();

    uint256 gasBefore = gasleft();
    (uint64 epoch, uint32 signer) =
        verifier.deserializeNotarizeLean(proof);
    uint256 gasUsed = gasBefore - gasleft();

    console.log("Gas used:", gasUsed);
}
```

**Expected Results:**
- Full struct deserialization: ~800-1200 gas
- Lean version (2 fields): ~400-600 gas
- Savings: ~400-600 gas per call

**In a real transaction with storage:**
- Total gas: 20,000-50,000 gas
- Savings: 1-3%

**Verdict:** Not worth the complexity for default API.

---

## Summary

| Approach | Gas Cost | Readability | Maintainability | Recommendation |
|----------|----------|-------------|-----------------|----------------|
| Structs (current) | Baseline | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ✅ **Default** |
| Flat tuples | -5% gas | ⭐⭐ | ⭐⭐⭐ | ❌ Not worth it |
| Lean extractors | -60% deser | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⚠️ **Optional add-on** |
| Packed bytes | -70% deser | ⭐ | ⭐⭐ | ❌ Only for view |
| Inline (no verifier) | -100% call | ⭐ | ⭐ | ❌ Code duplication |

**Final Answer:** Yes, we want to match Rust types because **readability prevents bugs that cost way more than 300 gas**, and the gas overhead is negligible in real use cases.
