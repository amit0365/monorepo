# Solidity Comment Style Guide

This document defines the minimal comment style used in this codebase.

## Philosophy

**Less is more.** Comments should be minimal, focusing on what code cannot express. Let function names, types, and signatures convey intent. Only document what is essential and non-obvious.

## Core Principles

1. **No NatSpec tags** - Avoid `@title`, `@notice`, `@dev`, `@param`, `@return`, etc.
2. **Format over behavior** - Document wire formats and data structures, not implementation logic
3. **Self-documenting code** - Clear naming eliminates need for most comments
4. **No section dividers** - No decorative headers like `// ============ Section ============`
5. **Minimal inline comments** - Remove comments that restate what code does

## Comment Syntax

### Triple Slash with Double Space
Always use three slashes followed by exactly two spaces:

```solidity
///  This is a comment
```

**Not:**
```solidity
/// This is wrong (one space)
////  This is wrong (four slashes)
//  This is wrong (two slashes)
```

### Multi-line Continuation
For multi-line comments, use the same prefix with triple space on continuation lines:

```solidity
///  First line of comment
///   Continuation line (note the extra space for indentation)
```

## Contract-Level Comments

### Libraries
Single line describing the purpose:

```solidity
///  Digest length constants (all 32 bytes)
library DigestLengths {
    uint256 constant SHA256 = 32;
    uint256 constant BLAKE3 = 32;
}
```

### Contracts
Single line describing the contract's role:

```solidity
///  Base contract for Simplex consensus proof verification
abstract contract SimplexVerifierBase {
    // ...
}
```

### Interfaces
Single line describing what the interface represents:

```solidity
///  Interface for signature schemes (Ed25519, BLS, etc)
interface ISignatureScheme {
    // ...
}
```

For interfaces with additional context, use two lines:

```solidity
///  Interface for multisignature schemes with key aggregation support
///  Bitmaps are used to indicate which participants signed a message.
interface IMultisigScheme is ISignatureScheme {
    // ...
}
```

## Function-Level Comments

### When to Comment

**DO comment:**
- Functions with complex binary format specifications
- Functions with non-obvious data layouts
- Constructor parameters (inline, without `@param`)

**DON'T comment:**
- Simple getter/setter functions
- Functions with self-explanatory names
- Implementation details that are clear from code
- Return values (type signature is sufficient)

### Format Specifications

Document binary formats and data structures:

```solidity
///  Format: bitmap + signature_count (varint) + signatures
function deserializeBitmapAndSignatures(...) { }

///  Format: epoch (8 bytes) + view (8 bytes)
function extractRoundBytes(...) { }

///  Format: round (16 bytes) + parent (varint) + payload (digest_length bytes)
function extractProposalBytes(...) { }

///  Format: signer (4 bytes) + signature
function deserializeSignerAndSignature(...) { }

///  Format: varint(namespace_len) + namespace + message
function encodeSignedMessage(...) { }
```

### Constructor Parameters

Document constructor parameters inline without tags:

```solidity
///  _keyStore Keystore managing validator keys and signature scheme
///  _digestLength Payload digest length in bytes
constructor(
    IKeyStore _keyStore,
    uint256 _digestLength
) {
    KEY_STORE = _keyStore;
    DIGEST_LENGTH = _digestLength;
}
```

### Delegation Functions

Comment when function behavior differs from what name suggests:

```solidity
///  Deserialize Finalize message (same format as Notarize)
function deserializeFinalize(bytes calldata proof) { }

///  Deserialize ConflictingFinalize fraud proof (same format as ConflictingNotarize)
function deserializeConflictingFinalize(bytes calldata proof) { }
```

### No Comments Needed

Simple, self-explanatory functions:

```solidity
function scheme() external view returns (ISignatureScheme) {
    return SCHEME;
}

function publicKeyLength() external pure returns (uint256) {
    return ED25519_PUBLIC_KEY_LENGTH;
}

function getParticipantCount() external view returns (uint256) {
    return participants.length;
}
```

## State Variables

### Immutable Configuration
No comments needed when name is clear:

```solidity
IKeyStore public immutable KEY_STORE;
uint256 public immutable DIGEST_LENGTH;
ISignatureScheme public immutable SCHEME;
```

### Constants
No comments for obvious constants:

```solidity
uint256 private constant ED25519_PUBLIC_KEY_LENGTH = 32;
uint256 private constant ED25519_SIGNATURE_LENGTH = 64;
```

## Inline Comments

### Allowed Cases

**Compiler directives:**
```solidity
// forge-lint: disable-next-line(unsafe-typecast)
uint8 dataBits = uint8(value & DATA_BITS_MASK);
```

**Critical safety notes (rare):**
Only when absolutely necessary for understanding correctness.

### Remove These

**Restating code:**
```solidity
// BAD: Comment just repeats what code does
offset += 16; // Skip round (16 bytes)

// GOOD: No comment needed
offset += 16;
```

**Obvious operations:**
```solidity
// BAD: Unnecessary explanation
delete participants; // Clear existing participants

// GOOD: Code is self-explanatory
delete participants;
```

## Events and Errors

No comments needed:

```solidity
event ParticipantsUpdated(uint256 count);

error TooManySigners();
error InvalidProofLength();
error InvalidBitmapTrailingBits();
error Conflicting_EpochMismatch();
```

## Interface Methods

No per-method documentation in interfaces:

```solidity
interface IKeyStore {
    event ParticipantsUpdated(uint256 count);

    function scheme() external view returns (ISignatureScheme);
    function getParticipant(uint256 index) external view returns (bytes memory);
    function getParticipantCount() external view returns (uint256);
    function setParticipants(bytes[] calldata keys) external;
}
```

## Examples

### Before (Verbose)
```solidity
/// @title SimplexVerifierBase
/// @notice Abstract base contract for Simplex consensus proof verification
/// @dev Provides shared deserialization logic for extracting raw bytes from proofs
/// @dev Concrete implementations handle scheme-specific signature formats
abstract contract SimplexVerifierBase {
    // ============ Errors ============

    error InvalidProofLength();

    // ============ Deserialization Helpers ============

    /// @notice Extract round bytes from proof
    /// @dev Round format: epoch (8 bytes) + view (8 bytes) = 16 bytes total
    /// @param data The proof calldata
    /// @param offset Starting position
    /// @return roundBytes The raw round bytes (16 bytes)
    /// @return newOffset Updated offset after reading
    function extractRoundBytes(bytes calldata data, uint256 offset)
        internal pure returns (bytes calldata roundBytes, uint256 newOffset)
    {
        if (offset + 16 > data.length) revert InvalidProofLength();
        return (data[offset:offset+16], offset + 16);
    }
}
```

### After (Minimal)
```solidity
///  Base contract for Simplex consensus proof verification
abstract contract SimplexVerifierBase {

    error InvalidProofLength();

    ///  Format: epoch (8 bytes) + view (8 bytes)
    function extractRoundBytes(bytes calldata data, uint256 offset)
        internal pure returns (bytes calldata roundBytes, uint256 newOffset)
    {
        if (offset + 16 > data.length) revert InvalidProofLength();
        return (data[offset:offset+16], offset + 16);
    }
}
```

## Exceptions

These are the only acceptable uses of more verbose commenting:

1. **Complex algorithms** - If implementing a novel or non-obvious algorithm
2. **Security-critical code** - When safety invariants need explanation
3. **External requirements** - When matching external specifications exactly

Even in these cases, prefer concise explanations over verbose documentation.

## Migration Checklist

When updating existing code:

- [ ] Remove all NatSpec tags (`@title`, `@notice`, `@dev`, `@param`, `@return`)
- [ ] Remove section divider comments
- [ ] Remove inline comments that restate code
- [ ] Add format comments only for complex binary structures
- [ ] Ensure triple slash + double space syntax
- [ ] Remove function-level comments for simple/obvious functions
- [ ] Keep only essential, non-obvious information

## Anti-Patterns to Avoid

❌ **Over-documentation**
```solidity
/// @notice Get a participant's public key by index
/// @param index The participant index
/// @return The public key bytes
function getParticipant(uint256 index) external view returns (bytes memory);
```

✅ **Correct - no comment needed**
```solidity
function getParticipant(uint256 index) external view returns (bytes memory);
```

---

❌ **Redundant inline comments**
```solidity
offset += 8;  // Skip 8 bytes
value >>= DATA_BITS_PER_BYTE;  // Shift right by 7 bits
```

✅ **Correct - let code speak**
```solidity
offset += 8;
value >>= DATA_BITS_PER_BYTE;
```

---

❌ **Section dividers**
```solidity
// ============ State Variables ============
bytes[] public participants;

// ============ Constructor ============
constructor() { }
```

✅ **Correct - no dividers**
```solidity
bytes[] public participants;

constructor() { }
```

## Summary

**Write code that needs no comments. When comments are necessary, make them minimal and focus on what cannot be expressed in code (formats, invariants, non-obvious relationships).**
