# Simplex Consensus Serialization Format

## Overview
This document describes the exact byte-level serialization format used by commonware's Simplex consensus, based on analysis of the Rust implementation.

## Primitive Encoding Rules

### Fixed-Size Integers
All fixed-size integers use **big-endian** encoding (from `codec/src/types/primitives.rs`):
- `u8`: 1 byte
- `u16`: 2 bytes (big-endian)
- `u32`: 4 bytes (big-endian)
- `u64`: 8 bytes (big-endian)
- `u128`: 16 bytes (big-endian)

### Variable-Length Integers (Varint)
Only `usize` and explicitly wrapped `UInt(value)` use varint (LEB128) encoding:
- Values 0-127: 1 byte
- Values 128+: multiple bytes with continuation bit

## Core Types

### Round
**Fixed-size: 16 bytes total**

From `consensus/src/types.rs:55-59`:
```rust
impl Write for Round {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch().write(buf);  // u64, 8 bytes BE
        self.view().write(buf);   // u64, 8 bytes BE
    }
}
```

Layout:
```
[8 bytes: epoch (u64 BE)] [8 bytes: view (u64 BE)]
```

### Proposal
**Variable-size: 16 + varint + 32 bytes**

From `consensus/src/simplex/types.rs:813-817`:
```rust
impl<D: Digest> Write for Proposal<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.round.write(writer);           // 16 bytes (Round)
        UInt(self.parent).write(writer);    // varint (parent view)
        self.payload.write(writer)          // 32 bytes (SHA256)
    }
}
```

Layout:
```
[16 bytes: Round] [varint: parent view] [32 bytes: payload digest]
```

### Vote (Ed25519)
**Fixed-size: 68 bytes total**

From `consensus/src/simplex/types.rs:104-107`:
```rust
impl<S: Scheme> Write for Vote<S> {
    fn write(&self, writer: &mut impl BufMut) {
        self.signer.write(writer);      // u32, 4 bytes BE
        self.signature.write(writer);   // Ed25519: 64 bytes
    }
}
```

Layout:
```
[4 bytes: signer (u32 BE)] [64 bytes: Ed25519 signature]
```

## Message Formats

### Notarize
**Format**: `Proposal + Vote`

Byte layout:
```
[8 bytes: epoch]
[8 bytes: view]
[varint: parent]
[32 bytes: payload]
[4 bytes: signer]
[64 bytes: signature]
```

**Minimum size**: 16 + 1 + 32 + 4 + 64 = 117 bytes (when parent=0)

### Nullify
**Format**: `Round + Vote`

Byte layout:
```
[8 bytes: epoch]
[8 bytes: view]
[4 bytes: signer]
[64 bytes: signature]
```

**Fixed size**: 16 + 4 + 64 = 84 bytes

### Finalize
**Format**: `Proposal + Vote`

Same as Notarize (117+ bytes)

### Notarization (Certificate)
**Format**: `Proposal + VoteCount(varint) + Votes[]`

Byte layout:
```
[16 bytes: Round]
[varint: parent]
[32 bytes: payload]
[varint: vote count]
For each vote:
  [4 bytes: signer]
  [64 bytes: signature]
```

### Nullification (Certificate)
**Format**: `Round + VoteCount(varint) + Votes[]`

Byte layout:
```
[8 bytes: epoch]
[8 bytes: view]
[varint: vote count]
For each vote:
  [4 bytes: signer]
  [64 bytes: signature]
```

### Finalization (Certificate)
Same format as Notarization

### ConflictingNotarize
**Format**: `Notarize + Notarize`

Two complete Notarize messages concatenated

### ConflictingFinalize
**Format**: `Finalize + Finalize`

Two complete Finalize messages concatenated

### NullifyFinalize
**Format**: `Nullify + Finalize`

Nullify message followed by Finalize message

## Common Mistakes

### WRONG: Using varint for Round fields
```solidity
// ❌ INCORRECT
(round.epoch, offset) = decodeVarintU64(data, offset);
(round.view, offset) = decodeVarintU64(data, offset);
```

### RIGHT: Using fixed big-endian for Round fields
```solidity
// ✅ CORRECT
round.epoch = uint64(bytes8(data[offset:offset+8]));
round.view = uint64(bytes8(data[offset+8:offset+16]));
offset += 16;
```

### WRONG: Using varint for signer
```solidity
// ❌ INCORRECT
(signerU64, offset) = decodeVarintU64(data, offset);
vote.signer = uint32(signerU64);
```

### RIGHT: Using fixed big-endian for signer
```solidity
// ✅ CORRECT
vote.signer = uint32(bytes4(data[offset:offset+4]));
offset += 4;
```

## References

- Codec primitives: `codec/src/types/primitives.rs` (lines 51-62)
- Round encoding: `consensus/src/types.rs` (lines 55-59)
- Proposal encoding: `consensus/src/simplex/types.rs` (lines 812-817)
- Vote encoding: `consensus/src/simplex/types.rs` (lines 103-108)
