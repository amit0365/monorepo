# Implementation Plan: Stream Framing Optimization

## Overview
This document outlines the implementation plan for two related performance optimizations:
1. **Issue #753**: Replace fixed 4-byte frame length prefix with varint encoding
2. **Issue #786**: Add BufReader/BufWriter to tokio runtime for reduced syscalls

## Performance Impact Analysis

### Current State
- **Overhead**: 4 bytes per message (fixed u32 length prefix)
- **System Calls**: 2 per message (1 for length, 1 for payload)
- **Small Message Penalty**: 40% overhead on 10-byte messages

### Expected Improvements
#### Varint Encoding
- **1-byte messages**: Save 3 bytes (75% reduction)
- **< 128 byte messages**: Save 3 bytes
- **< 16KB messages**: Save 2 bytes
- **< 2MB messages**: Save 1 byte
- **2MB-256MB messages**: No change
- **> 256MB messages**: +1 byte overhead

#### BufReader/BufWriter
- **Reduced syscalls**: Batch multiple small reads/writes
- **Better CPU cache utilization**: Larger buffer improves locality
- **Ideal for**: Message-heavy workloads with many small messages

## Implementation Strategy

### Phase 1: Varint Encoding (Issue #753)

#### 1.1 Varint Format Selection
Use **LEB128** (Little Endian Base 128) encoding:
```rust
// Encoding: Each byte has a continuation bit (MSB)
// 0xxxxxxx = last byte (0-127)
// 1xxxxxxx = more bytes follow (128+)

// Examples:
// 127 => [0x7F]                    (1 byte)
// 300 => [0xAC, 0x02]             (2 bytes)
// 16384 => [0x80, 0x80, 0x01]     (3 bytes)
```

#### 1.2 Implementation Challenges
The current `Stream` trait requires reading **exactly** N bytes:
```rust
fn recv(&mut self, buf: impl Into<StableBuf>) -> Result<StableBuf, Error>
```

**Problem**: Can't read varint byte-by-byte without changing trait.

**Solutions Considered**:
1. **Option A**: Modify Stream trait to support partial reads
2. **Option B**: Add buffering layer in codec.rs
3. **Option C**: Implement buffering in runtime (BufReader)

**Recommendation**: Option C - Implement BufReader first (Phase 2), then varint becomes trivial.

### Phase 2: BufReader/BufWriter (Issue #786)

#### 2.1 Tokio Runtime Modifications

```rust
// Current implementation
pub struct Stream {
    read_timeout: Duration,
    stream: OwnedReadHalf,
}

// New implementation with buffering
pub struct Stream {
    read_timeout: Duration,
    reader: BufReader<OwnedReadHalf>, // Wrapped in BufReader
}

pub struct Sink {
    write_timeout: Duration,
    writer: BufWriter<OwnedWriteHalf>, // Wrapped in BufWriter
}
```

#### 2.2 Configuration
Add buffer size configuration to `Config`:
```rust
pub struct Config {
    tcp_nodelay: Option<bool>,
    read_timeout: Duration,
    write_timeout: Duration,
    read_buffer_size: usize,  // New: Default 8KB
    write_buffer_size: usize, // New: Default 8KB
}
```

### Phase 3: Varint Implementation (After BufReader)

#### 3.1 New Codec Functions
```rust
// stream/src/utils/codec.rs

async fn encode_varint(value: u32) -> Vec<u8> {
    let mut result = Vec::new();
    let mut val = value;
    loop {
        let mut byte = (val & 0x7F) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80; // Set continuation bit
        }
        result.push(byte);
        if val == 0 {
            break;
        }
    }
    result
}

async fn decode_varint<T: Stream>(stream: &mut T) -> Result<u32, Error> {
    let mut result = 0u32;
    let mut shift = 0;
    loop {
        let mut byte_buf = vec![0u8; 1];
        stream.recv(byte_buf).await?;
        let byte = byte_buf[0];

        result |= ((byte & 0x7F) as u32) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 32 {
            return Err(Error::InvalidVarint);
        }
    }
    Ok(result)
}
```

## File Modifications Required

### Critical Files
1. **`stream/src/utils/codec.rs`**
   - Replace fixed 4-byte prefix with varint
   - Update all tests

2. **`runtime/src/network/tokio.rs`**
   - Wrap streams in BufReader/BufWriter
   - Add buffer configuration

### Secondary Files
3. **`runtime/src/network/iouring.rs`** - Add buffering
4. **`runtime/src/network/deterministic.rs`** - Mock buffering
5. **`runtime/src/mocks.rs`** - Update Channel mock
6. **All fuzz tests** - Regression testing

## Testing Strategy

### Unit Tests
- Varint encoding/decoding edge cases
- Buffer boundary conditions
- Message size limits

### Integration Tests
- End-to-end message exchange
- Multiple message sequences
- Error propagation

### Fuzz Tests
- Random message sizes
- Malformed varints
- Buffer overflow attempts

### Benchmarks
```rust
// Add new benchmarks in stream/benches/
#[bench]
fn bench_varint_small_messages() { }

#[bench]
fn bench_varint_large_messages() { }

#[bench]
fn bench_buffered_vs_unbuffered() { }
```

## Rollout Plan

### Week 1: BufReader/BufWriter
1. Implement in tokio runtime
2. Add configuration options
3. Test with existing fixed-length framing

### Week 2: Varint Encoding
1. Implement varint codec functions
2. Update codec.rs to use varints
3. Update all tests

### Week 3: Full Integration
1. Apply to all runtime implementations
2. Run full test suite
3. Benchmark improvements
4. Documentation updates

## Risk Mitigation

### Backward Compatibility
- Consider version negotiation for protocol changes
- Support both old and new formats during transition

### Performance Regression
- Benchmark before/after each change
- Profile with different message size distributions
- Test with real-world workloads

### Error Handling
- Maintain existing error types and semantics
- Add new error for malformed varints
- Proper cleanup on buffer failures

## Success Metrics

### Bandwidth Savings
- Target: 2-3% reduction for typical workloads
- Measure: Bytes sent/received per message

### Latency Improvement
- Target: 10-20% reduction for small messages
- Measure: Round-trip time for various message sizes

### System Call Reduction
- Target: 30-50% fewer read/write syscalls
- Measure: strace/dtrace monitoring

## Open Questions

1. **Buffer Sizes**: What are optimal defaults? (8KB? 16KB?)
2. **Flush Strategy**: When to flush BufWriter? (On send? Timer?)
3. **Migration Path**: How to handle protocol version mismatch?
4. **Other Runtimes**: Apply same optimizations to io_uring implementation?

## Next Steps

1. Review this plan with maintainers
2. Create feature branches for each phase
3. Begin Phase 2 implementation (BufReader/BufWriter)
4. Set up benchmarking infrastructure