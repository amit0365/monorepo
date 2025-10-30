//! Varint-based frame encoding/decoding for efficient network communication.
//!
//! This module implements variable-length integer encoding for message framing,
//! which reduces overhead for small messages compared to fixed 4-byte prefixes.
//!
//! # Encoding Format
//! Uses LEB128 (Little Endian Base 128) encoding where each byte has a continuation bit:
//! - Bit 7 (MSB): 1 if more bytes follow, 0 if this is the last byte
//! - Bits 0-6: 7 bits of the integer value
//!
//! # Size Comparison
//! - 0-127: 1 byte (saves 3 bytes)
//! - 128-16383: 2 bytes (saves 2 bytes)
//! - 16384-2097151: 3 bytes (saves 1 byte)
//! - 2097152-268435455: 4 bytes (same size)
//! - 268435456-u32::MAX: 5 bytes (1 byte overhead)

use crate::Error;
use bytes::{Bytes, BytesMut};
use commonware_runtime::{Sink, Stream};

/// Maximum varint size in bytes (5 bytes for u32)
const MAX_VARINT_SIZE: usize = 5;

/// Encodes a u32 as a varint (LEB128 format).
///
/// # Examples
/// ```
/// let encoded = encode_varint(127); // Returns [0x7F]
/// let encoded = encode_varint(300); // Returns [0xAC, 0x02]
/// ```
pub fn encode_varint(mut value: u32) -> Vec<u8> {
    let mut result = Vec::with_capacity(MAX_VARINT_SIZE);

    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;

        if value != 0 {
            byte |= 0x80; // Set continuation bit
        }

        result.push(byte);

        if value == 0 {
            break;
        }
    }

    result
}

/// Decodes a varint (LEB128 format) from a byte slice.
///
/// Returns the decoded value and the number of bytes consumed.
///
/// # Errors
/// Returns an error if:
/// - The varint is incomplete (not enough bytes)
/// - The varint is too large (would overflow u32)
pub fn decode_varint(bytes: &[u8]) -> Result<(u32, usize), Error> {
    let mut result = 0u32;
    let mut shift = 0;
    let mut position = 0;

    for byte in bytes {
        if shift >= 32 {
            // Would overflow u32
            return Err(Error::RecvTooLarge(u32::MAX as usize));
        }

        let value = (byte & 0x7F) as u32;

        // Check for overflow before shifting
        if let Some(shifted) = value.checked_shl(shift) {
            if let Some(new_result) = result.checked_add(shifted) {
                result = new_result;
            } else {
                return Err(Error::RecvTooLarge(u32::MAX as usize));
            }
        } else {
            return Err(Error::RecvTooLarge(u32::MAX as usize));
        }

        position += 1;

        if byte & 0x80 == 0 {
            // Last byte (no continuation bit)
            return Ok((result, position));
        }

        shift += 7;
    }

    // Incomplete varint
    Err(Error::RecvTooLarge(u32::MAX as usize))
}

/// Sends data with a varint length prefix.
///
/// This function is more efficient than the fixed 4-byte prefix for messages
/// smaller than 2MB, saving 1-3 bytes per message.
pub async fn send_frame_varint<S: Sink>(
    sink: &mut S,
    buf: &[u8],
    max_message_size: usize,
) -> Result<(), Error> {
    // Validate frame size
    let n = buf.len();
    if n > max_message_size {
        return Err(Error::SendTooLarge(n));
    }

    // Encode length as varint
    let len: u32 = n.try_into().map_err(|_| Error::SendTooLarge(n))?;
    let varint = encode_varint(len);

    // Prefix buffer with varint length
    let mut prefixed_buf = BytesMut::with_capacity(varint.len() + buf.len());
    prefixed_buf.extend_from_slice(&varint);
    prefixed_buf.extend_from_slice(buf);

    sink.send(prefixed_buf).await.map_err(Error::SendFailed)
}

/// Receives data with a varint length prefix.
///
/// This function reads the varint length prefix byte-by-byte until complete,
/// then reads the message payload. This is more efficient for small messages
/// but requires multiple small reads for the varint itself.
///
/// # Note
/// For optimal performance, this should be used with a buffered Stream
/// implementation to avoid multiple system calls for reading the varint.
pub async fn recv_frame_varint<T: Stream>(
    stream: &mut T,
    max_message_size: usize,
) -> Result<Bytes, Error> {
    // Read varint byte-by-byte
    // In practice, most messages will have 1-2 byte varints
    let mut varint_bytes = Vec::with_capacity(MAX_VARINT_SIZE);
    let mut decoded_len = None;

    for _ in 0..MAX_VARINT_SIZE {
        // Read one byte
        let byte_buf = stream.recv(vec![0u8; 1]).await.map_err(Error::RecvFailed)?;
        let byte = byte_buf.as_ref()[0];
        varint_bytes.push(byte);

        // Try to decode varint
        match decode_varint(&varint_bytes) {
            Ok((len, _)) => {
                decoded_len = Some(len as usize);
                break;
            }
            Err(_) if byte & 0x80 != 0 => {
                // Continuation bit set, need more bytes
                continue;
            }
            Err(e) => return Err(e),
        }
    }

    let len = decoded_len.ok_or_else(|| Error::RecvTooLarge(u32::MAX as usize))?;

    // Validate frame size
    if len > max_message_size {
        return Err(Error::RecvTooLarge(len));
    }

    // Read the message payload
    if len == 0 {
        return Ok(Bytes::new());
    }

    let read = stream.recv(vec![0; len]).await.map_err(Error::RecvFailed)?;
    Ok(read.into())
}

/// Optimized version for use with buffered streams that support peeking.
///
/// This version can read the varint more efficiently by peeking at buffered
/// data instead of reading byte-by-byte.
pub async fn recv_frame_varint_buffered<T: Stream>(
    stream: &mut T,
    max_message_size: usize,
    peek_fn: impl Fn(&mut T) -> Option<&[u8]>,
) -> Result<Bytes, Error> {
    // Try to peek at buffered data
    if let Some(peeked) = peek_fn(stream) {
        // Try to decode varint from peeked data
        match decode_varint(peeked) {
            Ok((len, varint_size)) => {
                // We can read the entire frame at once
                let total_size = varint_size + len as usize;
                if peeked.len() >= total_size {
                    // Everything is buffered, read it all
                    let frame = stream
                        .recv(vec![0; total_size])
                        .await
                        .map_err(Error::RecvFailed)?;

                    // Skip varint bytes and return payload
                    return Ok(Bytes::copy_from_slice(&frame.as_ref()[varint_size..]));
                }
            }
            Err(_) => {}
        }
    }

    // Fall back to byte-by-byte reading
    recv_frame_varint(stream, max_message_size).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{deterministic, mocks, Runner};
    use rand::Rng;

    #[test]
    fn test_varint_encoding() {
        // Test single byte (0-127)
        assert_eq!(encode_varint(0), vec![0x00]);
        assert_eq!(encode_varint(127), vec![0x7F]);

        // Test two bytes (128-16383)
        assert_eq!(encode_varint(128), vec![0x80, 0x01]);
        assert_eq!(encode_varint(300), vec![0xAC, 0x02]);
        assert_eq!(encode_varint(16383), vec![0xFF, 0x7F]);

        // Test three bytes (16384-2097151)
        assert_eq!(encode_varint(16384), vec![0x80, 0x80, 0x01]);
        assert_eq!(encode_varint(2097151), vec![0xFF, 0xFF, 0x7F]);

        // Test four bytes (2097152-268435455)
        assert_eq!(encode_varint(2097152), vec![0x80, 0x80, 0x80, 0x01]);
        assert_eq!(encode_varint(268435455), vec![0xFF, 0xFF, 0xFF, 0x7F]);

        // Test five bytes (268435456-u32::MAX)
        assert_eq!(encode_varint(268435456), vec![0x80, 0x80, 0x80, 0x80, 0x01]);
        assert_eq!(encode_varint(u32::MAX), vec![0xFF, 0xFF, 0xFF, 0xFF, 0x0F]);
    }

    #[test]
    fn test_varint_decoding() {
        // Test single byte
        assert_eq!(decode_varint(&[0x00]).unwrap(), (0, 1));
        assert_eq!(decode_varint(&[0x7F]).unwrap(), (127, 1));

        // Test two bytes
        assert_eq!(decode_varint(&[0x80, 0x01]).unwrap(), (128, 2));
        assert_eq!(decode_varint(&[0xAC, 0x02]).unwrap(), (300, 2));

        // Test three bytes
        assert_eq!(decode_varint(&[0x80, 0x80, 0x01]).unwrap(), (16384, 3));

        // Test four bytes
        assert_eq!(decode_varint(&[0x80, 0x80, 0x80, 0x01]).unwrap(), (2097152, 4));

        // Test five bytes (u32::MAX)
        assert_eq!(decode_varint(&[0xFF, 0xFF, 0xFF, 0xFF, 0x0F]).unwrap(), (u32::MAX, 5));
    }

    #[test]
    fn test_varint_incomplete() {
        // Incomplete varints should error
        assert!(decode_varint(&[0x80]).is_err());
        assert!(decode_varint(&[0x80, 0x80]).is_err());
        assert!(decode_varint(&[0xFF, 0xFF, 0xFF]).is_err());
    }

    #[test]
    fn test_varint_overflow() {
        // Varints that would overflow u32 should error
        assert!(decode_varint(&[0xFF, 0xFF, 0xFF, 0xFF, 0x80]).is_err());
        assert!(decode_varint(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF]).is_err());
    }

    #[test]
    fn test_varint_extra_bytes() {
        // Should only consume varint bytes, not extra data
        let data = vec![0xAC, 0x02, 0xDE, 0xAD, 0xBE, 0xEF];
        let (value, consumed) = decode_varint(&data).unwrap();
        assert_eq!(value, 300);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn test_send_recv_varint_small() {
        let (mut sink, mut stream) = mocks::Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|_context| async move {
            // Small message (1-byte varint)
            let small_msg = b"Hello";

            let result = send_frame_varint(&mut sink, small_msg, 1024).await;
            assert!(result.is_ok());

            let data = recv_frame_varint(&mut stream, 1024).await.unwrap();
            assert_eq!(data.as_ref(), small_msg);
        });
    }

    #[test]
    fn test_send_recv_varint_medium() {
        let (mut sink, mut stream) = mocks::Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Medium message (2-byte varint)
            let mut medium_msg = vec![0u8; 200];
            context.fill(&mut medium_msg[..]);

            let result = send_frame_varint(&mut sink, &medium_msg, 1024).await;
            assert!(result.is_ok());

            let data = recv_frame_varint(&mut stream, 1024).await.unwrap();
            assert_eq!(data.len(), 200);
            assert_eq!(data.as_ref(), medium_msg.as_slice());
        });
    }

    #[test]
    fn test_send_recv_varint_large() {
        let (mut sink, mut stream) = mocks::Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Large message (3-byte varint)
            let mut large_msg = vec![0u8; 20000];
            context.fill(&mut large_msg[..]);

            let result = send_frame_varint(&mut sink, &large_msg, 100000).await;
            assert!(result.is_ok());

            let data = recv_frame_varint(&mut stream, 100000).await.unwrap();
            assert_eq!(data.len(), 20000);
        });
    }

    #[test]
    fn test_send_varint_too_large() {
        let (mut sink, _) = mocks::Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut msg = vec![0u8; 1000];
            context.fill(&mut msg[..]);

            let result = send_frame_varint(&mut sink, &msg, 999).await;
            assert!(matches!(result, Err(Error::SendTooLarge(1000))));
        });
    }

    #[test]
    fn test_recv_varint_too_large() {
        let (mut sink, mut stream) = mocks::Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Manually create a frame with large size
            let varint = encode_varint(1000);
            let mut buf = BytesMut::new();
            buf.extend_from_slice(&varint);
            sink.send(buf).await.unwrap();

            let result = recv_frame_varint(&mut stream, 999).await;
            assert!(matches!(result, Err(Error::RecvTooLarge(1000))));
        });
    }

    #[test]
    fn test_multiple_messages_varint() {
        let (mut sink, mut stream) = mocks::Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Send multiple messages of different sizes
            let msgs = vec![
                (vec![0u8; 10], 10),     // 1-byte varint
                (vec![0u8; 200], 200),   // 2-byte varint
                (vec![0u8; 20000], 20000), // 3-byte varint
            ];

            for (msg, _) in &msgs {
                let mut m = msg.clone();
                context.fill(&mut m[..]);
                send_frame_varint(&mut sink, &m, 100000).await.unwrap();
            }

            // Receive and verify sizes only
            for (_, expected_size) in &msgs {
                let data = recv_frame_varint(&mut stream, 100000).await.unwrap();
                assert_eq!(data.len(), *expected_size);
            }
        });
    }

    #[test]
    fn test_empty_message_varint() {
        let (mut sink, mut stream) = mocks::Channel::init();

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Send empty message
            send_frame_varint(&mut sink, &[], 1024).await.unwrap();

            let data = recv_frame_varint(&mut stream, 1024).await.unwrap();
            assert_eq!(data.len(), 0);
        });
    }
}