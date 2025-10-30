//! Benchmark comparing fixed 4-byte framing vs varint framing
//!
//! Run with: cargo bench -p commonware-stream framing_comparison

use bytes::{BufMut as _, BytesMut};
use commonware_runtime::{deterministic, mocks, Runner};
use commonware_stream::utils::{codec, varint_codec};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

/// Benchmark message sizes representing different use cases
const MESSAGE_SIZES: &[usize] = &[
    10,     // Very small (control messages)
    100,    // Small (typical RPC)
    1000,   // Medium (data transfer)
    10000,  // Large (bulk transfer)
    100000, // Very large (file transfer)
];

fn bench_fixed_framing(c: &mut Criterion) {
    let mut group = c.benchmark_group("fixed_framing");

    for &size in MESSAGE_SIZES {
        group.bench_function(format!("send_{}_bytes", size), |b| {
            b.iter(|| {
                let executor = deterministic::Runner::default();
                executor.start(|mut context| async move {
                    let (mut sink, _) = mocks::Channel::init();
                    let mut msg = vec![0u8; size];
                    context.fill(&mut msg);

                    codec::send_frame(&mut sink, black_box(&msg), size * 2)
                        .await
                        .unwrap();
                });
            });
        });

        group.bench_function(format!("recv_{}_bytes", size), |b| {
            b.iter(|| {
                let executor = deterministic::Runner::default();
                executor.start(|mut context| async move {
                    let (mut sink, mut stream) = mocks::Channel::init();

                    // Pre-send a message
                    let mut msg = vec![0u8; size];
                    context.fill(&mut msg);
                    codec::send_frame(&mut sink, &msg, size * 2).await.unwrap();

                    // Benchmark receiving
                    let _ = codec::recv_frame(black_box(&mut stream), size * 2)
                        .await
                        .unwrap();
                });
            });
        });
    }

    group.finish();
}

fn bench_varint_framing(c: &mut Criterion) {
    let mut group = c.benchmark_group("varint_framing");

    for &size in MESSAGE_SIZES {
        group.bench_function(format!("send_{}_bytes", size), |b| {
            b.iter(|| {
                let executor = deterministic::Runner::default();
                executor.start(|mut context| async move {
                    let (mut sink, _) = mocks::Channel::init();
                    let mut msg = vec![0u8; size];
                    context.fill(&mut msg);

                    varint_codec::send_frame_varint(&mut sink, black_box(&msg), size * 2)
                        .await
                        .unwrap();
                });
            });
        });

        group.bench_function(format!("recv_{}_bytes", size), |b| {
            b.iter(|| {
                let executor = deterministic::Runner::default();
                executor.start(|mut context| async move {
                    let (mut sink, mut stream) = mocks::Channel::init();

                    // Pre-send a message
                    let mut msg = vec![0u8; size];
                    context.fill(&mut msg);
                    varint_codec::send_frame_varint(&mut sink, &msg, size * 2)
                        .await
                        .unwrap();

                    // Benchmark receiving
                    let _ = varint_codec::recv_frame_varint(black_box(&mut stream), size * 2)
                        .await
                        .unwrap();
                });
            });
        });
    }

    group.finish();
}

fn bench_overhead_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("overhead_comparison");

    // Measure the actual byte overhead for different message sizes
    group.bench_function("overhead_calculation", |b| {
        b.iter(|| {
            for &size in MESSAGE_SIZES {
                // Fixed framing: always 4 bytes
                let fixed_overhead = 4;

                // Varint framing: varies by size
                let varint_overhead = if size <= 127 {
                    1
                } else if size <= 16383 {
                    2
                } else if size <= 2097151 {
                    3
                } else if size <= 268435455 {
                    4
                } else {
                    5
                };

                let savings = fixed_overhead as i32 - varint_overhead as i32;
                black_box(savings);
            }
        });
    });

    group.finish();
}

fn bench_encode_decode_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode_decode");

    // Benchmark just the encoding/decoding without I/O
    for &value in &[127u32, 16383, 2097151, 268435455, u32::MAX] {
        group.bench_function(format!("encode_varint_{}", value), |b| {
            b.iter(|| {
                black_box(varint_codec::encode_varint(black_box(value)));
            });
        });

        let encoded = varint_codec::encode_varint(value);
        group.bench_function(format!("decode_varint_{}", value), |b| {
            b.iter(|| {
                black_box(varint_codec::decode_varint(black_box(&encoded)).unwrap());
            });
        });
    }

    // Compare with fixed encoding
    for &value in &[127u32, 16383, 2097151, 268435455, u32::MAX] {
        group.bench_function(format!("encode_fixed_{}", value), |b| {
            b.iter(|| {
                let mut buf = BytesMut::with_capacity(4);
                buf.put_u32(black_box(value));
                black_box(buf);
            });
        });

        let encoded = value.to_be_bytes();
        group.bench_function(format!("decode_fixed_{}", value), |b| {
            b.iter(|| {
                black_box(u32::from_be_bytes(black_box(encoded)));
            });
        });
    }

    group.finish();
}

fn bench_mixed_workload(c: &mut Criterion) {
    let mut group = c.benchmark_group("mixed_workload");

    // Simulate a realistic workload with mixed message sizes
    let workload_distribution = vec![
        (10, 30),    // 30% very small messages
        (100, 40),   // 40% small messages
        (1000, 20),  // 20% medium messages
        (10000, 8),  // 8% large messages
        (100000, 2), // 2% very large messages
    ];

    group.bench_function("fixed_mixed", |b| {
        b.iter(|| {
            let executor = deterministic::Runner::default();
            executor.start(|mut context| async move {
                let (mut sink, mut stream) = mocks::Channel::init();

                for (size, count) in &workload_distribution {
                    for _ in 0..*count {
                        let mut msg = vec![0u8; *size];
                        context.fill(&mut msg);
                        codec::send_frame(&mut sink, &msg, 200000).await.unwrap();
                    }
                }

                // Receive all messages
                for (size, count) in &workload_distribution {
                    for _ in 0..*count {
                        let _ = codec::recv_frame(&mut stream, 200000).await.unwrap();
                    }
                }
            });
        });
    });

    group.bench_function("varint_mixed", |b| {
        b.iter(|| {
            let executor = deterministic::Runner::default();
            executor.start(|mut context| async move {
                let (mut sink, mut stream) = mocks::Channel::init();

                for (size, count) in &workload_distribution {
                    for _ in 0..*count {
                        let mut msg = vec![0u8; *size];
                        context.fill(&mut msg);
                        varint_codec::send_frame_varint(&mut sink, &msg, 200000)
                            .await
                            .unwrap();
                    }
                }

                // Receive all messages
                for (size, count) in &workload_distribution {
                    for _ in 0..*count {
                        let _ = varint_codec::recv_frame_varint(&mut stream, 200000)
                            .await
                            .unwrap();
                    }
                }
            });
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_fixed_framing,
    bench_varint_framing,
    bench_overhead_comparison,
    bench_encode_decode_only,
    bench_mixed_workload
);
criterion_main!(benches);