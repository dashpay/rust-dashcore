//
// This file is a part of rust-dashcore.
// SPDX-License-Identifier: CC0-1.0
// See the accompanying file LICENSE or https://creativecommons.org/publicdomain/zero/1.0
//

//! Benchmarks for the proof of work scheme

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use dashcore_hashes::{hash_x11, Hash, HashEngine};

fn bench_x11(c: &mut Criterion) {
    let mut group = c.benchmark_group("x11");

    for (size, label) in
        [(32, "32b"), (64, "64b"), (80, "80b"), (128, "128b"), (1024, "1k"), (65536, "64k")]
    {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &vec![1u8; size], |b, bytes| {
            b.iter(|| hash_x11::Hash::hash(black_box(bytes)))
        });
    }

    // A block header fed field by field, as consensus encoding does.
    group.throughput(Throughput::Bytes(80));
    group.bench_function("header_fields", |b| {
        let header = [1u8; 80];
        b.iter(|| {
            let header = black_box(&header);
            let mut engine = hash_x11::Hash::engine();
            for field in [0..4, 4..36, 36..68, 68..72, 72..76, 76..80] {
                engine.input(&header[field]);
            }
            hash_x11::Hash::from_engine(engine)
        })
    });
    group.finish();
}

criterion_group!(x11_benches, bench_x11);
criterion_main!(x11_benches);
