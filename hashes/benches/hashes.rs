use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use dashcore_hashes::{Hash, HashEngine, hmac, siphash24};
use dashcore_hashes::{hash160, ripemd160, sha1, sha256, sha256d, sha512, sha512_256};

fn bench_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256");

    for (size, label) in [(10, "10b"), (1024, "1k"), (65536, "64k")] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &size, |b, &size| {
            let mut engine = sha256::Hash::engine();
            let bytes = vec![1u8; size];
            b.iter(|| {
                engine.input(&bytes);
                black_box(&engine);
            });
        });
    }
    group.finish();
}

fn bench_sha256d(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256d");

    for (size, label) in [(10, "10b"), (1024, "1k"), (65536, "64k")] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &size, |b, &size| {
            let mut engine = sha256d::Hash::engine();
            let bytes = vec![1u8; size];
            b.iter(|| {
                engine.input(&bytes);
                black_box(&engine);
            });
        });
    }
    group.finish();
}

fn bench_sha512(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha512");

    for (size, label) in [(10, "10b"), (1024, "1k"), (65536, "64k")] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &size, |b, &size| {
            let mut engine = sha512::Hash::engine();
            let bytes = vec![1u8; size];
            b.iter(|| {
                engine.input(&bytes);
                black_box(&engine);
            });
        });
    }
    group.finish();
}

fn bench_sha512_256(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha512_256");

    for (size, label) in [(10, "10b"), (1024, "1k"), (65536, "64k")] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &size, |b, &size| {
            let mut engine = sha512_256::Hash::engine();
            let bytes = vec![1u8; size];
            b.iter(|| {
                engine.input(&bytes);
                black_box(&engine);
            });
        });
    }
    group.finish();
}

fn bench_sha1(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha1");

    for (size, label) in [(10, "10b"), (1024, "1k"), (65536, "64k")] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &size, |b, &size| {
            let mut engine = sha1::Hash::engine();
            let bytes = vec![1u8; size];
            b.iter(|| {
                engine.input(&bytes);
                black_box(&engine);
            });
        });
    }
    group.finish();
}

fn bench_ripemd160(c: &mut Criterion) {
    let mut group = c.benchmark_group("ripemd160");

    for (size, label) in [(10, "10b"), (1024, "1k"), (65536, "64k")] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &size, |b, &size| {
            let mut engine = ripemd160::Hash::engine();
            let bytes = vec![1u8; size];
            b.iter(|| {
                engine.input(&bytes);
                black_box(&engine);
            });
        });
    }
    group.finish();
}

fn bench_hash160(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash160");

    for (size, label) in [(10, "10b"), (1024, "1k"), (65536, "64k")] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &size, |b, &size| {
            let mut engine = hash160::Hash::engine();
            let bytes = vec![1u8; size];
            b.iter(|| {
                engine.input(&bytes);
                black_box(&engine);
            });
        });
    }
    group.finish();
}

fn bench_siphash24(c: &mut Criterion) {
    let mut group = c.benchmark_group("siphash24");

    // Standard siphash benchmarks
    for (size, label) in [(1024, "1k"), (65536, "64k"), (1048576, "1m")] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &size, |b, &size| {
            let key = [0u8; 16];
            let bytes = vec![1u8; size];
            b.iter(|| {
                let hash =
                    siphash24::Hash::hash_with_keys(0x0706050403020100, 0x0f0e0d0c0b0a0908, &bytes);
                black_box(hash);
            });
        });
    }
    group.finish();
}

fn bench_hmac_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("hmac_sha256");

    for (size, label) in [(32, "32b"), (256, "256b"), (1024, "1k"), (65536, "64k")] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &size, |b, &size| {
            let key = [99u8; 32];
            let bytes = vec![1u8; size];
            b.iter(|| {
                let mut engine = hmac::HmacEngine::<sha256::Hash>::new(&key);
                engine.input(&bytes);
                black_box(&engine);
            });
        });
    }
    group.finish();
}

fn bench_hmac_sha512(c: &mut Criterion) {
    let mut group = c.benchmark_group("hmac_sha512");

    for (size, label) in [(32, "32b"), (256, "256b"), (1024, "1k"), (65536, "64k")] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &size, |b, &size| {
            let key = [99u8; 64];
            let bytes = vec![1u8; size];
            b.iter(|| {
                let mut engine = hmac::HmacEngine::<sha512::Hash>::new(&key);
                engine.input(&bytes);
                black_box(&engine);
            });
        });
    }
    group.finish();
}

fn bench_constant_time_comparisons(c: &mut Criterion) {
    use dashcore_hashes::cmp::fixed_time_eq;

    let mut group = c.benchmark_group("constant_time_cmp");

    // 32-byte comparisons (SHA256)
    group.bench_function("32b_ne", |b| {
        let hash_a = sha256::Hash::hash(&[0; 1]);
        let hash_b = sha256::Hash::hash(&[1; 1]);
        b.iter(|| fixed_time_eq(&hash_a[..], &hash_b[..]));
    });

    group.bench_function("32b_eq", |b| {
        let hash_a = sha256::Hash::hash(&[0; 1]);
        let hash_b = sha256::Hash::hash(&[0; 1]);
        b.iter(|| fixed_time_eq(&hash_a[..], &hash_b[..]));
    });

    // 64-byte comparisons (SHA512)
    group.bench_function("64b_ne", |b| {
        let hash_a = sha512::Hash::hash(&[0; 1]);
        let hash_b = sha512::Hash::hash(&[1; 1]);
        b.iter(|| fixed_time_eq(&hash_a[..], &hash_b[..]));
    });

    group.bench_function("64b_eq", |b| {
        let hash_a = sha512::Hash::hash(&[0; 1]);
        let hash_b = sha512::Hash::hash(&[0; 1]);
        b.iter(|| fixed_time_eq(&hash_a[..], &hash_b[..]));
    });

    group.finish();
}

fn bench_slice_comparisons(c: &mut Criterion) {
    let mut group = c.benchmark_group("slice_cmp");

    // 32-byte comparisons (SHA256)
    group.bench_function("32b_ne", |b| {
        let hash_a = sha256::Hash::hash(&[0; 1]);
        let hash_b = sha256::Hash::hash(&[1; 1]);
        b.iter(|| &hash_a[..] == &hash_b[..]);
    });

    group.bench_function("32b_eq", |b| {
        let hash_a = sha256::Hash::hash(&[0; 1]);
        let hash_b = sha256::Hash::hash(&[0; 1]);
        b.iter(|| &hash_a[..] == &hash_b[..]);
    });

    // 64-byte comparisons (SHA512)
    group.bench_function("64b_ne", |b| {
        let hash_a = sha512::Hash::hash(&[0; 1]);
        let hash_b = sha512::Hash::hash(&[1; 1]);
        b.iter(|| &hash_a[..] == &hash_b[..]);
    });

    group.bench_function("64b_eq", |b| {
        let hash_a = sha512::Hash::hash(&[0; 1]);
        let hash_b = sha512::Hash::hash(&[0; 1]);
        b.iter(|| &hash_a[..] == &hash_b[..]);
    });

    group.finish();
}

criterion_group!(
    hash_benches,
    bench_sha256,
    bench_sha256d,
    bench_sha512,
    bench_sha512_256,
    bench_sha1,
    bench_ripemd160,
    bench_hash160,
    bench_siphash24,
    bench_hmac_sha256,
    bench_hmac_sha512,
    bench_constant_time_comparisons,
    bench_slice_comparisons
);
criterion_main!(hash_benches);
