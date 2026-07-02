use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use dashcore_hashes::siphash24::{siphash, siphash_batch};

const K0: u64 = 0x0706050403020100;
const K1: u64 = 0x0f0e0d0c0b0a0908;

const LEN: usize = 25;

const COUNTS: [usize; 3] = [1_024, 16_384, 262_144];

fn make_inputs(count: usize) -> Vec<[u8; LEN]> {
    (0..count).map(|i| [(i & 0xff) as u8; LEN]).collect()
}

fn bench_siphash(c: &mut Criterion) {
    let mut group = c.benchmark_group("siphash24");

    for count in COUNTS {
        let inputs = make_inputs(count);
        let mut out = vec![0u64; count];
        group.throughput(Throughput::Elements(count as u64));

        group.bench_with_input(BenchmarkId::new("single", count), &inputs, |b, inputs| {
            b.iter(|| {
                for e in inputs {
                    black_box(siphash(K0, K1, e));
                }
            });
        });

        group.bench_with_input(BenchmarkId::new("batch", count), &inputs, |b, inputs| {
            b.iter(|| {
                siphash_batch::<LEN>(K0, K1, black_box(inputs), &mut out);
                black_box(&out);
            });
        });
    }
    group.finish();
}

criterion_group!(siphash_benches, bench_siphash);
criterion_main!(siphash_benches);
