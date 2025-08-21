use criterion::{Criterion, black_box, criterion_group, criterion_main};
use dashcore::blockdata::transaction::Transaction;
use dashcore::consensus::{Encodable, deserialize};
use dashcore::hashes::hex::FromHex;
use std::io::Write;

const SOME_TX: &str = "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000";

/// A writer that discards all data written to it.
struct EmptyWrite;

impl Write for EmptyWrite {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn bench_transaction_size(c: &mut Criterion) {
    let raw_tx = Vec::from_hex(SOME_TX).unwrap();
    let mut tx: Transaction = deserialize(&raw_tx).unwrap();

    c.bench_function("transaction_size", |b| {
        b.iter(|| {
            black_box(black_box(&mut tx).size());
        });
    });
}

fn bench_transaction_serialize(c: &mut Criterion) {
    let raw_tx = Vec::from_hex(SOME_TX).unwrap();
    let tx: Transaction = deserialize(&raw_tx).unwrap();

    c.bench_function("transaction_serialize", |b| {
        let mut data = Vec::with_capacity(raw_tx.len());
        b.iter(|| {
            let result = tx.consensus_encode(&mut data);
            black_box(&result);
            data.clear();
        });
    });
}

fn bench_transaction_serialize_logic(c: &mut Criterion) {
    let raw_tx = Vec::from_hex(SOME_TX).unwrap();
    let tx: Transaction = deserialize(&raw_tx).unwrap();

    c.bench_function("transaction_serialize_logic", |b| {
        b.iter(|| {
            let size = tx.consensus_encode(&mut EmptyWrite);
            black_box(&size);
        });
    });
}

fn bench_transaction_deserialize(c: &mut Criterion) {
    let raw_tx = Vec::from_hex(SOME_TX).unwrap();

    c.bench_function("transaction_deserialize", |b| {
        b.iter(|| {
            let tx: Transaction = deserialize(&raw_tx).unwrap();
            black_box(&tx);
        });
    });
}

criterion_group!(
    benches,
    bench_transaction_size,
    bench_transaction_serialize,
    bench_transaction_serialize_logic,
    bench_transaction_deserialize
);
criterion_main!(benches);
