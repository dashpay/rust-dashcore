//! Cost of extending a BIP44 receive pool by a batch of addresses.
//!
//! Run with:
//! `cargo bench -p key-wallet --bench address_generation`

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use key_wallet::managed_account::address_pool::AddressPoolType;
use key_wallet::{
    AddressPool, ChildNumber, DerivationPath, ExtendedPrivKey, KeySource, Mnemonic, Network,
};

const GAP_LIMIT: u32 = 20;

const BATCH_SIZES: [u32; 4] = [10, 50, 100, 500];

fn bench_address_generation(c: &mut Criterion) {
    let mnemonic = Mnemonic::from_phrase("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
    let seed = mnemonic.to_seed("");
    let master = ExtendedPrivKey::new_master(Network::Testnet, &seed).unwrap();
    let account_path = DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(44).unwrap(),
        ChildNumber::from_hardened_idx(5).unwrap(),
        ChildNumber::from_hardened_idx(0).unwrap(),
    ]);
    let key_source = KeySource::Private(master.derive_priv(&account_path).unwrap());
    let base_path = DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]);
    let pool = AddressPool::new(
        base_path,
        AddressPoolType::External,
        GAP_LIMIT,
        Network::Testnet,
        &key_source,
    )
    .unwrap();

    let mut group = c.benchmark_group("address_generation");
    for batch_size in BATCH_SIZES {
        group.throughput(Throughput::Elements(batch_size.into()));
        group.bench_with_input(BenchmarkId::from_parameter(batch_size), &batch_size, |b, &n| {
            b.iter_batched(
                || pool.clone(),
                |mut pool| black_box(pool.generate_addresses(n, &key_source, true).unwrap()),
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, bench_address_generation);
criterion_main!(benches);
