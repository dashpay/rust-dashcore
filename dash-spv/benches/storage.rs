use std::time::Duration;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use dash_spv::{
    storage::{BlockHeaderStorage, DiskStorageManager, StorageManager},
    ClientConfigBuilder, Hash,
};
use dashcore::{block::Version, BlockHash, CompactTarget, Header};
use rand::{rngs::StdRng, Rng, SeedableRng};
use tempfile::TempDir;
use tokio::runtime::Builder;

fn create_test_header(height: u32) -> Header {
    Header {
        version: Version::from_consensus(1),
        prev_blockhash: BlockHash::all_zeros(),
        merkle_root: dashcore_hashes::sha256d::Hash::all_zeros().into(),
        time: height,
        bits: CompactTarget::from_consensus(0x207fffff),
        nonce: height,
    }
}

fn bench_disk_storage(c: &mut Criterion) {
    const CHUNK_SIZE: u32 = 13_000;
    const NUM_ELEMENTS: u32 = CHUNK_SIZE * 20;
    const SEED: u64 = 42;

    let rt = Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap();

    let headers = (0..NUM_ELEMENTS).map(create_test_header).collect::<Vec<Header>>();
    let mut rng = StdRng::seed_from_u64(SEED);

    c.bench_function("storage/disk/store", |b| {
        b.to_async(&rt).iter_batched(
            || async {
                let config = ClientConfigBuilder::testnet()
                    .storage_path(TempDir::new().unwrap().path())
                    .build()
                    .expect("Valid config");
                DiskStorageManager::new(&config).await.unwrap()
            },
            |a| async {
                let mut storage = a.await;

                for chunk in headers.chunks(CHUNK_SIZE as usize) {
                    storage.store_headers(chunk).await.unwrap();
                }
            },
            BatchSize::SmallInput,
        )
    });

    let config = ClientConfigBuilder::testnet()
        .storage_path(TempDir::new().unwrap().path())
        .build()
        .expect("Valid config");

    let mut storage = rt.block_on(async {
        let mut storage = DiskStorageManager::new(&config).await.unwrap();

        for chunk in headers.chunks(CHUNK_SIZE as usize) {
            storage.store_headers(chunk).await.unwrap();
        }

        storage
    });

    c.bench_function("storage/disk/get", |b| {
        b.to_async(&rt).iter_batched(
            || rng.gen::<u32>() % NUM_ELEMENTS,
            async |height| {
                let _ = storage.get_header(height).await.unwrap();
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("storage/disk/reverse_index", |b| {
        b.to_async(&rt).iter_batched(
            || {
                let height = rand::random::<u32>() % NUM_ELEMENTS;
                headers[height as usize].block_hash()
            },
            async |hash| {
                let _ = storage.get_header_height_by_hash(&hash).await.unwrap();
            },
            BatchSize::SmallInput,
        )
    });

    rt.block_on(async {
        storage.shutdown().await;
    });
}

criterion_group!(
    name = disk_storage;
    config =  Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1));
    targets = bench_disk_storage);
criterion_main!(disk_storage);
