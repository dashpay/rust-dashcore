//! Compact-filter matching cost: full monitored set vs the pruned
//! forward-scan set for a mixing-heavy CoinJoin wallet
//! (dashpay/rust-dashcore#948).
//!
//! Mimics a wallet mid-recovery after many mixing rounds. Every CoinJoin
//! round pays a fresh single-use address, so the account accumulates `used`
//! spent addresses, keeps a small set of still-funded denominations
//! ([`LIVE_UTXOS`]), and watches the usual gap-limit lookahead on top. One
//! scan batch of BIP158 filters is then matched with
//! `monitored_script_pubkeys_for` (the pre-#948 query, which drags every
//! historical address through SipHash + sort per filter) and with
//! `scan_script_pubkeys_for` (the pruned query, bounded by live UTXOs + gap
//! lookahead).
//!
//! BIP158 keys each filter's SipHashes off the block hash, so the whole
//! query set is re-hashed and re-sorted per filter — which is exactly why
//! the query size dominates and why nothing is cacheable across filters.
//!
//! Run with:
//! `cargo bench -p key-wallet-manager --bench filter_scan`

use std::collections::HashMap;
use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use dashcore::bip158::{BlockFilter, FilterQuery};
use dashcore::hashes::Hash;
use dashcore::{Address, Block, OutPoint, Transaction, TxOut, Txid};
use key_wallet::account::ManagedAccountTrait;
use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet::{KeySource, ManagedAccountType, Network, Utxo};
use key_wallet_manager::{
    check_compact_filters_for_elements, FilterMatchKey, WalletInterface, WalletManager,
};

/// Denominated coins still unspent in the CoinJoin account — the wallet's
/// active mixing balance, which stays in the scan query.
const LIVE_UTXOS: usize = 200;

/// Filters matched per iteration — one scan batch.
const FILTERS: u32 = 512;

/// Historical single-use address counts to sweep, roughly
/// `denominations x rounds` at different points of a recovery scan. The
/// issue's reference wallet starts a mainnet recovery at a few hundred
/// monitored scripts and ends at several thousand.
const USED_ADDRESSES: [u32; 3] = [500, 2_000, 6_000];

type Manager = WalletManager<ManagedWalletInfo>;

/// Build a wallet whose CoinJoin account carries `used` spent single-use
/// addresses, [`LIVE_UTXOS`] still-funded ones, and the default gap-limit
/// lookahead of unused addresses above them.
///
/// The wallet is created from a fresh random mnemonic each run: the
/// workload is defined entirely by the pool/UTXO counts, so the timings
/// are stable across runs without pinning key material.
fn wallet_with_mixing_history(used: u32) -> (Manager, [u8; 32]) {
    let mut manager = Manager::new(Network::Regtest);
    let wallet_id = manager
        .create_wallet_with_random_mnemonic(WalletAccountCreationOptions::Default)
        .expect("create wallet");

    let key_source = KeySource::Public(
        manager
            .get_wallet(&wallet_id)
            .expect("wallet")
            .accounts
            .coinjoin_accounts
            .get(&0)
            .expect("CoinJoin account 0")
            .account_xpub,
    );

    let info = manager.get_wallet_info_mut(&wallet_id).expect("wallet info");
    let coinjoin = info.accounts.coinjoin_accounts.get_mut(&0).expect("managed CoinJoin account");

    // Extend the external (mixed-coin) branch so the pool holds `used`
    // historical addresses plus the pre-generated gap window above them.
    let addresses = {
        let ManagedAccountType::CoinJoin {
            external_addresses,
            ..
        } = coinjoin.managed_account_type_mut()
        else {
            panic!("expected CoinJoin managed account type");
        };
        external_addresses
            .generate_addresses(used, &key_source, true)
            .expect("derive CoinJoin addresses");
        external_addresses.all_addresses()
    };

    // The first `used` indices each received one mixing round's payout...
    let spent = &addresses[..used as usize];
    for address in spent {
        assert!(coinjoin.mark_address_used(address), "address should belong to the pool");
    }
    // ...and only the most recent LIVE_UTXOS denominations remain unspent.
    for (i, address) in spent.iter().rev().take(LIVE_UTXOS).enumerate() {
        let mut txid = [0u8; 32];
        txid[..4].copy_from_slice(&(i as u32).to_le_bytes());
        txid[31] = 0xc1;
        let utxo = Utxo::new(
            OutPoint::new(Txid::from_byte_array(txid), 0),
            TxOut {
                value: 100_001,
                script_pubkey: address.script_pubkey(),
            },
            address.clone(),
            100 + i as u32,
            false,
        );
        coinjoin.utxos.insert(utxo.outpoint, utxo);
    }

    (manager, wallet_id)
}

/// One scan batch of realistic filters over blocks that do not pay the
/// wallet. Each block's hash differs, so every filter re-keys its SipHashes
/// — the property that forces the per-filter re-hash being measured.
fn scan_batch_filters(count: u32) -> HashMap<FilterMatchKey, BlockFilter> {
    (0..count)
        .map(|height| {
            let third_party = Address::dummy(Network::Regtest, 1_000_000 + height as usize);
            let tx = Transaction::dummy(&third_party, 0..2, &[u64::from(height) + 1, 546]);
            let block = Block::dummy(height, vec![tx]);
            (FilterMatchKey::new(height, block.block_hash()), BlockFilter::dummy(&block))
        })
        .collect()
}

fn bench_filter_scan(c: &mut Criterion) {
    let filters = scan_batch_filters(FILTERS);

    let mut group = c.benchmark_group("filter_scan");
    group.sample_size(10);
    group.throughput(Throughput::Elements(u64::from(FILTERS)));

    for used in USED_ADDRESSES {
        let (manager, wallet_id) = wallet_with_mixing_history(used);
        let monitored = manager.monitored_script_pubkeys_for(&wallet_id);
        let pruned = manager.scan_script_pubkeys_for(&wallet_id);
        assert!(
            pruned.len() < monitored.len(),
            "the scan query must shrink once CoinJoin addresses are spent"
        );
        println!(
            "used={used}: monitored query = {} scripts, pruned scan query = {} scripts",
            monitored.len(),
            pruned.len()
        );

        for (name, scripts) in [("monitored", &monitored), ("pruned", &pruned)] {
            group.bench_with_input(BenchmarkId::new(name, used), scripts, |b, scripts| {
                b.iter(|| {
                    check_compact_filters_for_elements(
                        black_box(&filters),
                        black_box(scripts),
                        &[],
                        0,
                    )
                })
            });
        }
    }

    group.finish();

    // What the revision-keyed query cache saves per batch: re-collecting the
    // wallet's scan scripts and re-grouping them into a `FilterQuery`. With
    // the cache, this cost is paid once per wallet change instead of once
    // per batch.
    let mut assembly = c.benchmark_group("query_assembly");
    for used in USED_ADDRESSES {
        let (manager, wallet_id) = wallet_with_mixing_history(used);
        assembly.bench_with_input(BenchmarkId::new("pruned", used), &(), |b, _| {
            b.iter(|| {
                let scripts = manager.scan_script_pubkeys_for(black_box(&wallet_id));
                let query: FilterQuery = scripts.iter().map(|s| s.as_bytes()).collect();
                black_box(query)
            })
        });
    }
    assembly.finish();
}

criterion_group!(benches, bench_filter_scan);
criterion_main!(benches);
