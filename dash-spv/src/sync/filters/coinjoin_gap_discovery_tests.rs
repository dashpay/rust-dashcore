//! CoinJoin gap-limit discovery repros against the real filter → block →
//! wallet pipeline (`FiltersManager` + `BlockMatchTracker` + a real
//! `WalletManager<ManagedWalletInfo>` with a CoinJoin account).
//!
//! Background: a wallet with dense CoinJoin usage (dozens of consecutive
//! external indices funded per block) historically stalled at
//! `highest_used = 59` (initial 30-address watch window + one gap-limit
//! extension) because a matched block was applied to a wallet exactly once —
//! the `BlockMatchTracker` gate was keyed by `(wallet, block)`, not
//! `(wallet, address)` — so outputs paying addresses derived *from that same
//! block's matches* were never re-tested. PR #820 fixed the in-flight part:
//! `rescan_batch` now re-queues already-processed blocks of ACTIVE batches
//! against newly derived scripts, to a fixpoint.
//!
//! These tests pin both the fixed behaviour and the remaining hole:
//!
//! 1. [`coinjoin_gap_limit_dense_same_batch_recovers`] — the empirical
//!    stall-at-59 shape (two dense blocks in one batch). GREEN since #820;
//!    kept as a regression guard.
//! 2. [`coinjoin_gap_limit_inversion_within_batch_recovers`] — a gap-window
//!    output in an EARLIER block of the SAME (still-active) batch is
//!    recovered by the commit-time rescan. GREEN since #820.
//! 3. [`coinjoin_gap_limit_stall_across_committed_batch`] — the SAME shape
//!    with the earlier block in an already-COMMITTED batch (#846): rescans
//!    only reach `active_batches`, and committed batches are gone. GREEN
//!    since `rescan_committed_range` re-tests newly derived scripts against
//!    the STORED filters below the committing batch.
//!
//! Each test drives the manager exactly the way the production event loop
//! does: `try_process_batch` → `BlocksNeeded` → (blocks-manager stand-in)
//! `WalletInterface::process_block_for_wallets` → `BlockProcessed` (with the
//! wallet's freshly derived scripts) → `handle_sync_event` → commit-time
//! rescan, iterated to quiescence. Deterministic: fixed mnemonic, synthetic
//! blocks, real BIP-158 filters, no network.

use super::*;
use crate::storage::{
    DiskStorageManager, PersistentBlockHeaderStorage, PersistentFilterHeaderStorage,
    PersistentFilterStorage, StorageManager,
};
use dashcore::{
    Address, Block, BlockHash, Network, OutPoint, Transaction, TxIn, TxOut, Txid, Witness,
};
use key_wallet::account::ManagedAccountTrait;
use key_wallet::gap_limit::DEFAULT_COINJOIN_GAP_LIMIT;
use key_wallet::managed_account::address_pool::{AddressPool, AddressPoolType, KeySource};
use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::WalletManager;
use tokio::sync::mpsc::unbounded_channel;

/// Deterministic test wallet seed (standard BIP-39 test vector mnemonic).
const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// CoinJoin-denomination-shaped output value (0.001 DASH + per-round fee).
/// The matcher is purely script-based; the value is for realism only.
const DENOMINATION: u64 = 100_001;

type CjFiltersManager = FiltersManager<
    PersistentBlockHeaderStorage,
    PersistentFilterHeaderStorage,
    PersistentFilterStorage,
    WalletManager<ManagedWalletInfo>,
>;

/// Real wallet manager with one seed wallet (Default accounts incl. CoinJoin
/// account 0, external pool pre-generated to `DEFAULT_COINJOIN_GAP_LIMIT`),
/// wired into a `FiltersManager` over temp-dir storage.
async fn setup() -> (CjFiltersManager, Arc<RwLock<WalletManager<ManagedWalletInfo>>>, WalletId) {
    let mut wm = WalletManager::<ManagedWalletInfo>::new(Network::Regtest);
    let wallet_id = wm
        .create_wallet_from_mnemonic(TEST_MNEMONIC, 0, WalletAccountCreationOptions::Default)
        .expect("create deterministic test wallet");
    let wallet = Arc::new(RwLock::new(wm));

    let storage = DiskStorageManager::with_temp_dir().await.unwrap();
    let mut manager = FiltersManager::new(
        Arc::clone(&wallet),
        storage.block_headers(),
        storage.filter_headers(),
        storage.filters(),
    )
    .await;
    manager.set_state(SyncState::Syncing);
    (manager, wallet, wallet_id)
}

/// Derive the wallet's first `count` CoinJoin-account-0 External addresses
/// OFFLINE (via a standalone pool over the same xpub + base path), so test
/// blocks can pay indices far beyond the wallet's live watch window without
/// touching the wallet's own state.
async fn coinjoin_external_addresses(
    wallet: &Arc<RwLock<WalletManager<ManagedWalletInfo>>>,
    wallet_id: &WalletId,
    count: u32,
) -> Vec<Address> {
    let wm = wallet.read().await;
    let signing_wallet = wm.get_wallet(wallet_id).expect("wallet present");
    let xpub = signing_wallet
        .accounts
        .coinjoin_accounts
        .get(&0)
        .expect("CoinJoin account 0 (Default options)")
        .account_xpub;
    let info = wm.get_wallet_info(wallet_id).expect("wallet info present");
    let live_pool = coinjoin_external_pool(info);
    let mut pool = AddressPool::new(
        live_pool.base_path.clone(),
        AddressPoolType::External,
        count,
        Network::Regtest,
        &KeySource::Public(xpub),
    )
    .expect("derive standalone CoinJoin External pool");
    // `AddressPool::new` pre-generates `count` addresses; extend defensively
    // in case the constructor semantics change.
    if pool.highest_generated.map(|h| h + 1).unwrap_or(0) < count {
        let missing = count - pool.highest_generated.map(|h| h + 1).unwrap_or(0);
        pool.generate_addresses(missing, &KeySource::Public(xpub), true)
            .expect("extend standalone pool");
    }
    (0..count).map(|i| pool.address_at_index(i).expect("address generated")).collect()
}

/// The wallet's LIVE CoinJoin-account-0 External pool.
fn coinjoin_external_pool(info: &ManagedWalletInfo) -> &AddressPool {
    let account =
        info.accounts.coinjoin_accounts.get(&0).expect("CoinJoin account 0 (Default options)");
    account
        .managed_account_type()
        .address_pools()
        .into_iter()
        .find(|p| p.pool_type == AddressPoolType::External)
        .expect("CoinJoin External pool")
}

/// `(highest_used, highest_generated, used_count)` of the live CoinJoin
/// External pool — the discovery frontier the assertions pin.
async fn coinjoin_pool_state(
    wallet: &Arc<RwLock<WalletManager<ManagedWalletInfo>>>,
    wallet_id: &WalletId,
) -> (Option<u32>, Option<u32>, usize) {
    let wm = wallet.read().await;
    let info = wm.get_wallet_info(wallet_id).expect("wallet info present");
    let pool = coinjoin_external_pool(info);
    (pool.highest_used, pool.highest_generated, pool.used_indices.len())
}

/// One block at `height` whose single transaction pays every address in
/// `addresses` one denomination output. Returns the block, its real BIP-158
/// filter, and the filter match key.
fn block_paying(height: u32, addresses: &[Address]) -> (Block, BlockFilter, FilterMatchKey) {
    let mut prev_txid = [0xABu8; 32];
    prev_txid[..4].copy_from_slice(&height.to_le_bytes());
    let tx = Transaction {
        version: 1,
        lock_time: 0,
        // One non-null input so the tx is not coinbase-shaped.
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from(prev_txid), 0),
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: Witness::new(),
        }],
        output: addresses
            .iter()
            .map(|a| TxOut {
                value: DENOMINATION,
                script_pubkey: a.script_pubkey(),
            })
            .collect(),
        special_transaction_payload: None,
    };
    let block = Block::dummy(height, vec![tx]);
    let filter = BlockFilter::dummy(&block);
    let key = FilterMatchKey::new(height, block.block_hash());
    (block, filter, key)
}

/// Drive the production event loop to quiescence: consume `BlocksNeeded` by
/// processing the named blocks through the real wallet (the blocks-manager's
/// job), feed the resulting `BlockProcessed` events (carrying the wallet's
/// freshly derived scripts) back into the filters manager, and repeat until
/// no more blocks are requested. Blocks are processed in height order, like
/// the real `BlocksPipeline`.
async fn drive_to_quiescence(
    manager: &mut CjFiltersManager,
    wallet: &Arc<RwLock<WalletManager<ManagedWalletInfo>>>,
    blocks: &HashMap<BlockHash, Block>,
    initial_events: Vec<SyncEvent>,
) {
    let (tx, _rx) = unbounded_channel();
    let requests = RequestSender::new(tx);

    let mut events = initial_events;
    for _round in 0..64 {
        let mut pending: BTreeMap<(u32, BlockHash), BTreeSet<WalletId>> = BTreeMap::new();
        for event in events.drain(..) {
            if let SyncEvent::BlocksNeeded {
                blocks: needed,
            } = event
            {
                for (key, wallets) in needed {
                    pending.entry((key.height(), *key.hash())).or_default().extend(wallets);
                }
            }
        }
        if pending.is_empty() {
            return;
        }

        let mut next_events = Vec::new();
        for ((height, block_hash), wallets) in pending {
            let block = blocks.get(&block_hash).expect("BlocksNeeded for an unknown test block");
            let result = wallet
                .write()
                .await
                .process_block_for_wallets(block, block_hash, height, &wallets)
                .await;
            let confirmed_txids = result.relevant_txids().cloned().collect();
            let event = SyncEvent::BlockProcessed {
                block_hash,
                height,
                wallets,
                new_scripts: result.new_scripts,
                confirmed_txids,
            };
            next_events.extend(
                manager.handle_sync_event(&event, &requests).await.expect("BlockProcessed"),
            );
        }
        events = next_events;
    }
    panic!("drive_to_quiescence did not settle within 64 rounds — runaway rescan loop?");
}

/// The empirical stall-at-59 shape: block A funds CoinJoin External indices
/// 0..=51, the NEXT block funds 52..=139, both inside one active batch.
/// Before PR #820 the `(wallet, block)` gate stopped discovery at index 59
/// (29 initial + one 30-wide gap extension); the commit-time fixpoint rescan
/// now climbs the whole dense range. Regression guard for #820.
#[tokio::test]
async fn coinjoin_gap_limit_dense_same_batch_recovers() {
    let (mut manager, wallet, wallet_id) = setup().await;
    let addresses = coinjoin_external_addresses(&wallet, &wallet_id, 140).await;

    let (highest_used, highest_generated, _) = coinjoin_pool_state(&wallet, &wallet_id).await;
    assert_eq!(highest_used, None, "fresh wallet must have no used CoinJoin indices");
    assert_eq!(
        highest_generated,
        Some(DEFAULT_COINJOIN_GAP_LIMIT - 1),
        "fresh wallet must watch exactly the initial CoinJoin gap window"
    );

    let (block_a, filter_a, key_a) = block_paying(10, &addresses[0..=51]);
    let (block_b, filter_b, key_b) = block_paying(11, &addresses[52..=139]);
    let blocks: HashMap<BlockHash, Block> =
        HashMap::from([(block_a.block_hash(), block_a), (block_b.block_hash(), block_b)]);

    let mut batch = FiltersBatch::new(0, 99, HashMap::from([(key_a, filter_a), (key_b, filter_b)]));
    batch.mark_verified();
    manager.active_batches.insert(0, batch);
    manager.progress.update_stored_height(99);

    let initial_events = manager.try_process_batch().await.unwrap();
    drive_to_quiescence(&mut manager, &wallet, &blocks, initial_events).await;

    let (highest_used, _, used_count) = coinjoin_pool_state(&wallet, &wallet_id).await;
    assert_eq!(
        highest_used,
        Some(139),
        "dense same-batch CoinJoin range must be fully discovered via the commit-time \
         fixpoint rescan (PR #820); a stall at Some(59) means the (wallet, block) \
         once-per-block gate regressed. used_count={used_count}"
    );
    assert_eq!(used_count, 140, "every funded index 0..=139 must be marked used");
}

/// Height inversion INSIDE one active batch: indices 40..=51 are funded at
/// height 10, the in-window indices 0..=29 only at height 20. The initial
/// scan cannot see block A (nothing watched matches it), but once block B's
/// processing derives 30..=59 the commit-time rescan re-tests block A's
/// filter and recovers it. GREEN since #820 — contrast for the RED
/// cross-batch test below, isolating the commit boundary as the broken seam.
#[tokio::test]
async fn coinjoin_gap_limit_inversion_within_batch_recovers() {
    let (mut manager, wallet, wallet_id) = setup().await;
    let addresses = coinjoin_external_addresses(&wallet, &wallet_id, 60).await;

    let (block_a, filter_a, key_a) = block_paying(10, &addresses[40..=51]);
    let (block_b, filter_b, key_b) = block_paying(20, &addresses[0..=29]);
    let blocks: HashMap<BlockHash, Block> =
        HashMap::from([(block_a.block_hash(), block_a), (block_b.block_hash(), block_b)]);

    let mut batch = FiltersBatch::new(0, 99, HashMap::from([(key_a, filter_a), (key_b, filter_b)]));
    batch.mark_verified();
    manager.active_batches.insert(0, batch);
    manager.progress.update_stored_height(99);

    let initial_events = manager.try_process_batch().await.unwrap();
    drive_to_quiescence(&mut manager, &wallet, &blocks, initial_events).await;

    let (highest_used, _, used_count) = coinjoin_pool_state(&wallet, &wallet_id).await;
    assert_eq!(
        highest_used,
        Some(51),
        "a gap-window output in an earlier block of the SAME active batch must be \
         recovered by the commit-time rescan (PR #820). used_count={used_count}"
    );
}

/// Gap-window outputs in an already-COMMITTED batch (#846).
///
/// Same funding shape as the within-batch inversion test, but the early
/// block (indices 40..=51, height 10) sits in batch 0..=99 while the
/// in-window block (indices 0..=29) sits at height 110 in batch 100..=199.
/// Batch 0 scans clean (nothing watched matches) and commits. Processing the
/// height-110 block derives 30..=59, and those scripts DO match block 10's
/// filter — but `rescan_batch` only reaches `active_batches`, and committed
/// batches are gone (`try_commit_batches` removes them; the tracker prunes
/// at-or-below the committed height). Indices 40..=51 — squarely inside the
/// BIP-44/CoinJoin gap-limit recovery contract (40 < 29 + 1 + 30) — used to
/// stay invisible forever, along with their funds; a fresh re-sync from
/// genesis hit the same wall deterministically.
///
/// GREEN since `rescan_committed_range`: newly derived scripts are re-tested
/// against the persisted filters below the committing batch (BIP-158 filters
/// are address-independent, so re-matching needs no re-download), and hits
/// flow through the `track_for_new_scripts` re-download path to the same
/// commit-time fixpoint. `highest_used` reaches 51.
#[tokio::test]
async fn coinjoin_gap_limit_stall_across_committed_batch() {
    let (mut manager, wallet, wallet_id) = setup().await;
    let addresses = coinjoin_external_addresses(&wallet, &wallet_id, 60).await;

    let (block_a, filter_a, key_a) = block_paying(10, &addresses[40..=51]);
    let (block_b, filter_b, key_b) = block_paying(110, &addresses[0..=29]);

    // Uphold the production invariant the injected batches imply: every
    // height at or below `stored_height` has its header and filter
    // persisted (store_and_match_batches stores a batch's filters before
    // stored_height advances past it). The committed-range recovery path
    // re-tests exactly this stored data, so the invariant is load-bearing
    // here: batch 0 commits before block B's processing derives the missing
    // scripts, and by then its in-memory filters are gone.
    {
        let mut header_storage = manager.header_storage.write().await;
        let mut filter_storage = manager.filter_storage.write().await;
        for height in 0..=99u32 {
            let (header, filter_bytes) = if height == 10 {
                (block_a.header, filter_a.content.clone())
            } else {
                let filler = Block::dummy(height, vec![]);
                let filter = BlockFilter::dummy(&filler);
                (filler.header, filter.content)
            };
            header_storage
                .store_headers_at_height(&[header.into()], height)
                .await
                .expect("seed header");
            filter_storage.store_filter(height, &filter_bytes).await.expect("seed filter");
        }
    }

    let blocks: HashMap<BlockHash, Block> =
        HashMap::from([(block_a.block_hash(), block_a), (block_b.block_hash(), block_b)]);

    let mut batch_0 = FiltersBatch::new(0, 99, HashMap::from([(key_a, filter_a)]));
    batch_0.mark_verified();
    manager.active_batches.insert(0, batch_0);
    let mut batch_1 = FiltersBatch::new(100, 199, HashMap::from([(key_b, filter_b)]));
    batch_1.mark_verified();
    manager.active_batches.insert(100, batch_1);
    manager.progress.update_stored_height(199);

    let initial_events = manager.try_process_batch().await.unwrap();
    drive_to_quiescence(&mut manager, &wallet, &blocks, initial_events).await;

    let (highest_used, highest_generated, used_count) =
        coinjoin_pool_state(&wallet, &wallet_id).await;
    // Sanity: the in-window block was found and the gap window extended past
    // index 51, so the missed indices ARE inside the watched range by now.
    assert!(
        highest_generated >= Some(51),
        "gap maintenance must have extended the watch window past index 51 \
         (got {highest_generated:?})"
    );
    assert_eq!(
        highest_used,
        Some(51),
        "CoinJoin External indices 40..=51 were funded at height 10 in a batch that \
         committed before their scripts were derived, and the new-script rescan never \
         looks below the committed boundary (rescan_batch only reaches active_batches; \
         BlockMatchTracker/commit pruning drops the range). The addresses are within \
         the gap-limit recovery contract and are watched now (highest_generated = \
         {highest_generated:?}), yet their outputs stay invisible: highest_used stalls \
         at {highest_used:?}, used_count={used_count}. Fix direction: key re-scan \
         suppression by (wallet, address/script) instead of block/commit progress, or \
         trigger a below-committed-height rescan for a wallet whose gap maintenance \
         derives scripts mid-sync."
    );
}
