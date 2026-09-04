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
//! 4. [`committed_range_sweep_coalesces_across_batch_commits`] — the cost
//!    side of #846's fix: N script-carrying commits share one drain-time
//!    committed-range sweep instead of walking the stored history once per
//!    commit, while a late-derived script still finds its
//!    committed-prefix block before `FiltersSyncComplete`.
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
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::WalletManager;
use tokio::sync::mpsc::unbounded_channel;

/// Deterministic test wallet seed (standard BIP-39 test vector mnemonic).
const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// CoinJoin-denomination-shaped output value (0.001 DASH + per-round fee).
/// The matcher is purely script-based; the value is for realism only.
const DENOMINATION: u64 = 100_001;

/// The initial CoinJoin watch window is `0..G`. Every funded index range
/// below is expressed relative to `G` so the tests keep pinning the
/// beyond-the-window shapes they were written for even when the default gap
/// changes (it moved 30 -> 100 in #868, which would otherwise have silently
/// turned the cross-commit repro into a trivially-green test).
const G: usize = DEFAULT_COINJOIN_GAP_LIMIT as usize;

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

/// The empirical dense stall shape (stall-at-59 under the original gap of
/// 30): block A funds CoinJoin External indices 0..=51, the NEXT block funds
/// 52..=G+39 — the tail extends a full window past the initial one, so
/// discovery must climb through at least one gap extension. Before PR #820
/// the `(wallet, block)` gate stopped discovery at the first extension; the
/// commit-time fixpoint rescan now climbs the whole dense range. Regression
/// guard for #820.
#[tokio::test]
async fn coinjoin_gap_limit_dense_same_batch_recovers() {
    let (mut manager, wallet, wallet_id) = setup().await;
    let addresses = coinjoin_external_addresses(&wallet, &wallet_id, (G + 40) as u32).await;

    let (highest_used, highest_generated, _) = coinjoin_pool_state(&wallet, &wallet_id).await;
    assert_eq!(highest_used, None, "fresh wallet must have no used CoinJoin indices");
    assert_eq!(
        highest_generated,
        Some(DEFAULT_COINJOIN_GAP_LIMIT - 1),
        "fresh wallet must watch exactly the initial CoinJoin gap window"
    );

    let (block_a, filter_a, key_a) = block_paying(10, &addresses[0..=51]);
    let (block_b, filter_b, key_b) = block_paying(11, &addresses[52..=(G + 39)]);
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
        Some((G + 39) as u32),
        "dense same-batch CoinJoin range must be fully discovered via the commit-time \
         fixpoint rescan (PR #820); a stall at the first gap extension means the \
         (wallet, block) once-per-block gate regressed. used_count={used_count}"
    );
    assert_eq!(used_count, G + 40, "every funded index 0..=G+39 must be marked used");
}

/// Height inversion INSIDE one active batch: indices G+10..=G+21 (beyond the
/// initial watch window) are funded at height 10, in-window indices 0..=29
/// only at height 20. The initial scan cannot see block A (nothing watched
/// matches it), but once block B's processing extends the window past G+21
/// the commit-time rescan re-tests block A's filter and recovers it. GREEN
/// since #820 — contrast for the cross-batch test below, isolating the
/// commit boundary as the broken seam.
#[tokio::test]
async fn coinjoin_gap_limit_inversion_within_batch_recovers() {
    let (mut manager, wallet, wallet_id) = setup().await;
    let addresses = coinjoin_external_addresses(&wallet, &wallet_id, (G + 22) as u32).await;

    let (block_a, filter_a, key_a) = block_paying(10, &addresses[(G + 10)..=(G + 21)]);
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
        Some((G + 21) as u32),
        "a gap-window output in an earlier block of the SAME active batch must be \
         recovered by the commit-time rescan (PR #820). used_count={used_count}"
    );
}

/// Backward coverage across a committed batch is a durable rewind, not an
/// in-memory sweep.
///
/// Block A (height 10, batch 0) funds CoinJoin External indices G+10..=G+21,
/// beyond the initial gap window; block B (height 110, batch 1) funds
/// 0..=29 and its processing derives the scripts that would have matched
/// block A — after batch 0 has already committed. At the forward drain the
/// manager must not sweep the committed range in memory (an iOS suspension
/// drops such a sweep whole) but rewind the wallet's `synced_height` so the
/// sync-manager tick re-walks committed history in persisted batches, and
/// it must NOT declare the filters complete while that re-walk is pending:
/// one "synced" cycle with the walk still to run is exactly what the host
/// would mistake for a caught-up wallet. Once the wallet is back at the
/// committed frontier, completion is emitted.
///
/// The tick itself does not run in this harness, so the re-walk is
/// represented by advancing the wallet's checkpoint by hand.
#[tokio::test]
async fn backward_coverage_rewinds_and_holds_completion_until_rewalked() {
    let (mut manager, wallet, wallet_id) = setup().await;
    let addresses = coinjoin_external_addresses(&wallet, &wallet_id, (G + 22) as u32).await;

    let (block_a, filter_a, key_a) = block_paying(10, &addresses[(G + 10)..=(G + 21)]);
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

    let (_, highest_generated, _) = coinjoin_pool_state(&wallet, &wallet_id).await;
    assert!(
        highest_generated >= Some((G + 21) as u32),
        "gap maintenance must have extended the watch window past index G+21 \
         (got {highest_generated:?})"
    );

    // The drain rewound the wallet to its own floor instead of sweeping.
    let (synced_height, birth_height) = {
        let reader = wallet.read().await;
        let info = reader.get_wallet_info(&wallet_id).expect("wallet info");
        (info.synced_height(), info.birth_height())
    };
    assert_eq!(
        synced_height,
        birth_height.saturating_sub(1),
        "wallet synced_height must be rewound to birth_height - 1 for the durable re-walk"
    );
    assert!(manager.rewalk_pending().await, "a re-walk must be pending after the rewind");
    assert_eq!(
        manager.state(),
        SyncState::Syncing,
        "filters must not be declared complete while a rewound wallet is below the frontier"
    );

    // Stand in for the tick's re-walk: the wallet catches up to the
    // committed frontier. Only now may the filters complete.
    let committed = manager.progress.committed_height();
    wallet.write().await.update_wallet_synced_height(&wallet_id, committed);
    assert!(!manager.rewalk_pending().await);
    let events = manager.try_process_batch().await.unwrap();
    assert!(
        events.iter().any(|e| matches!(e, SyncEvent::FiltersSyncComplete { .. })),
        "FiltersSyncComplete must be emitted once the rewound wallet has caught up"
    );
    assert_eq!(manager.state(), SyncState::Synced);
}

/// Committed-range sweeps coalesce across batch commits.
///
/// Four batches; the last three each contain one in-window block whose
/// processing derives new scripts (each funds the next run of CoinJoin
/// indices, so gap maintenance extends the watch window at every commit).
/// Per-commit sweeping walks the entire committed prefix once per
/// script-carrying commit — on a real mainnet restore that shape produced
/// 191 full-prefix sweeps totalling ~14.5 minutes. Coalesced, the
/// accumulated scripts cross the stored history when the forward pipeline
/// drains: one sweep, plus one follow-up round for the scripts derived from
/// the block that sweep recovers.
///
/// The early block (height 10, beyond-window indices G+10..=G+21, unwatched
/// when its batch scans and commits) pins the #846 correctness contract at
/// the same time: the deferred sweep must still find it, and
/// `FiltersSyncComplete` must not be emitted before it has been found and
/// applied. `committed_range_sweeps` counts sweeps that reach the chunk walk
/// in `rescan_committed_range`.
#[tokio::test]
#[ignore = "backward coverage no longer sweeps the committed range in the \
manager; it rewinds the wallet and the sync-manager tick re-walks, which this \
harness cannot drive. The coalescing this test measured has no counterpart \
now — see backward_coverage_rewinds_and_holds_completion_until_rewalked for \
the contract that replaced it. Remove together with rescan_committed_range."]
async fn committed_range_sweep_coalesces_across_batch_commits() {
    let (mut manager, wallet, wallet_id) = setup().await;
    let addresses = coinjoin_external_addresses(&wallet, &wallet_id, (G + 22) as u32).await;

    // Beyond-window block in the range that commits first (#846 shape).
    let (block_early, filter_early, key_early) = block_paying(10, &addresses[(G + 10)..=(G + 21)]);
    // One in-window block per later batch. Each extends `highest_used` by 30,
    // so every one of these batches carries newly derived scripts into its
    // commit. After block 110 the generated window reaches 29 + G >= G + 21,
    // so the early block's scripts are among the first commit's derivations.
    let (block_1, filter_1, key_1) = block_paying(110, &addresses[0..=29]);
    let (block_2, filter_2, key_2) = block_paying(210, &addresses[30..=59]);
    let (block_3, filter_3, key_3) = block_paying(310, &addresses[60..=89]);

    // Persist headers and filters for the committed prefix 0..=299 — the
    // range the drain-time sweep reloads from storage. Real data at the
    // three block heights, filler elsewhere.
    {
        let mut header_storage = manager.header_storage.write().await;
        let mut filter_storage = manager.filter_storage.write().await;
        for height in 0..=299u32 {
            let (header, filter_bytes) = match height {
                10 => (block_early.header, filter_early.content.clone()),
                110 => (block_1.header, filter_1.content.clone()),
                210 => (block_2.header, filter_2.content.clone()),
                _ => {
                    let filler = Block::dummy(height, vec![]);
                    let filter = BlockFilter::dummy(&filler);
                    (filler.header, filter.content)
                }
            };
            header_storage
                .store_headers_at_height(&[header.into()], height)
                .await
                .expect("seed header");
            filter_storage.store_filter(height, &filter_bytes).await.expect("seed filter");
        }
    }

    let blocks: HashMap<BlockHash, Block> = HashMap::from([
        (block_early.block_hash(), block_early),
        (block_1.block_hash(), block_1),
        (block_2.block_hash(), block_2),
        (block_3.block_hash(), block_3),
    ]);

    for (start, filters) in [
        (0u32, HashMap::from([(key_early, filter_early)])),
        (100, HashMap::from([(key_1, filter_1)])),
        (200, HashMap::from([(key_2, filter_2)])),
        (300, HashMap::from([(key_3, filter_3)])),
    ] {
        let mut batch = FiltersBatch::new(start, start + 99, filters);
        batch.mark_verified();
        manager.active_batches.insert(start, batch);
    }
    manager.progress.update_stored_height(399);
    // Both halves of the drain gate have to be live, or the test only proves
    // the `active_batches.len() == 1` half: with the tips left at their
    // default 0, `end_height() >= filter_header_tip_height()` is trivially
    // true and the comparison that keeps the sweep from firing while more
    // batches are still to come is never exercised. Same for the target
    // height, which `FiltersSyncComplete` is checked against below.
    manager.progress.update_filter_header_tip_height(399);
    manager.progress.update_target_height(399);

    // Drive the production event loop to quiescence like `drive_to_quiescence`
    // does, additionally watching for `FiltersSyncComplete` so the completion
    // contract can be asserted at the moment it is emitted.
    let (tx, _rx) = unbounded_channel();
    let requests = RequestSender::new(tx);
    let mut events = manager.try_process_batch().await.unwrap();
    let mut sync_complete_seen = false;
    'rounds: for _round in 0..64 {
        let mut pending: BTreeMap<(u32, BlockHash), BTreeSet<WalletId>> = BTreeMap::new();
        for event in events.drain(..) {
            match event {
                SyncEvent::BlocksNeeded {
                    blocks: needed,
                } => {
                    for (key, wallets) in needed {
                        pending.entry((key.height(), *key.hash())).or_default().extend(wallets);
                    }
                }
                SyncEvent::FiltersSyncComplete {
                    ..
                } => {
                    let (highest_used, _, _) = coinjoin_pool_state(&wallet, &wallet_id).await;
                    assert_eq!(
                        highest_used,
                        Some((G + 21) as u32),
                        "FiltersSyncComplete emitted before the deferred committed-range \
                         sweep recovered the height-10 block: a script derived after its \
                         range committed was never tested against the committed prefix"
                    );
                    sync_complete_seen = true;
                }
                _ => {}
            }
        }
        if pending.is_empty() {
            break 'rounds;
        }
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
            events.extend(
                manager.handle_sync_event(&event, &requests).await.expect("BlockProcessed"),
            );
        }
    }

    assert!(sync_complete_seen, "the run must reach FiltersSyncComplete");

    let (highest_used, _, used_count) = coinjoin_pool_state(&wallet, &wallet_id).await;
    assert_eq!(
        highest_used,
        Some((G + 21) as u32),
        "the height-10 block's beyond-window outputs must be recovered by the \
         drain-time committed-range sweep (used_count={used_count})"
    );
    assert_eq!(used_count, 90 + 12, "indices 0..=89 and G+10..=G+21 must all be marked used");

    assert!(
        manager.committed_range_sweeps >= 1,
        "the deferred committed-range sweep must still run before completion"
    );
    assert!(
        manager.committed_range_sweeps <= 2,
        "three script-carrying batch commits must share the committed-range sweep \
         (one drain-time sweep plus one follow-up round for the scripts derived from \
         the recovered block); got {} sweeps — one sweep per commit means the \
         coalescing regressed",
        manager.committed_range_sweeps
    );
}
