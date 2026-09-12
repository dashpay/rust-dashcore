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

/// Gap-window outputs in an already-COMMITTED batch (#846).
///
/// Same funding shape as the within-batch inversion test, but the early
/// block (indices G+10..=G+21, height 10) sits in batch 0..=99 while the
/// in-window block (indices 0..=29) sits at height 110 in batch 100..=199.
/// Batch 0 scans clean (nothing watched matches) and commits. Processing the
/// height-110 block extends the window past G+21, and those scripts DO match
/// block 10's filter — but `rescan_batch` only reaches `active_batches`, and
/// committed batches are gone (`try_commit_batches` removes them; the
/// tracker prunes at-or-below the committed height). Indices G+10..=G+21 —
/// squarely inside the BIP-44/CoinJoin gap-limit recovery contract
/// (G+21 < 29 + 1 + G) — used to stay invisible forever, along with their
/// funds; a fresh re-sync from genesis hit the same wall deterministically.
///
/// GREEN since `rescan_committed_range`: newly derived scripts are re-tested
/// against the persisted filters below the committing batch (BIP-158 filters
/// are address-independent, so re-matching needs no re-download), and hits
/// flow through the `track_for_new_scripts` re-download path to the same
/// commit-time fixpoint. `highest_used` reaches G+21.
#[tokio::test]
async fn coinjoin_gap_limit_stall_across_committed_batch() {
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

    let (highest_used, highest_generated, used_count) =
        coinjoin_pool_state(&wallet, &wallet_id).await;
    // Sanity: the in-window block was found and the gap window extended past
    // index G+21, so the missed indices ARE inside the watched range by now.
    assert!(
        highest_generated >= Some((G + 21) as u32),
        "gap maintenance must have extended the watch window past index G+21 \
         (got {highest_generated:?})"
    );
    assert_eq!(
        highest_used,
        Some((G + 21) as u32),
        "CoinJoin External indices G+10..=G+21 were funded at height 10 in a batch that \
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

/// block A (height 10, batch 0..=99) pays beyond-window indices G+10..=G+21;
/// block B (height 110, batch 100..=199) pays in-window indices 0..=29.
/// Batch 0 scans clean and COMMITS. Processing block B derives the missing
/// scripts — at which point the session "crashes": the manager is dropped
/// before the backward sweep's re-downloaded block is processed. The
/// in-memory cascade is gone, batch 0 is committed, and nothing in a
/// restarted session would ever look below the committed boundary again.
///
/// The durable pending-sweep set closes this: the scripts were persisted to
/// metadata storage the moment they entered the manager, a restarted manager
/// (same storage, `with_metadata`) reloads them, seeds them into its lowest
/// active batch, and the ordinary commit-time cascade re-tests the stored
/// filters below the committed boundary — recovering block A's outputs.
#[tokio::test]
async fn interrupted_sweep_is_replayed_after_restart() {
    // Shared across the "restart": wallet (its pools/synced heights persist
    // in the real system via the SDK store) and disk storage (headers,
    // filters, metadata).
    let mut wm = WalletManager::<ManagedWalletInfo>::new(Network::Regtest);
    let wallet_id = wm
        .create_wallet_from_mnemonic(TEST_MNEMONIC, 0, WalletAccountCreationOptions::Default)
        .expect("create deterministic test wallet");
    let wallet = Arc::new(RwLock::new(wm));
    let storage = DiskStorageManager::with_temp_dir().await.unwrap();

    let addresses = coinjoin_external_addresses(&wallet, &wallet_id, (G + 22) as u32).await;
    let (block_a, filter_a, key_a) = block_paying(10, &addresses[(G + 10)..=(G + 21)]);
    let (block_b, filter_b, key_b) = block_paying(110, &addresses[0..=29]);
    let blocks: HashMap<BlockHash, Block> =
        HashMap::from([(block_a.block_hash(), block_a.clone()), (block_b.block_hash(), block_b)]);

    // Persist headers+filters for the to-be-committed range (see the
    // invariant note in the cross-committed-batch test).
    {
        let headers_arc = storage.block_headers();
        let filters_arc = storage.filters();
        let mut header_storage = headers_arc.write().await;
        let mut filter_storage = filters_arc.write().await;
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

    // ── Session 1: batch 0 commits clean, block B derives scripts, CRASH ──
    {
        let mut manager = FiltersManager::new(
            Arc::clone(&wallet),
            storage.block_headers(),
            storage.filter_headers(),
            storage.filters(),
        )
        .await
        .with_metadata(storage.metadata())
        .await;
        manager.set_state(SyncState::Syncing);

        let mut batch_0 = FiltersBatch::new(0, 99, HashMap::from([(key_a, filter_a.clone())]));
        batch_0.mark_verified();
        manager.active_batches.insert(0, batch_0);
        let mut batch_1 =
            FiltersBatch::new(100, 199, HashMap::from([(key_b.clone(), filter_b.clone())]));
        batch_1.mark_verified();
        manager.active_batches.insert(100, batch_1);
        manager.progress.update_stored_height(199);

        // Initial pass: batch 0 matches nothing and commits; batch 1
        // requests block B.
        let initial_events = manager.try_process_batch().await.unwrap();
        let needed: Vec<(u32, BlockHash, BTreeSet<WalletId>)> = initial_events
            .iter()
            .filter_map(|e| match e {
                SyncEvent::BlocksNeeded {
                    blocks: needed,
                } => Some(needed.iter().map(|(k, w)| (k.height(), *k.hash(), w.clone()))),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(needed.len(), 1, "only block B should be requested initially");

        // Process block B once — derives the beyond-window scripts, which
        // the manager must persist durably at this exact moment.
        let (tx, _rx) = unbounded_channel();
        let requests = RequestSender::new(tx);
        for (height, block_hash, wallets) in needed {
            let block = blocks.get(&block_hash).expect("known block");
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
            // The returned events (the sweep's own BlocksNeeded for block A
            // among them) are deliberately DROPPED: the process dies here.
            let _ = manager.handle_sync_event(&event, &requests).await.expect("BlockProcessed");
        }
        // manager dropped — in-memory cascade gone.
    }

    // ── Session 2: fresh manager over the same storage ──
    let mut manager = FiltersManager::new(
        Arc::clone(&wallet),
        storage.block_headers(),
        storage.filter_headers(),
        storage.filters(),
    )
    .await
    .with_metadata(storage.metadata())
    .await;
    manager.set_state(SyncState::Syncing);

    // Production resume recreates batches from the committed frontier up;
    // batch 0 is committed (synced_height advanced), so only batch 1 exists.
    let mut batch_1 = FiltersBatch::new(100, 199, HashMap::from([(key_b, filter_b)]));
    batch_1.mark_verified();
    manager.active_batches.insert(100, batch_1);
    manager.progress.update_stored_height(199);

    let initial_events = manager.try_process_batch().await.unwrap();
    drive_to_quiescence(&mut manager, &wallet, &blocks, initial_events).await;

    let (highest_used, highest_generated, used_count) =
        coinjoin_pool_state(&wallet, &wallet_id).await;
    assert_eq!(
        highest_used,
        Some((G + 21) as u32),
        "block A's outputs sit in a batch that committed before their scripts were \
         derived, and the session died before the backward sweep finished — only the \
         durable pending-sweep set can bring them back after the restart. \
         highest_generated={highest_generated:?}, used_count={used_count}"
    );
}

/// A born-wrong `TransactionRecord` IS corrected by the gap rescan — both
/// in the account and in the emitted event stream. Pins the fix for the
/// kotlin-sdk "TXO-store reconcile" field bug (2026-08-19), where the
/// correction never happened:
///
/// One block carries a funding tx paying in-window index 0 and a self-send
/// spending it, paying index G-1 (in-window) and index G+10 (beyond the
/// initial watch window). First processing records the self-send with the
/// beyond-window output invisible: `net_amount = PAY - FUND` instead of
/// `-fee`, and no `output_details` entry for vout 1 — a record born wrong,
/// projected as-is into every persistence mirror by the emitted events.
/// Marking G-1 used extends the window past G+10, the commit-time rescan
/// (#820) re-matches the block, and re-processing runs `update_utxos`
/// unconditionally — the account's UTXO set self-heals. Before the fix,
/// `confirm_transaction` re-emitted (and mutated) the record only when its
/// *context* changed, so neither the in-memory record nor any event carried
/// the correction; on-device that was the CoinJoin-funded-send shape — the
/// store kept `netAmount` = full input value with the change TXO row
/// missing, and an engine reload from that store made the funds vanish.
/// The test pins the fixed behavior: re-processing corrects the record's
/// net amount and output details, and a corrective event re-emits it.
#[tokio::test]
async fn born_wrong_record_is_corrected_by_gap_rescan() {
    use dashcore::ScriptBuf;
    use key_wallet::managed_account::transaction_record::{OutputRole, TransactionRecord};
    use key_wallet_manager::WalletEvent;

    let (mut manager, wallet, wallet_id) = setup().await;
    let addresses = coinjoin_external_addresses(&wallet, &wallet_id, (G + 11) as u32).await;
    let mut events_rx = wallet.read().await.subscribe_events();

    const FUND: u64 = 1_000_100_000; // 10.001 into in-window index 0
    const PAY: u64 = 50_000_000; // 0.5 back to in-window index G-1
    const HIDDEN: u64 = 950_000_000; // 9.5 to beyond-window index G+10
    const FEE: u64 = FUND - PAY - HIDDEN; // 100_000

    let funding = Transaction {
        version: 1,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from([0xABu8; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: FUND,
            script_pubkey: addresses[0].script_pubkey(),
        }],
        special_transaction_payload: None,
    };
    let send = Transaction {
        version: 1,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint::new(funding.txid(), 0),
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: PAY,
                script_pubkey: addresses[G - 1].script_pubkey(),
            },
            TxOut {
                value: HIDDEN,
                script_pubkey: addresses[G + 10].script_pubkey(),
            },
        ],
        special_transaction_payload: None,
    };
    let send_txid = send.txid();
    let hidden_outpoint = OutPoint::new(send_txid, 1);

    let block = Block::dummy(10, vec![funding, send]);
    let filter = BlockFilter::dummy(&block);
    let key = FilterMatchKey::new(10, block.block_hash());
    let blocks: HashMap<BlockHash, Block> = HashMap::from([(block.block_hash(), block.clone())]);

    let mut batch = FiltersBatch::new(0, 99, HashMap::from([(key, filter)]));
    batch.mark_verified();
    manager.active_batches.insert(0, batch);
    manager.progress.update_stored_height(99);

    let initial_events = manager.try_process_batch().await.unwrap();
    drive_to_quiescence(&mut manager, &wallet, &blocks, initial_events).await;

    {
        let wm = wallet.read().await;
        let info = wm.get_wallet_info(&wallet_id).expect("wallet info present");
        let account =
            info.coinjoin_managed_account_at_index(0).expect("CoinJoin account 0 present");

        // Engine UTXO self-heal — already correct in the field. If this
        // fails, the rescan re-processing itself regressed, which is a
        // different bug than the one this test pins.
        assert!(
            account.utxos.contains_key(&hidden_outpoint),
            "rescan re-processing must insert the beyond-window output into the \
             account UTXO set (update_utxos runs unconditionally in confirm_transaction)"
        );

        // The engine's own record must be corrected by the same re-processing.
        // Note the born-wrong shape is not a MISSING entry: the first
        // processing classified the unattributable output as `Sent`
        // (counterparty), so the correction is a role flip.
        let record =
            account.transactions().get(&send_txid).expect("send record present in account");
        assert!(
            record.output_details.iter().any(
                |o| o.index == 1 && matches!(o.role, OutputRole::Received | OutputRole::Change)
            ),
            "the re-processed record must classify the beyond-window output (vout 1) as \
             ours (Received/Change); a lingering Sent role means every store projection \
             derived from this record drops the TXO. got: {:?}",
            record.output_details,
        );
        assert_eq!(
            record.net_amount,
            -(FEE as i64),
            "the re-processed record's net_amount must be recomputed from the now-\
             complete ownership view (self-send nets -fee); the born-wrong value \
             PAY-FUND = {} is what makes restored balances collapse on reload",
            PAY as i64 - FUND as i64,
        );
    }

    // The persistence mirror is built exclusively from the emitted events:
    // whatever the last record-bearing event said about this txid is what
    // every store on every platform now holds.
    let mut last_record: Option<TransactionRecord> = None;
    while let Ok(event) = events_rx.try_recv() {
        match event {
            WalletEvent::TransactionDetected {
                record,
                ..
            } if record.txid == send_txid => {
                last_record = Some(*record);
            }
            WalletEvent::BlockProcessed {
                inserted,
                updated,
                ..
            } => {
                for r in inserted.into_iter().chain(updated) {
                    if r.txid == send_txid {
                        last_record = Some(r);
                    }
                }
            }
            _ => {}
        }
    }
    let projected = last_record.expect("an event must have carried the send record");
    assert!(
        projected
            .output_details
            .iter()
            .any(|o| o.index == 1 && matches!(o.role, OutputRole::Received | OutputRole::Change)),
        "the LAST emitted record for the send must classify the beyond-window output \
         (vout 1) as ours — the store mirrors are built from these events only, and \
         without a corrective emission (confirm_transaction returning None when only \
         ownership knowledge changed) every mirror keeps the born-wrong Sent role. \
         got: {:?}",
        projected.output_details,
    );
    assert_eq!(
        projected.net_amount,
        -(FEE as i64),
        "the LAST emitted record's net_amount must be the corrected value; the field \
         stores show the born-wrong {} shape (full input value) because no corrective \
         event ever fires",
        PAY as i64 - FUND as i64,
    );
}
