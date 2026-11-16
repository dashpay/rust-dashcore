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
//! These tests pin the fixed behaviour:
//!
//! 1. [`coinjoin_gap_limit_dense_same_batch_recovers`] — the empirical
//!    stall-at-59 shape (two dense blocks in one batch). GREEN since #820;
//!    kept as a regression guard.
//! 2. [`coinjoin_gap_limit_inversion_within_batch_recovers`] — a gap-window
//!    output in an EARLIER block of the SAME (still-active) batch is
//!    recovered by the commit-time rescan. GREEN since #820.
//! 3. [`coinjoin_rescan_skips_blocks_applied_after_the_scripts`] — the
//!    rescan re-applies only blocks whose last pass predates the matching
//!    scripts.
//! 4. [`provider_wallet_rescans_only_untested_outpoints`] — a rescan matches a
//!    batch only against the UTXO outpoints it was never matched against.
//! 5. [`provider_wallet_rescan_prefers_an_untested_outpoint_over_an_older_script`]
//!    — an untested outpoint re-applies a block even when an older script
//!    group also matches it.
//! 6. [`coinjoin_scripts_derived_in_one_batch_find_blocks_in_the_next`] —
//!    scripts derived by the lowest batch are deferred to the next batch and
//!    still find its blocks before it commits.
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
use crate::test_utils::MockNetworkManager;
use dashcore::bip158::BlockFilterWriter;
use dashcore::consensus::encode::serialize;
use dashcore::{
    Address, Block, BlockHash, Network, OutPoint, Transaction, TxIn, TxOut, Txid, Witness,
};
use key_wallet::account::ManagedAccountTrait;
use key_wallet::gap_limit::DEFAULT_COINJOIN_GAP_LIMIT;
use key_wallet::managed_account::address_pool::{AddressPool, AddressPoolType};
use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::test_utils::coinjoin_external_addresses;
use key_wallet_manager::WalletManager;

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
        0,
    )
    .await;
    manager.set_state(SyncState::Syncing);
    (manager, wallet, wallet_id)
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

/// The filter of `block` with `elements` added to its output scripts, the way
/// Dash Core adds a `ProRegTx`'s collateral outpoint.
fn filter_with_elements(block: &Block, elements: &[Vec<u8>]) -> BlockFilter {
    let mut content = Vec::new();
    let mut writer = BlockFilterWriter::new(&mut content, block);
    writer.add_output_scripts();
    for element in elements {
        writer.add_element(element);
    }
    writer.finish().expect("write test filter");
    BlockFilter::new(&content)
}

/// Drive the production event loop to quiescence: consume `BlocksNeeded` by
/// processing the named blocks through the real wallet (the blocks-manager's
/// job), feed the resulting `BlockProcessed` events (carrying the wallet's
/// freshly derived scripts) back into the filters manager, and repeat until
/// no more blocks are requested. Blocks are processed in height order, like
/// the real `BlocksPipeline`, and the manager ticks once per round. Returns how
/// often each block was applied.
async fn drive_to_quiescence(
    manager: &mut CjFiltersManager,
    wallet: &Arc<RwLock<WalletManager<ManagedWalletInfo>>>,
    blocks: &HashMap<BlockHash, Block>,
    initial_events: Vec<SyncEvent>,
) -> HashMap<BlockHash, usize> {
    let network: Arc<dyn NetworkManager> = Arc::new(MockNetworkManager::new());

    let mut passes: HashMap<BlockHash, usize> = HashMap::new();
    let mut events = initial_events;
    for _round in 0..64 {
        events.extend(manager.tick(&network).await.expect("tick"));
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
            return passes;
        }

        let mut next_events = Vec::new();
        for ((height, block_hash), wallets) in pending {
            let block = blocks.get(&block_hash).expect("BlocksNeeded for an unknown test block");
            let result = wallet
                .write()
                .await
                .process_block_for_wallets(block, block_hash, height, &wallets)
                .await;
            *passes.entry(block_hash).or_default() += 1;
            let confirmed_txids = result.relevant_txids().cloned().collect();
            let event = SyncEvent::BlockProcessed {
                block_hash,
                height,
                wallets,
                new_scripts: result.new_scripts,
                confirmed_txids,
            };
            next_events
                .extend(manager.handle_sync_event(&event, &network).await.expect("BlockProcessed"));
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
    let addresses = coinjoin_external_addresses(&*wallet.read().await, &wallet_id, (G + 40) as u32);

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
/// since #820.
#[tokio::test]
async fn coinjoin_gap_limit_inversion_within_batch_recovers() {
    let (mut manager, wallet, wallet_id) = setup().await;
    let addresses = coinjoin_external_addresses(&*wallet.read().await, &wallet_id, (G + 22) as u32);

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

/// Block A pays G+2 in its first transaction and index 5 in its second. Using
/// index 5 derives G+2, and the same application checks the block again, so A
/// is applied once. Block B pays index 1 and G+3 and is applied after A derived
/// G+3, so its first pass already credited G+3 and the rescan must not apply it again.
#[tokio::test]
async fn coinjoin_rescan_skips_blocks_applied_after_the_scripts() {
    let (mut manager, wallet, wallet_id) = setup().await;
    let addresses = coinjoin_external_addresses(&*wallet.read().await, &wallet_id, (G + 4) as u32);

    let (pays_g2, _, _) = block_paying(10, &[addresses[G + 2].clone()]);
    let (pays_5, _, _) = block_paying(11, &[addresses[5].clone()]);
    let block_a = Block::dummy(10, vec![pays_g2.txdata[0].clone(), pays_5.txdata[0].clone()]);
    let (filter_a, key_a) =
        (BlockFilter::dummy(&block_a), FilterMatchKey::new(10, block_a.block_hash()));
    let (block_b, filter_b, key_b) =
        block_paying(20, &[addresses[1].clone(), addresses[G + 3].clone()]);
    let (hash_a, hash_b) = (block_a.block_hash(), block_b.block_hash());
    let blocks: HashMap<BlockHash, Block> = HashMap::from([(hash_a, block_a), (hash_b, block_b)]);

    let mut batch = FiltersBatch::new(0, 99, HashMap::from([(key_a, filter_a), (key_b, filter_b)]));
    batch.mark_verified();
    manager.active_batches.insert(0, batch);
    manager.progress.update_stored_height(99);

    let initial_events = manager.try_process_batch().await.unwrap();
    let passes = drive_to_quiescence(&mut manager, &wallet, &blocks, initial_events).await;

    let (highest_used, _, used_count) = coinjoin_pool_state(&wallet, &wallet_id).await;
    assert_eq!(highest_used, Some((G + 3) as u32));
    assert_eq!(used_count, 4, "indices 1, 5, G+2 and G+3 must all be credited");
    let balance = wallet.read().await.get_wallet_balance(&wallet_id).expect("balance");
    assert_eq!(balance.confirmed(), 4 * DENOMINATION);
    assert_eq!(passes.get(&hash_a), Some(&1), "A credits the scripts it derived itself");
    assert_eq!(passes.get(&hash_b), Some(&1), "B was applied after G+3 was derived");
}

/// Runs one batch of `blocks` at `batch_start` through scan, block passes and
/// commit, returning how often each block was applied.
async fn run_batch(
    manager: &mut CjFiltersManager,
    wallet: &Arc<RwLock<WalletManager<ManagedWalletInfo>>>,
    batch_start: u32,
    blocks: Vec<(Block, BlockFilter, FilterMatchKey)>,
) -> HashMap<BlockHash, usize> {
    let batch_end = batch_start + 99;
    let filters = blocks.iter().map(|(_, filter, key)| (key.clone(), filter.clone())).collect();
    let mut batch = FiltersBatch::new(batch_start, batch_end, filters);
    batch.mark_verified();
    manager.active_batches.insert(batch_start, batch);
    manager.progress.update_stored_height(batch_end);

    let blocks = blocks.into_iter().map(|(block, _, _)| (block.block_hash(), block)).collect();
    let initial_events = manager.try_process_batch().await.unwrap();
    let passes = drive_to_quiescence(manager, wallet, &blocks, initial_events).await;
    assert!(!manager.active_batches.contains_key(&batch_start), "the batch must commit");
    passes
}

/// A provider wallet watches every UTXO outpoint, which a `ProRegTx` adds to
/// its block's filter as collateral. A rescan matches a batch only against the
/// outpoints the batch was never matched against, so a block is not applied
/// again for an outpoint its pass already knew.
#[tokio::test]
async fn provider_wallet_rescans_only_untested_outpoints() {
    let (mut manager, wallet, wallet_id) = setup().await;
    let addresses = coinjoin_external_addresses(&*wallet.read().await, &wallet_id, 7);

    // Batch 0: A creates the outpoint the later batches refer to.
    let (block_a, filter_a, key_a) = block_paying(10, &[addresses[5].clone()]);
    let outpoint_a = serialize(&OutPoint::new(block_a.txdata[0].txid(), 0));
    run_batch(&mut manager, &wallet, 0, vec![(block_a, filter_a, key_a)]).await;
    let elements = wallet.read().await.monitored_filter_elements_for(&wallet_id);
    assert!(elements.contains(&outpoint_a), "a provider wallet watches its UTXO outpoints");

    // Batch 1: B creates an outpoint without deriving an address, and E matches
    // only that outpoint. Only the commit-time reconcile can find E.
    let b = block_paying(110, &[addresses[2].clone()]);
    let outpoint_b = serialize(&OutPoint::new(b.0.txdata[0].txid(), 0));
    let (block_e, _, key_e) = block_paying(130, &[]);
    let filter_e = filter_with_elements(&block_e, &[outpoint_b]);
    let hash_e = block_e.block_hash();
    let passes = run_batch(&mut manager, &wallet, 100, vec![b, (block_e, filter_e, key_e)]).await;
    assert_eq!(passes.get(&hash_e), Some(&1), "E matches only the outpoint B created");

    // Batch 2 is scanned with A's outpoint, so C's pass knows it. D derives an
    // address, which rescans the batch before it commits.
    let (block_c, _, key_c) = block_paying(210, &[addresses[1].clone()]);
    let filter_c = filter_with_elements(&block_c, &[outpoint_a]);
    let hash_c = block_c.block_hash();
    let d = block_paying(220, &[addresses[6].clone()]);
    let passes = run_batch(&mut manager, &wallet, 200, vec![(block_c, filter_c, key_c), d]).await;
    assert_eq!(passes.get(&hash_c), Some(&1), "C already knew A's outpoint");
}

/// Block X pays index G+3, which block A derived in an earlier pass, so X's
/// pass already credited it. X's filter also carries the outpoint that block Z
/// creates after X's pass. The rescan matches both, and the outpoint must win:
/// X is applied again, since no pass of X saw that outpoint.
#[tokio::test]
async fn provider_wallet_rescan_prefers_an_untested_outpoint_over_an_older_script() {
    let (mut manager, wallet, wallet_id) = setup().await;
    let addresses = coinjoin_external_addresses(&*wallet.read().await, &wallet_id, (G + 4) as u32);

    let a = block_paying(10, &[addresses[5].clone()]);
    let z = block_paying(30, &[addresses[2].clone()]);
    let outpoint_z = serialize(&OutPoint::new(z.0.txdata[0].txid(), 0));
    let (block_x, _, key_x) = block_paying(20, &[addresses[1].clone(), addresses[G + 3].clone()]);
    let filter_x = filter_with_elements(&block_x, &[outpoint_z]);
    let hash_x = block_x.block_hash();

    let passes = run_batch(&mut manager, &wallet, 0, vec![a, (block_x, filter_x, key_x), z]).await;
    assert_eq!(passes.get(&hash_x), Some(&2), "X never saw the outpoint Z created");
}

/// Block A in the first batch pays index 5 and G+4, which derives the window
/// up to 2G+4. The next batch was scanned before that, and its blocks pay G+2
/// and G+6. Both are found by the deferred rescan, and every block is applied once.
#[tokio::test]
async fn coinjoin_scripts_derived_in_one_batch_find_blocks_in_the_next() {
    let (mut manager, wallet, wallet_id) = setup().await;
    let addresses = coinjoin_external_addresses(&*wallet.read().await, &wallet_id, (G + 7) as u32);

    let (block_a, filter_a, key_a) =
        block_paying(10, &[addresses[5].clone(), addresses[G + 4].clone()]);
    let (block_b, filter_b, key_b) = block_paying(120, &[addresses[G + 6].clone()]);
    let (block_c, filter_c, key_c) = block_paying(150, &[addresses[G + 2].clone()]);
    let blocks: HashMap<BlockHash, Block> =
        [block_a, block_b, block_c].into_iter().map(|block| (block.block_hash(), block)).collect();

    let mut batch = FiltersBatch::new(0, 99, HashMap::from([(key_a, filter_a)]));
    batch.mark_verified();
    manager.active_batches.insert(0, batch);
    let mut batch =
        FiltersBatch::new(100, 199, HashMap::from([(key_b, filter_b), (key_c, filter_c)]));
    batch.mark_verified();
    manager.active_batches.insert(100, batch);
    manager.progress.update_stored_height(199);

    let initial_events = manager.try_process_batch().await.unwrap();
    let passes = drive_to_quiescence(&mut manager, &wallet, &blocks, initial_events).await;

    let (highest_used, _, used_count) = coinjoin_pool_state(&wallet, &wallet_id).await;
    assert_eq!(highest_used, Some((G + 6) as u32));
    assert_eq!(used_count, 4, "indices 5, G+2, G+4 and G+6 must all be credited");
    let balance = wallet.read().await.get_wallet_balance(&wallet_id).expect("balance");
    assert_eq!(balance.confirmed(), 4 * DENOMINATION);
    assert_eq!(passes.len(), 3);
    assert!(passes.values().all(|count| *count == 1), "each block is applied once: {passes:?}");
    assert!(manager.active_batches.is_empty(), "both batches commit");
    assert_eq!(manager.progress.committed_height(), 199);
}
