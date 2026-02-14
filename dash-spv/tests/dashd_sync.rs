//! SPV sync tests using dashd.
//!
//! These tests demonstrate realistic SPV sync scenarios against a dashd instance.

use dash_spv::client::interface::DashSpvClientCommand;
use dash_spv::network::NetworkEvent;
use dash_spv::storage::{PeerStorage, PersistentPeerStorage, PersistentStorage};
use dash_spv::test_utils::{copy_dir, DashCoreNode, DashdTestContext};
use dash_spv::{
    client::{ClientConfig, DashSpvClient},
    network::PeerNetworkManager,
    storage::DiskStorageManager,
    sync::{SyncEvent, SyncProgress},
    LevelFilter, LoggingGuard, Network,
};
use dashcore::network::address::AddrV2Message;
use dashcore::network::constants::ServiceFlags;
use dashcore::Amount;
use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::wallet_manager::{WalletId, WalletManager};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::{BTreeSet, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::broadcast;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::watch;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

/// Default timeout for dashd sync tests.
const SYNC_TIMEOUT: u64 = 60;

/// SPV-specific test context wrapping the shared dashd infrastructure.
///
/// Storage and blockchain directories are cleaned up on drop.
/// Set `DASHD_TEST_RETAIN_DIR` to a directory path to retain logs and storage for failed tests.
struct TestContext {
    dashd: DashdTestContext,
    storage_dir: PathBuf,
    client_config: ClientConfig,
    _log_guard: LoggingGuard,
}

impl TestContext {
    async fn new() -> Option<Self> {
        // Create storage dir first so we can set up per-test file logging
        let storage_dir = TempDir::new().expect("Failed to create temporary directory");
        let log_dir = storage_dir.path().join("logs");
        let _log_guard = dash_spv::init_logging(dash_spv::LoggingConfig {
            level: Some(LevelFilter::DEBUG),
            console: std::env::var("DASHD_TEST_LOG").is_ok(),
            file: Some(dash_spv::LogFileConfig {
                log_dir: log_dir.clone(),
                max_files: 1,
            }),
            thread_local: true,
        })
        .expect("Failed to initialize test logging");

        let dashd = DashdTestContext::new().await?;

        // Persist storage dir so it survives test failures (for log inspection)
        let storage_path = storage_dir.keep();
        let client_config = create_test_config(storage_path.clone(), dashd.addr);

        eprintln!(
            "TestContext: addr={}, blocks={}, data={}",
            dashd.addr,
            dashd.expected_height,
            storage_path.display(),
        );

        Some(TestContext {
            dashd,
            storage_dir: storage_path,
            client_config,
            _log_guard,
        })
    }

    fn create_wallet(&self) -> (Arc<RwLock<WalletManager<ManagedWalletInfo>>>, WalletId) {
        create_test_wallet(&self.dashd.wallet.mnemonic, Network::Regtest)
    }
}

impl Drop for TestContext {
    fn drop(&mut self) {
        // Retain test data only for failed tests when DASHD_TEST_RETAIN_DIR is set.
        if std::thread::panicking() {
            if let Ok(retain_dir) = std::env::var("DASHD_TEST_RETAIN_DIR") {
                let test_name = std::thread::current().name().unwrap().to_string();
                let dest = PathBuf::from(&retain_dir).join(&test_name);
                if dest.exists() {
                    let _ = std::fs::remove_dir_all(&dest);
                }
                copy_dir(&self.storage_dir, &dest);
                eprintln!("Test data retained at: {}", dest.display());
            }
        }

        // Clean up the storage directory
        let _ = std::fs::remove_dir_all(&self.storage_dir);
    }
}

// ============================================================================
// Shared Helpers
// ============================================================================

/// Type alias for the SPV client used in tests.
type TestClient =
    DashSpvClient<WalletManager<ManagedWalletInfo>, PeerNetworkManager, DiskStorageManager>;

struct ClientHandle {
    monitor_handle: tokio::task::JoinHandle<TestClient>,
    progress_receiver: watch::Receiver<SyncProgress>,
    sync_event_receiver: broadcast::Receiver<SyncEvent>,
    network_event_receiver: broadcast::Receiver<NetworkEvent>,
    _command_sender: UnboundedSender<DashSpvClientCommand>,
    cancel_token: CancellationToken,
}

impl ClientHandle {
    pub async fn stop(self) -> TestClient {
        tracing::info!("Aborting network monitoring task...");
        self.cancel_token.cancel();
        let (result,) = tokio::join!(self.monitor_handle);
        result.expect("Monitor network task failed")
    }
}

/// Creates a new SPV client and starts it.
async fn create_and_start_client(
    config: &ClientConfig,
    wallet: Arc<RwLock<WalletManager<ManagedWalletInfo>>>,
) -> ClientHandle {
    let network_manager =
        PeerNetworkManager::new(config).await.expect("Failed to create network manager");
    let storage_manager =
        DiskStorageManager::new(config).await.expect("Failed to create storage manager");

    let mut client = DashSpvClient::new(config.clone(), network_manager, storage_manager, wallet)
        .await
        .expect("Failed to create client");

    client.start().await.expect("Failed to start client");

    let progress_receiver = client.subscribe_progress();
    let sync_event_receiver = client.subscribe_sync_events();
    let network_event_receiver = client.subscribe_network_events();
    let cancel_token = CancellationToken::new();
    let monitor_token = cancel_token.clone();
    let (_command_sender, command_receiver) = tokio::sync::mpsc::unbounded_channel();

    let monitor_handle = tokio::task::spawn(async move {
        if let Err(e) = client.monitor_network(command_receiver, monitor_token).await {
            tracing::error!("Monitor network error: {}", e);
        }
        client
    });

    ClientHandle {
        monitor_handle,
        progress_receiver,
        sync_event_receiver,
        network_event_receiver,
        _command_sender,
        cancel_token,
    }
}

/// Create a test wallet from mnemonic.
fn create_test_wallet(
    mnemonic: &str,
    network: Network,
) -> (Arc<RwLock<WalletManager<ManagedWalletInfo>>>, WalletId) {
    let mut wallet_manager = WalletManager::<ManagedWalletInfo>::new(network);
    let wallet_id = wallet_manager
        .create_wallet_from_mnemonic(
            mnemonic,
            "",
            0,
            WalletAccountCreationOptions::SpecificAccounts(
                BTreeSet::from([0]),
                BTreeSet::new(),
                BTreeSet::new(),
                BTreeSet::new(),
                BTreeSet::new(),
                None,
            ),
        )
        .expect("Failed to create wallet from mnemonic");
    (Arc::new(RwLock::new(wallet_manager)), wallet_id)
}

/// Create test client config pointing to a specific peer (exclusive mode).
fn create_test_config(storage_path: PathBuf, peer_addr: std::net::SocketAddr) -> ClientConfig {
    let mut config = ClientConfig::regtest().with_storage_path(storage_path).without_masternodes();
    config.peers.clear();
    config.add_peer(peer_addr);
    config
}

/// Create test client config with no explicit peers (non-exclusive mode).
///
/// The peer address is seeded into the peer store on disk so the client
/// discovers it through the normal peer discovery path.
async fn create_non_exclusive_test_config(
    storage_path: PathBuf,
    peer_addr: std::net::SocketAddr,
) -> ClientConfig {
    let mut config = ClientConfig::regtest().with_storage_path(storage_path).without_masternodes();
    // Clear default regtest peers so the manager enters non-exclusive mode
    config.peers.clear();
    // Seed the peer store so the client can discover our dashd node
    let peer_store = PersistentPeerStorage::open(config.storage_path.clone())
        .await
        .expect("Failed to open peer storage");
    let msg = AddrV2Message::new(peer_addr, ServiceFlags::NETWORK);
    peer_store.save_peers(&[msg]).await.expect("Failed to seed peer store");
    config
}

/// Wait for sync to reach target height.
async fn wait_for_sync(
    progress_receiver: &mut watch::Receiver<SyncProgress>,
    target_height: u32,
    timeout_secs: u64,
) {
    let timeout = tokio::time::sleep(Duration::from_secs(timeout_secs));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = &mut timeout => {
                let update = progress_receiver.borrow();
                panic!("Timeout waiting for sync to height {}. Current progress: {:?}",
                    target_height, update
                );
            }
            result = progress_receiver.changed() => {
                if result.is_err() {
                    panic!("Progress channel closed");
                }
                let update = progress_receiver.borrow_and_update().clone();
                let current_height = update.headers().unwrap().current_height();
                let filters_height = update.filters()
                    .ok()
                    .map(|f| f.current_height())
                    .unwrap_or(current_height);
                if update.is_synced() && current_height >= target_height
                    && filters_height >= target_height
                {
                    return;
                }
            }
        }
    }
}

/// Count all unique transactions across wallet accounts.
async fn count_wallet_transactions(
    wallet: &Arc<RwLock<WalletManager<ManagedWalletInfo>>>,
    wallet_id: &WalletId,
) -> usize {
    let wallet_read = wallet.read().await;
    let wallet_info = wallet_read.get_wallet_info(wallet_id).expect("Wallet info not found");
    let mut count = 0;
    for account in wallet_info.accounts().all_accounts() {
        count += account.transactions.len();
    }
    count
}

/// Get the spendable balance for a wallet.
async fn get_spendable_balance(
    wallet: &Arc<RwLock<WalletManager<ManagedWalletInfo>>>,
    wallet_id: &WalletId,
) -> u64 {
    let wallet_read = wallet.read().await;
    wallet_read.get_wallet_balance(wallet_id).expect("Failed to get wallet balance").spendable()
}

/// Get a receive address from the SPV wallet.
async fn get_wallet_receive_address(
    wallet: &Arc<RwLock<WalletManager<ManagedWalletInfo>>>,
    wallet_id: &WalletId,
) -> dashcore::Address {
    use key_wallet::managed_account::managed_account_type::ManagedAccountType;

    let wallet_read = wallet.read().await;
    let wallet_info = wallet_read.get_wallet_info(wallet_id).expect("Wallet info not found");

    let account =
        wallet_info.accounts().standard_bip44_accounts.get(&0).expect("BIP44 account 0 not found");

    if let ManagedAccountType::Standard {
        external_addresses,
        ..
    } = &account.account_type
    {
        external_addresses
            .unused_addresses()
            .into_iter()
            .next()
            .expect("No unused receive address available")
    } else {
        panic!("Account 0 is not a Standard account type");
    }
}

/// Check if wallet contains a specific transaction.
async fn wallet_has_transaction(
    wallet: &Arc<RwLock<WalletManager<ManagedWalletInfo>>>,
    wallet_id: &WalletId,
    txid: &dashcore::Txid,
) -> bool {
    let wallet_read = wallet.read().await;
    let wallet_info = wallet_read.get_wallet_info(wallet_id).expect("Wallet info not found");

    for account in wallet_info.accounts().all_accounts() {
        if account.transactions.contains_key(txid) {
            return true;
        }
    }

    for tx in wallet_info.immature_transactions() {
        if &tx.txid() == txid {
            return true;
        }
    }

    false
}

/// Validate that the synced wallet matches the expected baseline from dashd.
///
/// Checks sync heights, exact transaction set, and exact balance against the
/// wallet file loaded from the test data directory.
async fn assert_synced_wallet_matches_expected(
    progress: &SyncProgress,
    wallet: &Arc<RwLock<WalletManager<ManagedWalletInfo>>>,
    wallet_id: &WalletId,
    ctx: &TestContext,
) {
    // Validate sync heights
    let header_height = progress.headers().unwrap().current_height();
    let filter_header_height = progress.filter_headers().unwrap().current_height();
    assert_eq!(header_height, ctx.dashd.expected_height, "Header height mismatch");
    assert_eq!(filter_header_height, ctx.dashd.expected_height, "Filter header height mismatch");

    // Validate transactions match expected set
    let wallet_read = wallet.read().await;
    let wallet_info = wallet_read.get_wallet_info(wallet_id).expect("Wallet info not found");

    let mut spv_txids = HashSet::new();
    for managed_account in wallet_info.accounts().all_accounts() {
        for txid in managed_account.transactions.keys() {
            spv_txids.insert(txid.to_string());
        }
    }
    for tx in wallet_info.immature_transactions() {
        spv_txids.insert(tx.txid().to_string());
    }

    let expected_txids: HashSet<String> = ctx
        .dashd
        .wallet
        .transactions
        .iter()
        .filter_map(|tx| tx.get("txid").and_then(|v| v.as_str()).map(String::from))
        .collect();

    let missing: Vec<_> = expected_txids.difference(&spv_txids).collect();
    let extra: Vec<_> = spv_txids.difference(&expected_txids).collect();

    assert!(
        missing.is_empty(),
        "SPV wallet is missing {} transactions: {:?}",
        missing.len(),
        missing
    );
    assert!(
        extra.is_empty(),
        "SPV wallet has {} unexpected transactions: {:?}",
        extra.len(),
        extra
    );

    // Validate balance
    drop(wallet_read);
    let balance = get_spendable_balance(wallet, wallet_id).await;
    let expected_balance: u64 = ctx
        .dashd
        .wallet
        .utxos
        .iter()
        .filter_map(|u| u.get("amount").and_then(|v| v.as_f64()))
        .map(|dash| (dash * 100_000_000.0).round() as u64)
        .sum();

    assert_eq!(balance, expected_balance, "Wallet balance mismatch");
    tracing::info!(
        "Wallet validation passed: {} transactions, balance={}",
        spv_txids.len(),
        balance
    );
}

/// Returns true for sync events that represent meaningful forward progress.
///
/// Used by restart and disconnection tests to decide when to interrupt.
/// Only counts BlockProcessed events that generated new addresses, since
/// re-processed blocks from storage with no new info are not real progress.
fn is_progress_event(event: &SyncEvent) -> bool {
    match event {
        SyncEvent::BlockHeadersStored {
            ..
        }
        | SyncEvent::FilterHeadersStored {
            ..
        }
        | SyncEvent::FiltersStored {
            ..
        }
        | SyncEvent::BlocksNeeded {
            ..
        } => true,
        SyncEvent::BlockProcessed {
            new_addresses,
            ..
        } => !new_addresses.is_empty(),
        _ => false,
    }
}

/// Run a disconnect-and-reconnect loop during sync, then verify final state.
///
/// Waits for progress events, disconnects all peers after every 5th event,
/// validates disconnect/reconnect network events, and asserts wallet state
/// after sync completes.
async fn run_disconnect_loop(
    mut client_handle: ClientHandle,
    node: &DashCoreNode,
    num_disconnects: usize,
    wallet: &Arc<RwLock<WalletManager<ManagedWalletInfo>>>,
    wallet_id: &WalletId,
    ctx: &TestContext,
) {
    let mut disconnect_count = 0;
    let mut events_since_disconnect = 0;

    let timeout = tokio::time::sleep(Duration::from_secs(SYNC_TIMEOUT * 2));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = &mut timeout => {
                let progress = client_handle.progress_receiver.borrow();
                panic!(
                    "Timeout after {} disconnections. Current progress: {:?}",
                    disconnect_count, progress
                );
            }
            result = client_handle.sync_event_receiver.recv() => {
                match result {
                    Ok(ref event) if is_progress_event(event) => {
                        events_since_disconnect += 1;
                        if disconnect_count < num_disconnects && events_since_disconnect >= 5 {
                            tracing::info!(
                                "Disconnection {}: disconnecting peers after: {}",
                                disconnect_count + 1,
                                event.description()
                            );
                            node.disconnect_all_peers();
                            disconnect_count += 1;
                            events_since_disconnect = 0;

                            let saw_disconnect = wait_for_network_event(
                                &mut client_handle.network_event_receiver,
                                |e| matches!(e, NetworkEvent::PeerDisconnected { .. }),
                                Duration::from_secs(10),
                            ).await;
                            assert!(saw_disconnect, "SPV should observe PeerDisconnected");
                            tracing::info!("SPV observed PeerDisconnected");

                            let saw_reconnect = wait_for_network_event(
                                &mut client_handle.network_event_receiver,
                                |e| matches!(e, NetworkEvent::PeerConnected { .. }),
                                Duration::from_secs(30),
                            ).await;
                            assert!(saw_reconnect, "SPV should reconnect after disconnection");
                            tracing::info!("SPV reconnected (PeerConnected)");
                        }
                    }
                    Ok(SyncEvent::SyncComplete { .. }) => {
                        tracing::info!(
                            "Sync completed after {} peer disconnections",
                            disconnect_count
                        );
                        break;
                    }
                    Ok(_) => continue,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("Event receiver lagged by {} messages", n);
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        panic!("Sync event channel closed after {} disconnections", disconnect_count);
                    }
                }
            }
        }
    }

    assert_eq!(
        disconnect_count, num_disconnects,
        "Expected {} disconnections but only did {}",
        num_disconnects, disconnect_count
    );

    let client = client_handle.stop().await;
    assert_synced_wallet_matches_expected(&client.progress(), wallet, wallet_id, ctx).await;
}

// ============================================================================
// Tests
// ============================================================================

#[tokio::test]
async fn test_wallet_sync() {
    let Some(ctx) = TestContext::new().await else {
        return;
    };

    let (wallet, wallet_id) = ctx.create_wallet();

    let mut client_handle = create_and_start_client(&ctx.client_config, Arc::clone(&wallet)).await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.expected_height, SYNC_TIMEOUT)
        .await;

    let client = client_handle.stop().await;
    assert_synced_wallet_matches_expected(&client.progress(), &wallet, &wallet_id, &ctx).await;
}

/// Verify sync state is identical after stopping and restarting with same storage.
#[tokio::test]
async fn test_sync_restart_consistency() {
    let Some(ctx) = TestContext::new().await else {
        return;
    };

    let (wallet, wallet_id) = ctx.create_wallet();

    // First sync
    tracing::info!("=== Starting first sync ===");
    let mut client_handle = create_and_start_client(&ctx.client_config, Arc::clone(&wallet)).await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.expected_height, SYNC_TIMEOUT)
        .await;

    let mut first_client = client_handle.stop().await;
    assert_synced_wallet_matches_expected(&first_client.progress(), &wallet, &wallet_id, &ctx)
        .await;
    let first_balance = get_spendable_balance(&wallet, &wallet_id).await;
    let first_tx_count = count_wallet_transactions(&wallet, &wallet_id).await;

    first_client.stop().await.expect("Failed to stop first client");
    drop(first_client);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Restart with same storage and wallet
    tracing::info!("=== Restarting with same storage ===");
    let mut client_handle = create_and_start_client(&ctx.client_config, Arc::clone(&wallet)).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.expected_height, SYNC_TIMEOUT)
        .await;

    let mut second_client = client_handle.stop().await;
    assert_synced_wallet_matches_expected(&second_client.progress(), &wallet, &wallet_id, &ctx)
        .await;
    let second_balance = get_spendable_balance(&wallet, &wallet_id).await;
    let second_tx_count = count_wallet_transactions(&wallet, &wallet_id).await;

    // Validate state is identical across restarts
    assert_eq!(first_balance, second_balance, "Balance mismatch after restart");
    assert_eq!(first_tx_count, second_tx_count, "Transaction count mismatch after restart");
    tracing::info!("State consistent after restart");

    second_client.stop().await.expect("Failed to stop second client");
}

/// Verify correct rescan behavior when restarting with a fresh wallet but existing storage.
#[tokio::test]
async fn test_sync_restart_with_fresh_wallet() {
    let Some(ctx) = TestContext::new().await else {
        return;
    };

    let (wallet, wallet_id) = ctx.create_wallet();

    // First sync
    tracing::info!("=== Starting first sync ===");
    let mut client_handle = create_and_start_client(&ctx.client_config, Arc::clone(&wallet)).await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.expected_height, SYNC_TIMEOUT)
        .await;

    let mut first_client = client_handle.stop().await;
    assert_synced_wallet_matches_expected(&first_client.progress(), &wallet, &wallet_id, &ctx)
        .await;

    first_client.stop().await.expect("Failed to stop first client");
    drop(first_client);
    drop(wallet);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Restart with fresh wallet (triggers rescan)
    tracing::info!("=== Restarting with fresh wallet (triggers rescan) ===");
    let (fresh_wallet, fresh_wallet_id) =
        create_test_wallet(&ctx.dashd.wallet.mnemonic, Network::Regtest);

    {
        let balance = get_spendable_balance(&fresh_wallet, &fresh_wallet_id).await;
        assert_eq!(balance, 0, "Fresh wallet should start with zero balance");
    }

    let mut client_handle =
        create_and_start_client(&ctx.client_config, Arc::clone(&fresh_wallet)).await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.expected_height, SYNC_TIMEOUT)
        .await;

    let mut second_client = client_handle.stop().await;
    assert_synced_wallet_matches_expected(
        &second_client.progress(),
        &fresh_wallet,
        &fresh_wallet_id,
        &ctx,
    )
    .await;

    second_client.stop().await.expect("Failed to stop second client");
}

/// Verify sync completes successfully despite repeated interruptions.
///
/// Listens for key sync events (BlockHeadersStored, FilterHeadersStored, FiltersStored,
/// BlocksNeeded, BlockProcessed) and restarts the client on every 2nd occurrence until
/// sync completes. This exercises restart/resume from unpredictable points across the
/// full sync lifecycle.
#[tokio::test]
async fn test_sync_with_multiple_restarts() {
    let Some(ctx) = TestContext::new().await else {
        return;
    };

    let (wallet, wallet_id) = ctx.create_wallet();

    let mut restart_count = 0;
    let final_progress = loop {
        tracing::info!("=== Starting sync (restart count: {}) ===", restart_count);
        let mut client_handle =
            create_and_start_client(&ctx.client_config, Arc::clone(&wallet)).await;

        // Wait for either sync completion or the 2nd matching event
        let mut events_seen = 0;
        let mut should_restart = false;
        let timeout = tokio::time::sleep(Duration::from_secs(SYNC_TIMEOUT));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                _ = &mut timeout => {
                    let progress = client_handle.progress_receiver.borrow();
                    panic!(
                        "Timeout after {} restarts. Current progress: {:?}",
                        restart_count, progress
                    );
                }
                result = client_handle.sync_event_receiver.recv() => {
                    match result {
                        Ok(ref event) if is_progress_event(event) => {
                            events_seen += 1;
                            if events_seen % 2 == 0 {
                                tracing::info!("Restarting on: {}", event.description());
                                should_restart = true;
                                break;
                            }
                            tracing::info!("Skipped: {}", event.description());
                        }
                        Ok(SyncEvent::SyncComplete { .. }) => break,
                        Ok(_) => continue,
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!("Event receiver lagged by {} messages", n);
                            continue;
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            panic!("Sync event channel closed after {} restarts", restart_count);
                        }
                    }
                }
            }
        }

        let mut client = client_handle.stop().await;
        let progress = client.progress();
        client.stop().await.expect("Failed to stop client");

        if !should_restart {
            tracing::info!("Sync completed after {} restarts", restart_count);
            break progress;
        }

        drop(client);
        tokio::time::sleep(Duration::from_millis(100)).await;
        restart_count += 1;
    };

    assert_synced_wallet_matches_expected(&final_progress, &wallet, &wallet_id, &ctx).await;
}

/// Verify sync completes successfully despite restarts at random points.
///
/// Uses a seeded RNG to sleep a random duration (50-500ms) after starting, then restarts.
#[tokio::test]
async fn test_sync_with_random_restarts() {
    let Some(ctx) = TestContext::new().await else {
        return;
    };

    let (wallet, wallet_id) = ctx.create_wallet();

    let num_restarts = 10;
    let seed = 42;
    let mut rng = StdRng::seed_from_u64(seed);

    for i in 0..num_restarts {
        let delay_ms = rng.gen_range(50..500);
        tracing::info!("=== Restart {}: sleeping {}ms before stopping ===", i + 1, delay_ms);
        let client_handle = create_and_start_client(&ctx.client_config, Arc::clone(&wallet)).await;

        tokio::time::sleep(Duration::from_millis(delay_ms)).await;

        let mut client = client_handle.stop().await;
        client.stop().await.expect("Failed to stop client");
        drop(client);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Final sync to completion
    tracing::info!("=== Final sync to completion ===");
    let mut client_handle = create_and_start_client(&ctx.client_config, Arc::clone(&wallet)).await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.expected_height, SYNC_TIMEOUT)
        .await;

    let mut final_client = client_handle.stop().await;
    assert_synced_wallet_matches_expected(&final_client.progress(), &wallet, &wallet_id, &ctx)
        .await;
    tracing::info!("Sync completed after {} random restarts (seed={})", num_restarts, seed);

    final_client.stop().await.expect("Failed to stop final client");
}

/// Verify newly generated blocks with wallet transactions sync properly.
#[tokio::test]
async fn test_sync_then_generate_blocks() {
    let Some(ctx) = TestContext::new().await else {
        return;
    };
    if !ctx.dashd.supports_mining {
        eprintln!("Skipping test (dashd RPC miner not available)");
        return;
    }

    let (wallet, wallet_id) = ctx.create_wallet();

    // Initial sync
    tracing::info!("=== Starting initial sync ===");
    let mut client_handle = create_and_start_client(&ctx.client_config, Arc::clone(&wallet)).await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.expected_height, SYNC_TIMEOUT)
        .await;

    let initial_balance = get_spendable_balance(&wallet, &wallet_id).await;
    let initial_tx_count = count_wallet_transactions(&wallet, &wallet_id).await;
    tracing::info!(
        "Initial state: height={}, balance={}, tx_count={}",
        ctx.dashd.expected_height,
        initial_balance,
        initial_tx_count
    );

    // Send DASH to the SPV wallet and generate blocks to confirm
    let receive_address = get_wallet_receive_address(&wallet, &wallet_id).await;
    let send_amount = Amount::from_sat(100_000_000);
    let txid = ctx.dashd.node.send_to_address(&receive_address, send_amount);
    tracing::info!("Sent {} to SPV wallet, txid: {}", send_amount, txid);

    let new_blocks = 6;
    let miner_address = ctx.dashd.node.get_new_address_from_wallet("default");
    ctx.dashd.node.generate_blocks(new_blocks, &miner_address);

    let expected_new_height = ctx.dashd.expected_height + new_blocks as u32;

    // Wait for SPV to sync new blocks
    wait_for_sync(&mut client_handle.progress_receiver, expected_new_height, SYNC_TIMEOUT).await;

    let mut client = client_handle.stop().await;
    let final_height = client.progress().headers().unwrap().current_height();
    let final_tx_count = count_wallet_transactions(&wallet, &wallet_id).await;

    // Validate
    assert_eq!(final_height, expected_new_height, "Header height mismatch");
    assert!(
        wallet_has_transaction(&wallet, &wallet_id, &txid).await,
        "SPV wallet should contain transaction {}",
        txid
    );
    assert!(
        final_tx_count > initial_tx_count,
        "Transaction count should have increased: {} -> {}",
        initial_tx_count,
        final_tx_count
    );
    tracing::info!(
        "New blocks synced: height {} -> {}, tx_count {} -> {}",
        ctx.dashd.expected_height,
        final_height,
        initial_tx_count,
        final_tx_count
    );

    client.stop().await.expect("Failed to stop client");
}

/// Verify that multiple transactions sent in quick succession and mined in a single block
/// are all detected by the SPV client.
#[tokio::test]
async fn test_multiple_transactions_in_single_block() {
    let Some(ctx) = TestContext::new().await else {
        return;
    };
    if !ctx.dashd.supports_mining {
        eprintln!("Skipping test (dashd RPC miner not available)");
        return;
    }

    let (wallet, wallet_id) = ctx.create_wallet();

    // Initial sync to chain tip
    tracing::info!("=== Starting initial sync ===");
    let mut client_handle = create_and_start_client(&ctx.client_config, Arc::clone(&wallet)).await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.expected_height, SYNC_TIMEOUT)
        .await;

    let baseline_tx_count = count_wallet_transactions(&wallet, &wallet_id).await;
    let baseline_balance = get_spendable_balance(&wallet, &wallet_id).await;
    tracing::info!("Baseline: tx_count={}, balance={}", baseline_tx_count, baseline_balance);

    // Send 3 transactions of different amounts to the SPV wallet
    let receive_address = get_wallet_receive_address(&wallet, &wallet_id).await;
    let amounts =
        [Amount::from_sat(50_000_000), Amount::from_sat(75_000_000), Amount::from_sat(120_000_000)];
    let mut txids = Vec::new();
    for amount in &amounts {
        let txid = ctx.dashd.node.send_to_address(&receive_address, *amount);
        tracing::info!("Sent {} to SPV wallet, txid: {}", amount, txid);
        txids.push(txid);
    }

    // Mine a single block to confirm all 3
    let miner_address = ctx.dashd.node.get_new_address_from_wallet("default");
    ctx.dashd.node.generate_blocks(1, &miner_address);
    let expected_height = ctx.dashd.expected_height + 1;

    // Wait for SPV to sync the new block
    wait_for_sync(&mut client_handle.progress_receiver, expected_height, SYNC_TIMEOUT).await;

    let mut client = client_handle.stop().await;

    // Verify all 3 transactions are in the wallet
    let final_tx_count = count_wallet_transactions(&wallet, &wallet_id).await;
    let final_balance = get_spendable_balance(&wallet, &wallet_id).await;

    assert_eq!(
        final_tx_count,
        baseline_tx_count + 3,
        "Expected 3 new transactions, got {}",
        final_tx_count - baseline_tx_count
    );

    // Since dashd and SPV share the same wallet, sends are internal transfers.
    // The only balance change is the transaction fees deducted by dashd.
    let fees_paid = baseline_balance - final_balance;
    assert!(
        final_balance < baseline_balance,
        "Balance should decrease by fees for internal transfers"
    );
    assert!(fees_paid < 1_000_000, "Total fees ({}) should be reasonable", fees_paid);

    for txid in &txids {
        assert!(
            wallet_has_transaction(&wallet, &wallet_id, txid).await,
            "Wallet should contain transaction {}",
            txid
        );
    }

    tracing::info!(
        "All 3 transactions found: tx_count {} -> {}, balance {} -> {} (fees={})",
        baseline_tx_count,
        final_tx_count,
        baseline_balance,
        final_balance,
        fees_paid
    );

    client.stop().await.expect("Failed to stop client");
}

/// Verify that transactions sent one per block over several blocks are each detected
/// incrementally by the SPV client.
#[tokio::test]
async fn test_multiple_transactions_across_blocks() {
    let Some(ctx) = TestContext::new().await else {
        return;
    };
    if !ctx.dashd.supports_mining {
        eprintln!("Skipping test (dashd RPC miner not available)");
        return;
    }

    let (wallet, wallet_id) = ctx.create_wallet();

    // Initial sync to chain tip
    tracing::info!("=== Starting initial sync ===");
    let mut client_handle = create_and_start_client(&ctx.client_config, Arc::clone(&wallet)).await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.expected_height, SYNC_TIMEOUT)
        .await;

    let baseline_tx_count = count_wallet_transactions(&wallet, &wallet_id).await;
    let baseline_balance = get_spendable_balance(&wallet, &wallet_id).await;
    tracing::info!("Baseline: tx_count={}, balance={}", baseline_tx_count, baseline_balance);

    // Send 1 tx per block, 3 iterations
    let amounts =
        [Amount::from_sat(30_000_000), Amount::from_sat(60_000_000), Amount::from_sat(90_000_000)];
    let miner_address = ctx.dashd.node.get_new_address_from_wallet("default");
    let mut current_height = ctx.dashd.expected_height;
    let mut txids = Vec::new();

    for (i, amount) in amounts.iter().enumerate() {
        let receive_address = get_wallet_receive_address(&wallet, &wallet_id).await;
        let txid = ctx.dashd.node.send_to_address(&receive_address, *amount);
        tracing::info!("Iteration {}: sent {} to SPV wallet, txid: {}", i, amount, txid);
        txids.push(txid);

        ctx.dashd.node.generate_blocks(1, &miner_address);
        current_height += 1;

        wait_for_sync(&mut client_handle.progress_receiver, current_height, SYNC_TIMEOUT).await;

        let tx_count = count_wallet_transactions(&wallet, &wallet_id).await;
        assert_eq!(
            tx_count,
            baseline_tx_count + i + 1,
            "After iteration {}, expected {} transactions, got {}",
            i,
            baseline_tx_count + i + 1,
            tx_count
        );
        tracing::info!("Iteration {}: tx_count={}", i, tx_count);
    }

    let mut client = client_handle.stop().await;

    // Final verification
    let final_balance = get_spendable_balance(&wallet, &wallet_id).await;

    // Internal transfers: only fees are deducted
    let fees_paid = baseline_balance - final_balance;
    assert!(
        final_balance < baseline_balance,
        "Balance should decrease by fees for internal transfers"
    );
    assert!(fees_paid < 1_000_000, "Total fees ({}) should be reasonable", fees_paid);

    for txid in &txids {
        assert!(
            wallet_has_transaction(&wallet, &wallet_id, txid).await,
            "Wallet should contain transaction {}",
            txid
        );
    }

    tracing::info!(
        "All iterations complete: tx_count {} -> {}, balance {} -> {} (fees={})",
        baseline_tx_count,
        baseline_tx_count + amounts.len(),
        baseline_balance,
        final_balance,
        fees_paid
    );

    client.stop().await.expect("Failed to stop client");
}

/// Verify sync completes successfully despite peer disconnections mid-sync.
///
/// Waits for sync progress, then disconnects all peers via dashd RPC 3 times.
/// After each disconnection, validates that the SPV client observes a
/// `NetworkEvent::PeerDisconnected` followed by a `NetworkEvent::PeerConnected`
/// (automatic reconnection). After all disconnections, waits for full sync.
#[tokio::test]
async fn test_sync_with_peer_disconnection() {
    let Some(ctx) = TestContext::new().await else {
        return;
    };

    let (wallet, wallet_id) = ctx.create_wallet();

    let num_disconnects = 3;
    let client_handle = create_and_start_client(&ctx.client_config, Arc::clone(&wallet)).await;

    run_disconnect_loop(client_handle, &ctx.dashd.node, num_disconnects, &wallet, &wallet_id, &ctx)
        .await;
}

/// Wait for a specific network event, returning true if seen within the timeout.
async fn wait_for_network_event(
    receiver: &mut broadcast::Receiver<NetworkEvent>,
    predicate: impl Fn(&NetworkEvent) -> bool,
    max_wait: Duration,
) -> bool {
    let deadline = tokio::time::sleep(max_wait);
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            _ = &mut deadline => return false,
            result = receiver.recv() => {
                match result {
                    Ok(ref event) if predicate(event) => return true,
                    Ok(_) => continue,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return false,
                }
            }
        }
    }
}

/// Verify sync completes in non-exclusive mode despite peer disconnections.
///
/// Unlike `test_sync_with_peer_disconnection` which uses exclusive mode (explicit
/// peers), this test uses non-exclusive mode where the peer is discovered via the
/// seeded peer store. The reconnection path goes through the normal peer discovery
/// mechanism (known addresses + DNS fallback) instead of the exclusive peer list.
#[tokio::test]
async fn test_sync_with_peer_disconnection_non_exclusive() {
    let Some(ctx) = TestContext::new().await else {
        return;
    };

    let (wallet, wallet_id) = ctx.create_wallet();

    // Create non-exclusive config: no explicit peers, dashd seeded in peer store
    let non_exclusive_config =
        create_non_exclusive_test_config(ctx.storage_dir.clone(), ctx.dashd.addr).await;

    let num_disconnects = 3;
    let client_handle = create_and_start_client(&non_exclusive_config, Arc::clone(&wallet)).await;

    run_disconnect_loop(client_handle, &ctx.dashd.node, num_disconnects, &wallet, &wallet_id, &ctx)
        .await;
}

/// Verify that syncing with a wallet that has no on-chain activity results in zero
/// transactions and zero balance, while headers and filters sync fully.
#[tokio::test]
async fn test_sync_empty_wallet() {
    let Some(ctx) = TestContext::new().await else {
        return;
    };

    // Use a mnemonic with no regtest activity
    let empty_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let (wallet, wallet_id) = create_test_wallet(empty_mnemonic, Network::Regtest);

    tracing::info!("=== Starting sync with empty wallet ===");
    let mut client_handle = create_and_start_client(&ctx.client_config, Arc::clone(&wallet)).await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.expected_height, SYNC_TIMEOUT)
        .await;

    let client = client_handle.stop().await;

    // Verify headers and filter headers synced fully
    let final_progress = client.progress();
    let header_height = final_progress.headers().unwrap().current_height();
    let filter_header_height = final_progress.filter_headers().unwrap().current_height();

    assert_eq!(header_height, ctx.dashd.expected_height, "Header height mismatch");
    assert_eq!(filter_header_height, ctx.dashd.expected_height, "Filter header height mismatch");

    // Verify zero transactions and zero balance
    let tx_count = count_wallet_transactions(&wallet, &wallet_id).await;
    let balance = get_spendable_balance(&wallet, &wallet_id).await;

    assert_eq!(tx_count, 0, "Empty wallet should have 0 transactions, got {}", tx_count);
    assert_eq!(balance, 0, "Empty wallet should have 0 balance, got {}", balance);

    tracing::info!(
        "Empty wallet sync complete: headers={}, filters={}, txs={}, balance={}",
        header_height,
        filter_header_height,
        tx_count,
        balance
    );
}

/// Verify two wallets in one WalletManager sync independently without cross-contamination.
///
/// Creates a manager with the test mnemonic wallet (has transactions) and the "abandon"
/// wallet (no regtest activity). After sync, the test wallet should have all expected
/// transactions while the abandon wallet remains empty.
#[tokio::test]
async fn test_sync_two_wallets_same_client() {
    let Some(ctx) = TestContext::new().await else {
        return;
    };

    let empty_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // Create a WalletManager with two wallets
    let mut wallet_manager = WalletManager::<ManagedWalletInfo>::new(Network::Regtest);
    let test_wallet_id = wallet_manager
        .create_wallet_from_mnemonic(
            &ctx.dashd.wallet.mnemonic,
            "",
            0,
            WalletAccountCreationOptions::SpecificAccounts(
                BTreeSet::from([0]),
                BTreeSet::new(),
                BTreeSet::new(),
                BTreeSet::new(),
                BTreeSet::new(),
                None,
            ),
        )
        .expect("Failed to create test wallet");

    let empty_wallet_id = wallet_manager
        .create_wallet_from_mnemonic(
            empty_mnemonic,
            "",
            0,
            WalletAccountCreationOptions::SpecificAccounts(
                BTreeSet::from([0]),
                BTreeSet::new(),
                BTreeSet::new(),
                BTreeSet::new(),
                BTreeSet::new(),
                None,
            ),
        )
        .expect("Failed to create empty wallet");

    assert_eq!(wallet_manager.wallet_count(), 2, "Should have two wallets");
    let wallet = Arc::new(RwLock::new(wallet_manager));

    // Sync
    tracing::info!("=== Starting sync with two wallets ===");
    let mut client_handle = create_and_start_client(&ctx.client_config, Arc::clone(&wallet)).await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.expected_height, SYNC_TIMEOUT)
        .await;

    let client = client_handle.stop().await;

    // Verify sync heights
    let final_progress = client.progress();
    let header_height = final_progress.headers().unwrap().current_height();
    assert_eq!(header_height, ctx.dashd.expected_height, "Header height mismatch");

    // Verify the test wallet has expected transactions (including immature) and balance
    let test_balance = get_spendable_balance(&wallet, &test_wallet_id).await;
    let expected_balance: u64 = ctx
        .dashd
        .wallet
        .utxos
        .iter()
        .filter_map(|u| u.get("amount").and_then(|v| v.as_f64()))
        .map(|dash| (dash * 100_000_000.0).round() as u64)
        .sum();
    assert_eq!(test_balance, expected_balance, "Test wallet balance mismatch");

    // Compare transaction sets (accounts + immature)
    let wallet_read = wallet.read().await;
    let wallet_info = wallet_read.get_wallet_info(&test_wallet_id).expect("Wallet info not found");
    let mut spv_txids = HashSet::new();
    for account in wallet_info.accounts().all_accounts() {
        for txid in account.transactions.keys() {
            spv_txids.insert(txid.to_string());
        }
    }
    for tx in wallet_info.immature_transactions() {
        spv_txids.insert(tx.txid().to_string());
    }
    drop(wallet_read);

    let expected_txids: HashSet<String> = ctx
        .dashd
        .wallet
        .transactions
        .iter()
        .filter_map(|tx| tx.get("txid").and_then(|v| v.as_str()).map(String::from))
        .collect();
    let missing: Vec<_> = expected_txids.difference(&spv_txids).collect();
    let extra: Vec<_> = spv_txids.difference(&expected_txids).collect();
    assert!(missing.is_empty(), "Test wallet missing transactions: {:?}", missing);
    assert!(extra.is_empty(), "Test wallet has extra transactions: {:?}", extra);

    // Verify the empty wallet has zero transactions and zero balance
    let empty_tx_count = count_wallet_transactions(&wallet, &empty_wallet_id).await;
    let empty_balance = get_spendable_balance(&wallet, &empty_wallet_id).await;

    assert_eq!(
        empty_tx_count, 0,
        "Empty wallet should have 0 transactions, got {}",
        empty_tx_count
    );
    assert_eq!(empty_balance, 0, "Empty wallet should have 0 balance, got {}", empty_balance);

    tracing::info!(
        "Multi-wallet sync passed: test_wallet(txs={}, balance={}), empty_wallet(txs={}, balance={})",
        spv_txids.len(), test_balance, empty_tx_count, empty_balance
    );
}
