//! SPV sync tests using dashd.
//!
//! These tests demonstrate realistic SPV sync scenarios against a dashd instance.

use dash_spv::client::interface::DashSpvClientCommand;
use dash_spv::test_utils::{
    is_dashd_available, load_wallet_file, BlockchainCopy, DashCoreConfig, DashCoreNode,
};
use dash_spv::{
    client::{config::MempoolStrategy, ClientConfig, DashSpvClient},
    network::PeerNetworkManager,
    storage::DiskStorageManager,
    sync::SyncProgress,
    types::ValidationMode,
    LevelFilter, Network,
};
use dashcore::Amount;
use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::wallet_manager::{WalletId, WalletManager};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::watch;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

fn kill_all_dashd() {
    // Kill any existing dashd processes
    let _ = Command::new("pkill").arg("-9").arg("-x").arg("dashd").output();
    // Wait a moment for processes to die
    std::thread::sleep(Duration::from_millis(500));
}

#[tokio::test]
async fn test_wallet_sync() {
    // Ignore logging init errors since tests run in parallel and may have already initialized
    let _guard = dash_spv::init_console_logging(LevelFilter::DEBUG).ok();
    kill_all_dashd();

    // Skip if dashd is not available
    if !is_dashd_available() {
        warn!("dashd not available, skipping test");
        return;
    }

    // Create config with light wallet
    let config = DashCoreConfig {
        wallet: "light".to_string(),
        ..Default::default()
    };
    info!("Using datadir: {:?}", config.datadir);

    // Load light wallet from test data
    let light_wallet =
        load_wallet_file(&config.datadir, "light").expect("Failed to load light wallet");
    assert_eq!(light_wallet.wallet_name, "light", "Unexpected wallet name");
    info!(
        "Loaded '{}' wallet with {} transactions, {} UTXOs, balance: {:.8} DASH",
        light_wallet.wallet_name,
        light_wallet.transaction_count,
        light_wallet.utxo_count,
        light_wallet.balance
    );

    let mut node = DashCoreNode::with_config(config).expect(
        "Failed to create DashCoreNode. Check that dashd binary exists at the configured path.",
    );

    let addr = node.start().await.expect(
        "Failed to start dashd. This test requires dashd to run. \
                 On macOS, you may need to increase file descriptor limits: \
                 sudo launchctl limit maxfiles 65536 200000 && ulimit -n 10000",
    );
    info!("DashCoreNode started at {}", addr);

    // Get expected block count from dashd
    let expected_height =
        node.get_block_count().await.expect("Failed to get block count from dashd");
    info!("Dashd has {} blocks", expected_height);

    // Create SPV client configuration
    let temp_dir = TempDir::new().expect("Failed to create temporary directory");
    let mut config = ClientConfig::regtest()
        .with_storage_path(temp_dir.path())
        .with_validation_mode(ValidationMode::Basic)
        .with_mempool_tracking(MempoolStrategy::BloomFilter)
        .without_masternodes(); // Regtest doesn't have masternodes/quorums

    config.peers.clear();
    config.peers.push(addr);

    // Create wallet from mnemonic
    let mut wallet_manager = WalletManager::<ManagedWalletInfo>::new(config.network);
    let wallet_id = wallet_manager
        .create_wallet_from_mnemonic(
            &light_wallet.mnemonic,
            "", // No passphrase
            0,
            WalletAccountCreationOptions::SpecificAccounts(
                {
                    let mut accounts = std::collections::BTreeSet::new();
                    accounts.insert(0); // Create only BIP44 account 0
                    accounts
                },
                std::collections::BTreeSet::new(),
                std::collections::BTreeSet::new(),
                std::collections::BTreeSet::new(),
                std::collections::BTreeSet::new(),
                None,
            ),
        )
        .expect("Failed to create wallet from mnemonic");
    info!("Created wallet from mnemonic, ID: {:?}", wallet_id);

    let wallet = Arc::new(RwLock::new(wallet_manager));
    let mut client_handle = create_and_start_client(&config, wallet).await;

    wait_for_sync(&mut client_handle.progress_receiver, expected_height, 180).await;
    info!("SPV client sync completed successfully");

    let client = client_handle.stop().await;

    // Get final progress from parallel sync
    let final_progress = client.progress();

    // Extract heights from progress
    let header_height = final_progress.headers().unwrap().current_height();
    let filter_header_height = final_progress.filter_headers().unwrap().current_height();

    // Validate sync results
    info!("=== Validation ===");

    assert_eq!(header_height, expected_height, "Header height mismatch");
    info!("Header height matches: {}", header_height);

    assert_eq!(filter_header_height, expected_height, "Filter header height mismatch");
    info!("Filter header height matches: {}", filter_header_height);

    // Get the read lock of the wallet
    let wallet_read = client.wallet().read().await;

    // Validate wallet data
    let wallet_info = wallet_read.get_wallet_info(&wallet_id).expect("Wallet info not found");

    // Get SPV UTXOs and write to file for comparison
    {
        let utxos = wallet_info.utxos();

        let mut spv_utxos: Vec<String> = utxos
            .into_iter()
            .map(|utxo| format!("{}:{}", utxo.outpoint.txid, utxo.outpoint.vout))
            .collect();
        spv_utxos.sort();

        let mut file = File::create("/tmp/spv_utxos.txt").expect("Failed to create SPV UTXOs file");
        for utxo in &spv_utxos {
            writeln!(file, "{}", utxo).expect("Failed to write UTXO");
        }
        info!("Wrote {} SPV UTXOs to /tmp/spv_utxos.txt", spv_utxos.len());
    }

    // Get all SPV transaction IDs
    let mut spv_txids = std::collections::HashSet::new();
    for managed_account in wallet_info.accounts().all_accounts() {
        for txid in managed_account.transactions.keys() {
            spv_txids.insert(txid.to_string());
        }
    }
    // Add all immature transactions
    let immature = wallet_info.immature_transactions();
    for tx in immature {
        spv_txids.insert(tx.txid().to_string());
    }

    // Get expected transaction IDs from JSON
    let mut expected_txids = std::collections::HashSet::new();
    for tx in &light_wallet.transactions {
        if let Some(txid) = tx.get("txid").and_then(|v| v.as_str()) {
            expected_txids.insert(txid.to_string());
        }
    }

    info!("Transaction comparison:");
    info!("  SPV found:      {} transactions", spv_txids.len());
    info!("  Expected:       {} transactions", expected_txids.len());
    info!("  JSON tx_count:  {}", light_wallet.transaction_count);

    // Export SPV txids to file
    {
        let mut file =
            File::create("/tmp/spv_txids_actual.txt").expect("Failed to create SPV txids file");
        let mut sorted_spv: Vec<_> = spv_txids.iter().map(|s| s.as_str()).collect();
        sorted_spv.sort();
        for txid in sorted_spv {
            writeln!(file, "{}", txid).expect("Failed to write txid");
        }
        info!("Wrote {} SPV transaction IDs to /tmp/spv_txids_actual.txt", spv_txids.len());
    }

    // Find missing and extra transactions
    let missing_txids: Vec<_> = expected_txids.difference(&spv_txids).collect();
    let extra_txids: Vec<_> = spv_txids.difference(&expected_txids).collect();

    if !missing_txids.is_empty() {
        warn!("Missing {} transactions in SPV wallet:", missing_txids.len());
        for txid in missing_txids.iter().take(10) {
            warn!("    {}", txid);
        }
        if missing_txids.len() > 10 {
            warn!("    ... and {} more", missing_txids.len() - 10);
        }

        // Export missing txids to file
        let mut file =
            File::create("/tmp/missing_txids.txt").expect("Failed to create missing txids file");
        let mut sorted_missing: Vec<_> = missing_txids.iter().map(|s| s.as_str()).collect();
        sorted_missing.sort();
        for txid in sorted_missing {
            writeln!(file, "{}", txid).expect("Failed to write txid");
        }
        info!("Wrote {} missing transaction IDs to /tmp/missing_txids.txt", missing_txids.len());
    }

    if !extra_txids.is_empty() {
        warn!("Extra {} transactions in SPV wallet:", extra_txids.len());
        for txid in extra_txids.iter().take(10) {
            warn!("    {}", txid);
        }
        if extra_txids.len() > 10 {
            warn!("    ... and {} more", extra_txids.len() - 10);
        }
    }

    // Assert transaction count matches
    assert_eq!(
        spv_txids.len(),
        expected_txids.len(),
        "Transaction count mismatch: SPV has {}, expected {}",
        spv_txids.len(),
        expected_txids.len()
    );

    // Assert all expected transactions are present
    assert!(missing_txids.is_empty(), "SPV wallet is missing {} transactions", missing_txids.len());

    // Assert no unexpected transactions
    assert!(extra_txids.is_empty(), "SPV wallet has {} unexpected transactions", extra_txids.len());

    info!("All {} transactions match expected set", spv_txids.len());

    // Check wallet balance
    let balance = wallet_read.get_wallet_balance(&wallet_id).expect("Failed to get wallet balance");

    info!("SPV Wallet balance: {}", balance);

    let expected = light_wallet
        .utxos
        .iter()
        .filter_map(|u| u.get("amount").and_then(|v| v.as_f64()))
        .map(|dash| (dash * 100_000_000.0) as u64)
        .sum::<u64>();
    info!("Expected balance: {} satoshis ({:.8} DASH)", expected, expected as f64 / 100_000_000.0);

    assert_eq!(
        balance.spendable(),
        expected,
        "Wallet balance mismatch: SPV has {}, expected {}",
        balance.spendable(),
        expected
    );
    info!("Balance matches expected value from JSON");

    // Cleanup
    node.stop().await;

    info!("Full sync validation test completed successfully");
}

/// Type alias for the SPV client used in tests
type TestClient =
    DashSpvClient<WalletManager<ManagedWalletInfo>, PeerNetworkManager, DiskStorageManager>;

struct ClientHandle {
    monitor_handle: tokio::task::JoinHandle<TestClient>,
    progress_receiver: watch::Receiver<SyncProgress>,
    // Keep alive to keep the channel open otherwise the client will fail.
    _command_sender: UnboundedSender<DashSpvClientCommand>,
    cancel_token: CancellationToken,
}

impl ClientHandle {
    pub async fn stop(self) -> TestClient {
        // Abort the monitoring task
        info!("Aborting network monitoring task...");
        self.cancel_token.cancel();
        let (result,) = tokio::join!(self.monitor_handle);
        result.expect("Monitor network task failed")
    }
}

/// Creates a new SPV client and starts it
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

    let cancel_token = CancellationToken::new();
    let monitor_token = cancel_token.clone();
    let (_command_sender, command_receiver) = tokio::sync::mpsc::unbounded_channel();

    let monitor_handle = tokio::task::spawn(async move {
        if let Err(e) = client.monitor_network(command_receiver, monitor_token).await {
            warn!("Monitor network error: {}", e);
        }
        client
    });

    ClientHandle {
        monitor_handle,
        progress_receiver,
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
                {
                    let mut accounts = std::collections::BTreeSet::new();
                    accounts.insert(0);
                    accounts
                },
                std::collections::BTreeSet::new(),
                std::collections::BTreeSet::new(),
                std::collections::BTreeSet::new(),
                std::collections::BTreeSet::new(),
                None,
            ),
        )
        .expect("Failed to create wallet from mnemonic");
    (Arc::new(RwLock::new(wallet_manager)), wallet_id)
}

/// Create test client config pointing to a specific peer.
fn create_test_config(storage_path: PathBuf, peer_addr: std::net::SocketAddr) -> ClientConfig {
    let mut config = ClientConfig::regtest()
        .with_storage_path(storage_path)
        .with_validation_mode(ValidationMode::Basic)
        .with_mempool_tracking(MempoolStrategy::BloomFilter)
        .without_masternodes();
    config.peers.clear();
    config.peers.push(peer_addr);
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
                if update.is_synced() && current_height >= target_height {
                    return;
                }
            }
        }
    }
}

/// Get a receive address from the SPV wallet.
async fn get_wallet_receive_address(
    wallet: &Arc<RwLock<WalletManager<ManagedWalletInfo>>>,
    wallet_id: &WalletId,
) -> dashcore::Address {
    use key_wallet::managed_account::managed_account_type::ManagedAccountType;

    let wallet_read = wallet.read().await;
    let wallet_info = wallet_read.get_wallet_info(wallet_id).expect("Wallet info not found");

    // Get next unused receive address from BIP44 account 0
    let account =
        wallet_info.accounts().standard_bip44_accounts.get(&0).expect("BIP44 account 0 not found");

    // Extract external addresses from the Standard account type
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

    // Check in all accounts
    for account in wallet_info.accounts().all_accounts() {
        if account.transactions.contains_key(txid) {
            return true;
        }
    }

    // Also check immature transactions
    for tx in wallet_info.immature_transactions() {
        if &tx.txid() == txid {
            return true;
        }
    }

    false
}

/// Default source datadir for test blockchain (used by BlockchainCopy).
fn default_source_datadir() -> std::path::PathBuf {
    std::env::var("DASHD_DATADIR").map(std::path::PathBuf::from).expect("DASHD_DATADIR not set")
}

/// Verify sync state is identical after stopping and restarting with same storage.
#[tokio::test]
async fn test_sync_restart_consistency() {
    let _guard = dash_spv::init_console_logging(LevelFilter::DEBUG).ok();
    kill_all_dashd();

    if !is_dashd_available() {
        warn!("dashd not available, skipping test");
        return;
    }

    // Create isolated blockchain copy
    let blockchain =
        BlockchainCopy::new(&default_source_datadir()).expect("Failed to create blockchain copy");

    let config = DashCoreConfig {
        datadir: blockchain.datadir().to_path_buf(),
        wallet: "light".to_string(),
        ..Default::default()
    };
    info!("Using datadir: {:?}", config.datadir);

    // Load light wallet from test data
    let light_wallet =
        load_wallet_file(&config.datadir, "light").expect("Failed to load light wallet");
    info!(
        "Loaded '{}' wallet with {} transactions",
        light_wallet.wallet_name, light_wallet.transaction_count
    );

    let mut node = DashCoreNode::with_config(config).expect("Failed to create DashCoreNode");
    let addr = node.start().await.expect("Failed to start dashd");
    info!("DashCoreNode started at {}", addr);

    let expected_height =
        node.get_block_count().await.expect("Failed to get block count from dashd");
    info!("Dashd has {} blocks", expected_height);

    // Create SPV client config
    let storage_dir = TempDir::new().expect("Failed to create temporary directory");
    let storage_path = storage_dir.path().to_path_buf();
    let client_config = create_test_config(storage_path, addr);

    // Create wallet from mnemonic
    let (wallet, wallet_id) = create_test_wallet(&light_wallet.mnemonic, Network::Regtest);

    // === First sync ===
    info!("=== Starting first sync ===");
    let mut client_handle = create_and_start_client(&client_config, Arc::clone(&wallet)).await;
    wait_for_sync(&mut client_handle.progress_receiver, expected_height, 180).await;
    info!("First sync completed");

    // Record state after first sync
    let mut first_client = client_handle.stop().await;
    let first_progress = first_client.progress();
    let first_header_height = first_progress.headers().unwrap().current_height();
    let first_filter_height = first_progress.filter_headers().unwrap().current_height();

    let first_balance = {
        let wallet_read = wallet.read().await;
        wallet_read.get_wallet_balance(&wallet_id).expect("Failed to get wallet balance")
    };

    let first_tx_count = {
        let wallet_read = wallet.read().await;
        let wallet_info = wallet_read.get_wallet_info(&wallet_id).expect("Wallet info not found");
        let mut count = 0;
        for account in wallet_info.accounts().all_accounts() {
            count += account.transactions.len();
        }
        count += wallet_info.immature_transactions().len();
        count
    };

    info!(
        "First sync state: headers={}, filters={}, balance={}, tx_count={}",
        first_header_height,
        first_filter_height,
        first_balance.spendable(),
        first_tx_count
    );

    // Stop first client and drop it to release storage lock
    first_client.stop().await.expect("Failed to stop first client");
    drop(first_client);
    info!("First client stopped and storage released");

    // Brief delay to ensure lock is fully released
    tokio::time::sleep(Duration::from_millis(100)).await;

    // === Restart client with same storage ===
    info!("=== Restarting client with same storage ===");
    let mut client_handle = create_and_start_client(&client_config, Arc::clone(&wallet)).await;

    // Wait briefly for client to restore state from storage
    tokio::time::sleep(Duration::from_secs(3)).await;
    wait_for_sync(&mut client_handle.progress_receiver, expected_height, 60).await;
    info!("Restart sync completed");

    let mut second_client = client_handle.stop().await;
    let second_progress = second_client.progress();
    let second_header_height = second_progress.headers().unwrap().current_height();
    let second_filter_height = second_progress.filter_headers().unwrap().current_height();

    let second_balance = {
        let wallet_read = wallet.read().await;
        wallet_read.get_wallet_balance(&wallet_id).expect("Failed to get wallet balance")
    };

    let second_tx_count = {
        let wallet_read = wallet.read().await;
        let wallet_info = wallet_read.get_wallet_info(&wallet_id).expect("Wallet info not found");
        let mut count = 0;
        for account in wallet_info.accounts().all_accounts() {
            count += account.transactions.len();
        }
        count += wallet_info.immature_transactions().len();
        count
    };

    info!(
        "Second sync state: headers={}, filters={}, balance={}, tx_count={}",
        second_header_height,
        second_filter_height,
        second_balance.spendable(),
        second_tx_count
    );

    // === Assertions ===
    info!("=== Validation ===");

    assert_eq!(
        first_header_height, second_header_height,
        "Header height mismatch after restart: {} vs {}",
        first_header_height, second_header_height
    );
    info!("Header height consistent: {}", first_header_height);

    assert_eq!(
        first_filter_height, second_filter_height,
        "Filter header height mismatch after restart: {} vs {}",
        first_filter_height, second_filter_height
    );
    info!("Filter header height consistent: {}", first_filter_height);

    assert_eq!(
        first_balance.spendable(),
        second_balance.spendable(),
        "Balance mismatch after restart: {} vs {}",
        first_balance.spendable(),
        second_balance.spendable()
    );
    info!("Balance consistent: {}", first_balance.spendable());

    assert_eq!(
        first_tx_count, second_tx_count,
        "Transaction count mismatch after restart: {} vs {}",
        first_tx_count, second_tx_count
    );
    info!("Transaction count consistent: {}", first_tx_count);

    // Stop second client before cleanup
    second_client.stop().await.expect("Failed to stop second client");

    node.stop().await;
    info!("test_sync_restart_consistency completed successfully");
}

/// Verify sync state is correct after restarting with a fresh wallet (rescan scenario).
/// This simulates app restart where wallet state is NOT persisted but storage is.
#[tokio::test]
async fn test_sync_restart_with_fresh_wallet() {
    let _guard = dash_spv::init_console_logging(LevelFilter::DEBUG).ok();
    kill_all_dashd();

    if !is_dashd_available() {
        warn!("dashd not available, skipping test");
        return;
    }

    // Create isolated blockchain copy
    let blockchain =
        BlockchainCopy::new(&default_source_datadir()).expect("Failed to create blockchain copy");

    let config = DashCoreConfig {
        datadir: blockchain.datadir().to_path_buf(),
        wallet: "light".to_string(),
        ..Default::default()
    };
    info!("Using datadir: {:?}", config.datadir);

    // Load light wallet from test data
    let light_wallet =
        load_wallet_file(&config.datadir, "light").expect("Failed to load light wallet");
    info!(
        "Loaded '{}' wallet with {} transactions",
        light_wallet.wallet_name, light_wallet.transaction_count
    );

    let mut node = DashCoreNode::with_config(config).expect("Failed to create DashCoreNode");
    let addr = node.start().await.expect("Failed to start dashd");
    info!("DashCoreNode started at {}", addr);

    let expected_height =
        node.get_block_count().await.expect("Failed to get block count from dashd");
    info!("Dashd has {} blocks", expected_height);

    // Create SPV client config
    let storage_dir = TempDir::new().expect("Failed to create temporary directory");
    let storage_path = storage_dir.path().to_path_buf();
    let client_config = create_test_config(storage_path, addr);

    // Create first wallet from mnemonic
    let (wallet, wallet_id) = create_test_wallet(&light_wallet.mnemonic, Network::Regtest);

    // === First sync ===
    info!("=== Starting first sync ===");
    let mut client_handle = create_and_start_client(&client_config, Arc::clone(&wallet)).await;
    wait_for_sync(&mut client_handle.progress_receiver, expected_height, 180).await;
    info!("First sync completed");

    // Record state after first sync
    let mut first_client = client_handle.stop().await;
    let first_progress = first_client.progress();
    let first_header_height = first_progress.headers().unwrap().current_height();
    let first_filter_height = first_progress.filter_headers().unwrap().current_height();

    let first_balance = {
        let wallet_read = wallet.read().await;
        wallet_read.get_wallet_balance(&wallet_id).expect("Failed to get wallet balance")
    };

    let first_tx_count = {
        let wallet_read = wallet.read().await;
        let wallet_info = wallet_read.get_wallet_info(&wallet_id).expect("Wallet info not found");
        let mut count = 0;
        for account in wallet_info.accounts().all_accounts() {
            count += account.transactions.len();
        }
        count += wallet_info.immature_transactions().len();
        count
    };

    info!(
        "First sync state: headers={}, filters={}, balance={}, tx_count={}",
        first_header_height,
        first_filter_height,
        first_balance.spendable(),
        first_tx_count
    );

    // Stop first client and drop it to release storage lock
    first_client.stop().await.expect("Failed to stop first client");
    drop(first_client);
    drop(wallet); // Drop the first wallet
    info!("First client stopped and storage released");

    // Brief delay to ensure lock is fully released
    tokio::time::sleep(Duration::from_millis(100)).await;

    // === Restart with FRESH wallet (simulating app restart without wallet persistence) ===
    info!("=== Restarting with fresh wallet (triggers rescan) ===");

    // Create a NEW wallet from the same mnemonic - this has synced_height = 0
    let (fresh_wallet, fresh_wallet_id) =
        create_test_wallet(&light_wallet.mnemonic, Network::Regtest);

    // Verify fresh wallet starts with zero state
    {
        let wallet_read = fresh_wallet.read().await;
        let balance =
            wallet_read.get_wallet_balance(&fresh_wallet_id).expect("Failed to get wallet balance");
        assert_eq!(balance.spendable(), 0, "Fresh wallet should start with zero balance");
        info!("Fresh wallet confirmed to start with zero balance");
    }

    let mut client_handle =
        create_and_start_client(&client_config, Arc::clone(&fresh_wallet)).await;

    // Wait for rescan to complete - this should take longer as it rescans all stored filters
    wait_for_sync(&mut client_handle.progress_receiver, expected_height, 180).await;
    info!("Rescan sync completed");

    let mut second_client = client_handle.stop().await;
    let second_progress = second_client.progress();
    let second_header_height = second_progress.headers().unwrap().current_height();
    let second_filter_height = second_progress.filter_headers().unwrap().current_height();

    let second_balance = {
        let wallet_read = fresh_wallet.read().await;
        wallet_read.get_wallet_balance(&fresh_wallet_id).expect("Failed to get wallet balance")
    };

    let second_tx_count = {
        let wallet_read = fresh_wallet.read().await;
        let wallet_info =
            wallet_read.get_wallet_info(&fresh_wallet_id).expect("Wallet info not found");
        let mut count = 0;
        for account in wallet_info.accounts().all_accounts() {
            count += account.transactions.len();
        }
        count += wallet_info.immature_transactions().len();
        count
    };

    info!(
        "After rescan state: headers={}, filters={}, balance={}, tx_count={}",
        second_header_height,
        second_filter_height,
        second_balance.spendable(),
        second_tx_count
    );

    // === Assertions ===
    info!("=== Validation ===");

    assert_eq!(
        first_header_height, second_header_height,
        "Header height mismatch after rescan: {} vs {}",
        first_header_height, second_header_height
    );
    info!("Header height consistent: {}", first_header_height);

    assert_eq!(
        first_filter_height, second_filter_height,
        "Filter header height mismatch after rescan: {} vs {}",
        first_filter_height, second_filter_height
    );
    info!("Filter header height consistent: {}", first_filter_height);

    assert_eq!(
        first_balance.spendable(),
        second_balance.spendable(),
        "Balance mismatch after rescan: {} vs {}",
        first_balance.spendable(),
        second_balance.spendable()
    );
    info!("Balance consistent after rescan: {}", first_balance.spendable());

    assert_eq!(
        first_tx_count, second_tx_count,
        "Transaction count mismatch after rescan: {} vs {}",
        first_tx_count, second_tx_count
    );
    info!("Transaction count consistent after rescan: {}", first_tx_count);

    // Stop second client before cleanup
    second_client.stop().await.expect("Failed to stop second client");

    node.stop().await;
    info!("test_sync_restart_with_fresh_wallet completed successfully");
}

/// Wait for sync to reach a minimum height, returning the current height.
/// Useful for testing partial sync before interruption.
async fn wait_for_partial_sync(
    progress_receiver: &mut watch::Receiver<SyncProgress>,
    min_height: u32,
    timeout_secs: u64,
) -> u32 {
    let timeout = tokio::time::sleep(Duration::from_secs(timeout_secs));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = &mut timeout => {
                let update = progress_receiver.borrow();
                if let Ok(headers) = update.headers() {
                    return headers.current_height();
                }
                return 0;
            }
            result = progress_receiver.changed() => {
                if result.is_err() {
                    let update = progress_receiver.borrow();
                    if let Ok(headers) = update.headers() {
                        return headers.current_height();
                    }
                    return 0;
                }
                let update = progress_receiver.borrow_and_update().clone();
                if let Ok(headers) = update.headers() {
                    if headers.current_height() >= min_height {
                        return headers.current_height();
                    }
                }
            }
        }
    }
}

/// Verify sync completes successfully despite multiple interruptions.
#[tokio::test]
async fn test_sync_with_multiple_restarts() {
    let _guard = dash_spv::init_console_logging(LevelFilter::DEBUG).ok();
    kill_all_dashd();

    if !is_dashd_available() {
        warn!("dashd not available, skipping test");
        return;
    }

    // Create isolated blockchain copy
    let blockchain =
        BlockchainCopy::new(&default_source_datadir()).expect("Failed to create blockchain copy");

    let config = DashCoreConfig {
        datadir: blockchain.datadir().to_path_buf(),
        wallet: "light".to_string(),
        ..Default::default()
    };
    info!("Using datadir: {:?}", config.datadir);

    // Load light wallet from test data
    let light_wallet =
        load_wallet_file(&config.datadir, "light").expect("Failed to load light wallet");
    info!(
        "Loaded '{}' wallet with {} transactions",
        light_wallet.wallet_name, light_wallet.transaction_count
    );

    let mut node = DashCoreNode::with_config(config).expect("Failed to create DashCoreNode");
    let addr = node.start().await.expect("Failed to start dashd");
    info!("DashCoreNode started at {}", addr);

    let expected_height =
        node.get_block_count().await.expect("Failed to get block count from dashd");
    info!("Dashd has {} blocks", expected_height);

    // Create SPV client config and storage
    let storage_dir = TempDir::new().expect("Failed to create temporary directory");
    let storage_path = storage_dir.path().to_path_buf();
    let client_config = create_test_config(storage_path, addr);

    // Create wallet from mnemonic
    let (wallet, wallet_id) = create_test_wallet(&light_wallet.mnemonic, Network::Regtest);

    // Calculate target heights for partial syncs
    let target_30_percent = expected_height * 30 / 100;
    let target_60_percent = expected_height * 60 / 100;

    // === First partial sync (target ~30%) ===
    info!("=== Starting first partial sync (target ~{}%) ===", 30);
    let mut client_handle = create_and_start_client(&client_config, Arc::clone(&wallet)).await;

    let first_stop_height =
        wait_for_partial_sync(&mut client_handle.progress_receiver, target_30_percent, 120).await;
    info!("First partial sync reached height {}", first_stop_height);
    assert!(
        first_stop_height >= target_30_percent,
        "First sync did not reach target: {} < {}",
        first_stop_height,
        target_30_percent
    );

    let mut first_client = client_handle.stop().await;
    first_client.stop().await.expect("Failed to stop first client");
    drop(first_client);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // === Second partial sync (target ~60%) ===
    info!("=== Starting second partial sync (target ~{}%) ===", 60);
    let mut client_handle = create_and_start_client(&client_config, Arc::clone(&wallet)).await;

    // Wait briefly for client to initialize
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Check that we resumed from where we left off (not from genesis)
    let resumed_height = {
        let progress = client_handle.progress_receiver.borrow();
        progress.headers().ok().map(|h| h.current_height()).unwrap_or(0)
    };
    info!("Resumed from height {}", resumed_height);
    assert!(
        resumed_height >= first_stop_height,
        "Did not resume from previous height: {} < {}",
        resumed_height,
        first_stop_height
    );

    let second_stop_height =
        wait_for_partial_sync(&mut client_handle.progress_receiver, target_60_percent, 120).await;
    info!("Second partial sync reached height {}", second_stop_height);
    assert!(
        second_stop_height >= target_60_percent,
        "Second sync did not reach target: {} < {}",
        second_stop_height,
        target_60_percent
    );

    let mut second_client = client_handle.stop().await;
    second_client.stop().await.expect("Failed to stop second client");
    drop(second_client);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // === Final sync to completion ===
    info!("=== Starting final sync to completion ===");
    let mut client_handle = create_and_start_client(&client_config, Arc::clone(&wallet)).await;

    wait_for_sync(&mut client_handle.progress_receiver, expected_height, 180).await;
    info!("Final sync completed");

    let mut final_client = client_handle.stop().await;
    let final_progress = final_client.progress();
    let final_header_height = final_progress.headers().unwrap().current_height();
    let final_state = final_progress.state();

    info!("Final sync state: headers={}, state={:?}", final_header_height, final_state);

    // === Assertions ===
    assert_eq!(
        final_header_height, expected_height,
        "Final header height mismatch: {} vs {}",
        final_header_height, expected_height
    );
    info!("Final header height matches expected: {}", final_header_height);

    // Verify wallet state
    let final_balance = {
        let wallet_read = wallet.read().await;
        wallet_read.get_wallet_balance(&wallet_id).expect("Failed to get wallet balance")
    };
    info!("Final wallet balance: {}", final_balance.spendable());

    // Stop final client before cleanup
    final_client.stop().await.expect("Failed to stop final client");

    node.stop().await;
    info!("test_sync_with_multiple_restarts completed successfully");
}

/// Verify newly generated blocks with wallet transactions sync properly.
#[tokio::test]
async fn test_sync_then_generate_blocks() {
    let _guard = dash_spv::init_console_logging(LevelFilter::DEBUG).ok();
    kill_all_dashd();

    if !is_dashd_available() {
        warn!("dashd not available, skipping test");
        return;
    }

    // Create isolated blockchain copy
    let blockchain =
        BlockchainCopy::new(&default_source_datadir()).expect("Failed to create blockchain copy");

    let config = DashCoreConfig {
        datadir: blockchain.datadir().to_path_buf(),
        wallet: "light".to_string(),
        ..Default::default()
    };
    info!("Using datadir: {:?}", config.datadir);

    // Load light wallet from test data
    let light_wallet =
        load_wallet_file(&config.datadir, "light").expect("Failed to load light wallet");
    info!(
        "Loaded '{}' wallet with {} transactions",
        light_wallet.wallet_name, light_wallet.transaction_count
    );

    let mut node = DashCoreNode::with_config(config).expect("Failed to create DashCoreNode");
    let addr = node.start().await.expect("Failed to start dashd");
    info!("DashCoreNode started at {}", addr);

    let initial_height =
        node.get_block_count().await.expect("Failed to get block count from dashd");
    info!("Dashd has {} blocks initially", initial_height);

    // Create SPV client config and storage
    let storage_dir = TempDir::new().expect("Failed to create temporary directory");
    let storage_path = storage_dir.path().to_path_buf();
    let client_config = create_test_config(storage_path, addr);

    // Create wallet from mnemonic
    let (wallet, wallet_id) = create_test_wallet(&light_wallet.mnemonic, Network::Regtest);

    // === Initial sync ===
    info!("=== Starting initial sync ===");
    let mut client_handle = create_and_start_client(&client_config, Arc::clone(&wallet)).await;
    wait_for_sync(&mut client_handle.progress_receiver, initial_height, 180).await;
    info!("Initial sync completed");

    // Record initial state
    let initial_balance = {
        let wallet_read = wallet.read().await;
        wallet_read
            .get_wallet_balance(&wallet_id)
            .expect("Failed to get wallet balance")
            .spendable()
    };
    let initial_tx_count = {
        let wallet_read = wallet.read().await;
        let wallet_info = wallet_read.get_wallet_info(&wallet_id).expect("Wallet info not found");
        let mut count = 0;
        for account in wallet_info.accounts().all_accounts() {
            count += account.transactions.len();
        }
        count += wallet_info.immature_transactions().len();
        count
    };
    info!(
        "Initial state: height={}, balance={}, tx_count={}",
        initial_height, initial_balance, initial_tx_count
    );

    // === Generate blocks with transaction to SPV wallet ===
    info!("=== Generating blocks with transaction to SPV wallet ===");

    // Get an unused receive address from SPV wallet
    let receive_address = get_wallet_receive_address(&wallet, &wallet_id).await;
    info!("SPV wallet receive address: {}", receive_address);

    // Send DASH to the SPV wallet
    let send_amount = Amount::from_sat(100_000_000); // 1 DASH
    let txid = node
        .send_to_address(&receive_address, send_amount)
        .expect("Failed to send DASH to SPV wallet");
    info!("Sent {} to SPV wallet, txid: {}", send_amount, txid);

    // Generate 6 blocks to confirm the transaction
    let new_blocks = 6;
    let miner_address = node.get_new_address().expect("Failed to get miner address");
    let block_hashes =
        node.generate_blocks(new_blocks, &miner_address).expect("Failed to generate blocks");
    info!("Generated {} blocks: {:?}", new_blocks, block_hashes);

    let expected_new_height = initial_height + new_blocks as u32;

    // === Wait for SPV to sync new blocks ===
    info!("=== Waiting for SPV to sync new blocks ===");

    // Wait for sync to reach new height
    wait_for_sync(&mut client_handle.progress_receiver, expected_new_height, 60).await;
    info!("SPV synced to height {}", expected_new_height);

    // Get final state
    let mut client = client_handle.stop().await;
    let final_progress = client.progress();
    let final_header_height = final_progress.headers().unwrap().current_height();

    let final_balance = {
        let wallet_read = wallet.read().await;
        wallet_read
            .get_wallet_balance(&wallet_id)
            .expect("Failed to get wallet balance")
            .spendable()
    };
    let final_tx_count = {
        let wallet_read = wallet.read().await;
        let wallet_info = wallet_read.get_wallet_info(&wallet_id).expect("Wallet info not found");
        let mut count = 0;
        for account in wallet_info.accounts().all_accounts() {
            count += account.transactions.len();
        }
        count += wallet_info.immature_transactions().len();
        count
    };

    info!(
        "Final state: height={}, balance={}, tx_count={}",
        final_header_height, final_balance, final_tx_count
    );

    // === Assertions ===
    info!("=== Validation ===");

    // Verify new header height
    assert_eq!(
        final_header_height, expected_new_height,
        "Header height mismatch: {} vs {}",
        final_header_height, expected_new_height
    );
    info!("Header height increased correctly: {} -> {}", initial_height, final_header_height);

    // Verify wallet has the transaction
    let has_tx = wallet_has_transaction(&wallet, &wallet_id, &txid).await;
    assert!(has_tx, "SPV wallet should contain transaction {}", txid);
    info!("SPV wallet contains the sent transaction: {}", txid);

    // Note: Since both dashd and SPV use the same "light" wallet (same mnemonic),
    // this is effectively a self-transfer. The balance change reflects only the fee
    // and any coinbase rewards from the generated blocks.
    // The important assertion is that the transaction was found in the wallet above.
    info!(
        "Balance changed: {} -> {} (delta: {})",
        initial_balance,
        final_balance,
        final_balance as i64 - initial_balance as i64
    );

    // Verify transaction count increased (new blocks contain transactions)
    assert!(
        final_tx_count > initial_tx_count,
        "Transaction count should have increased: {} -> {}",
        initial_tx_count,
        final_tx_count
    );
    info!("Transaction count increased: {} -> {}", initial_tx_count, final_tx_count);

    // Stop client before cleanup
    client.stop().await.expect("Failed to stop client");

    node.stop().await;
    info!("test_sync_then_generate_blocks completed successfully");
}
