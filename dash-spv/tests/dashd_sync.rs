//! SPV sync tests using dashd.
//!
//! These tests demonstrate realistic SPV sync scenarios against a dashd instance.
mod common;

use common::{is_dashd_available, DashCoreNode};
use dash_spv::{
    client::{config::MempoolStrategy, ClientConfig, DashSpvClient},
    network::PeerNetworkManager,
    storage::DiskStorageManager,
    types::ValidationMode,
    LevelFilter, Network,
};
use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::wallet_manager::WalletManager;
use serde::Deserialize;
use std::fs::{self, File};
use std::io::Write;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// Wallet file structure (individual wallet JSON)
#[derive(Debug, Deserialize)]
struct WalletFile {
    wallet_name: String,
    mnemonic: String,
    balance: f64,
    transaction_count: usize,
    utxo_count: usize,
    transactions: Vec<serde_json::Value>,
    utxos: Vec<serde_json::Value>,
}

/// Helper function to load light wallet from test data
fn load_light_wallet(
    test_data_dir: &std::path::Path,
) -> Result<WalletFile, Box<dyn std::error::Error>> {
    let wallet_path = test_data_dir.join("wallets/light.json");

    let json_content = fs::read_to_string(&wallet_path)?;
    let wallet_file: WalletFile = serde_json::from_str(&json_content)?;

    Ok(wallet_file)
}

fn kill_all_dashd() {
    // Kill any existing dashd processes
    let _ = Command::new("pkill").arg("-9").arg("-x").arg("dashd").output();
    // Wait a moment for processes to die
    std::thread::sleep(Duration::from_millis(500));
}

#[tokio::test]
async fn test_wallet_sync() {
    let _guard =
        dash_spv::init_console_logging(LevelFilter::DEBUG).expect("Failed to initialize logging");
    kill_all_dashd();

    // Skip if dashd is not available
    if !is_dashd_available() {
        warn!("dashd not available, skipping test");
        return;
    }

    // Create config with light wallet
    let config = common::node::DashCoreConfig {
        wallet: "light".to_string(),
        ..Default::default()
    };
    info!("Using datadir: {:?}", config.datadir);

    // Load light wallet from test data
    let light_wallet = load_light_wallet(&config.datadir).expect("Failed to load light wallet");
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
    let mut config = ClientConfig::new(Network::Regtest)
        .with_validation_mode(ValidationMode::Basic)
        .with_connection_timeout(Duration::from_secs(30))
        .with_mempool_tracking(MempoolStrategy::BloomFilter)
        .without_masternodes(); // Regtest doesn't have masternodes/quorums

    config.peers.clear();
    config.peers.push(addr);

    // Create network and storage managers
    let network_manager =
        PeerNetworkManager::new(&config).await.expect("Failed to create network manager");
    let temp_dir = TempDir::new().expect("Failed to create temporary directory");
    let storage_manager = DiskStorageManager::new(temp_dir.path().to_path_buf())
        .await
        .expect("Failed to create storage manager");

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
                std::collections::BTreeSet::new(), // No BIP32 accounts
                std::collections::BTreeSet::new(), // No CoinJoin accounts
                std::collections::BTreeSet::new(), // No identity top-up accounts
                None,                              // No additional special accounts
            ),
        )
        .expect("Failed to create wallet from mnemonic");
    info!("Created wallet from mnemonic, ID: {:?}", wallet_id);

    let wallet = Arc::new(RwLock::new(wallet_manager));

    // Create SPV client
    let mut client = DashSpvClient::new(config, network_manager, storage_manager, wallet.clone())
        .await
        .expect("Failed to create SPV client");

    // Start syncing
    info!("Starting SPV client sync...");
    client.start().await.expect("Failed to start SPV client");

    // Take the progress receiver
    let mut progress_receiver =
        client.take_progress_receiver().expect("Progress receiver should be available");

    let token = CancellationToken::new();
    let monitor_token = token.clone();
    let (_command_sender, command_receiver) = tokio::sync::mpsc::unbounded_channel();
    // Spawn monitor_network() in background
    info!("Starting network monitoring task...");
    let monitor_handle = tokio::task::spawn(async move {
        if let Err(e) = client.monitor_network(command_receiver, monitor_token).await {
            warn!("Monitor network error: {}", e);
        }
        client
    });

    // Wait for sync to complete
    info!("Waiting for sync to complete (expected height: {})...", expected_height);
    let timeout = tokio::time::sleep(Duration::from_secs(120));
    tokio::pin!(timeout);
    let mut last_height = None;

    let final_progress = loop {
        tokio::select! {
            _ = &mut timeout => {
                panic!(
                    "SPV client sync timeout after 120 seconds at height {:?}",
                    last_height
                );
            }
            progress = progress_receiver.recv() => {
                match progress {
                    Some(progress) => {
                        let height = progress.sync_progress.header_height;

                        // Log progress when height changes
                        if last_height != Some(height) {
                            info!(
                                "Sync progress: {}/{} headers ({:.1}%) - Stage: {:?}",
                                height, expected_height, progress.percentage, progress.sync_stage
                            );
                            last_height = Some(height);
                        }

                        // Check if sync is complete
                        if progress.sync_stage == dash_spv::types::SyncStage::Complete {
                            info!(
                                "Sync completed! Headers: {}, Filter headers: {}, Filters: {}",
                                progress.sync_progress.header_height,
                                progress.sync_progress.filter_header_height,
                                progress.sync_progress.filters_downloaded
                            );
                            break progress.sync_progress;
                        }

                        // Check for failed state
                        if let dash_spv::types::SyncStage::Failed(reason) = &progress.sync_stage {
                            panic!("Sync failed: {}", reason);
                        }
                    }
                    None => {
                        panic!("Progress channel closed unexpectedly");
                    }
                }
            }
        }
    };

    // Abort the monitoring task
    info!("Aborting network monitoring task...");
    token.cancel();
    let (result,) = tokio::join!(monitor_handle);
    assert!(result.is_ok(), "Monitor network task failed");

    // Validate sync results
    info!("=== Validation ===");

    assert_eq!(final_progress.header_height, expected_height, "Header height mismatch");
    info!("Header height matches: {}", final_progress.header_height);

    assert_eq!(
        final_progress.filter_header_height, expected_height,
        "Filter header height mismatch"
    );
    info!("Filter header height matches: {}", final_progress.filter_header_height);

    assert!(final_progress.peer_count > 0, "No peers connected");
    info!("Connected to {} peer(s)", final_progress.peer_count);

    // Get the read lock of the wallet
    let wallet_read = wallet.read().await;

    // Validate wallet data
    let wallet_info = wallet_read.get_wallet_info(&wallet_id).expect("Wallet info not found");

    // Get SPV UTXOs and write to file for comparison
    {
        let utxos = wallet_info.get_utxos();

        let mut spv_utxos: Vec<String> = utxos
            .iter()
            .map(|(outpoint, _utxo)| format!("{}:{}", outpoint.txid, outpoint.vout))
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
    let immature = wallet_info.immature_transactions().all();
    for tx in immature {
        spv_txids.insert(tx.txid.to_string());
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

    info!(
        "SPV Wallet balance: {} satoshis ({:.8} DASH)",
        balance.total,
        balance.total as f64 / 100_000_000.0
    );

    let expected = light_wallet
        .utxos
        .iter()
        .filter_map(|u| u.get("amount").and_then(|v| v.as_f64()))
        .map(|dash| (dash * 100_000_000.0) as u64)
        .sum::<u64>();
    info!("Expected balance: {} satoshis ({:.8} DASH)", expected, expected as f64 / 100_000_000.0);

    assert_eq!(
        balance.total, expected,
        "Wallet balance mismatch: SPV has {}, expected {}",
        balance.total, expected
    );
    info!("Balance matches expected value from JSON");

    // Cleanup
    node.stop().await;

    info!("Full sync validation test completed successfully");
}
