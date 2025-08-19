//! Command-line interface for the Dash SPV client.

// Removed unused import
use std::path::PathBuf;
use std::process;
use std::sync::Arc;

use clap::{Arg, Command};
use tokio::signal;

use dash_spv::terminal::TerminalGuard;
use dash_spv::{ClientConfig, DashSpvClient, Network};
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::wallet_manager::WalletManager;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Error: {}", e);

        // Provide specific exit codes for different error types
        let exit_code = if let Some(spv_error) = e.downcast_ref::<dash_spv::SpvError>() {
            match spv_error {
                dash_spv::SpvError::Network(_) => 1,
                dash_spv::SpvError::Storage(_) => 2,
                dash_spv::SpvError::Validation(_) => 3,
                dash_spv::SpvError::Config(_) => 4,
                dash_spv::SpvError::Parse(_) => 5,
                _ => 255,
            }
        } else {
            255
        };

        process::exit(exit_code);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("dash-spv")
        .version(dash_spv::VERSION)
        .about("Dash SPV (Simplified Payment Verification) client")
        .arg(
            Arg::new("network")
                .short('n')
                .long("network")
                .value_name("NETWORK")
                .help("Network to connect to")
                .value_parser(["mainnet", "testnet", "regtest"])
                .default_value("mainnet"),
        )
        .arg(
            Arg::new("data-dir")
                .short('d')
                .long("data-dir")
                .value_name("DIR")
                .help("Data directory for storage (default: unique directory in /tmp)"),
        )
        .arg(
            Arg::new("peer")
                .short('p')
                .long("peer")
                .value_name("ADDRESS")
                .help("Peer address to connect to (can be used multiple times)")
                .action(clap::ArgAction::Append),
        )
        .arg(
            Arg::new("log-level")
                .short('l')
                .long("log-level")
                .value_name("LEVEL")
                .help("Log level")
                .value_parser(["error", "warn", "info", "debug", "trace"])
                .default_value("info"),
        )
        .arg(
            Arg::new("no-filters")
                .long("no-filters")
                .help("Disable BIP157 filter synchronization")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("no-masternodes")
                .long("no-masternodes")
                .help("Disable masternode list synchronization")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("validation-mode")
                .long("validation-mode")
                .value_name("MODE")
                .help("Validation mode")
                .value_parser(["none", "basic", "full"])
                .default_value("full"),
        )
        .arg(
            Arg::new("watch-address")
                .short('w')
                .long("watch-address")
                .value_name("ADDRESS")
                .help("Dash address to watch for transactions (can be used multiple times)")
                .action(clap::ArgAction::Append),
        )
        .arg(
            Arg::new("add-example-addresses")
                .long("add-example-addresses")
                .help("Add some example Dash addresses to watch for testing")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("terminal-ui")
                .long("terminal-ui")
                .help("Enable terminal UI status bar")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("start-height")
                .long("start-height")
                .short('s')
                .help("Start syncing from a specific block height using the nearest checkpoint. Use 'now' for the latest checkpoint")
                .value_name("HEIGHT"),
        )
        .get_matches();

    // Get log level (will be used after we know if terminal UI is enabled)
    let log_level = matches.get_one::<String>("log-level").ok_or("Missing log-level argument")?;

    // Parse network
    let network_str = matches.get_one::<String>("network").ok_or("Missing network argument")?;
    let network = match network_str.as_str() {
        "mainnet" => Network::Dash,
        "testnet" => Network::Testnet,
        "regtest" => Network::Regtest,
        n => return Err(format!("Invalid network: {}", n).into()),
    };

    // Parse validation mode
    let validation_str =
        matches.get_one::<String>("validation-mode").ok_or("Missing validation-mode argument")?;
    let validation_mode = match validation_str.as_str() {
        "none" => dash_spv::ValidationMode::None,
        "basic" => dash_spv::ValidationMode::Basic,
        "full" => dash_spv::ValidationMode::Full,
        v => return Err(format!("Invalid validation mode: {}", v).into()),
    };

    // Create configuration
    let data_dir = if let Some(data_dir_str) = matches.get_one::<String>("data-dir") {
        PathBuf::from(data_dir_str)
    } else {
        // Create a unique temp directory with timestamp and process ID
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let pid = std::process::id();
        let dir_name = format!("dash-spv-{}-{}", timestamp, pid);
        std::env::temp_dir().join(dir_name)
    };
    let mut config = ClientConfig::new(network)
        .with_storage_path(data_dir.clone())
        .with_validation_mode(validation_mode)
        .with_log_level(log_level);

    // Add custom peers if specified
    if let Some(peers) = matches.get_many::<String>("peer") {
        config.peers.clear();
        for peer in peers {
            match peer.parse() {
                Ok(addr) => config.add_peer(addr),
                Err(e) => {
                    eprintln!("Invalid peer address '{}': {}", peer, e);
                    process::exit(1);
                }
            };
        }
    }

    // Configure features
    if matches.get_flag("no-filters") {
        config = config.without_filters();
    }
    if matches.get_flag("no-masternodes") {
        config = config.without_masternodes();
    }

    // Set start height if specified
    if let Some(start_height_str) = matches.get_one::<String>("start-height") {
        if start_height_str == "now" {
            // Use a very high number to get the latest checkpoint
            config.start_from_height = Some(u32::MAX);
            tracing::info!("Will start syncing from the latest available checkpoint");
        } else {
            let start_height = start_height_str
                .parse::<u32>()
                .map_err(|e| format!("Invalid start height '{}': {}", start_height_str, e))?;
            config.start_from_height = Some(start_height);
            tracing::info!("Will start syncing from height: {}", start_height);
        }
    }

    // Validate configuration
    if let Err(e) = config.validate() {
        eprintln!("Configuration error: {}", e);
        process::exit(1);
    }

    tracing::info!("Starting Dash SPV client");
    tracing::info!("Network: {:?}", network);
    if let Some(path) = config.storage_path.as_ref() {
        tracing::info!("Data directory: {}", path.display());
    }
    tracing::info!("Validation mode: {:?}", validation_mode);
    tracing::info!("Sync strategy: Sequential");

    // Check if terminal UI should be enabled
    let enable_terminal_ui = matches.get_flag("terminal-ui");

    // Initialize logging first (without terminal UI)
    dash_spv::init_logging(log_level)?;

    // Log the data directory being used
    tracing::info!("Using data directory: {}", data_dir.display());

    // Create the SPV wallet manager
    let spv_wallet =
        key_wallet_manager::spv_wallet_manager::SPVWalletManager::with_base(WalletManager::<
            ManagedWalletInfo,
        >::new());
    let wallet = Arc::new(tokio::sync::RwLock::new(spv_wallet));

    // Create network manager
    let network_manager =
        match dash_spv::network::multi_peer::MultiPeerNetworkManager::new(&config).await {
            Ok(nm) => nm,
            Err(e) => {
                eprintln!("Failed to create network manager: {}", e);
                process::exit(1);
            }
        };

    // Create and start the client based on storage type
    if config.enable_persistence {
        if let Some(path) = &config.storage_path {
            let storage_manager =
                match dash_spv::storage::DiskStorageManager::new(path.clone()).await {
                    Ok(sm) => sm,
                    Err(e) => {
                        eprintln!("Failed to create disk storage manager: {}", e);
                        process::exit(1);
                    }
                };
            run_client(
                config,
                network_manager,
                storage_manager,
                wallet,
                enable_terminal_ui,
                &matches,
            )
            .await?;
        } else {
            let storage_manager = match dash_spv::storage::MemoryStorageManager::new().await {
                Ok(sm) => sm,
                Err(e) => {
                    eprintln!("Failed to create memory storage manager: {}", e);
                    process::exit(1);
                }
            };
            run_client(
                config,
                network_manager,
                storage_manager,
                wallet,
                enable_terminal_ui,
                &matches,
            )
            .await?;
        }
    } else {
        let storage_manager = match dash_spv::storage::MemoryStorageManager::new().await {
            Ok(sm) => sm,
            Err(e) => {
                eprintln!("Failed to create memory storage manager: {}", e);
                process::exit(1);
            }
        };
        run_client(config, network_manager, storage_manager, wallet, enable_terminal_ui, &matches)
            .await?;
    }

    Ok(())
}

async fn run_client<S: dash_spv::storage::StorageManager + Send + Sync + 'static>(
    config: ClientConfig,
    network_manager: dash_spv::network::multi_peer::MultiPeerNetworkManager,
    storage_manager: S,
    wallet: Arc<tokio::sync::RwLock<key_wallet_manager::spv_wallet_manager::SPVWalletManager>>,
    enable_terminal_ui: bool,
    matches: &clap::ArgMatches,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create and start the client
    let mut client = match DashSpvClient::<
        key_wallet_manager::spv_wallet_manager::SPVWalletManager,
        dash_spv::network::multi_peer::MultiPeerNetworkManager,
        S,
    >::new(config.clone(), network_manager, storage_manager, wallet)
    .await
    {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Failed to create SPV client: {}", e);
            process::exit(1);
        }
    };

    // Enable terminal UI in the client if requested
    let _terminal_guard = if enable_terminal_ui {
        client.enable_terminal_ui();

        // Get the terminal UI from the client and initialize it
        if let Some(ui) = client.get_terminal_ui() {
            match TerminalGuard::new(ui.clone()) {
                Ok(guard) => {
                    // Initial update with network info
                    let network_name = format!("{:?}", config.network);
                    let _ = ui
                        .update_status(|status| {
                            status.network = network_name;
                            status.peer_count = 0; // Will be updated when connected
                        })
                        .await;

                    Some(guard)
                }
                Err(e) => {
                    tracing::warn!("Failed to initialize terminal UI: {}", e);
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    if let Err(e) = client.start().await {
        eprintln!("Failed to start SPV client: {}", e);
        process::exit(1);
    }

    tracing::info!("SPV client started successfully");

    // Add watch addresses if specified
    if let Some(addresses) = matches.get_many::<String>("watch-address") {
        for addr_str in addresses {
            match addr_str.parse::<dashcore::Address<dashcore::address::NetworkUnchecked>>() {
                Ok(addr) => {
                    let network = config.network;
                    let checked_addr = addr.require_network(network).map_err(|_| {
                        format!("Address '{}' is not valid for network {:?}", addr_str, network)
                    });
                    match checked_addr {
                        Ok(valid_addr) => {
                            if let Err(e) = client
                                .add_watch_item(dash_spv::WatchItem::address(valid_addr))
                                .await
                            {
                                tracing::error!(
                                    "Failed to add watch address '{}': {}",
                                    addr_str,
                                    e
                                );
                            } else {
                                tracing::info!("Added watch address: {}", addr_str);
                            }
                        }
                        Err(e) => {
                            tracing::error!("Invalid address for network: {}", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Invalid address format '{}': {}", addr_str, e);
                }
            }
        }
    }

    // Add example addresses for testing if requested
    if matches.get_flag("add-example-addresses") {
        let network = config.network;
        let example_addresses = match network {
            dashcore::Network::Dash => vec![
                // Some example mainnet addresses (these are from block explorers/faucets)
                "Xesjop7V9xLndFMgZoCrckJ5ZPgJdJFbA3", // Crowdnode
            ],
            dashcore::Network::Testnet => vec![
                // Testnet addresses
                "yNEr8u4Kx8PTH9A9G3P7NwkJRmqFD7tKSj", // Example testnet address
                "yMGqjKTqr2HKKV6zqSg5vTPQUzJNt72h8h", // Another testnet example
            ],
            dashcore::Network::Regtest => vec![
                // Regtest addresses (these would be from local testing)
                "yQ9J8qK3nNW8JL8h5T6tB3VZwwH9h5T6tB", // Example regtest address
                "yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A", // Another regtest example
            ],
            _ => vec![],
        };

        for addr_str in example_addresses {
            match addr_str.parse::<dashcore::Address<dashcore::address::NetworkUnchecked>>() {
                Ok(addr) => {
                    if let Ok(valid_addr) = addr.require_network(network) {
                        // For the example mainnet address (Crowdnode), set earliest height to 1,000,000
                        let watch_item = if network == dashcore::Network::Dash
                            && addr_str == "Xesjop7V9xLndFMgZoCrckJ5ZPgJdJFbA3"
                        {
                            dash_spv::WatchItem::address_from_height(valid_addr, 200_000)
                        } else {
                            dash_spv::WatchItem::address(valid_addr)
                        };

                        if let Err(e) = client.add_watch_item(watch_item).await {
                            tracing::error!("Failed to add example address '{}': {}", addr_str, e);
                        } else {
                            let height_info = if network == dashcore::Network::Dash
                                && addr_str == "Xesjop7V9xLndFMgZoCrckJ5ZPgJdJFbA3"
                            {
                                " (from height 1,000,000)"
                            } else {
                                ""
                            };
                            tracing::info!(
                                "Added example watch address: {}{}",
                                addr_str,
                                height_info
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Example address '{}' failed to parse: {}", addr_str, e);
                }
            }
        }
    }

    // Display current watch list
    let watch_items = client.get_watch_items().await;
    if !watch_items.is_empty() {
        tracing::info!("Watching {} items:", watch_items.len());
        for (i, item) in watch_items.iter().enumerate() {
            match item {
                dash_spv::WatchItem::Address {
                    address,
                    earliest_height,
                } => {
                    let height_info = earliest_height
                        .map(|h| format!(" (from height {})", h))
                        .unwrap_or_default();
                    tracing::info!("  {}: Address {}{}", i + 1, address, height_info);
                }
                dash_spv::WatchItem::Script(script) => {
                    tracing::info!("  {}: Script {}", i + 1, script.to_hex_string())
                }
                dash_spv::WatchItem::Outpoint(outpoint) => {
                    tracing::info!("  {}: Outpoint {}:{}", i + 1, outpoint.txid, outpoint.vout)
                }
            }
        }
    } else {
        tracing::info!("No watch items configured. Use --watch-address or --add-example-addresses to watch for transactions.");
    }

    // Wait for at least one peer to connect before attempting sync
    tracing::info!("Waiting for peers to connect...");
    let mut wait_time = 0;
    const MAX_WAIT_TIME: u64 = 60; // Wait up to 60 seconds for peers

    loop {
        let peer_count = client.get_peer_count().await;
        if peer_count > 0 {
            tracing::info!("Connected to {} peer(s), starting synchronization", peer_count);
            break;
        }

        if wait_time >= MAX_WAIT_TIME {
            tracing::error!("No peers connected after {} seconds", MAX_WAIT_TIME);
            return Err("SPV client failed to connect to any peers".into());
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        wait_time += 1;

        if wait_time % 5 == 0 {
            tracing::info!("Still waiting for peers... ({}s elapsed)", wait_time);
        }
    }

    // Check filters for matches if we have watch items before starting monitoring
    let watch_items = client.get_watch_items().await;
    let should_check_filters = !watch_items.is_empty() && !matches.get_flag("no-filters");

    // Start synchronization first, then monitoring immediately
    // The key is to minimize the gap between sync requests and monitoring startup
    tracing::info!("Starting synchronization to tip...");
    match client.sync_to_tip().await {
        Ok(progress) => {
            tracing::info!("Synchronization requests sent! (actual sync happens asynchronously)");
            tracing::info!("Current Header height: {}", progress.header_height);
            tracing::info!("Current Filter header height: {}", progress.filter_header_height);
            tracing::info!("Current Masternode height: {}", progress.masternode_height);
        }
        Err(e) => {
            tracing::error!("Synchronization startup failed: {}", e);
            return Err(format!("SPV client synchronization startup failed: {}", e).into());
        }
    }

    // Start monitoring immediately after sync requests are sent
    tracing::info!("Starting network monitoring...");

    // For now, just focus on the core fix - getting headers to sync properly
    // Filter checking can be done manually later
    if should_check_filters {
        tracing::info!("Filter checking will be available after headers sync completes");
        tracing::info!("You can manually trigger filter sync later if needed");
    }

    tokio::select! {
        result = client.monitor_network() => {
            if let Err(e) = result {
                tracing::error!("Network monitoring failed: {}", e);
            }
        }
        _ = signal::ctrl_c() => {
            tracing::info!("Received shutdown signal (Ctrl-C)");

            // Stop the client immediately
            tracing::info!("Stopping SPV client...");
            if let Err(e) = client.stop().await {
                tracing::error!("Error stopping client: {}", e);
            } else {
                tracing::info!("SPV client stopped successfully");
            }
            return Ok(());
        }
    }

    // Stop the client (if monitor_network exited normally)
    tracing::info!("Stopping SPV client...");
    if let Err(e) = client.stop().await {
        tracing::error!("Error stopping client: {}", e);
    }

    tracing::info!("SPV client stopped");
    Ok(())
}
