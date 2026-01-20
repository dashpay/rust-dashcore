//! Command-line interface for the Dash SPV client.

// Removed unused import
use std::path::PathBuf;
use std::process;
use std::sync::Arc;

use clap::{Arg, Command};
use dash_spv::terminal::TerminalGuard;
use dash_spv::{ClientConfigBuilder, DashSpvClient, LevelFilter};
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::wallet_manager::WalletManager;
use tokio_util::sync::CancellationToken;

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
                .env("RUST_LOG")
                .default_value("info")
                .value_name("LEVEL")
                .help("Log level (CLI overrides RUST_LOG env var)")
                .value_parser(["error", "warn", "info", "debug", "trace"]),
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
            Arg::new("no-mempool")
                .long("no-mempool")
                .help("Disable mempool transaction tracking")
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
        .arg(
            Arg::new("no-log-file")
                .long("no-log-file")
                .help("Disable log file output (enables console logging as fallback)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("print-to-console")
                .long("print-to-console")
                .help("Print logs to the console")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("log-dir")
                .long("log-dir")
                .value_name("DIR")
                .help("Directory for log files (default: <data-dir>/logs)"),
        )
        .arg(
            Arg::new("max-log-files")
                .long("max-log-files")
                .help("Maximum number of archived log files to keep")
                .value_name("COUNT")
                .default_value("20")
                .value_parser(clap::value_parser!(usize)),
        )
        .arg(
            Arg::new("mnemonic-file")
                .long("mnemonic-file")
                .value_name("PATH")
                .help("Path to file containing BIP39 mnemonic phrase")
                .required(true),
        )
        .get_matches();

    let log_level: LevelFilter = matches
        .get_one::<String>("log-level")
        .expect("log-level has default value")
        .parse()
        .expect("log-level value_parser ensures valid level");

    // Parse network
    let network_str = matches.get_one::<String>("network").ok_or("Missing network argument")?;
    let mut cfg_builder = match network_str.as_str() {
        "mainnet" => ClientConfigBuilder::mainnet(),
        "testnet" => ClientConfigBuilder::testnet(),
        "regtest" => ClientConfigBuilder::regtest(),
        n => return Err(format!("Invalid network: {}", n).into()),
    };

    let mnemonic_path =
        matches.get_one::<String>("mnemonic-file").ok_or("Missing mnemonic-file argument")?;
    let mnemonic_phrase = std::fs::read_to_string(mnemonic_path)
        .map_err(|e| format!("Failed to read mnemonic file '{}': {}", mnemonic_path, e))?
        .trim()
        .to_string();

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

    // Parse logging flags and initialize logging early
    let no_log_file = matches.get_flag("no-log-file");
    let print_to_console = matches.get_flag("print-to-console");
    let enable_terminal_ui = matches.get_flag("terminal-ui");
    let max_log_files = *matches.get_one::<usize>("max-log-files").unwrap();
    let log_dir = matches
        .get_one::<String>("log-dir")
        .map(PathBuf::from)
        .unwrap_or_else(|| data_dir.join("logs"));

    // When terminal UI is enabled, force file logging and disable console to avoid mixing
    let file_config = if !no_log_file || enable_terminal_ui {
        Some(dash_spv::LogFileConfig {
            log_dir,
            max_files: max_log_files,
        })
    } else {
        None
    };

    // Disable console logging when terminal UI is enabled
    let console_enabled = if enable_terminal_ui {
        false
    } else {
        no_log_file || print_to_console
    };

    let logging_config = dash_spv::LoggingConfig {
        level: Some(log_level),
        console: console_enabled,
        file: file_config,
    };

    // Initialize logging, keep guard alive for the duration of run()
    let _logging_guard = dash_spv::init_logging(logging_config)?;

    tracing::info!("Starting Dash SPV client");
    tracing::info!("Network: {:?}", network_str);
    tracing::info!("Data directory: {}", data_dir.display());
    tracing::info!("Validation mode: {:?}", validation_mode);

    // Create configuration
    let config = cfg_builder.storage_path(data_dir.clone()).validation_mode(validation_mode);

    // Configure features
    if matches.get_flag("no-filters") {
        config.enable_filters(false);
    }
    if matches.get_flag("no-masternodes") {
        config.enable_masternodes(false);
    }
    if matches.get_flag("no-mempool") {
        config.enable_mempool_tracking(false);
    }

    // Set start height if specified
    if let Some(start_height_str) = matches.get_one::<String>("start-height") {
        if start_height_str == "now" {
            // Use a very high number to get the latest checkpoint
            config.start_from_height(u32::MAX);
            tracing::info!("Will start syncing from the latest available checkpoint");
        } else {
            let start_height = start_height_str
                .parse::<u32>()
                .map_err(|e| format!("Invalid start height '{}': {}", start_height_str, e))?;
            config.start_from_height(start_height);
            tracing::info!("Will start syncing from height: {}", start_height);
        }
    }

    // Validate configuration
    let mut config = match config.build() {
        Ok(config) => config,
        Err(e) => {
            tracing::error!("Configuration error: {}", e);
            process::exit(1);
        }
    };

    // Add custom peers if specified
    if let Some(peers) = matches.get_many::<String>("peer") {
        for peer in peers {
            match peer.parse() {
                Ok(addr) => config.add_peer(addr),
                Err(e) => {
                    tracing::error!("Invalid peer address '{}': {}", peer, e);
                    process::exit(1);
                }
            };
        }
    }

    tracing::info!("Sync strategy: Sequential");

    // Create the wallet manager
    let mut wallet_manager = WalletManager::<ManagedWalletInfo>::new(config.network());
    let wallet_id = wallet_manager.create_wallet_from_mnemonic(
        mnemonic_phrase.as_str(),
        "",
        0,
        key_wallet::wallet::initialization::WalletAccountCreationOptions::default(),
    )?;
    let wallet = Arc::new(tokio::sync::RwLock::new(wallet_manager));

    // Create network manager
    let network_manager = match dash_spv::network::manager::PeerNetworkManager::new(&config).await {
        Ok(nm) => nm,
        Err(e) => {
            eprintln!("Failed to create network manager: {}", e);
            process::exit(1);
        }
    };

    let storage_manager = match dash_spv::storage::DiskStorageManager::new(&config).await {
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
        wallet_id,
    )
    .await?;

    Ok(())
}

async fn run_client<S: dash_spv::storage::StorageManager>(
    config: dash_spv::ClientConfig,
    network_manager: dash_spv::network::manager::PeerNetworkManager,
    storage_manager: S,
    wallet: Arc<tokio::sync::RwLock<WalletManager<ManagedWalletInfo>>>,
    enable_terminal_ui: bool,
    matches: &clap::ArgMatches,
    wallet_id: [u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    // Create and start the client
    let mut client =
        match DashSpvClient::<
            WalletManager<ManagedWalletInfo>,
            dash_spv::network::manager::PeerNetworkManager,
            S,
        >::new(config.clone(), network_manager, storage_manager, wallet.clone())
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
                    let network_name = format!("{:?}", config.network());
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

    // Set up event logging: count detected transactions and log wallet balances periodically
    // Take the client's event receiver and spawn a logger task
    if let Some(mut event_rx) = client.take_event_receiver() {
        let wallet_for_logger = wallet.clone();
        let wallet_id_for_logger = wallet_id;
        tokio::spawn(async move {
            use dash_spv::types::SpvEvent;
            let mut total_detected_block_txs: u64 = 0;
            let mut total_detected_mempool_txs: u64 = 0;
            let mut last_snapshot = std::time::Instant::now();
            let snapshot_interval = std::time::Duration::from_secs(10);

            loop {
                tokio::select! {
                    maybe_event = event_rx.recv() => {
                        match maybe_event {
                            Some(SpvEvent::BlockProcessed { relevant_transactions, .. }) => {
                                if relevant_transactions > 0 {
                                    total_detected_block_txs = total_detected_block_txs.saturating_add(relevant_transactions as u64);
                                    tracing::info!(
                                        "Detected {} wallet-relevant tx(s) in block; cumulative (blocks): {}",
                                        relevant_transactions,
                                        total_detected_block_txs
                                    );
                                }
                            }
                            Some(SpvEvent::MempoolTransactionAdded { .. }) => {
                                total_detected_mempool_txs = total_detected_mempool_txs.saturating_add(1);
                                tracing::info!(
                                    "Detected wallet-relevant mempool tx; cumulative (mempool): {}",
                                    total_detected_mempool_txs
                                );
                            }
                            Some(_) => { /* ignore other events */ }
                            None => break, // sender closed
                        }
                    }
                    // Also do a periodic snapshot while events are flowing
                    _ = tokio::time::sleep(snapshot_interval) => {
                        // Log snapshot if interval has elapsed
                        if last_snapshot.elapsed() >= snapshot_interval {
                            let (tx_count, wallet_balance) = {
                                let mgr = wallet_for_logger.read().await;

                                // Count wallet-affecting transactions from wallet transaction history
                                let tx_count = mgr
                                    .wallet_transaction_history(&wallet_id_for_logger)
                                    .map(|v| v.len())
                                    .unwrap_or(0);

                                // Read wallet balance from the managed wallet info
                                let wallet_balance = mgr.get_wallet_balance(&wallet_id_for_logger).unwrap_or_default();

                                (tx_count, wallet_balance)
                            };
                            tracing::info!(
                                "Wallet tx summary: tx_count={} (blocks={} + mempool={}), balances: {}",
                                tx_count,
                                total_detected_block_txs,
                                total_detected_mempool_txs,
                                wallet_balance,
                            );
                            last_snapshot = std::time::Instant::now();
                        }
                    }
                }
            }
        });
    } else {
        tracing::warn!("Event channel not available; transaction/balance logging disabled");
    }

    // Add watch addresses if specified
    if let Some(addresses) = matches.get_many::<String>("watch-address") {
        for addr_str in addresses {
            match addr_str.parse::<dashcore::Address<dashcore::address::NetworkUnchecked>>() {
                Ok(addr) => {
                    let network = config.network();
                    let checked_addr = addr.require_network(network).map_err(|_| {
                        format!("Address '{}' is not valid for network {:?}", addr_str, network)
                    });
                    match checked_addr {
                        Ok(valid_addr) => {
                            // TODO: Add address to wallet for monitoring
                            // For now, just log that we would watch this address
                            tracing::info!(
                                "Would watch address: {} (wallet integration pending)",
                                valid_addr
                            );
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
        let network = config.network();
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
                    if let Ok(_valid_addr) = addr.require_network(network) {
                        // TODO: In the future, we could add these example addresses to the wallet
                        // For now, just log that we would monitor them
                        let height_info = if network == dashcore::Network::Dash
                            && addr_str == "Xesjop7V9xLndFMgZoCrckJ5ZPgJdJFbA3"
                        {
                            " (from height 200,000)"
                        } else {
                            ""
                        };
                        tracing::info!(
                            "Would monitor example address: {}{}",
                            addr_str,
                            height_info
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!("Example address '{}' failed to parse: {}", addr_str, e);
                }
            }
        }
    }

    // Display current wallet addresses
    {
        let wallet_lock = wallet.read().await;
        let monitored = wallet_lock.monitored_addresses();
        if !monitored.is_empty() {
            tracing::info!("Wallet monitoring {} addresses:", monitored.len());
            for (i, addr) in monitored.iter().take(10).enumerate() {
                tracing::info!("  {}: {}", i + 1, addr);
            }
            if monitored.len() > 10 {
                tracing::info!("  ... and {} more addresses", monitored.len() - 10);
            }
        } else {
            tracing::info!("No addresses being monitored by wallet. The wallet will generate addresses as needed.");
        }
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

    // Check filters for matches if wallet has addresses before starting monitoring
    let should_check_filters = {
        let wallet_lock = wallet.read().await;
        let monitored = wallet_lock.monitored_addresses();
        !monitored.is_empty() && !matches.get_flag("no-filters")
    };

    // Start monitoring immediately after sync requests are sent
    tracing::info!("Starting network monitoring...");

    // For now, just focus on the core fix - getting headers to sync properly
    // Filter checking can be done manually later
    if should_check_filters {
        tracing::info!("Filter checking will be available after headers sync completes");
        tracing::info!("You can manually trigger filter sync later if needed");
    }

    let (_command_sender, command_receiver) = tokio::sync::mpsc::unbounded_channel();
    let shutdown_token = CancellationToken::new();

    client.run(command_receiver, shutdown_token).await?;

    Ok(())
}
