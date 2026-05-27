//! Command-line interface for the Dash SPV client.

use std::path::PathBuf;
use std::process;
use std::sync::Arc;

use clap::{Parser, ValueEnum};
use dash_spv::{
    ClientConfig, DashSpvClient, DevnetConfig, LevelFilter, LlmqDevnetParams, MempoolStrategy,
    Network, ValidationMode,
};
use dashcore::sml::llmq_type::devnet_llmq_type_from_name;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::WalletManager;

/// Network selection for CLI
#[derive(Clone, Copy, Debug, ValueEnum)]
enum NetworkArg {
    Mainnet,
    Testnet,
    Devnet,
    Regtest,
}

impl From<NetworkArg> for Network {
    fn from(arg: NetworkArg) -> Self {
        match arg {
            NetworkArg::Mainnet => Network::Mainnet,
            NetworkArg::Testnet => Network::Testnet,
            NetworkArg::Devnet => Network::Devnet,
            NetworkArg::Regtest => Network::Regtest,
        }
    }
}

/// Validation mode selection for CLI
#[derive(Clone, Copy, Debug, ValueEnum)]
enum ValidationModeArg {
    None,
    Basic,
    Full,
}

impl From<ValidationModeArg> for dash_spv::ValidationMode {
    fn from(arg: ValidationModeArg) -> Self {
        match arg {
            ValidationModeArg::None => dash_spv::ValidationMode::None,
            ValidationModeArg::Basic => dash_spv::ValidationMode::Basic,
            ValidationModeArg::Full => dash_spv::ValidationMode::Full,
        }
    }
}

/// Log level selection for CLI
#[derive(Clone, Copy, Debug, ValueEnum)]
#[value(rename_all = "lowercase")]
enum LogLevelArg {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<LogLevelArg> for LevelFilter {
    fn from(arg: LogLevelArg) -> Self {
        match arg {
            LogLevelArg::Error => LevelFilter::ERROR,
            LogLevelArg::Warn => LevelFilter::WARN,
            LogLevelArg::Info => LevelFilter::INFO,
            LogLevelArg::Debug => LevelFilter::DEBUG,
            LogLevelArg::Trace => LevelFilter::TRACE,
        }
    }
}

/// Dash SPV (Simplified Payment Verification) client
#[derive(Parser, Debug)]
#[command(name = "dash-spv", version = dash_spv::VERSION, about)]
struct Args {
    /// Network to connect to
    #[arg(short, long, value_enum, default_value = "mainnet")]
    network: NetworkArg,

    /// Data directory for storage (default: unique directory in /tmp)
    #[arg(short, long)]
    data_dir: Option<PathBuf>,

    /// Peer address to connect to (can be used multiple times)
    #[arg(short, long, value_name = "ADDRESS")]
    peer: Vec<String>,

    /// Log level (CLI overrides RUST_LOG env var)
    #[arg(short, long, value_enum, env = "RUST_LOG", default_value = "info")]
    log_level: LogLevelArg,

    /// Disable BIP157 filter synchronization
    #[arg(long)]
    no_filters: bool,

    /// Disable masternode list synchronization
    #[arg(long)]
    no_masternodes: bool,

    /// Disable mempool transaction tracking
    #[arg(long)]
    no_mempool: bool,

    /// Mempool strategy: fetch-all (higher bandwidth / more privacy) or bloom-filter (efficient / less privacy)
    #[arg(long, value_enum, default_value = "bloom-filter")]
    mempool_strategy: MempoolStrategy,

    /// Validation mode
    #[arg(long, value_enum, default_value = "full")]
    validation_mode: ValidationModeArg,

    /// Start syncing from a specific block height using the nearest checkpoint.
    /// Use 'now' for the latest checkpoint.
    #[arg(short, long, value_name = "HEIGHT")]
    start_height: Option<String>,

    /// Disable log file output (enables console logging as fallback)
    #[arg(long)]
    no_log_file: bool,

    /// Print logs to the console
    #[arg(long)]
    print_to_console: bool,

    /// Directory for log files (default: <data-dir>/logs)
    #[arg(long)]
    log_dir: Option<PathBuf>,

    /// Maximum number of archived log files to keep
    #[arg(long, default_value = "20")]
    max_log_files: usize,

    /// Path to file containing BIP39 mnemonic phrase
    #[arg(long, value_name = "PATH")]
    mnemonic_file: String,

    /// Devnet name (required when --network=devnet). Embedded in user agent so devnet peers accept the connection.
    #[arg(long, value_name = "NAME")]
    devnet_name: Option<String>,

    /// Override `LLMQ_DEVNET` size and threshold (matches Dash Core's `-llmqdevnetparams=<size>:<threshold>`).
    #[arg(long, value_name = "SIZE:THRESHOLD")]
    llmq_devnet_params: Option<String>,

    /// Reroute ChainLocks onto the given devnet quorum (matches Dash Core's
    /// `-llmqchainlocks=<quorum name>`). Type must be devnet-registered and
    /// non-rotating.
    #[arg(long, value_name = "QUORUM_NAME")]
    llmq_chainlocks: Option<String>,

    /// Reroute InstantSend DIP24 onto the given devnet quorum (matches Dash Core's
    /// `-llmqinstantsenddip0024=<quorum name>`). Type must be devnet-registered
    /// and rotating.
    #[arg(long, value_name = "QUORUM_NAME")]
    llmq_instantsend_dip0024: Option<String>,

    /// Reroute Platform quorums onto the given devnet quorum (matches Dash Core's
    /// `-llmqplatform=<quorum name>`). Type must be devnet-registered.
    #[arg(long, value_name = "QUORUM_NAME")]
    llmq_platform: Option<String>,
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Error: {}", e);

        // Provide specific exit codes for different error types
        let exit_code = if let Some(spv_error) = e.downcast_ref::<dash_spv::SpvError>() {
            match spv_error {
                dash_spv::SpvError::Network(_) => 1,
                dash_spv::SpvError::Storage(_) => 2,
                dash_spv::SpvError::Config(_) => 3,
                _ => 255,
            }
        } else {
            255
        };

        process::exit(exit_code);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let network: Network = args.network.into();
    let validation_mode: dash_spv::ValidationMode = args.validation_mode.into();
    let log_level: LevelFilter = args.log_level.into();

    let mnemonic_phrase = std::fs::read_to_string(&args.mnemonic_file)
        .map_err(|e| format!("Failed to read mnemonic file '{}': {}", args.mnemonic_file, e))?
        .trim()
        .to_string();

    // Create data directory
    let data_dir = args.data_dir.clone().unwrap_or_else(|| {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let pid = std::process::id();
        let dir_name = format!("dash-spv-{}-{}", timestamp, pid);
        std::env::temp_dir().join(dir_name)
    });

    // Configure logging
    let log_dir = args.log_dir.clone().unwrap_or_else(|| data_dir.join("logs"));

    let file_config = if !args.no_log_file {
        Some(dash_spv::LogFileConfig {
            log_dir,
            max_files: args.max_log_files,
        })
    } else {
        None
    };

    let console_enabled = args.no_log_file || args.print_to_console;

    let logging_config = dash_spv::LoggingConfig {
        level: Some(log_level),
        console: console_enabled,
        file: file_config,
        thread_local: false,
    };

    // Initialize logging, keep guard alive for the duration of run()
    let _logging_guard = dash_spv::init_logging(logging_config)?;

    tracing::info!("Starting Dash SPV client");
    tracing::info!("Network: {:?}", network);
    tracing::info!("Data directory: {}", data_dir.display());
    tracing::info!("Validation mode: {:?}", validation_mode);

    let mut config = build_client_config(&args, data_dir.clone())?;
    if let Err(e) = config.validate() {
        tracing::error!("Configuration error: {}", e);
        process::exit(1);
    }
    if let Some(devnet) = &config.devnet {
        let user_agent = devnet.user_agent(dash_spv::VERSION);
        tracing::info!("Devnet user agent: {}", user_agent);
        config = config.with_user_agent(user_agent);
    }

    // Create the wallet manager
    let mut wallet_manager = WalletManager::<ManagedWalletInfo>::new(config.network);
    wallet_manager.create_wallet_from_mnemonic(
        mnemonic_phrase.as_str(),
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
    run_client(config, network_manager, storage_manager, wallet).await?;

    Ok(())
}

fn build_client_config(args: &Args, data_dir: PathBuf) -> Result<ClientConfig, String> {
    let network: Network = args.network.into();
    let validation_mode: ValidationMode = args.validation_mode.into();

    let mut config = ClientConfig::new(network)
        .with_storage_path(data_dir)
        .with_validation_mode(validation_mode);

    let devnet = build_devnet_config(args, network)?;
    if let Some(devnet) = devnet {
        config = config.with_devnet(devnet);
    }

    if !args.peer.is_empty() {
        config.peers.clear();
        for peer in &args.peer {
            let addr =
                peer.parse().map_err(|e| format!("Invalid peer address '{}': {}", peer, e))?;
            config.add_peer(addr);
        }
    }

    if args.no_filters {
        config = config.without_filters();
    }
    if args.no_masternodes {
        config = config.without_masternodes();
    }
    if args.no_mempool {
        config.enable_mempool_tracking = false;
    } else {
        config = config.with_mempool_tracking(args.mempool_strategy);
    }

    if let Some(ref start_height_str) = args.start_height {
        if start_height_str == "now" {
            config.start_from_height = Some(u32::MAX);
        } else {
            let start_height = start_height_str
                .parse::<u32>()
                .map_err(|e| format!("Invalid start height '{}': {}", start_height_str, e))?;
            config.start_from_height = Some(start_height);
        }
    }

    Ok(config)
}

fn build_devnet_config(args: &Args, network: Network) -> Result<Option<DevnetConfig>, String> {
    if network != Network::Devnet {
        if args.devnet_name.is_some() {
            return Err("--devnet-name is only valid with --network=devnet".into());
        }
        if args.llmq_devnet_params.is_some() {
            return Err("--llmq-devnet-params is only valid with --network=devnet".into());
        }
        if args.llmq_chainlocks.is_some() {
            return Err("--llmq-chainlocks is only valid with --network=devnet".into());
        }
        if args.llmq_instantsend_dip0024.is_some() {
            return Err("--llmq-instantsend-dip0024 is only valid with --network=devnet".into());
        }
        if args.llmq_platform.is_some() {
            return Err("--llmq-platform is only valid with --network=devnet".into());
        }
        return Ok(None);
    }

    let name = args.devnet_name.clone().ok_or("--devnet-name is required when --network=devnet")?;
    let mut devnet = DevnetConfig::new(name);

    if let Some(raw) = args.llmq_devnet_params.as_deref() {
        devnet = devnet.with_llmq_params(parse_llmq_devnet_params(raw)?);
    }
    if let Some(name) = args.llmq_chainlocks.as_deref() {
        devnet = devnet.with_chainlocks_type(devnet_llmq_type_from_name(name)?);
    }
    if let Some(name) = args.llmq_instantsend_dip0024.as_deref() {
        devnet = devnet.with_instantsend_dip0024_type(devnet_llmq_type_from_name(name)?);
    }
    if let Some(name) = args.llmq_platform.as_deref() {
        devnet = devnet.with_platform_type(devnet_llmq_type_from_name(name)?);
    }
    Ok(Some(devnet))
}

fn parse_llmq_devnet_params(raw: &str) -> Result<LlmqDevnetParams, String> {
    let (size_str, threshold_str) = raw
        .split_once(':')
        .ok_or_else(|| format!("--llmq-devnet-params expects SIZE:THRESHOLD, got '{}'", raw))?;
    let size: u32 =
        size_str.parse().map_err(|e| format!("invalid LLMQ_DEVNET size '{}': {}", size_str, e))?;
    let threshold: u32 = threshold_str
        .parse()
        .map_err(|e| format!("invalid LLMQ_DEVNET threshold '{}': {}", threshold_str, e))?;
    Ok(LlmqDevnetParams {
        size,
        threshold,
    })
}

async fn run_client<S: dash_spv::storage::StorageManager>(
    config: ClientConfig,
    network_manager: dash_spv::network::manager::PeerNetworkManager,
    storage_manager: S,
    wallet: Arc<tokio::sync::RwLock<WalletManager<ManagedWalletInfo>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create and start the client
    let client =
        match DashSpvClient::<
            WalletManager<ManagedWalletInfo>,
            dash_spv::network::manager::PeerNetworkManager,
            S,
        >::new(
            config.clone(), network_manager, storage_manager, wallet.clone(), Vec::new()
        )
        .await
        {
            Ok(client) => client,
            Err(e) => {
                eprintln!("Failed to create SPV client: {}", e);
                process::exit(1);
            }
        };

    let stop_client = client.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::debug!("Shutdown signal received");
            if let Err(e) = stop_client.stop().await {
                tracing::warn!("Error during ctrl-c stop: {}", e);
            }
        }
    });

    client.run().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dash_spv::LLMQType;
    use tempfile::TempDir;

    fn parse(argv: &[&str]) -> Result<Args, clap::Error> {
        let mut full = vec!["dash-spv"];
        full.extend_from_slice(argv);
        Args::try_parse_from(full)
    }

    fn args(extra: &[&str]) -> Args {
        let mut argv = vec!["--mnemonic-file", "/dev/null"];
        argv.extend_from_slice(extra);
        parse(&argv).expect("parse")
    }

    #[test]
    fn devnet_requires_name() {
        let args = args(&["--network", "devnet"]);
        let err = build_devnet_config(&args, Network::Devnet).expect_err("must require name");
        assert!(err.contains("--devnet-name is required"), "got: {}", err);
    }

    #[test]
    fn devnet_flags_rejected_on_non_devnet_networks() {
        for flag in &[
            "--devnet-name",
            "--llmq-devnet-params",
            "--llmq-chainlocks",
            "--llmq-instantsend-dip0024",
            "--llmq-platform",
        ] {
            let value = if *flag == "--llmq-devnet-params" {
                "8:5"
            } else if *flag == "--devnet-name" {
                "alpha"
            } else {
                "llmq_devnet"
            };
            for network in [Network::Mainnet, Network::Testnet, Network::Regtest] {
                let args = args(&[flag, value]);
                let err = build_devnet_config(&args, network)
                    .expect_err("non-devnet network must reject the flag");
                assert!(err.contains(flag), "expected error to name flag {}, got: {}", flag, err);
            }
        }
    }

    #[test]
    fn devnet_minimal_builds_config_with_no_overrides() {
        let args = args(&["--network", "devnet", "--devnet-name", "alpha"]);
        let devnet =
            build_devnet_config(&args, Network::Devnet).expect("must succeed").expect("some");
        assert_eq!(devnet.name, "alpha");
        assert!(devnet.llmq_params.is_none());
        assert!(devnet.llmq_chainlocks_type.is_none());
        assert!(devnet.llmq_instantsend_dip0024_type.is_none());
        assert!(devnet.llmq_platform_type.is_none());
    }

    #[test]
    fn devnet_full_compose() {
        let args = args(&[
            "--network",
            "devnet",
            "--devnet-name",
            "alpha",
            "--llmq-devnet-params",
            "8:5",
            "--llmq-chainlocks",
            "llmq_devnet",
            "--llmq-instantsend-dip0024",
            "llmq_devnet_dip0024",
            "--llmq-platform",
            "llmq_devnet_platform",
        ]);
        let devnet =
            build_devnet_config(&args, Network::Devnet).expect("must succeed").expect("some");
        assert_eq!(devnet.name, "alpha");
        assert_eq!(
            devnet.llmq_params,
            Some(LlmqDevnetParams {
                size: 8,
                threshold: 5
            })
        );
        assert_eq!(devnet.llmq_chainlocks_type, Some(LLMQType::LlmqtypeDevnet));
        assert_eq!(devnet.llmq_instantsend_dip0024_type, Some(LLMQType::LlmqtypeDevnetDIP0024));
        assert_eq!(devnet.llmq_platform_type, Some(LLMQType::LlmqtypeDevnetPlatform));
    }

    #[test]
    fn llmq_devnet_params_parse_errors() {
        assert!(parse_llmq_devnet_params("8").is_err(), "missing colon");
        assert!(parse_llmq_devnet_params("abc:5").is_err(), "non-numeric size");
        assert!(parse_llmq_devnet_params("8:abc").is_err(), "non-numeric threshold");
        assert!(parse_llmq_devnet_params(":").is_err(), "empty parts");
    }

    #[test]
    fn unknown_quorum_name_is_rejected() {
        let args = args(&[
            "--network",
            "devnet",
            "--devnet-name",
            "alpha",
            "--llmq-chainlocks",
            "not_a_quorum",
        ]);
        let err = build_devnet_config(&args, Network::Devnet).expect_err("must reject");
        assert!(err.contains("Invalid LLMQ type"), "got: {}", err);
    }

    #[test]
    fn build_client_config_returns_devnet_on_devnet() {
        let args = args(&["--network", "devnet", "--devnet-name", "alpha"]);
        let tmp = TempDir::new().unwrap();
        let config = build_client_config(&args, tmp.path().to_path_buf()).expect("ok");
        let devnet = config.devnet.as_ref().expect("devnet must be set");
        assert_eq!(devnet.name, "alpha");
        assert_eq!(config.network, Network::Devnet);
    }
}
