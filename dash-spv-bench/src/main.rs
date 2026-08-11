mod dashboard;
mod metrics;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use dash_spv::storage::DiskStorageManager;
use dash_spv::{ClientConfig, DashSpvClient, EventHandler};
use dashcore::Network;
use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use key_wallet::wallet::ManagedWalletInfo;
use key_wallet_manager::WalletManager;
use tokio::sync::RwLock;
use tracing_subscriber::prelude::*;

use crate::dashboard::Dashboard;
use crate::metrics::BenchEventHandler;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn load_mnemonics() -> Vec<String> {
    std::env::var("BENCH_WALLET_FILE")
        .ok()
        .filter(|p| !p.trim().is_empty())
        .and_then(|path| std::fs::read_to_string(&path).ok())
        .map(|contents| {
            contents
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::main]
async fn main() -> Result<()> {
    let dashboard = Arc::new(Dashboard::new());

    let (output_dir, _tempdir_guard): (PathBuf, Option<tempfile::TempDir>) =
        match std::env::var("BENCH_STORAGE_DIR") {
            Ok(dir) if !dir.trim().is_empty() => {
                let path = PathBuf::from(dir.trim());
                let _ = std::fs::remove_dir_all(&path);
                std::fs::create_dir_all(&path).context("create bench storage dir")?;
                (path, None)
            }
            _ => {
                let td = tempfile::tempdir().context("temp storage dir")?;
                (td.path().to_path_buf(), Some(td))
            }
        };

    let log_file = std::fs::File::create(output_dir.join("run.log")).context("create run.log")?;
    let terminal_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,dash_spv_bench=info"));
    let file_filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new("warn,dash_spv=debug,dash_spv_bench=debug")
    });
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(dashboard.log_writer())
                .with_filter(terminal_filter),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(std::sync::Mutex::new(log_file))
                .with_filter(file_filter),
        )
        .init();

    let mode = env_or("BENCH_MODE", "local").trim().to_ascii_lowercase();
    let (network, remote) = match mode.as_str() {
        "local" => (Network::Testnet, false),
        "testnet" => (Network::Testnet, true),
        "mainnet" => (Network::Mainnet, true),
        other => {
            return Err(anyhow!(
                "BENCH_MODE must be 'local', 'testnet' or 'mainnet', got '{other}'"
            ))
        }
    };

    let peers: Vec<SocketAddr> = std::env::var("BENCH_PEERS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|p| p.parse::<SocketAddr>().with_context(|| format!("bad peer {p}")))
        .collect::<Result<_>>()?;

    if !remote && peers.is_empty() {
        return Err(anyhow!("BENCH_MODE=local requires BENCH_PEERS (the docker peer addresses)"));
    }

    let dns_mode = remote && peers.is_empty();

    let start_height: Option<u32> =
        std::env::var("BENCH_START_HEIGHT").ok().and_then(|v| v.trim().parse().ok());

    let mnemonics = load_mnemonics();
    let timeout = Duration::from_secs(1800);

    tracing::info!(
        "dash-spv-bench: mode={} ({}) on {:?}, wallets={}",
        mode,
        if dns_mode {
            "DNS discovery".to_string()
        } else {
            format!("{} peers", peers.len())
        },
        network,
        mnemonics.len(),
    );

    let mut config = ClientConfig::new(network).with_storage_path(output_dir.clone());
    config.start_from_height = start_height;
    config.restrict_to_configured_peers = !dns_mode;
    if let Ok(v) = std::env::var("BENCH_MAX_PEERS") {
        if let Ok(n) = v.trim().parse() {
            config.max_peers = n;
        }
    }
    for addr in &peers {
        config.add_peer(*addr);
    }

    let storage_manager =
        DiskStorageManager::new(&config).await.map_err(|e| anyhow!("storage manager: {e}"))?;

    let mut wallet_manager = WalletManager::<ManagedWalletInfo>::new(network);
    let birth_height = start_height.unwrap_or(0);
    let mut wallet_ids = Vec::with_capacity(mnemonics.len());
    for mnemonic in &mnemonics {
        let id = wallet_manager
            .create_wallet_from_mnemonic(
                mnemonic,
                birth_height,
                WalletAccountCreationOptions::default(),
            )
            .map_err(|e| anyhow!("wallet from mnemonic: {e}"))?;
        wallet_ids.push(id);
    }
    let wallet = Arc::new(RwLock::new(wallet_manager));
    let wallet_probe = wallet.clone();

    let handler = Arc::new(BenchEventHandler::new(dashboard.clone()));
    let network = dash_spv::network::PeerNetworkManager::new(&config).await;

    let client = DashSpvClient::new(
        config,
        network,
        storage_manager,
        wallet,
        vec![handler.clone() as Arc<dyn EventHandler>],
    )
    .await
    .map_err(|e| anyhow!("client new: {e}"))?;

    let run_client = client.clone();
    let run_handle = tokio::spawn(async move {
        if let Err(e) = run_client.run().await {
            tracing::error!("client run() exited with error: {e}");
        }
    });

    tokio::select! {
        _ = handler.wait_done() => {}
        _ = tokio::time::sleep(timeout) => {}
        _ = tokio::signal::ctrl_c() => eprintln!("ctrl-c received, shutting down..."),
    }
    let m = handler.snapshot();

    let _ = client.shutdown().await;
    run_handle.abort();
    let _ = run_handle.await;

    use std::fmt::Write as _;
    let mut report = format!("{m}\n");

    if !wallet_ids.is_empty() {
        use key_wallet_manager::WalletInterface;
        let w = wallet_probe.read().await;
        let _ = writeln!(report, "wallet_synced_height: {}", w.synced_height());
        let _ = writeln!(report, "wallet_addresses:     {}", w.monitored_addresses().len());

        for (i, id) in wallet_ids.iter().enumerate() {
            let txs = w
                .get_wallet_info(id)
                .map(|info| {
                    info.accounts()
                        .all_accounts()
                        .iter()
                        .flat_map(|a| a.transactions().keys())
                        .collect::<std::collections::BTreeSet<_>>()
                        .len()
                })
                .unwrap_or(0);

            let (confirmed, total) =
                w.get_wallet_balance(id).map(|b| (b.confirmed(), b.total())).unwrap_or((0, 0));

            let _ = writeln!(
                report,
                "wallet[{i}] txs={txs} confirmed_sat={confirmed} total_sat={total}"
            );
        }

        let _ = writeln!(report, "wallet_describe:\n{}", w.describe().await);
    }

    print!("\n{report}");
    if let Err(e) = std::fs::write(output_dir.join("summary.txt"), &report) {
        tracing::warn!("could not write summary.txt: {e}");
    }
    tracing::info!("run outputs written to {}", output_dir.display());

    Ok(())
}
