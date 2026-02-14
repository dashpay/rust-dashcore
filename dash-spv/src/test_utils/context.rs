//! Shared dashd test context for integration tests.
//!
//! Provides `DashdTestContext` which encapsulates the common setup logic for
//! launching a dashd node with a pre-built blockchain and loading wallet data.
//! Used by both `dash-spv` and `dash-spv-ffi` integration tests.

use std::net::SocketAddr;

use tempfile::TempDir;
use tracing::info;

use super::copy_dir::copy_dir;
use super::{DashCoreConfig, DashCoreNode, WalletFile};

/// Shared test infrastructure for dashd integration tests.
///
/// Manages a dashd node instance backed by a copied blockchain directory,
/// along with the expected chain height and a pre-loaded wallet file.
pub struct DashdTestContext {
    pub node: DashCoreNode,
    pub addr: SocketAddr,
    pub expected_height: u32,
    pub wallet: WalletFile,
    pub supports_mining: bool,
    _datadir: TempDir,
}

impl DashdTestContext {
    /// Create a new dashd test context.
    ///
    /// Returns `None` if `SKIP_DASHD_TESTS` is set. Panics if required env vars
    /// are missing or if dashd fails to start.
    pub async fn new() -> Option<Self> {
        if std::env::var("SKIP_DASHD_TESTS").is_ok() {
            eprintln!("Skipping dashd integration test (SKIP_DASHD_TESTS is set)");
            return None;
        }

        let mut config = DashCoreConfig::from_env();
        let datadir = TempDir::new().expect("failed to create temp dir");
        copy_dir(&config.datadir, datadir.path());
        config.datadir = datadir.path().to_path_buf();
        config.wallet = "wallet".to_string();
        let config = config.with_dynamic_ports();

        let wallet = WalletFile::from_json(datadir.path(), "wallet");
        info!(
            "Loaded '{}' wallet: {} transactions, {} UTXOs, balance: {:.8} DASH",
            wallet.wallet_name, wallet.transaction_count, wallet.utxo_count, wallet.balance
        );

        let mut node = DashCoreNode::with_config(config);
        let addr = node.start().await;
        info!("DashCoreNode started at {}", addr);

        // Load a separate wallet for mining so coinbase rewards don't pollute
        // the test wallet's address space (the "wallet" wallet and SPV wallet
        // share the same mnemonic).
        node.ensure_wallet("default");
        info!("Mining wallet 'default' ready");

        let expected_height = node.get_block_count().await;
        info!("Dashd has {} blocks", expected_height);

        let supports_mining = node.supports_mining();
        if !supports_mining {
            info!("RPC miner not available (tests requiring block generation will be skipped)");
        }

        Some(DashdTestContext {
            node,
            addr,
            expected_height,
            wallet,
            supports_mining,
            _datadir: datadir,
        })
    }
}
