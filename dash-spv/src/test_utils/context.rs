//! Shared dashd test context for integration tests.
//!
//! Provides `DashdTestContext` which encapsulates the common setup logic for
//! launching a dashd node with a pre-built blockchain and loading wallet data.
//! Used by both `dash-spv` and `dash-spv-ffi` integration tests.

use std::net::SocketAddr;

use tempfile::TempDir;
use tracing::info;

use super::fs_helpers::{copy_dir, retain_test_dir};
use super::node::TestChain;
use super::{DashCoreConfig, DashCoreNode, WalletFile};

/// Shared test infrastructure for dashd integration tests.
///
/// Manages a dashd node instance backed by a copied blockchain directory,
/// along with the expected chain height and a pre-loaded wallet file.
pub struct DashdTestContext {
    /// The managed dashd process.
    pub node: DashCoreNode,
    /// P2P address of the running dashd node.
    pub addr: SocketAddr,
    /// Block height at startup (before any test-generated blocks).
    pub initial_height: u32,
    /// Pre-loaded wallet data from the test blockchain directory.
    pub wallet: WalletFile,
    /// Whether the dashd binary supports the `generatetoaddress` RPC.
    pub supports_mining: bool,
    /// Temporary directory containing the blockchain data.
    datadir: TempDir,
}

impl DashdTestContext {
    /// Create a new dashd test context for the given chain variant.
    ///
    /// Returns `None` if `SKIP_DASHD_TESTS` is set. Panics if the variant
    /// directory is not available under `DASHD_TEST_DATA` or if dashd fails
    /// to start.
    pub async fn new(chain: TestChain) -> Option<Self> {
        if std::env::var("SKIP_DASHD_TESTS").is_ok() {
            eprintln!("Skipping dashd integration test (SKIP_DASHD_TESTS is set)");
            return None;
        }

        let config = DashCoreConfig::from_env(chain)
            .unwrap_or_else(|| panic!("DASHD_TEST_DATA/{} not found", chain.variant_dir()));
        Some(Self::create(config).await)
    }

    /// Shared initialization: copies the datadir, starts dashd, loads wallets.
    async fn create(mut config: DashCoreConfig) -> Self {
        let datadir = TempDir::new().expect("failed to create temp dir");
        copy_dir(&config.datadir, datadir.path()).expect("failed to copy datadir");
        config.datadir = datadir.path().to_path_buf();
        config.wallet = "wallet".to_string();

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

        let initial_height = node.get_block_count();
        info!("Dashd has {} blocks", initial_height);

        let supports_mining = node.supports_mining();
        if !supports_mining {
            info!("RPC miner not available (tests requiring block generation will be skipped)");
        }

        DashdTestContext {
            node,
            addr,
            initial_height,
            wallet,
            supports_mining,
            datadir,
        }
    }
}

impl Drop for DashdTestContext {
    fn drop(&mut self) {
        let label = format!("dashd-{}", self.addr.port());
        retain_test_dir(self.datadir.path(), &label);
    }
}
