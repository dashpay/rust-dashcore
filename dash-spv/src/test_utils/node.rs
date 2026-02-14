//! Dash Core node test infrastructure for integration testing.
//!
//! This provides utilities for managing a dashd instance and loading test wallet data.

use dashcore::Address;
use dashcore::{Amount, BlockHash, Txid};
use dashcore_rpc::{Auth, Client, RpcApi};
use serde::Deserialize;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Child;
use tokio::time::{sleep, timeout};

/// Regtest P2P port
pub const REGTEST_P2P_PORT: u16 = 29999;
/// Regtest RPC port
pub const REGTEST_RPC_PORT: u16 = 29998;

/// Find an available TCP port by binding to port 0 and letting the OS assign one.
fn find_available_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("Failed to bind to port 0")
        .local_addr()
        .expect("Failed to get local address")
        .port()
}

/// Configuration for Dash Core node
pub struct DashCoreConfig {
    /// Path to dashd binary
    pub dashd_path: PathBuf,
    /// Path to existing datadir with blockchain data
    pub datadir: PathBuf,
    /// Wallet name to load on startup
    pub wallet: String,
    /// P2P port for the node
    pub p2p_port: u16,
    /// RPC port for the node
    pub rpc_port: u16,
}

impl DashCoreConfig {
    /// Create a config from environment variables.
    ///
    /// Reads `DASHD_PATH` and `DASHD_DATADIR`. Panics if either variable
    /// is not set or if the dashd binary doesn't exist.
    pub fn from_env() -> Self {
        let error = "DASHD_PATH and DASHD_DATADIR must be set for dashd integration tests. \
             Run `python3 contrib/setup-dashd.py` to set them up, \
             or set SKIP_DASHD_TESTS=1 to skip.";
        let dashd_path = std::env::var("DASHD_PATH").ok().map(PathBuf::from).expect(error);

        assert!(
            dashd_path.exists(),
            "DASHD_PATH points to a file that does not exist: {}",
            dashd_path.display()
        );

        let datadir = std::env::var("DASHD_DATADIR").ok().map(PathBuf::from).expect(error);

        Self {
            dashd_path,
            datadir,
            wallet: "default".to_string(),
            p2p_port: REGTEST_P2P_PORT,
            rpc_port: REGTEST_RPC_PORT,
        }
    }

    /// Create a config with dynamically allocated ports for parallel test execution.
    pub fn with_dynamic_ports(mut self) -> Self {
        self.p2p_port = find_available_port();
        self.rpc_port = find_available_port();
        self
    }
}

/// Test infrastructure for managing a Dash Core node
pub struct DashCoreNode {
    config: DashCoreConfig,
    process: Option<Child>,
}

impl DashCoreNode {
    /// Create a new Dash Core node with custom configuration
    pub fn with_config(config: DashCoreConfig) -> Self {
        Self {
            config,
            process: None,
        }
    }

    /// Start the Dash Core node
    pub async fn start(&mut self) -> SocketAddr {
        tracing::info!("Starting dashd...");
        tracing::info!("  Binary: {:?}", self.config.dashd_path);
        tracing::info!("  Datadir: {:?}", self.config.datadir);
        tracing::info!("  P2P port: {}", self.config.p2p_port);
        tracing::info!("  RPC port: {}", self.config.rpc_port);

        fs::create_dir_all(&self.config.datadir).expect("failed to create datadir");

        let args_vec = vec![
            "-regtest".to_string(),
            format!("-datadir={}", self.config.datadir.display()),
            format!("-port={}", self.config.p2p_port),
            format!("-rpcport={}", self.config.rpc_port),
            "-server=1".to_string(),
            "-daemon=0".to_string(),
            "-fallbackfee=0.00001".to_string(),
            "-rpcbind=127.0.0.1".to_string(),
            "-rpcallowip=127.0.0.1".to_string(),
            "-listen=1".to_string(),
            "-txindex=0".to_string(),
            "-addressindex=0".to_string(),
            "-spentindex=0".to_string(),
            "-timestampindex=0".to_string(),
            "-blockfilterindex=1".to_string(),
            "-peerblockfilters=1".to_string(),
            "-printtoconsole".to_string(),
            format!("-wallet={}", self.config.wallet),
        ];

        let mut cmd = tokio::process::Command::new(&self.config.dashd_path);
        cmd.args(&args_vec)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let mut child = cmd.spawn().expect("failed to spawn dashd process");

        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(async move {
                let mut reader = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = reader.next_line().await {
                    tracing::debug!("dashd stderr: {}", line);
                }
            });
        }

        self.process = Some(child);

        tracing::info!("Waiting for dashd to be ready...");
        tokio::time::sleep(Duration::from_millis(500)).await;
        if let Some(ref mut proc) = self.process {
            if let Ok(Some(status)) = proc.try_wait() {
                panic!("dashd exited immediately with status: {}", status);
            }
        }

        let ready = self.wait_for_ready().await;
        if !ready {
            if let Some(ref mut proc) = self.process {
                if let Ok(Some(status)) = proc.try_wait() {
                    panic!("dashd exited with status: {}", status);
                }
            }
            panic!("dashd failed to start within timeout");
        }

        let addr = SocketAddr::from(([127, 0, 0, 1], self.config.p2p_port));
        tracing::info!("dashd started and ready at {}", addr);

        addr
    }

    async fn wait_for_ready(&self) -> bool {
        let max_wait = Duration::from_secs(30);
        let check_interval = Duration::from_millis(500);

        let result = timeout(max_wait, async {
            // Wait for the P2P port to accept connections
            loop {
                let addr = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), self.config.p2p_port));
                if tokio::net::TcpStream::connect(addr).await.is_ok() {
                    break;
                }
                sleep(check_interval).await;
            }

            // Wait for RPC to be fully responsive (not just "warming up")
            loop {
                let url = format!("http://127.0.0.1:{}", self.config.rpc_port);
                let cookie_path = self.config.datadir.join("regtest/.cookie");
                if let Ok(auth) =
                    cookie_path.exists().then_some(Auth::CookieFile(cookie_path)).ok_or(())
                {
                    if let Ok(client) = Client::new(&url, auth) {
                        match client.get_blockchain_info() {
                            Ok(_) => return true,
                            Err(e) => {
                                tracing::debug!("RPC not ready yet: {}", e);
                            }
                        }
                    }
                }
                sleep(check_interval).await;
            }
        })
        .await;

        result.unwrap_or(false)
    }

    /// Stop the Dash Core node
    pub async fn stop(&mut self) {
        if let Some(mut process) = self.process.take() {
            tracing::info!("Stopping dashd...");
            let _ = process.kill().await;
            let _ = process.wait().await;
            tracing::info!("dashd stopped");
        }
    }

    /// Get block count via dash-cli
    pub async fn get_block_count(&self) -> u32 {
        let cli_name = if cfg!(windows) {
            "dash-cli.exe"
        } else {
            "dash-cli"
        };
        let dash_cli = self
            .config
            .dashd_path
            .parent()
            .map(|p| p.join(cli_name))
            .expect("could not find dash-cli");

        let output = Command::new(dash_cli)
            .arg("-regtest")
            .arg(format!("-datadir={}", self.config.datadir.display()))
            .arg(format!("-rpcport={}", self.config.rpc_port))
            .arg("getblockcount")
            .output()
            .expect("failed to run dash-cli");

        assert!(
            output.status.success(),
            "dash-cli failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let count_str = String::from_utf8(output.stdout).expect("invalid utf-8 from dash-cli");
        count_str.trim().parse::<u32>().expect("failed to parse block count")
    }

    /// Get an RPC client targeting the primary wallet.
    fn rpc_client(&self) -> Client {
        self.rpc_client_for_wallet(&self.config.wallet)
    }

    /// Get an RPC client targeting a specific wallet.
    fn rpc_client_for_wallet(&self, wallet_name: &str) -> Client {
        let url = format!("http://127.0.0.1:{}/wallet/{}", self.config.rpc_port, wallet_name);
        let cookie_path = self.config.datadir.join("regtest/.cookie");
        assert!(
            cookie_path.exists(),
            "RPC cookie file not found at {}. Is dashd running with this datadir?",
            cookie_path.display()
        );
        let auth = Auth::CookieFile(cookie_path);
        Client::new(&url, auth).expect("failed to create rpc client")
    }

    /// Load a wallet by name, creating it if it doesn't exist.
    pub fn ensure_wallet(&self, wallet_name: &str) {
        let client = self.rpc_client();
        match client.load_wallet(wallet_name) {
            Ok(_) => tracing::info!("Loaded wallet: {}", wallet_name),
            Err(_) => {
                client
                    .create_wallet(wallet_name, None, None, None, None)
                    .unwrap_or_else(|e| panic!("failed to create wallet '{}': {}", wallet_name, e));
                tracing::info!("Created wallet: {}", wallet_name);
            }
        }
    }

    /// Get a new address from the primary dashd wallet.
    pub fn get_new_address(&self) -> Address {
        let client = self.rpc_client();
        let address = client.get_new_address(None).expect("failed to get new address");
        address.assume_checked()
    }

    /// Get a new address from a specific dashd wallet.
    pub fn get_new_address_from_wallet(&self, wallet_name: &str) -> Address {
        let client = self.rpc_client_for_wallet(wallet_name);
        let address = client.get_new_address(None).expect("failed to get new address");
        address.assume_checked()
    }

    /// Check if the connected dashd supports `generatetoaddress` (RPC miner).
    ///
    /// Some builds (e.g. Windows release binaries) ship without the RPC miner compiled in.
    pub fn supports_mining(&self) -> bool {
        let client = self.rpc_client();
        let addr = self.get_new_address();
        match client.generate_to_address(0, &addr) {
            Ok(_) => true,
            Err(dashcore_rpc::Error::JsonRpc(dashcore_rpc::jsonrpc::Error::Rpc(ref e)))
                if e.message.contains("not available") =>
            {
                false
            }
            // Any other error (auth, network) still counts as "available" —
            // a real generate call will surface the actual error.
            Err(_) => true,
        }
    }

    /// Generate blocks to the given address.
    pub fn generate_blocks(&self, count: u64, address: &Address) -> Vec<BlockHash> {
        let client = self.rpc_client();
        let hashes = client.generate_to_address(count, address).expect("failed to generate blocks");
        tracing::info!("Generated {} blocks to {}", count, address);
        hashes
    }

    /// Send DASH to an address.
    pub fn send_to_address(&self, address: &Address, amount: Amount) -> Txid {
        let client = self.rpc_client();
        let txid = client
            .send_to_address(address, amount, None, None, None, None, None, None, None, None)
            .expect("failed to send to address");
        tracing::info!("Sent {} to {}, txid: {}", amount, address, txid);
        txid
    }

    /// Disconnect all currently connected peers.
    pub fn disconnect_all_peers(&self) {
        let client = self.rpc_client();
        let peers = client.get_peer_info().expect("failed to get peer info");
        for peer in &peers {
            let addr = peer.addr.to_string();
            let _ = client.disconnect_node(&addr);
            tracing::info!("Disconnected peer {}", addr);
        }
        tracing::info!("Disconnected {} peers", peers.len());
    }

    /// Get the datadir path
    pub fn datadir(&self) -> &Path {
        &self.config.datadir
    }
}

impl Drop for DashCoreNode {
    fn drop(&mut self) {
        if let Some(mut process) = self.process.take() {
            tracing::info!("Stopping dashd process in Drop...");
            if let Err(e) = process.start_kill() {
                tracing::warn!("Failed to kill dashd process: {}", e);
            }
        }
    }
}

/// Wallet file structure for test wallets
#[derive(Debug, Deserialize)]
pub struct WalletFile {
    pub wallet_name: String,
    pub mnemonic: String,
    pub balance: f64,
    pub transaction_count: usize,
    pub utxo_count: usize,
    pub transactions: Vec<serde_json::Value>,
    pub utxos: Vec<serde_json::Value>,
}

impl WalletFile {
    /// Load a wallet file from the wallets directory in a datadir
    pub fn from_json(datadir: &Path, wallet_name: &str) -> Self {
        let wallet_path = datadir.join("wallets").join(format!("{}.json", wallet_name));
        if !wallet_path.exists() {
            panic!("Wallet file not found: {:?}", wallet_path);
        }

        let contents = fs::read_to_string(&wallet_path).expect("Failed to read wallet file");
        serde_json::from_str(&contents).expect("Failed to deserialize wallet file")
    }
}
