//! Dash Core node harness for integration testing.
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

/// Configuration for Dash Core node
pub struct DashCoreConfig {
    /// Path to dashd binary
    pub dashd_path: PathBuf,
    /// Path to existing datadir with blockchain data
    pub datadir: PathBuf,
    /// Wallet name to load on startup
    pub wallet: String,
}

impl Default for DashCoreConfig {
    fn default() -> Self {
        let dashd_path = std::env::var("DASHD_PATH")
            .map(PathBuf::from)
            .expect("DASHD_PATH not set. Run: source ./contrib/setup-dashd.sh");

        let datadir = std::env::var("DASHD_DATADIR")
            .map(PathBuf::from)
            .or_else(|_| {
                std::env::var("HOME").map(|h| {
                    PathBuf::from(h)
                        .join(".rust-dashcore-test/regtest-blockchain-v0.0.1/regtest-1000")
                })
            })
            .expect("Neither DASHD_DATADIR nor HOME is set");

        Self {
            dashd_path,
            datadir,
            wallet: "default".to_string(),
        }
    }
}

/// Harness for managing a Dash Core node
pub struct DashCoreNode {
    config: DashCoreConfig,
    process: Option<Child>,
}

impl DashCoreNode {
    /// Create a new Dash Core node with custom configuration
    pub fn with_config(config: DashCoreConfig) -> Result<Self, Box<dyn std::error::Error>> {
        if !config.dashd_path.exists() {
            return Err(format!("dashd not found at {:?}", config.dashd_path).into());
        }

        Ok(Self {
            config,
            process: None,
        })
    }

    /// Start the Dash Core node
    pub async fn start(&mut self) -> Result<SocketAddr, Box<dyn std::error::Error>> {
        tracing::info!("Starting dashd...");
        tracing::info!("  Binary: {:?}", self.config.dashd_path);
        tracing::info!("  Datadir: {:?}", self.config.datadir);
        tracing::info!("  P2P port: {}", REGTEST_P2P_PORT);
        tracing::info!("  RPC port: {}", REGTEST_RPC_PORT);

        fs::create_dir_all(&self.config.datadir)?;

        let args_vec = vec![
            "-regtest".to_string(),
            format!("-datadir={}", self.config.datadir.display()),
            format!("-port={}", REGTEST_P2P_PORT),
            format!("-rpcport={}", REGTEST_RPC_PORT),
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

        let script = if cfg!(target_os = "macos") {
            format!(
                "launchctl limit maxfiles 10000 unlimited 2>/dev/null || true; ulimit -Sn 10000 2>/dev/null || ulimit -n 10000; exec {} {}",
                self.config.dashd_path.display(),
                args_vec.join(" ")
            )
        } else {
            format!(
                "ulimit -n 10000; exec {} {}",
                self.config.dashd_path.display(),
                args_vec.join(" ")
            )
        };

        let mut child = tokio::process::Command::new("bash")
            .arg("-c")
            .arg(&script)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;

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
                return Err(format!("dashd exited immediately with status: {}", status).into());
            }
        }

        let ready = self.wait_for_ready().await?;
        if !ready {
            if let Some(ref mut proc) = self.process {
                if let Ok(Some(status)) = proc.try_wait() {
                    return Err(format!("dashd exited with status: {}", status).into());
                }
            }
            return Err("dashd failed to start within timeout".into());
        }

        let addr = SocketAddr::from(([127, 0, 0, 1], REGTEST_P2P_PORT));
        tracing::info!("dashd started and ready at {}", addr);

        Ok(addr)
    }

    async fn wait_for_ready(&self) -> Result<bool, Box<dyn std::error::Error>> {
        let max_wait = Duration::from_secs(30);
        let check_interval = Duration::from_millis(500);

        let result = timeout(max_wait, async {
            loop {
                let addr = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), REGTEST_P2P_PORT));
                if tokio::net::TcpStream::connect(addr).await.is_ok() {
                    return true;
                }
                sleep(check_interval).await;
            }
        })
        .await;

        Ok(result.unwrap_or(false))
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
    pub async fn get_block_count(&self) -> Result<u32, Box<dyn std::error::Error>> {
        let dash_cli = self
            .config
            .dashd_path
            .parent()
            .map(|p| p.join("dash-cli"))
            .ok_or("Could not find dash-cli")?;

        let output = Command::new(dash_cli)
            .arg("-regtest")
            .arg(format!("-datadir={}", self.config.datadir.display()))
            .arg(format!("-rpcport={}", REGTEST_RPC_PORT))
            .arg("getblockcount")
            .output()?;

        if !output.status.success() {
            return Err(
                format!("dash-cli failed: {}", String::from_utf8_lossy(&output.stderr)).into()
            );
        }

        let count_str = String::from_utf8(output.stdout)?;
        let count = count_str.trim().parse::<u32>()?;
        Ok(count)
    }

    /// Get an RPC client for direct interaction with dashd.
    pub fn rpc_client(&self) -> Result<Client, Box<dyn std::error::Error>> {
        let url = format!("http://127.0.0.1:{}", REGTEST_RPC_PORT);
        // Regtest with cookie auth - read from datadir
        let cookie_path = self.config.datadir.join("regtest/.cookie");
        let auth = if cookie_path.exists() {
            Auth::CookieFile(cookie_path)
        } else {
            // Fallback to no auth if cookie doesn't exist yet
            Auth::None
        };
        Ok(Client::new(&url, auth)?)
    }

    /// Get a new address from the dashd wallet.
    ///
    /// # Returns
    /// A new receive address from the node's wallet.
    pub fn get_new_address(&self) -> Result<Address, Box<dyn std::error::Error>> {
        let client = self.rpc_client()?;
        let address = client.get_new_address(None)?;
        // Assume checked since we know the network is regtest
        Ok(address.assume_checked())
    }

    /// Generate blocks to the given address.
    ///
    /// # Arguments
    /// * `count` - Number of blocks to generate
    /// * `address` - Address to receive the coinbase rewards
    ///
    /// # Returns
    /// Vector of block hashes for the generated blocks.
    pub fn generate_blocks(
        &self,
        count: u64,
        address: &Address,
    ) -> Result<Vec<BlockHash>, Box<dyn std::error::Error>> {
        let client = self.rpc_client()?;
        let hashes = client.generate_to_address(count, address)?;
        tracing::info!("Generated {} blocks to {}", count, address);
        Ok(hashes)
    }

    /// Send DASH to an address.
    ///
    /// # Arguments
    /// * `address` - Destination address
    /// * `amount` - Amount to send
    ///
    /// # Returns
    /// Transaction ID of the sent transaction.
    pub fn send_to_address(
        &self,
        address: &Address,
        amount: Amount,
    ) -> Result<Txid, Box<dyn std::error::Error>> {
        let client = self.rpc_client()?;
        let txid = client
            .send_to_address(address, amount, None, None, None, None, None, None, None, None)?;
        tracing::info!("Sent {} to {}, txid: {}", amount, address, txid);
        Ok(txid)
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

/// Check if dashd is available (DASHD_PATH env var set and file exists)
pub fn is_dashd_available() -> bool {
    std::env::var("DASHD_PATH").map(|p| PathBuf::from(p).exists()).unwrap_or(false)
}

/// Kill all running dashd processes
pub fn kill_all_dashd() {
    let _ = Command::new("pkill").arg("-9").arg("-x").arg("dashd").output();
    std::thread::sleep(Duration::from_millis(500));
}

/// Wallet file structure for test wallets
#[derive(Debug, Deserialize)]
pub struct WalletFile {
    pub wallet_name: String,
    pub mnemonic: String,
    pub balance: f64,
    pub transaction_count: usize,
    pub utxo_count: usize,
    #[allow(dead_code)]
    pub transactions: Vec<serde_json::Value>,
    pub utxos: Vec<serde_json::Value>,
}

/// Load a wallet file from the wallets directory in a datadir
pub fn load_wallet_file(
    datadir: &Path,
    wallet_name: &str,
) -> Result<WalletFile, Box<dyn std::error::Error>> {
    let wallet_path = datadir.join("wallets").join(format!("{}.json", wallet_name));
    if !wallet_path.exists() {
        return Err(format!("Wallet file not found: {:?}", wallet_path).into());
    }

    let contents = fs::read_to_string(&wallet_path)?;
    let wallet: WalletFile = serde_json::from_str(&contents)?;
    Ok(wallet)
}
