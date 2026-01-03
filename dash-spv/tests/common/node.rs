//! Dash Core node harness for integration testing.
//!
//! This starts a dashd instance using existing regtest data providing full protocol support.
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout};

const REGTEST_P2P_PORT: u16 = 19999;
const REGTEST_RPC_PORT: u16 = 19998;

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
                // Fallback to default cache location from setup-dashd.sh
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

        // Ensure datadir exists
        std::fs::create_dir_all(&self.config.datadir)?;

        // Build command arguments
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

        // Try running through bash with explicit ulimit
        // Use launchctl to set file descriptor limit if on macOS
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

        let mut child = Command::new("bash")
            .arg("-c")
            .arg(&script)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        // Spawn task to read stderr for debugging
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(async move {
                let mut reader = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = reader.next_line().await {
                    tracing::debug!("dashd stderr: {}", line);
                }
            });
        }

        self.process = Some(child);

        // Wait for node to be ready by checking if port is open
        tracing::info!("Waiting for dashd to be ready...");

        // First check if process died immediately (e.g., due to lock)
        tokio::time::sleep(Duration::from_millis(500)).await;
        if let Some(ref mut proc) = self.process {
            if let Ok(Some(status)) = proc.try_wait() {
                return Err(format!("dashd exited immediately with status: {}", status).into());
            }
        }

        let ready = self.wait_for_ready().await?;
        if !ready {
            // Try to get exit status if process died
            if let Some(ref mut proc) = self.process {
                if let Ok(Some(status)) = proc.try_wait() {
                    return Err(format!("dashd exited with status: {}", status).into());
                }
            }
            return Err("dashd failed to start within timeout".into());
        }

        // Double-check process is still alive after port check
        if let Some(ref mut proc) = self.process {
            if let Ok(Some(status)) = proc.try_wait() {
                return Err(
                    format!("dashd died after port became ready, status: {}", status).into()
                );
            }
        }

        let addr = SocketAddr::from(([127, 0, 0, 1], REGTEST_P2P_PORT));
        tracing::info!("✅ dashd started and ready at {}", addr);

        Ok(addr)
    }

    /// Wait for dashd to be ready by checking if P2P port is accepting connections
    async fn wait_for_ready(&self) -> Result<bool, Box<dyn std::error::Error>> {
        let max_wait = Duration::from_secs(30);
        let check_interval = Duration::from_millis(500);

        let result = timeout(max_wait, async {
            loop {
                let addr = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), REGTEST_P2P_PORT));
                if tokio::net::TcpStream::connect(addr).await.is_ok() {
                    tracing::debug!("P2P port is accepting connections");
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

            // Try graceful shutdown via RPC if possible
            // For now, just kill the process
            let _ = process.kill().await;
            let _ = process.wait().await;

            tracing::info!("✅ dashd stopped");
        }
    }

    /// Get block count via RPC
    pub async fn get_block_count(&self) -> Result<u32, Box<dyn std::error::Error>> {
        // This would use RPC to get block count
        // For now, we'll use dash-cli
        let dash_cli = self
            .config
            .dashd_path
            .parent()
            .map(|p| p.join("dash-cli"))
            .ok_or("Could not find dash-cli")?;

        let output = std::process::Command::new(dash_cli)
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
        let count_str = count_str.trim();
        if count_str.is_empty() {
            return Err("Empty response from getblockcount".into());
        }
        let count = count_str.parse::<u32>()?;
        Ok(count)
    }
}

impl Drop for DashCoreNode {
    fn drop(&mut self) {
        if let Some(mut process) = self.process.take() {
            tracing::info!("Stopping dashd process in Drop...");

            if let Err(e) = process.start_kill() {
                tracing::warn!("Failed to kill dashd process: {}", e);
            } else {
                tracing::info!("✅ dashd process stopped");
            }
        }
    }
}

/// Check if dashd is available (DASHD_PATH env var set and file exists)
pub fn is_dashd_available() -> bool {
    std::env::var("DASHD_PATH").map(|p| PathBuf::from(p).exists()).unwrap_or(false)
}
