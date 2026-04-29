//! Network chaos test harness wrapping `DashdTestContext` with a Toxiproxy proxy.
//!
//! Each `ChaoticDashd` owns a private Toxiproxy server process and a configurable
//! number of TCP proxy slots that all forward to the same dashd P2P port. Tests
//! point an SPV client at the proxy listen ports and inject latency, bandwidth
//! limits or hard disconnects via the helpers on this struct to reproduce the
//! conditions described in the network chaos finding reports.

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::process::{Child, Command};
use tokio::task::spawn_blocking;
use tokio::time::sleep;
use toxiproxy_rust::client::Client as ToxiproxyClient;
use toxiproxy_rust::proxy::ProxyPack;

use super::node::TestChain;
use super::DashdTestContext;

const TOXIPROXY_BIN_ENV: &str = "TOXIPROXY_BIN";
const TOXIPROXY_READY_TIMEOUT: Duration = Duration::from_secs(10);

/// Network chaos harness wrapping a real dashd node behind a fleet of Toxiproxy
/// TCP proxies. Use the toxic helpers to inject latency, bandwidth limits, or
/// hard disconnects on individual peer slots.
pub struct ChaoticDashd {
    dashd: DashdTestContext,
    /// Toxiproxy server process. Killed on drop.
    toxiproxy: Child,
    /// Toxiproxy REST API address.
    api_addr: SocketAddr,
    /// Listen address for each proxy slot. Slot index matches `proxy_names`.
    listen_addrs: Vec<SocketAddr>,
    /// Proxy names registered with the Toxiproxy server, indexed by slot.
    proxy_names: Vec<String>,
}

impl ChaoticDashd {
    /// Spawn dashd, a private Toxiproxy server, and `num_peer_slots` TCP proxies
    /// that all forward to dashd's P2P port.
    ///
    /// Returns `None` if `SKIP_DASHD_TESTS` is set or test data is unavailable.
    /// Panics if `TOXIPROXY_BIN` is not set, the binary cannot be launched, or
    /// any proxy fails to register.
    pub async fn start(num_peer_slots: usize, chain: TestChain) -> Option<Self> {
        assert!(num_peer_slots > 0, "num_peer_slots must be at least 1");

        let dashd = DashdTestContext::new(chain).await?;
        let toxiproxy_bin = toxiproxy_bin_path();

        let api_port = reserve_port();
        let api_addr: SocketAddr =
            format!("127.0.0.1:{}", api_port).parse().expect("api addr parses");

        let toxiproxy = Command::new(&toxiproxy_bin)
            .args(["-host", "127.0.0.1", "-port", &api_port.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap_or_else(|e| {
                panic!("failed to spawn toxiproxy ({}): {}", toxiproxy_bin.display(), e)
            });

        wait_for_toxiproxy(api_addr).await;

        let mut listen_addrs = Vec::with_capacity(num_peer_slots);
        let mut proxy_packs = Vec::with_capacity(num_peer_slots);
        let mut proxy_names = Vec::with_capacity(num_peer_slots);
        let upstream = dashd.addr.to_string();
        for slot in 0..num_peer_slots {
            let listen_port = reserve_port();
            let listen = format!("127.0.0.1:{}", listen_port);
            let name = format!("dashd-slot-{}-{}", api_port, slot);
            listen_addrs.push(listen.parse().expect("listen addr parses"));
            proxy_packs.push(ProxyPack::new(name.clone(), listen, upstream.clone()));
            proxy_names.push(name);
        }

        spawn_blocking(move || ToxiproxyClient::new(api_addr).populate(proxy_packs))
            .await
            .expect("populate task panicked")
            .expect("toxiproxy populate failed");

        Some(Self {
            dashd,
            toxiproxy,
            api_addr,
            listen_addrs,
            proxy_names,
        })
    }

    /// PID of the embedded Toxiproxy server process, if still alive.
    pub fn toxiproxy_pid(&self) -> Option<u32> {
        self.toxiproxy.id()
    }

    /// Listen addresses an SPV client should be configured with, one per slot.
    pub fn p2p_addrs(&self) -> Vec<SocketAddr> {
        self.listen_addrs.clone()
    }

    /// Listen address for a single slot.
    pub fn p2p_addr(&self, slot: usize) -> SocketAddr {
        self.listen_addrs[slot]
    }

    /// Pure passthrough to the underlying dashd test context.
    pub fn dashd(&self) -> &DashdTestContext {
        &self.dashd
    }

    /// Number of configured peer slots.
    pub fn slot_count(&self) -> usize {
        self.proxy_names.len()
    }

    /// Add a latency toxic on both directions of a single slot.
    pub async fn add_latency(&self, slot: usize, latency_ms: u32, jitter_ms: u32) {
        let name = self.proxy_names[slot].clone();
        let api_addr = self.api_addr;
        spawn_blocking(move || apply_latency(api_addr, &name, latency_ms, jitter_ms))
            .await
            .expect("latency task panicked")
            .expect("apply_latency failed");
    }

    /// Apply the same latency toxic to every slot.
    pub async fn add_latency_all(&self, latency_ms: u32, jitter_ms: u32) {
        for slot in 0..self.slot_count() {
            self.add_latency(slot, latency_ms, jitter_ms).await;
        }
    }

    /// Add a downstream bandwidth cap on a single slot.
    pub async fn add_bandwidth_limit(&self, slot: usize, kbps: u32) {
        let name = self.proxy_names[slot].clone();
        let api_addr = self.api_addr;
        spawn_blocking(move || apply_bandwidth(api_addr, &name, kbps))
            .await
            .expect("bandwidth task panicked")
            .expect("apply_bandwidth failed");
    }

    /// Disable the proxy for `slot`, severing the TCP connection.
    pub async fn drop_connection(&self, slot: usize) {
        let name = self.proxy_names[slot].clone();
        let api_addr = self.api_addr;
        spawn_blocking(move || disable_proxy(api_addr, &name))
            .await
            .expect("disable task panicked")
            .expect("disable_proxy failed");
    }

    /// Re-enable the proxy for `slot` and clear any toxics on it.
    pub async fn restore(&self, slot: usize) {
        let name = self.proxy_names[slot].clone();
        let api_addr = self.api_addr;
        spawn_blocking(move || restore_proxy(api_addr, &name))
            .await
            .expect("restore task panicked")
            .expect("restore_proxy failed");
    }

    /// Disable every proxy.
    pub async fn drop_all(&self) {
        for slot in 0..self.slot_count() {
            self.drop_connection(slot).await;
        }
    }

    /// Restore every proxy to a clean state.
    pub async fn restore_all(&self) {
        for slot in 0..self.slot_count() {
            self.restore(slot).await;
        }
    }
}

fn toxiproxy_bin_path() -> PathBuf {
    let path = std::env::var(TOXIPROXY_BIN_ENV).unwrap_or_else(|_| {
        panic!(
            "{} environment variable is required. Run `eval $(python3 contrib/setup-dashd.py)` \
             to download the toxiproxy server binary and export this variable.",
            TOXIPROXY_BIN_ENV
        )
    });
    let path = PathBuf::from(path);
    assert!(path.exists(), "{} points to a missing file: {}", TOXIPROXY_BIN_ENV, path.display());
    path
}

/// Reserve a port by binding briefly. The kernel-assigned port is then released
/// for the next caller (typically toxiproxy-server or a proxy listener).
///
/// There is a small race window between drop and reuse, but the binary opens
/// the port within milliseconds and `wait_for_toxiproxy` rejects failures.
fn reserve_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind ephemeral port");
    listener.local_addr().expect("local_addr").port()
}

async fn wait_for_toxiproxy(api_addr: SocketAddr) {
    let deadline = Instant::now() + TOXIPROXY_READY_TIMEOUT;
    loop {
        if TcpStream::connect_timeout(&api_addr, Duration::from_millis(100)).is_ok() {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "toxiproxy server at {} did not become reachable within {:?}",
                api_addr, TOXIPROXY_READY_TIMEOUT
            );
        }
        sleep(Duration::from_millis(50)).await;
    }
}

fn apply_latency(
    api_addr: SocketAddr,
    name: &str,
    latency_ms: u32,
    jitter_ms: u32,
) -> Result<(), String> {
    let client = ToxiproxyClient::new(api_addr);
    let proxy = client.find_proxy(name)?;
    proxy.with_latency("upstream".into(), latency_ms, jitter_ms, 1.0);
    proxy.with_latency("downstream".into(), latency_ms, jitter_ms, 1.0);
    Ok(())
}

fn apply_bandwidth(api_addr: SocketAddr, name: &str, kbps: u32) -> Result<(), String> {
    let client = ToxiproxyClient::new(api_addr);
    let proxy = client.find_proxy(name)?;
    proxy.with_bandwidth("upstream".into(), kbps, 1.0);
    proxy.with_bandwidth("downstream".into(), kbps, 1.0);
    Ok(())
}

fn disable_proxy(api_addr: SocketAddr, name: &str) -> Result<(), String> {
    let client = ToxiproxyClient::new(api_addr);
    let proxy = client.find_proxy(name)?;
    proxy.disable()
}

fn restore_proxy(api_addr: SocketAddr, name: &str) -> Result<(), String> {
    let client = ToxiproxyClient::new(api_addr);
    let proxy = client.find_proxy(name)?;
    proxy.delete_all_toxics()?;
    proxy.enable()
}
