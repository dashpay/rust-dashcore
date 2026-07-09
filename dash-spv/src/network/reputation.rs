//! Peer behaviour scoring for selection.
//!
//! Each peer carries a behaviour multiplier in `[0, 1]`. Good actions nudge it up
//! toward 1, bad actions down toward 0, and a security violation (the peer fed us
//! invalid data — it lied) drops it straight to 0. Peer selection multiplies this
//! by the peer's response-time score, so a misbehaving peer is deprioritised and a
//! lying one is never chosen. This manager persists the multiplier (and last
//! measured latency) so the judgement survives across connections.

use crate::storage::PeerStorage;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// A peer behaviour event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeReason {
    HandshakeFailed,
    ConnectionFailed,
    Timeout,
    PingFailed,
    BadResponse,
    GoodResponse,
    LongUptime,
    /// The peer supplied invalid/untrustworthy data — treat it as a liar.
    InvalidData,
}

impl ChangeReason {
    /// A security violation collapses the multiplier to zero immediately.
    pub fn is_security_violation(&self) -> bool {
        matches!(self, ChangeReason::InvalidData)
    }

    /// Additive change to the `[0, 1]` behaviour multiplier for non-fatal events.
    fn delta(&self) -> f32 {
        match self {
            ChangeReason::HandshakeFailed => -0.3,
            ChangeReason::ConnectionFailed => -0.1,
            ChangeReason::Timeout => -0.2,
            ChangeReason::PingFailed => -0.2,
            ChangeReason::BadResponse => -0.3,
            ChangeReason::GoodResponse => 0.1,
            ChangeReason::LongUptime => 0.1,
            ChangeReason::InvalidData => -1.0,
        }
    }

    /// Apply this event to a multiplier, clamped to `[0, 1]` (0 on a security
    /// violation).
    pub fn apply(&self, multiplier: f32) -> f32 {
        if self.is_security_violation() {
            return 0.0;
        }
        (multiplier + self.delta()).clamp(0.0, 1.0)
    }
}

impl std::fmt::Display for ChangeReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            ChangeReason::HandshakeFailed => "handshake failed",
            ChangeReason::ConnectionFailed => "connection failed",
            ChangeReason::Timeout => "timed out",
            ChangeReason::PingFailed => "ping failed",
            ChangeReason::BadResponse => "bad response",
            ChangeReason::GoodResponse => "good response",
            ChangeReason::LongUptime => "long uptime",
            ChangeReason::InvalidData => "invalid data",
        };
        f.write_str(label)
    }
}

fn default_multiplier() -> f32 {
    1.0
}

fn clamp_multiplier<'de, D>(deserializer: D) -> Result<f32, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(f32::deserialize(deserializer)?.clamp(0.0, 1.0))
}

/// Persisted peer quality: behaviour multiplier plus last measured latency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerReputation {
    #[serde(default = "default_multiplier", deserialize_with = "clamp_multiplier")]
    pub multiplier: f32,
    #[serde(default)]
    pub median_rtt_ms: Option<u32>,
}

impl Default for PeerReputation {
    fn default() -> Self {
        Self {
            multiplier: 1.0,
            median_rtt_ms: None,
        }
    }
}

/// Tracks and persists per-peer behaviour multipliers.
pub struct PeerReputationManager {
    records: Arc<RwLock<HashMap<SocketAddr, PeerReputation>>>,
}

impl Default for PeerReputationManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerReputationManager {
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Apply a behaviour event to a peer that has no live connection to carry the
    /// multiplier (e.g. a connect or handshake failure). Returns the new value.
    pub async fn penalize(&self, addr: SocketAddr, reason: ChangeReason) -> f32 {
        let mut records = self.records.write().await;
        let record = records.entry(addr).or_default();
        record.multiplier = reason.apply(record.multiplier);
        record.multiplier
    }

    /// Write through a live peer's measured quality for persistence and reuse.
    pub async fn record(&self, addr: SocketAddr, multiplier: f32, median_rtt_ms: Option<u32>) {
        let mut records = self.records.write().await;
        let record = records.entry(addr).or_default();
        record.multiplier = multiplier.clamp(0.0, 1.0);
        if median_rtt_ms.is_some() {
            record.median_rtt_ms = median_rtt_ms;
        }
    }

    /// Record a peer's measured latency (from a background probe) without
    /// touching its behaviour multiplier.
    pub async fn record_latency(&self, addr: SocketAddr, median_rtt_ms: u32) {
        let mut records = self.records.write().await;
        records.entry(addr).or_default().median_rtt_ms = Some(median_rtt_ms);
    }

    /// Measured latency (ms) for each of `addrs` that has one, in a single lock. Used to
    /// filter dial candidates and drop connected peers by latency tier.
    pub async fn latencies(&self, addrs: &[SocketAddr]) -> HashMap<SocketAddr, u32> {
        let records = self.records.read().await;
        addrs
            .iter()
            .filter_map(|a| records.get(a).and_then(|r| r.median_rtt_ms).map(|l| (*a, l)))
            .collect()
    }

    /// Persisted `(multiplier, median_rtt_ms)` used to seed a peer on connect.
    pub async fn hint(&self, addr: &SocketAddr) -> Option<(f32, Option<u32>)> {
        self.records.read().await.get(addr).map(|r| (r.multiplier, r.median_rtt_ms))
    }

    /// A peer is dialable unless its multiplier has collapsed to zero.
    pub async fn is_usable(&self, addr: &SocketAddr) -> bool {
        self.records.read().await.get(addr).map(|r| r.multiplier > 0.0).unwrap_or(true)
    }

    /// True once the peer has a measured latency (has been probed at least once).
    pub async fn is_measured(&self, addr: &SocketAddr) -> bool {
        self.records.read().await.get(addr).map(|r| r.median_rtt_ms.is_some()).unwrap_or(false)
    }

    /// Order candidate addresses best-first (highest multiplier, then lowest
    /// measured latency), dropping any with a zero multiplier.
    pub async fn rank(&self, mut addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
        let records = self.records.read().await;
        let key = |addr: &SocketAddr| -> (f32, u32) {
            match records.get(addr) {
                Some(r) => (r.multiplier, r.median_rtt_ms.unwrap_or(u32::MAX)),
                None => (1.0, u32::MAX),
            }
        };
        addrs.retain(|addr| records.get(addr).map(|r| r.multiplier > 0.0).unwrap_or(true));
        addrs.sort_by(|a, b| {
            let (ma, la) = key(a);
            let (mb, lb) = key(b);
            mb.total_cmp(&ma).then(la.cmp(&lb))
        });
        addrs
    }

    pub async fn save_to_storage(&self, storage: &impl PeerStorage) -> std::io::Result<()> {
        let records = self.records.read().await;
        storage.save_peers_reputation(&records).await.map_err(std::io::Error::other)
    }

    pub async fn load_from_storage(&self, storage: &impl PeerStorage) -> std::io::Result<()> {
        let data = storage.load_peers_reputation().await.map_err(std::io::Error::other)?;
        let mut records = self.records.write().await;
        *records = data;
        tracing::info!("Loaded reputation data for {} peers", records.len());
        Ok(())
    }
}

// Include tests module
#[cfg(test)]
#[path = "reputation_tests.rs"]
mod reputation_tests;
