//! Peer reputation management system
//!
//! This module implements a reputation system to track peer behavior and protect
//! against malicious peers. It tracks both positive and negative behaviors,
//! implements automatic banning for excessive misbehavior, and provides reputation
//! decay over time for recovery.

use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::storage::PeerStorage;

/// Misbehavior score thresholds for different violations
pub mod misbehavior_scores {
    /// Invalid message format or protocol violation
    pub const INVALID_MESSAGE: i32 = 10;

    /// Invalid block header
    pub const INVALID_HEADER: i32 = 50;

    /// Invalid compact filter
    pub const INVALID_FILTER: i32 = 25;

    /// Timeout or slow response
    pub const TIMEOUT: i32 = 5;

    /// Sending unsolicited data
    pub const UNSOLICITED_DATA: i32 = 15;

    /// Invalid transaction
    pub const INVALID_TRANSACTION: i32 = 20;

    /// Invalid masternode list diff
    pub const INVALID_MASTERNODE_DIFF: i32 = 30;

    /// Invalid ChainLock
    pub const INVALID_CHAINLOCK: i32 = 40;

    /// Invalid InstantLock
    pub const INVALID_INSTANTLOCK: i32 = 35;

    /// Duplicate message
    pub const DUPLICATE_MESSAGE: i32 = 5;

    /// Connection flood attempt
    pub const CONNECTION_FLOOD: i32 = 20;
}

/// Positive behavior scores
pub mod positive_scores {
    /// Successfully provided valid headers
    pub const VALID_HEADERS: i32 = -5;

    /// Successfully provided valid filters
    pub const VALID_FILTERS: i32 = -3;

    /// Successfully provided valid block
    pub const VALID_BLOCK: i32 = -10;

    /// Fast response time
    pub const FAST_RESPONSE: i32 = -2;

    /// Long uptime connection
    pub const LONG_UPTIME: i32 = -5;
}

/// Ban duration for misbehaving peers
const BAN_DURATION: Duration = Duration::from_secs(24 * 60 * 60); // 24 hours

/// Reputation decay interval
const DECAY_INTERVAL: Duration = Duration::from_secs(60 * 60); // 1 hour

/// Amount to decay reputation score per interval
const DECAY_AMOUNT: i32 = 5;

/// Maximum misbehavior score before a peer is banned
const MAX_MISBEHAVIOR_SCORE: i32 = 100;

/// Minimum score (most positive reputation)
const MIN_MISBEHAVIOR_SCORE: i32 = -50;

const MAX_BAN_COUNT: u32 = 1000;

const MAX_ACTION_COUNT: u64 = 1_000_000;

fn default_instant() -> Instant {
    Instant::now()
}

fn clamp_peer_score<'de, D>(deserializer: D) -> Result<i32, D::Error>
where
    D: Deserializer<'de>,
{
    let mut v = i32::deserialize(deserializer)?;

    if v < MIN_MISBEHAVIOR_SCORE {
        log::warn!("Peer has invalid score {v}, clamping to min {MIN_MISBEHAVIOR_SCORE}");
        v = MIN_MISBEHAVIOR_SCORE
    } else if v > MAX_MISBEHAVIOR_SCORE {
        log::warn!("Peer has invalid score {v}, clamping to max {MAX_MISBEHAVIOR_SCORE}");
        v = MAX_MISBEHAVIOR_SCORE
    }

    Ok(v)
}

fn clamp_peer_ban_count<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let mut v = u32::deserialize(deserializer)?;

    if v > MAX_BAN_COUNT {
        log::warn!("Peer has excessive ban count {v}, clamping to {MAX_BAN_COUNT}");
        v = MAX_BAN_COUNT
    }

    Ok(v)
}

fn clamp_peer_connection_attempts<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let mut v = u64::deserialize(deserializer)?;

    v = v.min(MAX_ACTION_COUNT);

    Ok(v)
}

/// Peer reputation entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerReputation {
    /// Current misbehavior score
    #[serde(deserialize_with = "clamp_peer_score")]
    pub score: i32,

    /// Number of times this peer has been banned
    #[serde(deserialize_with = "clamp_peer_ban_count")]
    pub ban_count: u32,

    /// Time when the peer was banned (if currently banned)
    #[serde(skip)]
    pub banned_until: Option<Instant>,

    /// Last time the reputation was updated
    #[serde(skip, default = "default_instant")]
    pub last_update: Instant,

    /// Total number of positive actions
    pub positive_actions: u64,

    /// Total number of negative actions
    pub negative_actions: u64,

    /// Connection count
    #[serde(deserialize_with = "clamp_peer_connection_attempts")]
    pub connection_attempts: u64,

    /// Successful connection count
    pub successful_connections: u64,

    /// Last connection time
    #[serde(skip)]
    pub last_connection: Option<Instant>,
}

impl Default for PeerReputation {
    fn default() -> Self {
        Self {
            score: 0,
            ban_count: 0,
            banned_until: None,
            last_update: default_instant(),
            positive_actions: 0,
            negative_actions: 0,
            connection_attempts: 0,
            successful_connections: 0,
            last_connection: None,
        }
    }
}

impl PeerReputation {
    /// Check if the peer is currently banned
    pub fn is_banned(&self) -> bool {
        self.banned_until.is_some_and(|until| Instant::now() < until)
    }

    /// Get remaining ban time
    pub fn ban_time_remaining(&self) -> Option<Duration> {
        self.banned_until.and_then(|until| {
            let now = Instant::now();
            if now < until {
                Some(until - now)
            } else {
                None
            }
        })
    }

    /// Apply reputation decay
    pub fn apply_decay(&mut self) {
        let now = Instant::now();
        let elapsed = now - self.last_update;

        // Apply decay for each interval that has passed
        let intervals = elapsed.as_secs() / DECAY_INTERVAL.as_secs();
        if intervals > 0 {
            // Use saturating conversion to prevent overflow
            // Cap at a reasonable maximum to avoid excessive decay
            let intervals_i32 = intervals.min(i32::MAX as u64) as i32;
            let decay = intervals_i32.saturating_mul(DECAY_AMOUNT);
            self.score = (self.score - decay).max(MIN_MISBEHAVIOR_SCORE);
            self.last_update = now;
        }

        // Check if ban has expired
        if self.is_banned() && self.ban_time_remaining().is_none() {
            self.banned_until = None;
        }
    }
}

/// Reputation change event
#[derive(Debug, Clone)]
pub struct ReputationEvent {
    pub peer: SocketAddr,
    pub change: i32,
    pub reason: String,
    pub timestamp: Instant,
}

/// Peer reputation manager
pub struct PeerReputationManager {
    /// Reputation data for each peer
    reputations: Arc<RwLock<HashMap<SocketAddr, PeerReputation>>>,

    /// Recent reputation events for monitoring
    recent_events: Arc<RwLock<Vec<ReputationEvent>>>,

    /// Maximum number of events to keep
    max_events: usize,
}

impl Default for PeerReputationManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerReputationManager {
    /// Create a new reputation manager
    pub fn new() -> Self {
        Self {
            reputations: Arc::new(RwLock::new(HashMap::new())),
            recent_events: Arc::new(RwLock::new(Vec::new())),
            max_events: 1000,
        }
    }

    /// Update peer reputation
    pub async fn update_reputation(
        &self,
        peer: SocketAddr,
        score_change: i32,
        reason: &str,
    ) -> bool {
        let mut reputations = self.reputations.write().await;
        let reputation = reputations.entry(peer).or_default();

        // Apply decay first
        reputation.apply_decay();

        // Update score
        let old_score = reputation.score;
        reputation.score =
            (reputation.score + score_change).clamp(MIN_MISBEHAVIOR_SCORE, MAX_MISBEHAVIOR_SCORE);

        // Track positive/negative actions
        if score_change > 0 {
            reputation.negative_actions += 1;
        } else if score_change < 0 {
            reputation.positive_actions += 1;
        }

        // Check if peer should be banned
        let should_ban = reputation.score >= MAX_MISBEHAVIOR_SCORE && !reputation.is_banned();
        if should_ban {
            reputation.banned_until = Some(Instant::now() + BAN_DURATION);
            reputation.ban_count += 1;
            log::warn!(
                "Peer {} banned for misbehavior (score: {}, ban #{}, reason: {})",
                peer,
                reputation.score,
                reputation.ban_count,
                reason
            );
        }

        // Log significant changes
        if score_change.abs() >= 10 || should_ban {
            log::info!(
                "Peer {} reputation changed: {} -> {} (change: {}, reason: {})",
                peer,
                old_score,
                reputation.score,
                score_change,
                reason
            );
        }

        // Record event
        let event = ReputationEvent {
            peer,
            change: score_change,
            reason: reason.to_string(),
            timestamp: Instant::now(),
        };

        drop(reputations); // Release lock before recording event
        self.record_event(event).await;

        should_ban
    }

    /// Record a reputation event
    async fn record_event(&self, event: ReputationEvent) {
        let mut events = self.recent_events.write().await;
        events.push(event);

        // Keep only recent events
        if events.len() > self.max_events {
            let drain_count = events.len() - self.max_events;
            events.drain(0..drain_count);
        }
    }

    /// Check if a peer is banned
    pub async fn is_banned(&self, peer: &SocketAddr) -> bool {
        let mut reputations = self.reputations.write().await;
        if let Some(reputation) = reputations.get_mut(peer) {
            reputation.apply_decay();
            reputation.is_banned()
        } else {
            false
        }
    }

    /// Get peer reputation score
    pub async fn get_score(&self, peer: &SocketAddr) -> i32 {
        let mut reputations = self.reputations.write().await;
        if let Some(reputation) = reputations.get_mut(peer) {
            reputation.apply_decay();
            reputation.score
        } else {
            0
        }
    }

    /// Temporarily ban a peer for a specified duration, regardless of score.
    /// This can be used for critical protocol violations (e.g., invalid ChainLocks).
    pub async fn temporary_ban_peer(&self, peer: SocketAddr, duration: Duration, reason: &str) {
        let mut reputations = self.reputations.write().await;
        let reputation = reputations.entry(peer).or_default();

        reputation.banned_until = Some(Instant::now() + duration);
        reputation.ban_count += 1;

        log::warn!(
            "Peer {} temporarily banned for {:?} (ban #{}, reason: {})",
            peer,
            duration,
            reputation.ban_count,
            reason
        );
    }

    /// Record a connection attempt
    pub async fn record_connection_attempt(&self, peer: SocketAddr) {
        let mut reputations = self.reputations.write().await;
        let reputation = reputations.entry(peer).or_default();
        reputation.connection_attempts += 1;
        reputation.last_connection = Some(Instant::now());
    }

    /// Record a successful connection
    pub async fn record_successful_connection(&self, peer: SocketAddr) {
        let mut reputations = self.reputations.write().await;
        let reputation = reputations.entry(peer).or_default();
        reputation.successful_connections += 1;
    }

    /// Get all peer reputations
    pub async fn get_all_reputations(&self) -> HashMap<SocketAddr, PeerReputation> {
        let mut reputations = self.reputations.write().await;

        // Apply decay to all peers
        for reputation in reputations.values_mut() {
            reputation.apply_decay();
        }

        reputations.clone()
    }

    /// Get recent reputation events
    pub async fn get_recent_events(&self) -> Vec<ReputationEvent> {
        self.recent_events.read().await.clone()
    }

    /// Clear banned status for a peer (admin function)
    pub async fn unban_peer(&self, peer: &SocketAddr) {
        let mut reputations = self.reputations.write().await;
        if let Some(reputation) = reputations.get_mut(peer) {
            reputation.banned_until = None;
            reputation.score = reputation.score.min(MAX_MISBEHAVIOR_SCORE - 10);
            log::info!("Manually unbanned peer {}", peer);
        }
    }

    /// Reset reputation for a peer
    pub async fn reset_reputation(&self, peer: &SocketAddr) {
        let mut reputations = self.reputations.write().await;
        reputations.remove(peer);
        log::info!("Reset reputation for peer {}", peer);
    }

    /// Get peers sorted by reputation (best first)
    pub async fn get_peers_by_reputation(&self) -> Vec<(SocketAddr, i32)> {
        let mut reputations = self.reputations.write().await;

        // Apply decay and collect scores
        let mut peer_scores: Vec<(SocketAddr, i32)> = reputations
            .iter_mut()
            .map(|(addr, rep)| {
                rep.apply_decay();
                (*addr, rep.score)
            })
            .filter(|(_, score)| *score < MAX_MISBEHAVIOR_SCORE) // Exclude banned peers
            .collect();

        // Sort by score (lower is better)
        peer_scores.sort_by_key(|(_, score)| *score);

        peer_scores
    }

    /// Save reputation data to persistent storage
    pub async fn save_to_storage(&self, storage: &impl PeerStorage) -> std::io::Result<()> {
        let reputations = self.reputations.read().await;

        storage.save_peers_reputation(&reputations).await.map_err(std::io::Error::other)
    }

    /// Load reputation data from persistent storage
    pub async fn load_from_storage(&self, storage: &impl PeerStorage) -> std::io::Result<()> {
        let data = storage.load_peers_reputation().await.map_err(std::io::Error::other)?;

        let mut reputations = self.reputations.write().await;
        let mut loaded_count = 0;
        let mut skipped_count = 0;

        for (addr, mut reputation) in data {
            // Validate successful connections don't exceed attempts
            reputation.successful_connections =
                reputation.successful_connections.min(reputation.connection_attempts);

            // Skip entry if data appears corrupted
            if reputation.positive_actions > MAX_ACTION_COUNT
                || reputation.negative_actions > MAX_ACTION_COUNT
            {
                log::warn!("Skipping peer {} with potentially corrupted action counts", addr);
                skipped_count += 1;
                continue;
            }

            // Apply initial decay based on ban count
            if reputation.ban_count > 0 {
                reputation.score = reputation.score.max(50); // Start with higher score for previously banned peers
            }

            reputations.insert(addr, reputation);
            loaded_count += 1;
        }

        log::info!(
            "Loaded reputation data for {} peers (skipped {} corrupted entries)",
            loaded_count,
            skipped_count
        );
        Ok(())
    }
}

/// Helper trait for reputation-aware peer selection
pub trait ReputationAware {
    /// Select best peers based on reputation
    fn select_best_peers(
        &self,
        available_peers: Vec<SocketAddr>,
        count: usize,
    ) -> impl std::future::Future<Output = Vec<SocketAddr>> + Send;

    /// Check if we should connect to a peer based on reputation
    fn should_connect_to_peer(
        &self,
        peer: &SocketAddr,
    ) -> impl std::future::Future<Output = bool> + Send;
}

impl ReputationAware for PeerReputationManager {
    async fn select_best_peers(
        &self,
        available_peers: Vec<SocketAddr>,
        count: usize,
    ) -> Vec<SocketAddr> {
        let mut peer_scores = Vec::new();
        let mut reputations = self.reputations.write().await;

        for peer in available_peers {
            let reputation = reputations.entry(peer).or_default();
            reputation.apply_decay();

            if !reputation.is_banned() {
                peer_scores.push((peer, reputation.score));
            }
        }

        // Sort by score (lower is better)
        peer_scores.sort_by_key(|(_, score)| *score);

        // Return the best peers
        peer_scores.into_iter().take(count).map(|(peer, _)| peer).collect()
    }

    async fn should_connect_to_peer(&self, peer: &SocketAddr) -> bool {
        !self.is_banned(peer).await
    }
}

// Include tests module
#[cfg(test)]
#[path = "reputation_tests.rs"]
mod reputation_tests;
