//! Peer reputation management system
//!
//! This module implements a reputation system to track peer behavior and protect
//! against malicious peers. It tracks both positive and negative behaviors,
//! implements automatic banning for excessive misbehavior, and provides reputation
//! decay over time for recovery.

use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::storage::{PeerStorage, PersistentPeerStorage};

pub enum ReputationChangeReason {
    // Negative Changes
    InvalidMessage,
    InvalidHeader,
    Timeout,
    InvalidTransaction,
    InvalidChainLock,
    InvalidInstantLock,

    // Positive changes
    LongUptime,

    // Other
    Other(i32, String),
}

impl ReputationChangeReason {
    pub fn score(&self) -> i32 {
        // This score represents the missbehaviour score change, that means
        // the higher the score, the more severe the violation.
        match self {
            ReputationChangeReason::InvalidMessage => 10,
            ReputationChangeReason::InvalidHeader => 50,
            ReputationChangeReason::Timeout => 5,
            ReputationChangeReason::InvalidTransaction => 20,
            ReputationChangeReason::InvalidChainLock => 40,
            ReputationChangeReason::InvalidInstantLock => 35,
            ReputationChangeReason::LongUptime => -5,
            ReputationChangeReason::Other(score, _) => *score,
        }
    }
}

impl std::fmt::Display for ReputationChangeReason {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ReputationChangeReason::InvalidMessage => {
                write!(f, "Invalid message format or protocol violation")
            }
            ReputationChangeReason::InvalidHeader => write!(f, "Invalid block header"),
            ReputationChangeReason::Timeout => write!(f, "Timeout or slow response"),
            ReputationChangeReason::InvalidTransaction => write!(f, "Invalid transaction"),
            ReputationChangeReason::InvalidChainLock => write!(f, "Invalid ChainLock"),
            ReputationChangeReason::InvalidInstantLock => write!(f, "Invalid InstantLock"),
            ReputationChangeReason::LongUptime => write!(f, "Long uptime"),
            ReputationChangeReason::Other(_, reason) => write!(f, "{}", reason),
        }
    }
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
    score: i32,

    /// Number of times this peer has been banned
    #[serde(deserialize_with = "clamp_peer_ban_count")]
    ban_count: u32,

    /// Time when the peer was banned (if currently banned)
    #[serde(skip)]
    banned_until: Option<Instant>,

    /// Last time the reputation was updated
    #[serde(skip, default = "default_instant")]
    last_update: Instant,

    /// Connection count
    #[serde(deserialize_with = "clamp_peer_connection_attempts")]
    connection_attempts: u64,

    /// Successful connection count
    successful_connections: u64,

    /// Last connection time
    #[serde(skip)]
    last_connection: Option<Instant>,
}

impl Default for PeerReputation {
    fn default() -> Self {
        Self {
            score: 0,
            ban_count: 0,
            banned_until: None,
            last_update: default_instant(),
            connection_attempts: 0,
            successful_connections: 0,
            last_connection: None,
        }
    }
}

impl PeerReputation {
    fn is_banned(&self) -> bool {
        self.banned_until.is_some_and(|until| Instant::now() < until)
    }

    fn ban_time_remaining(&self) -> Option<Duration> {
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
    fn apply_decay(&mut self) {
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

#[derive(Default)]
pub struct PeerReputationManager {
    reputations: HashMap<SocketAddr, PeerReputation>,
}

impl PeerReputationManager {
    /// Update peer reputation
    pub async fn update_reputation(
        &mut self,
        peer: SocketAddr,
        reason: ReputationChangeReason,
    ) -> bool {
        let reputation = self.reputations.entry(peer).or_default();

        // Apply decay first
        reputation.apply_decay();

        // Update score
        let old_score = reputation.score;
        reputation.score =
            (reputation.score + reason.score()).clamp(MIN_MISBEHAVIOR_SCORE, MAX_MISBEHAVIOR_SCORE);

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
        if reason.score().abs() >= 10 || should_ban {
            log::info!(
                "Peer {} reputation changed: {} -> {} (change: {}, reason: {})",
                peer,
                old_score,
                reputation.score,
                reason.score(),
                reason
            );
        }

        should_ban
    }

    /// Check if a peer is banned
    pub async fn is_banned(&mut self, peer: &SocketAddr) -> bool {
        let reputations = &mut self.reputations;
        if let Some(reputation) = reputations.get_mut(peer) {
            reputation.apply_decay();
            reputation.is_banned()
        } else {
            false
        }
    }

    /// Temporarily ban a peer for a specified duration, regardless of score.
    /// This can be used for critical protocol violations (e.g., invalid ChainLocks).
    pub async fn temporary_ban_peer(&mut self, peer: SocketAddr, duration: Duration) {
        let reputations = &mut self.reputations;
        let reputation = reputations.entry(peer).or_default();

        reputation.banned_until = Some(Instant::now() + duration);
        reputation.ban_count += 1;

        log::warn!(
            "Peer {} temporarily banned for {:?} (ban #{})",
            peer,
            duration,
            reputation.ban_count,
        );
    }

    /// Record a connection attempt
    pub async fn record_connection_attempt(&mut self, peer: SocketAddr) {
        let reputations = &mut self.reputations;
        let reputation = reputations.entry(peer).or_default();
        reputation.connection_attempts += 1;
        reputation.last_connection = Some(Instant::now());
    }

    /// Record a successful connection
    pub async fn record_successful_connection(&mut self, peer: SocketAddr) {
        let reputations = &mut self.reputations;
        let reputation = reputations.entry(peer).or_default();
        reputation.successful_connections += 1;
    }

    /// Clear banned status for a peer (admin function)
    pub async fn unban_peer(&mut self, peer: &SocketAddr) {
        let reputations = &mut self.reputations;
        if let Some(reputation) = reputations.get_mut(peer) {
            reputation.banned_until = None;
            reputation.score = reputation.score.min(MAX_MISBEHAVIOR_SCORE - 10);
            log::info!("Manually unbanned peer {}", peer);
        }
    }

    pub async fn select_best_peers(
        &mut self,
        available_peers: Vec<SocketAddr>,
        count: usize,
    ) -> Vec<SocketAddr> {
        let mut peer_scores = Vec::new();
        let reputations = &mut self.reputations;

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

    pub async fn should_connect_to_peer(&mut self, peer: &SocketAddr) -> bool {
        !self.is_banned(peer).await
    }

    /// Save reputation data to persistent storage
    pub async fn save_to_storage(
        &mut self,
        storage: &PersistentPeerStorage,
    ) -> std::io::Result<()> {
        storage.save_peers_reputation(&self.reputations).await.map_err(std::io::Error::other)
    }

    /// Load reputation data from persistent storage
    pub async fn load_from_storage(
        &mut self,
        storage: &PersistentPeerStorage,
    ) -> std::io::Result<()> {
        let data = storage.load_peers_reputation().await.map_err(std::io::Error::other)?;
        log::info!("Loaded reputation data for {} peers", data.len());

        let reputations = &mut self.reputations;

        for (addr, mut reputation) in data {
            // Validate successful connections don't exceed attempts
            reputation.successful_connections =
                reputation.successful_connections.min(reputation.connection_attempts);

            // Apply initial decay based on ban count
            if reputation.ban_count > 0 {
                reputation.score = reputation.score.max(50); // Start with higher score for previously banned peers
            }

            reputations.insert(addr, reputation);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::storage::PersistentStorage;

    use super::*;
    use std::net::SocketAddr;

    #[tokio::test]
    async fn test_basic_reputation_operations() {
        let mut manager = PeerReputationManager::default();
        let peer: SocketAddr = "127.0.0.1:8333".parse().unwrap();

        // Initial score should be 0
        assert_eq!(manager.select_best_peers(vec![peer], 1).await[0], peer);
        assert_eq!(manager.reputations.get(&peer).expect("Peer not found").score, 0);

        // Test misbehavior
        manager.update_reputation(peer, ReputationChangeReason::InvalidMessage).await;
        assert_eq!(manager.reputations.get(&peer).expect("Peer not found").score, 10);
    }

    #[tokio::test]
    async fn test_banning_mechanism() {
        let mut manager = PeerReputationManager::default();
        let peer: SocketAddr = "192.168.1.1:8333".parse().unwrap();

        // Accumulate misbehavior
        for i in 0..10 {
            let banned =
                manager.update_reputation(peer, ReputationChangeReason::InvalidMessage).await;

            // Should be banned on the 10th violation (total score = 100)
            if i == 9 {
                assert!(banned);
            } else {
                assert!(!banned);
            }
        }

        assert!(manager.is_banned(&peer).await);
    }

    #[tokio::test]
    async fn test_reputation_persistence() {
        let mut manager = PeerReputationManager::default();
        let peer1: SocketAddr = "10.0.0.1:8333".parse().unwrap();
        let peer2: SocketAddr = "10.0.0.2:8333".parse().unwrap();

        // Set reputations
        manager
            .update_reputation(peer1, ReputationChangeReason::Other(-10, "Good peer".to_string()))
            .await;
        manager
            .update_reputation(peer2, ReputationChangeReason::Other(50, "Bad peer".to_string()))
            .await;

        // Save and load
        let temp_dir = tempfile::TempDir::new().unwrap();
        let peer_storage = PersistentPeerStorage::open(temp_dir.path())
            .await
            .expect("Failed to open PersistentPeerStorage");
        manager.save_to_storage(&peer_storage).await.unwrap();

        let mut new_manager = PeerReputationManager::default();
        new_manager.load_from_storage(&peer_storage).await.unwrap();

        // Verify scores were preserved
        assert_eq!(new_manager.reputations.get(&peer1).expect("Peer not found").score, -10);
        assert_eq!(new_manager.reputations.get(&peer2).expect("Peer not found").score, 50);
    }

    #[tokio::test]
    async fn test_peer_selection() {
        let mut manager = PeerReputationManager::default();

        let good_peer: SocketAddr = "1.1.1.1:8333".parse().unwrap();
        let neutral_peer: SocketAddr = "2.2.2.2:8333".parse().unwrap();
        let bad_peer: SocketAddr = "3.3.3.3:8333".parse().unwrap();

        // Set different reputations
        manager
            .update_reputation(
                good_peer,
                ReputationChangeReason::Other(-20, "Very good".to_string()),
            )
            .await;
        manager
            .update_reputation(bad_peer, ReputationChangeReason::Other(80, "Very bad".to_string()))
            .await;
        // neutral_peer has default score of 0

        let all_peers = vec![good_peer, neutral_peer, bad_peer];
        let selected = manager.select_best_peers(all_peers, 2).await;

        // Should select good_peer first, then neutral_peer
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0], good_peer);
        assert_eq!(selected[1], neutral_peer);
    }
}
