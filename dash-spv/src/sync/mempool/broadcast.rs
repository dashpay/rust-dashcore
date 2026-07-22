//! Broadcast acceptance tracking for self-originated transactions.
//!
//! Implements the classic SPV acceptance heuristic: the transaction is sent to
//! a subset of connected peers while being withheld from the rest (the
//! "holdout" set). Peers never re-announce a transaction to the peer they
//! received it from, so an `inv` for our txid from a holdout peer proves the
//! transaction propagated through the network and entered mempools.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use dashcore::network::message_network::RejectReason;
use dashcore::Transaction;

/// How many peers to withhold a broadcast transaction from.
///
/// At least one peer must be withheld for acceptance detection via `inv` echo
/// to work; with a holdout of zero the outcome stays [`BroadcastResult::Uncertain`]
/// until an InstantSend lock or block confirmation arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BroadcastHoldout {
    /// Withhold from half of the connected peers (rounded down).
    #[default]
    Half,
    /// Withhold from a fixed number of peers, clamped so that the
    /// transaction is always sent to at least one peer.
    Count(usize),
}

impl BroadcastHoldout {
    /// Number of peers to withhold from, given `peer_count` connected peers.
    pub fn count_for(&self, peer_count: usize) -> usize {
        match self {
            BroadcastHoldout::Half => peer_count / 2,
            BroadcastHoldout::Count(k) => (*k).min(peer_count.saturating_sub(1)),
        }
    }
}

/// Configuration for broadcast acceptance tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BroadcastConfig {
    /// Peers to withhold the initial send from.
    pub holdout: BroadcastHoldout,
    /// Distinct non-recipient peers that must announce the txid back before
    /// the broadcast is considered accepted.
    pub acceptance_threshold: usize,
    /// How long a broadcast may stay pending before its outcome is reported
    /// as uncertain.
    pub acceptance_timeout: Duration,
}

impl Default for BroadcastConfig {
    fn default() -> Self {
        Self {
            holdout: BroadcastHoldout::default(),
            acceptance_threshold: 1,
            acceptance_timeout: Duration::from_secs(60),
        }
    }
}

/// Network-level outcome of a transaction broadcast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BroadcastResult {
    /// The transaction propagated through the network: peers we did not send
    /// it to announced it back (or it was InstantSend-locked / mined).
    Accepted {
        /// Number of distinct non-recipient peers that announced the txid.
        /// Zero when acceptance was proven by an InstantSend lock or a block
        /// confirmation before any echo arrived.
        relayed_by: usize,
    },
    /// A peer rejected the transaction via a p2p `reject` message.
    ///
    /// Best-effort signal: modern Dash Core versions may never send BIP61
    /// `reject` messages, in which case invalid transactions surface as
    /// `Uncertain` instead.
    Rejected {
        /// Protocol reject code.
        code: RejectReason,
        /// Human-readable reason string from the rejecting peer.
        reason: String,
    },
    /// No acceptance or rejection signal arrived within the configured
    /// timeout. The transaction may still confirm later; a late echo,
    /// InstantSend lock, or confirmation upgrades the outcome to `Accepted`.
    Uncertain,
}

impl std::fmt::Display for BroadcastResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BroadcastResult::Accepted {
                relayed_by,
            } => write!(f, "Accepted(relayed_by={})", relayed_by),
            BroadcastResult::Rejected {
                code,
                reason,
            } => write!(f, "Rejected(code={:?}, reason={})", code, reason),
            BroadcastResult::Uncertain => write!(f, "Uncertain"),
        }
    }
}

/// Internal lifecycle state of a tracked broadcast.
///
/// Valid transitions: `Pending -> Accepted | Rejected | Uncertain` and
/// `Uncertain -> Accepted`. Every transition emits exactly one
/// `SyncEvent::TransactionBroadcastResult`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BroadcastStatus {
    /// Broadcast sent, awaiting an acceptance or rejection signal.
    Pending,
    /// Accepted by the network (echo threshold, IS lock, or confirmation).
    Accepted,
    /// Rejected by a peer via a p2p `reject` message.
    Rejected,
    /// Timed out without a definitive signal.
    Uncertain,
}

/// Per-transaction broadcast tracking state.
///
/// The full transaction is stored so rebroadcast works even when the wallet
/// does not consider the transaction relevant (the `transactions` map only
/// holds wallet-relevant entries).
#[derive(Debug, Clone)]
pub(crate) struct TxBroadcastState {
    /// The broadcast transaction.
    pub transaction: Transaction,
    /// Peers the transaction was sent to directly. Announcements from these
    /// peers carry no acceptance information.
    pub sent_to: HashSet<SocketAddr>,
    /// Peers deliberately not sent the transaction; sticky across
    /// rebroadcasts so an echo remains possible.
    pub holdout: HashSet<SocketAddr>,
    /// Non-recipient peers that announced the txid back via `inv`.
    pub announced_by: HashSet<SocketAddr>,
    /// When the broadcast was first initiated (drives the acceptance timeout).
    pub created_at: Instant,
    /// When the transaction was last sent to the network (drives rebroadcast).
    pub last_broadcast: Instant,
    /// Current lifecycle status.
    pub status: BroadcastStatus,
}

impl TxBroadcastState {
    pub fn new(transaction: Transaction, now: Instant) -> Self {
        Self {
            transaction,
            sent_to: HashSet::new(),
            holdout: HashSet::new(),
            announced_by: HashSet::new(),
            created_at: now,
            last_broadcast: now,
            status: BroadcastStatus::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holdout_half_rounds_down() {
        let h = BroadcastHoldout::Half;
        assert_eq!(h.count_for(0), 0);
        assert_eq!(h.count_for(1), 0);
        assert_eq!(h.count_for(2), 1);
        assert_eq!(h.count_for(3), 1);
        assert_eq!(h.count_for(4), 2);
        assert_eq!(h.count_for(5), 2);
    }

    #[test]
    fn holdout_count_clamps_to_leave_one_recipient() {
        let h = BroadcastHoldout::Count(3);
        assert_eq!(h.count_for(0), 0);
        assert_eq!(h.count_for(1), 0);
        assert_eq!(h.count_for(2), 1);
        assert_eq!(h.count_for(4), 3);
        assert_eq!(h.count_for(10), 3);
    }
}
