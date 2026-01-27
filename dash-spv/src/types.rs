//! Common type definitions for the Dash SPV client.
//!
//! # Architecture Note
//! This file has grown to 1,065 lines and should be split into:
//! - types/chain.rs - ChainState, CachedHeader
//! - types/sync.rs - SyncProgress, SyncStage
//! - types/events.rs - SpvEvent, MempoolRemovalReason
//! - types/stats.rs - SpvStats, PeerInfo
//! - types/balances.rs - AddressBalance, UnconfirmedTransaction
//!
//! # Thread Safety
//! Many types here are wrapped in `Arc<RwLock>` or `Arc<Mutex>` when used.
//! Always acquire locks in consistent order to prevent deadlocks:
//! 1. state (ChainState)
//! 2. stats (SpvStats)
//! 3. mempool_state (MempoolState)

use std::time::{Duration, Instant, SystemTime};

use dashcore::{
    block::Header as BlockHeader,
    consensus::{Decodable, Encodable},
    Amount, BlockHash, Transaction, Txid,
};
use serde::{Deserialize, Serialize};

/// Shared, mutex-protected set of filter heights used across components.
///
/// # Why `Arc<Mutex<HashSet>>`?
/// - Arc: Shared ownership between FilterSyncManager and SpvStats
/// - Mutex: Interior mutability for concurrent updates from filter download tasks
/// - HashSet: Fast O(1) membership testing for gap detection
///
/// # Performance Note
/// Consider `Arc<RwLock>` if read contention becomes an issue (most operations are reads).
pub type SharedFilterHeights = std::sync::Arc<tokio::sync::Mutex<std::collections::HashSet<u32>>>;

/// A block header with its cached hash to avoid expensive X11 recomputation.
///
/// During header sync, each header's hash is computed multiple times:
/// - For existence checks in storage
/// - For validation logging
/// - For chain continuity validation
/// - For storage indexing
///
/// This wrapper caches the hash after first computation, providing ~4-6x reduction
/// in X11 hashing operations per header.
#[derive(Debug, Clone)]
pub struct HashedBlockHeader {
    /// The block header
    header: BlockHeader,
    hash: BlockHash,
}

impl HashedBlockHeader {
    pub fn header(&self) -> &BlockHeader {
        &self.header
    }

    pub fn hash(&self) -> &BlockHash {
        &self.hash
    }
}

impl From<BlockHeader> for HashedBlockHeader {
    fn from(header: BlockHeader) -> Self {
        Self {
            header,
            hash: header.block_hash(),
        }
    }
}

impl From<&BlockHeader> for HashedBlockHeader {
    fn from(header: &BlockHeader) -> Self {
        Self {
            header: *header,
            hash: header.block_hash(),
        }
    }
}

impl PartialEq for HashedBlockHeader {
    fn eq(&self, other: &Self) -> bool {
        self.header == other.header
    }
}

impl Encodable for HashedBlockHeader {
    #[inline]
    fn consensus_encode<W: std::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, std::io::Error> {
        Ok(self.header().consensus_encode(writer)? + self.hash().consensus_encode(writer)?)
    }
}

impl Decodable for HashedBlockHeader {
    #[inline]
    fn consensus_decode<R: std::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, dashcore::consensus::encode::Error> {
        Ok(Self {
            header: BlockHeader::consensus_decode(reader)?,
            hash: BlockHash::consensus_decode(reader)?,
        })
    }
}

/// Unique identifier for a peer connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId(pub u64);

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "peer_{}", self.0)
    }
}

/// Sync progress information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncProgress {
    /// Current height of synchronized headers.
    pub header_height: u32,

    /// Current height of synchronized filter headers.
    pub filter_header_height: u32,

    /// Current height of synchronized masternode list.
    pub masternode_height: u32,

    /// Total number of peers connected.
    pub peer_count: u32,

    /// Whether filter sync is available (peers support it).
    pub filter_sync_available: bool,

    /// Number of compact filters downloaded.
    pub filters_downloaded: u64,

    /// Last height where filters were synced/verified.
    pub last_synced_filter_height: Option<u32>,

    /// Sync start time.
    pub sync_start: SystemTime,

    /// Last update time.
    pub last_update: SystemTime,
}

impl Default for SyncProgress {
    fn default() -> Self {
        let now = SystemTime::now();
        Self {
            header_height: 0,
            filter_header_height: 0,
            masternode_height: 0,
            peer_count: 0,
            filter_sync_available: false,
            filters_downloaded: 0,
            last_synced_filter_height: None,
            sync_start: now,
            last_update: now,
        }
    }
}

/// Detailed sync progress with performance metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedSyncProgress {
    /// Snapshot of the core sync metrics for quick consumption.
    pub sync_progress: SyncProgress,
    pub peer_best_height: u32,
    pub percentage: f64,

    /// Performance metrics
    pub headers_per_second: f64,
    pub bytes_per_second: u64,
    pub estimated_time_remaining: Option<Duration>,

    /// Detailed status
    pub sync_stage: SyncStage,
    pub total_headers_processed: u64,
    pub total_bytes_downloaded: u64,

    /// Timing
    pub sync_start_time: SystemTime,
    pub last_update_time: SystemTime,
}

/// Sync stage for detailed progress tracking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncStage {
    Connecting,
    QueryingPeerHeight,
    DownloadingHeaders {
        start: u32,
        end: u32,
    },
    ValidatingHeaders {
        batch_size: usize,
    },
    StoringHeaders {
        batch_size: usize,
    },
    DownloadingFilterHeaders {
        current: u32,
        target: u32,
    },
    DownloadingFilters {
        completed: u32,
        total: u32,
    },
    DownloadingBlocks {
        pending: usize,
    },
    Complete,
    Failed(String),
}

impl DetailedSyncProgress {
    pub fn calculate_percentage(&self) -> f64 {
        if self.peer_best_height == 0 {
            return 0.0;
        }
        let current_height = self.sync_progress.header_height;
        ((current_height as f64 / self.peer_best_height as f64) * 100.0).min(100.0)
    }

    pub fn calculate_eta(&self) -> Option<Duration> {
        if self.headers_per_second <= 0.0 {
            return None;
        }

        let current_height = self.sync_progress.header_height;
        let remaining = self.peer_best_height.saturating_sub(current_height);
        if remaining == 0 {
            return Some(Duration::from_secs(0));
        }

        let seconds = remaining as f64 / self.headers_per_second;
        Some(Duration::from_secs_f64(seconds))
    }
}

/// Chain state maintained by the SPV client.
///
/// # CRITICAL: This is the heart of the SPV client's state
///
/// ## Thread Safety
/// Almost always wrapped in `Arc<RwLock<ChainState>>` for shared access.
/// Multiple readers can access simultaneously, but writes are exclusive.
///
/// ## Checkpoint Sync
/// When syncing from a checkpoint (not genesis), `sync_base_height` is non-zero.
#[derive(Clone, Default)]
pub struct ChainState {
    /// Last ChainLock height.
    pub last_chainlock_height: Option<u32>,

    /// Base height when syncing from a checkpoint (0 if syncing from genesis).
    pub sync_base_height: u32,
}

impl ChainState {
    /// Create a new empty chain state
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialize chain state from a checkpoint.
    pub fn init_from_checkpoint(&mut self, checkpoint_height: u32) {
        // Set sync base height to checkpoint
        self.sync_base_height = checkpoint_height;

        tracing::info!("Initialized ChainState from checkpoint - height: {}", checkpoint_height);
    }
}

impl std::fmt::Debug for ChainState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainState")
            .field("last_chainlock_height", &self.last_chainlock_height)
            .field("sync_base_height", &self.sync_base_height)
            .finish()
    }
}

/// Validation mode for the SPV client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ValidationMode {
    /// Validate only basic structure and signatures.
    Basic,

    /// Validate proof of work and chain rules.
    #[default]
    Full,

    /// Skip most validation (useful for testing).
    None,
}

/// Filter match result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterMatch {
    /// Block hash where match was found.
    pub block_hash: BlockHash,

    /// Block height.
    pub height: u32,

    /// Whether we requested the full block.
    pub block_requested: bool,
}

// WatchItem has been removed in favor of using key-wallet-manager's address tracking

/// Statistics about the SPV client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpvStats {
    /// Number of connected peers.
    pub connected_peers: u32,

    /// Total number of known peers.
    pub total_peers: u32,

    /// Current blockchain height.
    pub header_height: u32,

    /// Current filter height.
    pub filter_height: u32,

    /// Number of headers downloaded.
    pub headers_downloaded: u64,

    /// Number of filter headers downloaded.
    pub filter_headers_downloaded: u64,

    /// Number of filters downloaded.
    pub filters_downloaded: u64,

    /// Number of compact filters that matched watch items.
    pub filters_matched: u64,

    /// Number of blocks with relevant transactions (after full block processing).
    pub blocks_with_relevant_transactions: u64,

    /// Number of full blocks requested.
    pub blocks_requested: u64,

    /// Number of full blocks processed.
    pub blocks_processed: u64,

    /// Number of masternode diffs processed.
    pub masternode_diffs_processed: u64,

    /// Total bytes received.
    pub bytes_received: u64,

    /// Total bytes sent.
    pub bytes_sent: u64,

    /// Connection uptime.
    pub uptime: std::time::Duration,

    /// Number of filters requested during sync.
    pub filters_requested: u64,

    /// Number of filters received during sync.
    pub filters_received: u64,

    /// Filter sync start time.
    #[serde(skip)]
    pub filter_sync_start_time: Option<std::time::Instant>,

    /// Last time a filter was received.
    #[serde(skip)]
    pub last_filter_received_time: Option<std::time::Instant>,

    /// Received filter heights for gap tracking (shared with FilterSyncManager).
    #[serde(skip)]
    pub received_filter_heights: SharedFilterHeights,

    /// Number of filter requests currently active.
    pub active_filter_requests: u32,

    /// Number of filter requests currently queued.
    pub pending_filter_requests: u32,

    /// Number of filter request timeouts.
    pub filter_request_timeouts: u64,

    /// Number of filter requests retried.
    pub filter_requests_retried: u64,
}

impl Default for SpvStats {
    fn default() -> Self {
        Self {
            connected_peers: 0,
            total_peers: 0,
            header_height: 0,
            filter_height: 0,
            headers_downloaded: 0,
            filter_headers_downloaded: 0,
            filters_downloaded: 0,
            filters_matched: 0,
            blocks_with_relevant_transactions: 0,
            blocks_requested: 0,
            blocks_processed: 0,
            masternode_diffs_processed: 0,
            bytes_received: 0,
            bytes_sent: 0,
            uptime: std::time::Duration::default(),
            filters_requested: 0,
            filters_received: 0,
            filter_sync_start_time: None,
            last_filter_received_time: None,
            received_filter_heights: std::sync::Arc::new(tokio::sync::Mutex::new(
                std::collections::HashSet::new(),
            )),
            active_filter_requests: 0,
            pending_filter_requests: 0,
            filter_request_timeouts: 0,
            filter_requests_retried: 0,
        }
    }
}

/// Balance information for an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressBalance {
    /// Confirmed balance (6+ confirmations or InstantLocked).
    pub confirmed: dashcore::Amount,

    /// Unconfirmed balance (less than 6 confirmations).
    pub unconfirmed: dashcore::Amount,

    /// Pending balance from mempool transactions (not InstantLocked).
    pub pending: dashcore::Amount,

    /// Pending balance from InstantLocked mempool transactions.
    pub pending_instant: dashcore::Amount,
}

impl AddressBalance {
    /// Get the total balance (confirmed + unconfirmed + pending).
    pub fn total(&self) -> dashcore::Amount {
        self.confirmed + self.unconfirmed + self.pending + self.pending_instant
    }

    /// Get the available balance (confirmed + pending_instant).
    pub fn available(&self) -> dashcore::Amount {
        self.confirmed + self.pending_instant
    }
}

/// Mempool balance information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MempoolBalance {
    /// Pending balance from mempool transactions (not InstantLocked).
    pub pending: dashcore::Amount,

    /// Pending balance from InstantLocked mempool transactions.
    pub pending_instant: dashcore::Amount,
}

// Custom serialization for AddressBalance to handle Amount serialization
impl Serialize for AddressBalance {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("AddressBalance", 4)?;
        state.serialize_field("confirmed", &self.confirmed.to_sat())?;
        state.serialize_field("unconfirmed", &self.unconfirmed.to_sat())?;
        state.serialize_field("pending", &self.pending.to_sat())?;
        state.serialize_field("pending_instant", &self.pending_instant.to_sat())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for AddressBalance {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{MapAccess, Visitor};
        use std::fmt;

        struct AddressBalanceVisitor;

        impl<'de> Visitor<'de> for AddressBalanceVisitor {
            type Value = AddressBalance;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an AddressBalance struct")
            }

            fn visit_map<M>(self, mut map: M) -> Result<AddressBalance, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut confirmed: Option<u64> = None;
                let mut unconfirmed: Option<u64> = None;
                let mut pending: Option<u64> = None;
                let mut pending_instant: Option<u64> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "confirmed" => {
                            if confirmed.is_some() {
                                return Err(serde::de::Error::duplicate_field("confirmed"));
                            }
                            confirmed = Some(map.next_value()?);
                        }
                        "unconfirmed" => {
                            if unconfirmed.is_some() {
                                return Err(serde::de::Error::duplicate_field("unconfirmed"));
                            }
                            unconfirmed = Some(map.next_value()?);
                        }
                        "pending" => {
                            if pending.is_some() {
                                return Err(serde::de::Error::duplicate_field("pending"));
                            }
                            pending = Some(map.next_value()?);
                        }
                        "pending_instant" => {
                            if pending_instant.is_some() {
                                return Err(serde::de::Error::duplicate_field("pending_instant"));
                            }
                            pending_instant = Some(map.next_value()?);
                        }
                        _ => {
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }

                let confirmed =
                    confirmed.ok_or_else(|| serde::de::Error::missing_field("confirmed"))?;
                let unconfirmed =
                    unconfirmed.ok_or_else(|| serde::de::Error::missing_field("unconfirmed"))?;
                // Default to 0 for backwards compatibility
                let pending = pending.unwrap_or(0);
                let pending_instant = pending_instant.unwrap_or(0);

                Ok(AddressBalance {
                    confirmed: dashcore::Amount::from_sat(confirmed),
                    unconfirmed: dashcore::Amount::from_sat(unconfirmed),
                    pending: dashcore::Amount::from_sat(pending),
                    pending_instant: dashcore::Amount::from_sat(pending_instant),
                })
            }
        }

        deserializer.deserialize_struct(
            "AddressBalance",
            &["confirmed", "unconfirmed", "pending", "pending_instant"],
            AddressBalanceVisitor,
        )
    }
}

/// Events emitted by the SPV client.
#[derive(Debug, Clone)]
pub enum SpvEvent {
    /// Balance has been updated.
    BalanceUpdate {
        /// Confirmed balance in satoshis.
        confirmed: u64,
        /// Unconfirmed balance in satoshis.
        unconfirmed: u64,
        /// Total balance in satoshis.
        total: u64,
    },

    /// New transaction detected.
    TransactionDetected {
        /// Transaction ID.
        txid: String,
        /// Whether the transaction is confirmed.
        confirmed: bool,
        /// Block height if confirmed.
        block_height: Option<u32>,
        /// Net amount change (positive for received, negative for sent).
        amount: i64,
        /// Addresses affected by this transaction.
        addresses: Vec<String>,
    },

    /// Block processed.
    BlockProcessed {
        /// Block height.
        height: u32,
        /// Block hash.
        hash: String,
        /// Total number of transactions in the block.
        transactions_count: usize,
        /// Number of relevant transactions.
        relevant_transactions: usize,
    },

    /// Sync progress update.
    SyncProgress {
        /// Current block height.
        current_height: u32,
        /// Target block height.
        target_height: u32,
        /// Progress percentage.
        percentage: f64,
    },

    /// ChainLock received and validated.
    ChainLockReceived {
        /// Block height of the ChainLock.
        height: u32,
        /// Block hash of the ChainLock.
        hash: dashcore::BlockHash,
    },

    /// InstantLock received and validated.
    InstantLockReceived {
        /// Transaction ID locked by this InstantLock.
        txid: Txid,
        /// Transaction inputs locked by this InstantLock.
        inputs: Vec<dashcore::OutPoint>,
    },

    /// Unconfirmed transaction added to mempool.
    MempoolTransactionAdded {
        /// Transaction ID.
        txid: Txid,
        /// Raw transaction data.
        transaction: Box<Transaction>,
        /// Net amount change (positive for received, negative for sent).
        amount: i64,
        /// Addresses affected by this transaction.
        addresses: Vec<String>,
        /// Whether this is an InstantSend transaction.
        is_instant_send: bool,
    },

    /// Transaction confirmed (moved from mempool to block).
    MempoolTransactionConfirmed {
        /// Transaction ID.
        txid: Txid,
        /// Block height where confirmed.
        block_height: u32,
        /// Block hash where confirmed.
        block_hash: BlockHash,
    },

    /// Transaction removed from mempool (expired, replaced, or double-spent).
    MempoolTransactionRemoved {
        /// Transaction ID.
        txid: Txid,
        /// Reason for removal.
        reason: MempoolRemovalReason,
    },

    /// Compact filter matched for a block.
    CompactFilterMatched {
        /// Block hash that matched.
        hash: String,
    },
}

/// Reason for removing a transaction from mempool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MempoolRemovalReason {
    /// Transaction expired (exceeded timeout).
    Expired,
    /// Transaction was replaced by another transaction.
    Replaced {
        by_txid: Txid,
    },
    /// Transaction was double-spent.
    DoubleSpent {
        conflicting_txid: Txid,
    },
    /// Transaction was included in a block.
    Confirmed,
    /// Manual removal (e.g., user action).
    Manual,
}

/// Unconfirmed transaction in mempool.
#[derive(Debug, Clone)]
pub struct UnconfirmedTransaction {
    /// The transaction itself.
    pub transaction: Transaction,
    /// Time when first seen.
    pub first_seen: Instant,
    /// Fee paid by the transaction.
    pub fee: Amount,
    /// Size of transaction in bytes.
    pub size: usize,
    /// Whether this is an InstantSend transaction.
    pub is_instant_send: bool,
    /// Whether this transaction was sent by our wallet.
    pub is_outgoing: bool,
    /// Addresses involved (for quick filtering).
    pub addresses: Vec<dashcore::Address>,
    /// Net amount change for our wallet.
    pub net_amount: i64,
}

impl UnconfirmedTransaction {
    /// Create a new unconfirmed transaction.
    pub fn new(
        transaction: Transaction,
        fee: Amount,
        is_instant_send: bool,
        is_outgoing: bool,
        addresses: Vec<dashcore::Address>,
        net_amount: i64,
    ) -> Self {
        let size = dashcore::consensus::encode::serialize(&transaction).len();

        Self {
            transaction,
            first_seen: Instant::now(),
            fee,
            size,
            is_instant_send,
            is_outgoing,
            addresses,
            net_amount,
        }
    }

    /// Get the transaction ID.
    pub fn txid(&self) -> Txid {
        self.transaction.txid()
    }

    /// Check if transaction has expired.
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.first_seen.elapsed() > timeout
    }

    /// Get fee rate in satoshis per byte.
    pub fn fee_rate(&self) -> f64 {
        if self.size == 0 {
            return 0.0;
        }
        self.fee.to_sat() as f64 / self.size as f64
    }
}

/// Mempool state tracking.
#[derive(Debug, Clone, Default)]
pub struct MempoolState {
    /// Currently tracked unconfirmed transactions.
    pub transactions: std::collections::HashMap<Txid, UnconfirmedTransaction>,
    /// Recent sends (txid -> timestamp) for Selective strategy.
    pub recent_sends: std::collections::HashMap<Txid, Instant>,
    /// Total pending balance change.
    pub pending_balance: i64,
    /// Total pending InstantSend balance.
    pub pending_instant_balance: i64,
}

impl MempoolState {
    /// Add a transaction to mempool.
    pub fn add_transaction(&mut self, tx: UnconfirmedTransaction) {
        if tx.is_instant_send {
            self.pending_instant_balance += tx.net_amount;
        } else {
            self.pending_balance += tx.net_amount;
        }

        let txid = tx.txid();
        self.transactions.insert(txid, tx);
    }

    /// Remove a transaction from mempool.
    pub fn remove_transaction(&mut self, txid: &Txid) -> Option<UnconfirmedTransaction> {
        if let Some(tx) = self.transactions.remove(txid) {
            if tx.is_instant_send {
                self.pending_instant_balance -= tx.net_amount;
            } else {
                self.pending_balance -= tx.net_amount;
            }
            Some(tx)
        } else {
            None
        }
    }

    /// Prune expired transactions.
    pub fn prune_expired(&mut self, timeout: Duration) -> Vec<Txid> {
        let mut expired = Vec::new();

        self.transactions.retain(|txid, tx| {
            if tx.is_expired(timeout) {
                expired.push(*txid);
                if tx.is_instant_send {
                    self.pending_instant_balance -= tx.net_amount;
                } else {
                    self.pending_balance -= tx.net_amount;
                }
                false
            } else {
                true
            }
        });

        // Also prune old recent sends
        let cutoff = Instant::now() - timeout;
        self.recent_sends.retain(|_, &mut timestamp| timestamp > cutoff);

        expired
    }

    /// Record a recent send.
    pub fn record_send(&mut self, txid: Txid) {
        self.recent_sends.insert(txid, Instant::now());
    }

    /// Check if a transaction was recently sent.
    pub fn is_recent_send(&self, txid: &Txid, window: Duration) -> bool {
        self.recent_sends.get(txid).map(|&timestamp| timestamp.elapsed() < window).unwrap_or(false)
    }

    /// Get total pending balance (regular + InstantSend).
    pub fn total_pending_balance(&self) -> i64 {
        self.pending_balance + self.pending_instant_balance
    }
}
