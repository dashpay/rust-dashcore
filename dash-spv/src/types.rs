//! Common type definitions for the Dash SPV client.

use std::time::{Duration, Instant, SystemTime};

use dashcore::{
    block::Header as BlockHeader, hash_types::FilterHeader, network::constants::NetworkExt,
    sml::masternode_list_engine::MasternodeListEngine, Amount, BlockHash, Network, Transaction,
    Txid,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Shared, mutex-protected set of filter heights used across components.
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
pub struct CachedHeader {
    /// The block header
    header: BlockHeader,
    /// Cached hash (computed lazily and stored in Arc for cheap clones)
    hash: Arc<std::sync::OnceLock<BlockHash>>,
}

impl CachedHeader {
    /// Create a new cached header from a block header
    pub fn new(header: BlockHeader) -> Self {
        Self {
            header,
            hash: Arc::new(std::sync::OnceLock::new()),
        }
    }

    /// Get the block header
    pub fn header(&self) -> &BlockHeader {
        &self.header
    }

    /// Get the cached block hash (computes once, returns cached value thereafter)
    pub fn block_hash(&self) -> BlockHash {
        *self.hash.get_or_init(|| self.header.block_hash())
    }

    /// Convert back to a plain BlockHeader
    pub fn into_inner(self) -> BlockHeader {
        self.header
    }
}

impl From<BlockHeader> for CachedHeader {
    fn from(header: BlockHeader) -> Self {
        Self::new(header)
    }
}

impl AsRef<BlockHeader> for CachedHeader {
    fn as_ref(&self) -> &BlockHeader {
        &self.header
    }
}

impl std::ops::Deref for CachedHeader {
    type Target = BlockHeader;

    fn deref(&self) -> &Self::Target {
        &self.header
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
#[derive(Clone, Default)]
pub struct ChainState {
    /// Block headers indexed by height.
    pub headers: Vec<BlockHeader>,

    /// Filter headers indexed by height.
    pub filter_headers: Vec<FilterHeader>,

    /// Last ChainLock height.
    pub last_chainlock_height: Option<u32>,

    /// Last ChainLock hash.
    pub last_chainlock_hash: Option<BlockHash>,

    /// Current filter tip.
    pub current_filter_tip: Option<FilterHeader>,

    /// Masternode list engine.
    pub masternode_engine: Option<MasternodeListEngine>,

    /// Last masternode diff height processed.
    pub last_masternode_diff_height: Option<u32>,

    /// Base height when syncing from a checkpoint (0 if syncing from genesis).
    pub sync_base_height: u32,

    /// Whether the chain was synced from a checkpoint rather than genesis.
    pub synced_from_checkpoint: bool,
}

impl ChainState {
    /// Create a new empty chain state
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new chain state for the given network.
    pub fn new_for_network(network: Network) -> Self {
        let mut state = Self::default();

        // Initialize with genesis block
        let genesis_header = match network {
            Network::Dash => {
                // Use known genesis for mainnet
                dashcore::blockdata::constants::genesis_block(network).header
            }
            Network::Testnet => {
                // Use known genesis for testnet
                dashcore::blockdata::constants::genesis_block(network).header
            }
            _ => {
                // For other networks, use the existing genesis block function
                dashcore::blockdata::constants::genesis_block(network).header
            }
        };

        // Add genesis header to the chain state
        state.headers.push(genesis_header);

        tracing::debug!("Initialized ChainState with genesis block - network: {:?}, hash: {}, headers_count: {}", 
            network, genesis_header.block_hash(), state.headers.len());

        // Initialize masternode engine for the network
        let mut engine = MasternodeListEngine::default_for_network(network);
        if let Some(genesis_hash) = network.known_genesis_block_hash() {
            engine.feed_block_height(0, genesis_hash);
        }
        state.masternode_engine = Some(engine);

        // Initialize checkpoint fields
        state.sync_base_height = 0;
        state.synced_from_checkpoint = false;

        state
    }

    /// Get the current tip height.
    pub fn tip_height(&self) -> u32 {
        if self.headers.is_empty() {
            // When headers is empty, sync_base_height represents our current position
            // This happens when we're syncing from a checkpoint but haven't received headers yet
            self.sync_base_height
        } else {
            // Normal case: base + number of headers - 1
            self.sync_base_height + self.headers.len() as u32 - 1
        }
    }

    /// Get the current tip hash.
    pub fn tip_hash(&self) -> Option<BlockHash> {
        self.headers.last().map(|h| h.block_hash())
    }

    /// Get header at the given height.
    pub fn header_at_height(&self, height: u32) -> Option<&BlockHeader> {
        if height < self.sync_base_height {
            return None; // Height is before our sync base
        }
        let index = (height - self.sync_base_height) as usize;
        self.headers.get(index)
    }

    /// Get filter header at the given height.
    pub fn filter_header_at_height(&self, height: u32) -> Option<&FilterHeader> {
        if height < self.sync_base_height {
            return None; // Height is before our sync base
        }
        let index = (height - self.sync_base_height) as usize;
        self.filter_headers.get(index)
    }

    /// Add headers to the chain.
    pub fn add_headers(&mut self, headers: Vec<BlockHeader>) {
        self.headers.extend(headers);
    }

    /// Add filter headers to the chain.
    pub fn add_filter_headers(&mut self, filter_headers: Vec<FilterHeader>) {
        if let Some(last) = filter_headers.last() {
            self.current_filter_tip = Some(*last);
        }
        self.filter_headers.extend(filter_headers);
    }

    /// Get the tip header
    pub fn get_tip_header(&self) -> Option<BlockHeader> {
        self.headers.last().copied()
    }

    /// Get the height
    pub fn get_height(&self) -> u32 {
        self.tip_height()
    }

    /// Add a single header
    pub fn add_header(&mut self, header: BlockHeader) {
        self.headers.push(header);
    }

    /// Remove the tip header (for reorgs)
    pub fn remove_tip(&mut self) -> Option<BlockHeader> {
        self.headers.pop()
    }

    /// Update chain lock status
    pub fn update_chain_lock(&mut self, height: u32, hash: BlockHash) {
        // Only update if this is a newer chain lock
        if self.last_chainlock_height.is_none_or(|h| height > h) {
            self.last_chainlock_height = Some(height);
            self.last_chainlock_hash = Some(hash);
        }
    }

    /// Check if a block at given height is chain-locked
    pub fn is_height_chain_locked(&self, height: u32) -> bool {
        self.last_chainlock_height.is_some_and(|locked_height| height <= locked_height)
    }

    /// Check if we have a chain lock
    pub fn has_chain_lock(&self) -> bool {
        self.last_chainlock_height.is_some()
    }

    /// Get the last chain-locked height
    pub fn get_last_chainlock_height(&self) -> Option<u32> {
        self.last_chainlock_height
    }

    /// Get filter matched heights (placeholder for now)
    /// In a real implementation, this would track heights where filters matched wallet transactions
    pub fn get_filter_matched_heights(&self) -> Option<Vec<u32>> {
        // For now, return an empty vector as we don't track this yet
        // This would typically be populated during filter sync when matches are found
        Some(Vec::new())
    }

    /// Calculate the total chain work up to the tip
    pub fn calculate_chain_work(&self) -> Option<crate::chain::chain_work::ChainWork> {
        use crate::chain::chain_work::ChainWork;

        // If we have no headers, return None
        if self.headers.is_empty() {
            return None;
        }

        // Start with zero work
        let mut total_work = ChainWork::zero();

        // Add work from each header
        for header in &self.headers {
            total_work = total_work.add_header(header);
        }

        Some(total_work)
    }

    /// Initialize chain state from a checkpoint.
    pub fn init_from_checkpoint(
        &mut self,
        checkpoint_height: u32,
        checkpoint_header: BlockHeader,
        network: Network,
    ) {
        // Clear any existing headers
        self.headers.clear();
        self.filter_headers.clear();

        // Set sync base height to checkpoint
        self.sync_base_height = checkpoint_height;
        self.synced_from_checkpoint = true;

        // Add the checkpoint header as our first header
        self.headers.push(checkpoint_header);

        tracing::info!(
            "Initialized ChainState from checkpoint - height: {}, hash: {}, network: {:?}",
            checkpoint_height,
            checkpoint_header.block_hash(),
            network
        );

        // Initialize masternode engine for the network, starting from checkpoint
        let mut engine = MasternodeListEngine::default_for_network(network);
        engine.feed_block_height(checkpoint_height, checkpoint_header.block_hash());
        self.masternode_engine = Some(engine);
    }

    /// Get the absolute height for a given index in our headers vector.
    pub fn index_to_height(&self, index: usize) -> u32 {
        self.sync_base_height + index as u32
    }

    /// Get the index in our headers vector for a given absolute height.
    pub fn height_to_index(&self, height: u32) -> Option<usize> {
        if height < self.sync_base_height {
            None
        } else {
            Some((height - self.sync_base_height) as usize)
        }
    }
}

impl std::fmt::Debug for ChainState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainState")
            .field("headers", &format!("{} headers", self.headers.len()))
            .field("filter_headers", &format!("{} filter headers", self.filter_headers.len()))
            .field("last_chainlock_height", &self.last_chainlock_height)
            .field("last_chainlock_hash", &self.last_chainlock_hash)
            .field("current_filter_tip", &self.current_filter_tip)
            .field("last_masternode_diff_height", &self.last_masternode_diff_height)
            .field("sync_base_height", &self.sync_base_height)
            .field("synced_from_checkpoint", &self.synced_from_checkpoint)
            .finish()
    }
}

/// Validation mode for the SPV client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationMode {
    /// Validate only basic structure and signatures.
    Basic,

    /// Validate proof of work and chain rules.
    Full,

    /// Skip most validation (useful for testing).
    None,
}

impl Default for ValidationMode {
    fn default() -> Self {
        Self::Full
    }
}

/// Peer information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Peer address.
    pub address: std::net::SocketAddr,

    /// Connection state.
    pub connected: bool,

    /// Last seen time.
    pub last_seen: SystemTime,

    /// Peer version.
    pub version: Option<u32>,

    /// Peer services.
    pub services: Option<u64>,

    /// User agent.
    pub user_agent: Option<String>,

    /// Best height reported by peer.
    pub best_height: Option<u32>,

    /// Whether this peer wants to receive DSQ (CoinJoin queue) messages.
    pub wants_dsq_messages: Option<bool>,

    /// Whether this peer has actually sent us Headers2 messages (not just supports it).
    pub has_sent_headers2: bool,
}

impl PeerInfo {
    /// Check if peer supports compact filters (BIP 157/158).
    pub fn supports_compact_filters(&self) -> bool {
        use dashcore::network::constants::ServiceFlags;

        self.services
            .map(|s| ServiceFlags::from(s).has(ServiceFlags::COMPACT_FILTERS))
            .unwrap_or(false)
    }

    /// Check if peer supports headers2 compression (DIP-0025).
    pub fn supports_headers2(&self) -> bool {
        use dashcore::network::constants::{ServiceFlags, NODE_HEADERS_COMPRESSED};

        self.services.map(|s| ServiceFlags::from(s).has(NODE_HEADERS_COMPRESSED)).unwrap_or(false)
    }
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
