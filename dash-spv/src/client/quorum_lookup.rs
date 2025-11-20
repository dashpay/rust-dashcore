//! Thread-safe quorum and masternode lookup component.
//!
//! This module provides a shareable interface for querying masternode lists and quorums
//! without requiring exclusive access to the DashSpvClient. This solves the architectural
//! challenge where the sync_manager (which owns the masternode engine) is not shareable,
//! but applications need to perform quorum lookups from multiple threads.
//!
//! ## Design Philosophy
//!
//! The `QuorumLookup` component provides read-only access to masternode and quorum data
//! through a thread-safe `Arc`-wrapped interface. This allows:
//!
//! 1. **Shared Access**: Multiple parts of an application can clone `Arc<QuorumLookup>`
//!    and perform concurrent queries without blocking each other.
//!
//! 2. **Separation of Concerns**: Query operations are separated from sync operations,
//!    maintaining the single-owner pattern for the sync manager.
//!
//! 3. **Non-blocking Reads**: Uses `RwLock` internally to allow multiple concurrent readers
//!    while ensuring consistency during masternode list updates.
//!
//! ## Usage Example
//!
//! ```rust,no_run
//! # use dash_spv::client::DashSpvClient;
//! # use std::sync::Arc;
//! # async fn example(client: &DashSpvClient<
//! #     key_wallet_manager::wallet_manager::WalletManager<key_wallet::wallet::managed_wallet_info::ManagedWalletInfo>,
//! #     dash_spv::network::manager::PeerNetworkManager,
//! #     dash_spv::storage::DiskStorageManager
//! # >) {
//! // Get the shared quorum lookup component
//! let quorum_lookup = client.quorum_lookup();
//!
//! // Clone it for use in another thread/task
//! let lookup_clone = quorum_lookup.clone();
//!
//! // Perform queries
//! if let Some(quorum) = quorum_lookup.get_quorum_at_height(
//!     100000,
//!     1, // LLMQ_TYPE_50_60
//!     &[0u8; 32]
//! ).await {
//!     println!("Found quorum with {} members", quorum.quorum_entry.quorum_public_key.len());
//! }
//! # }
//! ```

use dashcore::sml::llmq_type::LLMQType;
use dashcore::sml::masternode_list::MasternodeList;
use dashcore::sml::masternode_list_engine::MasternodeListEngine;
use dashcore::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use dashcore::QuorumHash;
use dashcore_hashes::Hash;
use std::sync::{Arc, RwLock};
use tracing::{debug, warn};

/// Thread-safe component for querying masternode lists and quorums.
///
/// This struct wraps the masternode list engine in a thread-safe manner,
/// allowing multiple threads to perform read-only queries concurrently.
///
/// ## Thread Safety
///
/// Uses `Arc<RwLock<Option<Arc<MasternodeListEngine>>>>` to provide:
/// - **Multiple concurrent readers**: Many threads can query simultaneously
/// - **Exclusive writer**: Only the sync manager updates the engine
/// - **Interior mutability**: The outer `Arc` allows cheap cloning for sharing
///
/// ## Performance Considerations
///
/// - Cloning `QuorumLookup` is cheap (just clones the `Arc`)
/// - Read queries acquire a read lock (non-blocking for other readers)
/// - The engine itself is wrapped in an inner `Arc` to avoid deep copying
pub struct QuorumLookup {
    /// The masternode list engine, wrapped for thread-safe access.
    ///
    /// - Outer `Arc`: Allows cheap cloning of QuorumLookup
    /// - `RwLock`: Provides concurrent read access, exclusive write access
    /// - Inner `Option<Arc<...>>`: Engine may not be available before masternode sync
    engine: Arc<RwLock<Option<Arc<MasternodeListEngine>>>>,
}

impl QuorumLookup {
    /// Create a new QuorumLookup with no engine (before masternode sync).
    pub fn new() -> Self {
        Self {
            engine: Arc::new(RwLock::new(None)),
        }
    }

    /// Create a QuorumLookup with an existing engine.
    pub fn with_engine(engine: Arc<MasternodeListEngine>) -> Self {
        Self {
            engine: Arc::new(RwLock::new(Some(engine))),
        }
    }

    /// Update the masternode list engine.
    ///
    /// This method is called by the sync manager when masternode data becomes available.
    /// It uses a write lock to ensure exclusive access during updates.
    ///
    /// ## Panics
    ///
    /// Panics if the RwLock is poisoned (which should never happen in normal operation).
    pub fn set_engine(&self, engine: Arc<MasternodeListEngine>) {
        let mut guard = self.engine.write().expect("QuorumLookup RwLock should not be poisoned");
        *guard = Some(engine);
        debug!("Masternode engine updated in QuorumLookup");
    }

    /// Get a reference to the masternode list engine if available.
    ///
    /// Returns `None` if masternode sync hasn't completed yet.
    ///
    /// ## Panics
    ///
    /// Panics if the RwLock is poisoned.
    pub fn engine(&self) -> Option<Arc<MasternodeListEngine>> {
        let guard = self.engine.read().expect("QuorumLookup RwLock should not be poisoned");
        guard.clone()
    }

    /// Get the masternode list at a specific block height.
    ///
    /// Returns `None` if:
    /// - Masternode sync is not yet complete
    /// - The masternode list for that height is not available
    ///
    /// ## Example
    ///
    /// ```rust,no_run
    /// # use dash_spv::client::QuorumLookup;
    /// # async fn example(lookup: &QuorumLookup) {
    /// if let Some(ml) = lookup.get_masternode_list_at_height(100000).await {
    ///     println!("Masternode list has {} masternodes", ml.masternodes.len());
    /// }
    /// # }
    /// ```
    pub async fn get_masternode_list_at_height(&self, height: u32) -> Option<MasternodeList> {
        let engine = self.engine()?;

        // Clone the masternode list to avoid holding the lock
        engine.masternode_lists.get(&height).cloned()
    }

    /// Get a quorum entry by type and hash at a specific block height.
    ///
    /// This is the core method for quorum lookups, used by applications to retrieve
    /// quorum public keys and other quorum information needed for validation.
    ///
    /// ## Parameters
    ///
    /// - `height`: Block height at which to query the masternode list
    /// - `quorum_type`: LLMQ type (e.g., 1 for LLMQ_TYPE_50_60, 4 for LLMQ_TYPE_400_60)
    /// - `quorum_hash`: 32-byte hash identifying the specific quorum
    ///
    /// ## Returns
    ///
    /// - `Some(quorum)`: If the quorum is found
    /// - `None`: If masternode sync incomplete, no list at height, or quorum not found
    ///
    /// ## Example
    ///
    /// ```rust,no_run
    /// # use dash_spv::client::QuorumLookup;
    /// # async fn example(lookup: &QuorumLookup) {
    /// let quorum_hash = [0u8; 32]; // Your quorum hash here
    /// if let Some(quorum) = lookup.get_quorum_at_height(
    ///     100000,
    ///     1, // LLMQ_TYPE_50_60
    ///     &quorum_hash
    /// ).await {
    ///     println!("Found quorum with public key: {:?}", quorum.quorum_entry.quorum_public_key);
    /// } else {
    ///     println!("Quorum not found");
    /// }
    /// # }
    /// ```
    pub async fn get_quorum_at_height(
        &self,
        height: u32,
        quorum_type: u8,
        quorum_hash: &[u8; 32],
    ) -> Option<QualifiedQuorumEntry> {
        // Convert quorum type to LLMQType
        let llmq_type: LLMQType = LLMQType::from(quorum_type);
        if llmq_type == LLMQType::LlmqtypeUnknown {
            warn!("Invalid quorum type {} requested at height {}", quorum_type, height);
            return None;
        }

        // Convert hash
        let qhash = QuorumHash::from_byte_array(*quorum_hash);

        // Get the masternode list at this height
        let ml = self.get_masternode_list_at_height(height).await?;

        // Look for the quorum in the masternode list
        match ml.quorums.get(&llmq_type) {
            Some(quorums) => match quorums.get(&qhash) {
                Some(quorum) => {
                    debug!(
                        "Found quorum type {} at height {} with hash {}",
                        quorum_type,
                        height,
                        hex::encode(quorum_hash)
                    );
                    Some(quorum.clone())
                }
                None => {
                    warn!(
                        "Quorum not found: type {} at height {} with hash {} (masternode list exists with {} quorums of this type)",
                        quorum_type,
                        height,
                        hex::encode(quorum_hash),
                        quorums.len()
                    );
                    None
                }
            },
            None => {
                warn!(
                    "No quorums of type {} found at height {} (masternode list exists)",
                    quorum_type, height
                );
                None
            }
        }
    }

    /// Check if the masternode engine is available.
    ///
    /// Returns `true` if masternode sync has completed and the engine is ready for queries.
    pub fn is_available(&self) -> bool {
        self.engine().is_some()
    }

    /// Get the number of masternode lists currently stored in the engine.
    ///
    /// Returns `0` if the engine is not yet available.
    ///
    /// This can be useful for monitoring sync progress or debugging.
    pub fn masternode_list_count(&self) -> usize {
        self.engine().map(|engine| engine.masternode_lists.len()).unwrap_or(0)
    }

    /// Get the height range of available masternode lists.
    ///
    /// Returns `None` if no masternode lists are available yet.
    /// Returns `Some((min_height, max_height))` if lists are available.
    pub fn masternode_list_height_range(&self) -> Option<(u32, u32)> {
        let engine = self.engine()?;

        let heights: Vec<u32> = engine.masternode_lists.keys().copied().collect();
        if heights.is_empty() {
            return None;
        }

        let min = heights.iter().min().copied()?;
        let max = heights.iter().max().copied()?;
        Some((min, max))
    }
}

impl Clone for QuorumLookup {
    fn clone(&self) -> Self {
        Self {
            engine: Arc::clone(&self.engine),
        }
    }
}

impl Default for QuorumLookup {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_quorum_lookup_new() {
        let lookup = QuorumLookup::new();
        assert!(!lookup.is_available());
        assert_eq!(lookup.masternode_list_count(), 0);
        assert_eq!(lookup.masternode_list_height_range(), None);
    }

    #[tokio::test]
    async fn test_quorum_lookup_clone() {
        let lookup1 = QuorumLookup::new();
        let lookup2 = lookup1.clone();

        // Both should see the same state
        assert!(!lookup1.is_available());
        assert!(!lookup2.is_available());
    }

    #[tokio::test]
    async fn test_quorum_lookup_before_sync() {
        let lookup = QuorumLookup::new();

        // Queries should return None before engine is set
        assert!(lookup.get_masternode_list_at_height(100).await.is_none());
        assert!(lookup.get_quorum_at_height(100, 1, &[0u8; 32]).await.is_none());
    }
}
