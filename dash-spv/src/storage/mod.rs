//! Storage abstraction for the Dash SPV client.

pub mod disk;
pub mod memory;
pub mod sync_state;
pub mod sync_storage;
pub mod types;

use async_trait::async_trait;
use std::any::Any;
use std::collections::HashMap;
use std::ops::Range;

use dashcore::{block::Header as BlockHeader, hash_types::FilterHeader, Address, OutPoint, Txid};

use crate::error::StorageResult;
use crate::types::{ChainState, MempoolState, UnconfirmedTransaction};

pub use disk::DiskStorageManager;
pub use memory::MemoryStorageManager;
pub use sync_state::{PersistentSyncState, RecoverySuggestion, SyncStateValidation};
pub use sync_storage::MemoryStorage;
pub use types::*;

use crate::error::StorageError;
use dashcore::BlockHash;

/// Synchronous storage trait for chain operations
pub trait ChainStorage: Send + Sync {
    /// Get a header by its block hash
    fn get_header(&self, hash: &BlockHash) -> Result<Option<BlockHeader>, StorageError>;

    /// Get a header by its height
    fn get_header_by_height(&self, height: u32) -> Result<Option<BlockHeader>, StorageError>;

    /// Get the height of a block by its hash
    fn get_header_height(&self, hash: &BlockHash) -> Result<Option<u32>, StorageError>;

    /// Store a header at a specific height
    fn store_header(&self, header: &BlockHeader, height: u32) -> Result<(), StorageError>;

    /// Get transaction IDs in a block
    fn get_block_transactions(
        &self,
        block_hash: &BlockHash,
    ) -> Result<Option<Vec<dashcore::Txid>>, StorageError>;

    /// Get a transaction by its ID
    fn get_transaction(
        &self,
        txid: &dashcore::Txid,
    ) -> Result<Option<dashcore::Transaction>, StorageError>;
}

/// Storage manager trait for abstracting data persistence.
///
/// # Thread Safety
///
/// This trait requires `Send + Sync` bounds to ensure thread safety, but uses `&mut self`
/// for mutation methods. This design choice provides several benefits:
///
/// 1. **Simplified Implementation**: Storage backends don't need to implement interior
///    mutability patterns (like `Arc<Mutex<T>>` or `RwLock<T>`) internally.
///
/// 2. **Performance**: Avoids unnecessary locking overhead when the storage manager
///    is already protected by external synchronization.
///
/// 3. **Flexibility**: Callers can choose the appropriate synchronization strategy
///    based on their specific use case (e.g., single-threaded, mutex-protected, etc.).
///
/// ## Usage Pattern
///
/// The typical usage pattern wraps the storage manager in an `Arc<Mutex<T>>` or similar:
///
/// ```rust,no_run
/// # use std::sync::Arc;
/// # use tokio::sync::Mutex;
/// # use dash_spv::storage::{StorageManager, MemoryStorageManager};
/// # use dashcore::blockdata::block::Header as BlockHeader;
/// #
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let storage: Arc<Mutex<dyn StorageManager>> = Arc::new(Mutex::new(MemoryStorageManager::new().await?));
/// let headers: Vec<BlockHeader> = vec![]; // Your headers here
///
/// // In async context:
/// let mut guard = storage.lock().await;
/// guard.store_headers(&headers).await?;
/// # Ok(())
/// # }
/// ```
///
/// ## Implementation Requirements
///
/// Implementations must ensure that:
/// - All operations are atomic at the logical level (e.g., all headers in a batch succeed or fail together)
/// - Read operations are consistent (no partial reads of in-progress writes)
/// - The implementation is safe to move between threads (`Send`)
/// - The implementation can be referenced from multiple threads (`Sync`)
///
/// Note that the `&mut self` requirement means only one thread can be mutating the storage
/// at a time when using external synchronization, which naturally provides consistency.
#[async_trait]
pub trait StorageManager: Send + Sync {
    /// Convert to Any for downcasting
    fn as_any_mut(&mut self) -> &mut dyn Any;
    /// Store block headers.
    async fn store_headers(&mut self, headers: &[BlockHeader]) -> StorageResult<()>;

    /// Load block headers in the given range.
    async fn load_headers(&self, range: Range<u32>) -> StorageResult<Vec<BlockHeader>>;

    /// Get a specific header by height.
    ///
    /// TODO: Consider changing this API to accept blockchain heights instead of storage-relative heights.
    /// Currently expects storage index (0-based from sync_base_height), but this creates confusion
    /// since most blockchain operations work with absolute blockchain heights. A future refactor
    /// could make this more intuitive by handling the height conversion internally.
    async fn get_header(&self, height: u32) -> StorageResult<Option<BlockHeader>>;

    /// Get the current tip height.
    async fn get_tip_height(&self) -> StorageResult<Option<u32>>;

    /// Store filter headers.
    async fn store_filter_headers(&mut self, headers: &[FilterHeader]) -> StorageResult<()>;

    /// Load filter headers in the given range.
    async fn load_filter_headers(&self, range: Range<u32>) -> StorageResult<Vec<FilterHeader>>;

    /// Get a specific filter header by height.
    async fn get_filter_header(&self, height: u32) -> StorageResult<Option<FilterHeader>>;

    /// Get the current filter tip height.
    async fn get_filter_tip_height(&self) -> StorageResult<Option<u32>>;

    /// Store masternode state.
    async fn store_masternode_state(&mut self, state: &MasternodeState) -> StorageResult<()>;

    /// Load masternode state.
    async fn load_masternode_state(&self) -> StorageResult<Option<MasternodeState>>;

    /// Store chain state.
    async fn store_chain_state(&mut self, state: &ChainState) -> StorageResult<()>;

    /// Load chain state.
    async fn load_chain_state(&self) -> StorageResult<Option<ChainState>>;

    /// Store a compact filter.
    async fn store_filter(&mut self, height: u32, filter: &[u8]) -> StorageResult<()>;

    /// Load a compact filter.
    async fn load_filter(&self, height: u32) -> StorageResult<Option<Vec<u8>>>;

    /// Store metadata.
    async fn store_metadata(&mut self, key: &str, value: &[u8]) -> StorageResult<()>;

    /// Load metadata.
    async fn load_metadata(&self, key: &str) -> StorageResult<Option<Vec<u8>>>;

    /// Clear all data.
    async fn clear(&mut self) -> StorageResult<()>;

    /// Get storage statistics.
    async fn stats(&self) -> StorageResult<StorageStats>;

    /// Get header height by block hash (reverse lookup).
    async fn get_header_height_by_hash(
        &self,
        hash: &dashcore::BlockHash,
    ) -> StorageResult<Option<u32>>;

    /// Get multiple headers in a single batch operation.
    /// Returns headers with their heights. More efficient than calling get_header multiple times.
    async fn get_headers_batch(
        &self,
        start_height: u32,
        end_height: u32,
    ) -> StorageResult<Vec<(u32, BlockHeader)>>;

    // UTXO methods removed - handled by external wallet

    /// Store persistent sync state.
    async fn store_sync_state(&mut self, state: &PersistentSyncState) -> StorageResult<()>;

    /// Load persistent sync state.
    async fn load_sync_state(&self) -> StorageResult<Option<PersistentSyncState>>;

    /// Clear sync state (for recovery).
    async fn clear_sync_state(&mut self) -> StorageResult<()>;

    /// Store a sync checkpoint.
    async fn store_sync_checkpoint(
        &mut self,
        height: u32,
        checkpoint: &sync_state::SyncCheckpoint,
    ) -> StorageResult<()>;

    /// Get sync checkpoints in a height range.
    async fn get_sync_checkpoints(
        &self,
        start_height: u32,
        end_height: u32,
    ) -> StorageResult<Vec<sync_state::SyncCheckpoint>>;

    /// Store a chain lock.
    async fn store_chain_lock(
        &mut self,
        height: u32,
        chain_lock: &dashcore::ChainLock,
    ) -> StorageResult<()>;

    /// Load a chain lock by height.
    async fn load_chain_lock(&self, height: u32) -> StorageResult<Option<dashcore::ChainLock>>;

    /// Get chain locks in a height range.
    async fn get_chain_locks(
        &self,
        start_height: u32,
        end_height: u32,
    ) -> StorageResult<Vec<(u32, dashcore::ChainLock)>>;

    /// Store an instant lock.
    async fn store_instant_lock(
        &mut self,
        txid: dashcore::Txid,
        instant_lock: &dashcore::InstantLock,
    ) -> StorageResult<()>;

    /// Load an instant lock by transaction ID.
    async fn load_instant_lock(
        &self,
        txid: dashcore::Txid,
    ) -> StorageResult<Option<dashcore::InstantLock>>;

    // Mempool storage methods
    /// Store an unconfirmed transaction.
    async fn store_mempool_transaction(
        &mut self,
        txid: &Txid,
        tx: &UnconfirmedTransaction,
    ) -> StorageResult<()>;

    /// Remove a mempool transaction.
    async fn remove_mempool_transaction(&mut self, txid: &Txid) -> StorageResult<()>;

    /// Get a mempool transaction.
    async fn get_mempool_transaction(
        &self,
        txid: &Txid,
    ) -> StorageResult<Option<UnconfirmedTransaction>>;

    /// Get all mempool transactions.
    async fn get_all_mempool_transactions(
        &self,
    ) -> StorageResult<HashMap<Txid, UnconfirmedTransaction>>;

    /// Store the complete mempool state.
    async fn store_mempool_state(&mut self, state: &MempoolState) -> StorageResult<()>;

    /// Load the mempool state.
    async fn load_mempool_state(&self) -> StorageResult<Option<MempoolState>>;

    /// Clear all mempool data.
    async fn clear_mempool(&mut self) -> StorageResult<()>;
}

/// Helper trait to provide as_any_mut for all StorageManager implementations
pub trait AsAnyMut {
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

impl<T: 'static> AsAnyMut for T {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
