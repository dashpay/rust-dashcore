//! Storage abstraction for the Dash SPV client.

pub(crate) mod io;

pub mod types;

mod headers;
mod lockfile;
mod segments;
mod state;

use async_trait::async_trait;
use std::collections::HashMap;
use std::ops::Range;

use dashcore::{block::Header as BlockHeader, hash_types::FilterHeader, Txid};

use crate::error::StorageResult;
use crate::types::{ChainState, MempoolState, UnconfirmedTransaction};

pub use types::*;

#[async_trait]
pub trait StorageManager:
    BlockHeaderStorage
    + FilterHeaderStorage
    + FilterStorage
    + TransactionStorage
    + MempoolStateStorage
    + MetadataStorage
    + ChainStateStorage
    + MasternodeStateStorage
    + Send
    + Sync
{
}

/// Commands for the background worker
#[derive(Debug, Clone)]
enum WorkerCommand {
    SaveBlockHeaderSegmentCache {
        segment_id: u32,
    },
    SaveFilterHeaderSegmentCache {
        segment_id: u32,
    },
    SaveFilterSegmentCache {
        segment_id: u32,
    },
    SaveIndex {
        index: HashMap<BlockHash, u32>,
    },
    Shutdown,
}

/// Disk-based storage manager with segmented files and async background saving.
pub struct DiskStorageManager {
    pub(super) base_path: PathBuf,

    // Segmented header storage
    pub(super) block_headers: Arc<RwLock<SegmentCache<BlockHeader>>>,
    pub(super) filter_headers: Arc<RwLock<SegmentCache<FilterHeader>>>,
    pub(super) filters: Arc<RwLock<SegmentCache<Vec<u8>>>>,

    // Reverse index for O(1) lookups
    pub(super) header_hash_index: Arc<RwLock<HashMap<BlockHash, u32>>>,

    // Background worker
    pub(super) worker_tx: Option<mpsc::Sender<WorkerCommand>>,
    pub(super) worker_handle: Option<tokio::task::JoinHandle<()>>,

    // Index save tracking to avoid redundant saves
    pub(super) last_index_save_count: Arc<RwLock<usize>>,

    // Mempool storage
    pub(super) mempool_transactions: Arc<RwLock<HashMap<Txid, UnconfirmedTransaction>>>,
    pub(super) mempool_state: Arc<RwLock<Option<MempoolState>>>,

    // Lock file to prevent concurrent access from multiple processes.
    _lock_file: LockFile,
}

impl DiskStorageManager {
    pub async fn new(base_path: PathBuf) -> StorageResult<Self> {
        use std::fs;

        // Create directories if they don't exist
        fs::create_dir_all(&base_path)
            .map_err(|e| StorageError::WriteFailed(format!("Failed to create directory: {}", e)))?;

        // Acquire exclusive lock on the data directory
        let lock_file = LockFile::new(base_path.join(".lock"))?;

        let headers_dir = base_path.join("headers");
        let filters_dir = base_path.join("filters");
        let state_dir = base_path.join("state");

        fs::create_dir_all(&headers_dir).map_err(|e| {
            StorageError::WriteFailed(format!("Failed to create headers directory: {}", e))
        })?;
        fs::create_dir_all(&filters_dir).map_err(|e| {
            StorageError::WriteFailed(format!("Failed to create filters directory: {}", e))
        })?;
        fs::create_dir_all(&state_dir).map_err(|e| {
            StorageError::WriteFailed(format!("Failed to create state directory: {}", e))
        })?;

        let mut storage = Self {
            base_path: base_path.clone(),
            block_headers: Arc::new(RwLock::new(
                SegmentCache::load_or_new(base_path.clone()).await?,
            )),
            filter_headers: Arc::new(RwLock::new(
                SegmentCache::load_or_new(base_path.clone()).await?,
            )),
            filters: Arc::new(RwLock::new(SegmentCache::load_or_new(base_path.clone()).await?)),
            header_hash_index: Arc::new(RwLock::new(HashMap::new())),
            worker_tx: None,
            worker_handle: None,
            last_index_save_count: Arc::new(RwLock::new(0)),
            mempool_transactions: Arc::new(RwLock::new(HashMap::new())),
            mempool_state: Arc::new(RwLock::new(None)),
            _lock_file: lock_file,
        };

        // Load chain state to get sync_base_height
        if let Ok(Some(state)) = storage.load_chain_state().await {
            tracing::debug!("Loaded sync_base_height: {}", state.sync_base_height);
        }

        // Start background worker
        storage.start_worker().await;

        // Rebuild index
        let block_index = match load_block_index(&storage).await {
            Ok(index) => index,
            Err(e) => {
                tracing::error!(
                    "An unexpected IO or deserialization error didn't allow the block index to be built: {}",
                    e
                );
                HashMap::new()
            }
        };
        storage.header_hash_index = Arc::new(RwLock::new(block_index));

        Ok(storage)
    }

    #[cfg(test)]
    pub async fn with_temp_dir() -> StorageResult<Self> {
        use tempfile::TempDir;

        let temp_dir = TempDir::new()?;
        Self::new(temp_dir.path().into()).await
    }

    /// Start the background worker
    pub(super) async fn start_worker(&mut self) {
        let (worker_tx, mut worker_rx) = mpsc::channel::<WorkerCommand>(100);

        let worker_base_path = self.base_path.clone();
        let base_path = self.base_path.clone();

        let block_headers = Arc::clone(&self.block_headers);
        let filter_headers = Arc::clone(&self.filter_headers);
        let cfilters = Arc::clone(&self.filters);

        let worker_handle = tokio::spawn(async move {
            while let Some(cmd) = worker_rx.recv().await {
                match cmd {
                    WorkerCommand::SaveBlockHeaderSegmentCache {
                        segment_id,
                    } => {
                        let mut cache = block_headers.write().await;
                        let segment = match cache.get_segment_mut(&segment_id).await {
                            Ok(segment) => segment,
                            Err(e) => {
                                eprintln!("Failed to get segment {}: {}", segment_id, e);
                                continue;
                            }
                        };

                        match segment.persist(&base_path).await {
                            Ok(()) => {
                                tracing::trace!(
                                    "Background worker completed saving header segment {}",
                                    segment_id
                                );
                            }
                            Err(e) => {
                                eprintln!("Failed to save segment {}: {}", segment_id, e);
                            }
                        }
                    }
                    WorkerCommand::SaveFilterHeaderSegmentCache {
                        segment_id,
                    } => {
                        let mut cache = filter_headers.write().await;
                        let segment = match cache.get_segment_mut(&segment_id).await {
                            Ok(segment) => segment,
                            Err(e) => {
                                eprintln!("Failed to get segment {}: {}", segment_id, e);
                                continue;
                            }
                        };

                        match segment.persist(&base_path).await {
                            Ok(()) => {
                                tracing::trace!(
                                    "Background worker completed saving header segment {}",
                                    segment_id
                                );
                            }
                            Err(e) => {
                                eprintln!("Failed to save segment {}: {}", segment_id, e);
                            }
                        }
                    }
                    WorkerCommand::SaveFilterSegmentCache {
                        segment_id,
                    } => {
                        let mut cache = cfilters.write().await;
                        let segment = match cache.get_segment_mut(&segment_id).await {
                            Ok(segment) => segment,
                            Err(e) => {
                                eprintln!("Failed to get segment {}: {}", segment_id, e);
                                continue;
                            }
                        };

                        match segment.persist(&base_path).await {
                            Ok(()) => {
                                tracing::trace!(
                                    "Background worker completed saving filter segment {}",
                                    segment_id
                                );
                            }
                            Err(e) => {
                                eprintln!("Failed to save segment {}: {}", segment_id, e);
                            }
                        }
                    }
                    WorkerCommand::SaveIndex {
                        index,
                    } => {
                        let path = worker_base_path.join("headers/index.dat");
                        if let Err(e) = super::headers::save_index_to_disk(&path, &index).await {
                            eprintln!("Failed to save index: {}", e);
                        } else {
                            tracing::trace!("Background worker completed saving index");
                        }
                    }
                    WorkerCommand::Shutdown => {
                        break;
                    }
                }
            }
        });

        self.worker_tx = Some(worker_tx);
        self.worker_handle = Some(worker_handle);
    }

    /// Stop the background worker without forcing a save.
    pub(super) async fn stop_worker(&mut self) {
        if let Some(tx) = self.worker_tx.take() {
            let _ = tx.send(WorkerCommand::Shutdown).await;
        }
        if let Some(handle) = self.worker_handle.take() {
            let _ = handle.await;
        }
    }

    /// Clear all data.
    pub(super) async fn clear(&mut self) -> StorageResult<()> {
        // First, stop the background worker to avoid races with file deletion
        self.stop_worker().await;

        // Clear in-memory state
        self.block_headers.write().await.clear_in_memory();
        self.filter_headers.write().await.clear_in_memory();
        self.filters.write().await.clear_in_memory();

        self.header_hash_index.write().await.clear();
        self.mempool_transactions.write().await.clear();
        *self.mempool_state.write().await = None;

        // Remove all files and directories under base_path
        if self.base_path.exists() {
            // Best-effort removal; if concurrent files appear, retry once
            match tokio::fs::remove_dir_all(&self.base_path).await {
                Ok(_) => {}
                Err(e) => {
                    // Retry once after a short delay to handle transient races
                    if e.kind() == std::io::ErrorKind::Other
                        || e.kind() == std::io::ErrorKind::DirectoryNotEmpty
                    {
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        tokio::fs::remove_dir_all(&self.base_path).await?;
                    } else {
                        return Err(crate::error::StorageError::Io(e));
                    }
                }
            }
            tokio::fs::create_dir_all(&self.base_path).await?;
        }

        // Recreate expected subdirectories
        tokio::fs::create_dir_all(self.base_path.join("headers")).await?;
        tokio::fs::create_dir_all(self.base_path.join("filters")).await?;
        tokio::fs::create_dir_all(self.base_path.join("state")).await?;

        // Restart the background worker for future operations
        self.start_worker().await;

        Ok(())
    }

    /// Clear all filter headers and compact filters.
    pub(super) async fn clear_filters(&mut self) -> StorageResult<()> {
        // Stop worker to prevent concurrent writes to filter directories
        self.stop_worker().await;

        // Clear in-memory and on-disk filter headers segments
        self.filter_headers.write().await.clear_all().await?;
        self.filters.write().await.clear_all().await?;

        // Restart background worker for future operations
        self.start_worker().await;

        Ok(())
    }

    /// Shutdown the storage manager
    pub(super) async fn shutdown(&mut self) {
        // Persist all dirty data
        self.save_dirty().await;

        // Shutdown background worker
        if let Some(tx) = self.worker_tx.take() {
            // Save the header index before shutdown
            let index = self.header_hash_index.read().await.clone();
            let _ = tx
                .send(super::manager::WorkerCommand::SaveIndex {
                    index,
                })
                .await;
            let _ = tx.send(super::manager::WorkerCommand::Shutdown).await;
        }

        if let Some(handle) = self.worker_handle.take() {
            let _ = handle.await;
        }
    }

    /// Save all dirty segments to disk via background worker.
    pub(super) async fn save_dirty(&self) {
        self.filter_headers.write().await.persist_dirty(self).await;
        self.block_headers.write().await.persist_dirty(self).await;
        self.filters.write().await.persist_dirty(self).await;

        if let Some(tx) = &self.worker_tx {
            // Save the index only if it has grown significantly (every 10k new entries)
            let current_index_size = self.header_hash_index.read().await.len();
            let last_save_count = *self.last_index_save_count.read().await;

            // Save if index has grown by 10k entries, or if we've never saved before
            if current_index_size >= last_save_count + 10_000 || last_save_count == 0 {
                let index = self.header_hash_index.read().await.clone();
                let _ = tx
                    .send(WorkerCommand::SaveIndex {
                        index,
                    })
                    .await;

                // Update the last save count
                *self.last_index_save_count.write().await = current_index_size;
                tracing::debug!(
                    "Scheduled index save (size: {}, last_save: {})",
                    current_index_size,
                    last_save_count
                );
            }
        }
    }
}

#[async_trait]
pub trait BlockHeaderStorage {
    /// Store block headers.
    async fn store_headers(&mut self, headers: &[BlockHeader]) -> StorageResult<()>;

    /// Load block headers in the given range.
    async fn load_headers(&self, range: Range<u32>) -> StorageResult<Vec<BlockHeader>>;

    /// Get a specific header by blockchain height.
    async fn get_header(&self, height: u32) -> StorageResult<Option<BlockHeader>>;

    /// Get the current tip blockchain height.
    async fn get_tip_height(&self) -> StorageResult<Option<u32>>;

    /// Get header height by block hash (reverse lookup).
    async fn get_header_height_by_hash(
        &self,
        hash: &dashcore::BlockHash,
    ) -> StorageResult<Option<u32>>;
}

#[async_trait]
pub trait FilterHeaderStorage {
    /// Store filter headers.
    async fn store_filter_headers(&mut self, headers: &[FilterHeader]) -> StorageResult<()>;

    /// Load filter headers in the given blockchain height range.
    async fn load_filter_headers(&self, range: Range<u32>) -> StorageResult<Vec<FilterHeader>>;

    /// Get a specific filter header by blockchain height.
    async fn get_filter_header(&self, height: u32) -> StorageResult<Option<FilterHeader>>;

    /// Get the current filter tip blockchain height.
    async fn get_filter_tip_height(&self) -> StorageResult<Option<u32>>;
}

#[async_trait]
pub trait FilterStorage {
    /// Store a compact filter at a blockchain height.
    async fn store_filter(&mut self, height: u32, filter: &[u8]) -> StorageResult<()>;

    /// Load compact filters in the given blockchain height range.
    async fn load_filters(&self, range: Range<u32>) -> StorageResult<Vec<Vec<u8>>>;
}

#[async_trait]
pub trait TransactionStorage {
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
}

#[async_trait]
pub trait MempoolStateStorage {
    /// Store the complete mempool state.
    async fn store_mempool_state(&mut self, state: &MempoolState) -> StorageResult<()>;

    /// Load the mempool state.
    async fn load_mempool_state(&self) -> StorageResult<Option<MempoolState>>;
}

#[async_trait]
pub trait MetadataStorage {
    /// Store metadata.
    async fn store_metadata(&mut self, key: &str, value: &[u8]) -> StorageResult<()>;

    /// Load metadata.
    async fn load_metadata(&self, key: &str) -> StorageResult<Option<Vec<u8>>>;
}

#[async_trait]
pub trait ChainStateStorage {
    /// Store chain state.
    async fn store_chain_state(&mut self, state: &ChainState) -> StorageResult<()>;

    /// Load chain state.
    async fn load_chain_state(&self) -> StorageResult<Option<ChainState>>;
}

#[async_trait]
pub trait MasternodeStateStorage {
    /// Store masternode state.
    async fn store_masternode_state(&mut self, state: &MasternodeState) -> StorageResult<()>;

    /// Load masternode state.
    async fn load_masternode_state(&self) -> StorageResult<Option<MasternodeState>>;
}
