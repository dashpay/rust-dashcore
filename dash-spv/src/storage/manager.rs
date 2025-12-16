//! Core DiskStorageManager struct and background worker implementation.

use std::collections::HashMap;
use std::io::Result;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use dashcore::{block::Header as BlockHeader, hash_types::FilterHeader, BlockHash, Txid};

use crate::error::{StorageError, StorageResult};
use crate::storage::headers::load_block_index;
use crate::storage::segments::SegmentCache;
use crate::types::{MempoolState, UnconfirmedTransaction};

use super::lockfile::LockFile;

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
    pub(super) worker_handle: Option<tokio::task::JoinHandle<()>>,

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

        // Temporary fix to load the sync base height if we have data already persisted
        let sync_base_height =
            load_sync_base_height_if_persisted(base_path.join("state/chain.json"))
                .await
                .unwrap_or(0);

        async fn load_sync_base_height_if_persisted(path: PathBuf) -> Result<u32> {
            let content = tokio::fs::read_to_string(path).await?;
            let value: serde_json::Value = serde_json::from_str(&content)?;

            Ok(value
                .get("sync_base_height")
                .and_then(|v| v.as_u64())
                .map(|h| h as u32)
                .unwrap_or(0))
        }

        let mut storage = Self {
            base_path: base_path.clone(),
            block_headers: Arc::new(RwLock::new(
                SegmentCache::load_or_new(base_path.clone(), sync_base_height).await?,
            )),
            filter_headers: Arc::new(RwLock::new(
                SegmentCache::load_or_new(base_path.clone(), sync_base_height).await?,
            )),
            filters: Arc::new(RwLock::new(
                SegmentCache::load_or_new(base_path.clone(), sync_base_height).await?,
            )),
            header_hash_index: Arc::new(RwLock::new(HashMap::new())),
            worker_handle: None,
            mempool_transactions: Arc::new(RwLock::new(HashMap::new())),
            mempool_state: Arc::new(RwLock::new(None)),
            _lock_file: lock_file,
        };

        // Load chain state to get sync_base_height
        if let Ok(Some(state)) = storage.load_chain_state().await {
            storage.filter_headers.write().await.set_sync_base_height(state.sync_base_height);
            storage.block_headers.write().await.set_sync_base_height(state.sync_base_height);
            storage.filters.write().await.set_sync_base_height(state.sync_base_height);
            tracing::debug!("Loaded sync_base_height: {}", state.sync_base_height);
        }

        // Start background worker that
        // persists data when appropriate
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
        let block_headers = Arc::clone(&self.block_headers);
        let filter_headers = Arc::clone(&self.filter_headers);
        let filters = Arc::clone(&self.filters);

        let worker_handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(5));

            loop {
                ticker.tick().await;

                block_headers.write().await.persist_evicted().await;
                filter_headers.write().await.persist_evicted().await;
                filters.write().await.persist_evicted().await;
            }
        });

        self.worker_handle = Some(worker_handle);
    }

    /// Stop the background worker without forcing a save.
    pub(super) fn stop_worker(&self) {
        if let Some(handle) = &self.worker_handle {
            handle.abort();
        }
    }
}
