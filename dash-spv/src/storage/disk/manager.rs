//! Core DiskStorageManager struct and background worker implementation.

use std::collections::HashMap;
use std::io::Result;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

use dashcore::{block::Header as BlockHeader, hash_types::FilterHeader, BlockHash, Txid};

use crate::error::{StorageError, StorageResult};
use crate::storage::disk::headers::load_block_index;
use crate::storage::disk::segments::SegmentCache;
use crate::types::{MempoolState, UnconfirmedTransaction};

use super::lockfile::LockFile;

/// Commands for the background worker
#[derive(Debug, Clone)]
pub(super) enum WorkerCommand {
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
    /// Create a new disk storage manager with segmented storage.
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
            worker_tx: None,
            worker_handle: None,
            last_index_save_count: Arc::new(RwLock::new(0)),
            mempool_transactions: Arc::new(RwLock::new(HashMap::new())),
            mempool_state: Arc::new(RwLock::new(None)),
            _lock_file: lock_file,
        };

        // Load chain state to get sync_base_height
        if let Ok(Some(state)) = storage.load_chain_state().await {
            storage.filter_headers.write().await.set_sync_base_height(state.sync_base_height);
            storage.block_headers.write().await.set_sync_base_height(state.sync_base_height);
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
}
