//! Core DiskStorageManager struct and background worker implementation.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

use dashcore::{block::Header as BlockHeader, hash_types::FilterHeader, BlockHash, Txid};

use crate::error::{StorageError, StorageResult};
use crate::storage;
use crate::storage::disk::segments::{load_header_segments, SegmentCache};
use crate::types::{MempoolState, UnconfirmedTransaction};

/// Commands for the background worker
#[derive(Debug, Clone)]
pub(super) enum WorkerCommand {
    SaveBlockHeaderSegmentCache {
        segment_id: u32,
    },
    SaveFilterHeaderSegmentCache {
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
}

impl DiskStorageManager {
    /// Create a new disk storage manager with segmented storage.
    pub async fn new(base_path: PathBuf) -> StorageResult<Self> {
        use std::fs;

        // Create directories if they don't exist
        fs::create_dir_all(&base_path)
            .map_err(|e| StorageError::WriteFailed(format!("Failed to create directory: {}", e)))?;

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
            block_headers: Arc::new(RwLock::new(SegmentCache::new(base_path.clone()).await?)),
            filter_headers: Arc::new(RwLock::new(SegmentCache::new(base_path.clone()).await?)),
            header_hash_index: Arc::new(RwLock::new(HashMap::new())),
            worker_tx: None,
            worker_handle: None,
            last_index_save_count: Arc::new(RwLock::new(0)),
            mempool_transactions: Arc::new(RwLock::new(HashMap::new())),
            mempool_state: Arc::new(RwLock::new(None)),
        };

        // Load chain state to get sync_base_height
        if let Ok(Some(state)) = storage.load_chain_state().await {
            storage.filter_headers.write().await.set_sync_base_height(state.sync_base_height);
            storage.block_headers.write().await.set_sync_base_height(state.sync_base_height);
            tracing::debug!("Loaded sync_base_height: {}", state.sync_base_height);
        }

        // Start background worker
        storage.start_worker().await;

        // Load segment metadata and rebuild index
        storage.load_segment_metadata().await?;

        Ok(storage)
    }

    /// Start the background worker
    pub(super) async fn start_worker(&mut self) {
        let (worker_tx, mut worker_rx) = mpsc::channel::<WorkerCommand>(100);

        let worker_base_path = self.base_path.clone();
        let base_path = self.base_path.clone();

        let block_headers = Arc::clone(&self.block_headers);
        let filter_headers = Arc::clone(&self.filter_headers);

        let worker_handle = tokio::spawn(async move {
            while let Some(cmd) = worker_rx.recv().await {
                match cmd {
                    WorkerCommand::SaveBlockHeaderSegmentCache {
                        segment_id,
                    } => {
                        let mut cache = block_headers.write().await;
                        let segment = cache.get_segment_mut(&segment_id).await;
                        if let Err(e) = segment.and_then(|segment| segment.persist(&base_path)) {
                            eprintln!("Failed to save segment {}: {}", segment_id, e);
                        } else {
                            tracing::trace!(
                                "Background worker completed saving header segment {}",
                                segment_id
                            );
                        }
                    }
                    WorkerCommand::SaveFilterHeaderSegmentCache {
                        segment_id,
                    } => {
                        let mut cache = filter_headers.write().await;
                        let segment = cache.get_segment_mut(&segment_id).await;
                        if let Err(e) = segment.and_then(|segment| segment.persist(&base_path)) {
                            eprintln!("Failed to save filter segment {}: {}", segment_id, e);
                        } else {
                            tracing::trace!(
                                "Background worker completed saving filter segment {}",
                                segment_id
                            );
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

    /// Load segment metadata and rebuild indexes.
    async fn load_segment_metadata(&mut self) -> StorageResult<()> {
        use std::fs;

        // Load header index if it exists
        let index_path = self.base_path.join("headers/index.dat");
        let mut index_loaded = false;
        if index_path.exists() {
            if let Ok(index) = super::headers::load_index_from_file(&index_path).await {
                *self.header_hash_index.write().await = index;
                index_loaded = true;
            }
        }

        // Find highest segment to determine tip height
        let headers_dir = self.base_path.join("filter_headers");
        if let Ok(entries) = fs::read_dir(&headers_dir) {
            let mut all_segment_ids = Vec::new();

            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.starts_with("segment_") && name.ends_with(".dat") {
                        if let Ok(id) = name[8..12].parse::<u32>() {
                            all_segment_ids.push(id);
                        }
                    }
                }
            }

            // If index wasn't loaded but we have segments, rebuild it
            if !index_loaded && !all_segment_ids.is_empty() {
                tracing::info!("Index file not found, rebuilding from segments...");

                // Load chain state to get sync_base_height for proper height calculation
                let sync_base_height = if let Ok(Some(chain_state)) = self.load_chain_state().await
                {
                    chain_state.sync_base_height
                } else {
                    0 // Assume genesis sync if no chain state
                };

                let mut new_index = HashMap::new();

                // Sort segment IDs to process in order
                all_segment_ids.sort();

                for segment_id in all_segment_ids {
                    let segment_path = self
                        .base_path
                        .join(format!("filter_headers/segment_{:04}.dat", segment_id));
                    if let Ok(headers) = load_header_segments::<BlockHeader>(&segment_path) {
                        // Calculate the storage index range for this segment
                        let storage_start = segment_id * HEADERS_PER_SEGMENT;
                        for (offset, header) in headers.iter().enumerate() {
                            // Convert storage index to blockchain height
                            let storage_index = storage_start + offset as u32;
                            let blockchain_height = sync_base_height + storage_index;
                            let hash = header.block_hash();
                            new_index.insert(hash, blockchain_height);
                        }
                    }
                }

                *self.header_hash_index.write().await = new_index;
                tracing::info!(
                    "Index rebuilt with {} entries (sync_base_height: {})",
                    self.header_hash_index.read().await.len(),
                    sync_base_height
                );
            }
        }

        Ok(())
    }
}
