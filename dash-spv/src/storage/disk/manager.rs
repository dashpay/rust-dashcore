//! Core DiskStorageManager struct and background worker implementation.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

use dashcore::{block::Header as BlockHeader, hash_types::FilterHeader, BlockHash, Txid};

use crate::error::{StorageError, StorageResult};
use crate::types::{MempoolState, UnconfirmedTransaction};

use super::segments::{FilterSegmentCache, SegmentCache};
use super::HEADERS_PER_SEGMENT;

/// Commands for the background worker
#[derive(Debug, Clone)]
pub(super) enum WorkerCommand {
    SaveHeaderSegment {
        segment_id: u32,
        headers: Vec<BlockHeader>,
    },
    SaveFilterSegment {
        segment_id: u32,
        filter_headers: Vec<FilterHeader>,
    },
    SaveIndex {
        index: HashMap<BlockHash, u32>,
    },
    Shutdown,
}

/// Notifications from the background worker
#[derive(Debug, Clone)]
#[allow(clippy::enum_variant_names)]
pub(super) enum WorkerNotification {
    HeaderSegmentSaved {
        segment_id: u32,
    },
    FilterSegmentSaved {
        segment_id: u32,
    },
    IndexSaved,
}

/// Disk-based storage manager with segmented files and async background saving.
pub struct DiskStorageManager {
    pub(super) base_path: PathBuf,

    // Segmented header storage
    pub(super) active_segments: Arc<RwLock<HashMap<u32, SegmentCache>>>,
    pub(super) active_filter_segments: Arc<RwLock<HashMap<u32, FilterSegmentCache>>>,

    // Reverse index for O(1) lookups
    pub(super) header_hash_index: Arc<RwLock<HashMap<BlockHash, u32>>>,

    // Background worker
    pub(super) worker_tx: Option<mpsc::Sender<WorkerCommand>>,
    pub(super) worker_handle: Option<tokio::task::JoinHandle<()>>,
    pub(super) notification_rx: Arc<RwLock<mpsc::Receiver<WorkerNotification>>>,

    // Cached values
    pub(super) cached_tip_height: Arc<RwLock<Option<u32>>>,
    pub(super) cached_filter_tip_height: Arc<RwLock<Option<u32>>>,

    // Checkpoint sync support
    pub(super) sync_base_height: Arc<RwLock<u32>>,

    // Index save tracking to avoid redundant saves
    pub(super) last_index_save_count: Arc<RwLock<usize>>,

    // Mempool storage
    pub(super) mempool_transactions: Arc<RwLock<HashMap<Txid, UnconfirmedTransaction>>>,
    pub(super) mempool_state: Arc<RwLock<Option<MempoolState>>>,
}

impl DiskStorageManager {
    /// Force-save the reverse header index to disk synchronously.
    pub(super) async fn flush_header_index(&self) -> StorageResult<()> {
        let index = self.header_hash_index.read().await.clone();
        let path = self.base_path.join("headers/index.dat");
        super::io::save_index_to_disk(&path, &index).await?;
        *self.last_index_save_count.write().await = index.len();
        Ok(())
    }

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
            base_path,
            active_segments: Arc::new(RwLock::new(HashMap::new())),
            active_filter_segments: Arc::new(RwLock::new(HashMap::new())),
            header_hash_index: Arc::new(RwLock::new(HashMap::new())),
            worker_tx: None,
            worker_handle: None,
            notification_rx: Arc::new(RwLock::new(mpsc::channel(1).1)), // Temporary placeholder
            cached_tip_height: Arc::new(RwLock::new(None)),
            cached_filter_tip_height: Arc::new(RwLock::new(None)),
            sync_base_height: Arc::new(RwLock::new(0)),
            last_index_save_count: Arc::new(RwLock::new(0)),
            mempool_transactions: Arc::new(RwLock::new(HashMap::new())),
            mempool_state: Arc::new(RwLock::new(None)),
        };

        // Start background worker
        storage.start_worker().await;

        // Load segment metadata and rebuild index
        storage.load_segment_metadata().await?;

        // Load chain state to get sync_base_height
        if let Ok(Some(chain_state)) = storage.load_chain_state().await {
            *storage.sync_base_height.write().await = chain_state.sync_base_height;
            tracing::debug!("Loaded sync_base_height: {}", chain_state.sync_base_height);
        }

        Ok(storage)
    }

    /// Start the background worker and notification channel.
    pub(super) async fn start_worker(&mut self) {
        use super::io::{save_filter_segment_to_disk, save_index_to_disk, save_segment_to_disk};

        let (worker_tx, mut worker_rx) = mpsc::channel::<WorkerCommand>(100);
        let (notification_tx, notification_rx) = mpsc::channel::<WorkerNotification>(100);

        let worker_base_path = self.base_path.clone();
        let worker_notification_tx = notification_tx.clone();
        let worker_handle = tokio::spawn(async move {
            while let Some(cmd) = worker_rx.recv().await {
                match cmd {
                    WorkerCommand::SaveHeaderSegment {
                        segment_id,
                        headers,
                    } => {
                        let path =
                            worker_base_path.join(format!("headers/segment_{:04}.dat", segment_id));
                        if let Err(e) = save_segment_to_disk(&path, &headers).await {
                            eprintln!("Failed to save segment {}: {}", segment_id, e);
                        } else {
                            tracing::trace!(
                                "Background worker completed saving header segment {}",
                                segment_id
                            );
                            let _ = worker_notification_tx
                                .send(WorkerNotification::HeaderSegmentSaved {
                                    segment_id,
                                })
                                .await;
                        }
                    }
                    WorkerCommand::SaveFilterSegment {
                        segment_id,
                        filter_headers,
                    } => {
                        let path = worker_base_path
                            .join(format!("filters/filter_segment_{:04}.dat", segment_id));
                        if let Err(e) = save_filter_segment_to_disk(&path, &filter_headers).await {
                            eprintln!("Failed to save filter segment {}: {}", segment_id, e);
                        } else {
                            tracing::trace!(
                                "Background worker completed saving filter segment {}",
                                segment_id
                            );
                            let _ = worker_notification_tx
                                .send(WorkerNotification::FilterSegmentSaved {
                                    segment_id,
                                })
                                .await;
                        }
                    }
                    WorkerCommand::SaveIndex {
                        index,
                    } => {
                        let path = worker_base_path.join("headers/index.dat");
                        if let Err(e) = save_index_to_disk(&path, &index).await {
                            eprintln!("Failed to save index: {}", e);
                        } else {
                            tracing::trace!("Background worker completed saving index");
                            let _ =
                                worker_notification_tx.send(WorkerNotification::IndexSaved).await;
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
        self.notification_rx = Arc::new(RwLock::new(notification_rx));
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

    /// Get the segment ID for a given height.
    pub(super) fn get_segment_id(height: u32) -> u32 {
        height / HEADERS_PER_SEGMENT
    }

    /// Get the offset within a segment for a given height.
    pub(super) fn get_segment_offset(height: u32) -> usize {
        (height % HEADERS_PER_SEGMENT) as usize
    }

    /// Process notifications from background worker to clear save_pending flags.
    pub(super) async fn process_worker_notifications(&self) {
        use super::segments::SegmentState;

        let mut rx = self.notification_rx.write().await;

        // Process all pending notifications without blocking
        while let Ok(notification) = rx.try_recv() {
            match notification {
                WorkerNotification::HeaderSegmentSaved {
                    segment_id,
                } => {
                    let mut segments = self.active_segments.write().await;
                    if let Some(segment) = segments.get_mut(&segment_id) {
                        // Transition Saving -> Clean, unless new changes occurred (Saving -> Dirty)
                        if segment.state == SegmentState::Saving {
                            segment.state = SegmentState::Clean;
                            tracing::debug!(
                                "Header segment {} save completed, state: Clean",
                                segment_id
                            );
                        } else {
                            tracing::debug!("Header segment {} save completed, but state is {:?} (likely dirty again)", segment_id, segment.state);
                        }
                    }
                }
                WorkerNotification::FilterSegmentSaved {
                    segment_id,
                } => {
                    let mut segments = self.active_filter_segments.write().await;
                    if let Some(segment) = segments.get_mut(&segment_id) {
                        // Transition Saving -> Clean, unless new changes occurred (Saving -> Dirty)
                        if segment.state == SegmentState::Saving {
                            segment.state = SegmentState::Clean;
                            tracing::debug!(
                                "Filter segment {} save completed, state: Clean",
                                segment_id
                            );
                        } else {
                            tracing::debug!("Filter segment {} save completed, but state is {:?} (likely dirty again)", segment_id, segment.state);
                        }
                    }
                }
                WorkerNotification::IndexSaved => {
                    tracing::debug!("Index save completed");
                }
            }
        }
    }

    /// Load segment metadata and rebuild indexes.
    async fn load_segment_metadata(&mut self) -> StorageResult<()> {
        use std::fs;

        // Load header index if it exists
        let index_path = self.base_path.join("headers/index.dat");
        let mut index_loaded = false;
        if index_path.exists() {
            if let Ok(index) = super::io::load_index_from_file(&index_path).await {
                *self.header_hash_index.write().await = index;
                index_loaded = true;
            }
        }

        // Find highest segment to determine tip height
        let headers_dir = self.base_path.join("headers");
        if let Ok(entries) = fs::read_dir(&headers_dir) {
            let mut max_segment_id = None;
            let mut max_filter_segment_id = None;
            let mut all_segment_ids = Vec::new();

            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.starts_with("segment_") && name.ends_with(".dat") {
                        if let Ok(id) = name[8..12].parse::<u32>() {
                            all_segment_ids.push(id);
                            max_segment_id =
                                Some(max_segment_id.map_or(id, |max: u32| max.max(id)));
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
                    let segment_path =
                        self.base_path.join(format!("headers/segment_{:04}.dat", segment_id));
                    if let Ok(headers) = super::io::load_headers_from_file(&segment_path).await {
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

            // Also check the filters directory for filter segments
            let filters_dir = self.base_path.join("filters");
            if let Ok(entries) = fs::read_dir(&filters_dir) {
                for entry in entries.flatten() {
                    if let Some(name) = entry.file_name().to_str() {
                        if name.starts_with("filter_segment_") && name.ends_with(".dat") {
                            if let Ok(id) = name[15..19].parse::<u32>() {
                                max_filter_segment_id =
                                    Some(max_filter_segment_id.map_or(id, |max: u32| max.max(id)));
                            }
                        }
                    }
                }
            }

            // If we have segments, load the highest one to find tip
            if let Some(segment_id) = max_segment_id {
                super::segments::ensure_segment_loaded(self, segment_id).await?;
                let segments = self.active_segments.read().await;
                if let Some(segment) = segments.get(&segment_id) {
                    let tip_height =
                        segment_id * HEADERS_PER_SEGMENT + segment.valid_count as u32 - 1;
                    *self.cached_tip_height.write().await = Some(tip_height);
                }
            }

            // If we have filter segments, load the highest one to find filter tip
            if let Some(segment_id) = max_filter_segment_id {
                super::segments::ensure_filter_segment_loaded(self, segment_id).await?;
                let segments = self.active_filter_segments.read().await;
                if let Some(segment) = segments.get(&segment_id) {
                    // Calculate storage index
                    let storage_index =
                        segment_id * HEADERS_PER_SEGMENT + segment.filter_headers.len() as u32 - 1;

                    // Convert storage index to blockchain height
                    let sync_base_height = *self.sync_base_height.read().await;
                    let blockchain_height = if sync_base_height > 0 {
                        sync_base_height + storage_index
                    } else {
                        storage_index
                    };

                    *self.cached_filter_tip_height.write().await = Some(blockchain_height);
                }
            }
        }

        Ok(())
    }
}
