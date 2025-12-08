//! Core DiskStorageManager struct and background worker implementation.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

use dashcore::{block::Header as BlockHeader, hash_types::FilterHeader, BlockHash, Txid};

use crate::error::{StorageError, StorageResult};
use crate::storage::disk::segments::{load_header_segments, Segment, SegmentCache};
use crate::types::{MempoolState, UnconfirmedTransaction};

use super::HEADERS_PER_SEGMENT;

/// Commands for the background worker
#[derive(Debug, Clone)]
pub(super) enum WorkerCommand {
    SaveBlockHeaderSegmentCache(Segment<BlockHeader>),
    SaveFilterHeaderSegmentCache(Segment<FilterHeader>),
    SaveIndex {
        index: HashMap<BlockHash, u32>,
    },
    Shutdown,
}

/// Notifications from the background worker
#[derive(Debug, Clone)]
#[allow(clippy::enum_variant_names)]
pub(super) enum WorkerNotification {
    BlockHeaderSegmentCacheSaved(Segment<BlockHeader>),
    BlockFilterSegmentCacheSaved(Segment<FilterHeader>),
    IndexSaved,
}

/// Disk-based storage manager with segmented files and async background saving.
pub struct DiskStorageManager {
    pub(super) base_path: PathBuf,

    // Segmented header storage
    pub(super) active_segments: Arc<RwLock<SegmentCache<BlockHeader>>>,
    pub(super) active_filter_segments: Arc<RwLock<SegmentCache<FilterHeader>>>,

    // Reverse index for O(1) lookups
    pub(super) header_hash_index: Arc<RwLock<HashMap<BlockHash, u32>>>,

    // Background worker
    pub(super) worker_tx: Option<mpsc::Sender<WorkerCommand>>,
    pub(super) worker_handle: Option<tokio::task::JoinHandle<()>>,
    pub(super) notification_rx: Arc<RwLock<mpsc::Receiver<WorkerNotification>>>,

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
            active_segments: Arc::new(RwLock::new(SegmentCache::new(base_path.clone()))),
            active_filter_segments: Arc::new(RwLock::new(SegmentCache::new(base_path.clone()))),
            header_hash_index: Arc::new(RwLock::new(HashMap::new())),
            worker_tx: None,
            worker_handle: None,
            notification_rx: Arc::new(RwLock::new(mpsc::channel(1).1)), // Temporary placeholder
            last_index_save_count: Arc::new(RwLock::new(0)),
            mempool_transactions: Arc::new(RwLock::new(HashMap::new())),
            mempool_state: Arc::new(RwLock::new(None)),
        };

        // Load chain state to get sync_base_height
        if let Ok(Some(state)) = storage.load_chain_state().await {
            storage
                .active_filter_segments
                .write()
                .await
                .set_sync_base_height(state.sync_base_height);
            storage.active_segments.write().await.set_sync_base_height(state.sync_base_height);
            tracing::debug!("Loaded sync_base_height: {}", state.sync_base_height);
        }

        // Start background worker
        storage.start_worker().await;

        // Load segment metadata and rebuild index
        storage.load_segment_metadata().await?;

        Ok(storage)
    }

    /// Start the background worker and notification channel.
    pub(super) async fn start_worker(&mut self) {
        let (worker_tx, mut worker_rx) = mpsc::channel::<WorkerCommand>(100);
        let (notification_tx, notification_rx) = mpsc::channel::<WorkerNotification>(100);

        let worker_base_path = self.base_path.clone();
        let worker_notification_tx = notification_tx.clone();
        let base_path = self.base_path.clone();

        let worker_handle = tokio::spawn(async move {
            while let Some(cmd) = worker_rx.recv().await {
                match cmd {
                    WorkerCommand::SaveBlockHeaderSegmentCache(cache) => {
                        let segment_id = cache.segment_id;
                        if let Err(e) = cache.persist(&base_path) {
                            eprintln!("Failed to save segment {}: {}", segment_id, e);
                        } else {
                            tracing::trace!(
                                "Background worker completed saving header segment {}",
                                segment_id
                            );
                            let _ = worker_notification_tx
                                .send(WorkerNotification::BlockHeaderSegmentCacheSaved(cache))
                                .await;
                        }
                    }
                    WorkerCommand::SaveFilterHeaderSegmentCache(cache) => {
                        let segment_id = cache.segment_id;
                        if let Err(e) = cache.persist(&base_path) {
                            eprintln!("Failed to save filter segment {}: {}", segment_id, e);
                        } else {
                            tracing::trace!(
                                "Background worker completed saving filter segment {}",
                                segment_id
                            );
                            let _ = worker_notification_tx
                                .send(WorkerNotification::BlockFilterSegmentCacheSaved(cache))
                                .await;
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
                WorkerNotification::BlockHeaderSegmentCacheSaved(cache) => {
                    let segment_id = cache.segment_id;
                    let mut segments = self.active_segments.write().await;
                    if let Some(segment) = segments.get_segment_if_loaded_mut(&segment_id) {
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
                WorkerNotification::BlockFilterSegmentCacheSaved(cache) => {
                    let segment_id = cache.segment_id;
                    let mut segments = self.active_filter_segments.write().await;
                    if let Some(segment) = segments.get_segment_if_loaded_mut(&segment_id) {
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
            if let Ok(index) = super::headers::load_index_from_file(&index_path).await {
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
                let mut segments_cache = self.active_segments.write().await;
                let segment = segments_cache.get_segment(&segment_id).await?;
                let storage_index =
                    segment_id * HEADERS_PER_SEGMENT + segment.valid_count as u32 - 1;
                let tip_height = segments_cache.storage_index_to_height(storage_index);
                segments_cache.set_tip_height(tip_height);
            }

            // If we have filter segments, load the highest one to find filter tip
            if let Some(segment_id) = max_filter_segment_id {
                let mut segments_cache = self.active_filter_segments.write().await;
                let segment = segments_cache.get_segment(&segment_id).await?;
                let storage_index =
                    segment_id * HEADERS_PER_SEGMENT + segment.valid_count as u32 - 1;

                let tip_height = segments_cache.storage_index_to_height(storage_index);
                segments_cache.set_tip_height(tip_height);
            }
        }

        Ok(())
    }
}
