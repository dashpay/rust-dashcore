//! Disk-based storage implementation with segmented files and async background saving.

use async_trait::async_trait;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, RwLock};

use dashcore::{
    block::{Header as BlockHeader, Version},
    consensus::{encode, Decodable, Encodable},
    hash_types::FilterHeader,
    pow::CompactTarget,
    BlockHash, Txid,
};
use dashcore_hashes::Hash;

use crate::error::{StorageError, StorageResult};
use crate::storage::{MasternodeState, StorageManager, StorageStats};
use crate::types::{ChainState, MempoolState, UnconfirmedTransaction};

/// Number of headers per segment file
const HEADERS_PER_SEGMENT: u32 = 50_000;

/// Maximum number of segments to keep in memory
const MAX_ACTIVE_SEGMENTS: usize = 10;

/// Commands for the background worker
#[derive(Debug, Clone)]
enum WorkerCommand {
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
    // Removed: SaveUtxoCache - UTXO management is now handled externally
    Shutdown,
}

/// Notifications from the background worker
#[derive(Debug, Clone)]
#[allow(clippy::enum_variant_names)]
enum WorkerNotification {
    HeaderSegmentSaved {
        segment_id: u32,
    },
    FilterSegmentSaved {
        segment_id: u32,
    },
    IndexSaved,
    // Removed: UtxoCacheSaved - UTXO management is now handled externally
}

/// State of a segment in memory
#[derive(Debug, Clone, PartialEq)]
enum SegmentState {
    Clean,  // No changes, up to date on disk
    Dirty,  // Has changes, needs saving
    Saving, // Currently being saved in background
}

/// In-memory cache for a segment of headers
#[derive(Clone)]
struct SegmentCache {
    segment_id: u32,
    headers: Vec<BlockHeader>,
    valid_count: usize, // Number of actual valid headers (excluding padding)
    state: SegmentState,
    last_saved: Instant,
    last_accessed: Instant,
}

/// In-memory cache for a segment of filter headers
#[derive(Clone)]
struct FilterSegmentCache {
    segment_id: u32,
    filter_headers: Vec<FilterHeader>,
    state: SegmentState,
    last_saved: Instant,
    last_accessed: Instant,
}

/// Disk-based storage manager with segmented files and async background saving.
pub struct DiskStorageManager {
    base_path: PathBuf,

    // Segmented header storage
    active_segments: Arc<RwLock<HashMap<u32, SegmentCache>>>,
    active_filter_segments: Arc<RwLock<HashMap<u32, FilterSegmentCache>>>,

    // Reverse index for O(1) lookups
    header_hash_index: Arc<RwLock<HashMap<BlockHash, u32>>>,

    // Background worker
    worker_tx: Option<mpsc::Sender<WorkerCommand>>,
    worker_handle: Option<tokio::task::JoinHandle<()>>,
    notification_rx: Arc<RwLock<mpsc::Receiver<WorkerNotification>>>,

    // Cached values
    cached_tip_height: Arc<RwLock<Option<u32>>>,
    cached_filter_tip_height: Arc<RwLock<Option<u32>>>,

    // Checkpoint sync support
    sync_base_height: Arc<RwLock<u32>>,

    // Mempool storage
    mempool_transactions: Arc<RwLock<HashMap<Txid, UnconfirmedTransaction>>>,
    mempool_state: Arc<RwLock<Option<MempoolState>>>,
}

/// Creates a sentinel header used for padding segments.
/// This header has invalid values that cannot be mistaken for valid blocks.
fn create_sentinel_header() -> BlockHeader {
    BlockHeader {
        version: Version::from_consensus(i32::MAX), // Invalid version
        prev_blockhash: BlockHash::from_byte_array([0xFF; 32]), // All 0xFF pattern
        merkle_root: dashcore::hashes::sha256d::Hash::from_byte_array([0xFF; 32]).into(),
        time: u32::MAX,                                  // Far future timestamp
        bits: CompactTarget::from_consensus(0xFFFFFFFF), // Invalid difficulty
        nonce: u32::MAX,                                 // Max nonce value
    }
}

impl DiskStorageManager {
    /// Start the background worker and notification channel.
    async fn start_worker(&mut self) {
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
    async fn stop_worker(&mut self) {
        if let Some(tx) = self.worker_tx.take() {
            let _ = tx.send(WorkerCommand::Shutdown).await;
        }
        if let Some(handle) = self.worker_handle.take() {
            let _ = handle.await;
        }
    }
    /// Create a new disk storage manager with segmented storage.
    pub async fn new(base_path: PathBuf) -> StorageResult<Self> {
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

        // Create background worker channels
        let (worker_tx, mut worker_rx) = mpsc::channel::<WorkerCommand>(100);
        let (notification_tx, notification_rx) = mpsc::channel::<WorkerNotification>(100);

        // Start background worker
        let worker_base_path = base_path.clone();
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
                    // Removed: SaveUtxoCache handling - UTXO management is now handled externally
                    WorkerCommand::Shutdown => {
                        break;
                    }
                }
            }
        });

        let mut storage = Self {
            base_path,
            active_segments: Arc::new(RwLock::new(HashMap::new())),
            active_filter_segments: Arc::new(RwLock::new(HashMap::new())),
            header_hash_index: Arc::new(RwLock::new(HashMap::new())),
            worker_tx: Some(worker_tx),
            worker_handle: Some(worker_handle),
            notification_rx: Arc::new(RwLock::new(notification_rx)),
            cached_tip_height: Arc::new(RwLock::new(None)),
            cached_filter_tip_height: Arc::new(RwLock::new(None)),
            sync_base_height: Arc::new(RwLock::new(0)),
            mempool_transactions: Arc::new(RwLock::new(HashMap::new())),
            mempool_state: Arc::new(RwLock::new(None)),
        };

        // Load segment metadata and rebuild index
        storage.load_segment_metadata().await?;

        // Load chain state to get sync_base_height
        if let Ok(Some(chain_state)) = storage.load_chain_state().await {
            *storage.sync_base_height.write().await = chain_state.sync_base_height;
            tracing::debug!("Loaded sync_base_height: {}", chain_state.sync_base_height);
        }

        Ok(storage)
    }

    /// Load segment metadata and rebuild indexes.
    async fn load_segment_metadata(&mut self) -> StorageResult<()> {
        // Load header index if it exists
        let index_path = self.base_path.join("headers/index.dat");
        let mut index_loaded = false;
        if index_path.exists() {
            if let Ok(index) = self.load_index_from_file(&index_path).await {
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
                    if let Ok(headers) = self.load_headers_from_file(&segment_path).await {
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
                self.ensure_segment_loaded(segment_id).await?;
                let segments = self.active_segments.read().await;
                if let Some(segment) = segments.get(&segment_id) {
                    let tip_height =
                        segment_id * HEADERS_PER_SEGMENT + segment.valid_count as u32 - 1;
                    *self.cached_tip_height.write().await = Some(tip_height);
                }
            }

            // If we have filter segments, load the highest one to find filter tip
            if let Some(segment_id) = max_filter_segment_id {
                self.ensure_filter_segment_loaded(segment_id).await?;
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

    /// Get the segment ID for a given height.
    fn get_segment_id(height: u32) -> u32 {
        height / HEADERS_PER_SEGMENT
    }

    /// Get the offset within a segment for a given height.
    fn get_segment_offset(height: u32) -> usize {
        (height % HEADERS_PER_SEGMENT) as usize
    }

    /// Ensure a segment is loaded in memory.
    async fn ensure_segment_loaded(&self, segment_id: u32) -> StorageResult<()> {
        // Process background worker notifications to clear save_pending flags
        self.process_worker_notifications().await;

        let mut segments = self.active_segments.write().await;

        if segments.contains_key(&segment_id) {
            // Update last accessed time
            if let Some(segment) = segments.get_mut(&segment_id) {
                segment.last_accessed = Instant::now();
            }
            return Ok(());
        }

        // Load segment from disk
        let segment_path = self.base_path.join(format!("headers/segment_{:04}.dat", segment_id));
        let mut headers = if segment_path.exists() {
            self.load_headers_from_file(&segment_path).await?
        } else {
            Vec::new()
        };

        // Store the actual number of valid headers before padding
        let valid_count = headers.len();

        // Ensure the segment has space for all possible headers in this segment
        // This is crucial for proper indexing
        let expected_size = HEADERS_PER_SEGMENT as usize;
        if headers.len() < expected_size {
            // Pad with sentinel headers that cannot be mistaken for valid blocks
            // Use max values for version and nonce, and specific invalid patterns
            let sentinel_header = create_sentinel_header();
            headers.resize(expected_size, sentinel_header);
        }

        // Evict old segments if needed
        if segments.len() >= MAX_ACTIVE_SEGMENTS {
            self.evict_oldest_segment(&mut segments).await?;
        }

        segments.insert(
            segment_id,
            SegmentCache {
                segment_id,
                headers,
                valid_count,
                state: SegmentState::Clean,
                last_saved: Instant::now(),
                last_accessed: Instant::now(),
            },
        );

        Ok(())
    }

    /// Evict the oldest (least recently accessed) segment.
    async fn evict_oldest_segment(
        &self,
        segments: &mut HashMap<u32, SegmentCache>,
    ) -> StorageResult<()> {
        if let Some(oldest_id) =
            segments.iter().min_by_key(|(_, s)| s.last_accessed).map(|(id, _)| *id)
        {
            // Get the segment to check if it needs saving
            if let Some(oldest_segment) = segments.get(&oldest_id) {
                // Save if dirty or saving before evicting - do it synchronously to ensure data consistency
                if oldest_segment.state != SegmentState::Clean {
                    tracing::debug!(
                        "Synchronously saving segment {} before eviction (state: {:?})",
                        oldest_segment.segment_id,
                        oldest_segment.state
                    );
                    let segment_path = self
                        .base_path
                        .join(format!("headers/segment_{:04}.dat", oldest_segment.segment_id));
                    save_segment_to_disk(&segment_path, &oldest_segment.headers).await?;
                    tracing::debug!(
                        "Successfully saved segment {} to disk",
                        oldest_segment.segment_id
                    );
                }
            }

            segments.remove(&oldest_id);
        }

        Ok(())
    }

    /// Ensure a filter segment is loaded in memory.
    async fn ensure_filter_segment_loaded(&self, segment_id: u32) -> StorageResult<()> {
        // Process background worker notifications to clear save_pending flags
        self.process_worker_notifications().await;

        let mut segments = self.active_filter_segments.write().await;

        if segments.contains_key(&segment_id) {
            // Update last accessed time
            if let Some(segment) = segments.get_mut(&segment_id) {
                segment.last_accessed = Instant::now();
            }
            return Ok(());
        }

        // Load segment from disk
        let segment_path =
            self.base_path.join(format!("filters/filter_segment_{:04}.dat", segment_id));
        let filter_headers = if segment_path.exists() {
            self.load_filter_headers_from_file(&segment_path).await?
        } else {
            Vec::new()
        };

        // Evict old segments if needed
        if segments.len() >= MAX_ACTIVE_SEGMENTS {
            self.evict_oldest_filter_segment(&mut segments).await?;
        }

        segments.insert(
            segment_id,
            FilterSegmentCache {
                segment_id,
                filter_headers,
                state: SegmentState::Clean,
                last_saved: Instant::now(),
                last_accessed: Instant::now(),
            },
        );

        Ok(())
    }

    /// Evict the oldest (least recently accessed) filter segment.
    async fn evict_oldest_filter_segment(
        &self,
        segments: &mut HashMap<u32, FilterSegmentCache>,
    ) -> StorageResult<()> {
        if let Some((oldest_id, oldest_segment)) =
            segments.iter().min_by_key(|(_, s)| s.last_accessed).map(|(id, s)| (*id, s.clone()))
        {
            // Save if dirty or saving before evicting - do it synchronously to ensure data consistency
            if oldest_segment.state != SegmentState::Clean {
                tracing::trace!(
                    "Synchronously saving filter segment {} before eviction (state: {:?})",
                    oldest_segment.segment_id,
                    oldest_segment.state
                );
                let segment_path = self
                    .base_path
                    .join(format!("filters/filter_segment_{:04}.dat", oldest_segment.segment_id));
                save_filter_segment_to_disk(&segment_path, &oldest_segment.filter_headers).await?;
                tracing::debug!(
                    "Successfully saved filter segment {} to disk",
                    oldest_segment.segment_id
                );
            }

            segments.remove(&oldest_id);
        }

        Ok(())
    }

    /// Process notifications from background worker to clear save_pending flags.
    async fn process_worker_notifications(&self) {
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
                } // Removed: UtxoCacheSaved - UTXO management is now handled externally
            }
        }
    }

    /// Save all dirty segments to disk via background worker.
    /// CRITICAL FIX: Only mark segments as save_pending, not clean, until background save actually completes.
    async fn save_dirty_segments(&self) -> StorageResult<()> {
        if let Some(tx) = &self.worker_tx {
            // Collect segments to save (only dirty ones)
            let (segments_to_save, segment_ids_to_mark) = {
                let segments = self.active_segments.read().await;
                let to_save: Vec<_> = segments
                    .values()
                    .filter(|s| s.state == SegmentState::Dirty)
                    .map(|s| (s.segment_id, s.headers.clone()))
                    .collect();
                let ids_to_mark: Vec<_> = to_save.iter().map(|(id, _)| *id).collect();
                (to_save, ids_to_mark)
            };

            // Send header segments to worker
            for (segment_id, headers) in segments_to_save {
                let _ = tx
                    .send(WorkerCommand::SaveHeaderSegment {
                        segment_id,
                        headers,
                    })
                    .await;
            }

            // Mark ONLY the header segments we're actually saving as Saving
            {
                let mut segments = self.active_segments.write().await;
                for segment_id in &segment_ids_to_mark {
                    if let Some(segment) = segments.get_mut(segment_id) {
                        segment.state = SegmentState::Saving;
                        segment.last_saved = Instant::now();
                    }
                }
            }

            // Collect filter segments to save (only dirty ones)
            let (filter_segments_to_save, filter_segment_ids_to_mark) = {
                let segments = self.active_filter_segments.read().await;
                let to_save: Vec<_> = segments
                    .values()
                    .filter(|s| s.state == SegmentState::Dirty)
                    .map(|s| (s.segment_id, s.filter_headers.clone()))
                    .collect();
                let ids_to_mark: Vec<_> = to_save.iter().map(|(id, _)| *id).collect();
                (to_save, ids_to_mark)
            };

            // Send filter segments to worker
            for (segment_id, filter_headers) in filter_segments_to_save {
                let _ = tx
                    .send(WorkerCommand::SaveFilterSegment {
                        segment_id,
                        filter_headers,
                    })
                    .await;
            }

            // Mark ONLY the filter segments we're actually saving as Saving
            {
                let mut segments = self.active_filter_segments.write().await;
                for segment_id in &filter_segment_ids_to_mark {
                    if let Some(segment) = segments.get_mut(segment_id) {
                        segment.state = SegmentState::Saving;
                        segment.last_saved = Instant::now();
                    }
                }
            }

            // Save the index
            let index = self.header_hash_index.read().await.clone();
            let _ = tx
                .send(WorkerCommand::SaveIndex {
                    index,
                })
                .await;

            // Removed: UTXO cache saving - UTXO management is now handled externally
        }

        Ok(())
    }

    /// Load headers from file.
    async fn load_headers_from_file(&self, path: &Path) -> StorageResult<Vec<BlockHeader>> {
        tokio::task::spawn_blocking({
            let path = path.to_path_buf();
            move || {
                let file = File::open(&path)?;
                let mut reader = BufReader::new(file);
                let mut headers = Vec::new();

                loop {
                    match BlockHeader::consensus_decode(&mut reader) {
                        Ok(header) => headers.push(header),
                        Err(encode::Error::Io(ref e))
                            if e.kind() == std::io::ErrorKind::UnexpectedEof =>
                        {
                            break
                        }
                        Err(e) => {
                            return Err(StorageError::ReadFailed(format!(
                                "Failed to decode header: {}",
                                e
                            )))
                        }
                    }
                }

                Ok(headers)
            }
        })
        .await
        .map_err(|e| StorageError::ReadFailed(format!("Task join error: {}", e)))?
    }

    /// Load filter headers from file.
    async fn load_filter_headers_from_file(&self, path: &Path) -> StorageResult<Vec<FilterHeader>> {
        tokio::task::spawn_blocking({
            let path = path.to_path_buf();
            move || {
                let file = File::open(&path)?;
                let mut reader = BufReader::new(file);
                let mut headers = Vec::new();

                loop {
                    match FilterHeader::consensus_decode(&mut reader) {
                        Ok(header) => headers.push(header),
                        Err(encode::Error::Io(ref e))
                            if e.kind() == std::io::ErrorKind::UnexpectedEof =>
                        {
                            break
                        }
                        Err(e) => {
                            return Err(StorageError::ReadFailed(format!(
                                "Failed to decode filter header: {}",
                                e
                            )))
                        }
                    }
                }

                Ok(headers)
            }
        })
        .await
        .map_err(|e| StorageError::ReadFailed(format!("Task join error: {}", e)))?
    }

    /// Load index from file.
    async fn load_index_from_file(&self, path: &Path) -> StorageResult<HashMap<BlockHash, u32>> {
        tokio::task::spawn_blocking({
            let path = path.to_path_buf();
            move || {
                let content = fs::read(&path)?;
                bincode::deserialize(&content).map_err(|e| {
                    StorageError::ReadFailed(format!("Failed to deserialize index: {}", e))
                })
            }
        })
        .await
        .map_err(|e| StorageError::ReadFailed(format!("Task join error: {}", e)))?
    }

    /// Store headers starting from a specific height (used for checkpoint sync)
    pub async fn store_headers_from_height(
        &mut self,
        headers: &[BlockHeader],
        start_height: u32,
    ) -> StorageResult<()> {
        // Early return if no headers to store
        if headers.is_empty() {
            tracing::trace!("DiskStorage: no headers to store");
            return Ok(());
        }

        // Acquire write locks for the entire operation to prevent race conditions
        let mut cached_tip = self.cached_tip_height.write().await;
        let mut reverse_index = self.header_hash_index.write().await;

        // For checkpoint sync, we need to track both:
        // - blockchain heights (for hash index and logging)
        // - storage indices (for cached_tip_height)
        let mut blockchain_height = start_height;
        let initial_blockchain_height = blockchain_height;

        // Get the current storage index (0-based count of headers in storage)
        let mut storage_index = match *cached_tip {
            Some(tip) => tip + 1,
            None => 0, // Start at index 0 if no headers stored yet
        };
        let initial_storage_index = storage_index;

        tracing::info!(
            "DiskStorage: storing {} headers starting at blockchain height {} (storage index {})",
            headers.len(),
            initial_blockchain_height,
            initial_storage_index
        );

        // Process each header
        for header in headers {
            // Use storage index for segment calculation (not blockchain height!)
            // This ensures headers are stored at the correct storage-relative positions
            let segment_id = Self::get_segment_id(storage_index);
            let offset = Self::get_segment_offset(storage_index);

            // Ensure segment is loaded
            self.ensure_segment_loaded(segment_id).await?;

            // Update segment
            {
                let mut segments = self.active_segments.write().await;
                if let Some(segment) = segments.get_mut(&segment_id) {
                    // Ensure we have space in the segment
                    if offset >= segment.headers.len() {
                        // Fill with sentinel headers up to the offset
                        let sentinel_header = create_sentinel_header();
                        segment.headers.resize(offset + 1, sentinel_header);
                    }
                    segment.headers[offset] = *header;
                    // Only increment valid_count when offset equals the current valid_count
                    // This ensures valid_count represents contiguous valid headers without gaps
                    if offset == segment.valid_count {
                        segment.valid_count += 1;
                    }
                    // Transition to Dirty state (from Clean, Dirty, or Saving)
                    segment.state = SegmentState::Dirty;
                    segment.last_accessed = Instant::now();
                }
            }

            // Update reverse index with blockchain height
            reverse_index.insert(header.block_hash(), blockchain_height);

            blockchain_height += 1;
            storage_index += 1;
        }

        // Update cached tip height with storage index (not blockchain height)
        // Only update if we actually stored headers
        if !headers.is_empty() {
            *cached_tip = Some(storage_index - 1);
        }

        let final_blockchain_height = if blockchain_height > 0 {
            blockchain_height - 1
        } else {
            0 // No headers were stored
        };

        let final_storage_index = if storage_index > 0 {
            storage_index - 1
        } else {
            0 // No headers were stored
        };

        tracing::info!(
            "DiskStorage: stored {} headers from checkpoint sync. Blockchain height: {} -> {}, Storage index: {} -> {}",
            headers.len(),
            initial_blockchain_height,
            final_blockchain_height,
            initial_storage_index,
            final_storage_index
        );

        // Release locks before saving (to avoid deadlocks during background saves)
        drop(reverse_index);
        drop(cached_tip);

        // Save dirty segments periodically (every 1000 headers)
        if headers.len() >= 1000 || blockchain_height.is_multiple_of(1000) {
            self.save_dirty_segments().await?;
        }

        Ok(())
    }

    // UTXO methods removed - handled by external wallet
}

/// Save a segment of headers to disk.
async fn save_segment_to_disk(path: &Path, headers: &[BlockHeader]) -> StorageResult<()> {
    tokio::task::spawn_blocking({
        let path = path.to_path_buf();
        let headers = headers.to_vec();
        move || {
            let file = OpenOptions::new().create(true).write(true).truncate(true).open(&path)?;
            let mut writer = BufWriter::new(file);

            // Only save actual headers, not sentinel headers
            for header in headers {
                // Skip sentinel headers (used for padding)
                if header.version.to_consensus() == i32::MAX
                    && header.time == u32::MAX
                    && header.nonce == u32::MAX
                    && header.prev_blockhash == BlockHash::from_byte_array([0xFF; 32])
                {
                    continue;
                }
                header.consensus_encode(&mut writer).map_err(|e| {
                    StorageError::WriteFailed(format!("Failed to encode header: {}", e))
                })?;
            }

            writer.flush()?;
            Ok(())
        }
    })
    .await
    .map_err(|e| StorageError::WriteFailed(format!("Task join error: {}", e)))?
}

/// Save a segment of filter headers to disk.
async fn save_filter_segment_to_disk(
    path: &Path,
    filter_headers: &[FilterHeader],
) -> StorageResult<()> {
    tokio::task::spawn_blocking({
        let path = path.to_path_buf();
        let filter_headers = filter_headers.to_vec();
        move || {
            let file = OpenOptions::new().create(true).write(true).truncate(true).open(&path)?;
            let mut writer = BufWriter::new(file);

            for header in filter_headers {
                header.consensus_encode(&mut writer).map_err(|e| {
                    StorageError::WriteFailed(format!("Failed to encode filter header: {}", e))
                })?;
            }

            writer.flush()?;
            Ok(())
        }
    })
    .await
    .map_err(|e| StorageError::WriteFailed(format!("Task join error: {}", e)))?
}

/// Save index to disk.
async fn save_index_to_disk(path: &Path, index: &HashMap<BlockHash, u32>) -> StorageResult<()> {
    tokio::task::spawn_blocking({
        let path = path.to_path_buf();
        let index = index.clone();
        move || {
            let data = bincode::serialize(&index).map_err(|e| {
                StorageError::WriteFailed(format!("Failed to serialize index: {}", e))
            })?;
            fs::write(&path, data)?;
            Ok(())
        }
    })
    .await
    .map_err(|e| StorageError::WriteFailed(format!("Task join error: {}", e)))?
}

#[async_trait]
impl StorageManager for DiskStorageManager {
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    async fn store_headers(&mut self, headers: &[BlockHeader]) -> StorageResult<()> {
        // Early return if no headers to store
        if headers.is_empty() {
            tracing::trace!("DiskStorage: no headers to store");
            return Ok(());
        }

        // Load chain state to get sync_base_height for proper blockchain height calculation
        let chain_state = self.load_chain_state().await?;
        let sync_base_height = chain_state.as_ref().map(|cs| cs.sync_base_height).unwrap_or(0);

        // Acquire write locks for the entire operation to prevent race conditions
        let mut cached_tip = self.cached_tip_height.write().await;
        let mut reverse_index = self.header_hash_index.write().await;

        let mut next_height = match *cached_tip {
            Some(tip) => tip + 1,
            None => 0, // Start at height 0 if no headers stored yet
        };

        let initial_height = next_height;
        // Calculate the blockchain height based on sync_base_height + storage index
        let initial_blockchain_height = sync_base_height + initial_height;

        // Use trace for single headers, debug for small batches, info for large batches
        match headers.len() {
            1 => tracing::trace!("DiskStorage: storing 1 header at blockchain height {} (storage index {})", 
                initial_blockchain_height, initial_height),
            2..=10 => tracing::debug!(
                "DiskStorage: storing {} headers starting at blockchain height {} (storage index {})",
                headers.len(),
                initial_blockchain_height,
                initial_height
            ),
            _ => tracing::info!(
                "DiskStorage: storing {} headers starting at blockchain height {} (storage index {})",
                headers.len(),
                initial_blockchain_height,
                initial_height
            ),
        }

        for header in headers {
            let segment_id = Self::get_segment_id(next_height);
            let offset = Self::get_segment_offset(next_height);

            // Ensure segment is loaded
            self.ensure_segment_loaded(segment_id).await?;

            // Update segment
            {
                let mut segments = self.active_segments.write().await;
                if let Some(segment) = segments.get_mut(&segment_id) {
                    // Ensure we have space in the segment
                    if offset >= segment.headers.len() {
                        // Fill with sentinel headers up to the offset
                        let sentinel_header = create_sentinel_header();
                        segment.headers.resize(offset + 1, sentinel_header);
                    }
                    segment.headers[offset] = *header;
                    // Only increment valid_count when offset equals the current valid_count
                    // This ensures valid_count represents contiguous valid headers without gaps
                    if offset == segment.valid_count {
                        segment.valid_count += 1;
                    }
                    // Transition to Dirty state (from Clean, Dirty, or Saving)
                    segment.state = SegmentState::Dirty;
                    segment.last_accessed = Instant::now();
                }
            }

            // Update reverse index with blockchain height (not storage index)
            let blockchain_height = sync_base_height + next_height;
            reverse_index.insert(header.block_hash(), blockchain_height);

            next_height += 1;
        }

        // Update cached tip height atomically with reverse index
        // Only update if we actually stored headers
        if !headers.is_empty() {
            *cached_tip = Some(next_height - 1);
        }

        let final_height = if next_height > 0 {
            next_height - 1
        } else {
            0 // No headers were stored
        };

        let final_blockchain_height = sync_base_height + final_height;

        // Use appropriate log level based on batch size
        match headers.len() {
            1 => tracing::trace!("DiskStorage: stored header at blockchain height {} (storage index {})", 
                final_blockchain_height, final_height),
            2..=10 => tracing::debug!(
                "DiskStorage: stored {} headers. Blockchain height: {} -> {} (storage index: {} -> {})",
                headers.len(),
                initial_blockchain_height,
                final_blockchain_height,
                initial_height,
                final_height
            ),
            _ => tracing::info!(
                "DiskStorage: stored {} headers. Blockchain height: {} -> {} (storage index: {} -> {})",
                headers.len(),
                initial_blockchain_height,
                final_blockchain_height,
                initial_height,
                final_height
            ),
        }

        // Release locks before saving (to avoid deadlocks during background saves)
        drop(reverse_index);
        drop(cached_tip);

        // Save dirty segments periodically (every 1000 headers)
        if headers.len() >= 1000 || next_height % 1000 == 0 {
            self.save_dirty_segments().await?;
        }

        Ok(())
    }

    async fn load_headers(&self, range: Range<u32>) -> StorageResult<Vec<BlockHeader>> {
        let mut headers = Vec::new();

        // Convert blockchain height range to storage index range using sync_base_height
        let sync_base_height = *self.sync_base_height.read().await;
        let storage_start = if sync_base_height > 0 && range.start >= sync_base_height {
            range.start - sync_base_height
        } else {
            range.start
        };

        let storage_end = if sync_base_height > 0 && range.end > sync_base_height {
            range.end - sync_base_height
        } else {
            range.end
        };

        let start_segment = Self::get_segment_id(storage_start);
        let end_segment = Self::get_segment_id(storage_end.saturating_sub(1));

        for segment_id in start_segment..=end_segment {
            self.ensure_segment_loaded(segment_id).await?;

            let segments = self.active_segments.read().await;
            if let Some(segment) = segments.get(&segment_id) {
                let start_idx = if segment_id == start_segment {
                    Self::get_segment_offset(storage_start)
                } else {
                    0
                };

                let end_idx = if segment_id == end_segment {
                    Self::get_segment_offset(storage_end.saturating_sub(1)) + 1
                } else {
                    segment.headers.len()
                };

                // Only include headers up to valid_count to avoid returning sentinel headers
                let actual_end_idx = end_idx.min(segment.valid_count);

                if start_idx < segment.headers.len()
                    && actual_end_idx <= segment.headers.len()
                    && start_idx < actual_end_idx
                {
                    headers.extend_from_slice(&segment.headers[start_idx..actual_end_idx]);
                }
            }
        }

        Ok(headers)
    }

    async fn get_header(&self, height: u32) -> StorageResult<Option<BlockHeader>> {
        // Accept blockchain (absolute) height and convert to storage index using sync_base_height.
        let sync_base_height = *self.sync_base_height.read().await;

        // Convert absolute height to storage index (base-inclusive mapping)
        let storage_index = if sync_base_height > 0 {
            if height >= sync_base_height {
                height - sync_base_height
            } else {
                // If caller passes a small value (likely a pre-conversion storage index), use it directly
                height
            }
        } else {
            height
        };

        // First check if this storage index is within our known range
        let tip_index_opt = *self.cached_tip_height.read().await;
        if let Some(tip_index) = tip_index_opt {
            if storage_index > tip_index {
                tracing::trace!(
                    "Requested header at storage index {} is beyond tip index {} (abs height {} base {})",
                    storage_index,
                    tip_index,
                    height,
                    sync_base_height
                );
                return Ok(None);
            }
        } else {
            tracing::trace!("No headers stored yet, returning None for height {}", height);
            return Ok(None);
        }

        let segment_id = Self::get_segment_id(storage_index);
        let offset = Self::get_segment_offset(storage_index);

        self.ensure_segment_loaded(segment_id).await?;

        let segments = self.active_segments.read().await;
        let header = segments.get(&segment_id).and_then(|segment| {
            // Check if this offset is within the valid range
            if offset < segment.valid_count {
                segment.headers.get(offset).copied()
            } else {
                // This is beyond the valid headers in this segment
                None
            }
        });

        if header.is_none() {
            tracing::debug!(
                "Header not found at storage index {} (segment: {}, offset: {}, abs height {}, base {})",
                storage_index,
                segment_id,
                offset,
                height,
                sync_base_height
            );
        }

        Ok(header)
    }

    async fn get_tip_height(&self) -> StorageResult<Option<u32>> {
        let tip_index_opt = *self.cached_tip_height.read().await;
        if let Some(tip_index) = tip_index_opt {
            let base = *self.sync_base_height.read().await;
            if base > 0 {
                Ok(Some(base + tip_index))
            } else {
                Ok(Some(tip_index))
            }
        } else {
            Ok(None)
        }
    }

    async fn store_filter_headers(&mut self, headers: &[FilterHeader]) -> StorageResult<()> {
        let sync_base_height = *self.sync_base_height.read().await;

        // Determine the next blockchain height
        let mut next_blockchain_height = {
            let current_tip = self.cached_filter_tip_height.read().await;
            match *current_tip {
                Some(tip) => tip + 1,
                None => {
                    // If we have a checkpoint, start from there, otherwise from 0
                    if sync_base_height > 0 {
                        sync_base_height
                    } else {
                        0
                    }
                }
            }
        };

        for header in headers {
            // Convert blockchain height to storage index
            let storage_index = if sync_base_height > 0 {
                // For checkpoint sync, storage index is relative to sync_base_height
                if next_blockchain_height >= sync_base_height {
                    next_blockchain_height - sync_base_height
                } else {
                    // This shouldn't happen in normal operation
                    tracing::warn!(
                        "Attempting to store filter header at height {} below sync_base_height {}",
                        next_blockchain_height,
                        sync_base_height
                    );
                    next_blockchain_height
                }
            } else {
                // For genesis sync, storage index equals blockchain height
                next_blockchain_height
            };

            let segment_id = Self::get_segment_id(storage_index);
            let offset = Self::get_segment_offset(storage_index);

            // Ensure segment is loaded
            self.ensure_filter_segment_loaded(segment_id).await?;

            // Update segment
            {
                let mut segments = self.active_filter_segments.write().await;
                if let Some(segment) = segments.get_mut(&segment_id) {
                    // Ensure we have space in the segment
                    if offset >= segment.filter_headers.len() {
                        // Fill with zero filter headers up to the offset
                        let zero_filter_header = FilterHeader::from_byte_array([0u8; 32]);
                        segment.filter_headers.resize(offset + 1, zero_filter_header);
                    }
                    segment.filter_headers[offset] = *header;
                    // Transition to Dirty state (from Clean, Dirty, or Saving)
                    segment.state = SegmentState::Dirty;
                    segment.last_accessed = Instant::now();
                }
            }

            next_blockchain_height += 1;
        }

        // Update cached tip height with blockchain height
        if next_blockchain_height > 0 {
            *self.cached_filter_tip_height.write().await = Some(next_blockchain_height - 1);
        }

        // Save dirty segments periodically (every 1000 filter headers)
        if headers.len() >= 1000 || next_blockchain_height % 1000 == 0 {
            self.save_dirty_segments().await?;
        }

        Ok(())
    }

    async fn load_filter_headers(&self, range: Range<u32>) -> StorageResult<Vec<FilterHeader>> {
        let sync_base_height = *self.sync_base_height.read().await;
        let mut filter_headers = Vec::new();

        // Convert blockchain height range to storage index range
        let storage_start = if sync_base_height > 0 && range.start >= sync_base_height {
            range.start - sync_base_height
        } else {
            range.start
        };

        let storage_end = if sync_base_height > 0 && range.end > sync_base_height {
            range.end - sync_base_height
        } else {
            range.end
        };

        let start_segment = Self::get_segment_id(storage_start);
        let end_segment = Self::get_segment_id(storage_end.saturating_sub(1));

        for segment_id in start_segment..=end_segment {
            self.ensure_filter_segment_loaded(segment_id).await?;

            let segments = self.active_filter_segments.read().await;
            if let Some(segment) = segments.get(&segment_id) {
                let start_idx = if segment_id == start_segment {
                    Self::get_segment_offset(storage_start)
                } else {
                    0
                };

                let end_idx = if segment_id == end_segment {
                    Self::get_segment_offset(storage_end.saturating_sub(1)) + 1
                } else {
                    segment.filter_headers.len()
                };

                if start_idx < segment.filter_headers.len()
                    && end_idx <= segment.filter_headers.len()
                {
                    filter_headers.extend_from_slice(&segment.filter_headers[start_idx..end_idx]);
                }
            }
        }

        Ok(filter_headers)
    }

    async fn get_filter_header(
        &self,
        blockchain_height: u32,
    ) -> StorageResult<Option<FilterHeader>> {
        let sync_base_height = *self.sync_base_height.read().await;

        // Convert blockchain height to storage index
        let storage_index = if sync_base_height > 0 {
            // For checkpoint sync, storage index is relative to sync_base_height
            if blockchain_height >= sync_base_height {
                blockchain_height - sync_base_height
            } else {
                // This shouldn't happen in normal operation, but handle it gracefully
                tracing::warn!(
                    "Attempting to get filter header at height {} below sync_base_height {}",
                    blockchain_height,
                    sync_base_height
                );
                return Ok(None);
            }
        } else {
            // For genesis sync, storage index equals blockchain height
            blockchain_height
        };

        let segment_id = Self::get_segment_id(storage_index);
        let offset = Self::get_segment_offset(storage_index);

        self.ensure_filter_segment_loaded(segment_id).await?;

        let segments = self.active_filter_segments.read().await;
        Ok(segments
            .get(&segment_id)
            .and_then(|segment| segment.filter_headers.get(offset))
            .copied())
    }

    async fn get_filter_tip_height(&self) -> StorageResult<Option<u32>> {
        Ok(*self.cached_filter_tip_height.read().await)
    }

    async fn store_masternode_state(&mut self, state: &MasternodeState) -> StorageResult<()> {
        let path = self.base_path.join("state/masternode.json");
        let json = serde_json::to_string_pretty(state).map_err(|e| {
            StorageError::Serialization(format!("Failed to serialize masternode state: {}", e))
        })?;

        tokio::fs::write(path, json).await?;
        Ok(())
    }

    async fn load_masternode_state(&self) -> StorageResult<Option<MasternodeState>> {
        let path = self.base_path.join("state/masternode.json");
        if !path.exists() {
            return Ok(None);
        }

        let content = tokio::fs::read_to_string(path).await?;
        let state = serde_json::from_str(&content).map_err(|e| {
            StorageError::Serialization(format!("Failed to deserialize masternode state: {}", e))
        })?;

        Ok(Some(state))
    }

    async fn store_chain_state(&mut self, state: &ChainState) -> StorageResult<()> {
        // Update our sync_base_height
        *self.sync_base_height.write().await = state.sync_base_height;

        // First store all headers
        // For checkpoint sync, we need to store headers starting from the checkpoint height
        if state.synced_from_checkpoint && state.sync_base_height > 0 && !state.headers.is_empty() {
            // Store headers starting from the checkpoint height
            self.store_headers_from_height(&state.headers, state.sync_base_height).await?;
        } else {
            self.store_headers(&state.headers).await?;
        }

        // Store filter headers
        self.store_filter_headers(&state.filter_headers).await?;

        // Store other state as JSON
        let state_data = serde_json::json!({
            "last_chainlock_height": state.last_chainlock_height,
            "last_chainlock_hash": state.last_chainlock_hash,
            "current_filter_tip": state.current_filter_tip,
            "last_masternode_diff_height": state.last_masternode_diff_height,
            "sync_base_height": state.sync_base_height,
            "synced_from_checkpoint": state.synced_from_checkpoint,
        });

        let path = self.base_path.join("state/chain.json");
        tokio::fs::write(path, state_data.to_string()).await?;

        Ok(())
    }

    async fn load_chain_state(&self) -> StorageResult<Option<ChainState>> {
        let path = self.base_path.join("state/chain.json");
        if !path.exists() {
            return Ok(None);
        }

        let content = tokio::fs::read_to_string(path).await?;
        let value: serde_json::Value = serde_json::from_str(&content).map_err(|e| {
            StorageError::Serialization(format!("Failed to parse chain state: {}", e))
        })?;

        let mut state = ChainState::default();

        // Load all headers
        if let Some(tip_height) = self.get_tip_height().await? {
            let range_start = if state.synced_from_checkpoint && state.sync_base_height > 0 {
                state.sync_base_height
            } else {
                0
            };
            state.headers = self.load_headers(range_start..tip_height + 1).await?;
        }

        // Load all filter headers
        if let Some(filter_tip_height) = self.get_filter_tip_height().await? {
            state.filter_headers = self.load_filter_headers(0..filter_tip_height + 1).await?;
        }

        state.last_chainlock_height =
            value.get("last_chainlock_height").and_then(|v| v.as_u64()).map(|h| h as u32);
        state.last_chainlock_hash =
            value.get("last_chainlock_hash").and_then(|v| v.as_str()).and_then(|s| s.parse().ok());
        state.current_filter_tip =
            value.get("current_filter_tip").and_then(|v| v.as_str()).and_then(|s| s.parse().ok());
        state.last_masternode_diff_height =
            value.get("last_masternode_diff_height").and_then(|v| v.as_u64()).map(|h| h as u32);

        // Load checkpoint sync fields
        state.sync_base_height =
            value.get("sync_base_height").and_then(|v| v.as_u64()).map(|h| h as u32).unwrap_or(0);
        state.synced_from_checkpoint =
            value.get("synced_from_checkpoint").and_then(|v| v.as_bool()).unwrap_or(false);

        Ok(Some(state))
    }

    async fn store_filter(&mut self, height: u32, filter: &[u8]) -> StorageResult<()> {
        let path = self.base_path.join(format!("filters/{}.dat", height));
        tokio::fs::write(path, filter).await?;
        Ok(())
    }

    async fn load_filter(&self, height: u32) -> StorageResult<Option<Vec<u8>>> {
        let path = self.base_path.join(format!("filters/{}.dat", height));
        if !path.exists() {
            return Ok(None);
        }

        let data = tokio::fs::read(path).await?;
        Ok(Some(data))
    }

    async fn store_metadata(&mut self, key: &str, value: &[u8]) -> StorageResult<()> {
        let path = self.base_path.join(format!("state/{}.dat", key));
        tokio::fs::write(path, value).await?;
        Ok(())
    }

    async fn load_metadata(&self, key: &str) -> StorageResult<Option<Vec<u8>>> {
        let path = self.base_path.join(format!("state/{}.dat", key));
        if !path.exists() {
            return Ok(None);
        }

        let data = tokio::fs::read(path).await?;
        Ok(Some(data))
    }

    async fn clear(&mut self) -> StorageResult<()> {
        // First, stop the background worker to avoid races with file deletion
        self.stop_worker().await;

        // Clear in-memory state
        self.active_segments.write().await.clear();
        self.active_filter_segments.write().await.clear();
        self.header_hash_index.write().await.clear();
        *self.cached_tip_height.write().await = None;
        *self.cached_filter_tip_height.write().await = None;
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
                        return Err(StorageError::Io(e));
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

    async fn clear_filters(&mut self) -> StorageResult<()> {
        // Stop worker to prevent concurrent writes to filter directories
        self.stop_worker().await;

        // Clear in-memory filter state
        self.active_filter_segments.write().await.clear();
        *self.cached_filter_tip_height.write().await = None;

        // Remove filter headers and compact filter files
        let filters_dir = self.base_path.join("filters");
        if filters_dir.exists() {
            tokio::fs::remove_dir_all(&filters_dir).await?;
        }
        tokio::fs::create_dir_all(&filters_dir).await?;

        // Restart background worker for future operations
        self.start_worker().await;

        Ok(())
    }

    async fn stats(&self) -> StorageResult<StorageStats> {
        let mut component_sizes = HashMap::new();
        let mut total_size = 0u64;

        // Calculate directory sizes
        if let Ok(mut entries) = tokio::fs::read_dir(&self.base_path).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if let Ok(metadata) = entry.metadata().await {
                    if metadata.is_file() {
                        total_size += metadata.len();
                    }
                }
            }
        }

        let header_count = self.cached_tip_height.read().await.map_or(0, |h| h as u64 + 1);
        let filter_header_count =
            self.cached_filter_tip_height.read().await.map_or(0, |h| h as u64 + 1);

        component_sizes.insert("headers".to_string(), header_count * 80);
        component_sizes.insert("filter_headers".to_string(), filter_header_count * 32);
        component_sizes
            .insert("index".to_string(), self.header_hash_index.read().await.len() as u64 * 40);

        Ok(StorageStats {
            header_count,
            filter_header_count,
            filter_count: 0, // TODO: Count filter files
            total_size,
            component_sizes,
        })
    }

    async fn get_header_height_by_hash(
        &self,
        hash: &dashcore::BlockHash,
    ) -> StorageResult<Option<u32>> {
        Ok(self.header_hash_index.read().await.get(hash).copied())
    }

    async fn get_headers_batch(
        &self,
        start_height: u32,
        end_height: u32,
    ) -> StorageResult<Vec<(u32, BlockHeader)>> {
        if start_height > end_height {
            return Ok(Vec::new());
        }

        // Use the existing load_headers method which handles segmentation internally
        // Note: Range is exclusive at the end, so we need end_height + 1
        let range_end = end_height.saturating_add(1);
        let headers = self.load_headers(start_height..range_end).await?;

        // Convert to the expected format with heights
        let mut results = Vec::with_capacity(headers.len());
        for (idx, header) in headers.into_iter().enumerate() {
            results.push((start_height + idx as u32, header));
        }

        Ok(results)
    }

    // UTXO methods removed - handled by external wallet

    async fn store_sync_state(
        &mut self,
        state: &crate::storage::PersistentSyncState,
    ) -> StorageResult<()> {
        let path = self.base_path.join("sync_state.json");

        // Serialize to JSON for human readability and easy debugging
        let json = serde_json::to_string_pretty(state).map_err(|e| {
            StorageError::WriteFailed(format!("Failed to serialize sync state: {}", e))
        })?;

        // Write to a temporary file first for atomicity
        let temp_path = path.with_extension("tmp");
        tokio::fs::write(&temp_path, json.as_bytes()).await?;

        // Atomically rename to final path
        tokio::fs::rename(&temp_path, &path).await?;

        tracing::debug!("Saved sync state at height {}", state.chain_tip.height);
        Ok(())
    }

    async fn load_sync_state(&self) -> StorageResult<Option<crate::storage::PersistentSyncState>> {
        let path = self.base_path.join("sync_state.json");

        if !path.exists() {
            tracing::debug!("No sync state file found");
            return Ok(None);
        }

        let json = tokio::fs::read_to_string(&path).await?;
        let state: crate::storage::PersistentSyncState =
            serde_json::from_str(&json).map_err(|e| {
                StorageError::ReadFailed(format!("Failed to deserialize sync state: {}", e))
            })?;

        tracing::debug!("Loaded sync state from height {}", state.chain_tip.height);
        Ok(Some(state))
    }

    async fn clear_sync_state(&mut self) -> StorageResult<()> {
        let path = self.base_path.join("sync_state.json");
        if path.exists() {
            tokio::fs::remove_file(&path).await?;
            tracing::debug!("Cleared sync state");
        }
        Ok(())
    }

    async fn store_sync_checkpoint(
        &mut self,
        height: u32,
        checkpoint: &crate::storage::sync_state::SyncCheckpoint,
    ) -> StorageResult<()> {
        let checkpoints_dir = self.base_path.join("checkpoints");
        tokio::fs::create_dir_all(&checkpoints_dir).await?;

        let path = checkpoints_dir.join(format!("checkpoint_{:08}.json", height));
        let json = serde_json::to_string(checkpoint).map_err(|e| {
            StorageError::WriteFailed(format!("Failed to serialize checkpoint: {}", e))
        })?;

        tokio::fs::write(&path, json.as_bytes()).await?;
        tracing::debug!("Stored checkpoint at height {}", height);
        Ok(())
    }

    async fn get_sync_checkpoints(
        &self,
        start_height: u32,
        end_height: u32,
    ) -> StorageResult<Vec<crate::storage::sync_state::SyncCheckpoint>> {
        let checkpoints_dir = self.base_path.join("checkpoints");

        if !checkpoints_dir.exists() {
            return Ok(Vec::new());
        }

        let mut checkpoints: Vec<super::sync_state::SyncCheckpoint> = Vec::new();
        let mut entries = tokio::fs::read_dir(&checkpoints_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();

            // Parse height from filename
            if let Some(height_str) =
                file_name_str.strip_prefix("checkpoint_").and_then(|s| s.strip_suffix(".json"))
            {
                if let Ok(height) = height_str.parse::<u32>() {
                    if height >= start_height && height <= end_height {
                        let path = entry.path();
                        let json = tokio::fs::read_to_string(&path).await?;
                        if let Ok(checkpoint) =
                            serde_json::from_str::<super::sync_state::SyncCheckpoint>(&json)
                        {
                            checkpoints.push(checkpoint);
                        }
                    }
                }
            }
        }

        // Sort by height
        checkpoints.sort_by_key(|c| c.height);
        Ok(checkpoints)
    }

    async fn store_chain_lock(
        &mut self,
        height: u32,
        chain_lock: &dashcore::ChainLock,
    ) -> StorageResult<()> {
        let chainlocks_dir = self.base_path.join("chainlocks");
        tokio::fs::create_dir_all(&chainlocks_dir).await?;

        let path = chainlocks_dir.join(format!("chainlock_{:08}.bin", height));
        let data = bincode::serialize(chain_lock).map_err(|e| {
            StorageError::WriteFailed(format!("Failed to serialize chain lock: {}", e))
        })?;

        tokio::fs::write(&path, &data).await?;
        tracing::debug!("Stored chain lock at height {}", height);
        Ok(())
    }

    async fn load_chain_lock(&self, height: u32) -> StorageResult<Option<dashcore::ChainLock>> {
        let path = self.base_path.join("chainlocks").join(format!("chainlock_{:08}.bin", height));

        if !path.exists() {
            return Ok(None);
        }

        let data = tokio::fs::read(&path).await?;
        let chain_lock = bincode::deserialize(&data).map_err(|e| {
            StorageError::ReadFailed(format!("Failed to deserialize chain lock: {}", e))
        })?;

        Ok(Some(chain_lock))
    }

    async fn get_chain_locks(
        &self,
        start_height: u32,
        end_height: u32,
    ) -> StorageResult<Vec<(u32, dashcore::ChainLock)>> {
        let chainlocks_dir = self.base_path.join("chainlocks");

        if !chainlocks_dir.exists() {
            return Ok(Vec::new());
        }

        let mut chain_locks = Vec::new();
        let mut entries = tokio::fs::read_dir(&chainlocks_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();

            // Parse height from filename
            if let Some(height_str) =
                file_name_str.strip_prefix("chainlock_").and_then(|s| s.strip_suffix(".bin"))
            {
                if let Ok(height) = height_str.parse::<u32>() {
                    if height >= start_height && height <= end_height {
                        let path = entry.path();
                        let data = tokio::fs::read(&path).await?;
                        if let Ok(chain_lock) = bincode::deserialize(&data) {
                            chain_locks.push((height, chain_lock));
                        }
                    }
                }
            }
        }

        // Sort by height
        chain_locks.sort_by_key(|(h, _)| *h);
        Ok(chain_locks)
    }

    async fn store_instant_lock(
        &mut self,
        txid: dashcore::Txid,
        instant_lock: &dashcore::InstantLock,
    ) -> StorageResult<()> {
        let islocks_dir = self.base_path.join("islocks");
        tokio::fs::create_dir_all(&islocks_dir).await?;

        let path = islocks_dir.join(format!("islock_{}.bin", txid));
        let data = bincode::serialize(instant_lock).map_err(|e| {
            StorageError::WriteFailed(format!("Failed to serialize instant lock: {}", e))
        })?;

        tokio::fs::write(&path, &data).await?;
        tracing::debug!("Stored instant lock for txid {}", txid);
        Ok(())
    }

    async fn load_instant_lock(
        &self,
        txid: dashcore::Txid,
    ) -> StorageResult<Option<dashcore::InstantLock>> {
        let path = self.base_path.join("islocks").join(format!("islock_{}.bin", txid));

        if !path.exists() {
            return Ok(None);
        }

        let data = tokio::fs::read(&path).await?;
        let instant_lock = bincode::deserialize(&data).map_err(|e| {
            StorageError::ReadFailed(format!("Failed to deserialize instant lock: {}", e))
        })?;

        Ok(Some(instant_lock))
    }

    // Mempool storage methods
    async fn store_mempool_transaction(
        &mut self,
        txid: &Txid,
        tx: &UnconfirmedTransaction,
    ) -> StorageResult<()> {
        self.mempool_transactions.write().await.insert(*txid, tx.clone());
        Ok(())
    }

    async fn remove_mempool_transaction(&mut self, txid: &Txid) -> StorageResult<()> {
        self.mempool_transactions.write().await.remove(txid);
        Ok(())
    }

    async fn get_mempool_transaction(
        &self,
        txid: &Txid,
    ) -> StorageResult<Option<UnconfirmedTransaction>> {
        Ok(self.mempool_transactions.read().await.get(txid).cloned())
    }

    async fn get_all_mempool_transactions(
        &self,
    ) -> StorageResult<HashMap<Txid, UnconfirmedTransaction>> {
        Ok(self.mempool_transactions.read().await.clone())
    }

    async fn store_mempool_state(&mut self, state: &MempoolState) -> StorageResult<()> {
        *self.mempool_state.write().await = Some(state.clone());
        Ok(())
    }

    async fn load_mempool_state(&self) -> StorageResult<Option<MempoolState>> {
        Ok(self.mempool_state.read().await.clone())
    }

    async fn clear_mempool(&mut self) -> StorageResult<()> {
        self.mempool_transactions.write().await.clear();
        *self.mempool_state.write().await = None;
        Ok(())
    }

    /// Shutdown the storage manager.
    async fn shutdown(&mut self) -> StorageResult<()> {
        // Save all dirty segments
        self.save_dirty_segments().await?;

        // Shutdown background worker
        if let Some(tx) = self.worker_tx.take() {
            let _ = tx.send(WorkerCommand::Shutdown).await;
        }

        if let Some(handle) = self.worker_handle.take() {
            let _ = handle.await;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_sentinel_headers_not_returned() -> Result<(), Box<dyn std::error::Error>> {
        // Create a temporary directory for the test
        let temp_dir = TempDir::new()?;
        let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await?;

        // Create a test header
        let test_header = BlockHeader {
            version: Version::from_consensus(1),
            prev_blockhash: BlockHash::from_byte_array([1; 32]),
            merkle_root: dashcore::hashes::sha256d::Hash::from_byte_array([2; 32]).into(),
            time: 12345,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 67890,
        };

        // Store just one header
        storage.store_headers(&[test_header]).await?;

        // Load headers for a range that would include padding
        let loaded_headers = storage.load_headers(0..10).await?;

        // Should only get back the one header we stored, not the sentinel padding
        assert_eq!(loaded_headers.len(), 1);
        assert_eq!(loaded_headers[0], test_header);

        // Try to get a header at index 5 (which would be a sentinel)
        let header_at_5 = storage.get_header(5).await?;
        assert!(header_at_5.is_none(), "Should not return sentinel headers");

        Ok(())
    }

    #[tokio::test]
    async fn test_sentinel_headers_not_saved_to_disk() -> Result<(), Box<dyn std::error::Error>> {
        // Create a temporary directory for the test
        let temp_dir = TempDir::new()?;
        let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await?;

        // Create test headers
        let headers: Vec<BlockHeader> = (0..3)
            .map(|i| BlockHeader {
                version: Version::from_consensus(1),
                prev_blockhash: BlockHash::from_byte_array([i as u8; 32]),
                merkle_root: dashcore::hashes::sha256d::Hash::from_byte_array([(i + 1) as u8; 32])
                    .into(),
                time: 12345 + i,
                bits: CompactTarget::from_consensus(0x1d00ffff),
                nonce: 67890 + i,
            })
            .collect();

        // Store headers
        storage.store_headers(&headers).await?;

        // Force save to disk
        storage.save_dirty_segments().await?;

        // Wait a bit for background save
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Create a new storage instance to load from disk
        let storage2 = DiskStorageManager::new(temp_dir.path().to_path_buf()).await?;

        // Load headers - should only get the 3 we stored
        let loaded_headers = storage2.load_headers(0..HEADERS_PER_SEGMENT).await?;
        assert_eq!(loaded_headers.len(), 3);

        Ok(())
    }

    #[tokio::test]
    async fn test_checkpoint_storage_indexing() -> StorageResult<()> {
        use crate::types::ChainState;
        use dashcore::TxMerkleNode;
        use tempfile::tempdir;

        let temp_dir = tempdir().expect("Failed to create temp dir");
        let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await?;

        // Create test headers starting from checkpoint height
        let checkpoint_height = 1_100_000;
        let headers: Vec<BlockHeader> = (0..100)
            .map(|i| BlockHeader {
                version: Version::from_consensus(1),
                prev_blockhash: BlockHash::from_byte_array([i as u8; 32]),
                merkle_root: TxMerkleNode::from_byte_array([(i + 1) as u8; 32]),
                time: 1234567890 + i,
                bits: CompactTarget::from_consensus(0x1a2b3c4d),
                nonce: 67890 + i,
            })
            .collect();

        // Store headers using checkpoint sync method
        storage.store_headers_from_height(&headers, checkpoint_height).await?;

        // Set sync base height so storage interprets heights as blockchain heights
        let mut base_state = ChainState::new();
        base_state.sync_base_height = checkpoint_height;
        base_state.synced_from_checkpoint = true;
        storage.store_chain_state(&base_state).await?;

        // Verify headers are stored at correct blockchain heights
        // Header at blockchain height 1,100,000 should be retrievable by that height
        let header_at_base = storage.get_header(checkpoint_height).await?;
        assert!(header_at_base.is_some(), "Header at base blockchain height should exist");
        assert_eq!(header_at_base.unwrap(), headers[0]);

        // Header at blockchain height 1,100,099 should be retrievable by that height
        let header_at_ending = storage.get_header(checkpoint_height + 99).await?;
        assert!(header_at_ending.is_some(), "Header at ending blockchain height should exist");
        assert_eq!(header_at_ending.unwrap(), headers[99]);

        // Test the reverse index (hash -> blockchain height)
        let hash_0 = headers[0].block_hash();
        let height_0 = storage.get_header_height_by_hash(&hash_0).await?;
        assert_eq!(
            height_0,
            Some(checkpoint_height),
            "Hash should map to blockchain height 1,100,000"
        );

        let hash_99 = headers[99].block_hash();
        let height_99 = storage.get_header_height_by_hash(&hash_99).await?;
        assert_eq!(
            height_99,
            Some(checkpoint_height + 99),
            "Hash should map to blockchain height 1,100,099"
        );

        // Store chain state to persist sync_base_height
        let mut chain_state = ChainState::new();
        chain_state.sync_base_height = checkpoint_height;
        chain_state.synced_from_checkpoint = true;
        storage.store_chain_state(&chain_state).await?;

        // Force save to disk
        storage.save_dirty_segments().await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Create a new storage instance to test index rebuilding
        let storage2 = DiskStorageManager::new(temp_dir.path().to_path_buf()).await?;

        // Verify the index was rebuilt correctly
        let height_after_rebuild = storage2.get_header_height_by_hash(&hash_0).await?;
        assert_eq!(
            height_after_rebuild,
            Some(checkpoint_height),
            "After index rebuild, hash should still map to blockchain height 1,100,000"
        );

        // Verify header can still be retrieved by blockchain height after reload
        let header_after_reload = storage2.get_header(checkpoint_height).await?;
        assert!(
            header_after_reload.is_some(),
            "Header at base blockchain height should exist after reload"
        );
        assert_eq!(header_after_reload.unwrap(), headers[0]);

        Ok(())
    }
}
