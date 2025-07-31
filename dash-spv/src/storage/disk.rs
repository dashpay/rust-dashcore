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
    Address, BlockHash, OutPoint, Txid,
};
use dashcore_hashes::Hash;

use crate::error::{StorageError, StorageResult};
use crate::storage::{MasternodeState, StorageManager, StorageStats, StoredTerminalBlock};
use crate::types::{ChainState, MempoolState, UnconfirmedTransaction};
use crate::wallet::Utxo;

/// Number of headers per segment file
const HEADERS_PER_SEGMENT: u32 = 50_000;

/// Maximum number of segments to keep in memory
const MAX_ACTIVE_SEGMENTS: usize = 10;

/// How often to save dirty segments (seconds)
#[allow(dead_code)]
const SAVE_INTERVAL_SECS: u64 = 10;

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
    SaveUtxoCache {
        utxos: HashMap<OutPoint, Utxo>,
    },
    Shutdown,
}

/// Notifications from the background worker
#[derive(Debug, Clone)]
enum WorkerNotification {
    HeaderSegmentSaved {
        segment_id: u32,
    },
    FilterSegmentSaved {
        segment_id: u32,
    },
    IndexSaved,
    UtxoCacheSaved,
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

    // In-memory UTXO cache for high performance
    utxo_cache: Arc<RwLock<HashMap<OutPoint, Utxo>>>,
    utxo_address_index: Arc<RwLock<HashMap<Address, Vec<OutPoint>>>>,
    utxo_cache_dirty: Arc<RwLock<bool>>,

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
                    WorkerCommand::SaveUtxoCache {
                        utxos,
                    } => {
                        let path = worker_base_path.join("state/utxos.dat");
                        if let Err(e) = save_utxo_cache_to_disk(&path, &utxos).await {
                            eprintln!("Failed to save UTXO cache: {}", e);
                        } else {
                            tracing::trace!("Background worker completed saving UTXO cache");
                            let _ = worker_notification_tx
                                .send(WorkerNotification::UtxoCacheSaved)
                                .await;
                        }
                    }
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
            utxo_cache: Arc::new(RwLock::new(HashMap::new())),
            utxo_address_index: Arc::new(RwLock::new(HashMap::new())),
            utxo_cache_dirty: Arc::new(RwLock::new(false)),
            mempool_transactions: Arc::new(RwLock::new(HashMap::new())),
            mempool_state: Arc::new(RwLock::new(None)),
        };

        // Load segment metadata and rebuild index
        storage.load_segment_metadata().await?;

        // Load UTXO cache from disk
        storage.load_utxo_cache_into_memory().await?;

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
                let mut new_index = HashMap::new();

                // Sort segment IDs to process in order
                all_segment_ids.sort();

                for segment_id in all_segment_ids {
                    let segment_path =
                        self.base_path.join(format!("headers/segment_{:04}.dat", segment_id));
                    if let Ok(headers) = self.load_headers_from_file(&segment_path).await {
                        let start_height = segment_id * HEADERS_PER_SEGMENT;
                        for (offset, header) in headers.iter().enumerate() {
                            let height = start_height + offset as u32;
                            let hash = header.block_hash();
                            new_index.insert(hash, height);
                        }
                    }
                }

                *self.header_hash_index.write().await = new_index;
                tracing::info!(
                    "Index rebuilt with {} entries",
                    self.header_hash_index.read().await.len()
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
                    let tip_height =
                        segment_id * HEADERS_PER_SEGMENT + segment.filter_headers.len() as u32 - 1;
                    *self.cached_filter_tip_height.write().await = Some(tip_height);
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
                }
                WorkerNotification::UtxoCacheSaved => {
                    tracing::debug!("UTXO cache save completed");
                }
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

            // Save UTXO cache if dirty
            let is_dirty = *self.utxo_cache_dirty.read().await;
            if is_dirty {
                let utxos = self.utxo_cache.read().await.clone();
                let _ = tx
                    .send(WorkerCommand::SaveUtxoCache {
                        utxos,
                    })
                    .await;
                *self.utxo_cache_dirty.write().await = false;
            }
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

        let mut next_height = start_height;
        let initial_height = next_height;

        tracing::info!(
            "DiskStorage: storing {} headers starting at height {} (checkpoint sync)",
            headers.len(),
            initial_height
        );

        // Process each header
        for header in headers {
            let segment_id = Self::get_segment_id(next_height);
            let offset = Self::get_segment_offset(next_height);

            // Ensure segment is loaded BEFORE acquiring locks to avoid deadlock
            self.ensure_segment_loaded(segment_id).await?;

            // Now acquire write locks for the update operation
            let mut cached_tip = self.cached_tip_height.write().await;
            let mut reverse_index = self.header_hash_index.write().await;

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

            // Update reverse index
            reverse_index.insert(header.block_hash(), next_height);

            // Update cached tip for each header to keep it current
            *cached_tip = Some(next_height);

            // Release locks before processing next header to avoid holding them too long
            drop(reverse_index);
            drop(cached_tip);

            next_height += 1;
        }

        let final_height = if next_height > 0 {
            next_height - 1
        } else {
            0 // No headers were stored
        };

        tracing::info!(
            "DiskStorage: stored {} headers from checkpoint sync. Height: {} -> {}",
            headers.len(),
            initial_height,
            final_height
        );

        // Save dirty segments periodically
        // - Every 100 headers when storing small batches (common during sync)
        // - Every 1000 headers when storing large batches
        // - At multiples of 1000 for checkpoint saves
        let should_save = if headers.len() <= 10 {
            // For small batches (1-10 headers), save every 100 headers
            next_height % 100 == 0
        } else if headers.len() >= 1000 {
            // For large batches, always save
            true
        } else {
            // For medium batches, save at 1000 boundaries
            next_height % 1000 == 0
        };

        tracing::debug!(
            "DiskStorage: should_save = {}, next_height = {}, headers.len() = {}",
            should_save,
            next_height,
            headers.len()
        );
        if should_save {
            self.save_dirty_segments().await?;
        }

        Ok(())
    }

    /// Shutdown the storage manager.
    pub async fn shutdown(&mut self) -> StorageResult<()> {
        // Save all dirty segments
        self.save_dirty_segments().await?;

        // Persist UTXO cache if dirty
        self.persist_utxo_cache_if_dirty().await?;

        // Shutdown background worker
        if let Some(tx) = self.worker_tx.take() {
            let _ = tx.send(WorkerCommand::Shutdown).await;
        }

        if let Some(handle) = self.worker_handle.take() {
            let _ = handle.await;
        }

        Ok(())
    }

    /// Load the consolidated UTXO cache from disk.
    async fn load_utxo_cache(&self) -> StorageResult<HashMap<OutPoint, Utxo>> {
        let path = self.base_path.join("state/utxos.dat");
        if !path.exists() {
            return Ok(HashMap::new());
        }

        let data = tokio::fs::read(path).await?;
        if data.is_empty() {
            return Ok(HashMap::new());
        }

        let utxos = bincode::deserialize::<HashMap<OutPoint, Utxo>>(&data).map_err(|e| {
            StorageError::Serialization(format!("Failed to deserialize UTXO cache: {}", e))
        })?;

        Ok(utxos)
    }

    /// Store the consolidated UTXO cache to disk.
    async fn store_utxo_cache(&self, utxos: &HashMap<OutPoint, Utxo>) -> StorageResult<()> {
        let path = self.base_path.join("state/utxos.dat");

        // Ensure the directory exists
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let data = bincode::serialize(utxos).map_err(|e| {
            StorageError::Serialization(format!("Failed to serialize UTXO cache: {}", e))
        })?;

        // Atomic write using temporary file
        let temp_path = path.with_extension("tmp");
        tokio::fs::write(&temp_path, &data).await?;
        tokio::fs::rename(&temp_path, &path).await?;

        Ok(())
    }

    /// Load UTXO cache from disk into memory on startup.
    async fn load_utxo_cache_into_memory(&self) -> StorageResult<()> {
        let utxos = self.load_utxo_cache().await?;

        // Populate in-memory cache
        {
            let mut cache = self.utxo_cache.write().await;
            *cache = utxos.clone();
        }

        // Build address index
        {
            let mut address_index = self.utxo_address_index.write().await;
            address_index.clear();

            for (outpoint, utxo) in &utxos {
                let entry = address_index.entry(utxo.address.clone()).or_insert_with(Vec::new);
                entry.push(*outpoint);
            }
        }

        // Mark cache as clean
        *self.utxo_cache_dirty.write().await = false;

        tracing::info!("Loaded {} UTXOs into memory cache with address indexing", utxos.len());
        Ok(())
    }

    /// Persist UTXO cache to disk if dirty.
    async fn persist_utxo_cache_if_dirty(&self) -> StorageResult<()> {
        let is_dirty = *self.utxo_cache_dirty.read().await;
        if !is_dirty {
            return Ok(());
        }

        let utxos = self.utxo_cache.read().await.clone();
        self.store_utxo_cache(&utxos).await?;

        // Mark as clean after successful persist
        *self.utxo_cache_dirty.write().await = false;

        tracing::debug!("Persisted {} UTXOs to disk", utxos.len());
        Ok(())
    }

    /// Update the address index when adding a UTXO.
    async fn update_address_index_add(&self, outpoint: OutPoint, utxo: &Utxo) {
        let mut address_index = self.utxo_address_index.write().await;
        let entry = address_index.entry(utxo.address.clone()).or_insert_with(Vec::new);
        if !entry.contains(&outpoint) {
            entry.push(outpoint);
        }
    }

    /// Update the address index when removing a UTXO.
    async fn update_address_index_remove(&self, outpoint: &OutPoint, utxo: &Utxo) {
        let mut address_index = self.utxo_address_index.write().await;
        if let Some(entry) = address_index.get_mut(&utxo.address) {
            entry.retain(|op| op != outpoint);
            if entry.is_empty() {
                address_index.remove(&utxo.address);
            }
        }
    }
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

/// Save UTXO cache to disk.
async fn save_utxo_cache_to_disk(
    path: &Path,
    utxos: &HashMap<OutPoint, Utxo>,
) -> StorageResult<()> {
    tokio::task::spawn_blocking({
        let path = path.to_path_buf();
        let utxos = utxos.clone();
        move || {
            // Ensure the directory exists
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let data = bincode::serialize(&utxos).map_err(|e| {
                StorageError::WriteFailed(format!("Failed to serialize UTXO cache: {}", e))
            })?;

            // Atomic write using temporary file
            let temp_path = path.with_extension("tmp");
            std::fs::write(&temp_path, &data)?;
            std::fs::rename(&temp_path, &path)?;

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

        // Acquire write locks for the entire operation to prevent race conditions
        let mut cached_tip = self.cached_tip_height.write().await;
        let mut reverse_index = self.header_hash_index.write().await;

        let mut next_height = match *cached_tip {
            Some(tip) => tip + 1,
            None => 0, // Start at height 0 if no headers stored yet
        };

        let initial_height = next_height;

        // Use trace for single headers, debug for small batches, info for large batches
        match headers.len() {
            1 => tracing::trace!("DiskStorage: storing 1 header at height {}", initial_height),
            2..=10 => tracing::debug!(
                "DiskStorage: storing {} headers starting at height {}",
                headers.len(),
                initial_height
            ),
            _ => tracing::info!(
                "DiskStorage: storing {} headers starting at height {}",
                headers.len(),
                initial_height
            ),
        }

        for header in headers {
            let segment_id = Self::get_segment_id(next_height);
            let offset = Self::get_segment_offset(next_height);

            // Debug logging for hang investigation
            if next_height == 2310663 {
                tracing::warn!(
                    "🔍 Processing header at critical height 2310663 - segment_id: {}, offset: {}",
                    segment_id,
                    offset
                );
            }

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

            // Update reverse index (atomically with tip height)
            reverse_index.insert(header.block_hash(), next_height);

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

        // Use appropriate log level based on batch size
        match headers.len() {
            1 => tracing::trace!("DiskStorage: stored header at height {}", final_height),
            2..=10 => tracing::debug!(
                "DiskStorage: stored {} headers. Height: {} -> {}",
                headers.len(),
                if initial_height > 0 {
                    initial_height - 1
                } else {
                    0
                },
                final_height
            ),
            _ => tracing::info!(
                "DiskStorage: stored {} headers. Height: {} -> {}",
                headers.len(),
                if initial_height > 0 {
                    initial_height - 1
                } else {
                    0
                },
                final_height
            ),
        }

        // Release locks before saving (to avoid deadlocks during background saves)
        drop(reverse_index);
        drop(cached_tip);

        // Save dirty segments periodically
        // - Every 100 headers when storing small batches (common during sync)
        // - Every 1000 headers when storing large batches
        // - At multiples of 1000 for checkpoint saves
        let should_save = if headers.len() <= 10 {
            // For small batches (1-10 headers), save every 100 headers
            next_height % 100 == 0
        } else if headers.len() >= 1000 {
            // For large batches, always save
            true
        } else {
            // For medium batches, save at 1000 boundaries
            next_height % 1000 == 0
        };

        if should_save {
            self.save_dirty_segments().await?;
        }

        Ok(())
    }

    async fn load_headers(&self, range: Range<u32>) -> StorageResult<Vec<BlockHeader>> {
        let mut headers = Vec::new();

        let start_segment = Self::get_segment_id(range.start);
        let end_segment = Self::get_segment_id(range.end.saturating_sub(1));

        for segment_id in start_segment..=end_segment {
            self.ensure_segment_loaded(segment_id).await?;

            let segments = self.active_segments.read().await;
            if let Some(segment) = segments.get(&segment_id) {
                let _segment_start_height = segment_id * HEADERS_PER_SEGMENT;
                let _segment_end_height = _segment_start_height + segment.headers.len() as u32;

                let start_idx = if segment_id == start_segment {
                    Self::get_segment_offset(range.start)
                } else {
                    0
                };

                let end_idx = if segment_id == end_segment {
                    Self::get_segment_offset(range.end.saturating_sub(1)) + 1
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
        // First check if this height is within our known range
        let tip_height = self.cached_tip_height.read().await;
        if let Some(tip) = *tip_height {
            if height > tip {
                tracing::trace!(
                    "Requested header at height {} is beyond tip height {}",
                    height,
                    tip
                );
                return Ok(None);
            }
        } else {
            tracing::trace!("No headers stored yet, returning None for height {}", height);
            return Ok(None);
        }

        let segment_id = Self::get_segment_id(height);
        let offset = Self::get_segment_offset(height);

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
                "Header not found at height {} (segment: {}, offset: {})",
                height,
                segment_id,
                offset
            );
        }

        Ok(header)
    }

    async fn get_tip_height(&self) -> StorageResult<Option<u32>> {
        Ok(*self.cached_tip_height.read().await)
    }

    async fn store_filter_headers(&mut self, headers: &[FilterHeader]) -> StorageResult<()> {
        let mut next_height = {
            let current_tip = self.cached_filter_tip_height.read().await;
            match *current_tip {
                Some(tip) => tip + 1,
                None => 0, // Start at height 0 if no headers stored yet
            }
        }; // Read lock is dropped here

        for header in headers {
            let segment_id = Self::get_segment_id(next_height);
            let offset = Self::get_segment_offset(next_height);

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

            next_height += 1;
        }

        // Update cached tip height
        if next_height > 0 {
            *self.cached_filter_tip_height.write().await = Some(next_height - 1);
        }

        // Save dirty segments periodically (every 1000 filter headers)
        if headers.len() >= 1000 || next_height % 1000 == 0 {
            self.save_dirty_segments().await?;
        }

        Ok(())
    }

    async fn load_filter_headers(&self, range: Range<u32>) -> StorageResult<Vec<FilterHeader>> {
        let mut filter_headers = Vec::new();

        let start_segment = Self::get_segment_id(range.start);
        let end_segment = Self::get_segment_id(range.end.saturating_sub(1));

        for segment_id in start_segment..=end_segment {
            self.ensure_filter_segment_loaded(segment_id).await?;

            let segments = self.active_filter_segments.read().await;
            if let Some(segment) = segments.get(&segment_id) {
                let start_idx = if segment_id == start_segment {
                    Self::get_segment_offset(range.start)
                } else {
                    0
                };

                let end_idx = if segment_id == end_segment {
                    Self::get_segment_offset(range.end.saturating_sub(1)) + 1
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

    async fn get_filter_header(&self, height: u32) -> StorageResult<Option<FilterHeader>> {
        let segment_id = Self::get_segment_id(height);
        let offset = Self::get_segment_offset(height);

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
        // Store the main state info as JSON (without the large engine_state)
        let json_path = self.base_path.join("state/masternode.json");
        let engine_path = self.base_path.join("state/masternode_engine.bin");
        
        // Create a version without the engine state for JSON storage
        let json_state = serde_json::json!({
            "last_height": state.last_height,
            "last_update": state.last_update,
            "terminal_block_hash": state.terminal_block_hash,
            "engine_state_size": state.engine_state.len()
        });
        
        let json = serde_json::to_string_pretty(&json_state).map_err(|e| {
            StorageError::Serialization(format!("Failed to serialize masternode state: {}", e))
        })?;
        tokio::fs::write(json_path, json).await?;
        
        // Store the engine state as binary
        if !state.engine_state.is_empty() {
            tokio::fs::write(engine_path, &state.engine_state).await?;
        }
        
        Ok(())
    }

    async fn load_masternode_state(&self) -> StorageResult<Option<MasternodeState>> {
        let json_path = self.base_path.join("state/masternode.json");
        let engine_path = self.base_path.join("state/masternode_engine.bin");
        
        if !json_path.exists() {
            return Ok(None);
        }
        
        // Try to read the file with size limit check
        let metadata = tokio::fs::metadata(&json_path).await?;
        if metadata.len() > 10_000_000 { // 10MB limit for JSON file
            tracing::error!("Masternode state JSON file is too large: {} bytes. Likely corrupted.", metadata.len());
            // Delete the corrupted file and return None to start fresh
            let _ = tokio::fs::remove_file(&json_path).await;
            let _ = tokio::fs::remove_file(&engine_path).await;
            return Ok(None);
        }
        
        let content = tokio::fs::read_to_string(&json_path).await?;
        
        // First try to parse as the new format (without engine_state in JSON)
        if let Ok(json_state) = serde_json::from_str::<serde_json::Value>(&content) {
            if !json_state.get("engine_state").is_some() {
                // New format - load from separate files
                let last_height = json_state["last_height"].as_u64()
                    .ok_or_else(|| StorageError::Serialization("Missing last_height".to_string()))? as u32;
                let last_update = json_state["last_update"].as_u64()
                    .ok_or_else(|| StorageError::Serialization("Missing last_update".to_string()))?;
                let terminal_block_hash = json_state["terminal_block_hash"].as_array()
                    .and_then(|arr| {
                        if arr.len() == 32 {
                            let mut hash = [0u8; 32];
                            for (i, v) in arr.iter().enumerate() {
                                hash[i] = v.as_u64()? as u8;
                            }
                            Some(hash)
                        } else {
                            None
                        }
                    });
                
                // Load the engine state binary if it exists
                let engine_state = if engine_path.exists() {
                    tokio::fs::read(engine_path).await?
                } else {
                    Vec::new()
                };
                
                return Ok(Some(MasternodeState {
                    last_height,
                    engine_state,
                    last_update,
                    terminal_block_hash,
                }));
            }
        }
        
        // Fall back to old format (with engine_state in JSON) - but with size protection
        match serde_json::from_str::<MasternodeState>(&content) {
            Ok(state) => Ok(Some(state)),
            Err(e) => {
                tracing::error!("Failed to deserialize masternode state: {}. Deleting corrupted file.", e);
                // Delete the corrupted file
                let _ = tokio::fs::remove_file(&json_path).await;
                let _ = tokio::fs::remove_file(&engine_path).await;
                Ok(None)
            }
        }
    }

    async fn store_chain_state(&mut self, state: &ChainState) -> StorageResult<()> {
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
            state.headers = self.load_headers(0..tip_height + 1).await?;
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
        // Clear in-memory data
        self.active_segments.write().await.clear();
        self.active_filter_segments.write().await.clear();
        self.header_hash_index.write().await.clear();
        *self.cached_tip_height.write().await = None;
        *self.cached_filter_tip_height.write().await = None;

        // Clear UTXO cache
        self.utxo_cache.write().await.clear();
        self.utxo_address_index.write().await.clear();
        *self.utxo_cache_dirty.write().await = false;

        // Clear mempool
        self.mempool_transactions.write().await.clear();
        *self.mempool_state.write().await = None;

        // Remove all files
        if self.base_path.exists() {
            tokio::fs::remove_dir_all(&self.base_path).await?;
            tokio::fs::create_dir_all(&self.base_path).await?;
        }

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

    // High-performance UTXO storage using in-memory cache with address indexing

    async fn store_utxo(&mut self, outpoint: &OutPoint, utxo: &Utxo) -> StorageResult<()> {
        // Add to in-memory cache
        {
            let mut cache = self.utxo_cache.write().await;
            cache.insert(*outpoint, utxo.clone());
        }

        // Update address index
        self.update_address_index_add(*outpoint, utxo).await;

        // Mark cache as dirty for background persistence
        *self.utxo_cache_dirty.write().await = true;

        Ok(())
    }

    async fn remove_utxo(&mut self, outpoint: &OutPoint) -> StorageResult<()> {
        // Get the UTXO before removing to update address index
        let utxo = {
            let cache = self.utxo_cache.read().await;
            cache.get(outpoint).cloned()
        };

        if let Some(utxo) = utxo {
            // Remove from in-memory cache
            {
                let mut cache = self.utxo_cache.write().await;
                cache.remove(outpoint);
            }

            // Update address index
            self.update_address_index_remove(outpoint, &utxo).await;

            // Mark cache as dirty for background persistence
            *self.utxo_cache_dirty.write().await = true;
        }

        Ok(())
    }

    async fn get_utxos_for_address(&self, address: &Address) -> StorageResult<Vec<Utxo>> {
        // Use address index for O(1) lookup
        let outpoints = {
            let address_index = self.utxo_address_index.read().await;
            address_index.get(address).cloned().unwrap_or_default()
        };

        // Fetch UTXOs from cache
        let cache = self.utxo_cache.read().await;
        let utxos: Vec<Utxo> =
            outpoints.into_iter().filter_map(|outpoint| cache.get(&outpoint).cloned()).collect();

        Ok(utxos)
    }

    async fn get_all_utxos(&self) -> StorageResult<HashMap<OutPoint, Utxo>> {
        // Return a clone of the in-memory cache
        let cache = self.utxo_cache.read().await;
        Ok(cache.clone())
    }

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

    async fn store_terminal_block(&mut self, block: &StoredTerminalBlock) -> StorageResult<()> {
        let terminal_blocks_dir = self.base_path.join("terminal_blocks");
        tokio::fs::create_dir_all(&terminal_blocks_dir).await?;

        let path = terminal_blocks_dir.join(format!("terminal_block_{}.bin", block.height));
        let data = bincode::serialize(block).map_err(|e| {
            StorageError::WriteFailed(format!("Failed to serialize terminal block: {}", e))
        })?;

        tokio::fs::write(&path, data).await?;
        Ok(())
    }

    async fn load_terminal_block(&self, height: u32) -> StorageResult<Option<StoredTerminalBlock>> {
        let path = self.base_path.join(format!("terminal_blocks/terminal_block_{}.bin", height));

        if !path.exists() {
            return Ok(None);
        }

        let data = tokio::fs::read(&path).await?;
        let block = bincode::deserialize(&data).map_err(|e| {
            StorageError::ReadFailed(format!("Failed to deserialize terminal block: {}", e))
        })?;

        Ok(Some(block))
    }

    async fn get_all_terminal_blocks(&self) -> StorageResult<Vec<StoredTerminalBlock>> {
        let terminal_blocks_dir = self.base_path.join("terminal_blocks");

        if !terminal_blocks_dir.exists() {
            return Ok(Vec::new());
        }

        let mut terminal_blocks: Vec<StoredTerminalBlock> = Vec::new();
        let mut entries = tokio::fs::read_dir(&terminal_blocks_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();

            // Parse height from filename
            if let Some(height_str) =
                file_name_str.strip_prefix("terminal_block_").and_then(|s| s.strip_suffix(".bin"))
            {
                if let Ok(_height) = height_str.parse::<u32>() {
                    let path = entry.path();
                    let data = tokio::fs::read(&path).await?;
                    if let Ok(block) = bincode::deserialize(&data) {
                        terminal_blocks.push(block);
                    }
                }
            }
        }

        // Sort by height
        terminal_blocks.sort_by_key(|b| b.height);
        Ok(terminal_blocks)
    }

    async fn has_terminal_block(&self, height: u32) -> StorageResult<bool> {
        let path = self.base_path.join(format!("terminal_blocks/terminal_block_{}.bin", height));
        Ok(path.exists())
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
}
