//! Disk-based storage implementation with segmented files and async background saving.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use async_trait::async_trait;
use tokio::sync::{RwLock, mpsc};

use dashcore::{
    block::{Header as BlockHeader, Version},
    consensus::{encode, Decodable, Encodable},
    hash_types::FilterHeader,
    pow::CompactTarget,
    BlockHash, Address, OutPoint,
};
use dashcore_hashes::Hash;

use crate::error::{StorageError, StorageResult};
use crate::storage::{StorageManager, MasternodeState, StorageStats};
use crate::types::ChainState;
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
    Shutdown,
}


/// In-memory cache for a segment of headers
#[derive(Clone)]
struct SegmentCache {
    segment_id: u32,
    headers: Vec<BlockHeader>,
    dirty: bool,
    last_saved: Instant,
    last_accessed: Instant,
}

/// In-memory cache for a segment of filter headers
#[derive(Clone)]
struct FilterSegmentCache {
    segment_id: u32,
    filter_headers: Vec<FilterHeader>,
    dirty: bool,
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
    
    // Cached values
    cached_tip_height: Arc<RwLock<Option<u32>>>,
    cached_filter_tip_height: Arc<RwLock<Option<u32>>>,
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
        
        fs::create_dir_all(&headers_dir)?;
        fs::create_dir_all(&filters_dir)?;
        fs::create_dir_all(&state_dir)?;
        
        
        // Create background worker channel
        let (worker_tx, mut worker_rx) = mpsc::channel::<WorkerCommand>(100);
        
        // Start background worker
        let worker_base_path = base_path.clone();
        let worker_handle = tokio::spawn(async move {
            while let Some(cmd) = worker_rx.recv().await {
                match cmd {
                    WorkerCommand::SaveHeaderSegment { segment_id, headers } => {
                        let path = worker_base_path.join(format!("headers/segment_{:04}.dat", segment_id));
                        if let Err(e) = save_segment_to_disk(&path, &headers).await {
                            eprintln!("Failed to save segment {}: {}", segment_id, e);
                        }
                    }
                    WorkerCommand::SaveFilterSegment { segment_id, filter_headers } => {
                        let path = worker_base_path.join(format!("headers/filter_segment_{:04}.dat", segment_id));
                        if let Err(e) = save_filter_segment_to_disk(&path, &filter_headers).await {
                            eprintln!("Failed to save filter segment {}: {}", segment_id, e);
                        }
                    }
                    WorkerCommand::SaveIndex { index } => {
                        let path = worker_base_path.join("headers/index.dat");
                        if let Err(e) = save_index_to_disk(&path, &index).await {
                            eprintln!("Failed to save index: {}", e);
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
            cached_tip_height: Arc::new(RwLock::new(None)),
            cached_filter_tip_height: Arc::new(RwLock::new(None)),
        };
        
        // Load segment metadata and rebuild index
        storage.load_segment_metadata().await?;
        
        Ok(storage)
    }
    
    /// Load segment metadata and rebuild indexes.
    async fn load_segment_metadata(&mut self) -> StorageResult<()> {
        // Load header index if it exists
        let index_path = self.base_path.join("headers/index.dat");
        if index_path.exists() {
            if let Ok(index) = self.load_index_from_file(&index_path).await {
                *self.header_hash_index.write().await = index;
            }
        }
        
        // Find highest segment to determine tip height
        let headers_dir = self.base_path.join("headers");
        if let Ok(entries) = fs::read_dir(&headers_dir) {
            let mut max_segment_id = None;
            let mut max_filter_segment_id = None;
            
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.starts_with("segment_") && name.ends_with(".dat") {
                        if let Ok(id) = name[8..12].parse::<u32>() {
                            max_segment_id = Some(max_segment_id.map_or(id, |max: u32| max.max(id)));
                        }
                    } else if name.starts_with("filter_segment_") && name.ends_with(".dat") {
                        if let Ok(id) = name[15..19].parse::<u32>() {
                            max_filter_segment_id = Some(max_filter_segment_id.map_or(id, |max: u32| max.max(id)));
                        }
                    }
                }
            }
            
            // If we have segments, load the highest one to find tip
            if let Some(segment_id) = max_segment_id {
                self.ensure_segment_loaded(segment_id).await?;
                let segments = self.active_segments.read().await;
                if let Some(segment) = segments.get(&segment_id) {
                    let tip_height = segment_id * HEADERS_PER_SEGMENT + segment.headers.len() as u32 - 1;
                    *self.cached_tip_height.write().await = Some(tip_height);
                }
            }
            
            // If we have filter segments, load the highest one to find filter tip
            if let Some(segment_id) = max_filter_segment_id {
                self.ensure_filter_segment_loaded(segment_id).await?;
                let segments = self.active_filter_segments.read().await;
                if let Some(segment) = segments.get(&segment_id) {
                    let tip_height = segment_id * HEADERS_PER_SEGMENT + segment.filter_headers.len() as u32 - 1;
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
        let headers = if segment_path.exists() {
            self.load_headers_from_file(&segment_path).await?
        } else {
            Vec::new()
        };
        
        // Evict old segments if needed
        if segments.len() >= MAX_ACTIVE_SEGMENTS {
            self.evict_oldest_segment(&mut segments).await?;
        }
        
        segments.insert(segment_id, SegmentCache {
            segment_id,
            headers,
            dirty: false,
            last_saved: Instant::now(),
            last_accessed: Instant::now(),
        });
        
        Ok(())
    }
    
    /// Evict the oldest (least recently accessed) segment.
    async fn evict_oldest_segment(&self, segments: &mut HashMap<u32, SegmentCache>) -> StorageResult<()> {
        if let Some((oldest_id, oldest_segment)) = segments
            .iter()
            .min_by_key(|(_, s)| s.last_accessed)
            .map(|(id, s)| (*id, s.clone()))
        {
            // Save if dirty before evicting - send to background worker
            if oldest_segment.dirty {
                if let Some(tx) = &self.worker_tx {
                    let _ = tx.send(WorkerCommand::SaveHeaderSegment {
                        segment_id: oldest_segment.segment_id,
                        headers: oldest_segment.headers.clone(),
                    }).await;
                }
            }
            
            segments.remove(&oldest_id);
        }
        
        Ok(())
    }
    
    /// Ensure a filter segment is loaded in memory.
    async fn ensure_filter_segment_loaded(&self, segment_id: u32) -> StorageResult<()> {
        let mut segments = self.active_filter_segments.write().await;
        
        if segments.contains_key(&segment_id) {
            // Update last accessed time
            if let Some(segment) = segments.get_mut(&segment_id) {
                segment.last_accessed = Instant::now();
            }
            return Ok(());
        }
        
        // Load segment from disk
        let segment_path = self.base_path.join(format!("headers/filter_segment_{:04}.dat", segment_id));
        let filter_headers = if segment_path.exists() {
            self.load_filter_headers_from_file(&segment_path).await?
        } else {
            Vec::new()
        };
        
        // Evict old segments if needed
        if segments.len() >= MAX_ACTIVE_SEGMENTS {
            self.evict_oldest_filter_segment(&mut segments).await?;
        }
        
        segments.insert(segment_id, FilterSegmentCache {
            segment_id,
            filter_headers,
            dirty: false,
            last_saved: Instant::now(),
            last_accessed: Instant::now(),
        });
        
        Ok(())
    }
    
    /// Evict the oldest (least recently accessed) filter segment.
    async fn evict_oldest_filter_segment(&self, segments: &mut HashMap<u32, FilterSegmentCache>) -> StorageResult<()> {
        if let Some((oldest_id, oldest_segment)) = segments
            .iter()
            .min_by_key(|(_, s)| s.last_accessed)
            .map(|(id, s)| (*id, s.clone()))
        {
            // Save if dirty before evicting - send to background worker
            if oldest_segment.dirty {
                if let Some(tx) = &self.worker_tx {
                    let _ = tx.send(WorkerCommand::SaveFilterSegment {
                        segment_id: oldest_segment.segment_id,
                        filter_headers: oldest_segment.filter_headers.clone(),
                    }).await;
                }
            }
            
            segments.remove(&oldest_id);
        }
        
        Ok(())
    }
    
    /// Save all dirty segments to disk via background worker.
    async fn save_dirty_segments(&self) -> StorageResult<()> {
        if let Some(tx) = &self.worker_tx {
            // Collect segments to save
            let segments_to_save = {
                let segments = self.active_segments.read().await;
                segments.values()
                    .filter(|s| s.dirty)
                    .map(|s| (s.segment_id, s.headers.clone(), false))
                    .collect::<Vec<_>>()
            };
            
            // Send header segments to worker
            for (segment_id, headers, _) in segments_to_save {
                let _ = tx.send(WorkerCommand::SaveHeaderSegment {
                    segment_id,
                    headers,
                }).await;
            }
            
            // Mark header segments as clean
            {
                let mut segments = self.active_segments.write().await;
                for segment in segments.values_mut() {
                    if segment.dirty {
                        segment.dirty = false;
                        segment.last_saved = Instant::now();
                    }
                }
            }
            
            // Collect filter segments to save
            let filter_segments_to_save = {
                let segments = self.active_filter_segments.read().await;
                segments.values()
                    .filter(|s| s.dirty)
                    .map(|s| (s.segment_id, s.filter_headers.clone()))
                    .collect::<Vec<_>>()
            };
            
            // Send filter segments to worker
            for (segment_id, filter_headers) in filter_segments_to_save {
                let _ = tx.send(WorkerCommand::SaveFilterSegment {
                    segment_id,
                    filter_headers,
                }).await;
            }
            
            // Mark filter segments as clean
            {
                let mut segments = self.active_filter_segments.write().await;
                for segment in segments.values_mut() {
                    if segment.dirty {
                        segment.dirty = false;
                        segment.last_saved = Instant::now();
                    }
                }
            }
            
            // Save the index
            let index = self.header_hash_index.read().await.clone();
            let _ = tx.send(WorkerCommand::SaveIndex { index }).await;
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
                        Err(encode::Error::Io(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                        Err(e) => return Err(StorageError::ReadFailed(format!("Failed to decode header: {}", e))),
                    }
                }
                
                Ok(headers)
            }
        }).await.map_err(|e| StorageError::ReadFailed(format!("Task join error: {}", e)))?
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
                        Err(encode::Error::Io(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                        Err(e) => return Err(StorageError::ReadFailed(format!("Failed to decode filter header: {}", e))),
                    }
                }
                
                Ok(headers)
            }
        }).await.map_err(|e| StorageError::ReadFailed(format!("Task join error: {}", e)))?
    }
    
    /// Load index from file.
    async fn load_index_from_file(&self, path: &Path) -> StorageResult<HashMap<BlockHash, u32>> {
        tokio::task::spawn_blocking({
            let path = path.to_path_buf();
            move || {
                let content = fs::read(&path)?;
                bincode::deserialize(&content)
                    .map_err(|e| StorageError::ReadFailed(format!("Failed to deserialize index: {}", e)))
            }
        }).await.map_err(|e| StorageError::ReadFailed(format!("Task join error: {}", e)))?
    }
    
    /// Shutdown the storage manager.
    pub async fn shutdown(&mut self) -> StorageResult<()> {
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


/// Save a segment of headers to disk.
async fn save_segment_to_disk(path: &Path, headers: &[BlockHeader]) -> StorageResult<()> {
    tokio::task::spawn_blocking({
        let path = path.to_path_buf();
        let headers = headers.to_vec();
        move || {
            let file = OpenOptions::new().create(true).write(true).truncate(true).open(&path)?;
            let mut writer = BufWriter::new(file);
            
            for header in headers {
                header.consensus_encode(&mut writer)
                    .map_err(|e| StorageError::WriteFailed(format!("Failed to encode header: {}", e)))?;
            }
            
            writer.flush()?;
            Ok(())
        }
    }).await.map_err(|e| StorageError::WriteFailed(format!("Task join error: {}", e)))?
}

/// Save a segment of filter headers to disk.
async fn save_filter_segment_to_disk(path: &Path, filter_headers: &[FilterHeader]) -> StorageResult<()> {
    tokio::task::spawn_blocking({
        let path = path.to_path_buf();
        let filter_headers = filter_headers.to_vec();
        move || {
            let file = OpenOptions::new().create(true).write(true).truncate(true).open(&path)?;
            let mut writer = BufWriter::new(file);
            
            for header in filter_headers {
                header.consensus_encode(&mut writer)
                    .map_err(|e| StorageError::WriteFailed(format!("Failed to encode filter header: {}", e)))?;
            }
            
            writer.flush()?;
            Ok(())
        }
    }).await.map_err(|e| StorageError::WriteFailed(format!("Task join error: {}", e)))?
}

/// Save index to disk.
async fn save_index_to_disk(path: &Path, index: &HashMap<BlockHash, u32>) -> StorageResult<()> {
    tokio::task::spawn_blocking({
        let path = path.to_path_buf();
        let index = index.clone();
        move || {
            let data = bincode::serialize(&index)
                .map_err(|e| StorageError::WriteFailed(format!("Failed to serialize index: {}", e)))?;
            fs::write(&path, data)?;
            Ok(())
        }
    }).await.map_err(|e| StorageError::WriteFailed(format!("Task join error: {}", e)))?
}

#[async_trait]
impl StorageManager for DiskStorageManager {
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    async fn store_headers(&mut self, headers: &[BlockHeader]) -> StorageResult<()> {
        let mut next_height = {
            let current_tip = self.cached_tip_height.read().await;
            match *current_tip {
                Some(tip) => tip + 1,
                None => 0, // Start at height 0 if no headers stored yet
            }
        }; // Read lock is dropped here

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
                        // Fill with default headers up to the offset
                        let default_header = BlockHeader {
                            version: Version::from_consensus(0),
                            prev_blockhash: BlockHash::all_zeros(),
                            merkle_root: dashcore::hashes::sha256d::Hash::all_zeros().into(),
                            time: 0,
                            bits: CompactTarget::from_consensus(0),
                            nonce: 0,
                        };
                        segment.headers.resize(offset + 1, default_header);
                    }
                    segment.headers[offset] = *header;
                    segment.dirty = true;
                    segment.last_accessed = Instant::now();
                }
            }
            
            // Update reverse index
            self.header_hash_index.write().await.insert(header.block_hash(), next_height);
            
            next_height += 1;
        }

        // Update cached tip height
        *self.cached_tip_height.write().await = Some(next_height - 1);
        
        // Save dirty segments periodically (every 1000 headers)
        if headers.len() >= 1000 || next_height % 1000 == 0 {
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
                
                if start_idx < segment.headers.len() && end_idx <= segment.headers.len() {
                    headers.extend_from_slice(&segment.headers[start_idx..end_idx]);
                }
            }
        }
        
        Ok(headers)
    }
    
    async fn get_header(&self, height: u32) -> StorageResult<Option<BlockHeader>> {
        let segment_id = Self::get_segment_id(height);
        let offset = Self::get_segment_offset(height);
        
        self.ensure_segment_loaded(segment_id).await?;
        
        let segments = self.active_segments.read().await;
        Ok(segments.get(&segment_id)
            .and_then(|segment| segment.headers.get(offset))
            .copied())
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
                    segment.dirty = true;
                    segment.last_accessed = Instant::now();
                }
            }
            
            next_height += 1;
        }
        
        // Update cached tip height
        *self.cached_filter_tip_height.write().await = Some(next_height - 1);
        
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
                
                if start_idx < segment.filter_headers.len() && end_idx <= segment.filter_headers.len() {
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
        Ok(segments.get(&segment_id)
            .and_then(|segment| segment.filter_headers.get(offset))
            .copied())
    }
    
    async fn get_filter_tip_height(&self) -> StorageResult<Option<u32>> {
        Ok(*self.cached_filter_tip_height.read().await)
    }
    
    async fn store_masternode_state(&mut self, state: &MasternodeState) -> StorageResult<()> {
        let path = self.base_path.join("state/masternode.json");
        let json = serde_json::to_string_pretty(state)
            .map_err(|e| StorageError::Serialization(format!("Failed to serialize masternode state: {}", e)))?;
        
        tokio::fs::write(path, json).await?;
        Ok(())
    }
    
    async fn load_masternode_state(&self) -> StorageResult<Option<MasternodeState>> {
        let path = self.base_path.join("state/masternode.json");
        if !path.exists() {
            return Ok(None);
        }
        
        let content = tokio::fs::read_to_string(path).await?;
        let state = serde_json::from_str(&content)
            .map_err(|e| StorageError::Serialization(format!("Failed to deserialize masternode state: {}", e)))?;
        
        Ok(Some(state))
    }
    
    async fn store_chain_state(&mut self, state: &ChainState) -> StorageResult<()> {
        // First store all headers
        self.store_headers(&state.headers).await?;
        
        // Store filter headers
        self.store_filter_headers(&state.filter_headers).await?;
        
        // Store other state as JSON
        let state_data = serde_json::json!({
            "last_chainlock_height": state.last_chainlock_height,
            "last_chainlock_hash": state.last_chainlock_hash,
            "current_filter_tip": state.current_filter_tip,
            "last_masternode_diff_height": state.last_masternode_diff_height,
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
        let value: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| StorageError::Serialization(format!("Failed to parse chain state: {}", e)))?;
        
        let mut state = ChainState::default();
        
        // Load all headers
        if let Some(tip_height) = self.get_tip_height().await? {
            state.headers = self.load_headers(0..tip_height + 1).await?;
        }
        
        // Load all filter headers
        if let Some(filter_tip_height) = self.get_filter_tip_height().await? {
            state.filter_headers = self.load_filter_headers(0..filter_tip_height + 1).await?;
        }
        
        state.last_chainlock_height = value.get("last_chainlock_height").and_then(|v| v.as_u64()).map(|h| h as u32);
        state.last_chainlock_hash = value.get("last_chainlock_hash").and_then(|v| v.as_str()).and_then(|s| s.parse().ok());
        state.current_filter_tip = value.get("current_filter_tip").and_then(|v| v.as_str()).and_then(|s| s.parse().ok());
        state.last_masternode_diff_height = value.get("last_masternode_diff_height").and_then(|v| v.as_u64()).map(|h| h as u32);
        
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
        let filter_header_count = self.cached_filter_tip_height.read().await.map_or(0, |h| h as u64 + 1);
        
        component_sizes.insert("headers".to_string(), header_count * 80);
        component_sizes.insert("filter_headers".to_string(), filter_header_count * 32);
        component_sizes.insert("index".to_string(), self.header_hash_index.read().await.len() as u64 * 40);
        
        Ok(StorageStats {
            header_count,
            filter_header_count,
            filter_count: 0, // TODO: Count filter files
            total_size,
            component_sizes,
        })
    }
    
    async fn get_header_height_by_hash(&self, hash: &dashcore::BlockHash) -> StorageResult<Option<u32>> {
        Ok(self.header_hash_index.read().await.get(hash).copied())
    }
    
    async fn get_headers_batch(&self, start_height: u32, end_height: u32) -> StorageResult<Vec<(u32, BlockHeader)>> {
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
    
    // For Phase 1, implement UTXO storage using metadata storage (simple but functional)
    // TODO: In future phases, implement proper segmented UTXO storage for better performance
    
    async fn store_utxo(&mut self, outpoint: &OutPoint, utxo: &Utxo) -> StorageResult<()> {
        // Store the UTXO
        let key = format!("utxo_{}", outpoint);
        let data = bincode::serialize(utxo)
            .map_err(|e| StorageError::Serialization(format!("Failed to serialize UTXO: {}", e)))?;
        self.store_metadata(&key, &data).await?;
        
        // Update the UTXO index
        let mut outpoints = if let Some(index_data) = self.load_metadata("utxo_index").await? {
            if !index_data.is_empty() {
                bincode::deserialize::<Vec<OutPoint>>(&index_data)
                    .map_err(|e| StorageError::Serialization(format!("Failed to deserialize UTXO index: {}", e)))?
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        
        if !outpoints.contains(outpoint) {
            outpoints.push(*outpoint);
            let index_data = bincode::serialize(&outpoints)
                .map_err(|e| StorageError::Serialization(format!("Failed to serialize UTXO index: {}", e)))?;
            self.store_metadata("utxo_index", &index_data).await?;
        }
        
        Ok(())
    }
    
    async fn remove_utxo(&mut self, outpoint: &OutPoint) -> StorageResult<()> {
        let key = format!("utxo_{}", outpoint);
        // For removal, we just store an empty value to mark it as deleted
        self.store_metadata(&key, &[]).await?;
        
        // Update the UTXO index to remove the outpoint
        if let Some(index_data) = self.load_metadata("utxo_index").await? {
            if !index_data.is_empty() {
                let mut outpoints: Vec<OutPoint> = bincode::deserialize(&index_data)
                    .map_err(|e| StorageError::Serialization(format!("Failed to deserialize UTXO index: {}", e)))?;
                
                outpoints.retain(|op| op != outpoint);
                let updated_index_data = bincode::serialize(&outpoints)
                    .map_err(|e| StorageError::Serialization(format!("Failed to serialize UTXO index: {}", e)))?;
                self.store_metadata("utxo_index", &updated_index_data).await?;
            }
        }
        
        Ok(())
    }
    
    async fn get_utxos_for_address(&self, address: &Address) -> StorageResult<Vec<Utxo>> {
        // This is inefficient but works for Phase 1
        // Get all UTXOs and filter by address
        let all_utxos = self.get_all_utxos().await?;
        let filtered_utxos: Vec<Utxo> = all_utxos
            .into_values()
            .filter(|utxo| &utxo.address == address)
            .collect();
        Ok(filtered_utxos)
    }
    
    async fn get_all_utxos(&self) -> StorageResult<HashMap<OutPoint, Utxo>> {
        let mut utxos = HashMap::new();
        
        // Load UTXO index to know which UTXOs exist
        if let Some(data) = self.load_metadata("utxo_index").await? {
            if !data.is_empty() {
                let outpoints: Vec<OutPoint> = bincode::deserialize(&data)
                    .map_err(|e| StorageError::Serialization(format!("Failed to deserialize UTXO index: {}", e)))?;
                
                for outpoint in outpoints {
                    let key = format!("utxo_{}", outpoint);
                    if let Some(utxo_data) = self.load_metadata(&key).await? {
                        if !utxo_data.is_empty() { // Not deleted
                            let utxo: Utxo = bincode::deserialize(&utxo_data)
                                .map_err(|e| StorageError::Serialization(format!("Failed to deserialize UTXO: {}", e)))?;
                            utxos.insert(outpoint, utxo);
                        }
                    }
                }
            }
        }
        
        Ok(utxos)
    }
}

