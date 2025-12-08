//! Header storage operations for DiskStorageManager.

use std::collections::HashMap;
use std::ops::Range;
use std::path::Path;
use std::time::Instant;
use std::{fs, hash};

use dashcore::block::Header as BlockHeader;
use dashcore::secp256k1::hashes;
use dashcore::BlockHash;

use crate::error::StorageResult;
use crate::storage::disk::segments::Segment;
use crate::StorageError;

use super::manager::DiskStorageManager;

impl DiskStorageManager {
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
            ensure_segment_loaded(self, segment_id).await?;

            // Update segment
            {
                let mut segments = self.active_segments.write().await;
                if let Some(segment) = segments.get_mut(&segment_id) {
                    segment.insert(*header, offset);
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
            0
        };
        let final_storage_index = if storage_index > 0 {
            storage_index - 1
        } else {
            0
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
            super::segments::save_dirty_segments_cache(self).await?;
        }

        Ok(())
    }

    /// Store headers with optional precomputed hashes for performance optimization.
    ///
    /// This is a performance optimization for hot paths that have already computed header hashes.
    /// When called from header sync with CachedHeader wrappers, passing precomputed hashes avoids
    /// recomputing the expensive X11 hash for indexing (saves ~35% of CPU during sync).
    pub async fn store_headers_internal(&mut self, headers: &[BlockHeader]) -> StorageResult<()> {
        let hashes = headers.iter().map(|header| header.block_hash()).collect::<Vec<_>>();

        let mut height = if let Some(height) = self.active_segments.read().await.tip_height() {
            height + 1
        } else {
            0
        };

        self.active_segments.write().await.store_headers(headers, self).await?;

        // Update reverse index
        let mut reverse_index = self.header_hash_index.write().await;

        for hash in hashes {
            reverse_index.insert(hash, height);
            height += 1;
        }

        // Release locks before saving (to avoid deadlocks during background saves)
        drop(reverse_index);

        Ok(())
    }

    /// Get header height by hash.
    pub async fn get_header_height_by_hash(&self, hash: &BlockHash) -> StorageResult<Option<u32>> {
        Ok(self.header_hash_index.read().await.get(hash).copied())
    }

    /// Get a batch of headers with their heights.
    pub async fn get_headers_batch(
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
}

/// Load index from file.
pub(super) async fn load_index_from_file(path: &Path) -> StorageResult<HashMap<BlockHash, u32>> {
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

/// Save index to disk.
pub(super) async fn save_index_to_disk(
    path: &Path,
    index: &HashMap<BlockHash, u32>,
) -> StorageResult<()> {
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

/// Ensure a segment is loaded in memory.
pub(super) async fn ensure_segment_loaded(
    manager: &DiskStorageManager,
    segment_id: u32,
) -> StorageResult<()> {
    // Process background worker notifications to clear save_pending flags
    manager.process_worker_notifications().await;

    let mut segments = manager.active_segments.write().await;

    if segments.contains_key(&segment_id) {
        // Update last accessed time
        if let Some(segment) = segments.get_mut(&segment_id) {
            segment.last_accessed = Instant::now();
        }
        return Ok(());
    }

    // Evict old segments if needed
    if segments.len() >= super::MAX_ACTIVE_SEGMENTS {
        if let Some((oldest_id, oldest_segment_cache)) =
            segments.iter().min_by_key(|(_, s)| s.last_accessed).map(|(id, s)| (*id, s.clone()))
        {
            oldest_segment_cache.evict(&manager.base_path)?;
            segments.remove(&oldest_id);
        }
    }

    let block_header_cache = Segment::load(&manager.base_path, segment_id).await?;

    segments.insert(segment_id, block_header_cache);

    Ok(())
}
