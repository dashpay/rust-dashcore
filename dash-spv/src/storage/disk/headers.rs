//! Header storage operations for DiskStorageManager.

use std::collections::HashMap;
use std::fs;
use std::ops::Range;
use std::path::Path;
use std::time::Instant;

use dashcore::block::Header as BlockHeader;
use dashcore::BlockHash;

use crate::error::StorageResult;
use crate::storage::disk::segments::SegmentCache;
use crate::StorageError;

use super::manager::DiskStorageManager;

impl DiskStorageManager {
    /// Internal implementation that optionally accepts pre-computed hashes
    pub(super) async fn store_headers_impl(
        &mut self,
        headers: &[BlockHeader],
        precomputed_hashes: Option<&[BlockHash]>,
    ) -> StorageResult<()> {
        // Early return if no headers to store
        if headers.is_empty() {
            tracing::trace!("DiskStorage: no headers to store");
            return Ok(());
        }

        // Validate that if hashes are provided, the count matches
        if let Some(hashes) = precomputed_hashes {
            if hashes.len() != headers.len() {
                return Err(crate::error::StorageError::WriteFailed(
                    "Precomputed hash count doesn't match header count".to_string(),
                ));
            }
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

        for (i, header) in headers.iter().enumerate() {
            let segment_id = Self::get_segment_id(next_height);
            let offset = Self::get_segment_offset(next_height);

            // Ensure segment is loaded
            ensure_segment_loaded(self, segment_id).await?;

            // Update segment
            {
                let mut segments = self.active_segments.write().await;
                if let Some(segment) = segments.get_mut(&segment_id) {
                    segment.store(*header, offset);
                }
            }

            // Update reverse index with blockchain height (not storage index)
            let blockchain_height = sync_base_height + next_height;

            // Use precomputed hash if available, otherwise compute it
            let header_hash = if let Some(hashes) = precomputed_hashes {
                hashes[i]
            } else {
                header.block_hash()
            };

            reverse_index.insert(header_hash, blockchain_height);

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
            0
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
            super::segments::save_dirty_segments_cache(self).await?;
        }

        Ok(())
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
            ensure_segment_loaded(self, segment_id).await?;

            // Update segment
            {
                let mut segments = self.active_segments.write().await;
                if let Some(segment) = segments.get_mut(&segment_id) {
                    segment.store(*header, offset);
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
    pub async fn store_headers_internal(
        &mut self,
        headers: &[BlockHeader],
        precomputed_hashes: Option<&[BlockHash]>,
    ) -> StorageResult<()> {
        self.store_headers_impl(headers, precomputed_hashes).await
    }

    /// Load headers for a blockchain height range.
    pub async fn load_headers(&self, range: Range<u32>) -> StorageResult<Vec<BlockHeader>> {
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
            ensure_segment_loaded(self, segment_id).await?;

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

    /// Get a header at a specific blockchain height.
    pub async fn get_header(&self, height: u32) -> StorageResult<Option<BlockHeader>> {
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

        ensure_segment_loaded(self, segment_id).await?;

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

    /// Get the blockchain height of the tip.
    pub async fn get_tip_height(&self) -> StorageResult<Option<u32>> {
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

    let block_header_cache =
        SegmentCache::load_block_header_cache(&manager.base_path, segment_id).await?;

    segments.insert(segment_id, block_header_cache);

    Ok(())
}
