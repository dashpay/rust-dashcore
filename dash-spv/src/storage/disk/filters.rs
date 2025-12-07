//! Filter storage operations for DiskStorageManager.

use std::ops::Range;
use std::time::Instant;

use dashcore::hash_types::FilterHeader;

use crate::error::StorageResult;
use crate::storage::disk::segments::Segment;

use super::manager::DiskStorageManager;

impl DiskStorageManager {
    /// Store filter headers.
    pub async fn store_filter_headers(&mut self, headers: &[FilterHeader]) -> StorageResult<()> {
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
            ensure_filter_segment_loaded(self, segment_id).await?;

            // Update segment
            {
                let mut segments = self.active_filter_segments.write().await;
                if let Some(segment) = segments.get_mut(&segment_id) {
                    segment.insert(*header, offset);
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
            super::segments::save_dirty_segments_cache(self).await?;
        }

        Ok(())
    }

    /// Load filter headers for a blockchain height range.
    pub async fn load_filter_headers(&self, range: Range<u32>) -> StorageResult<Vec<FilterHeader>> {
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
            ensure_filter_segment_loaded(self, segment_id).await?;

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
                    segment.headers.len()
                };

                if start_idx < segment.headers.len() && end_idx <= segment.headers.len() {
                    filter_headers.extend_from_slice(&segment.headers[start_idx..end_idx]);
                }
            }
        }

        Ok(filter_headers)
    }

    /// Get a filter header at a specific blockchain height.
    pub async fn get_filter_header(
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

        ensure_filter_segment_loaded(self, segment_id).await?;

        let segments = self.active_filter_segments.read().await;
        Ok(segments.get(&segment_id).and_then(|segment| segment.headers.get(offset)).copied())
    }

    /// Get the blockchain height of the filter tip.
    pub async fn get_filter_tip_height(&self) -> StorageResult<Option<u32>> {
        Ok(*self.cached_filter_tip_height.read().await)
    }

    /// Store a compact filter.
    pub async fn store_filter(&mut self, height: u32, filter: &[u8]) -> StorageResult<()> {
        let path = self.base_path.join(format!("filters/{}.dat", height));
        tokio::fs::write(path, filter).await?;
        Ok(())
    }

    /// Load a compact filter.
    pub async fn load_filter(&self, height: u32) -> StorageResult<Option<Vec<u8>>> {
        let path = self.base_path.join(format!("filters/{}.dat", height));
        if !path.exists() {
            return Ok(None);
        }

        let data = tokio::fs::read(path).await?;
        Ok(Some(data))
    }

    /// Clear all filter data.
    pub async fn clear_filters(&mut self) -> StorageResult<()> {
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
}

/// Ensure a filter segment is loaded in memory.
pub(super) async fn ensure_filter_segment_loaded(
    manager: &DiskStorageManager,
    segment_id: u32,
) -> StorageResult<()> {
    // Process background worker notifications to clear save_pending flags
    manager.process_worker_notifications().await;

    let mut segments = manager.active_filter_segments.write().await;

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

    let filter_header_cache = Segment::load(&manager.base_path, segment_id).await?;

    segments.insert(segment_id, filter_header_cache);

    Ok(())
}
