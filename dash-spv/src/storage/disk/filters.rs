//! Filter storage operations for DiskStorageManager.

use std::ops::Range;

use dashcore::hash_types::FilterHeader;
use dashcore_hashes::Hash;

use crate::error::StorageResult;
use crate::storage::disk::FILTERS_PER_SEGMENT;
use super::manager::DiskStorageManager;
use super::segments::{FilterDataIndexEntry, SegmentState};

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
            super::segments::ensure_filter_segment_loaded(self, segment_id).await?;

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
                    segment.last_accessed = std::time::Instant::now();
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
            super::segments::save_dirty_segments(self).await?;
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
            super::segments::ensure_filter_segment_loaded(self, segment_id).await?;

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

        super::segments::ensure_filter_segment_loaded(self, segment_id).await?;

        let segments = self.active_filter_segments.read().await;
        Ok(segments
            .get(&segment_id)
            .and_then(|segment| segment.filter_headers.get(offset))
            .copied())
    }

    /// Get the blockchain height of the filter tip.
    pub async fn get_filter_tip_height(&self) -> StorageResult<Option<u32>> {
        Ok(*self.cached_filter_tip_height.read().await)
    }

    /// Store a compact filter.
    pub async fn store_filter(&mut self, height: u32, filter: &[u8]) -> StorageResult<()> {
        let sync_base_height = *self.sync_base_height.read().await;

        // Convert blockchain height to storage index
        let storage_index = if sync_base_height > 0 && height >= sync_base_height {
            height - sync_base_height
        } else {
            height
        };

        let segment_id = Self::get_filter_segment_id(storage_index);
        let offset = Self::get_filter_segment_offset(storage_index);

        // Ensure segment is loaded
        super::segments::ensure_filter_data_segment_loaded(self, segment_id).await?;

        // Update segment
        {
            let mut segments = self.active_filter_data_segments.write().await;
            if let Some(segment) = segments.get_mut(&segment_id) {
                // Ensure index has space
                while segment.index.len() <= offset {
                    segment.index.push(FilterDataIndexEntry::default());
                }

                // Calculate offset for this filter's data
                let data_offset = segment.current_data_size;

                // Update index entry
                segment.index[offset] = FilterDataIndexEntry {
                    offset: data_offset,
                    length: filter.len() as u32,
                };

                // Store filter in cache
                segment.filters.insert(offset, filter.to_vec());
                segment.current_data_size += filter.len() as u64;
                segment.filter_count = segment.index.iter().filter(|e| e.length > 0).count();

                segment.state = SegmentState::Dirty;
                segment.last_accessed = std::time::Instant::now();
            }
        }

        // Save dirty segments periodically
        if height.is_multiple_of(FILTERS_PER_SEGMENT / 4) {
            super::segments::save_dirty_segments(self).await?;
        }

        Ok(())
    }

    /// Load a compact filter.
    pub async fn load_filter(&self, height: u32) -> StorageResult<Option<Vec<u8>>> {
        let sync_base_height = *self.sync_base_height.read().await;

        // Convert blockchain height to storage index
        let storage_index = if sync_base_height > 0 && height >= sync_base_height {
            height - sync_base_height
        } else {
            height
        };

        let segment_id = Self::get_filter_segment_id(storage_index);
        let offset = Self::get_filter_segment_offset(storage_index);

        // First check in-memory cache (segment may not be saved to disk yet)
        {
            let segments = self.active_filter_data_segments.read().await;
            if let Some(segment) = segments.get(&segment_id) {
                // Check if filter exists in index
                if offset < segment.index.len() && segment.index[offset].length > 0 {
                    // Check if filter is cached in memory
                    if let Some(filter) = segment.filters.get(&offset) {
                        return Ok(Some(filter.clone()));
                    }

                    // Filter is in index but not cached - load from combined segment file
                    let entry = &segment.index[offset];
                    let file_data_offset = segment.file_data_offset;
                    let segment_path = self
                        .base_path
                        .join(format!("filters/filter_data_segment_{:04}.dat", segment_id));
                    if segment_path.exists() {
                        let filter = super::io::load_filter_data_at_offset(
                            &segment_path,
                            entry.offset,
                            file_data_offset,
                            entry.length,
                        )
                        .await?;
                        return Ok(Some(filter));
                    }
                }
            }
        }

        // Try loading from disk if segment not in memory
        let segment_path =
            self.base_path.join(format!("filters/filter_data_segment_{:04}.dat", segment_id));

        if segment_path.exists() {
            let (index, data_offset) = super::io::load_filter_data_index(&segment_path).await?;
            if offset < index.len() && index[offset].length > 0 {
                let entry = &index[offset];
                let filter = super::io::load_filter_data_at_offset(
                    &segment_path,
                    entry.offset,
                    data_offset,
                    entry.length,
                )
                .await?;
                return Ok(Some(filter));
            }
        }

        Ok(None)
    }

    /// Clear all filter data.
    pub async fn clear_filters(&mut self) -> StorageResult<()> {
        // Stop worker to prevent concurrent writes to filter directories
        self.stop_worker().await;

        // Clear in-memory filter state
        self.active_filter_segments.write().await.clear();
        self.active_filter_data_segments.write().await.clear();
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
