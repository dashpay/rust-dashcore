//! Filter storage operations for DiskStorageManager.

use std::ops::Range;

use dashcore::hash_types::FilterHeader;
use dashcore_hashes::Hash;

use crate::error::StorageResult;

use super::manager::DiskStorageManager;
use super::segments::SegmentState;

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

    /// Get the highest stored compact filter height by scanning the filters directory.
    /// This checks which filters are actually persisted on disk, not just filter headers.
    ///
    /// Returns None if no filters are stored, otherwise returns the highest height found.
    ///
    /// Note: This only counts individual filter files ({height}.dat), not segment files.
    pub async fn get_stored_filter_height(&self) -> StorageResult<Option<u32>> {
        let filters_dir = self.base_path.join("filters");

        // If filters directory doesn't exist, no filters are stored
        if !filters_dir.exists() {
            return Ok(None);
        }

        let mut max_height: Option<u32> = None;

        // Read directory entries
        let mut entries = tokio::fs::read_dir(&filters_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();

            // Skip if not a file
            if !path.is_file() {
                continue;
            }

            // Check if it's a .dat file
            if path.extension().and_then(|e| e.to_str()) != Some("dat") {
                continue;
            }

            // Extract height from filename (format: "{height}.dat")
            // Only parse if filename is PURELY numeric (not "filter_segment_0001")
            // This ensures we only count individual filter files, not segments
            let filename = match path.file_stem().and_then(|f| f.to_str()) {
                Some(name) if name.chars().all(|c| c.is_ascii_digit()) => name,
                _ => continue, // Skip non-numeric names like "filter_segment_0001"
            };

            // Since filename only contains digits, this can never fail and can be optimized
            // but we'll keep it to ensure correctness
            let height: u32 = match filename.parse() {
                Ok(h) => h,
                Err(_) => continue,
            };

            // Sanity check - testnet/mainnet should never exceed 2M
            if height > 2_000_000 {
                tracing::warn!(
                    "Found suspiciously high filter file: {}.dat (height {}), ignoring",
                    filename,
                    height
                );
                continue;
            }

            max_height = Some(max_height.map_or(height, |current| current.max(height)));
        }

        Ok(max_height)
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
