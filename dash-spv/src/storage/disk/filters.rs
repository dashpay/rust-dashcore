//! Filter storage operations for DiskStorageManager.

use super::manager::DiskStorageManager;
use super::segments::{FilterDataIndexEntry, SegmentState};
use crate::error::StorageResult;
use crate::storage::disk::FILTERS_PER_SEGMENT;

impl DiskStorageManager {
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

        // Update cached filter data tip height
        {
            let mut tip = self.cached_filter_data_tip_height.write().await;
            if tip.is_none_or(|t| height > t) {
                *tip = Some(height);
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

        // Clear in-memory and on-disk filter headers segments
        self.filter_headers.write().await.clear_all().await?;
        self.active_filter_data_segments.write().await.clear();

        // Remove on-disk compact filter files
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
