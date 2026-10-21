use std::{ops::Range, path::PathBuf};

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::{
    error::StorageResult,
    storage::{segments::SegmentCache, PersistentStorage},
};

#[async_trait]
pub trait FilterStorage: Send + Sync + 'static {
    async fn store_filter(&mut self, height: u32, filter: &[u8]) -> StorageResult<()>;

    /// Load a contiguous range of filters by height.
    ///
    /// Returns `StorageError::InvalidArgument` when the range extends into a
    /// segment queued for deletion by a prior `truncate_above` (before the next
    /// `persist`). Callers must clamp the range to at most `filter_tip_height`.
    async fn load_filters(&self, range: Range<u32>) -> StorageResult<Vec<Vec<u8>>>;

    async fn filter_tip_height(&self) -> StorageResult<u32>;

    /// Drop all filters with `height > target_height`.
    ///
    /// Truncating above the current tip is a no-op, truncating below
    /// `start_height` returns an error. Changes are applied in-memory and
    /// flushed on the next `persist`.
    ///
    /// The truncation is not durable until the next successful `persist` call.
    /// A crash between `truncate_above` and `persist` may leave orphaned segment
    /// files on disk and cause the storage to reopen at the pre-truncation tip.
    async fn truncate_above(&mut self, target_height: u32) -> StorageResult<()>;
}

pub struct PersistentFilterStorage {
    filters: RwLock<SegmentCache<Vec<u8>>>,
}

impl PersistentFilterStorage {
    const FOLDER_NAME: &str = "filters";
}

#[async_trait]
impl PersistentStorage for PersistentFilterStorage {
    async fn open(storage_path: impl Into<PathBuf> + Send) -> StorageResult<Self> {
        let storage_path = storage_path.into();
        let filters_folder = storage_path.join(Self::FOLDER_NAME);

        let filters = SegmentCache::load_or_new(filters_folder).await?;

        Ok(Self {
            filters: RwLock::new(filters),
        })
    }

    async fn persist(&mut self, storage_path: impl Into<PathBuf> + Send) -> StorageResult<()> {
        let storage_path = storage_path.into();
        let filters_folder = storage_path.join(Self::FOLDER_NAME);

        tokio::fs::create_dir_all(&filters_folder).await?;

        self.filters.write().await.persist(&filters_folder).await;
        Ok(())
    }
}

#[async_trait]
impl FilterStorage for PersistentFilterStorage {
    async fn store_filter(&mut self, height: u32, filter: &[u8]) -> StorageResult<()> {
        self.filters.write().await.store_items_at_height(&[filter.to_vec()], height).await
    }

    async fn load_filters(&self, range: Range<u32>) -> StorageResult<Vec<Vec<u8>>> {
        self.filters.write().await.get_items(range).await
    }

    async fn filter_tip_height(&self) -> StorageResult<u32> {
        Ok(self.filters.read().await.tip_height().unwrap_or(0))
    }

    async fn truncate_above(&mut self, target_height: u32) -> StorageResult<()> {
        self.filters.write().await.truncate_above(target_height).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn filter_bytes(seed: u8) -> Vec<u8> {
        vec![seed; 8]
    }

    #[tokio::test]
    async fn test_truncate_above_wrapper_smoke() {
        let tmp_dir = TempDir::new().unwrap();
        let mut storage = PersistentFilterStorage::open(tmp_dir.path()).await.unwrap();

        for height in 0..5 {
            storage.store_filter(height, &filter_bytes(height as u8)).await.unwrap();
        }

        storage.truncate_above(2).await.unwrap();

        assert_eq!(storage.filter_tip_height().await.unwrap(), 2);
        assert!(storage.load_filters(3..4).await.is_err());
    }
}
