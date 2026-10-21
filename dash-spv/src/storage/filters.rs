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

    /// Lowest filter height present in storage, or `None` when no filters are
    /// stored.
    ///
    /// `filter_tip_height` is a tip watermark only: storage is dense within
    /// `[filter_start_height, filter_tip_height]`, but heights below the start
    /// were never stored. Callers must not treat the tip as proof that storage
    /// is contiguous from an arbitrary lower height.
    async fn filter_start_height(&self) -> Option<u32>;

    /// Drop every stored filter, leaving the storage empty.
    ///
    /// Used when the stored range cannot serve the current scan (e.g. filters
    /// were previously stored from a checkpoint above a wallet's rescan
    /// start): keeping an unreachable island of tip-region filters would leave
    /// a permanent hole below it that the contiguous store path cannot fill.
    ///
    /// Like `truncate_above`, the deletion is not durable until the next
    /// successful `persist` call.
    async fn clear_filters(&mut self) -> StorageResult<()>;

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

    /// Declare the highest filter height that has been scanned and committed
    /// for every wallet, allowing the storage to stop holding those filters in
    /// memory.
    ///
    /// Filters at or below this height stay readable: `load_filters` reloads
    /// them from disk on demand. The watermark may move backwards when a
    /// rescan rolls the scan position back.
    ///
    /// Defaults to a no-op for implementations that hold no in-memory cache.
    async fn set_committed_height(&mut self, _height: u32) {}
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

    async fn filter_start_height(&self) -> Option<u32> {
        self.filters.read().await.start_height()
    }

    async fn clear_filters(&mut self) -> StorageResult<()> {
        self.filters.write().await.clear()
    }

    async fn truncate_above(&mut self, target_height: u32) -> StorageResult<()> {
        self.filters.write().await.truncate_above(target_height).await
    }

    async fn set_committed_height(&mut self, height: u32) {
        self.filters.write().await.set_committed_height(height);
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

    /// Filters stored only in a high region (as when headers previously
    /// synced from a checkpoint): the start accessor reports the true lowest
    /// stored height, reads below it fail loudly instead of returning
    /// sentinels, and `clear_filters` durably empties the storage.
    #[tokio::test]
    async fn test_filter_start_height_and_clear_filters() {
        let tmp_dir = TempDir::new().unwrap();
        let mut storage = PersistentFilterStorage::open(tmp_dir.path()).await.unwrap();

        assert_eq!(storage.filter_start_height().await, None);

        for height in 900..=1000 {
            storage.store_filter(height, &filter_bytes(height as u8)).await.unwrap();
        }
        assert_eq!(storage.filter_start_height().await, Some(900));
        assert_eq!(storage.filter_tip_height().await.unwrap(), 1000);

        // Reads that begin below the stored range must error, not hand back
        // sentinel data zipped against real headers.
        assert!(storage.load_filters(100..200).await.is_err());
        assert!(storage.load_filters(850..950).await.is_err());
        assert_eq!(storage.load_filters(900..1001).await.unwrap().len(), 101);

        storage.persist(tmp_dir.path()).await.unwrap();
        let segment_file =
            tmp_dir.path().join(PersistentFilterStorage::FOLDER_NAME).join("segment_0000.dat");
        assert!(segment_file.exists());

        // The start height survives a reload.
        let mut storage = PersistentFilterStorage::open(tmp_dir.path()).await.unwrap();
        assert_eq!(storage.filter_start_height().await, Some(900));

        storage.clear_filters().await.unwrap();
        assert_eq!(storage.filter_start_height().await, None);
        assert_eq!(storage.filter_tip_height().await.unwrap(), 0);
        assert!(storage.load_filters(900..901).await.is_err());

        storage.persist(tmp_dir.path()).await.unwrap();
        assert!(!segment_file.exists());

        // Reopen: the clear is durable, and the storage accepts a fresh
        // contiguous range from a lower start.
        let mut storage = PersistentFilterStorage::open(tmp_dir.path()).await.unwrap();
        assert_eq!(storage.filter_start_height().await, None);
        assert_eq!(storage.filter_tip_height().await.unwrap(), 0);

        for height in 100..=110 {
            storage.store_filter(height, &filter_bytes(height as u8)).await.unwrap();
        }
        assert_eq!(storage.filter_start_height().await, Some(100));
        assert_eq!(storage.load_filters(100..111).await.unwrap().len(), 11);
    }
}
