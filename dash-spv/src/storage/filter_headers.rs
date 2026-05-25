use crate::error::StorageResult;
use crate::storage::segments::SegmentCache;
use crate::storage::PersistentStorage;
use async_trait::async_trait;
use dashcore::hash_types::FilterHeader;
use std::ops::Range;
use std::path::PathBuf;
use tokio::sync::RwLock;

#[async_trait]
pub trait FilterHeaderStorage: Send + Sync + 'static {
    async fn store_filter_headers(&mut self, headers: &[FilterHeader]) -> StorageResult<()>;

    async fn store_filter_headers_at_height(
        &mut self,
        headers: &[FilterHeader],
        height: u32,
    ) -> StorageResult<()>;

    /// Load a contiguous range of filter headers by height.
    ///
    /// Returns `StorageError::InvalidArgument` when the range extends into a
    /// segment queued for deletion by a prior `truncate_above` (before the next
    /// `persist`). Callers must clamp the range to at most `get_filter_tip_height`.
    async fn load_filter_headers(&self, range: Range<u32>) -> StorageResult<Vec<FilterHeader>>;

    async fn get_filter_header(&self, height: u32) -> StorageResult<Option<FilterHeader>> {
        if let Some(tip_height) = self.get_filter_tip_height().await? {
            if height > tip_height {
                return Ok(None);
            }
        } else {
            return Ok(None);
        }

        if let Some(start_height) = self.get_filter_start_height().await {
            if height < start_height {
                return Ok(None);
            }
        } else {
            return Ok(None);
        }

        Ok(self.load_filter_headers(height..height + 1).await?.first().copied())
    }

    async fn get_filter_tip_height(&self) -> StorageResult<Option<u32>>;

    async fn get_filter_start_height(&self) -> Option<u32>;

    /// Drop all filter headers with `height > target_height`.
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

pub struct PersistentFilterHeaderStorage {
    filter_headers: RwLock<SegmentCache<FilterHeader>>,
}

impl PersistentFilterHeaderStorage {
    const FOLDER_NAME: &str = "filter_headers";
}

#[async_trait]
impl PersistentStorage for PersistentFilterHeaderStorage {
    async fn open(storage_path: impl Into<PathBuf> + Send) -> StorageResult<Self> {
        let storage_path = storage_path.into();
        let segments_folder = storage_path.join(Self::FOLDER_NAME);

        let filter_headers = SegmentCache::load_or_new(segments_folder).await?;

        Ok(Self {
            filter_headers: RwLock::new(filter_headers),
        })
    }

    async fn persist(&mut self, base_path: impl Into<PathBuf> + Send) -> StorageResult<()> {
        let filter_headers_folder = base_path.into().join(Self::FOLDER_NAME);

        tokio::fs::create_dir_all(&filter_headers_folder).await?;

        self.filter_headers.write().await.persist(&filter_headers_folder).await;
        Ok(())
    }
}

#[async_trait]
impl FilterHeaderStorage for PersistentFilterHeaderStorage {
    async fn store_filter_headers(&mut self, headers: &[FilterHeader]) -> StorageResult<()> {
        self.filter_headers.write().await.store_items(headers).await
    }

    async fn store_filter_headers_at_height(
        &mut self,
        headers: &[FilterHeader],
        height: u32,
    ) -> StorageResult<()> {
        self.filter_headers.write().await.store_items_at_height(headers, height).await
    }

    async fn load_filter_headers(&self, range: Range<u32>) -> StorageResult<Vec<FilterHeader>> {
        self.filter_headers.write().await.get_items(range).await
    }

    async fn get_filter_tip_height(&self) -> StorageResult<Option<u32>> {
        Ok(self.filter_headers.read().await.tip_height())
    }

    async fn get_filter_start_height(&self) -> Option<u32> {
        self.filter_headers.read().await.start_height()
    }

    async fn truncate_above(&mut self, target_height: u32) -> StorageResult<()> {
        self.filter_headers.write().await.truncate_above(target_height).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_truncate_above_and_restore() {
        let tmp_dir = TempDir::new().unwrap();
        let mut storage = PersistentFilterHeaderStorage::open(tmp_dir.path()).await.unwrap();

        let headers = FilterHeader::dummy_batch(0..10);
        storage.store_filter_headers(&headers).await.unwrap();
        assert_eq!(storage.get_filter_tip_height().await.unwrap(), Some(9));

        storage.truncate_above(4).await.unwrap();
        assert_eq!(storage.get_filter_tip_height().await.unwrap(), Some(4));

        let kept = storage.load_filter_headers(0..5).await.unwrap();
        assert_eq!(kept, headers[0..5]);

        let replacement = FilterHeader::dummy_batch(100..105);
        storage.store_filter_headers_at_height(&replacement, 5).await.unwrap();
        assert_eq!(storage.get_filter_tip_height().await.unwrap(), Some(9));

        let reloaded = storage.load_filter_headers(5..10).await.unwrap();
        assert_eq!(reloaded, replacement);
    }

    #[tokio::test]
    async fn test_truncate_above_persist_reopen_filter_headers() {
        let tmp_dir = TempDir::new().unwrap();
        {
            let mut storage = PersistentFilterHeaderStorage::open(tmp_dir.path()).await.unwrap();
            let headers = FilterHeader::dummy_batch(0..10);
            storage.store_filter_headers(&headers).await.unwrap();
            storage.truncate_above(4).await.unwrap();
            storage.persist(tmp_dir.path()).await.unwrap();
        }

        let storage = PersistentFilterHeaderStorage::open(tmp_dir.path()).await.unwrap();
        assert_eq!(storage.get_filter_tip_height().await.unwrap(), Some(4));
        let kept = storage.load_filter_headers(0..5).await.unwrap();
        assert_eq!(kept, FilterHeader::dummy_batch(0..5));
        for h in 5..10 {
            assert_eq!(storage.get_filter_header(h).await.unwrap(), None);
        }
    }

    #[tokio::test]
    async fn test_truncate_above_tip_noop() {
        let tmp_dir = TempDir::new().unwrap();
        let mut storage = PersistentFilterHeaderStorage::open(tmp_dir.path()).await.unwrap();

        let headers = FilterHeader::dummy_batch(0..5);
        storage.store_filter_headers(&headers).await.unwrap();

        storage.truncate_above(100).await.unwrap();
        assert_eq!(storage.get_filter_tip_height().await.unwrap(), Some(4));
    }
}
