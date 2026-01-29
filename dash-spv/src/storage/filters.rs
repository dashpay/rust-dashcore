use std::{ops::Range, path::PathBuf};

use async_trait::async_trait;
use dashcore::hash_types::FilterHeader;
use tokio::sync::RwLock;

use crate::{
    error::StorageResult,
    storage::{segments::SegmentCache, PersistentStorage},
};

#[async_trait]
pub trait FilterHeaderStorage: Send + Sync + 'static {
    async fn store_filter_headers(&mut self, headers: &[FilterHeader]) -> StorageResult<()>;

    async fn store_filter_headers_at_height(
        &mut self,
        headers: &[FilterHeader],
        height: u32,
    ) -> StorageResult<()>;

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
}

#[async_trait]
pub trait FilterStorage: Send + Sync + 'static {
    async fn store_filter(&mut self, height: u32, filter: &[u8]) -> StorageResult<()>;

    async fn load_filters(&self, range: Range<u32>) -> StorageResult<Vec<Vec<u8>>>;

    async fn filter_tip_height(&self) -> StorageResult<u32>;
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
}
