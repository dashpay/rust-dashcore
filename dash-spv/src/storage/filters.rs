use std::{ops::Range, path::PathBuf};

use async_trait::async_trait;
use dashcore::hash_types::FilterHeader;

use crate::{
    error::StorageResult,
    storage::{segments::SegmentCache, PersistentStorage},
};

#[async_trait]
pub trait FilterHeaderStorage {
    /// Store filter headers.
    async fn store_filter_headers(&mut self, headers: &[FilterHeader]) -> StorageResult<()>;

    /// Load filter headers in the given blockchain height range.
    async fn load_filter_headers(&self, range: Range<u32>) -> StorageResult<Vec<FilterHeader>>;

    /// Get a specific filter header by blockchain height.
    async fn get_filter_header(&self, height: u32) -> StorageResult<Option<FilterHeader>>;

    /// Get the current filter tip blockchain height.
    async fn get_filter_tip_height(&self) -> StorageResult<Option<u32>>;
}

#[async_trait]
pub trait FilterStorage {
    /// Store a compact filter at a blockchain height.
    async fn store_filter(&mut self, height: u32, filter: &[u8]) -> StorageResult<()>;

    /// Load compact filters in the given blockchain height range.
    async fn load_filters(&self, range: Range<u32>) -> StorageResult<Vec<Vec<u8>>>;
}

pub struct PersistentFilterHeaderStorage {
    filter_headers: SegmentCache<FilterHeader>,
}

impl PersistentFilterHeaderStorage {
    const FOLDER_NAME: &str = "filter_headers";
}

#[async_trait]
impl PersistentStorage for PersistentFilterHeaderStorage {
    async fn load(storage_path: impl Into<PathBuf> + Send) -> StorageResult<Self> {
        let storage_path = storage_path.into();
        let segments_folder = storage_path.join(Self::FOLDER_NAME);

        let filter_headers = SegmentCache::load_or_new(segments_folder).await?;

        Ok(Self {
            filter_headers,
        })
    }

    async fn persist(&mut self, base_path: impl Into<PathBuf> + Send) -> StorageResult<()> {
        let filter_headers_folder = base_path.into().join(Self::FOLDER_NAME);

        tokio::fs::create_dir_all(filter_headers_folder).await?;

        self.filter_headers.persist(filter_headers_folder).await
    }
}

#[async_trait]
impl FilterHeaderStorage for PersistentFilterHeaderStorage {
    /// Store filter headers.
    async fn store_filter_headers(&mut self, headers: &[FilterHeader]) -> StorageResult<()> {
        self.filter_headers.store_items(headers).await
    }

    /// Load filter headers in the given blockchain height range.
    async fn load_filter_headers(&self, range: Range<u32>) -> StorageResult<Vec<FilterHeader>> {
        self.filter_headers.get_items(range).await
    }

    /// Get a specific filter header by blockchain height.
    async fn get_filter_header(&self, height: u32) -> StorageResult<Option<FilterHeader>> {
        Ok(self.filter_headers.get_items(height..height + 1).await?.first().copied())
    }

    /// Get the current filter tip blockchain height.
    async fn get_filter_tip_height(&self) -> StorageResult<Option<u32>> {
        Ok(self.filter_headers.read().await.tip_height())
    }
}

pub struct PersistentFilterStorage {
    filters: SegmentCache<Vec<u8>>,
}

impl PersistentFilterStorage {
    const FOLDER_NAME: &str = "filters";
}

#[async_trait]
impl PersistentStorage for PersistentFilterStorage {
    async fn load(storage_path: impl Into<PathBuf> + Send) -> StorageResult<Self> {
        let storage_path = storage_path.into();
        let filters_folder = storage_path.join(Self::FOLDER_NAME);

        let filters = SegmentCache::load_or_new(filters_folder).await?;

        Ok(Self {
            filters,
        })
    }

    async fn persist(&mut self, storage_path: impl Into<PathBuf> + Send) -> StorageResult<()> {
        let storage_path = storage_path.into();
        let filters_folder = storage_path.join(Self::FOLDER_NAME);

        tokio::fs::create_dir_all(filters_folder).await?;

        self.filters.persist(filters_folder).await
    }
}

#[async_trait]
impl FilterStorage for PersistentFilterStorage {
    /// Store a compact filter at a blockchain height.
    async fn store_filter(&mut self, height: u32, filter: &[u8]) -> StorageResult<()> {
        self.filters.store_items_at_height(&[filter.to_vec()], height).await
    }

    /// Load compact filters in the given blockchain height range.
    async fn load_filters(&self, range: Range<u32>) -> StorageResult<Vec<Vec<u8>>> {
        self.filters.get_items(range).await
    }
}
