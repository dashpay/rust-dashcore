use std::{
    ops::Range,
    sync::{Arc, RwLock},
};

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
    filter_headers: Arc<RwLock<SegmentCache<FilterHeader>>>,
}

#[async_trait]
impl PersistentStorage for PersistentFilterHeaderStorage {
    async fn load(&self) -> StorageResult<Self> {
        todo!()
    }

    async fn persist(&self) {
        todo!()
    }
}

#[async_trait]
impl FilterHeaderStorage for PersistentFilterHeaderStorage {
    /// Store filter headers.
    async fn store_filter_headers(&mut self, headers: &[FilterHeader]) -> StorageResult<()> {
        self.filter_headers.write().await.store_items(headers).await
    }

    /// Load filter headers in the given blockchain height range.
    async fn load_filter_headers(&self, range: Range<u32>) -> StorageResult<Vec<FilterHeader>> {
        self.filter_headers.write().await.get_items(range).await
    }

    /// Get a specific filter header by blockchain height.
    async fn get_filter_header(&self, height: u32) -> StorageResult<Option<FilterHeader>> {
        Ok(self.filter_headers.write().await.get_items(height..height + 1).await?.first().copied())
    }

    /// Get the current filter tip blockchain height.
    async fn get_filter_tip_height(&self) -> StorageResult<Option<u32>> {
        Ok(self.filter_headers.read().await.tip_height())
    }
}

pub struct PersistentFilterStorage {
    filters: Arc<RwLock<SegmentCache<Vec<u8>>>>,
}

#[async_trait]
impl PersistentStorage for PersistentFilterStorage {
    async fn load(&self) -> StorageResult<Self> {
        todo!()
    }

    async fn persist(&self) {
        todo!()
    }
}

#[async_trait]
impl FilterStorage for PersistentFilterStorage {
    /// Store a compact filter at a blockchain height.
    async fn store_filter(&mut self, height: u32, filter: &[u8]) -> StorageResult<()> {
        self.filters.write().await.store_items_at_height(&[filter.to_vec()], height).await
    }

    /// Load compact filters in the given blockchain height range.
    async fn load_filters(&self, range: Range<u32>) -> StorageResult<Vec<Vec<u8>>> {
        self.filters.write().await.get_items(range).await
    }
}
