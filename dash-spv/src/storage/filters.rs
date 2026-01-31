use std::{ops::Range, path::PathBuf};

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::{
    error::StorageResult,
    storage::{segments::SegmentCache, PersistentStorage},
};

#[async_trait]
pub trait FilterStorage {
    async fn store_filter(&mut self, height: u32, filter: &[u8]) -> StorageResult<()>;

    async fn load_filters(&self, range: Range<u32>) -> StorageResult<Vec<Vec<u8>>>;
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
}
