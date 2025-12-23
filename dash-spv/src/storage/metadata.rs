use async_trait::async_trait;

use crate::{
    error::StorageResult,
    storage::{io::atomic_write, PersistentStorage},
};

#[async_trait]
pub trait MetadataStorage {
    async fn store_metadata(&mut self, key: &str, value: &[u8]) -> StorageResult<()>;

    async fn load_metadata(&self, key: &str) -> StorageResult<Option<Vec<u8>>>;
}

pub struct PersistentMetadataStorage {}

#[async_trait]
impl PersistentStorage for PersistentMetadataStorage {
    async fn load(&self) -> StorageResult<Self> {
        Ok(PersistentMetadataStorage {})
    }

    async fn persist(&self) {
        // Current implementation persists data everytime data is stored
    }
}

#[async_trait]
impl MetadataStorage for PersistentMetadataStorage {
    async fn store_metadata(&mut self, key: &str, value: &[u8]) -> StorageResult<()> {
        let path = self.base_path.join(format!("state/{}.dat", key));
        atomic_write(&path, value).await?;
        Ok(())
    }

    async fn load_metadata(&self, key: &str) -> StorageResult<Option<Vec<u8>>> {
        let path = self.base_path.join(format!("state/{}.dat", key));
        if !path.exists() {
            return Ok(None);
        }

        let data = tokio::fs::read(path).await?;
        Ok(Some(data))
    }
}
