use std::path::PathBuf;

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

pub struct PersistentMetadataStorage {
    storage_path: PathBuf,
}

impl PersistentMetadataStorage {
    const FOLDER_NAME: &str = "metadata";
}

#[async_trait]
impl PersistentStorage for PersistentMetadataStorage {
    async fn load(storage_path: impl Into<PathBuf> + Send) -> StorageResult<Self> {
        Ok(PersistentMetadataStorage {
            storage_path: storage_path.into(),
        })
    }

    async fn persist(&mut self, _storage_path: impl Into<PathBuf> + Send) -> StorageResult<()> {
        // Current implementation persists data everytime data is stored
        Ok(())
    }
}

#[async_trait]
impl MetadataStorage for PersistentMetadataStorage {
    async fn store_metadata(&mut self, key: &str, value: &[u8]) -> StorageResult<()> {
        let metadata_folder = self.storage_path.join(Self::FOLDER_NAME);
        let path = metadata_folder.join(format!("{key}.dat"));

        tokio::fs::create_dir_all(metadata_folder).await?;

        atomic_write(&path, value).await?;

        Ok(())
    }

    async fn load_metadata(&self, key: &str) -> StorageResult<Option<Vec<u8>>> {
        let path = self.storage_path.join(Self::FOLDER_NAME).join(format!("{key}.dat"));

        if !path.exists() {
            return Ok(None);
        }

        let data = tokio::fs::read(path).await?;
        Ok(Some(data))
    }
}
