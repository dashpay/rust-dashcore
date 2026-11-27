use std::path::PathBuf;

use crate::{
    error::StorageResult,
    storage::{io::atomic_write, PersistentStorage},
    StorageError,
};
use async_trait::async_trait;
use serde::de::DeserializeOwned;

#[async_trait]
pub trait MetadataStorage: Send + Sync + 'static {
    async fn store_metadata(&mut self, key: &str, value: &[u8]) -> StorageResult<()>;

    /// The JSON value stored under `key`, `None` when nothing is.
    async fn load_metadata<T: DeserializeOwned + Send>(
        &self,
        key: &str,
    ) -> StorageResult<Option<T>>;
}

pub struct PersistentMetadataStorage {
    storage_path: PathBuf,
}

impl PersistentMetadataStorage {
    const FOLDER_NAME: &str = "metadata";
}

#[async_trait]
impl PersistentStorage for PersistentMetadataStorage {
    async fn open(storage_path: impl Into<PathBuf> + Send) -> StorageResult<Self> {
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

    async fn load_metadata<T: DeserializeOwned + Send>(
        &self,
        key: &str,
    ) -> StorageResult<Option<T>> {
        let path = self.storage_path.join(Self::FOLDER_NAME).join(format!("{key}.dat"));

        if !path.exists() {
            return Ok(None);
        }

        let data = tokio::fs::read(path).await?;
        serde_json::from_slice(&data).map(Some).map_err(|e| {
            StorageError::Corruption(format!("Failed to deserialize metadata {key}: {e}"))
        })
    }
}
