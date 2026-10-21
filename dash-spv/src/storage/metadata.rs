use std::path::PathBuf;

use crate::{
    error::StorageResult,
    storage::{io::atomic_write, PersistentStorage},
    StorageError,
};
use async_trait::async_trait;
use dashcore::prelude::CoreBlockHeight;

/// Metadata key for persisting the best known peer height.
const LAST_TARGET_HEIGHT_KEY: &str = "last_target_height";

#[async_trait]
pub trait MetadataStorage: Send + Sync + 'static {
    async fn store_metadata(&mut self, key: &str, value: &[u8]) -> StorageResult<()>;

    async fn load_metadata(&self, key: &str) -> StorageResult<Option<Vec<u8>>>;
    /// Persist the last target height to metadata storage.
    async fn store_last_target_height(&mut self, height: CoreBlockHeight) -> StorageResult<()>;
    /// Load the last target height from metadata storage.
    async fn load_last_target_height(&self) -> StorageResult<CoreBlockHeight>;
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

    async fn load_metadata(&self, key: &str) -> StorageResult<Option<Vec<u8>>> {
        let path = self.storage_path.join(Self::FOLDER_NAME).join(format!("{key}.dat"));

        if !path.exists() {
            return Ok(None);
        }

        let data = tokio::fs::read(path).await?;
        Ok(Some(data))
    }

    /// Persist the last target height to metadata storage.
    async fn store_last_target_height(&mut self, height: CoreBlockHeight) -> StorageResult<()> {
        match serde_json::to_vec(&height) {
            Ok(converted) => self.store_metadata(LAST_TARGET_HEIGHT_KEY, &converted).await,
            Err(e) => {
                let error = format!("Failed to serialize last target height: {}", e);
                tracing::warn!(error);
                Err(StorageError::Serialization(error))
            }
        }
    }

    /// Load the last target height from metadata storage. Used by the block headers manager to
    /// restore progress after restart.
    async fn load_last_target_height(&self) -> StorageResult<CoreBlockHeight> {
        match self.load_metadata(LAST_TARGET_HEIGHT_KEY).await {
            Ok(Some(bytes)) => match serde_json::from_slice::<CoreBlockHeight>(&bytes) {
                Ok(last_target_height) => {
                    tracing::debug!("Restored last target height {}", last_target_height);
                    Ok(last_target_height)
                }
                Err(e) => {
                    let error = format!("Failed to deserialize last target height: {}", e);
                    tracing::warn!(error);
                    Err(StorageError::Serialization(error))
                }
            },
            Ok(None) => {
                let error = "No last target height found (fresh start)".to_string();
                tracing::debug!(error);
                Err(StorageError::NotFound(error))
            }
            Err(e) => {
                let error = format!("Failed to load last target height: {}", e);
                tracing::warn!(error);
                Err(StorageError::Corruption(error))
            }
        }
    }
}
