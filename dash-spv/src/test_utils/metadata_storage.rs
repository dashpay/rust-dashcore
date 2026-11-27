use async_trait::async_trait;
use dashcore::prelude::CoreBlockHeight;
use serde::de::DeserializeOwned;

use crate::error::{StorageError, StorageResult};
use crate::storage::MetadataStorage;

/// A [`MetadataStorage`] whose writes fail, as on a full disk.
pub struct FailingMetadataStorage;

#[async_trait]
impl MetadataStorage for FailingMetadataStorage {
    async fn store_metadata(&mut self, _key: &str, _value: &[u8]) -> StorageResult<()> {
        Err(StorageError::WriteFailed("disk full".to_string()))
    }

    async fn load_metadata<T: DeserializeOwned + Send>(
        &self,
        _key: &str,
    ) -> StorageResult<Option<T>> {
        Ok(None)
    }

    async fn store_last_target_height(&mut self, _height: CoreBlockHeight) -> StorageResult<()> {
        Err(StorageError::WriteFailed("disk full".to_string()))
    }

    async fn load_last_target_height(&self) -> StorageResult<CoreBlockHeight> {
        Err(StorageError::NotFound("nothing stored".to_string()))
    }
}
