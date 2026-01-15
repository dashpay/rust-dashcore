use std::path::PathBuf;

use async_trait::async_trait;

use crate::{
    error::StorageResult,
    storage::{io::atomic_write, MasternodeState, PersistentStorage},
};

#[async_trait]
pub trait MasternodeStateStorage {
    async fn store_masternode_state(&mut self, state: &MasternodeState) -> StorageResult<()>;

    async fn load_masternode_state(&self) -> StorageResult<Option<MasternodeState>>;
}

pub struct PersistentMasternodeStateStorage {
    storage_path: PathBuf,
}

impl PersistentMasternodeStateStorage {
    const FOLDER_NAME: &str = "masternodestate";
    const MASTERNODE_FILE_NAME: &str = "masternodestate.json";
}

#[async_trait]
impl PersistentStorage for PersistentMasternodeStateStorage {
    async fn open(storage_path: impl Into<PathBuf> + Send) -> StorageResult<Self> {
        Ok(PersistentMasternodeStateStorage {
            storage_path: storage_path.into(),
        })
    }

    async fn persist(&mut self, _storage_path: impl Into<PathBuf> + Send) -> StorageResult<()> {
        // Current implementation persists data everytime data is stored
        Ok(())
    }
}

#[async_trait]
impl MasternodeStateStorage for PersistentMasternodeStateStorage {
    async fn store_masternode_state(&mut self, state: &MasternodeState) -> StorageResult<()> {
        let masternodestate_folder = self.storage_path.join(Self::FOLDER_NAME);
        let path = masternodestate_folder.join(Self::MASTERNODE_FILE_NAME);

        tokio::fs::create_dir_all(masternodestate_folder).await?;

        let json = serde_json::to_string_pretty(state).map_err(|e| {
            crate::StorageError::Serialization(format!(
                "Failed to serialize masternode state: {}",
                e
            ))
        })?;

        atomic_write(&path, json.as_bytes()).await?;
        Ok(())
    }

    async fn load_masternode_state(&self) -> StorageResult<Option<MasternodeState>> {
        let path = self.storage_path.join(Self::FOLDER_NAME).join(Self::MASTERNODE_FILE_NAME);

        if !path.exists() {
            return Ok(None);
        }

        let content = tokio::fs::read_to_string(path).await?;
        let state = serde_json::from_str(&content).map_err(|e| {
            crate::StorageError::Serialization(format!(
                "Failed to deserialize masternode state: {}",
                e
            ))
        })?;

        Ok(Some(state))
    }
}
