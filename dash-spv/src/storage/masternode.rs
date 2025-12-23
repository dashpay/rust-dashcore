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

pub struct PersistentMasternodeStateStorage {}

#[async_trait]
impl PersistentStorage for PersistentMasternodeStateStorage {
    async fn load(&self) -> StorageResult<Self> {
        Ok(PersistentMasternodeStateStorage {})
    }

    async fn persist(&self) {
        // Current implementation persists data everytime data is stored
    }
}

#[async_trait]
impl MasternodeStateStorage for PersistentMasternodeStateStorage {
    async fn store_masternode_state(&mut self, state: &MasternodeState) -> StorageResult<()> {
        let path = self.base_path.join("state/masternode.json");
        let json = serde_json::to_string_pretty(state).map_err(|e| {
            crate::error::StorageError::Serialization(format!(
                "Failed to serialize masternode state: {}",
                e
            ))
        })?;

        atomic_write(&path, json.as_bytes()).await?;
        Ok(())
    }

    async fn load_masternode_state(&self) -> StorageResult<Option<MasternodeState>> {
        let path = self.base_path.join("state/masternode.json");
        if !path.exists() {
            return Ok(None);
        }

        let content = tokio::fs::read_to_string(path).await?;
        let state = serde_json::from_str(&content).map_err(|e| {
            crate::error::StorageError::Serialization(format!(
                "Failed to deserialize masternode state: {}",
                e
            ))
        })?;

        Ok(Some(state))
    }
}
