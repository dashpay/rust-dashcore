use std::path::PathBuf;

use async_trait::async_trait;

use crate::{
    error::StorageResult,
    storage::{io::atomic_write, PersistentStorage},
    ChainState,
};

#[async_trait]
pub trait ChainStateStorage {
    async fn store_chain_state(&mut self, state: &ChainState) -> StorageResult<()>;

    async fn load_chain_state(&self) -> StorageResult<Option<ChainState>>;
}

pub struct PersistentChainStateStorage {
    storage_path: PathBuf,
}

impl PersistentChainStateStorage {
    const FOLDER_NAME: &str = "chainstate";
    const FILE_NAME: &str = "chainstate.json";
}

#[async_trait]
impl PersistentStorage for PersistentChainStateStorage {
    async fn open(storage_path: impl Into<PathBuf> + Send) -> StorageResult<Self> {
        Ok(PersistentChainStateStorage {
            storage_path: storage_path.into(),
        })
    }

    async fn persist(&mut self, _storage_path: impl Into<PathBuf> + Send) -> StorageResult<()> {
        // Current implementation persists data everytime data is stored
        Ok(())
    }
}

#[async_trait]
impl ChainStateStorage for PersistentChainStateStorage {
    async fn store_chain_state(&mut self, state: &ChainState) -> StorageResult<()> {
        let state_data = serde_json::json!({
            "last_chainlock_height": state.last_chainlock_height,
            "sync_base_height": state.sync_base_height,
        });

        let chainstate_folder = self.storage_path.join(Self::FOLDER_NAME);
        let path = chainstate_folder.join(Self::FILE_NAME);

        tokio::fs::create_dir_all(chainstate_folder).await?;

        let json = state_data.to_string();
        atomic_write(&path, json.as_bytes()).await?;

        Ok(())
    }

    async fn load_chain_state(&self) -> StorageResult<Option<ChainState>> {
        let path = self.storage_path.join(Self::FOLDER_NAME).join(Self::FILE_NAME);
        if !path.exists() {
            return Ok(None);
        }

        let content = tokio::fs::read_to_string(path).await?;
        let value: serde_json::Value = serde_json::from_str(&content).map_err(|e| {
            crate::error::StorageError::Serialization(format!("Failed to parse chain state: {}", e))
        })?;

        let state = ChainState {
            last_chainlock_height: value
                .get("last_chainlock_height")
                .and_then(|v| v.as_u64())
                .map(|h| h as u32),
            sync_base_height: value
                .get("sync_base_height")
                .and_then(|v| v.as_u64())
                .map(|h| h as u32)
                .unwrap_or(0),
        };

        Ok(Some(state))
    }
}
