use std::path::PathBuf;

use async_trait::async_trait;

use dashcore::sml::masternode_list_engine::MasternodeListEngine;
use dashcore::Network;

use crate::{
    error::StorageResult,
    storage::{io::atomic_write, MasternodeState, PersistentStorage},
};

/// Persistence for the masternode list engine.
///
/// Takes and returns the engine itself: the on-disk shape is
/// [`MasternodeState`] and stays here, so a caller neither builds it nor knows
/// how it is encoded.
#[async_trait]
pub trait MasternodeStateStorage {
    async fn store_engine(
        &mut self,
        engine: &MasternodeListEngine,
        height: u32,
    ) -> StorageResult<()>;

    /// Always yields an engine: with nothing persisted yet, the network's
    /// default, which is what a first run starts from anyway.
    async fn load_engine(&self, network: Network) -> StorageResult<MasternodeListEngine>;
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
    async fn store_engine(
        &mut self,
        engine: &MasternodeListEngine,
        height: u32,
    ) -> StorageResult<()> {
        let masternodestate_folder = self.storage_path.join(Self::FOLDER_NAME);
        let path = masternodestate_folder.join(Self::MASTERNODE_FILE_NAME);

        tokio::fs::create_dir_all(masternodestate_folder).await?;

        let state = MasternodeState {
            last_height: height,
            engine_state: serde_json::to_vec(engine).map_err(|e| {
                crate::error::StorageError::Serialization(format!(
                    "Failed to serialize masternode engine: {}",
                    e
                ))
            })?,
            last_update: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };

        let json = serde_json::to_string_pretty(&state).map_err(|e| {
            crate::error::StorageError::Serialization(format!(
                "Failed to serialize masternode state: {}",
                e
            ))
        })?;

        atomic_write(&path, json.as_bytes()).await?;
        Ok(())
    }

    async fn load_engine(&self, network: Network) -> StorageResult<MasternodeListEngine> {
        let path = self.storage_path.join(Self::FOLDER_NAME).join(Self::MASTERNODE_FILE_NAME);

        if !path.exists() {
            tracing::debug!("No persisted masternode state, starting from the network default");
            return Ok(MasternodeListEngine::default_for_network(network));
        }

        let content = tokio::fs::read_to_string(path).await?;
        let state: MasternodeState = serde_json::from_str(&content).map_err(|e| {
            crate::error::StorageError::Serialization(format!(
                "Failed to deserialize masternode state: {}",
                e
            ))
        })?;
        let engine = serde_json::from_slice(&state.engine_state).map_err(|e| {
            crate::error::StorageError::Serialization(format!(
                "Failed to deserialize masternode engine: {}",
                e
            ))
        })?;

        tracing::debug!("Loaded masternode engine from height {}", state.last_height);
        Ok(engine)
    }
}
