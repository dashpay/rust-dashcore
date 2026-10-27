use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::sml_engine::MasternodeListEngine;
use dashcore::prelude::CoreBlockHeight;
use dashcore::Network;

use crate::error::{StorageError, StorageResult};
use crate::storage::{io::atomic_write, BlockHeaderStorage};

#[async_trait]
pub trait MasternodeStorage: Send + Sync + 'static {
    /// Drops what the engine holds above `height` and stores it again, so the
    /// snapshot never holds lists of an abandoned branch.
    async fn truncate_above(&mut self, height: CoreBlockHeight) -> StorageResult<()>;
}

pub struct PersistentMasternodeStorage<H: BlockHeaderStorage> {
    storage_path: PathBuf,
    network: Network,
    engine: Arc<RwLock<MasternodeListEngine<H>>>,
}

impl<H: BlockHeaderStorage> PersistentMasternodeStorage<H> {
    const FOLDER_NAME: &str = "masternodes";
    const FILE_NAME: &str = "engine.dat";

    /// Opens the storage and restores the engine from the snapshot when its
    /// newest list is still in the header chain at its height. The engine
    /// starts empty otherwise.
    pub async fn open(
        storage_path: impl Into<PathBuf> + Send,
        headers: Arc<RwLock<H>>,
        network: Network,
    ) -> Self {
        let storage_path = storage_path.into();

        let path = storage_path.join(Self::FOLDER_NAME).join(Self::FILE_NAME);

        let engine = match Self::read_snapshot(network, &headers, &path).await {
            Ok(Some(engine)) => Some(engine),
            Ok(None) => None,
            Err(e) => {
                if path.exists() {
                    tokio::fs::remove_file(&path).await.ok();
                }

                tracing::warn!("Not restoring the masternode engine snapshot: {e}");
                None
            }
        };

        let engine = engine.unwrap_or_else(|| MasternodeListEngine::new(network, headers));

        PersistentMasternodeStorage {
            storage_path,
            network,
            engine: Arc::new(RwLock::new(engine)),
        }
    }

    async fn read_snapshot(
        network: Network,
        headers: &Arc<RwLock<H>>,
        path: &Path,
    ) -> StorageResult<Option<MasternodeListEngine<H>>> {
        if !path.exists() {
            return Ok(None);
        }

        let bytes = tokio::fs::read(path).await?;

        let engine = MasternodeListEngine::from_snapshot(network, Arc::clone(headers), &bytes)
            .map_err(|e| StorageError::ReadFailed(e.to_string()))?;

        let Some(engine_tip) = engine.latest_masternode_list() else {
            tracing::warn!("The masternode engine snapshot has no lists, ignoring it");
            return Ok(None);
        };

        let in_chain =
            headers.read().await.get_header_height_by_hash(&engine_tip.block_hash).await?;

        if in_chain != Some(engine_tip.known_height) {
            tracing::warn!(
                "The masternode engine snapshot's tip {} is not in the header chain, ignoring it",
                engine_tip.known_height
            );
            return Ok(None);
        }

        Ok(Some(engine))
    }

    /// Shared access to the engine this storage persists.
    pub fn engine(&self) -> Arc<RwLock<MasternodeListEngine<H>>> {
        Arc::clone(&self.engine)
    }

    fn folder(&self) -> PathBuf {
        self.storage_path.join(Self::FOLDER_NAME)
    }

    fn path(&self) -> PathBuf {
        self.folder().join(Self::FILE_NAME)
    }

    /// Replaces the snapshot with the engine. An engine without lists is not
    /// stored, and drops the snapshot instead, so it never outlives the lists
    /// it held.
    pub async fn persist(&mut self) -> StorageResult<()> {
        let engine = self.engine.read().await;

        if engine.latest_masternode_list().is_none() {
            drop(engine);
            let _ = tokio::fs::remove_file(self.path()).await;
            return Ok(());
        }

        let bytes = engine.snapshot().map_err(|e| StorageError::WriteFailed(e.to_string()))?;

        drop(engine);

        tokio::fs::create_dir_all(self.folder()).await?;
        atomic_write(&self.path(), &bytes).await?;

        Ok(())
    }

    pub async fn clear(&mut self, headers: Arc<RwLock<H>>) {
        *self.engine.write().await = MasternodeListEngine::new(self.network, headers);
    }
}

#[async_trait]
impl<H: BlockHeaderStorage> MasternodeStorage for PersistentMasternodeStorage<H> {
    async fn truncate_above(&mut self, height: CoreBlockHeight) -> StorageResult<()> {
        self.engine.write().await.truncate_above(height).await;

        self.persist().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sml_engine::test_support::TestEngine;
    use crate::test_utils::MockHeaderStorage;
    use dashcore::sml::masternode_list::MasternodeList;
    use dashcore::BlockHash;
    use dashcore_hashes::Hash;

    use tempfile::TempDir;
    use test_case::test_case;

    type TestStorage = PersistentMasternodeStorage<MockHeaderStorage>;

    fn hash(byte: u8) -> BlockHash {
        BlockHash::from_slice(&[byte; 32]).unwrap()
    }

    async fn open_storage(dir: &TempDir, headers: Arc<RwLock<MockHeaderStorage>>) -> TestStorage {
        PersistentMasternodeStorage::open(dir.path(), headers, Network::Mainnet).await
    }

    /// An engine whose header chain holds `heights` and whose lists stand at
    /// each of them.
    fn engine_with_lists(heights: &[(u8, u32)]) -> TestEngine {
        let mut engine = TestEngine::knowing(
            Network::Mainnet,
            heights.iter().map(|(b, h)| (hash(*b), *h)).collect(),
        );
        for (byte, height) in heights {
            engine.masternode_lists.insert(*height, MasternodeList::empty(hash(*byte), *height));
        }
        engine
    }

    /// Makes `engine` the storage's engine and persists it.
    async fn persist(storage: &mut TestStorage, engine: TestEngine) {
        *storage.engine().write().await = engine;
        storage.persist().await.unwrap();
    }

    async fn list_heights(storage: &TestStorage) -> Vec<u32> {
        storage.engine().read().await.masternode_lists.keys().copied().collect()
    }

    fn snapshot_file(dir: &TempDir) -> PathBuf {
        dir.path().join("masternodes").join("engine.dat")
    }

    #[tokio::test]
    async fn a_reopened_storage_restores_the_persisted_engine() {
        let dir = TempDir::new().unwrap();
        let engine = TestEngine::mainnet_fixture();
        let headers = engine.headers();
        let expected = engine.snapshot().unwrap();
        persist(&mut open_storage(&dir, Arc::clone(&headers)).await, engine).await;

        let reopened = open_storage(&dir, headers).await;

        let restored = reopened.engine();
        let restored = restored.read().await;
        assert!(!restored.rotated_quorums_per_cycle().is_empty(), "the fixture holds cycles");
        assert_eq!(restored.snapshot().unwrap(), expected);
    }

    #[tokio::test]
    async fn an_empty_storage_opens_with_an_empty_engine() {
        let dir = TempDir::new().unwrap();
        let storage = open_storage(&dir, engine_with_lists(&[]).headers()).await;

        assert!(list_heights(&storage).await.is_empty());
    }

    #[tokio::test]
    async fn persisting_replaces_the_previous_snapshot() {
        let dir = TempDir::new().unwrap();
        let heights = [(0xAA, 100), (0xBB, 200)];
        let headers = engine_with_lists(&heights).headers();
        let mut storage = open_storage(&dir, Arc::clone(&headers)).await;

        persist(&mut storage, engine_with_lists(&heights[..1])).await;
        persist(&mut storage, engine_with_lists(&heights)).await;

        let files = std::fs::read_dir(dir.path().join("masternodes")).unwrap().count();
        assert_eq!(files, 1);
        assert_eq!(list_heights(&open_storage(&dir, headers).await).await, vec![100, 200]);
    }

    #[tokio::test]
    async fn an_engine_without_lists_is_not_persisted() {
        let dir = TempDir::new().unwrap();
        let mut storage = open_storage(&dir, engine_with_lists(&[]).headers()).await;

        storage.persist().await.unwrap();

        assert!(!snapshot_file(&dir).exists());
    }

    #[test_case(200, &[100, 200]; "at the newest list keeps it")]
    #[test_case(150, &[100]; "between the lists drops the newer one")]
    #[test_case(50, &[]; "below every list drops the snapshot")]
    #[tokio::test]
    async fn truncating_stores_what_the_engine_keeps(height: u32, kept: &[u32]) {
        let dir = TempDir::new().unwrap();
        let heights = [(0xAA, 100), (0xBB, 200)];
        let headers = engine_with_lists(&heights).headers();
        let mut storage = open_storage(&dir, Arc::clone(&headers)).await;
        persist(&mut storage, engine_with_lists(&heights)).await;

        storage.truncate_above(height).await.unwrap();

        assert_eq!(list_heights(&storage).await, kept);
        assert_eq!(snapshot_file(&dir).exists(), !kept.is_empty());
        assert_eq!(list_heights(&open_storage(&dir, headers).await).await, kept);
    }

    #[tokio::test]
    async fn a_snapshot_whose_block_left_the_chain_is_not_restored() {
        let dir = TempDir::new().unwrap();
        let heights = [(0xAA, 100), (0xBB, 200)];
        let mut chain = engine_with_lists(&heights);
        persist(&mut open_storage(&dir, chain.headers()).await, engine_with_lists(&heights)).await;

        chain.forget_block(&hash(0xBB));

        assert!(list_heights(&open_storage(&dir, chain.headers()).await).await.is_empty());
    }

    #[test_case(&[]; "empty")]
    #[test_case(&[0xFF, 0xFF]; "undecodable")]
    #[tokio::test]
    async fn an_unreadable_snapshot_is_not_restored(bytes: &[u8]) {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("masternodes")).unwrap();
        std::fs::write(snapshot_file(&dir), bytes).unwrap();

        let storage = open_storage(&dir, engine_with_lists(&[]).headers()).await;

        assert!(list_heights(&storage).await.is_empty());
    }

    #[tokio::test]
    async fn clearing_empties_the_shared_engine_in_place() {
        let dir = TempDir::new().unwrap();
        let heights = [(0xAA, 100)];
        let headers = engine_with_lists(&heights).headers();
        let mut storage = open_storage(&dir, Arc::clone(&headers)).await;
        persist(&mut storage, engine_with_lists(&heights)).await;
        let shared = storage.engine();

        storage.clear(headers).await;

        assert!(shared.read().await.masternode_lists.is_empty());
    }
}
