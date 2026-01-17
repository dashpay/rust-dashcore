//! Storage abstraction for the Dash SPV client.

pub(crate) mod io;

pub mod types;

mod blocks;
mod chainstate;
mod filters;
mod lockfile;
mod masternode;
mod metadata;
mod segments;
mod transactions;

use async_trait::async_trait;
use dashcore::hash_types::FilterHeader;
use dashcore::{Header as BlockHeader, Txid};
use std::collections::HashMap;
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::error::StorageResult;
use crate::storage::blocks::{BlockHeaderTip, PersistentBlockHeaderStorage};
use crate::storage::chainstate::PersistentChainStateStorage;
use crate::storage::filters::{PersistentFilterHeaderStorage, PersistentFilterStorage};
use crate::storage::lockfile::LockFile;
use crate::storage::masternode::PersistentMasternodeStateStorage;
use crate::storage::metadata::PersistentMetadataStorage;
use crate::storage::transactions::PersistentTransactionStorage;
use crate::types::{MempoolState, UnconfirmedTransaction};
use crate::ChainState;

pub use crate::storage::blocks::BlockHeaderStorage;
pub use crate::storage::chainstate::ChainStateStorage;
pub use crate::storage::filters::FilterHeaderStorage;
pub use crate::storage::filters::FilterStorage;
pub use crate::storage::masternode::MasternodeStateStorage;
pub use crate::storage::metadata::MetadataStorage;
pub use crate::storage::transactions::TransactionStorage;

pub use types::*;

#[async_trait]
pub trait PersistentStorage: Sized {
    /// If the storage_path contains persisted data the storage will use it, if not,
    /// a empty storage will be created.
    async fn open(storage_path: impl Into<PathBuf> + Send) -> StorageResult<Self>;

    async fn persist(&mut self, storage_path: impl Into<PathBuf> + Send) -> StorageResult<()>;
}

#[async_trait]
pub trait StorageManager:
    BlockHeaderStorage
    + FilterHeaderStorage
    + FilterStorage
    + TransactionStorage
    + MetadataStorage
    + ChainStateStorage
    + MasternodeStateStorage
    + Send
    + Sync
    + 'static
{
    /// Deletes in-disk and in-memory data
    async fn clear(&mut self) -> StorageResult<()>;

    /// Stops all background tasks and persists the data.
    async fn shutdown(&mut self);
}

/// Disk-based storage manager with segmented files and async background saving.
/// Only one instance of DiskStorageManager working on the same storage path
/// can exist at a time.
pub struct DiskStorageManager {
    storage_path: PathBuf,

    block_headers: Arc<RwLock<PersistentBlockHeaderStorage>>,
    filter_headers: Arc<RwLock<PersistentFilterHeaderStorage>>,
    filters: Arc<RwLock<PersistentFilterStorage>>,
    transactions: Arc<RwLock<PersistentTransactionStorage>>,
    metadata: Arc<RwLock<PersistentMetadataStorage>>,
    chainstate: Arc<RwLock<PersistentChainStateStorage>>,
    masternodestate: Arc<RwLock<PersistentMasternodeStateStorage>>,

    // Background worker
    worker_handle: Option<tokio::task::JoinHandle<()>>,

    _lock_file: LockFile,
}

impl DiskStorageManager {
    pub async fn new(storage_path: impl Into<PathBuf> + Send) -> StorageResult<Self> {
        use std::fs;

        let storage_path = storage_path.into();
        let lock_file = {
            let mut lock_file = storage_path.clone();
            lock_file.set_extension("lock");
            lock_file
        };

        fs::create_dir_all(&storage_path)?;

        let lock_file = LockFile::new(lock_file)?;

        let mut storage = Self {
            storage_path: storage_path.clone(),

            block_headers: Arc::new(RwLock::new(
                PersistentBlockHeaderStorage::open(&storage_path).await?,
            )),
            filter_headers: Arc::new(RwLock::new(
                PersistentFilterHeaderStorage::open(&storage_path).await?,
            )),
            filters: Arc::new(RwLock::new(PersistentFilterStorage::open(&storage_path).await?)),
            transactions: Arc::new(RwLock::new(
                PersistentTransactionStorage::open(&storage_path).await?,
            )),
            metadata: Arc::new(RwLock::new(PersistentMetadataStorage::open(&storage_path).await?)),
            chainstate: Arc::new(RwLock::new(
                PersistentChainStateStorage::open(&storage_path).await?,
            )),
            masternodestate: Arc::new(RwLock::new(
                PersistentMasternodeStateStorage::open(&storage_path).await?,
            )),

            worker_handle: None,

            _lock_file: lock_file,
        };

        storage.start_worker().await;

        Ok(storage)
    }

    #[cfg(test)]
    pub async fn with_temp_dir() -> StorageResult<Self> {
        use tempfile::TempDir;

        let temp_dir = TempDir::new()?;
        Self::new(temp_dir.path()).await
    }

    /// Start the background worker saving data every 5 seconds
    async fn start_worker(&mut self) {
        let block_headers = Arc::clone(&self.block_headers);
        let filter_headers = Arc::clone(&self.filter_headers);
        let filters = Arc::clone(&self.filters);
        let transactions = Arc::clone(&self.transactions);
        let metadata = Arc::clone(&self.metadata);
        let chainstate = Arc::clone(&self.chainstate);
        let masternodestate = Arc::clone(&self.masternodestate);

        let storage_path = self.storage_path.clone();

        let worker_handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(5));

            loop {
                ticker.tick().await;

                let _ = block_headers.write().await.persist(&storage_path).await;
                let _ = filter_headers.write().await.persist(&storage_path).await;
                let _ = filters.write().await.persist(&storage_path).await;
                let _ = transactions.write().await.persist(&storage_path).await;
                let _ = metadata.write().await.persist(&storage_path).await;
                let _ = chainstate.write().await.persist(&storage_path).await;
                let _ = masternodestate.write().await.persist(&storage_path).await;
            }
        });

        self.worker_handle = Some(worker_handle);
    }

    /// Stop the background worker without forcing a save.
    fn stop_worker(&self) {
        if let Some(handle) = &self.worker_handle {
            handle.abort();
        }
    }

    async fn persist(&self) {
        let storage_path = &self.storage_path;

        let _ = self.block_headers.write().await.persist(storage_path).await;
        let _ = self.filter_headers.write().await.persist(storage_path).await;
        let _ = self.filters.write().await.persist(storage_path).await;
        let _ = self.transactions.write().await.persist(storage_path).await;
        let _ = self.metadata.write().await.persist(storage_path).await;
        let _ = self.chainstate.write().await.persist(storage_path).await;
        let _ = self.masternodestate.write().await.persist(storage_path).await;
    }
}

#[async_trait]
impl StorageManager for DiskStorageManager {
    async fn clear(&mut self) -> StorageResult<()> {
        // First, stop the background worker to avoid races with file deletion
        self.stop_worker();

        // Remove all files and directories under storage_path
        if self.storage_path.exists() {
            // Best-effort removal; if concurrent files appear, retry once
            match tokio::fs::remove_dir_all(&self.storage_path).await {
                Ok(_) => {}
                Err(e)
                    if e.kind() == std::io::ErrorKind::Other
                        || e.kind() == std::io::ErrorKind::DirectoryNotEmpty =>
                {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    tokio::fs::remove_dir_all(&self.storage_path).await?;
                }
                Err(e) => return Err(crate::error::StorageError::Io(e)),
            }
            tokio::fs::create_dir_all(&self.storage_path).await?;
        }

        // Instantiate storages again once persisted data has been cleared
        let storage_path = &self.storage_path;

        self.block_headers =
            Arc::new(RwLock::new(PersistentBlockHeaderStorage::open(storage_path).await?));
        self.filter_headers =
            Arc::new(RwLock::new(PersistentFilterHeaderStorage::open(storage_path).await?));
        self.filters = Arc::new(RwLock::new(PersistentFilterStorage::open(storage_path).await?));
        self.transactions =
            Arc::new(RwLock::new(PersistentTransactionStorage::open(storage_path).await?));
        self.metadata = Arc::new(RwLock::new(PersistentMetadataStorage::open(storage_path).await?));
        self.chainstate =
            Arc::new(RwLock::new(PersistentChainStateStorage::open(storage_path).await?));
        self.masternodestate =
            Arc::new(RwLock::new(PersistentMasternodeStateStorage::open(storage_path).await?));

        // Restart the background worker for future operations
        self.start_worker().await;

        Ok(())
    }

    /// Shutdown the storage manager.
    async fn shutdown(&mut self) {
        self.stop_worker();

        self.persist().await;
    }
}

#[async_trait]
impl blocks::BlockHeaderStorage for DiskStorageManager {
    async fn store_headers(&mut self, headers: &[BlockHeader]) -> StorageResult<()> {
        self.block_headers.write().await.store_headers(headers).await
    }

    async fn store_headers_at_height(
        &mut self,
        headers: &[BlockHeader],
        height: u32,
    ) -> StorageResult<()> {
        self.block_headers.write().await.store_headers_at_height(headers, height).await
    }

    async fn load_headers(&self, range: Range<u32>) -> StorageResult<Vec<BlockHeader>> {
        self.block_headers.read().await.load_headers(range).await
    }

    async fn get_tip_height(&self) -> Option<u32> {
        self.block_headers.read().await.get_tip_height().await
    }

    async fn get_tip(&self) -> Option<BlockHeaderTip> {
        self.block_headers.read().await.get_tip().await
    }

    async fn get_start_height(&self) -> Option<u32> {
        self.block_headers.read().await.get_start_height().await
    }

    async fn get_stored_headers_len(&self) -> u32 {
        self.block_headers.read().await.get_stored_headers_len().await
    }

    async fn get_header_height_by_hash(
        &self,
        hash: &dashcore::BlockHash,
    ) -> StorageResult<Option<u32>> {
        self.block_headers.read().await.get_header_height_by_hash(hash).await
    }
}

#[async_trait]
impl filters::FilterHeaderStorage for DiskStorageManager {
    async fn store_filter_headers(&mut self, headers: &[FilterHeader]) -> StorageResult<()> {
        self.filter_headers.write().await.store_filter_headers(headers).await
    }

    async fn load_filter_headers(&self, range: Range<u32>) -> StorageResult<Vec<FilterHeader>> {
        self.filter_headers.read().await.load_filter_headers(range).await
    }

    async fn get_filter_tip_height(&self) -> StorageResult<Option<u32>> {
        self.filter_headers.read().await.get_filter_tip_height().await
    }

    async fn get_filter_start_height(&self) -> Option<u32> {
        self.filter_headers.read().await.get_filter_start_height().await
    }
}

#[async_trait]
impl filters::FilterStorage for DiskStorageManager {
    async fn store_filter(&mut self, height: u32, filter: &[u8]) -> StorageResult<()> {
        self.filters.write().await.store_filter(height, filter).await
    }

    async fn load_filters(&self, range: Range<u32>) -> StorageResult<Vec<Vec<u8>>> {
        self.filters.read().await.load_filters(range).await
    }
}

#[async_trait]
impl transactions::TransactionStorage for DiskStorageManager {
    async fn store_mempool_transaction(
        &mut self,
        txid: &Txid,
        tx: &UnconfirmedTransaction,
    ) -> StorageResult<()> {
        self.transactions.write().await.store_mempool_transaction(txid, tx).await
    }

    async fn remove_mempool_transaction(&mut self, txid: &Txid) -> StorageResult<()> {
        self.transactions.write().await.remove_mempool_transaction(txid).await
    }

    async fn get_mempool_transaction(
        &self,
        txid: &Txid,
    ) -> StorageResult<Option<UnconfirmedTransaction>> {
        self.transactions.read().await.get_mempool_transaction(txid).await
    }

    async fn get_all_mempool_transactions(
        &self,
    ) -> StorageResult<HashMap<Txid, UnconfirmedTransaction>> {
        self.transactions.read().await.get_all_mempool_transactions().await
    }

    async fn store_mempool_state(&mut self, state: &MempoolState) -> StorageResult<()> {
        self.transactions.write().await.store_mempool_state(state).await
    }

    async fn load_mempool_state(&self) -> StorageResult<Option<MempoolState>> {
        self.transactions.read().await.load_mempool_state().await
    }
}

#[async_trait]
impl metadata::MetadataStorage for DiskStorageManager {
    async fn store_metadata(&mut self, key: &str, value: &[u8]) -> StorageResult<()> {
        self.metadata.write().await.store_metadata(key, value).await
    }

    async fn load_metadata(&self, key: &str) -> StorageResult<Option<Vec<u8>>> {
        self.metadata.read().await.load_metadata(key).await
    }
}

#[async_trait]
impl chainstate::ChainStateStorage for DiskStorageManager {
    async fn store_chain_state(&mut self, state: &ChainState) -> StorageResult<()> {
        self.chainstate.write().await.store_chain_state(state).await
    }

    async fn load_chain_state(&self) -> StorageResult<Option<ChainState>> {
        self.chainstate.read().await.load_chain_state().await
    }
}

#[async_trait]
impl masternode::MasternodeStateStorage for DiskStorageManager {
    async fn store_masternode_state(&mut self, state: &MasternodeState) -> StorageResult<()> {
        self.masternodestate.write().await.store_masternode_state(state).await
    }

    async fn load_masternode_state(&self) -> StorageResult<Option<MasternodeState>> {
        self.masternodestate.read().await.load_masternode_state().await
    }
}

#[cfg(test)]
mod tests {
    use crate::ChainState;

    use super::*;
    use dashcore::Header as BlockHeader;
    use tempfile::{tempdir, TempDir};

    #[tokio::test]
    async fn test_load_headers() -> Result<(), Box<dyn std::error::Error>> {
        // Create a temporary directory for the test
        let temp_dir = TempDir::new()?;
        let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf())
            .await
            .expect("Unable to create storage");

        // Create a test header
        let test_header = BlockHeader::dummy(1);

        // Store just one header
        storage.store_headers(&[test_header]).await?;

        let loaded_headers = storage.load_headers(0..1).await?;

        // Should only get back the one header we stored
        assert_eq!(loaded_headers.len(), 1);
        assert_eq!(loaded_headers[0], test_header);

        Ok(())
    }

    #[tokio::test]
    async fn test_checkpoint_storage_indexing() -> StorageResult<()> {
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await?;

        // Create test headers starting from checkpoint height
        let checkpoint_height = 1_100_000;
        let headers = BlockHeader::dummy_batch(checkpoint_height..checkpoint_height + 100);

        let mut base_state = ChainState::new();
        base_state.sync_base_height = checkpoint_height;
        storage.store_chain_state(&base_state).await?;

        storage.store_headers_at_height(&headers, checkpoint_height).await?;
        assert_eq!(storage.get_stored_headers_len().await, headers.len() as u32);

        // Verify headers are stored at correct blockchain heights
        let header_at_base = storage.get_header(checkpoint_height).await?;
        assert_eq!(
            header_at_base.expect("Header at base blockchain height should exist"),
            headers[0]
        );

        let header_at_ending = storage.get_header(checkpoint_height + 99).await?;
        assert_eq!(
            header_at_ending.expect("Header at ending blockchain height should exist"),
            headers[99]
        );

        // Test the reverse index (hash -> blockchain height)
        let hash_0 = headers[0].block_hash();
        let height_0 = storage.get_header_height_by_hash(&hash_0).await?;
        assert_eq!(
            height_0,
            Some(checkpoint_height),
            "Hash should map to blockchain height 1,100,000"
        );

        let hash_99 = headers[99].block_hash();
        let height_99 = storage.get_header_height_by_hash(&hash_99).await?;
        assert_eq!(
            height_99,
            Some(checkpoint_height + 99),
            "Hash should map to blockchain height 1,100,099"
        );

        // Store chain state to persist sync_base_height
        let mut chain_state = ChainState::new();
        chain_state.sync_base_height = checkpoint_height;
        storage.store_chain_state(&chain_state).await?;

        // Force save to disk
        storage.persist().await;

        drop(storage);

        // Create a new storage instance to test index rebuilding
        let storage2 = DiskStorageManager::new(temp_dir.path().to_path_buf()).await?;

        // Verify the index was rebuilt correctly
        let height_after_rebuild = storage2.get_header_height_by_hash(&hash_0).await?;
        assert_eq!(
            height_after_rebuild,
            Some(checkpoint_height),
            "After index rebuild, hash should still map to blockchain height 1,100,000"
        );

        // Verify header can still be retrieved by blockchain height after reload
        let header_after_reload = storage2.get_header(checkpoint_height).await?;
        assert!(
            header_after_reload.is_some(),
            "Header at base blockchain height should exist after reload"
        );
        assert_eq!(header_after_reload.unwrap(), headers[0]);

        Ok(())
    }

    #[tokio::test]
    async fn test_shutdown_flushes_index() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let base_path = temp_dir.path().to_path_buf();
        let headers = BlockHeader::dummy_batch(0..11_000);
        let last_hash = headers.last().unwrap().block_hash();

        {
            let mut storage = DiskStorageManager::new(base_path.clone()).await?;

            storage.store_headers(&headers[..10_000]).await?;
            storage.persist().await;

            storage.store_headers(&headers[10_000..]).await?;
            storage.shutdown().await;
        }

        let storage = DiskStorageManager::new(base_path).await?;
        let height = storage.get_header_height_by_hash(&last_hash).await?;
        assert_eq!(height, Some(10_999));

        Ok(())
    }
}
