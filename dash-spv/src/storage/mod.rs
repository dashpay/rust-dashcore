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
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::error::StorageResult;
use crate::storage::blocks::PersistentBlockHeaderStorage;
use crate::storage::chainstate::PersistentChainStateStorage;
use crate::storage::filters::{PersistentFilterHeaderStorage, PersistentFilterStorage};
use crate::storage::lockfile::LockFile;
use crate::storage::metadata::PersistentMetadataStorage;
use crate::storage::transactions::PersistentTransactionStorage;

pub use types::*;

#[async_trait]
pub trait PersistentStorage: Sized {
    async fn load(storage_path: impl Into<PathBuf> + Send) -> StorageResult<Self>;
    async fn persist(&mut self, storage_path: impl Into<PathBuf> + Send) -> StorageResult<()>;

    async fn persist_dirty(
        &mut self,
        storage_path: impl Into<PathBuf> + Send,
    ) -> StorageResult<()> {
        self.persist(storage_path).await
    }
}

#[async_trait]
pub trait StorageManager:
    blocks::BlockHeaderStorage
    + filters::FilterHeaderStorage
    + filters::FilterStorage
    + transactions::TransactionStorage
    + metadata::MetadataStorage
    + chainstate::ChainStateStorage
    + masternode::MasternodeStateStorage
    + Send
    + Sync
{
}

/// Disk-based storage manager with segmented files and async background saving.
pub struct DiskStorageManager {
    storage_path: PathBuf,

    block_headers: Arc<RwLock<PersistentBlockHeaderStorage>>,
    filter_headers: Arc<RwLock<PersistentFilterHeaderStorage>>,
    filters: Arc<RwLock<PersistentFilterStorage>>,
    transactions: Arc<RwLock<PersistentTransactionStorage>>,
    metadata: Arc<RwLock<PersistentMetadataStorage>>,
    chainstate: Arc<RwLock<PersistentChainStateStorage>>,

    // Background worker
    worker_handle: Option<tokio::task::JoinHandle<()>>,

    // Lock file to prevent concurrent access from multiple processes.
    _lock_file: LockFile,
}

impl DiskStorageManager {
    pub async fn new(storage_path: impl Into<PathBuf> + Send) -> StorageResult<Self> {
        use std::fs;

        let storage_path = storage_path.into();

        // Create directories if they don't exist
        fs::create_dir_all(&storage_path)?;

        // Acquire exclusive lock on the data directory
        let lock_file = LockFile::new(storage_path.with_added_extension(".lock"))?;

        let mut storage = Self {
            storage_path: storage_path.clone(),

            block_headers: Arc::new(RwLock::new(
                PersistentBlockHeaderStorage::load(&storage_path).await?,
            )),
            filter_headers: Arc::new(RwLock::new(
                PersistentFilterHeaderStorage::load(&storage_path).await?,
            )),
            filters: Arc::new(RwLock::new(PersistentFilterStorage::load(&storage_path).await?)),
            transactions: Arc::new(RwLock::new(
                PersistentTransactionStorage::load(&storage_path).await?,
            )),
            metadata: Arc::new(RwLock::new(PersistentMetadataStorage::load(&storage_path).await?)),
            chainstate: Arc::new(RwLock::new(
                PersistentChainStateStorage::load(&storage_path).await?,
            )),

            worker_handle: None,

            _lock_file: lock_file,
        };

        // Start background worker that
        // persists data when appropriate
        storage.start_worker().await;

        Ok(storage)
    }

    #[cfg(test)]
    pub async fn with_temp_dir() -> StorageResult<Self> {
        use tempfile::TempDir;

        let temp_dir = TempDir::new()?;
        Self::new(temp_dir.path()).await
    }

    /// Start the background worker
    pub(super) async fn start_worker(&mut self) {
        let block_headers = Arc::clone(&self.block_headers);
        let filter_headers = Arc::clone(&self.filter_headers);
        let filters = Arc::clone(&self.filters);
        let transactions = Arc::clone(&self.transactions);
        let metadata = Arc::clone(&self.metadata);
        let chainstate = Arc::clone(&self.chainstate);

        let storage_path = self.storage_path.clone();

        let worker_handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(5));

            loop {
                ticker.tick().await;

                let _ = block_headers.write().await.persist_dirty(&storage_path).await;
                let _ = filter_headers.write().await.persist_dirty(&storage_path).await;
                let _ = filters.write().await.persist_dirty(&storage_path).await;
                let _ = transactions.write().await.persist_dirty(&storage_path).await;
                let _ = metadata.write().await.persist_dirty(&storage_path).await;
                let _ = chainstate.write().await.persist_dirty(&storage_path).await;
            }
        });

        self.worker_handle = Some(worker_handle);
    }

    /// Stop the background worker without forcing a save.
    pub(super) fn stop_worker(&mut self) {
        if let Some(handle) = self.worker_handle.take() {
            handle.abort();
        }
    }

    /// Clear all filter headers and compact filters.
    pub(super) async fn clear_filters(&mut self) -> StorageResult<()> {
        // Stop worker to prevent concurrent writes to filter directories
        self.stop_worker().await;

        // Clear in-memory and on-disk filter headers segments
        self.filter_headers.write().await.clear_all().await?;
        self.filters.write().await.clear_all().await?;

        // Restart background worker for future operations
        self.start_worker().await;

        Ok(())
    }
    
    /// Clear all storage.
    pub async fn clear(&mut self) -> StorageResult<()> {
        // First, stop the background worker to avoid races with file deletion
        self.stop_worker();

        // Remove all files and directories under base_path
        if self.storage_path.exists() {
            // Best-effort removal; if concurrent files appear, retry once
            match tokio::fs::remove_dir_all(&self.storage_path).await {
                Ok(_) => {}
                Err(e) => {
                    // Retry once after a short delay to handle transient races
                    if e.kind() == std::io::ErrorKind::Other
                        || e.kind() == std::io::ErrorKind::DirectoryNotEmpty
                    {
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        tokio::fs::remove_dir_all(&self.storage_path).await?;
                    } else {
                        return Err(crate::error::StorageError::Io(e));
                    }
                }
            }
            tokio::fs::create_dir_all(&self.storage_path).await?;
        }

        // Instantiate storages again once persisted data has been cleared
        let storage_path = &self.storage_path;

        self.block_headers =
            Arc::new(RwLock::new(PersistentBlockHeaderStorage::load(storage_path).await?));
        self.filter_headers =
            Arc::new(RwLock::new(PersistentFilterHeaderStorage::load(storage_path).await?));
        self.filters = Arc::new(RwLock::new(PersistentFilterStorage::load(storage_path).await?));
        self.transactions =
            Arc::new(RwLock::new(PersistentTransactionStorage::load(storage_path).await?));
        self.metadata = Arc::new(RwLock::new(PersistentMetadataStorage::load(storage_path).await?));
        self.chainstate =
            Arc::new(RwLock::new(PersistentChainStateStorage::load(storage_path).await?));

        // Restart the background worker for future operations
        self.start_worker().await;

        Ok(())
    }

    /// Shutdown the storage manager.
    pub async fn shutdown(&mut self) {
        self.stop_worker();

        // Persist all dirty data
        self.persist().await;
    }

    async fn persist(&self) {
        let storage_path = &self.storage_path;

        let _ = self.block_headers.write().await.persist(storage_path).await;
        let _ = self.filter_headers.write().await.persist(storage_path).await;
        let _ = self.filters.write().await.persist(storage_path).await;
        let _ = self.transactions.write().await.persist(storage_path).await;
        let _ = self.metadata.write().await.persist(storage_path).await;
        let _ = self.chainstate.write().await.persist(storage_path).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::{block::Version, pow::CompactTarget};
    use dashcore_hashes::Hash;
    use tempfile::TempDir;

    fn build_headers(count: usize) -> Vec<BlockHeader> {
        let mut headers = Vec::with_capacity(count);
        let mut prev_hash = BlockHash::from_byte_array([0u8; 32]);

        for i in 0..count {
            let header = BlockHeader {
                version: Version::from_consensus(1),
                prev_blockhash: prev_hash,
                merkle_root: dashcore::hashes::sha256d::Hash::from_byte_array(
                    [(i % 255) as u8; 32],
                )
                .into(),
                time: 1 + i as u32,
                bits: CompactTarget::from_consensus(0x1d00ffff),
                nonce: i as u32,
            };
            prev_hash = header.block_hash();
            headers.push(header);
        }

        headers
    }

    #[tokio::test]
    async fn test_load_headers() -> Result<(), Box<dyn std::error::Error>> {
        // Create a temporary directory for the test
        let temp_dir = TempDir::new()?;
        let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf())
            .await
            .expect("Unable to create storage");

        // Create a test header
        let test_header = BlockHeader {
            version: Version::from_consensus(1),
            prev_blockhash: BlockHash::from_byte_array([1; 32]),
            merkle_root: dashcore::hashes::sha256d::Hash::from_byte_array([2; 32]).into(),
            time: 12345,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 67890,
        };

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
        use dashcore::TxMerkleNode;
        use tempfile::tempdir;

        let temp_dir = tempdir().expect("Failed to create temp dir");
        let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await?;

        // Create test headers starting from checkpoint height
        let checkpoint_height = 1_100_000;
        let headers: Vec<BlockHeader> = (0..100)
            .map(|i| BlockHeader {
                version: Version::from_consensus(1),
                prev_blockhash: BlockHash::from_byte_array([i as u8; 32]),
                merkle_root: TxMerkleNode::from_byte_array([(i + 1) as u8; 32]),
                time: 1234567890 + i,
                bits: CompactTarget::from_consensus(0x1a2b3c4d),
                nonce: 67890 + i,
            })
            .collect();

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
        let headers = build_headers(11_000);
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
