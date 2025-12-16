//! State persistence and StorageManager trait implementation.

use async_trait::async_trait;
use std::collections::HashMap;

use dashcore::{block::Header as BlockHeader, BlockHash, Txid};

use crate::error::StorageResult;
use crate::storage::headers::save_index_to_disk;
use crate::storage::{MasternodeState, StorageManager};
use crate::types::{ChainState, MempoolState, UnconfirmedTransaction};

use super::io::atomic_write;
use super::manager::DiskStorageManager;

impl DiskStorageManager {
    /// Store chain state to disk.
    pub async fn store_chain_state(&mut self, state: &ChainState) -> StorageResult<()> {
        // Store other state as JSON
        let state_data = serde_json::json!({
            "last_chainlock_height": state.last_chainlock_height,
            "last_chainlock_hash": state.last_chainlock_hash,
            "current_filter_tip": state.current_filter_tip,
            "last_masternode_diff_height": state.last_masternode_diff_height,
            "sync_base_height": state.sync_base_height,
        });

        let path = self.base_path.join("state/chain.json");
        let json = state_data.to_string();
        atomic_write(&path, json.as_bytes()).await?;

        Ok(())
    }

    /// Load chain state from disk.
    pub async fn load_chain_state(&self) -> StorageResult<Option<ChainState>> {
        let path = self.base_path.join("state/chain.json");
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
            last_chainlock_hash: value
                .get("last_chainlock_hash")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok()),
            current_filter_tip: value
                .get("current_filter_tip")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok()),
            masternode_engine: None,
            last_masternode_diff_height: value
                .get("last_masternode_diff_height")
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

    /// Store masternode state.
    pub async fn store_masternode_state(&mut self, state: &MasternodeState) -> StorageResult<()> {
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

    /// Load masternode state.
    pub async fn load_masternode_state(&self) -> StorageResult<Option<MasternodeState>> {
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

    /// Store metadata.
    pub async fn store_metadata(&mut self, key: &str, value: &[u8]) -> StorageResult<()> {
        let path = self.base_path.join(format!("state/{}.dat", key));
        atomic_write(&path, value).await?;
        Ok(())
    }

    /// Load metadata.
    pub async fn load_metadata(&self, key: &str) -> StorageResult<Option<Vec<u8>>> {
        let path = self.base_path.join(format!("state/{}.dat", key));
        if !path.exists() {
            return Ok(None);
        }

        let data = tokio::fs::read(path).await?;
        Ok(Some(data))
    }
}

/// Mempool storage methods
impl DiskStorageManager {
    /// Store a mempool transaction.
    pub async fn store_mempool_transaction(
        &mut self,
        txid: &Txid,
        tx: &UnconfirmedTransaction,
    ) -> StorageResult<()> {
        self.mempool_transactions.write().await.insert(*txid, tx.clone());
        Ok(())
    }

    /// Remove a mempool transaction.
    pub async fn remove_mempool_transaction(&mut self, txid: &Txid) -> StorageResult<()> {
        self.mempool_transactions.write().await.remove(txid);
        Ok(())
    }

    /// Get a mempool transaction.
    pub async fn get_mempool_transaction(
        &self,
        txid: &Txid,
    ) -> StorageResult<Option<UnconfirmedTransaction>> {
        Ok(self.mempool_transactions.read().await.get(txid).cloned())
    }

    /// Get all mempool transactions.
    pub async fn get_all_mempool_transactions(
        &self,
    ) -> StorageResult<HashMap<Txid, UnconfirmedTransaction>> {
        Ok(self.mempool_transactions.read().await.clone())
    }

    /// Store mempool state.
    pub async fn store_mempool_state(&mut self, state: &MempoolState) -> StorageResult<()> {
        *self.mempool_state.write().await = Some(state.clone());
        Ok(())
    }

    /// Load mempool state.
    pub async fn load_mempool_state(&self) -> StorageResult<Option<MempoolState>> {
        Ok(self.mempool_state.read().await.clone())
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
        storage.save_dirty().await;

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
            storage.save_dirty().await;

            storage.store_headers(&headers[10_000..]).await?;
            storage.shutdown().await;
        }

        let storage = DiskStorageManager::new(base_path).await?;
        let height = storage.get_header_height_by_hash(&last_hash).await?;
        assert_eq!(height, Some(10_999));

        Ok(())
    }
}
