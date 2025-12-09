//! State persistence and StorageManager trait implementation.

use async_trait::async_trait;
use std::collections::HashMap;

use dashcore::{block::Header as BlockHeader, BlockHash, Txid};
#[cfg(test)]
use dashcore_hashes::Hash;

use crate::error::StorageResult;
use crate::storage::{MasternodeState, StorageManager, StorageStats};
use crate::types::{ChainState, MempoolState, UnconfirmedTransaction};

use super::io::atomic_write;
use super::manager::DiskStorageManager;

impl DiskStorageManager {
    /// Store chain state to disk.
    pub async fn store_chain_state(&mut self, state: &ChainState) -> StorageResult<()> {
        // Update our sync_base_height
        self.filter_headers.write().await.set_sync_base_height(state.sync_base_height);
        self.block_headers.write().await.set_sync_base_height(state.sync_base_height);

        // First store all headers
        // For checkpoint sync, we need to store headers starting from the checkpoint height
        if state.synced_from_checkpoint() && !state.headers.is_empty() {
            // Store headers starting from the checkpoint height
            self.store_headers_from_height(&state.headers, state.sync_base_height).await?;
        } else {
            self.store_headers_internal(&state.headers).await?;
        }

        // Store filter headers
        self.store_filter_headers(&state.filter_headers).await?;

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

        let mut state = ChainState {
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
            ..Default::default()
        };

        let range_start = state.sync_base_height;
        if let Some(tip_height) = self.get_tip_height().await? {
            state.headers = self.load_headers(range_start..tip_height + 1).await?;
        }
        if let Some(filter_tip_height) = self.get_filter_tip_height().await? {
            state.filter_headers =
                self.load_filter_headers(range_start..filter_tip_height + 1).await?;
        }

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

    /// Store sync state.
    pub async fn store_sync_state(
        &mut self,
        state: &crate::storage::PersistentSyncState,
    ) -> StorageResult<()> {
        let path = self.base_path.join("sync_state.json");

        // Serialize to JSON for human readability and easy debugging
        let json = serde_json::to_string_pretty(state).map_err(|e| {
            crate::error::StorageError::WriteFailed(format!(
                "Failed to serialize sync state: {}",
                e
            ))
        })?;

        atomic_write(&path, json.as_bytes()).await?;

        tracing::debug!("Saved sync state at height {}", state.chain_tip.height);
        Ok(())
    }

    /// Load sync state.
    pub async fn load_sync_state(
        &self,
    ) -> StorageResult<Option<crate::storage::PersistentSyncState>> {
        let path = self.base_path.join("sync_state.json");

        if !path.exists() {
            tracing::debug!("No sync state file found");
            return Ok(None);
        }

        let json = tokio::fs::read_to_string(&path).await?;
        let state: crate::storage::PersistentSyncState =
            serde_json::from_str(&json).map_err(|e| {
                crate::error::StorageError::ReadFailed(format!(
                    "Failed to deserialize sync state: {}",
                    e
                ))
            })?;

        tracing::debug!("Loaded sync state from height {}", state.chain_tip.height);
        Ok(Some(state))
    }

    /// Clear sync state.
    pub async fn clear_sync_state(&mut self) -> StorageResult<()> {
        let path = self.base_path.join("sync_state.json");
        if path.exists() {
            tokio::fs::remove_file(&path).await?;
            tracing::debug!("Cleared sync state");
        }
        Ok(())
    }

    /// Store a sync checkpoint.
    pub async fn store_sync_checkpoint(
        &mut self,
        height: u32,
        checkpoint: &crate::storage::sync_state::SyncCheckpoint,
    ) -> StorageResult<()> {
        let path =
            self.base_path.join("checkpoints").join(format!("checkpoint_{:08}.json", height));
        let json = serde_json::to_string(checkpoint).map_err(|e| {
            crate::error::StorageError::WriteFailed(format!(
                "Failed to serialize checkpoint: {}",
                e
            ))
        })?;

        atomic_write(&path, json.as_bytes()).await?;
        tracing::debug!("Stored checkpoint at height {}", height);
        Ok(())
    }

    /// Get sync checkpoints in a height range.
    pub async fn get_sync_checkpoints(
        &self,
        start_height: u32,
        end_height: u32,
    ) -> StorageResult<Vec<crate::storage::sync_state::SyncCheckpoint>> {
        let checkpoints_dir = self.base_path.join("checkpoints");

        if !checkpoints_dir.exists() {
            return Ok(Vec::new());
        }

        let mut checkpoints: Vec<crate::storage::sync_state::SyncCheckpoint> = Vec::new();
        let mut entries = tokio::fs::read_dir(&checkpoints_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();

            // Parse height from filename
            if let Some(height_str) =
                file_name_str.strip_prefix("checkpoint_").and_then(|s| s.strip_suffix(".json"))
            {
                if let Ok(height) = height_str.parse::<u32>() {
                    if height >= start_height && height <= end_height {
                        let path = entry.path();
                        let json = tokio::fs::read_to_string(&path).await?;
                        if let Ok(checkpoint) = serde_json::from_str::<
                            crate::storage::sync_state::SyncCheckpoint,
                        >(&json)
                        {
                            checkpoints.push(checkpoint);
                        }
                    }
                }
            }
        }

        // Sort by height
        checkpoints.sort_by_key(|c| c.height);
        Ok(checkpoints)
    }

    /// Store a ChainLock.
    pub async fn store_chain_lock(
        &mut self,
        height: u32,
        chain_lock: &dashcore::ChainLock,
    ) -> StorageResult<()> {
        let path = self.base_path.join("chainlocks").join(format!("chainlock_{:08}.bin", height));
        let data = bincode::serialize(chain_lock).map_err(|e| {
            crate::error::StorageError::WriteFailed(format!(
                "Failed to serialize chain lock: {}",
                e
            ))
        })?;

        atomic_write(&path, &data).await?;
        tracing::debug!("Stored chain lock at height {}", height);
        Ok(())
    }

    /// Load a ChainLock.
    pub async fn load_chain_lock(&self, height: u32) -> StorageResult<Option<dashcore::ChainLock>> {
        let path = self.base_path.join("chainlocks").join(format!("chainlock_{:08}.bin", height));

        if !path.exists() {
            return Ok(None);
        }

        let data = tokio::fs::read(&path).await?;
        let chain_lock = bincode::deserialize(&data).map_err(|e| {
            crate::error::StorageError::ReadFailed(format!(
                "Failed to deserialize chain lock: {}",
                e
            ))
        })?;

        Ok(Some(chain_lock))
    }

    /// Get ChainLocks in a height range.
    pub async fn get_chain_locks(
        &self,
        start_height: u32,
        end_height: u32,
    ) -> StorageResult<Vec<(u32, dashcore::ChainLock)>> {
        let chainlocks_dir = self.base_path.join("chainlocks");

        if !chainlocks_dir.exists() {
            return Ok(Vec::new());
        }

        let mut chain_locks = Vec::new();
        let mut entries = tokio::fs::read_dir(&chainlocks_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();

            // Parse height from filename
            if let Some(height_str) =
                file_name_str.strip_prefix("chainlock_").and_then(|s| s.strip_suffix(".bin"))
            {
                if let Ok(height) = height_str.parse::<u32>() {
                    if height >= start_height && height <= end_height {
                        let path = entry.path();
                        let data = tokio::fs::read(&path).await?;
                        if let Ok(chain_lock) = bincode::deserialize(&data) {
                            chain_locks.push((height, chain_lock));
                        }
                    }
                }
            }
        }

        // Sort by height
        chain_locks.sort_by_key(|(h, _)| *h);
        Ok(chain_locks)
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

    /// Clear all storage.
    pub async fn clear(&mut self) -> StorageResult<()> {
        // First, stop the background worker to avoid races with file deletion
        self.stop_worker().await;

        // Clear in-memory state
        self.block_headers.write().await.clear();
        self.filter_headers.write().await.clear();
        self.header_hash_index.write().await.clear();
        self.mempool_transactions.write().await.clear();
        *self.mempool_state.write().await = None;

        // Remove all files and directories under base_path
        if self.base_path.exists() {
            // Best-effort removal; if concurrent files appear, retry once
            match tokio::fs::remove_dir_all(&self.base_path).await {
                Ok(_) => {}
                Err(e) => {
                    // Retry once after a short delay to handle transient races
                    if e.kind() == std::io::ErrorKind::Other
                        || e.kind() == std::io::ErrorKind::DirectoryNotEmpty
                    {
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        tokio::fs::remove_dir_all(&self.base_path).await?;
                    } else {
                        return Err(crate::error::StorageError::Io(e));
                    }
                }
            }
            tokio::fs::create_dir_all(&self.base_path).await?;
        }

        // Recreate expected subdirectories
        tokio::fs::create_dir_all(self.base_path.join("headers")).await?;
        tokio::fs::create_dir_all(self.base_path.join("filters")).await?;
        tokio::fs::create_dir_all(self.base_path.join("state")).await?;

        // Restart the background worker for future operations
        self.start_worker().await;

        Ok(())
    }

    /// Get storage statistics.
    pub async fn stats(&self) -> StorageResult<StorageStats> {
        let mut component_sizes = HashMap::new();
        let mut total_size = 0u64;

        // Calculate directory sizes
        if let Ok(mut entries) = tokio::fs::read_dir(&self.base_path).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if let Ok(metadata) = entry.metadata().await {
                    if metadata.is_file() {
                        total_size += metadata.len();
                    }
                }
            }
        }

        let header_count = self.block_headers.read().await.tip_height().map_or(0, |h| h as u64 + 1);
        let filter_header_count =
            self.filter_headers.read().await.tip_height().map_or(0, |h| h as u64 + 1);

        component_sizes.insert("headers".to_string(), header_count * 80);
        component_sizes.insert("filter_headers".to_string(), filter_header_count * 32);
        component_sizes
            .insert("index".to_string(), self.header_hash_index.read().await.len() as u64 * 40);

        Ok(StorageStats {
            header_count,
            filter_header_count,
            filter_count: 0, // TODO: Count filter files
            total_size,
            component_sizes,
        })
    }

    /// Shutdown the storage manager.
    pub async fn shutdown(&mut self) -> StorageResult<()> {
        // Save all dirty segments
        super::segments::save_dirty_segments_cache(self).await?;

        // Shutdown background worker
        if let Some(tx) = self.worker_tx.take() {
            // Save the header index before shutdown
            let index = self.header_hash_index.read().await.clone();
            let _ = tx
                .send(super::manager::WorkerCommand::SaveIndex {
                    index,
                })
                .await;
            let _ = tx.send(super::manager::WorkerCommand::Shutdown).await;
        }

        if let Some(handle) = self.worker_handle.take() {
            let _ = handle.await;
        }

        Ok(())
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

    /// Clear mempool.
    pub async fn clear_mempool(&mut self) -> StorageResult<()> {
        self.mempool_transactions.write().await.clear();
        *self.mempool_state.write().await = None;
        Ok(())
    }
}

#[async_trait]
impl StorageManager for DiskStorageManager {
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    async fn store_headers(&mut self, headers: &[BlockHeader]) -> StorageResult<()> {
        self.store_headers_internal(headers).await
    }

    async fn load_headers(&self, range: std::ops::Range<u32>) -> StorageResult<Vec<BlockHeader>> {
        self.block_headers.write().await.get_headers(range).await
    }

    async fn get_header(&self, height: u32) -> StorageResult<Option<BlockHeader>> {
        Ok(self.block_headers.write().await.get_headers(height..height + 1).await?.get(0).copied())
    }

    async fn get_tip_height(&self) -> StorageResult<Option<u32>> {
        Ok(self.block_headers.read().await.tip_height())
    }

    async fn store_filter_headers(
        &mut self,
        headers: &[dashcore::hash_types::FilterHeader],
    ) -> StorageResult<()> {
        self.filter_headers.write().await.store_headers(headers, self).await
    }

    async fn load_filter_headers(
        &self,
        range: std::ops::Range<u32>,
    ) -> StorageResult<Vec<dashcore::hash_types::FilterHeader>> {
        self.filter_headers.write().await.get_headers(range).await
    }

    async fn get_filter_header(
        &self,
        height: u32,
    ) -> StorageResult<Option<dashcore::hash_types::FilterHeader>> {
        Ok(self.filter_headers.write().await.get_headers(height..height + 1).await?.get(0).copied())
    }

    async fn get_filter_tip_height(&self) -> StorageResult<Option<u32>> {
        Ok(self.filter_headers.read().await.tip_height())
    }

    async fn store_masternode_state(&mut self, state: &MasternodeState) -> StorageResult<()> {
        Self::store_masternode_state(self, state).await
    }

    async fn load_masternode_state(&self) -> StorageResult<Option<MasternodeState>> {
        Self::load_masternode_state(self).await
    }

    async fn store_chain_state(&mut self, state: &ChainState) -> StorageResult<()> {
        Self::store_chain_state(self, state).await
    }

    async fn load_chain_state(&self) -> StorageResult<Option<ChainState>> {
        Self::load_chain_state(self).await
    }

    async fn store_filter(&mut self, height: u32, filter: &[u8]) -> StorageResult<()> {
        Self::store_filter(self, height, filter).await
    }

    async fn load_filter(&self, height: u32) -> StorageResult<Option<Vec<u8>>> {
        Self::load_filter(self, height).await
    }

    async fn store_metadata(&mut self, key: &str, value: &[u8]) -> StorageResult<()> {
        Self::store_metadata(self, key, value).await
    }

    async fn load_metadata(&self, key: &str) -> StorageResult<Option<Vec<u8>>> {
        Self::load_metadata(self, key).await
    }

    async fn clear(&mut self) -> StorageResult<()> {
        Self::clear(self).await
    }

    async fn clear_filters(&mut self) -> StorageResult<()> {
        Self::clear_filters(self).await
    }

    async fn stats(&self) -> StorageResult<StorageStats> {
        Self::stats(self).await
    }

    async fn get_header_height_by_hash(&self, hash: &BlockHash) -> StorageResult<Option<u32>> {
        Self::get_header_height_by_hash(self, hash).await
    }

    async fn store_sync_state(
        &mut self,
        state: &crate::storage::PersistentSyncState,
    ) -> StorageResult<()> {
        Self::store_sync_state(self, state).await
    }

    async fn load_sync_state(&self) -> StorageResult<Option<crate::storage::PersistentSyncState>> {
        Self::load_sync_state(self).await
    }

    async fn clear_sync_state(&mut self) -> StorageResult<()> {
        Self::clear_sync_state(self).await
    }

    async fn store_sync_checkpoint(
        &mut self,
        height: u32,
        checkpoint: &crate::storage::sync_state::SyncCheckpoint,
    ) -> StorageResult<()> {
        Self::store_sync_checkpoint(self, height, checkpoint).await
    }

    async fn get_sync_checkpoints(
        &self,
        start_height: u32,
        end_height: u32,
    ) -> StorageResult<Vec<crate::storage::sync_state::SyncCheckpoint>> {
        Self::get_sync_checkpoints(self, start_height, end_height).await
    }

    async fn store_chain_lock(
        &mut self,
        height: u32,
        chain_lock: &dashcore::ChainLock,
    ) -> StorageResult<()> {
        Self::store_chain_lock(self, height, chain_lock).await
    }

    async fn load_chain_lock(&self, height: u32) -> StorageResult<Option<dashcore::ChainLock>> {
        Self::load_chain_lock(self, height).await
    }

    async fn get_chain_locks(
        &self,
        start_height: u32,
        end_height: u32,
    ) -> StorageResult<Vec<(u32, dashcore::ChainLock)>> {
        Self::get_chain_locks(self, start_height, end_height).await
    }

    async fn store_mempool_transaction(
        &mut self,
        txid: &Txid,
        tx: &UnconfirmedTransaction,
    ) -> StorageResult<()> {
        Self::store_mempool_transaction(self, txid, tx).await
    }

    async fn remove_mempool_transaction(&mut self, txid: &Txid) -> StorageResult<()> {
        Self::remove_mempool_transaction(self, txid).await
    }

    async fn get_mempool_transaction(
        &self,
        txid: &Txid,
    ) -> StorageResult<Option<UnconfirmedTransaction>> {
        Self::get_mempool_transaction(self, txid).await
    }

    async fn get_all_mempool_transactions(
        &self,
    ) -> StorageResult<HashMap<Txid, UnconfirmedTransaction>> {
        Self::get_all_mempool_transactions(self).await
    }

    async fn store_mempool_state(&mut self, state: &MempoolState) -> StorageResult<()> {
        Self::store_mempool_state(self, state).await
    }

    async fn load_mempool_state(&self) -> StorageResult<Option<MempoolState>> {
        Self::load_mempool_state(self).await
    }

    async fn clear_mempool(&mut self) -> StorageResult<()> {
        Self::clear_mempool(self).await
    }

    async fn shutdown(&mut self) -> StorageResult<()> {
        Self::shutdown(self).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::{block::Version, pow::CompactTarget};
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
    async fn test_sentinel_headers_not_returned() -> Result<(), Box<dyn std::error::Error>> {
        // Create a temporary directory for the test
        let temp_dir = TempDir::new()?;
        let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await?;

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

        // Load headers for a range that would include padding
        let loaded_headers = storage.load_headers(0..10).await?;

        // Should only get back the one header we stored, not the sentinel padding
        assert_eq!(loaded_headers.len(), 1);
        assert_eq!(loaded_headers[0], test_header);

        // Try to get a header at index 5 (which would be a sentinel)
        let header_at_5 = storage.get_header(5).await?;
        assert!(header_at_5.is_none(), "Should not return sentinel headers");

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

        // Set sync base height so storage interprets heights as blockchain heights
        let mut base_state = ChainState::new();
        base_state.sync_base_height = checkpoint_height;
        storage.store_chain_state(&base_state).await?;

        // Verify headers are stored at correct blockchain heights
        let header_at_base = storage.get_header(checkpoint_height).await?;
        assert!(header_at_base.is_some(), "Header at base blockchain height should exist");
        assert_eq!(header_at_base.unwrap(), headers[0]);

        let header_at_ending = storage.get_header(checkpoint_height + 99).await?;
        assert!(header_at_ending.is_some(), "Header at ending blockchain height should exist");
        assert_eq!(header_at_ending.unwrap(), headers[99]);

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
        super::super::segments::save_dirty_segments_cache(&storage).await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

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
            super::super::segments::save_dirty_segments_cache(&storage).await?;

            storage.store_headers(&headers[10_000..]).await?;
            storage.shutdown().await?;
        }

        let storage = DiskStorageManager::new(base_path).await?;
        let height = storage.get_header_height_by_hash(&last_hash).await?;
        assert_eq!(height, Some(10_999));

        Ok(())
    }
}
