//! In-memory storage implementation.

use async_trait::async_trait;
use std::collections::HashMap;
use std::ops::Range;

use dashcore::{block::Header as BlockHeader, hash_types::FilterHeader, BlockHash, Txid};

use crate::error::{StorageError, StorageResult};
use crate::storage::{MasternodeState, StorageManager, StorageStats};
use crate::types::{ChainState, MempoolState, UnconfirmedTransaction};

/// In-memory storage manager.
pub struct MemoryStorageManager {
    headers: Vec<BlockHeader>,
    filter_headers: Vec<FilterHeader>,
    filters: HashMap<u32, Vec<u8>>,
    masternode_state: Option<MasternodeState>,
    chain_state: Option<ChainState>,
    metadata: HashMap<String, Vec<u8>>,
    // Reverse indexes for O(1) lookups
    header_hash_index: HashMap<BlockHash, u32>,
    // Mempool storage
    mempool_transactions: HashMap<Txid, UnconfirmedTransaction>,
    mempool_state: Option<MempoolState>,
}

impl MemoryStorageManager {
    /// Create a new memory storage manager.
    pub async fn new() -> StorageResult<Self> {
        Ok(Self {
            headers: Vec::new(),
            filter_headers: Vec::new(),
            filters: HashMap::new(),
            masternode_state: None,
            chain_state: None,
            metadata: HashMap::new(),
            header_hash_index: HashMap::new(),
            mempool_transactions: HashMap::new(),
            mempool_state: None,
        })
    }
}

#[async_trait]
impl StorageManager for MemoryStorageManager {
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    async fn store_headers(&mut self, headers: &[BlockHeader]) -> StorageResult<()> {
        let initial_count = self.headers.len();
        tracing::debug!(
            "MemoryStorage: storing {} headers, current count: {}",
            headers.len(),
            initial_count
        );

        for header in headers {
            let height = self.headers.len() as u32;
            let block_hash = header.block_hash();

            // Check if we already have this header
            if self.header_hash_index.contains_key(&block_hash) {
                tracing::warn!(
                    "MemoryStorage: header {} already exists at height {:?}, skipping",
                    block_hash,
                    self.header_hash_index.get(&block_hash)
                );
                continue;
            }

            // Store the header
            self.headers.push(*header);

            // Update the reverse index
            self.header_hash_index.insert(block_hash, height);

            tracing::debug!("MemoryStorage: stored header {} at height {}", block_hash, height);
        }

        let final_count = self.headers.len();
        tracing::info!(
            "MemoryStorage: stored headers complete. Count: {} -> {}",
            initial_count,
            final_count
        );
        Ok(())
    }

    async fn load_headers(&self, range: Range<u32>) -> StorageResult<Vec<BlockHeader>> {
        let start = range.start as usize;
        let end = range.end.min(self.headers.len() as u32) as usize;

        if start > self.headers.len() {
            return Ok(Vec::new());
        }

        Ok(self.headers[start..end].to_vec())
    }

    async fn get_header(&self, height: u32) -> StorageResult<Option<BlockHeader>> {
        Ok(self.headers.get(height as usize).copied())
    }

    async fn get_tip_height(&self) -> StorageResult<Option<u32>> {
        if self.headers.is_empty() {
            Ok(None)
        } else {
            Ok(Some(self.headers.len() as u32 - 1))
        }
    }

    async fn store_filter_headers(&mut self, headers: &[FilterHeader]) -> StorageResult<()> {
        for header in headers {
            self.filter_headers.push(*header);
        }
        Ok(())
    }

    async fn load_filter_headers(&self, range: Range<u32>) -> StorageResult<Vec<FilterHeader>> {
        let start = range.start as usize;
        let end = range.end.min(self.filter_headers.len() as u32) as usize;

        if start > self.filter_headers.len() {
            return Ok(Vec::new());
        }

        Ok(self.filter_headers[start..end].to_vec())
    }

    async fn get_filter_header(&self, height: u32) -> StorageResult<Option<FilterHeader>> {
        // Filter headers are stored starting from height 0 in the vector
        Ok(self.filter_headers.get(height as usize).copied())
    }

    async fn get_filter_tip_height(&self) -> StorageResult<Option<u32>> {
        if self.filter_headers.is_empty() {
            Ok(None)
        } else {
            // Filter headers are stored starting from height 0, so length-1 gives us the highest height
            Ok(Some(self.filter_headers.len() as u32 - 1))
        }
    }

    async fn store_masternode_state(&mut self, state: &MasternodeState) -> StorageResult<()> {
        self.masternode_state = Some(state.clone());
        Ok(())
    }

    async fn load_masternode_state(&self) -> StorageResult<Option<MasternodeState>> {
        Ok(self.masternode_state.clone())
    }

    async fn store_chain_state(&mut self, state: &ChainState) -> StorageResult<()> {
        self.chain_state = Some(state.clone());
        Ok(())
    }

    async fn load_chain_state(&self) -> StorageResult<Option<ChainState>> {
        Ok(self.chain_state.clone())
    }

    async fn store_filter(&mut self, height: u32, filter: &[u8]) -> StorageResult<()> {
        self.filters.insert(height, filter.to_vec());
        Ok(())
    }

    async fn load_filter(&self, height: u32) -> StorageResult<Option<Vec<u8>>> {
        Ok(self.filters.get(&height).cloned())
    }

    async fn store_metadata(&mut self, key: &str, value: &[u8]) -> StorageResult<()> {
        self.metadata.insert(key.to_string(), value.to_vec());
        Ok(())
    }

    async fn load_metadata(&self, key: &str) -> StorageResult<Option<Vec<u8>>> {
        Ok(self.metadata.get(key).cloned())
    }

    async fn clear(&mut self) -> StorageResult<()> {
        self.headers.clear();
        self.filter_headers.clear();
        self.filters.clear();
        self.masternode_state = None;
        self.chain_state = None;
        self.metadata.clear();
        self.header_hash_index.clear();
        self.mempool_transactions.clear();
        self.mempool_state = None;
        Ok(())
    }

    async fn stats(&self) -> StorageResult<StorageStats> {
        let mut component_sizes = HashMap::new();

        // Calculate sizes for all storage components
        let header_size = self.headers.len() * std::mem::size_of::<BlockHeader>();
        let filter_header_size = self.filter_headers.len() * std::mem::size_of::<FilterHeader>();
        let filter_size: usize = self.filters.values().map(|f| f.len()).sum();
        let metadata_size: usize = self.metadata.values().map(|v| v.len()).sum();

        // Calculate size of masternode_state (approximate)
        let masternode_state_size = if self.masternode_state.is_some() {
            std::mem::size_of::<MasternodeState>()
        } else {
            0
        };

        // Calculate size of chain_state (approximate)
        let chain_state_size = if self.chain_state.is_some() {
            std::mem::size_of::<ChainState>()
        } else {
            0
        };

        // Calculate size of header_hash_index
        let header_hash_index_size = self.header_hash_index.len()
            * (std::mem::size_of::<BlockHash>() + std::mem::size_of::<u32>());

        // UTXO size calculation removed - UTXO management is now handled externally
        let utxo_size = 0;
        let utxo_address_index_size = 0;

        // Insert all component sizes
        component_sizes.insert("headers".to_string(), header_size as u64);
        component_sizes.insert("filter_headers".to_string(), filter_header_size as u64);
        component_sizes.insert("filters".to_string(), filter_size as u64);
        component_sizes.insert("metadata".to_string(), metadata_size as u64);
        component_sizes.insert("masternode_state".to_string(), masternode_state_size as u64);
        component_sizes.insert("chain_state".to_string(), chain_state_size as u64);
        component_sizes.insert("header_hash_index".to_string(), header_hash_index_size as u64);
        component_sizes.insert("utxos".to_string(), utxo_size as u64);
        component_sizes.insert("utxo_address_index".to_string(), utxo_address_index_size as u64);

        // Calculate total size
        let total_size = header_size as u64
            + filter_header_size as u64
            + filter_size as u64
            + metadata_size as u64
            + masternode_state_size as u64
            + chain_state_size as u64
            + header_hash_index_size as u64
            + utxo_size as u64
            + utxo_address_index_size as u64;

        Ok(StorageStats {
            header_count: self.headers.len() as u64,
            filter_header_count: self.filter_headers.len() as u64,
            filter_count: self.filters.len() as u64,
            total_size,
            component_sizes,
        })
    }

    async fn get_header_height_by_hash(&self, hash: &BlockHash) -> StorageResult<Option<u32>> {
        Ok(self.header_hash_index.get(hash).copied())
    }

    async fn get_headers_batch(
        &self,
        start_height: u32,
        end_height: u32,
    ) -> StorageResult<Vec<(u32, BlockHeader)>> {
        if start_height > end_height {
            return Ok(Vec::new());
        }

        let mut results = Vec::with_capacity((end_height - start_height + 1) as usize);

        for height in start_height..=end_height {
            if let Some(header) = self.headers.get(height as usize) {
                results.push((height, *header));
            }
        }

        Ok(results)
    }

    // UTXO methods removed - handled by external wallet

    async fn store_sync_state(
        &mut self,
        state: &crate::storage::PersistentSyncState,
    ) -> StorageResult<()> {
        // For in-memory storage, we could store the sync state but it won't persist across restarts
        // This is mainly for testing and compatibility
        self.metadata.insert(
            "sync_state".to_string(),
            serde_json::to_vec(state).map_err(|e| {
                StorageError::WriteFailed(format!("Failed to serialize sync state: {}", e))
            })?,
        );
        Ok(())
    }

    async fn load_sync_state(&self) -> StorageResult<Option<crate::storage::PersistentSyncState>> {
        // Try to load from metadata (won't persist across restarts)
        if let Some(data) = self.metadata.get("sync_state") {
            let state = serde_json::from_slice(data).map_err(|e| {
                StorageError::ReadFailed(format!("Failed to deserialize sync state: {}", e))
            })?;
            Ok(Some(state))
        } else {
            Ok(None)
        }
    }

    async fn clear_sync_state(&mut self) -> StorageResult<()> {
        self.metadata.remove("sync_state");
        // Also clear checkpoints
        self.metadata.retain(|k, _| !k.starts_with("checkpoint_"));
        Ok(())
    }

    async fn store_sync_checkpoint(
        &mut self,
        height: u32,
        checkpoint: &crate::storage::sync_state::SyncCheckpoint,
    ) -> StorageResult<()> {
        let key = format!("checkpoint_{:08}", height);
        self.metadata.insert(
            key,
            serde_json::to_vec(checkpoint).map_err(|e| {
                StorageError::WriteFailed(format!("Failed to serialize checkpoint: {}", e))
            })?,
        );
        Ok(())
    }

    async fn get_sync_checkpoints(
        &self,
        start_height: u32,
        end_height: u32,
    ) -> StorageResult<Vec<crate::storage::sync_state::SyncCheckpoint>> {
        let mut checkpoints: Vec<crate::storage::sync_state::SyncCheckpoint> = Vec::new();

        for (key, data) in &self.metadata {
            if let Some(height_str) = key.strip_prefix("checkpoint_") {
                if let Ok(height) = height_str.parse::<u32>() {
                    if height >= start_height && height <= end_height {
                        if let Ok(checkpoint) = serde_json::from_slice::<
                            crate::storage::sync_state::SyncCheckpoint,
                        >(data)
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

    async fn store_chain_lock(
        &mut self,
        height: u32,
        chain_lock: &dashcore::ChainLock,
    ) -> StorageResult<()> {
        let key = format!("chainlock_{:08}", height);
        self.metadata.insert(
            key,
            bincode::serialize(chain_lock).map_err(|e| {
                StorageError::WriteFailed(format!("Failed to serialize chain lock: {}", e))
            })?,
        );
        Ok(())
    }

    async fn load_chain_lock(&self, height: u32) -> StorageResult<Option<dashcore::ChainLock>> {
        let key = format!("chainlock_{:08}", height);
        if let Some(data) = self.metadata.get(&key) {
            let chain_lock = bincode::deserialize(data).map_err(|e| {
                StorageError::ReadFailed(format!("Failed to deserialize chain lock: {}", e))
            })?;
            Ok(Some(chain_lock))
        } else {
            Ok(None)
        }
    }

    async fn get_chain_locks(
        &self,
        start_height: u32,
        end_height: u32,
    ) -> StorageResult<Vec<(u32, dashcore::ChainLock)>> {
        let mut chain_locks = Vec::new();

        for (key, data) in &self.metadata {
            if let Some(height_str) = key.strip_prefix("chainlock_") {
                if let Ok(height) = height_str.parse::<u32>() {
                    if height >= start_height && height <= end_height {
                        if let Ok(chain_lock) = bincode::deserialize(data) {
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

    async fn store_instant_lock(
        &mut self,
        txid: dashcore::Txid,
        instant_lock: &dashcore::InstantLock,
    ) -> StorageResult<()> {
        let key = format!("islock_{}", txid);
        self.metadata.insert(
            key,
            bincode::serialize(instant_lock).map_err(|e| {
                StorageError::WriteFailed(format!("Failed to serialize instant lock: {}", e))
            })?,
        );
        Ok(())
    }

    async fn load_instant_lock(
        &self,
        txid: dashcore::Txid,
    ) -> StorageResult<Option<dashcore::InstantLock>> {
        let key = format!("islock_{}", txid);
        if let Some(data) = self.metadata.get(&key) {
            let instant_lock = bincode::deserialize(data).map_err(|e| {
                StorageError::ReadFailed(format!("Failed to deserialize instant lock: {}", e))
            })?;
            Ok(Some(instant_lock))
        } else {
            Ok(None)
        }
    }

    // Mempool storage methods
    async fn store_mempool_transaction(
        &mut self,
        txid: &Txid,
        tx: &UnconfirmedTransaction,
    ) -> StorageResult<()> {
        self.mempool_transactions.insert(*txid, tx.clone());
        Ok(())
    }

    async fn remove_mempool_transaction(&mut self, txid: &Txid) -> StorageResult<()> {
        self.mempool_transactions.remove(txid);
        Ok(())
    }

    async fn get_mempool_transaction(
        &self,
        txid: &Txid,
    ) -> StorageResult<Option<UnconfirmedTransaction>> {
        Ok(self.mempool_transactions.get(txid).cloned())
    }

    async fn get_all_mempool_transactions(
        &self,
    ) -> StorageResult<HashMap<Txid, UnconfirmedTransaction>> {
        Ok(self.mempool_transactions.clone())
    }

    async fn store_mempool_state(&mut self, state: &MempoolState) -> StorageResult<()> {
        self.mempool_state = Some(state.clone());
        Ok(())
    }

    async fn load_mempool_state(&self) -> StorageResult<Option<MempoolState>> {
        Ok(self.mempool_state.clone())
    }

    async fn clear_mempool(&mut self) -> StorageResult<()> {
        self.mempool_transactions.clear();
        self.mempool_state = None;
        Ok(())
    }
}
