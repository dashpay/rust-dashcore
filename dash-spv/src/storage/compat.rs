//! Compatibility layer to bridge old StorageManager trait with new StorageClient
//!
//! This allows gradual migration from the old mutable reference based storage
//! to the new event-driven storage service architecture.

use super::{
    service::StorageClient,
    sync_state::{PersistentSyncState, SyncCheckpoint},
    types::{MasternodeState, StoredTerminalBlock},
    StorageError, StorageManager, StorageResult, StorageStats,
};
use crate::types::{ChainState, MempoolState, UnconfirmedTransaction};
use crate::wallet::Utxo;
use async_trait::async_trait;
use dashcore::{
    block::Header as BlockHeader, hash_types::FilterHeader, Address, BlockHash, ChainLock,
    InstantLock, OutPoint, Txid,
};
use std::collections::HashMap;
use std::ops::Range;

/// A wrapper that implements the old StorageManager trait using the new StorageClient
///
/// This allows existing code to continue using the StorageManager trait while
/// the underlying implementation uses the new event-driven architecture.
pub struct StorageManagerCompat {
    client: StorageClient,
}

impl StorageManagerCompat {
    /// Create a new compatibility wrapper around a StorageClient
    pub fn new(client: StorageClient) -> Self {
        Self {
            client,
        }
    }
}

#[async_trait]
impl StorageManager for StorageManagerCompat {
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    async fn store_headers(&mut self, headers: &[BlockHeader]) -> StorageResult<()> {
        if headers.is_empty() {
            return Ok(());
        }

        tracing::debug!(
            "StorageManagerCompat::store_headers - storing {} headers as a batch",
            headers.len()
        );

        let start_time = std::time::Instant::now();

        // Use the new batch storage method in a spawned task to prevent cancellation
        let client = self.client.clone();
        let headers_vec = headers.to_vec();
        let result = tokio::spawn(async move { client.store_headers(&headers_vec).await })
            .await
            .map_err(|e| {
                tracing::error!("Failed to spawn store_headers task: {:?}", e);
                StorageError::ServiceUnavailable
            })?;

        result?;

        let total_duration = start_time.elapsed();
        let headers_per_second = if total_duration.as_secs_f64() > 0.0 {
            headers.len() as f64 / total_duration.as_secs_f64()
        } else {
            0.0
        };

        tracing::debug!(
            "StorageManagerCompat::store_headers - stored {} headers in {:?} ({:.1} headers/sec)",
            headers.len(),
            total_duration,
            headers_per_second
        );

        Ok(())
    }

    async fn load_headers(&self, range: Range<u32>) -> StorageResult<Vec<BlockHeader>> {
        self.client.load_headers(range).await
    }

    async fn get_header(&self, height: u32) -> StorageResult<Option<BlockHeader>> {
        self.client.get_header(height).await
    }

    async fn get_tip_height(&self) -> StorageResult<Option<u32>> {
        self.client.get_tip_height().await
    }

    async fn store_filter_headers(&mut self, headers: &[FilterHeader]) -> StorageResult<()> {
        // Store filter headers one by one with their heights
        let tip_height = self.client.get_filter_tip_height().await?.unwrap_or(0);

        for (i, header) in headers.iter().enumerate() {
            let height = tip_height + i as u32 + 1;
            self.client.store_filter_header(header, height).await?;
        }

        Ok(())
    }

    async fn load_filter_headers(&self, range: Range<u32>) -> StorageResult<Vec<FilterHeader>> {
        let mut headers = Vec::new();

        for height in range {
            if let Some(header) = self.client.get_filter_header(height).await? {
                headers.push(header);
            }
        }

        Ok(headers)
    }

    async fn get_filter_header(&self, height: u32) -> StorageResult<Option<FilterHeader>> {
        self.client.get_filter_header(height).await
    }

    async fn get_filter_tip_height(&self) -> StorageResult<Option<u32>> {
        self.client.get_filter_tip_height().await
    }

    async fn store_masternode_state(&mut self, state: &MasternodeState) -> StorageResult<()> {
        self.client.save_masternode_state(state).await
    }

    async fn load_masternode_state(&self) -> StorageResult<Option<MasternodeState>> {
        self.client.load_masternode_state().await
    }

    async fn store_chain_state(&mut self, state: &ChainState) -> StorageResult<()> {
        self.client.store_chain_state(state).await
    }

    async fn load_chain_state(&self) -> StorageResult<Option<ChainState>> {
        self.client.load_chain_state().await
    }

    async fn store_filter(&mut self, height: u32, filter: &[u8]) -> StorageResult<()> {
        self.client.store_filter(filter, height).await
    }

    async fn load_filter(&self, height: u32) -> StorageResult<Option<Vec<u8>>> {
        self.client.get_filter(height).await
    }

    async fn store_metadata(&mut self, _key: &str, _value: &[u8]) -> StorageResult<()> {
        // TODO: Implement metadata storage in StorageClient
        Err(StorageError::NotImplemented("Metadata storage not yet implemented in StorageClient"))
    }

    async fn load_metadata(&self, _key: &str) -> StorageResult<Option<Vec<u8>>> {
        // TODO: Implement metadata storage in StorageClient
        Ok(None)
    }

    async fn clear(&mut self) -> StorageResult<()> {
        // TODO: Implement clear in StorageClient
        Err(StorageError::NotImplemented("Clear not yet implemented in StorageClient"))
    }

    async fn stats(&self) -> StorageResult<StorageStats> {
        // TODO: Implement stats in StorageClient
        Ok(StorageStats::default())
    }

    async fn get_header_height_by_hash(&self, hash: &BlockHash) -> StorageResult<Option<u32>> {
        self.client.get_header_height(hash).await
    }

    async fn get_headers_batch(
        &self,
        start_height: u32,
        end_height: u32,
    ) -> StorageResult<Vec<(u32, BlockHeader)>> {
        let mut results = Vec::new();

        for height in start_height..=end_height {
            if let Some(header) = self.client.get_header(height).await? {
                results.push((height, header));
            }
        }

        Ok(results)
    }

    async fn store_utxo(&mut self, outpoint: &OutPoint, utxo: &Utxo) -> StorageResult<()> {
        self.client.store_utxo(outpoint, utxo).await
    }

    async fn remove_utxo(&mut self, outpoint: &OutPoint) -> StorageResult<()> {
        self.client.remove_utxo(outpoint).await
    }

    async fn get_utxos_for_address(&self, address: &Address) -> StorageResult<Vec<Utxo>> {
        let utxos_with_outpoints = self.client.get_utxos_for_address(address).await?;
        Ok(utxos_with_outpoints.into_iter().map(|(_, utxo)| utxo).collect())
    }

    async fn get_all_utxos(&self) -> StorageResult<HashMap<OutPoint, Utxo>> {
        let utxos = self.client.get_all_utxos().await?;
        Ok(utxos.into_iter().collect())
    }

    async fn store_sync_state(&mut self, _state: &PersistentSyncState) -> StorageResult<()> {
        // TODO: Implement sync state storage in StorageClient
        Err(StorageError::NotImplemented("Sync state storage not yet implemented in StorageClient"))
    }

    async fn load_sync_state(&self) -> StorageResult<Option<PersistentSyncState>> {
        // TODO: Implement sync state storage in StorageClient
        Ok(None)
    }

    async fn clear_sync_state(&mut self) -> StorageResult<()> {
        // TODO: Implement sync state storage in StorageClient
        Ok(())
    }

    async fn store_sync_checkpoint(
        &mut self,
        _height: u32,
        _checkpoint: &SyncCheckpoint,
    ) -> StorageResult<()> {
        // TODO: Implement checkpoint storage in StorageClient
        Err(StorageError::NotImplemented("Checkpoint storage not yet implemented in StorageClient"))
    }

    async fn get_sync_checkpoints(
        &self,
        _start_height: u32,
        _end_height: u32,
    ) -> StorageResult<Vec<SyncCheckpoint>> {
        // TODO: Implement checkpoint storage in StorageClient
        Ok(Vec::new())
    }

    async fn store_chain_lock(
        &mut self,
        _height: u32,
        _chain_lock: &ChainLock,
    ) -> StorageResult<()> {
        // TODO: Implement ChainLock storage in StorageClient
        Err(StorageError::NotImplemented("ChainLock storage not yet implemented in StorageClient"))
    }

    async fn load_chain_lock(&self, _height: u32) -> StorageResult<Option<ChainLock>> {
        // TODO: Implement ChainLock storage in StorageClient
        Ok(None)
    }

    async fn get_chain_locks(
        &self,
        _start_height: u32,
        _end_height: u32,
    ) -> StorageResult<Vec<(u32, ChainLock)>> {
        // TODO: Implement ChainLock storage in StorageClient
        Ok(Vec::new())
    }

    async fn store_instant_lock(
        &mut self,
        _txid: Txid,
        _instant_lock: &InstantLock,
    ) -> StorageResult<()> {
        // TODO: Implement InstantLock storage in StorageClient
        Err(StorageError::NotImplemented(
            "InstantLock storage not yet implemented in StorageClient",
        ))
    }

    async fn load_instant_lock(&self, _txid: Txid) -> StorageResult<Option<InstantLock>> {
        // TODO: Implement InstantLock storage in StorageClient
        Ok(None)
    }

    async fn store_terminal_block(&mut self, _block: &StoredTerminalBlock) -> StorageResult<()> {
        // TODO: Implement terminal block storage in StorageClient
        Err(StorageError::NotImplemented(
            "Terminal block storage not yet implemented in StorageClient",
        ))
    }

    async fn load_terminal_block(
        &self,
        _height: u32,
    ) -> StorageResult<Option<StoredTerminalBlock>> {
        // TODO: Implement terminal block storage in StorageClient
        Ok(None)
    }

    async fn get_all_terminal_blocks(&self) -> StorageResult<Vec<StoredTerminalBlock>> {
        // TODO: Implement terminal block storage in StorageClient
        Ok(Vec::new())
    }

    async fn has_terminal_block(&self, _height: u32) -> StorageResult<bool> {
        // TODO: Implement terminal block storage in StorageClient
        Ok(false)
    }

    async fn store_mempool_transaction(
        &mut self,
        txid: &Txid,
        tx: &UnconfirmedTransaction,
    ) -> StorageResult<()> {
        self.client.add_mempool_transaction(txid, tx).await
    }

    async fn remove_mempool_transaction(&mut self, txid: &Txid) -> StorageResult<()> {
        self.client.remove_mempool_transaction(txid).await
    }

    async fn get_mempool_transaction(
        &self,
        txid: &Txid,
    ) -> StorageResult<Option<UnconfirmedTransaction>> {
        self.client.get_mempool_transaction(txid).await
    }

    async fn get_all_mempool_transactions(
        &self,
    ) -> StorageResult<HashMap<Txid, UnconfirmedTransaction>> {
        // TODO: Implement get_all_mempool_transactions in StorageClient
        Ok(HashMap::new())
    }

    async fn store_mempool_state(&mut self, state: &MempoolState) -> StorageResult<()> {
        self.client.save_mempool_state(state).await
    }

    async fn load_mempool_state(&self) -> StorageResult<Option<MempoolState>> {
        self.client.load_mempool_state().await
    }

    async fn clear_mempool(&mut self) -> StorageResult<()> {
        self.client.clear_mempool().await
    }
}
