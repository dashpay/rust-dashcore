//! Memory storage backend adapter for the new service architecture

use super::service::StorageBackend;
use super::types::MasternodeState;
use super::{StorageError, StorageResult};
use crate::types::{ChainState, MempoolState, UnconfirmedTransaction};
use crate::wallet::Utxo;
use dashcore::hash_types::FilterHeader;
use dashcore::{block::Header as BlockHeader, Address, BlockHash, OutPoint, Txid};
use std::collections::HashMap;
use std::ops::Range;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Memory-based storage backend implementation
pub struct MemoryStorageBackend {
    headers: Arc<RwLock<HashMap<u32, BlockHeader>>>,
    header_index: Arc<RwLock<HashMap<BlockHash, u32>>>,
    filter_headers: Arc<RwLock<HashMap<u32, FilterHeader>>>,
    filters: Arc<RwLock<HashMap<u32, Vec<u8>>>>,
    masternode_state: Arc<RwLock<Option<MasternodeState>>>,
    chain_state: Arc<RwLock<Option<ChainState>>>,
    utxos: Arc<RwLock<HashMap<OutPoint, Utxo>>>,
    utxo_by_address: Arc<RwLock<HashMap<Address, Vec<OutPoint>>>>,
    mempool_state: Arc<RwLock<Option<MempoolState>>>,
    mempool_txs: Arc<RwLock<HashMap<Txid, UnconfirmedTransaction>>>,
}

impl MemoryStorageBackend {
    pub fn new() -> Self {
        Self {
            headers: Arc::new(RwLock::new(HashMap::new())),
            header_index: Arc::new(RwLock::new(HashMap::new())),
            filter_headers: Arc::new(RwLock::new(HashMap::new())),
            filters: Arc::new(RwLock::new(HashMap::new())),
            masternode_state: Arc::new(RwLock::new(None)),
            chain_state: Arc::new(RwLock::new(None)),
            utxos: Arc::new(RwLock::new(HashMap::new())),
            utxo_by_address: Arc::new(RwLock::new(HashMap::new())),
            mempool_state: Arc::new(RwLock::new(None)),
            mempool_txs: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl StorageBackend for MemoryStorageBackend {
    // Header operations
    async fn store_header(&mut self, header: &BlockHeader, height: u32) -> StorageResult<()> {
        let mut headers = self.headers.write().await;
        let mut index = self.header_index.write().await;

        headers.insert(height, *header);
        index.insert(header.block_hash(), height);
        Ok(())
    }

    async fn store_headers(&mut self, headers_batch: &[BlockHeader]) -> StorageResult<()> {
        if headers_batch.is_empty() {
            return Ok(());
        }

        let mut headers = self.headers.write().await;
        let mut index = self.header_index.write().await;

        // Get the current tip height
        let initial_height = headers.keys().max().copied().unwrap_or(0) + 1;

        // Store all headers in the batch
        for (i, header) in headers_batch.iter().enumerate() {
            let height = initial_height + i as u32;
            headers.insert(height, *header);
            index.insert(header.block_hash(), height);
        }

        Ok(())
    }

    async fn get_header(&self, height: u32) -> StorageResult<Option<BlockHeader>> {
        let headers = self.headers.read().await;
        Ok(headers.get(&height).copied())
    }

    async fn get_header_by_hash(&self, hash: &BlockHash) -> StorageResult<Option<BlockHeader>> {
        let index = self.header_index.read().await;
        if let Some(&height) = index.get(hash) {
            let headers = self.headers.read().await;
            Ok(headers.get(&height).copied())
        } else {
            Ok(None)
        }
    }

    async fn get_header_height(&self, hash: &BlockHash) -> StorageResult<Option<u32>> {
        let index = self.header_index.read().await;
        Ok(index.get(hash).copied())
    }

    async fn get_tip_height(&self) -> StorageResult<Option<u32>> {
        let headers = self.headers.read().await;
        Ok(headers.keys().max().copied())
    }

    async fn load_headers(&self, range: Range<u32>) -> StorageResult<Vec<BlockHeader>> {
        let headers = self.headers.read().await;
        let mut result = Vec::new();

        for height in range {
            if let Some(header) = headers.get(&height) {
                result.push(*header);
            }
        }

        Ok(result)
    }

    // Filter operations
    async fn store_filter_header(
        &mut self,
        header: &FilterHeader,
        height: u32,
    ) -> StorageResult<()> {
        let mut filter_headers = self.filter_headers.write().await;
        filter_headers.insert(height, *header);
        Ok(())
    }

    async fn get_filter_header(&self, height: u32) -> StorageResult<Option<FilterHeader>> {
        let filter_headers = self.filter_headers.read().await;
        Ok(filter_headers.get(&height).copied())
    }

    async fn get_filter_tip_height(&self) -> StorageResult<Option<u32>> {
        let filter_headers = self.filter_headers.read().await;
        Ok(filter_headers.keys().max().copied())
    }

    async fn store_filter(&mut self, filter: &[u8], height: u32) -> StorageResult<()> {
        let mut filters = self.filters.write().await;
        filters.insert(height, filter.to_vec());
        Ok(())
    }

    async fn get_filter(&self, height: u32) -> StorageResult<Option<Vec<u8>>> {
        let filters = self.filters.read().await;
        Ok(filters.get(&height).cloned())
    }

    // State operations
    async fn save_masternode_state(&mut self, state: &MasternodeState) -> StorageResult<()> {
        let mut mn_state = self.masternode_state.write().await;
        *mn_state = Some(state.clone());
        Ok(())
    }

    async fn load_masternode_state(&self) -> StorageResult<Option<MasternodeState>> {
        let mn_state = self.masternode_state.read().await;
        Ok(mn_state.clone())
    }

    async fn store_chain_state(&mut self, state: &ChainState) -> StorageResult<()> {
        let mut chain_state = self.chain_state.write().await;
        *chain_state = Some(state.clone());
        Ok(())
    }

    async fn load_chain_state(&self) -> StorageResult<Option<ChainState>> {
        let chain_state = self.chain_state.read().await;
        Ok(chain_state.clone())
    }

    // UTXO operations
    async fn store_utxo(&mut self, outpoint: &OutPoint, utxo: &Utxo) -> StorageResult<()> {
        let mut utxos = self.utxos.write().await;
        let mut by_address = self.utxo_by_address.write().await;

        utxos.insert(*outpoint, utxo.clone());

        let outpoints = by_address.entry(utxo.address.clone()).or_insert_with(Vec::new);
        if !outpoints.contains(outpoint) {
            outpoints.push(*outpoint);
        }

        Ok(())
    }

    async fn remove_utxo(&mut self, outpoint: &OutPoint) -> StorageResult<()> {
        let mut utxos = self.utxos.write().await;
        let mut by_address = self.utxo_by_address.write().await;

        if let Some(utxo) = utxos.remove(outpoint) {
            if let Some(outpoints) = by_address.get_mut(&utxo.address) {
                outpoints.retain(|op| op != outpoint);
                if outpoints.is_empty() {
                    by_address.remove(&utxo.address);
                }
            }
        }

        Ok(())
    }

    async fn get_utxo(&self, outpoint: &OutPoint) -> StorageResult<Option<Utxo>> {
        let utxos = self.utxos.read().await;
        Ok(utxos.get(outpoint).cloned())
    }

    async fn get_utxos_for_address(
        &self,
        address: &Address,
    ) -> StorageResult<Vec<(OutPoint, Utxo)>> {
        let by_address = self.utxo_by_address.read().await;
        let utxos = self.utxos.read().await;

        let mut result = Vec::new();
        if let Some(outpoints) = by_address.get(address) {
            for outpoint in outpoints {
                if let Some(utxo) = utxos.get(outpoint) {
                    result.push((*outpoint, utxo.clone()));
                }
            }
        }

        Ok(result)
    }

    async fn get_all_utxos(&self) -> StorageResult<Vec<(OutPoint, Utxo)>> {
        let utxos = self.utxos.read().await;
        Ok(utxos.iter().map(|(k, v)| (*k, v.clone())).collect())
    }

    // Mempool operations
    async fn save_mempool_state(&mut self, state: &MempoolState) -> StorageResult<()> {
        let mut mempool_state = self.mempool_state.write().await;
        *mempool_state = Some(state.clone());
        Ok(())
    }

    async fn load_mempool_state(&self) -> StorageResult<Option<MempoolState>> {
        let mempool_state = self.mempool_state.read().await;
        Ok(mempool_state.clone())
    }

    async fn add_mempool_transaction(
        &mut self,
        txid: &Txid,
        tx: &UnconfirmedTransaction,
    ) -> StorageResult<()> {
        let mut mempool_txs = self.mempool_txs.write().await;
        mempool_txs.insert(*txid, tx.clone());
        Ok(())
    }

    async fn remove_mempool_transaction(&mut self, txid: &Txid) -> StorageResult<()> {
        let mut mempool_txs = self.mempool_txs.write().await;
        mempool_txs.remove(txid);
        Ok(())
    }

    async fn get_mempool_transaction(
        &self,
        txid: &Txid,
    ) -> StorageResult<Option<UnconfirmedTransaction>> {
        let mempool_txs = self.mempool_txs.read().await;
        Ok(mempool_txs.get(txid).cloned())
    }

    async fn clear_mempool(&mut self) -> StorageResult<()> {
        let mut mempool_txs = self.mempool_txs.write().await;
        mempool_txs.clear();
        Ok(())
    }
}
