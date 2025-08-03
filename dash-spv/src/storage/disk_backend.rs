//! Disk storage backend adapter for the new service architecture

use super::disk::DiskStorageManager;
use super::service::StorageBackend;
use super::types::MasternodeState;
use super::{StorageError, StorageManager as OldStorageManager, StorageResult};
use crate::types::{ChainState, MempoolState, UnconfirmedTransaction};
use crate::wallet::Utxo;
use dashcore::hash_types::FilterHeader;
use dashcore::{block::Header as BlockHeader, Address, BlockHash, OutPoint, Txid};
use std::ops::Range;
use std::path::PathBuf;

/// Disk-based storage backend implementation
///
/// This wraps the existing DiskStorageManager to implement the new StorageBackend trait.
/// This allows gradual migration while maintaining backward compatibility.
pub struct DiskStorageBackend {
    inner: DiskStorageManager,
}

impl DiskStorageBackend {
    pub async fn new(path: PathBuf) -> StorageResult<Self> {
        let inner = DiskStorageManager::new(path).await?;
        Ok(Self {
            inner,
        })
    }
}

#[async_trait::async_trait]
impl StorageBackend for DiskStorageBackend {
    // Header operations
    async fn store_header(&mut self, header: &BlockHeader, height: u32) -> StorageResult<()> {
        // Use store_headers_from_height to specify the exact height
        let result = self.inner.store_headers_from_height(&[*header], height).await;
        result
    }

    async fn store_headers(&mut self, headers: &[BlockHeader]) -> StorageResult<()> {
        self.inner.store_headers(headers).await
    }

    async fn get_header(&self, height: u32) -> StorageResult<Option<BlockHeader>> {
        self.inner.get_header(height).await
    }

    async fn get_header_by_hash(&self, hash: &BlockHash) -> StorageResult<Option<BlockHeader>> {
        // First get the height of this hash
        if let Some(height) = self.inner.get_header_height_by_hash(hash).await? {
            self.inner.get_header(height).await
        } else {
            Ok(None)
        }
    }

    async fn get_header_height(&self, hash: &BlockHash) -> StorageResult<Option<u32>> {
        self.inner.get_header_height_by_hash(hash).await
    }

    async fn get_tip_height(&self) -> StorageResult<Option<u32>> {
        self.inner.get_tip_height().await
    }

    async fn load_headers(&self, range: Range<u32>) -> StorageResult<Vec<BlockHeader>> {
        self.inner.load_headers(range).await
    }

    // Filter operations
    async fn store_filter_header(
        &mut self,
        header: &FilterHeader,
        _height: u32,
    ) -> StorageResult<()> {
        self.inner.store_filter_headers(&[*header]).await
    }

    async fn get_filter_header(&self, height: u32) -> StorageResult<Option<FilterHeader>> {
        self.inner.get_filter_header(height).await
    }

    async fn get_filter_tip_height(&self) -> StorageResult<Option<u32>> {
        self.inner.get_filter_tip_height().await
    }

    async fn store_filter(&mut self, filter: &[u8], height: u32) -> StorageResult<()> {
        self.inner.store_filter(height, filter).await
    }

    async fn get_filter(&self, height: u32) -> StorageResult<Option<Vec<u8>>> {
        self.inner.load_filter(height).await
    }

    // State operations
    async fn save_masternode_state(&mut self, state: &MasternodeState) -> StorageResult<()> {
        self.inner.store_masternode_state(state).await
    }

    async fn load_masternode_state(&self) -> StorageResult<Option<MasternodeState>> {
        self.inner.load_masternode_state().await
    }

    async fn store_chain_state(&mut self, state: &ChainState) -> StorageResult<()> {
        self.inner.store_chain_state(state).await
    }

    async fn load_chain_state(&self) -> StorageResult<Option<ChainState>> {
        self.inner.load_chain_state().await
    }

    // UTXO operations
    async fn store_utxo(&mut self, outpoint: &OutPoint, utxo: &Utxo) -> StorageResult<()> {
        self.inner.store_utxo(outpoint, utxo).await
    }

    async fn remove_utxo(&mut self, outpoint: &OutPoint) -> StorageResult<()> {
        self.inner.remove_utxo(outpoint).await
    }

    async fn get_utxo(&self, outpoint: &OutPoint) -> StorageResult<Option<Utxo>> {
        let utxos = self.inner.get_all_utxos().await?;
        Ok(utxos.get(outpoint).cloned())
    }

    async fn get_utxos_for_address(
        &self,
        address: &Address,
    ) -> StorageResult<Vec<(OutPoint, Utxo)>> {
        let utxos = self.inner.get_utxos_for_address(address).await?;
        // Convert Vec<Utxo> to Vec<(OutPoint, Utxo)>
        Ok(utxos.into_iter().map(|utxo| (utxo.outpoint, utxo)).collect())
    }

    async fn get_all_utxos(&self) -> StorageResult<Vec<(OutPoint, Utxo)>> {
        let utxos = self.inner.get_all_utxos().await?;
        Ok(utxos.into_iter().collect())
    }

    // Mempool operations
    async fn save_mempool_state(&mut self, state: &MempoolState) -> StorageResult<()> {
        self.inner.store_mempool_state(state).await
    }

    async fn load_mempool_state(&self) -> StorageResult<Option<MempoolState>> {
        self.inner.load_mempool_state().await
    }

    async fn add_mempool_transaction(
        &mut self,
        txid: &Txid,
        tx: &UnconfirmedTransaction,
    ) -> StorageResult<()> {
        self.inner.store_mempool_transaction(txid, tx).await
    }

    async fn remove_mempool_transaction(&mut self, txid: &Txid) -> StorageResult<()> {
        self.inner.remove_mempool_transaction(txid).await
    }

    async fn get_mempool_transaction(
        &self,
        txid: &Txid,
    ) -> StorageResult<Option<UnconfirmedTransaction>> {
        self.inner.get_mempool_transaction(txid).await
    }

    async fn clear_mempool(&mut self) -> StorageResult<()> {
        self.inner.clear_mempool().await
    }
}
