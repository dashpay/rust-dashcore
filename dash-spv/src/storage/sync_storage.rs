//! Synchronous storage wrapper for testing

use super::ChainStorage;
use crate::error::StorageError;
use dashcore::{BlockHash, Header as BlockHeader, Transaction, Txid};
use std::collections::HashMap;
use std::sync::RwLock;

/// Simple in-memory storage for testing
pub struct MemoryStorage {
    headers: RwLock<HashMap<BlockHash, (BlockHeader, u32)>>,
    height_index: RwLock<HashMap<u32, BlockHash>>,
    transactions: RwLock<HashMap<Txid, Transaction>>,
    block_txs: RwLock<HashMap<BlockHash, Vec<Txid>>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            headers: RwLock::new(HashMap::new()),
            height_index: RwLock::new(HashMap::new()),
            transactions: RwLock::new(HashMap::new()),
            block_txs: RwLock::new(HashMap::new()),
        }
    }
}

impl ChainStorage for MemoryStorage {
    fn get_header(&self, hash: &BlockHash) -> Result<Option<BlockHeader>, StorageError> {
        let headers = self.headers.read().map_err(|e| {
            StorageError::LockPoisoned(format!("Failed to acquire read lock: {}", e))
        })?;
        Ok(headers.get(hash).map(|(h, _)| *h))
    }

    fn get_header_by_height(&self, height: u32) -> Result<Option<BlockHeader>, StorageError> {
        let height_index = self.height_index.read().map_err(|e| {
            StorageError::LockPoisoned(format!("Failed to acquire read lock: {}", e))
        })?;
        if let Some(hash) = height_index.get(&height).cloned() {
            drop(height_index); // Release lock before calling get_header
            self.get_header(&hash)
        } else {
            Ok(None)
        }
    }

    fn get_header_height(&self, hash: &BlockHash) -> Result<Option<u32>, StorageError> {
        let headers = self.headers.read().map_err(|e| {
            StorageError::LockPoisoned(format!("Failed to acquire read lock: {}", e))
        })?;
        Ok(headers.get(hash).map(|(_, h)| *h))
    }

    fn store_header(&self, header: &BlockHeader, height: u32) -> Result<(), StorageError> {
        let hash = header.block_hash();
        let mut headers = self.headers.write().map_err(|e| {
            StorageError::LockPoisoned(format!("Failed to acquire write lock: {}", e))
        })?;
        headers.insert(hash, (*header, height));
        drop(headers); // Release lock before acquiring the next one

        let mut height_index = self.height_index.write().map_err(|e| {
            StorageError::LockPoisoned(format!("Failed to acquire write lock: {}", e))
        })?;
        height_index.insert(height, hash);
        Ok(())
    }

    fn get_block_transactions(
        &self,
        block_hash: &BlockHash,
    ) -> Result<Option<Vec<Txid>>, StorageError> {
        let block_txs = self.block_txs.read().map_err(|e| {
            StorageError::LockPoisoned(format!("Failed to acquire read lock: {}", e))
        })?;
        Ok(block_txs.get(block_hash).cloned())
    }

    fn get_transaction(&self, txid: &Txid) -> Result<Option<Transaction>, StorageError> {
        let transactions = self.transactions.read().map_err(|e| {
            StorageError::LockPoisoned(format!("Failed to acquire read lock: {}", e))
        })?;
        Ok(transactions.get(txid).cloned())
    }
}
