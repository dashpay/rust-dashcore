//! Synchronous storage wrapper for testing

use std::collections::HashMap;
use std::sync::RwLock;
use dashcore::{BlockHash, Header as BlockHeader, Transaction, Txid};
use crate::error::StorageError;
use super::ChainStorage;

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
        Ok(self.headers.read().unwrap().get(hash).map(|(h, _)| *h))
    }
    
    fn get_header_by_height(&self, height: u32) -> Result<Option<BlockHeader>, StorageError> {
        if let Some(hash) = self.height_index.read().unwrap().get(&height).cloned() {
            self.get_header(&hash)
        } else {
            Ok(None)
        }
    }
    
    fn get_header_height(&self, hash: &BlockHash) -> Result<Option<u32>, StorageError> {
        Ok(self.headers.read().unwrap().get(hash).map(|(_, h)| *h))
    }
    
    fn store_header(&self, header: &BlockHeader, height: u32) -> Result<(), StorageError> {
        let hash = header.block_hash();
        self.headers.write().unwrap().insert(hash, (*header, height));
        self.height_index.write().unwrap().insert(height, hash);
        Ok(())
    }
    
    fn get_block_transactions(&self, block_hash: &BlockHash) -> Result<Option<Vec<Txid>>, StorageError> {
        Ok(self.block_txs.read().unwrap().get(block_hash).cloned())
    }
    
    fn get_transaction(&self, txid: &Txid) -> Result<Option<Transaction>, StorageError> {
        Ok(self.transactions.read().unwrap().get(txid).cloned())
    }
}