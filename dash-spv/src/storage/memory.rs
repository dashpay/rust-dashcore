//! In-memory storage implementation.

use std::collections::HashMap;
use std::ops::Range;
use async_trait::async_trait;

use dashcore::{
    block::Header as BlockHeader,
    hash_types::FilterHeader,
};

use crate::error::{StorageError, StorageResult};
use crate::storage::{StorageManager, MasternodeState, StorageStats};
use crate::types::ChainState;

/// In-memory storage manager.
pub struct MemoryStorageManager {
    headers: Vec<BlockHeader>,
    filter_headers: Vec<FilterHeader>,
    filters: HashMap<u32, Vec<u8>>,
    masternode_state: Option<MasternodeState>,
    chain_state: Option<ChainState>,
    metadata: HashMap<String, Vec<u8>>,
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
        })
    }
}

#[async_trait]
impl StorageManager for MemoryStorageManager {
    async fn store_headers(&mut self, headers: &[BlockHeader]) -> StorageResult<()> {
        for header in headers {
            // Simple append - in a real implementation, we'd want to validate continuity
            self.headers.push(*header);
        }
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
        Ok(self.filter_headers.get(height as usize).copied())
    }
    
    async fn get_filter_tip_height(&self) -> StorageResult<Option<u32>> {
        if self.filter_headers.is_empty() {
            Ok(None)
        } else {
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
        Ok(())
    }
    
    async fn stats(&self) -> StorageResult<StorageStats> {
        let mut component_sizes = HashMap::new();
        
        let header_size = self.headers.len() * std::mem::size_of::<BlockHeader>();
        let filter_header_size = self.filter_headers.len() * std::mem::size_of::<FilterHeader>();
        let filter_size: usize = self.filters.values().map(|f| f.len()).sum();
        let metadata_size: usize = self.metadata.values().map(|v| v.len()).sum();
        
        component_sizes.insert("headers".to_string(), header_size as u64);
        component_sizes.insert("filter_headers".to_string(), filter_header_size as u64);
        component_sizes.insert("filters".to_string(), filter_size as u64);
        component_sizes.insert("metadata".to_string(), metadata_size as u64);
        
        Ok(StorageStats {
            header_count: self.headers.len() as u64,
            filter_header_count: self.filter_headers.len() as u64,
            filter_count: self.filters.len() as u64,
            total_size: header_size as u64 + filter_header_size as u64 + filter_size as u64 + metadata_size as u64,
            component_sizes,
        })
    }
}