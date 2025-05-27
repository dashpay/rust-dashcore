//! Storage abstraction for the Dash SPV client.

pub mod memory;
pub mod disk;
pub mod types;

use std::ops::Range;
use std::any::Any;
use async_trait::async_trait;

use dashcore::{
    block::Header as BlockHeader,
    hash_types::FilterHeader,
};

use crate::error::StorageResult;
use crate::types::ChainState;

pub use memory::MemoryStorageManager;
pub use disk::DiskStorageManager;
pub use types::*;

/// Storage manager trait for abstracting data persistence.
#[async_trait]
pub trait StorageManager: Send + Sync {
    /// Convert to Any for downcasting
    fn as_any_mut(&mut self) -> &mut dyn Any;
    /// Store block headers.
    async fn store_headers(&mut self, headers: &[BlockHeader]) -> StorageResult<()>;
    
    /// Load block headers in the given range.
    async fn load_headers(&self, range: Range<u32>) -> StorageResult<Vec<BlockHeader>>;
    
    /// Get a specific header by height.
    async fn get_header(&self, height: u32) -> StorageResult<Option<BlockHeader>>;
    
    /// Get the current tip height.
    async fn get_tip_height(&self) -> StorageResult<Option<u32>>;
    
    /// Store filter headers.
    async fn store_filter_headers(&mut self, headers: &[FilterHeader]) -> StorageResult<()>;
    
    /// Load filter headers in the given range.
    async fn load_filter_headers(&self, range: Range<u32>) -> StorageResult<Vec<FilterHeader>>;
    
    /// Get a specific filter header by height.
    async fn get_filter_header(&self, height: u32) -> StorageResult<Option<FilterHeader>>;
    
    /// Get the current filter tip height.
    async fn get_filter_tip_height(&self) -> StorageResult<Option<u32>>;
    
    /// Store masternode state.
    async fn store_masternode_state(&mut self, state: &MasternodeState) -> StorageResult<()>;
    
    /// Load masternode state.
    async fn load_masternode_state(&self) -> StorageResult<Option<MasternodeState>>;
    
    /// Store chain state.
    async fn store_chain_state(&mut self, state: &ChainState) -> StorageResult<()>;
    
    /// Load chain state.
    async fn load_chain_state(&self) -> StorageResult<Option<ChainState>>;
    
    /// Store a compact filter.
    async fn store_filter(&mut self, height: u32, filter: &[u8]) -> StorageResult<()>;
    
    /// Load a compact filter.
    async fn load_filter(&self, height: u32) -> StorageResult<Option<Vec<u8>>>;
    
    /// Store metadata.
    async fn store_metadata(&mut self, key: &str, value: &[u8]) -> StorageResult<()>;
    
    /// Load metadata.
    async fn load_metadata(&self, key: &str) -> StorageResult<Option<Vec<u8>>>;
    
    /// Clear all data.
    async fn clear(&mut self) -> StorageResult<()>;
    
    /// Get storage statistics.
    async fn stats(&self) -> StorageResult<StorageStats>;
    
    /// Get header height by block hash (reverse lookup).
    async fn get_header_height_by_hash(&self, hash: &dashcore::BlockHash) -> StorageResult<Option<u32>>;
    
    /// Get multiple headers in a single batch operation.
    /// Returns headers with their heights. More efficient than calling get_header multiple times.
    async fn get_headers_batch(&self, start_height: u32, end_height: u32) -> StorageResult<Vec<(u32, BlockHeader)>>;
}

/// Helper trait to provide as_any_mut for all StorageManager implementations
pub trait AsAnyMut {
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

impl<T: 'static> AsAnyMut for T {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}