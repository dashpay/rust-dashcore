//! Disk-based storage implementation.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use async_trait::async_trait;

use dashcore::{
    block::Header as BlockHeader,
    consensus::{encode, Decodable, Encodable},
    hash_types::FilterHeader,
};

use crate::error::{StorageError, StorageResult};
use crate::storage::{StorageManager, MasternodeState, StorageStats};
use crate::types::ChainState;

/// Disk-based storage manager.
pub struct DiskStorageManager {
    base_path: PathBuf,
    header_cache: Vec<BlockHeader>,
    filter_header_cache: Vec<FilterHeader>,
    cache_size: usize,
}

impl DiskStorageManager {
    /// Create a new disk storage manager.
    pub async fn new(base_path: PathBuf) -> StorageResult<Self> {
        // Create directories if they don't exist
        fs::create_dir_all(&base_path)
            .map_err(|e| StorageError::WriteFailed(format!("Failed to create directory: {}", e)))?;
        
        let headers_dir = base_path.join("headers");
        let filters_dir = base_path.join("filters");
        let state_dir = base_path.join("state");
        
        fs::create_dir_all(&headers_dir)?;
        fs::create_dir_all(&filters_dir)?;
        fs::create_dir_all(&state_dir)?;
        
        let mut storage = Self {
            base_path,
            header_cache: Vec::new(),
            filter_header_cache: Vec::new(),
            cache_size: 10000,
        };
        
        // Load existing data into cache
        storage.load_cache().await?;
        
        Ok(storage)
    }
    
    /// Load data into cache.
    async fn load_cache(&mut self) -> StorageResult<()> {
        // Load headers
        let headers_path = self.base_path.join("headers/headers.dat");
        if headers_path.exists() {
            self.header_cache = self.load_headers_from_file(&headers_path).await?;
        }
        
        // Load filter headers
        let filter_headers_path = self.base_path.join("headers/filter_headers.dat");
        if filter_headers_path.exists() {
            self.filter_header_cache = self.load_filter_headers_from_file(&filter_headers_path).await?;
        }
        
        Ok(())
    }
    
    /// Save cache to disk.
    async fn save_cache(&self) -> StorageResult<()> {
        // Save headers
        let headers_path = self.base_path.join("headers/headers.dat");
        self.save_headers_to_file(&self.header_cache, &headers_path).await?;
        
        // Save filter headers
        let filter_headers_path = self.base_path.join("headers/filter_headers.dat");
        self.save_filter_headers_to_file(&self.filter_header_cache, &filter_headers_path).await?;
        
        Ok(())
    }
    
    /// Load headers from file.
    async fn load_headers_from_file(&self, path: &Path) -> StorageResult<Vec<BlockHeader>> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let mut headers = Vec::new();
        
        loop {
            match BlockHeader::consensus_decode(&mut reader) {
                Ok(header) => headers.push(header),
                Err(encode::Error::Io(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(StorageError::ReadFailed(format!("Failed to decode header: {}", e))),
            }
        }
        
        Ok(headers)
    }
    
    /// Save headers to file.
    async fn save_headers_to_file(&self, headers: &[BlockHeader], path: &Path) -> StorageResult<()> {
        let file = OpenOptions::new().create(true).write(true).truncate(true).open(path)?;
        let mut writer = BufWriter::new(file);
        
        for header in headers {
            header.consensus_encode(&mut writer)
                .map_err(|e| StorageError::WriteFailed(format!("Failed to encode header: {}", e)))?;
        }
        
        writer.flush()?;
        Ok(())
    }
    
    /// Load filter headers from file.
    async fn load_filter_headers_from_file(&self, path: &Path) -> StorageResult<Vec<FilterHeader>> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let mut headers = Vec::new();
        
        loop {
            match FilterHeader::consensus_decode(&mut reader) {
                Ok(header) => headers.push(header),
                Err(encode::Error::Io(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(StorageError::ReadFailed(format!("Failed to decode filter header: {}", e))),
            }
        }
        
        Ok(headers)
    }
    
    /// Save filter headers to file.
    async fn save_filter_headers_to_file(&self, headers: &[FilterHeader], path: &Path) -> StorageResult<()> {
        let file = OpenOptions::new().create(true).write(true).truncate(true).open(path)?;
        let mut writer = BufWriter::new(file);
        
        for header in headers {
            header.consensus_encode(&mut writer)
                .map_err(|e| StorageError::WriteFailed(format!("Failed to encode filter header: {}", e)))?;
        }
        
        writer.flush()?;
        Ok(())
    }
}

#[async_trait]
impl StorageManager for DiskStorageManager {
    async fn store_headers(&mut self, headers: &[BlockHeader]) -> StorageResult<()> {
        self.header_cache.extend_from_slice(headers);
        
        // Save to disk if cache is getting large
        if self.header_cache.len() % 1000 == 0 {
            self.save_cache().await?;
        }
        
        Ok(())
    }
    
    async fn load_headers(&self, range: Range<u32>) -> StorageResult<Vec<BlockHeader>> {
        let start = range.start as usize;
        let end = range.end.min(self.header_cache.len() as u32) as usize;
        
        if start > self.header_cache.len() {
            return Ok(Vec::new());
        }
        
        Ok(self.header_cache[start..end].to_vec())
    }
    
    async fn get_header(&self, height: u32) -> StorageResult<Option<BlockHeader>> {
        Ok(self.header_cache.get(height as usize).copied())
    }
    
    async fn get_tip_height(&self) -> StorageResult<Option<u32>> {
        if self.header_cache.is_empty() {
            Ok(None)
        } else {
            Ok(Some(self.header_cache.len() as u32 - 1))
        }
    }
    
    async fn store_filter_headers(&mut self, headers: &[FilterHeader]) -> StorageResult<()> {
        self.filter_header_cache.extend_from_slice(headers);
        
        // Save to disk if cache is getting large
        if self.filter_header_cache.len() % 1000 == 0 {
            self.save_cache().await?;
        }
        
        Ok(())
    }
    
    async fn load_filter_headers(&self, range: Range<u32>) -> StorageResult<Vec<FilterHeader>> {
        let start = range.start as usize;
        let end = range.end.min(self.filter_header_cache.len() as u32) as usize;
        
        if start > self.filter_header_cache.len() {
            return Ok(Vec::new());
        }
        
        Ok(self.filter_header_cache[start..end].to_vec())
    }
    
    async fn get_filter_header(&self, height: u32) -> StorageResult<Option<FilterHeader>> {
        Ok(self.filter_header_cache.get(height as usize).copied())
    }
    
    async fn get_filter_tip_height(&self) -> StorageResult<Option<u32>> {
        if self.filter_header_cache.is_empty() {
            Ok(None)
        } else {
            Ok(Some(self.filter_header_cache.len() as u32 - 1))
        }
    }
    
    async fn store_masternode_state(&mut self, state: &MasternodeState) -> StorageResult<()> {
        let path = self.base_path.join("state/masternode.json");
        let json = serde_json::to_string_pretty(state)
            .map_err(|e| StorageError::Serialization(format!("Failed to serialize masternode state: {}", e)))?;
        
        fs::write(path, json)?;
        Ok(())
    }
    
    async fn load_masternode_state(&self) -> StorageResult<Option<MasternodeState>> {
        let path = self.base_path.join("state/masternode.json");
        if !path.exists() {
            return Ok(None);
        }
        
        let content = fs::read_to_string(path)?;
        let state = serde_json::from_str(&content)
            .map_err(|e| StorageError::Serialization(format!("Failed to deserialize masternode state: {}", e)))?;
        
        Ok(Some(state))
    }
    
    async fn store_chain_state(&mut self, state: &ChainState) -> StorageResult<()> {
        // Store individual components
        self.header_cache = state.headers.clone();
        self.filter_header_cache = state.filter_headers.clone();
        
        self.save_cache().await?;
        
        // Store other state as JSON
        let state_data = serde_json::json!({
            "chainlock_tip": state.chainlock_tip,
            "current_filter_tip": state.current_filter_tip,
            "last_masternode_diff_height": state.last_masternode_diff_height,
        });
        
        let path = self.base_path.join("state/chain.json");
        fs::write(path, state_data.to_string())?;
        
        Ok(())
    }
    
    async fn load_chain_state(&self) -> StorageResult<Option<ChainState>> {
        let path = self.base_path.join("state/chain.json");
        if !path.exists() {
            return Ok(None);
        }
        
        let content = fs::read_to_string(path)?;
        let value: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| StorageError::Serialization(format!("Failed to parse chain state: {}", e)))?;
        
        let mut state = ChainState::default();
        state.headers = self.header_cache.clone();
        state.filter_headers = self.filter_header_cache.clone();
        state.chainlock_tip = value.get("chainlock_tip").and_then(|v| v.as_str()).and_then(|s| s.parse().ok());
        state.current_filter_tip = value.get("current_filter_tip").and_then(|v| v.as_str()).and_then(|s| s.parse().ok());
        state.last_masternode_diff_height = value.get("last_masternode_diff_height").and_then(|v| v.as_u64()).map(|h| h as u32);
        
        Ok(Some(state))
    }
    
    async fn store_filter(&mut self, height: u32, filter: &[u8]) -> StorageResult<()> {
        let path = self.base_path.join(format!("filters/{}.dat", height));
        fs::write(path, filter)?;
        Ok(())
    }
    
    async fn load_filter(&self, height: u32) -> StorageResult<Option<Vec<u8>>> {
        let path = self.base_path.join(format!("filters/{}.dat", height));
        if !path.exists() {
            return Ok(None);
        }
        
        let data = fs::read(path)?;
        Ok(Some(data))
    }
    
    async fn store_metadata(&mut self, key: &str, value: &[u8]) -> StorageResult<()> {
        let path = self.base_path.join(format!("state/{}.dat", key));
        fs::write(path, value)?;
        Ok(())
    }
    
    async fn load_metadata(&self, key: &str) -> StorageResult<Option<Vec<u8>>> {
        let path = self.base_path.join(format!("state/{}.dat", key));
        if !path.exists() {
            return Ok(None);
        }
        
        let data = fs::read(path)?;
        Ok(Some(data))
    }
    
    async fn clear(&mut self) -> StorageResult<()> {
        self.header_cache.clear();
        self.filter_header_cache.clear();
        
        // Remove all files
        if self.base_path.exists() {
            fs::remove_dir_all(&self.base_path)?;
            fs::create_dir_all(&self.base_path)?;
        }
        
        Ok(())
    }
    
    async fn stats(&self) -> StorageResult<StorageStats> {
        let mut component_sizes = HashMap::new();
        let mut total_size = 0u64;
        
        // Calculate directory sizes
        if let Ok(entries) = fs::read_dir(&self.base_path) {
            for entry in entries.flatten() {
                if let Ok(metadata) = entry.metadata() {
                    if metadata.is_file() {
                        total_size += metadata.len();
                    }
                }
            }
        }
        
        component_sizes.insert("headers".to_string(), self.header_cache.len() as u64 * 80); // Approximate
        component_sizes.insert("filter_headers".to_string(), self.filter_header_cache.len() as u64 * 32);
        
        Ok(StorageStats {
            header_count: self.header_cache.len() as u64,
            filter_header_count: self.filter_header_cache.len() as u64,
            filter_count: 0, // TODO: Count filter files
            total_size,
            component_sizes,
        })
    }
}