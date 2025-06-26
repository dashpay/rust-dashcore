// Rust Dash Library
// Written for Dash in 2025 by
//     The Dash Core Developers
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Headers2 state management for compressed header synchronization.
//!
//! This module manages compression state for each peer and provides
//! statistics about header compression efficiency.

use dashcore::blockdata::block::Header;
use dashcore::network::message_headers2::{CompressedHeader, CompressionState, DecompressionError};
use std::collections::HashMap;
use crate::types::PeerId;

/// Size of an uncompressed block header in bytes
const UNCOMPRESSED_HEADER_SIZE: usize = 80;

/// Error types for headers2 processing
#[derive(Debug, Clone)]
pub enum ProcessError {
    /// First header in a batch must be uncompressed
    FirstHeaderNotFull,
    /// Decompression failed for a specific header
    DecompressionError(usize, DecompressionError),
}

impl std::fmt::Display for ProcessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProcessError::FirstHeaderNotFull => {
                write!(f, "first header in batch must be uncompressed")
            }
            ProcessError::DecompressionError(index, err) => {
                write!(f, "decompression error at header {}: {}", index, err)
            }
        }
    }
}

impl std::error::Error for ProcessError {}

/// Manages compression state for each peer
#[derive(Debug, Default)]
pub struct Headers2StateManager {
    /// Compression state per peer
    peer_states: HashMap<PeerId, CompressionState>,
    
    /// Statistics
    pub total_headers_received: u64,
    pub compressed_headers_received: u64,
    pub bytes_saved: u64,
    pub total_bytes_received: u64,
}

impl Headers2StateManager {
    /// Create a new Headers2StateManager
    pub fn new() -> Self {
        Self {
            peer_states: HashMap::new(),
            total_headers_received: 0,
            compressed_headers_received: 0,
            bytes_saved: 0,
            total_bytes_received: 0,
        }
    }
    
    /// Get or create compression state for a peer
    pub fn get_state(&mut self, peer_id: PeerId) -> &mut CompressionState {
        self.peer_states.entry(peer_id).or_insert_with(CompressionState::new)
    }
    
    /// Process compressed headers from a peer
    pub fn process_headers(&mut self, peer_id: PeerId, headers: Vec<CompressedHeader>) -> Result<Vec<Header>, ProcessError> {
        if headers.is_empty() {
            return Ok(Vec::new());
        }
        
        // First header must be uncompressed for proper sync
        if !headers[0].is_full() {
            return Err(ProcessError::FirstHeaderNotFull);
        }
        
        let mut decompressed = Vec::with_capacity(headers.len());
        
        // Process headers and collect statistics
        for (i, compressed) in headers.into_iter().enumerate() {
            // Update statistics
            self.total_headers_received += 1;
            self.total_bytes_received += compressed.encoded_size() as u64;
            
            if compressed.is_compressed() {
                self.compressed_headers_received += 1;
                self.bytes_saved += compressed.bytes_saved() as u64;
            }
            
            // Get state and decompress
            let state = self.get_state(peer_id);
            let header = state.decompress(&compressed)
                .map_err(|e| ProcessError::DecompressionError(i, e))?;
            
            decompressed.push(header);
        }
        
        Ok(decompressed)
    }
    
    /// Reset state for a peer (e.g., after disconnect)
    pub fn reset_peer(&mut self, peer_id: PeerId) {
        self.peer_states.remove(&peer_id);
    }
    
    /// Get compression ratio
    pub fn compression_ratio(&self) -> f64 {
        if self.total_headers_received == 0 {
            0.0
        } else {
            self.compressed_headers_received as f64 / self.total_headers_received as f64
        }
    }
    
    /// Get bandwidth savings percentage
    pub fn bandwidth_savings(&self) -> f64 {
        if self.total_bytes_received == 0 {
            0.0
        } else {
            let uncompressed_size = self.total_headers_received * UNCOMPRESSED_HEADER_SIZE;
            let savings = (uncompressed_size - self.total_bytes_received) as f64;
            (savings / uncompressed_size as f64) * 100.0
        }
    }
    
    /// Get detailed statistics
    pub fn get_stats(&self) -> Headers2Stats {
        Headers2Stats {
            total_headers: self.total_headers_received,
            compressed_headers: self.compressed_headers_received,
            bytes_saved: self.bytes_saved,
            total_bytes_received: self.total_bytes_received,
            compression_ratio: self.compression_ratio(),
            bandwidth_savings: self.bandwidth_savings(),
            active_peers: self.peer_states.len(),
        }
    }
}

/// Statistics about headers2 compression
#[derive(Debug, Clone)]
pub struct Headers2Stats {
    /// Total number of headers received
    pub total_headers: u64,
    /// Number of headers that were compressed
    pub compressed_headers: u64,
    /// Bytes saved through compression
    pub bytes_saved: u64,
    /// Total bytes received (compressed)
    pub total_bytes_received: u64,
    /// Ratio of compressed to total headers
    pub compression_ratio: f64,
    /// Bandwidth savings percentage
    pub bandwidth_savings: f64,
    /// Number of peers with active compression state
    pub active_peers: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::blockdata::block::{Header, Version};
    use dashcore::hash_types::{BlockHash, TxMerkleNode};
    use dashcore::network::message_headers2::CompressionState;
    use dashcore::pow::CompactTarget;
    
    fn create_test_header(nonce: u32) -> Header {
        Header {
            version: Version::from_consensus(0x20000000),
            prev_blockhash: BlockHash::from_byte_array([0u8; 32]),
            merkle_root: TxMerkleNode::from_byte_array([1u8; 32]),
            time: 1234567890 + nonce,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce,
        }
    }
    
    #[test]
    fn test_headers2_state_manager() {
        let mut manager = Headers2StateManager::new();
        let peer_id = PeerId(1);
        
        // Create a compression state and compress some headers
        let mut compress_state = CompressionState::new();
        let header1 = create_test_header(1);
        let header2 = create_test_header(2);
        
        let compressed1 = compress_state.compress(&header1);
        let compressed2 = compress_state.compress(&header2);
        
        // Process headers
        let result = manager.process_headers(peer_id, vec![compressed1, compressed2]);
        assert!(result.is_ok());
        
        let decompressed = result.unwrap();
        assert_eq!(decompressed.len(), 2);
        assert_eq!(decompressed[0], header1);
        assert_eq!(decompressed[1], header2);
        
        // Check statistics
        assert_eq!(manager.total_headers_received, 2);
        assert!(manager.compressed_headers_received > 0);
        assert!(manager.bytes_saved > 0);
    }
    
    #[test]
    fn test_first_header_must_be_full() {
        let mut manager = Headers2StateManager::new();
        let peer_id = PeerId(1);
        
        // Create a highly compressed header (would fail without previous state)
        let mut state = CompressionState::new();
        let header = create_test_header(1);
        
        // Compress once to prime the state
        let _ = state.compress(&header);
        
        // Now compress another header - this will be highly compressed
        let compressed = state.compress(&header);
        
        // Try to process it as first header - should fail
        let result = manager.process_headers(peer_id, vec![compressed]);
        assert!(matches!(result, Err(ProcessError::FirstHeaderNotFull)));
    }
    
    #[test]
    fn test_peer_reset() {
        let mut manager = Headers2StateManager::new();
        let peer_id = PeerId(1);
        
        // Add some state
        let _state = manager.get_state(peer_id);
        assert_eq!(manager.peer_states.len(), 1);
        
        // Reset peer
        manager.reset_peer(peer_id);
        assert_eq!(manager.peer_states.len(), 0);
    }
    
    #[test]
    fn test_statistics() {
        let mut manager = Headers2StateManager::new();
        let stats = manager.get_stats();
        
        assert_eq!(stats.total_headers, 0);
        assert_eq!(stats.compression_ratio, 0.0);
        assert_eq!(stats.bandwidth_savings, 0.0);
        assert_eq!(stats.active_peers, 0);
    }
}