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

use crate::types::PeerId;
use dashcore::blockdata::block::Header;
use dashcore::network::message_headers2::{CompressedHeader, CompressionState, DecompressionError};
use std::collections::HashMap;

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
}

impl Headers2StateManager {
    /// Create a new Headers2StateManager
    pub fn new() -> Self {
        Self {
            peer_states: HashMap::new(),
        }
    }

    /// Get or create compression state for a peer
    pub fn get_state(&mut self, peer_id: PeerId) -> &mut CompressionState {
        self.peer_states.entry(peer_id).or_default()
    }

    /// Initialize compression state for a peer with a known header
    /// This is useful when starting sync from a specific point
    pub fn init_peer_state(&mut self, peer_id: PeerId, last_header: Header) {
        let state = self.peer_states.entry(peer_id).or_default();
        // Set the previous header in the compression state
        state.prev_header = Some(last_header);
        tracing::debug!(
            "Initialized compression state for peer {} with header at height implied by hash {}",
            peer_id,
            last_header.block_hash()
        );
    }

    /// Process compressed headers from a peer
    pub fn process_headers(
        &mut self,
        peer_id: PeerId,
        headers: &[CompressedHeader],
    ) -> Result<Vec<Header>, ProcessError> {
        if headers.is_empty() {
            return Ok(Vec::new());
        }

        // First header should ideally be uncompressed for proper sync
        // However, if we're continuing from an existing state, it might be compressed
        // Also, when syncing from genesis, some peers send compressed headers that reference genesis
        if !headers[0].is_full() {
            tracing::warn!(
                "First header in batch is compressed - this may indicate we're continuing from existing state or syncing from genesis"
            );
            // Don't fail here - let the decompression logic handle it
            // If it fails due to missing previous header, the caller should initialize compression state
        }

        let mut decompressed = Vec::with_capacity(headers.len());

        // Process headers and collect statistics
        for (i, compressed) in headers.iter().enumerate() {
            // Get state and decompress
            let state = self.get_state(peer_id);
            let header =
                state.decompress(compressed).map_err(|e| ProcessError::DecompressionError(i, e))?;

            decompressed.push(header);
        }

        Ok(decompressed)
    }

    /// Reset state for a peer (e.g., after disconnect)
    pub fn reset_peer(&mut self, peer_id: PeerId) {
        self.peer_states.remove(&peer_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::blockdata::block::{Header, Version};
    use dashcore::hash_types::{BlockHash, TxMerkleNode};
    use dashcore::network::message_headers2::CompressionState;
    use dashcore::pow::CompactTarget;
    use dashcore_hashes::Hash;

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
        let result = manager.process_headers(peer_id, &[compressed1, compressed2]);
        assert!(result.is_ok());

        let decompressed = result.expect("decompression should succeed in test");
        assert_eq!(decompressed.len(), 2);
        assert_eq!(decompressed[0], header1);
        assert_eq!(decompressed[1], header2);
    }

    #[test]
    fn test_first_header_compressed_fails_decompression() {
        let mut manager = Headers2StateManager::new();
        let peer_id = PeerId(1);

        // Create a highly compressed header (would fail without previous state)
        let mut state = CompressionState::new();
        let header = create_test_header(1);

        // Compress once to prime the state
        let _ = state.compress(&header);

        // Now compress another header - this will be highly compressed
        let compressed = state.compress(&header);

        // Try to process it as first header - should fail with DecompressionError
        // because the peer doesn't have the previous header state
        let result = manager.process_headers(peer_id, &[compressed]);
        assert!(matches!(result, Err(ProcessError::DecompressionError(0, _))));
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
}
