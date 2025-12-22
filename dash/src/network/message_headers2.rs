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

//! Headers2 compressed block header protocol support (DIP-0025).
//!
//! This module implements the compressed block header protocol as specified in DIP-0025,
//! which reduces bandwidth usage for header synchronization by compressing headers
//! from 80 bytes to as low as 37 bytes through stateful compression techniques.

use crate::blockdata::block::{Header, Version};
use crate::consensus::{Decodable, Encodable};
use crate::hash_types::{BlockHash, TxMerkleNode};
use crate::pow::CompactTarget;
use crate::{VarInt, io};
use core::fmt;

/// Bitfield flags for compressed header
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressionFlags(pub u8);

impl CompressionFlags {
    /// Mask for version offset bits (bits 0-2)
    pub const VERSION_BITS_MASK: u8 = 0b00000111;
    /// Flag indicating previous block hash is included
    pub const PREV_BLOCK_HASH: u8 = 0b00001000;
    /// Flag indicating full timestamp is included (vs 2-byte offset)
    pub const TIMESTAMP: u8 = 0b00010000;
    /// Flag indicating nBits field is included
    pub const NBITS: u8 = 0b00100000;

    /// Get the version offset from the flags (0-7)
    pub fn version_offset(&self) -> u8 {
        self.0 & Self::VERSION_BITS_MASK
    }

    /// Check if previous block hash is included
    pub fn has_prev_block_hash(&self) -> bool {
        (self.0 & Self::PREV_BLOCK_HASH) != 0
    }

    /// Check if full timestamp is included
    pub fn has_full_timestamp(&self) -> bool {
        (self.0 & Self::TIMESTAMP) != 0
    }

    /// Check if nBits field is included
    pub fn has_nbits(&self) -> bool {
        (self.0 & Self::NBITS) != 0
    }
}

impl Encodable for CompressionFlags {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }
}

impl Decodable for CompressionFlags {
    fn consensus_decode<R: io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, crate::consensus::encode::Error> {
        Ok(CompressionFlags(u8::consensus_decode(r)?))
    }
}

/// Compressed representation of a block header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressedHeader {
    /// Compression flags indicating which fields are present
    pub flags: CompressionFlags,
    /// Version if not found in cache (when version_offset == 7)
    pub version: Option<i32>,
    /// Previous block hash if not sequential
    pub prev_blockhash: Option<BlockHash>,
    /// Merkle root (always present)
    pub merkle_root: TxMerkleNode,
    /// Time offset from previous block (if not using full timestamp)
    pub time_offset: Option<i16>,
    /// Full timestamp (if offset would overflow)
    pub time_full: Option<u32>,
    /// nBits difficulty target (if different from previous)
    pub bits: Option<CompactTarget>,
    /// Nonce (always present)
    pub nonce: u32,
}

impl CompressedHeader {
    /// Check if this is a full (uncompressed) header
    pub fn is_full(&self) -> bool {
        self.flags.has_prev_block_hash()
            && self.flags.has_full_timestamp()
            && self.flags.has_nbits()
    }

    /// Check if any compression is applied
    pub fn is_compressed(&self) -> bool {
        !self.is_full()
    }

    /// Estimate bytes saved by compression
    pub fn bytes_saved(&self) -> usize {
        let mut saved = 0;

        // Version: 4 bytes saved if cached (minus 1 byte if version_offset == 7)
        if self.version.is_none() {
            saved += 4;
        }

        // Previous block hash: 32 bytes saved if sequential
        if self.prev_blockhash.is_none() {
            saved += 32;
        }

        // Timestamp: 2 bytes saved if using offset
        if self.time_offset.is_some() {
            saved += 2;
        }

        // nBits: 4 bytes saved if unchanged
        if self.bits.is_none() {
            saved += 4;
        }

        saved
    }

    /// Get the encoded size of this compressed header
    pub fn encoded_size(&self) -> usize {
        let mut size = 1; // flags byte

        if self.version.is_some() {
            size += 4;
        }

        if self.prev_blockhash.is_some() {
            size += 32;
        }

        size += 32; // merkle_root

        if self.time_offset.is_some() {
            size += 2;
        } else if self.time_full.is_some() {
            size += 4;
        }

        if self.bits.is_some() {
            size += 4;
        }

        size += 4; // nonce

        size
    }
}

impl Encodable for CompressedHeader {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;

        // Encode flags
        len += self.flags.consensus_encode(w)?;

        // Encode version if present
        if let Some(v) = self.version {
            len += v.consensus_encode(w)?;
        }

        // Encode prev_blockhash if present
        if let Some(hash) = self.prev_blockhash {
            len += hash.consensus_encode(w)?;
        }

        // Always encode merkle root
        len += self.merkle_root.consensus_encode(w)?;

        // Encode time
        if let Some(offset) = self.time_offset {
            len += offset.consensus_encode(w)?;
        } else if let Some(time) = self.time_full {
            len += time.consensus_encode(w)?;
        }

        // Encode bits if present
        if let Some(bits) = self.bits {
            len += bits.consensus_encode(w)?;
        }

        // Always encode nonce
        len += self.nonce.consensus_encode(w)?;

        Ok(len)
    }
}

impl Decodable for CompressedHeader {
    fn consensus_decode<R: io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, crate::consensus::encode::Error> {
        let flags = CompressionFlags::consensus_decode(r)?;

        // C++ semantics: offset=0 means version IS present (not in cache)
        // offset=1-7 means version is in cache at position (offset-1)
        let version = if flags.version_offset() == 0 {
            Some(i32::consensus_decode(r)?)
        } else {
            None
        };

        let prev_blockhash = if flags.has_prev_block_hash() {
            Some(BlockHash::consensus_decode(r)?)
        } else {
            None
        };

        let merkle_root = TxMerkleNode::consensus_decode(r)?;

        let (time_offset, time_full) = if flags.has_full_timestamp() {
            (None, Some(u32::consensus_decode(r)?))
        } else {
            (Some(i16::consensus_decode(r)?), None)
        };

        let bits = if flags.has_nbits() {
            Some(CompactTarget::consensus_decode(r)?)
        } else {
            None
        };

        let nonce = u32::consensus_decode(r)?;

        Ok(CompressedHeader {
            flags,
            version,
            prev_blockhash,
            merkle_root,
            time_offset,
            time_full,
            bits,
            nonce,
        })
    }
}

/// Maximum number of unique versions to cache (matches C++ implementation)
const MAX_VERSION_CACHE_SIZE: usize = 7;

/// State required for compression/decompression.
///
/// This implementation matches the C++ Dash Core reference implementation:
/// - Uses a list with MRU (Most Recently Used) ordering
/// - Front of list = most recently used version
/// - Version offset encoding: 0 = not in cache (full version present), 1-7 = position + 1
#[derive(Debug, Clone)]
pub struct CompressionState {
    /// Last 7 unique versions seen (front = most recently used)
    /// Matches C++ std::list<int32_t> with MRU reordering
    pub version_cache: Vec<i32>,
    /// Previous header for delta encoding
    pub prev_header: Option<Header>,
}

impl CompressionState {
    /// Create a new compression state
    pub fn new() -> Self {
        Self {
            version_cache: Vec::with_capacity(MAX_VERSION_CACHE_SIZE),
            prev_header: None,
        }
    }

    /// Compress a header given the current state.
    ///
    /// Version offset encoding (matching C++ DIP-0025):
    /// - offset = 0: version NOT in cache, full version field IS present
    /// - offset = 1-7: version found at position (offset-1) in cache, no version field
    pub fn compress(&mut self, header: &Header) -> CompressedHeader {
        let mut flags = CompressionFlags(0);

        // Version compression (C++ semantics)
        let version_i32 = header.version.to_consensus();
        let version = if let Some(position) = self.find_version_position(version_i32) {
            // Version found in cache at `position` (0-indexed)
            // C++ uses 1-indexed offset: offset = position + 1
            flags.0 |= (position + 1) as u8;
            // Move to front (MRU)
            self.mark_version_as_mru(position);
            None
        } else {
            // Version NOT in cache, offset = 0 means "uncompressed"
            // flags.0 |= 0; // no-op, explicit for clarity
            self.save_version_as_mru(version_i32);
            Some(version_i32)
        };

        // Previous block hash compression
        let prev_blockhash = if self.is_sequential(&header.prev_blockhash) {
            None
        } else {
            flags.0 |= CompressionFlags::PREV_BLOCK_HASH;
            Some(header.prev_blockhash)
        };

        // Timestamp compression
        let (time_offset, time_full) = if let Some(prev) = &self.prev_header {
            let delta = header.time as i64 - prev.time as i64;
            if delta >= i16::MIN as i64 && delta <= i16::MAX as i64 {
                (Some(delta as i16), None)
            } else {
                flags.0 |= CompressionFlags::TIMESTAMP;
                (None, Some(header.time))
            }
        } else {
            // First header, include full timestamp
            flags.0 |= CompressionFlags::TIMESTAMP;
            (None, Some(header.time))
        };

        // nBits compression
        let bits = if let Some(prev) = &self.prev_header {
            if prev.bits == header.bits {
                None
            } else {
                flags.0 |= CompressionFlags::NBITS;
                Some(header.bits)
            }
        } else {
            // First header, include nBits
            flags.0 |= CompressionFlags::NBITS;
            Some(header.bits)
        };

        self.prev_header = Some(*header);

        CompressedHeader {
            flags,
            version,
            prev_blockhash,
            merkle_root: header.merkle_root,
            time_offset,
            time_full,
            bits,
            nonce: header.nonce,
        }
    }

    /// Decompress a header given the current state.
    ///
    /// Version offset decoding (matching C++ DIP-0025):
    /// - offset = 0: version NOT in cache, read full version from message
    /// - offset = 1-7: version at position (offset-1) in cache
    pub fn decompress(
        &mut self,
        compressed: &CompressedHeader,
    ) -> Result<Header, DecompressionError> {
        // Version (C++ semantics)
        let version = match compressed.flags.version_offset() {
            0 => {
                // Offset 0 means NOT in cache, full version should be present
                let v = compressed.version.ok_or(DecompressionError::MissingVersion)?;
                self.save_version_as_mru(v);
                v
            }
            offset @ 1..=7 => {
                // Offset 1-7 means position 0-6 in cache (1-indexed)
                let position = (offset - 1) as usize;
                let v = self.get_version_at(position)?;
                self.mark_version_as_mru(position);
                v
            }
            _ => return Err(DecompressionError::InvalidVersionOffset),
        };

        // Previous block hash
        let prev_blockhash = if let Some(hash) = compressed.prev_blockhash {
            hash
        } else {
            self.prev_header.as_ref().ok_or(DecompressionError::MissingPreviousHeader)?.block_hash()
        };

        // Timestamp
        let time = if let Some(offset) = compressed.time_offset {
            let prev_time =
                self.prev_header.as_ref().ok_or(DecompressionError::MissingPreviousHeader)?.time;
            (prev_time as i64 + offset as i64) as u32
        } else {
            compressed.time_full.ok_or(DecompressionError::MissingTimestamp)?
        };

        // nBits
        let bits = if let Some(b) = compressed.bits {
            b
        } else {
            self.prev_header.as_ref().ok_or(DecompressionError::MissingPreviousHeader)?.bits
        };

        let header = Header {
            version: Version::from_consensus(version),
            prev_blockhash,
            merkle_root: compressed.merkle_root,
            time,
            bits,
            nonce: compressed.nonce,
        };

        self.prev_header = Some(header);

        Ok(header)
    }

    /// Find the position of a version in the cache (0-indexed).
    /// Returns None if not found.
    fn find_version_position(&self, version: i32) -> Option<usize> {
        self.version_cache.iter().position(|&v| v == version)
    }

    /// Get version at a specific position in the cache.
    fn get_version_at(&self, position: usize) -> Result<i32, DecompressionError> {
        self.version_cache.get(position).copied().ok_or(DecompressionError::InvalidVersionOffset)
    }

    /// Move a version at the given position to the front (MRU).
    /// Matches C++ MarkVersionAsMostRecent behavior.
    fn mark_version_as_mru(&mut self, position: usize) {
        if position > 0 && position < self.version_cache.len() {
            let version = self.version_cache.remove(position);
            self.version_cache.insert(0, version);
        }
    }

    /// Save a new version as the most recently used.
    /// Matches C++ SaveVersionAsMostRecent behavior.
    fn save_version_as_mru(&mut self, version: i32) {
        self.version_cache.insert(0, version);
        if self.version_cache.len() > MAX_VERSION_CACHE_SIZE {
            self.version_cache.pop();
        }
    }

    /// Check if the given hash matches the hash of the previous header
    fn is_sequential(&self, prev_hash: &BlockHash) -> bool {
        if let Some(prev) = &self.prev_header {
            prev.block_hash() == *prev_hash
        } else {
            false
        }
    }

    /// Reset the compression state
    pub fn reset(&mut self) {
        self.version_cache.clear();
        self.prev_header = None;
    }
}

impl Default for CompressionState {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors that can occur during decompression
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecompressionError {
    /// Version offset is invalid (must be 0-7)
    InvalidVersionOffset,
    /// Previous header required but not available
    MissingPreviousHeader,
    /// Timestamp required but not provided
    MissingTimestamp,
    /// Version field expected but not present (offset=0 but no version in message)
    MissingVersion,
}

impl fmt::Display for DecompressionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DecompressionError::InvalidVersionOffset => {
                write!(f, "invalid version offset in compressed header")
            }
            DecompressionError::MissingPreviousHeader => {
                write!(f, "previous header required for decompression")
            }
            DecompressionError::MissingTimestamp => {
                write!(f, "timestamp missing in compressed header")
            }
            DecompressionError::MissingVersion => {
                write!(f, "version field expected but not present in compressed header")
            }
        }
    }
}

impl std::error::Error for DecompressionError {}

/// Headers2 message containing compressed headers
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Headers2Message {
    /// Vector of compressed headers
    pub headers: Vec<CompressedHeader>,
}

impl Headers2Message {
    /// Create a new Headers2 message
    pub fn new(headers: Vec<CompressedHeader>) -> Self {
        Self {
            headers,
        }
    }
}

impl Encodable for Headers2Message {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += VarInt(self.headers.len() as u64).consensus_encode(w)?;
        for header in &self.headers {
            len += header.consensus_encode(w)?;
        }
        Ok(len)
    }
}

impl Decodable for Headers2Message {
    fn consensus_decode<R: io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, crate::consensus::encode::Error> {
        let count = VarInt::consensus_decode(r)?.0;
        let mut headers = Vec::with_capacity(count as usize);
        for _ in 0..count {
            headers.push(CompressedHeader::consensus_decode(r)?);
        }
        Ok(Headers2Message {
            headers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashes::Hash;

    fn create_test_header(nonce: u32, prev_nonce: u32) -> Header {
        let mut prev_hash = [0u8; 32];
        prev_hash[0] = prev_nonce as u8;

        Header {
            version: Version::from_consensus(0x20000000),
            prev_blockhash: BlockHash::from_byte_array(prev_hash),
            merkle_root: TxMerkleNode::from_byte_array([1u8; 32]),
            time: 1234567890 + nonce,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce,
        }
    }

    // fn create_header_with_version(version: i32) -> Header {
    //     Header {
    //         version: Version::from_consensus(version),
    //         prev_blockhash: BlockHash::from_byte_array([0u8; 32]),
    //         merkle_root: TxMerkleNode::from_byte_array([1u8; 32]),
    //         time: 1234567890,
    //         bits: CompactTarget::from_consensus(0x1d00ffff),
    //         nonce: 1,
    //     }
    // }

    fn create_test_chain(count: usize) -> Vec<Header> {
        let mut headers: Vec<Header> = Vec::with_capacity(count);
        for i in 0..count {
            let prev_hash = if i == 0 {
                BlockHash::from_byte_array([0u8; 32])
            } else {
                headers[i - 1].block_hash()
            };
            headers.push(Header {
                version: Version::from_consensus(0x20000000),
                prev_blockhash: prev_hash,
                merkle_root: TxMerkleNode::from_byte_array([1u8; 32]),
                time: 1234567890 + i as u32,
                bits: CompactTarget::from_consensus(0x1d00ffff),
                nonce: i as u32,
            });
        }
        headers
    }

    #[test]
    fn test_compression_flags() {
        let flags = CompressionFlags(0b00101011);
        assert_eq!(flags.version_offset(), 3);
        assert!(flags.has_prev_block_hash());
        assert!(!flags.has_full_timestamp());
        assert!(flags.has_nbits());
    }

    #[test]
    fn test_version_cache() {
        let mut state = CompressionState::new();

        // Add versions using save_version_as_mru (simulating uncompressed versions)
        // This matches C++ behavior where new versions are added to the front
        for i in 1..=10 {
            state.save_version_as_mru(i);
        }

        // Cache should contain [10, 9, 8, 7, 6, 5, 4] (front = most recent)
        // Version 4 should be at position 6 (last valid position)
        assert_eq!(state.find_version_position(4), Some(6));

        // Version 3 should not be in cache (evicted)
        assert_eq!(state.find_version_position(3), None);

        // Version 10 should be at position 0 (most recent)
        assert_eq!(state.find_version_position(10), Some(0));
    }

    #[test]
    fn test_compression_sequential_headers() {
        let mut state = CompressionState::new();

        // Create sequential headers
        let header1 = create_test_header(1, 0);
        let header2 = create_test_header(2, 1);

        let compressed1 = state.compress(&header1);

        // Update header2 to have correct previous hash
        let mut header2 = header2;
        header2.prev_blockhash = header1.block_hash();

        let compressed2 = state.compress(&header2);

        // First header should be mostly uncompressed
        assert!(compressed1.version.is_some());
        assert!(compressed1.prev_blockhash.is_some());
        assert!(compressed1.time_full.is_some());
        assert!(compressed1.bits.is_some());

        // Second header should be highly compressed
        assert!(compressed2.version.is_none()); // Same version
        assert!(compressed2.prev_blockhash.is_none()); // Sequential
        assert!(compressed2.time_offset.is_some()); // Time delta
        assert!(compressed2.bits.is_none()); // Same bits
    }

    #[test]
    fn test_headers2_message_serialization() {
        use crate::consensus::encode::{deserialize, serialize};

        let mut state = CompressionState::new();
        let headers = create_test_chain(10);

        // Compress headers
        let mut compressed_headers = Vec::new();
        for header in &headers {
            compressed_headers.push(state.compress(header));
        }

        // Create Headers2Message
        let msg = Headers2Message {
            headers: compressed_headers,
        };

        // Serialize
        let serialized = serialize(&msg);

        // Deserialize
        let deserialized: Headers2Message = deserialize(&serialized).unwrap();

        assert_eq!(msg.headers.len(), deserialized.headers.len());

        // Verify we can decompress
        let mut decompress_state = CompressionState::new();
        for (i, compressed) in deserialized.headers.iter().enumerate() {
            let decompressed = decompress_state.decompress(compressed).unwrap();
            assert_eq!(decompressed, headers[i]);
        }
    }

    #[test]
    fn test_decompression_roundtrip() {
        let mut compress_state = CompressionState::new();
        let mut decompress_state = CompressionState::new();

        let header = create_test_header(1, 0);

        let compressed = compress_state.compress(&header);
        let decompressed = decompress_state.decompress(&compressed).unwrap();

        assert_eq!(header, decompressed);
    }

    #[test]
    fn test_compression_state_reset() {
        let mut state = CompressionState::new();

        // Add some data
        state.save_version_as_mru(1);
        state.prev_header = Some(create_test_header(1, 0));

        // Reset
        state.reset();

        // Verify reset
        assert!(state.version_cache.is_empty());
        assert!(state.prev_header.is_none());
    }

    #[test]
    fn test_version_offset_cpp_semantics() {
        // Test that offset encoding matches C++ DIP-0025:
        // offset = 0: version NOT in cache (full version present)
        // offset = 1-7: version at position (offset-1) in cache

        let mut state = CompressionState::new();

        // First header - version not in cache, should use offset=0
        let header1 = create_test_header(1, 0);
        let compressed1 = state.compress(&header1);

        assert_eq!(
            compressed1.flags.version_offset(),
            0,
            "First header should have offset=0 (not in cache)"
        );
        assert!(compressed1.version.is_some(), "First header should include version field");

        // Second header - same version, now in cache at position 0
        // Should use offset = position + 1 = 1
        let mut header2 = create_test_header(2, 1);
        header2.prev_blockhash = header1.block_hash();
        header2.version = header1.version; // Same version
        let compressed2 = state.compress(&header2);

        assert_eq!(
            compressed2.flags.version_offset(),
            1,
            "Second header should have offset=1 (cache position 0)"
        );
        assert!(compressed2.version.is_none(), "Second header should not include version field");
    }

    #[test]
    fn test_mru_reordering() {
        // Test that using a cached version moves it to front (MRU behavior)
        let mut state = CompressionState::new();

        // Add 3 different versions
        state.save_version_as_mru(100);
        state.save_version_as_mru(200);
        state.save_version_as_mru(300);
        // Cache is now [300, 200, 100]

        assert_eq!(state.find_version_position(100), Some(2));
        assert_eq!(state.find_version_position(200), Some(1));
        assert_eq!(state.find_version_position(300), Some(0));

        // Mark version 100 as MRU (simulating it being used)
        state.mark_version_as_mru(2);
        // Cache should now be [100, 300, 200]

        assert_eq!(state.find_version_position(100), Some(0));
        assert_eq!(state.find_version_position(300), Some(1));
        assert_eq!(state.find_version_position(200), Some(2));
    }

    #[test]
    fn test_first_header_flags_cpp_compatible() {
        // Verify first header produces C++-compatible flags
        let mut state = CompressionState::new();
        let header = create_test_header(1, 0);
        let compressed = state.compress(&header);

        // C++ produces flags = 0b00111000 for first header:
        // - version_offset = 0 (bits 0-2)
        // - PREV_BLOCK_HASH = 1 (bit 3)
        // - TIMESTAMP = 1 (bit 4)
        // - NBITS = 1 (bit 5)
        let expected_flags = 0b00111000u8;
        assert_eq!(
            compressed.flags.0, expected_flags,
            "First header flags should match C++ format: expected 0b{:08b}, got 0b{:08b}",
            expected_flags, compressed.flags.0
        );
    }
}
