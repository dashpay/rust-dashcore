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

        if let Some(_) = self.version {
            size += 4;
        }

        if let Some(_) = self.prev_blockhash {
            size += 32;
        }

        size += 32; // merkle_root

        if let Some(_) = self.time_offset {
            size += 2;
        } else if let Some(_) = self.time_full {
            size += 4;
        }

        if let Some(_) = self.bits {
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

        let version = if flags.version_offset() == 7 {
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

/// State required for compression/decompression
#[derive(Debug, Clone)]
pub struct CompressionState {
    /// Last 7 unique versions seen (circular buffer)
    pub version_cache: [i32; 7],
    /// Current index in version cache
    pub version_index: usize,
    /// Previous header for delta encoding
    pub prev_header: Option<Header>,
}

impl CompressionState {
    /// Create a new compression state
    pub fn new() -> Self {
        Self {
            version_cache: [0; 7],
            version_index: 0,
            prev_header: None,
        }
    }

    /// Compress a header given the current state
    pub fn compress(&mut self, header: &Header) -> CompressedHeader {
        let mut flags = CompressionFlags(0);

        // Version compression
        let version_i32 = header.version.to_consensus();
        let version = if let Some(offset) = self.find_version_offset(version_i32) {
            flags.0 |= offset as u8;
            None
        } else {
            // Version not in cache, set offset to 7 and include full version
            flags.0 |= 7;
            self.add_version(version_i32);
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

        self.prev_header = Some(header.clone());

        CompressedHeader {
            flags,
            version,
            prev_blockhash,
            merkle_root: header.merkle_root,
            time_offset,
            time_full,
            bits: bits,
            nonce: header.nonce,
        }
    }

    /// Decompress a header given the current state
    pub fn decompress(
        &mut self,
        compressed: &CompressedHeader,
    ) -> Result<Header, DecompressionError> {
        // Version
        let version = if let Some(v) = compressed.version {
            self.add_version(v);
            v
        } else {
            let offset = compressed.flags.version_offset() as usize;
            if offset >= 7 {
                return Err(DecompressionError::InvalidVersionOffset);
            }
            // Calculate the index in the circular buffer
            let idx = (self.version_index + 7 - offset - 1) % 7;
            self.version_cache[idx]
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

        self.prev_header = Some(header.clone());

        Ok(header)
    }

    /// Find the offset of a version in the cache
    fn find_version_offset(&self, version: i32) -> Option<usize> {
        for i in 0..7 {
            // Calculate the actual index in the circular buffer
            let idx = (self.version_index + 7 - i - 1) % 7;
            if self.version_cache[idx] == version {
                return Some(i);
            }
        }
        None
    }

    /// Add a version to the cache
    fn add_version(&mut self, version: i32) {
        // Only add if it's different from the last added version
        if self.version_index == 0 || self.version_cache[(self.version_index + 6) % 7] != version {
            self.version_cache[self.version_index] = version;
            self.version_index = (self.version_index + 1) % 7;
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
        self.version_cache = [0; 7];
        self.version_index = 0;
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
    /// Version offset is invalid (must be 0-6)
    InvalidVersionOffset,
    /// Previous header required but not available
    MissingPreviousHeader,
    /// Timestamp required but not provided
    MissingTimestamp,
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

        // Add versions
        for i in 1..=10 {
            state.add_version(i);
        }

        // Check that version 4 is still in cache (10-4 = 6, within last 7)
        assert_eq!(state.find_version_offset(4), Some(6));

        // Check that version 3 is not in cache (10-3 = 7, outside last 7)
        assert_eq!(state.find_version_offset(3), None);

        // Check most recent version
        assert_eq!(state.find_version_offset(10), Some(0));
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
        state.add_version(1);
        state.prev_header = Some(create_test_header(1, 0));

        // Reset
        state.reset();

        // Verify reset
        assert_eq!(state.version_index, 0);
        assert!(state.prev_header.is_none());
        assert_eq!(state.version_cache, [0; 7]);
    }
}
