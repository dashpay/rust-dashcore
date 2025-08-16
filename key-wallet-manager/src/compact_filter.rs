//! BIP 157/158 Compact Block Filter implementation
//!
//! This module provides support for compact block filters as specified in BIP 157 and BIP 158.
//! Compact filters allow light clients to determine whether a block contains transactions
//! relevant to them without downloading the full block.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::convert::TryInto;

use dashcore::blockdata::block::Block;
use dashcore::blockdata::script::ScriptBuf;
use dashcore::blockdata::transaction::Transaction;
use dashcore::{OutPoint, Txid};
use dashcore_hashes::{sha256, Hash};
use key_wallet::Address;

/// Filter type as defined in BIP 158
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterType {
    /// Basic filter (P = 19, M = 784931)
    Basic = 0x00,
}

impl FilterType {
    /// Get the P value for this filter type
    pub fn p_value(&self) -> u8 {
        match self {
            FilterType::Basic => 19,
        }
    }

    /// Get the M value for this filter type
    pub fn m_value(&self) -> u64 {
        match self {
            FilterType::Basic => 784931,
        }
    }
}

/// Golomb-coded set for compact filters
#[derive(Clone)]
pub struct GolombCodedSet {
    /// The encoded data
    data: Vec<u8>,
    /// Number of elements in the set
    n: u32,
    /// P value (bits per entry)
    p: u8,
    /// M value (modulus)
    m: u64,
}

impl GolombCodedSet {
    /// Create a new Golomb-coded set
    pub fn new(elements: &[Vec<u8>], p: u8, m: u64, key: &[u8; 16]) -> Self {
        let mut hashed_elements = Vec::new();

        // Hash all elements with SipHash
        for element in elements {
            let hash = siphash24(key, element);
            // Reduce hash modulo m to get filter value
            let value = hash % m;
            hashed_elements.push(value);
        }

        // Sort elements
        hashed_elements.sort_unstable();

        // Delta encode and Golomb-Rice encode
        let mut data = Vec::new();
        let mut bit_writer = BitWriter::new(&mut data);
        let mut last_value = 0u64;

        for value in hashed_elements.iter() {
            let delta = value - last_value;
            golomb_encode(&mut bit_writer, delta, p);
            last_value = *value;
        }

        bit_writer.flush();

        GolombCodedSet {
            data,
            n: elements.len() as u32,
            p,
            m,
        }
    }

    /// Check if an element might be in the set
    pub fn contains(&self, element: &[u8], key: &[u8; 16]) -> bool {
        let hash = siphash24(key, element);
        let target = hash % self.m;

        let mut bit_reader = BitReader::new(&self.data);
        let mut last_value = 0u64;

        for _ in 0..self.n {
            match golomb_decode(&mut bit_reader, self.p) {
                Some(delta) => {
                    let value = last_value + delta;
                    if value == target {
                        return true;
                    }
                    if value > target {
                        return false;
                    }
                    last_value = value;
                }
                None => return false,
            }
        }

        false
    }

    /// Get the encoded data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Match any of the provided elements
    pub fn match_any(&self, elements: &[Vec<u8>], key: &[u8; 16]) -> bool {
        let mut targets = Vec::new();
        for element in elements {
            let hash = siphash24(key, element);
            let value = hash % self.m;
            targets.push(value);
        }
        targets.sort_unstable();

        let mut bit_reader = BitReader::new(&self.data);
        let mut last_value = 0u64;
        let mut target_idx = 0;

        for _ in 0..self.n {
            match golomb_decode(&mut bit_reader, self.p) {
                Some(delta) => {
                    let value = last_value + delta;

                    // Skip targets that are too small
                    while target_idx < targets.len() && targets[target_idx] < value {
                        target_idx += 1;
                    }

                    // Check if we found a match
                    if target_idx < targets.len() && targets[target_idx] == value {
                        return true;
                    }

                    last_value = value;
                }
                None => return false,
            }
        }

        false
    }
}

/// Compact filter for a block
#[derive(Clone)]
pub struct CompactFilter {
    /// Filter type
    pub filter_type: FilterType,
    /// Block hash this filter is for
    pub block_hash: [u8; 32],
    /// The Golomb-coded set
    pub filter: GolombCodedSet,
}

impl CompactFilter {
    /// Create a test filter for unit tests
    #[cfg(test)]
    pub fn new_test_filter(scripts: &[ScriptBuf]) -> Self {
        let elements: Vec<Vec<u8>> = scripts.iter().map(|s| s.to_bytes()).collect();
        let block_hash = [0u8; 32];
        let key = derive_filter_key(&block_hash);

        let filter = GolombCodedSet::new(
            &elements,
            FilterType::Basic.p_value(),
            FilterType::Basic.m_value(),
            &key,
        );

        CompactFilter {
            filter_type: FilterType::Basic,
            block_hash,
            filter,
        }
    }

    /// Create a filter from a block
    pub fn from_block(block: &Block, filter_type: FilterType) -> Self {
        let mut elements = Vec::new();

        // Add all spent outpoints (except coinbase)
        for (i, tx) in block.txdata.iter().enumerate() {
            if i == 0 {
                continue; // Skip coinbase
            }
            for input in &tx.input {
                elements.push(input.previous_output.consensus_encode_to_vec());
            }
        }

        // Add all created outputs
        for tx in &block.txdata {
            for output in &tx.output {
                elements.push(output.script_pubkey.to_bytes());
            }
        }

        // Create filter key from block hash
        let block_hash = block.header.block_hash();
        let key = derive_filter_key(&block_hash.to_byte_array());

        let filter =
            GolombCodedSet::new(&elements, filter_type.p_value(), filter_type.m_value(), &key);

        CompactFilter {
            filter_type,
            block_hash: block_hash.to_byte_array(),
            filter,
        }
    }

    /// Check if a data element might be in this block
    pub fn contains(&self, data: &[u8], key: &[u8; 16]) -> bool {
        self.filter.contains(data, key)
    }

    /// Check if a script might be in this block
    pub fn contains_script(&self, script: &ScriptBuf) -> bool {
        let key = derive_filter_key(&self.block_hash);
        self.filter.contains(&script.to_bytes(), &key)
    }

    /// Check if an outpoint might be spent in this block
    pub fn contains_outpoint(&self, outpoint: &OutPoint) -> bool {
        let key = derive_filter_key(&self.block_hash);
        self.filter.contains(&outpoint.consensus_encode_to_vec(), &key)
    }

    /// Match any of the provided scripts
    pub fn match_any_script(&self, scripts: &[ScriptBuf]) -> bool {
        let elements: Vec<Vec<u8>> = scripts.iter().map(|s| s.to_bytes()).collect();
        let key = derive_filter_key(&self.block_hash);
        self.filter.match_any(&elements, &key)
    }
}

/// Filter header for BIP 157
pub struct FilterHeader {
    /// Filter type
    pub filter_type: FilterType,
    /// Block hash
    pub block_hash: [u8; 32],
    /// Previous filter header
    pub prev_header: [u8; 32],
    /// Filter hash
    pub filter_hash: [u8; 32],
}

impl FilterHeader {
    /// Calculate the filter header
    pub fn calculate(&self) -> [u8; 32] {
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&self.filter_hash);
        data.extend_from_slice(&self.prev_header);
        sha256::Hash::hash(&data).to_byte_array()
    }
}

// Helper functions

fn derive_filter_key(block_hash: &[u8; 32]) -> [u8; 16] {
    let hash = sha256::Hash::hash(block_hash);
    hash.as_byte_array()[0..16].try_into().unwrap()
}

fn siphash24(key: &[u8; 16], data: &[u8]) -> u64 {
    // Simplified SipHash-2-4 implementation
    // In production, use a proper SipHash library
    use dashcore_hashes::siphash24;
    let key_array = [
        u64::from_le_bytes(key[0..8].try_into().unwrap()),
        u64::from_le_bytes(key[8..16].try_into().unwrap()),
    ];
    let hash = siphash24::Hash::hash_with_keys(key_array[0], key_array[1], data);
    // Convert hash to u64 by taking first 8 bytes
    let hash_bytes = hash.as_byte_array();
    u64::from_le_bytes(hash_bytes[0..8].try_into().unwrap())
}

// Bit manipulation helpers

struct BitWriter<'a> {
    data: &'a mut Vec<u8>,
    current_byte: u8,
    bit_position: u8,
}

impl<'a> BitWriter<'a> {
    fn new(data: &'a mut Vec<u8>) -> Self {
        BitWriter {
            data,
            current_byte: 0,
            bit_position: 0,
        }
    }

    fn write_bit(&mut self, bit: bool) {
        if bit {
            self.current_byte |= 1 << (7 - self.bit_position);
        }
        self.bit_position += 1;
        if self.bit_position == 8 {
            self.data.push(self.current_byte);
            self.current_byte = 0;
            self.bit_position = 0;
        }
    }

    fn write_bits(&mut self, value: u64, bits: u8) {
        for i in (0..bits).rev() {
            self.write_bit((value >> i) & 1 == 1);
        }
    }

    fn flush(&mut self) {
        if self.bit_position > 0 {
            self.data.push(self.current_byte);
        }
    }
}

struct BitReader<'a> {
    data: &'a [u8],
    byte_position: usize,
    bit_position: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitReader {
            data,
            byte_position: 0,
            bit_position: 0,
        }
    }

    fn read_bit(&mut self) -> Option<bool> {
        if self.byte_position >= self.data.len() {
            return None;
        }
        let bit = (self.data[self.byte_position] >> (7 - self.bit_position)) & 1 == 1;
        self.bit_position += 1;
        if self.bit_position == 8 {
            self.byte_position += 1;
            self.bit_position = 0;
        }
        Some(bit)
    }

    fn read_bits(&mut self, bits: u8) -> Option<u64> {
        let mut value = 0u64;
        for _ in 0..bits {
            value <<= 1;
            if self.read_bit()? {
                value |= 1;
            }
        }
        Some(value)
    }
}

fn golomb_encode(writer: &mut BitWriter, value: u64, p: u8) {
    let q = value >> p;
    let r = value & ((1 << p) - 1);

    // Write q 1-bits followed by a 0-bit
    for _ in 0..q {
        writer.write_bit(true);
    }
    writer.write_bit(false);

    // Write r as a p-bit number
    writer.write_bits(r, p);
}

fn golomb_decode(reader: &mut BitReader, p: u8) -> Option<u64> {
    // Read unary-encoded q
    let mut q = 0u64;
    while reader.read_bit()? {
        q += 1;
    }

    // Read r
    let r = reader.read_bits(p)?;

    Some((q << p) | r)
}

// Extension trait for encoding
trait ConsensusEncode {
    fn consensus_encode_to_vec(&self) -> Vec<u8>;
}

impl ConsensusEncode for OutPoint {
    fn consensus_encode_to_vec(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(36);
        data.extend_from_slice(&self.txid.to_byte_array());
        data.extend_from_slice(&self.vout.to_le_bytes());
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_golomb_encoding() {
        let mut data = Vec::new();
        let mut writer = BitWriter::new(&mut data);

        golomb_encode(&mut writer, 42, 5);
        writer.flush();

        let mut reader = BitReader::new(&data);
        let decoded = golomb_decode(&mut reader, 5);

        assert_eq!(decoded, Some(42));
    }

    #[test]
    fn test_compact_filter() {
        let elements = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];

        let key = [0u8; 16];
        let filter = GolombCodedSet::new(&elements, 19, 784931, &key);

        assert!(filter.contains(&[1, 2, 3], &key));
        assert!(filter.contains(&[4, 5, 6], &key));
        assert!(!filter.contains(&[10, 11, 12], &key));
    }
}
