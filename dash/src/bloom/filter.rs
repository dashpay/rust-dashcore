//! Bloom filter implementation for BIP37

use std::cmp;
use std::io;

use bitvec::prelude::*;

use crate::consensus::{Decodable, Encodable, ReadExt, encode};
use crate::network::message_bloom::BloomFlags;
use super::error::BloomError;
use super::hash::murmur3;

/// Maximum size of a bloom filter in bytes (36KB)
pub const MAX_BLOOM_FILTER_SIZE: usize = 36000;

/// Maximum number of hash functions
pub const MAX_HASH_FUNCS: u32 = 50;

/// Bloom filter implementation as specified in BIP37
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BloomFilter {
    /// The filter data as a bit vector
    filter: BitVec<u8, Lsb0>,
    /// Number of hash functions to use
    n_hash_funcs: u32,
    /// Random value to add to hash function seeds
    n_tweak: u32,
    /// Flags controlling filter update behavior
    flags: BloomFlags,
}

impl BloomFilter {
    /// Create a new bloom filter with specified parameters
    ///
    /// # Arguments
    /// * `elements` - Expected number of elements to be added
    /// * `false_positive_rate` - Desired false positive rate (0.0 to 1.0)
    /// * `tweak` - Random value to add to hash seeds
    /// * `flags` - Update behavior flags
    pub fn new(
        elements: u32,
        false_positive_rate: f64,
        tweak: u32,
        flags: BloomFlags,
    ) -> Result<Self, BloomError> {
        if elements == 0 {
            return Err(BloomError::InvalidElementCount(elements));
        }

        if false_positive_rate <= 0.0 || false_positive_rate >= 1.0 {
            return Err(BloomError::InvalidFalsePositiveRate(false_positive_rate));
        }

        // Calculate optimal filter size and hash count
        let ln2 = std::f64::consts::LN_2;
        let ln2_squared = ln2 * ln2;

        let filter_size = (-1.0 * elements as f64 * false_positive_rate.ln() / ln2_squared).ceil() as usize;
        let filter_size = cmp::max(1, cmp::min(filter_size, MAX_BLOOM_FILTER_SIZE * 8));

        let n_hash_funcs = (filter_size as f64 / elements as f64 * ln2).ceil() as u32;
        let n_hash_funcs = cmp::max(1, cmp::min(n_hash_funcs, MAX_HASH_FUNCS));

        let filter_bytes = (filter_size + 7) / 8;
        if filter_bytes > MAX_BLOOM_FILTER_SIZE {
            return Err(BloomError::FilterTooLarge(filter_bytes));
        }

        let filter = bitvec![u8, Lsb0; 0; filter_size];
        
        Ok(BloomFilter {
            filter,
            n_hash_funcs,
            n_tweak: tweak,
            flags,
        })
    }

    /// Create a bloom filter from raw components
    pub fn from_bytes(
        data: Vec<u8>,
        n_hash_funcs: u32,
        n_tweak: u32,
        flags: BloomFlags,
    ) -> Result<Self, BloomError> {
        if data.len() > MAX_BLOOM_FILTER_SIZE {
            return Err(BloomError::FilterTooLarge(data.len()));
        }

        if n_hash_funcs > MAX_HASH_FUNCS {
            return Err(BloomError::TooManyHashFuncs(n_hash_funcs));
        }

        let filter = BitVec::from_vec(data);

        Ok(BloomFilter {
            filter,
            n_hash_funcs,
            n_tweak,
            flags,
        })
    }

    /// Insert data into the filter
    pub fn insert(&mut self, data: &[u8]) {
        for i in 0..self.n_hash_funcs {
            let seed = i.wrapping_mul(0xfba4c795).wrapping_add(self.n_tweak);
            let hash = murmur3(data, seed);
            let index = (hash as usize) % self.filter.len();
            self.filter.set(index, true);
        }
    }

    /// Check if data might be in the filter
    pub fn contains(&self, data: &[u8]) -> bool {
        if self.filter.is_empty() {
            return true; // Empty filter matches everything
        }

        for i in 0..self.n_hash_funcs {
            let seed = i.wrapping_mul(0xfba4c795).wrapping_add(self.n_tweak);
            let hash = murmur3(data, seed);
            let index = (hash as usize) % self.filter.len();
            if !self.filter[index] {
                return false;
            }
        }
        true
    }

    /// Clear the filter (set all bits to 0)
    pub fn clear(&mut self) {
        self.filter.fill(false);
    }

    /// Check if the filter is empty (all bits are 0)
    pub fn is_empty(&self) -> bool {
        !self.filter.any()
    }

    /// Get the filter size in bytes
    pub fn size(&self) -> usize {
        (self.filter.len() + 7) / 8
    }

    /// Get the filter as raw bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.filter.as_raw_slice().to_vec()
    }

    /// Get the number of hash functions
    pub fn hash_funcs(&self) -> u32 {
        self.n_hash_funcs
    }

    /// Get the tweak value
    pub fn tweak(&self) -> u32 {
        self.n_tweak
    }

    /// Get the flags
    pub fn flags(&self) -> BloomFlags {
        self.flags
    }

    /// Estimate the current false positive rate based on number of set bits
    pub fn estimate_false_positive_rate(&self, elements: u32) -> f64 {
        if elements == 0 || self.filter.is_empty() {
            return 0.0;
        }

        let filter_size = self.filter.len();

        // P(false positive) = (1 - e^(-k*n/m))^k
        // where k = hash functions, n = elements, m = filter size
        let ratio = -(self.n_hash_funcs as f64 * elements as f64) / filter_size as f64;
        let base = 1.0 - ratio.exp();
        base.powf(self.n_hash_funcs as f64)
    }
}

impl Encodable for BloomFilter {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        let data = self.to_bytes();
        len += data.consensus_encode(w)?;
        len += self.n_hash_funcs.consensus_encode(w)?;
        len += self.n_tweak.consensus_encode(w)?;
        len += self.flags.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for BloomFilter {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let data = Vec::<u8>::consensus_decode(r)?;
        let n_hash_funcs = u32::consensus_decode(r)?;
        let n_tweak = u32::consensus_decode(r)?;
        let flags = BloomFlags::consensus_decode(r)?;

        BloomFilter::from_bytes(data, n_hash_funcs, n_tweak, flags)
            .map_err(|_| encode::Error::ParseFailed("invalid bloom filter parameters"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_filter_basic() {
        let mut filter = BloomFilter::new(10, 0.001, 0, BloomFlags::None).unwrap();
        
        // Test insertion and lookup
        filter.insert(b"hello");
        assert!(filter.contains(b"hello"));
        assert!(!filter.contains(b"world"));
        
        filter.insert(b"world");
        assert!(filter.contains(b"hello"));
        assert!(filter.contains(b"world"));
    }

    #[test]
    fn test_bloom_filter_false_positives() {
        let mut filter = BloomFilter::new(100, 0.01, 0, BloomFlags::None).unwrap();
        
        // Insert some elements
        for i in 0u32..50 {
            filter.insert(&i.to_le_bytes());
        }
        
        // Check inserted elements
        for i in 0u32..50 {
            assert!(filter.contains(&i.to_le_bytes()));
        }
        
        // Count false positives
        let mut false_positives = 0;
        for i in 50u32..1000 {
            if filter.contains(&i.to_le_bytes()) {
                false_positives += 1;
            }
        }
        
        // Should be roughly around 1% (10 out of 950)
        assert!(false_positives < 50); // Allow some margin
    }

    #[test]
    fn test_bloom_filter_clear() {
        let mut filter = BloomFilter::new(10, 0.001, 0, BloomFlags::None).unwrap();
        
        filter.insert(b"test");
        assert!(filter.contains(b"test"));
        
        filter.clear();
        assert!(!filter.contains(b"test"));
        assert!(filter.is_empty());
    }

    #[test]
    fn test_bloom_filter_limits() {
        // Test maximum size
        assert!(BloomFilter::new(100000, 0.00001, 0, BloomFlags::None).is_ok());
        
        // Test invalid parameters
        assert!(matches!(
            BloomFilter::new(0, 0.01, 0, BloomFlags::None),
            Err(BloomError::InvalidElementCount(0))
        ));
        
        assert!(matches!(
            BloomFilter::new(10, 0.0, 0, BloomFlags::None),
            Err(BloomError::InvalidFalsePositiveRate(_))
        ));
        
        assert!(matches!(
            BloomFilter::new(10, 1.0, 0, BloomFlags::None),
            Err(BloomError::InvalidFalsePositiveRate(_))
        ));
    }

    #[test]
    fn test_bloom_filter_serialization() {
        let filter = BloomFilter::new(10, 0.001, 12345, BloomFlags::All).unwrap();
        
        // Encode
        let mut encoded = Vec::new();
        filter.consensus_encode(&mut encoded).unwrap();
        
        // Decode
        let decoded = BloomFilter::consensus_decode(&mut &encoded[..]).unwrap();
        
        assert_eq!(filter, decoded);
    }
}