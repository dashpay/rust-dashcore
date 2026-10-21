//! Bloom filter implementation for BIP37

use std::io;

use bitvec::prelude::*;

use super::error::BloomError;
use super::hash::murmur3;
use crate::consensus::{Decodable, Encodable, encode};
use crate::network::message_bloom::BloomFlags;

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

        // Calculate optimal filter size and hash count matching the Dash Core implementation:
        // https://github.com/dashpay/dash/blob/1c9809f1c6b917a88e466e2e059e0594afb04a59/src/common/bloom.cpp#L29-L45
        let ln2 = std::f64::consts::LN_2;
        let ln2_squared = ln2 * ln2;

        let filter_bits =
            (-1.0 / ln2_squared * elements as f64 * false_positive_rate.ln()) as usize;
        let filter_bits = filter_bits.min(MAX_BLOOM_FILTER_SIZE * 8);
        let filter_bytes = filter_bits / 8;

        if filter_bytes > MAX_BLOOM_FILTER_SIZE {
            return Err(BloomError::FilterTooLarge(filter_bytes));
        }

        let aligned_bits = filter_bytes * 8;

        let n_hash_funcs = (aligned_bits as f64 / elements as f64 * ln2) as u32;
        let n_hash_funcs = n_hash_funcs.clamp(1, MAX_HASH_FUNCS);

        let filter = bitvec![u8, Lsb0; 0; aligned_bits];

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
        self.filter.len().div_ceil(8)
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
    use crate::crypto::key::{PrivateKey, secp256k1};

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

        // Extreme false positive rate near 1.0 produces a zero-byte filter, matching Dash Core
        let filter = BloomFilter::new(1, 0.999, 0, BloomFlags::None).unwrap();
        assert_eq!(filter.size(), 0);
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

    /// Verify serialized output matches Dash Core's bloom_create_insert_serialize test vector:
    /// https://github.com/dashpay/dash/blob/b66b56c3019fe7ab0c9f35dd9894c0ded4d9d420/src/test/bloom_tests.cpp#L24-L49
    ///
    /// Filter: 3 elements, 0.01 fp rate, tweak 0, BLOOM_UPDATE_ALL.
    /// Data inserted: three 20-byte hashes from the C++ test.
    /// Expected serialized bytes: "03614e9b050000000000000001"
    #[test]
    fn test_bloom_filter_dash_core_compatibility() {
        let mut filter = BloomFilter::new(3, 0.01, 0, BloomFlags::All).unwrap();

        let data1 = hex::decode("99108ad8ed9bb6274d3980bab5a85c048f0950c8").unwrap();
        let data2 = hex::decode("b5a2c786d9ef4658287ced5914b37a1b4aa32eee").unwrap();
        let data3 = hex::decode("b9300670b4c5366e95b2699e8b18bc75e5f729c5").unwrap();

        assert!(!filter.contains(&data1));

        filter.insert(&data1);
        assert!(filter.contains(&data1));
        assert!(
            !filter.contains(&hex::decode("19108ad8ed9bb6274d3980bab5a85c048f0950c8").unwrap())
        );

        filter.insert(&data2);
        assert!(filter.contains(&data2));

        filter.insert(&data3);
        assert!(filter.contains(&data3));

        let mut encoded = Vec::new();
        filter.consensus_encode(&mut encoded).unwrap();

        let expected = hex::decode("03614e9b050000000000000001").unwrap();
        assert_eq!(encoded, expected, "Serialized bloom filter must match Dash Core test vector");
    }

    /// Verify bloom filter with pubkey and pubkey hash insertion matches Dash Core's
    /// bloom_create_insert_key test:
    /// https://github.com/dashpay/dash/blob/b66b56c3019fe7ab0c9f35dd9894c0ded4d9d420/src/test/bloom_tests.cpp#L76-L95
    ///
    /// Filter: 2 elements, 0.001 fp rate, tweak 0, BLOOM_UPDATE_ALL.
    /// Data inserted: uncompressed pubkey bytes and Hash160(pubkey) bytes.
    /// Expected serialized bytes: "038fc16b080000000000000001"
    #[test]
    fn test_bloom_create_insert_key() {
        let secp = secp256k1::Secp256k1::new();

        // Private key from Dash Core test WIF: 7sQb6QHALg4XyHsJHsSNXnEHGhZfzTTUPJXJqaqK7CavQkiL9Ms
        let privkey_bytes: [u8; 32] =
            hex::decode("f49addfd726a59abde172c86452f5f73038a02f4415878dc14934175e8418aff")
                .unwrap()
                .try_into()
                .unwrap();
        let secret_key = secp256k1::SecretKey::from_byte_array(&privkey_bytes).unwrap();
        let privkey =
            PrivateKey::new_uncompressed(secret_key, crate::network::constants::Network::Mainnet);
        let pubkey = privkey.public_key(&secp);

        let mut filter = BloomFilter::new(2, 0.001, 0, BloomFlags::All).unwrap();

        // Insert serialized uncompressed public key
        let pubkey_bytes = pubkey.to_bytes();
        filter.insert(&pubkey_bytes);

        // Insert pubkey hash (Hash160 of the serialized pubkey)
        let pubkey_hash = pubkey.pubkey_hash();
        filter.insert(pubkey_hash.as_ref());

        let mut encoded = Vec::new();
        filter.consensus_encode(&mut encoded).unwrap();

        let expected = hex::decode("038fc16b080000000000000001").unwrap();
        assert_eq!(
            encoded, expected,
            "Serialized bloom filter must match Dash Core bloom_create_insert_key test vector"
        );
    }

    /// Verify with tweak = 2147483649 from Dash Core's bloom_create_insert_serialize_with_tweak:
    /// https://github.com/dashpay/dash/blob/b66b56c3019fe7ab0c9f35dd9894c0ded4d9d420/src/test/bloom_tests.cpp#L51-L74
    #[test]
    fn test_bloom_filter_dash_core_compatibility_with_tweak() {
        let mut filter = BloomFilter::new(3, 0.01, 2147483649, BloomFlags::All).unwrap();

        let data1 = hex::decode("99108ad8ed9bb6274d3980bab5a85c048f0950c8").unwrap();
        let data2 = hex::decode("b5a2c786d9ef4658287ced5914b37a1b4aa32eee").unwrap();
        let data3 = hex::decode("b9300670b4c5366e95b2699e8b18bc75e5f729c5").unwrap();

        filter.insert(&data1);
        assert!(filter.contains(&data1));
        assert!(
            !filter.contains(&hex::decode("19108ad8ed9bb6274d3980bab5a85c048f0950c8").unwrap())
        );

        filter.insert(&data2);
        assert!(filter.contains(&data2));

        filter.insert(&data3);
        assert!(filter.contains(&data3));

        let mut encoded = Vec::new();
        filter.consensus_encode(&mut encoded).unwrap();

        let expected = hex::decode("03ce4299050000000100008001").unwrap();
        assert_eq!(
            encoded, expected,
            "Serialized bloom filter must match Dash Core test vector (with tweak)"
        );
    }
}
