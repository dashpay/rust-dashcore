//! Bloom filter implementation for BIP37
//!
//! This module provides bloom filter support as specified in BIP37 for
//! Simplified Payment Verification (SPV) clients.

pub mod error;
pub mod filter;
pub mod hash;

// #[cfg(test)]
// mod test_murmur3_vectors;

pub use error::BloomError;
pub use filter::{BloomFilter, MAX_BLOOM_FILTER_SIZE, MAX_HASH_FUNCS};
pub use hash::murmur3;

// Re-export BloomFlags from network module to avoid circular dependency
pub use crate::network::message_bloom::BloomFlags;
