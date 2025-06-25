//! Bloom filter error types

use std::fmt;

/// Errors that can occur when working with bloom filters
#[derive(Debug, Clone, PartialEq)]
pub enum BloomError {
    /// Filter size exceeds maximum allowed (36KB)
    FilterTooLarge(usize),
    /// Number of hash functions exceeds maximum allowed (50)
    TooManyHashFuncs(u32),
    /// Invalid false positive rate (must be between 0 and 1)
    InvalidFalsePositiveRate(f64),
    /// Invalid number of elements (must be greater than 0)
    InvalidElementCount(u32),
}

impl fmt::Display for BloomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BloomError::FilterTooLarge(size) => {
                write!(f, "Filter size {} exceeds maximum of 36000 bytes", size)
            }
            BloomError::TooManyHashFuncs(count) => {
                write!(f, "Hash function count {} exceeds maximum of 50", count)
            }
            BloomError::InvalidFalsePositiveRate(rate) => {
                write!(f, "Invalid false positive rate {}, must be between 0 and 1", rate)
            }
            BloomError::InvalidElementCount(count) => {
                write!(f, "Invalid element count {}, must be greater than 0", count)
            }
        }
    }
}

impl std::error::Error for BloomError {}