//! Fee calculation and estimation
//!
//! This module provides fee rate management and fee estimation
//! for transactions.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Fee rate in satoshis per kilobyte
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FeeRate {
    /// Satoshis per kilobyte
    sat_per_kb: u64,
}

impl Default for FeeRate {
    fn default() -> Self {
        Self {
            sat_per_kb: 1000,
        }
    }
}

impl FeeRate {
    /// Create a new fee rate
    pub fn new(sat_per_kb: u64) -> Self {
        Self {
            sat_per_kb,
        }
    }

    /// Create from satoshis per byte
    pub fn from_sat_per_byte(sat_per_byte: u64) -> Self {
        Self {
            sat_per_kb: sat_per_byte * 1000,
        }
    }

    /// Create from duffs per byte (1 duff = 1 satoshi in Dash)
    pub fn from_duffs_per_byte(duffs_per_byte: u64) -> Self {
        Self::from_sat_per_byte(duffs_per_byte)
    }

    /// Get satoshis per kilobyte
    pub fn as_sat_per_kb(&self) -> u64 {
        self.sat_per_kb
    }

    /// Get satoshis per byte
    pub fn as_sat_per_byte(&self) -> f64 {
        self.sat_per_kb as f64 / 1000.0
    }

    /// Calculate fee for a given transaction size in bytes
    pub fn calculate_fee(&self, size_bytes: usize) -> u64 {
        // Round up to ensure we pay at least the minimum fee
        (self.sat_per_kb * size_bytes as u64).div_ceil(1000)
    }

    /// Calculate fee for a given virtual size (vsize)
    pub fn calculate_fee_vsize(&self, vsize: usize) -> u64 {
        self.calculate_fee(vsize)
    }

    /// Default minimum fee rate (1 sat/byte)
    pub fn min() -> Self {
        Self {
            sat_per_kb: 1000,
        }
    }

    /// Economy fee rate (0.5 sat/byte)
    pub fn economy() -> Self {
        Self {
            sat_per_kb: 500,
        }
    }

    /// Normal fee rate (1 sat/byte)
    pub fn normal() -> Self {
        Self {
            sat_per_kb: 1000,
        }
    }

    /// Priority fee rate (2 sat/byte)
    pub fn priority() -> Self {
        Self {
            sat_per_kb: 2000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fee_rate_calculation() {
        let rate = FeeRate::new(1000); // 1 sat/byte

        assert_eq!(rate.calculate_fee(250), 250);
        assert_eq!(rate.calculate_fee(1000), 1000);

        // Test rounding up
        assert_eq!(rate.calculate_fee(251), 251);
        assert_eq!(rate.calculate_fee(1), 1);
    }

    #[test]
    fn test_fee_rate_from_sat_per_byte() {
        let rate = FeeRate::from_sat_per_byte(5);
        assert_eq!(rate.as_sat_per_kb(), 5000);
        assert_eq!(rate.calculate_fee(1000), 5000);
    }
}
