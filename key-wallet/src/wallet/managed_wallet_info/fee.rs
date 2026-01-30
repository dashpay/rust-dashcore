//! Fee calculation and estimation
//!
//! This module provides fee rate management and fee estimation
//! for transactions.

use core::cmp;

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

/// Fee estimation levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum FeeLevel {
    /// Economy - slower confirmation
    Economy,
    /// Normal - standard confirmation
    Normal,
    /// Priority - faster confirmation
    Priority,
    /// Custom fee rate
    Custom(FeeRate),
}

impl FeeLevel {
    /// Get the fee rate for this level
    pub fn fee_rate(&self) -> FeeRate {
        match self {
            Self::Economy => FeeRate::economy(),
            Self::Normal => FeeRate::normal(),
            Self::Priority => FeeRate::priority(),
            Self::Custom(rate) => *rate,
        }
    }
}

/// Fee estimator for dynamic fee calculation
pub struct FeeEstimator {
    /// Minimum fee rate
    min_fee_rate: FeeRate,
    /// Maximum fee rate
    max_fee_rate: FeeRate,
    /// Current estimated rates for different confirmation targets
    estimates: Vec<(u32, FeeRate)>, // (blocks, fee_rate)
}

impl FeeEstimator {
    /// Create a new fee estimator
    pub fn new() -> Self {
        Self {
            min_fee_rate: FeeRate::min(),
            max_fee_rate: FeeRate::new(100_000), // 100 sat/byte max
            estimates: vec![
                (1, FeeRate::new(10_000)), // 10 sat/byte for next block
                (3, FeeRate::new(5_000)),  // 5 sat/byte for 3 blocks
                (6, FeeRate::new(2_000)),  // 2 sat/byte for 6 blocks
                (12, FeeRate::new(1_000)), // 1 sat/byte for 12 blocks
                (24, FeeRate::new(500)),   // 0.5 sat/byte for 24 blocks
            ],
        }
    }

    /// Update fee estimates (would be called with data from network)
    pub fn update_estimates(&mut self, estimates: Vec<(u32, FeeRate)>) {
        self.estimates = estimates;
        self.estimates.sort_by_key(|(blocks, _)| *blocks);
    }

    /// Get fee rate for target confirmation in blocks
    pub fn estimate_fee(&self, target_blocks: u32) -> FeeRate {
        // Find the appropriate estimate
        for &(blocks, rate) in &self.estimates {
            if target_blocks <= blocks {
                return self.clamp_fee_rate(rate);
            }
        }

        // Use the lowest rate if target is beyond our estimates
        self.estimates
            .last()
            .map(|&(_, rate)| self.clamp_fee_rate(rate))
            .unwrap_or(self.min_fee_rate)
    }

    /// Get fee rate for a specific level
    pub fn estimate_fee_level(&self, level: FeeLevel) -> FeeRate {
        match level {
            FeeLevel::Priority => self.estimate_fee(1),
            FeeLevel::Normal => self.estimate_fee(6),
            FeeLevel::Economy => self.estimate_fee(24),
            FeeLevel::Custom(rate) => self.clamp_fee_rate(rate),
        }
    }

    /// Clamp fee rate to min/max bounds
    fn clamp_fee_rate(&self, rate: FeeRate) -> FeeRate {
        FeeRate::new(cmp::min(
            cmp::max(rate.sat_per_kb, self.min_fee_rate.sat_per_kb),
            self.max_fee_rate.sat_per_kb,
        ))
    }

    /// Set minimum fee rate
    pub fn set_min_fee_rate(&mut self, rate: FeeRate) {
        self.min_fee_rate = rate;
    }

    /// Set maximum fee rate
    pub fn set_max_fee_rate(&mut self, rate: FeeRate) {
        self.max_fee_rate = rate;
    }
}

impl Default for FeeEstimator {
    fn default() -> Self {
        Self::new()
    }
}

/// Calculate the size of a transaction
pub fn estimate_tx_size(num_inputs: usize, num_outputs: usize, has_change: bool) -> usize {
    // Base size: version (2) + type (2) + locktime (4) + varint counts
    let mut size = 10;

    // Inputs (P2PKH assumed: ~148 bytes each)
    size += num_inputs * 148;

    // Outputs (P2PKH assumed: ~34 bytes each)
    size += num_outputs * 34;

    // Change output if needed
    if has_change {
        size += 34;
    }

    size
}

/// Calculate the virtual size of a transaction (for fee calculation).
/// For Dash, vsize equals size.
pub fn estimate_tx_vsize(num_inputs: usize, num_outputs: usize, has_change: bool) -> usize {
    estimate_tx_size(num_inputs, num_outputs, has_change)
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

    #[test]
    fn test_fee_levels() {
        assert_eq!(FeeLevel::Economy.fee_rate().as_sat_per_kb(), 500);
        assert_eq!(FeeLevel::Normal.fee_rate().as_sat_per_kb(), 1000);
        assert_eq!(FeeLevel::Priority.fee_rate().as_sat_per_kb(), 2000);

        let custom = FeeLevel::Custom(FeeRate::new(3000));
        assert_eq!(custom.fee_rate().as_sat_per_kb(), 3000);
    }

    #[test]
    fn test_fee_estimator() {
        let estimator = FeeEstimator::new();

        // Test different confirmation targets
        let fee_1_block = estimator.estimate_fee(1);
        let fee_6_blocks = estimator.estimate_fee(6);
        let fee_24_blocks = estimator.estimate_fee(24);

        // Fees should decrease with longer confirmation targets
        assert!(fee_1_block.as_sat_per_kb() >= fee_6_blocks.as_sat_per_kb());
        assert!(fee_6_blocks.as_sat_per_kb() >= fee_24_blocks.as_sat_per_kb());
    }

    #[test]
    fn test_tx_size_estimation() {
        // 1 input, 1 output, no change
        let size = estimate_tx_size(1, 1, false);
        assert!(size > 180 && size < 200);

        // 2 inputs, 2 outputs, with change
        let size = estimate_tx_size(2, 2, true);
        assert!(size > 400 && size < 450);
    }
}
