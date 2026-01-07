//! Chain work calculation for determining the best chain
//!
//! This module handles the calculation of cumulative proof of work,
//! which is used to determine the chain with the most work (best chain).

use dashcore::{Header as BlockHeader, Target};
use std::cmp::Ordering;
use std::ops::Add;

/// Represents cumulative chain work as a 256-bit integer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainWork {
    /// The work value as bytes in big-endian order
    work: [u8; 32],
}

impl ChainWork {
    /// Create a new ChainWork with zero work
    pub fn zero() -> Self {
        Self {
            work: [0u8; 32],
        }
    }

    /// Calculate work from a single header
    pub fn from_header(header: &BlockHeader) -> Self {
        let target = header.target();
        Self::from_target(target)
    }

    /// Calculate work from a target
    pub fn from_target(target: Target) -> Self {
        // Use the proper work calculation from dashcore
        // Work = 2^256 / (target + 1)
        let work = target.to_work();
        Self {
            work: work.to_be_bytes(),
        }
    }

    /// Create ChainWork from accumulated work at a given height plus a new header
    ///
    /// IMPORTANT: This is a temporary approximation that returns only the work from
    /// the current header. For accurate cumulative work calculation, callers should
    /// track the actual cumulative work by summing individual block work values.
    ///
    /// TODO: This function should be refactored to accept the previous cumulative work
    /// as a parameter, or callers should maintain cumulative work separately.
    pub fn from_height_and_header(_height: u32, header: &BlockHeader) -> Self {
        // Currently returns only the work from the current header
        // This is incorrect for cumulative work but better than adding height bytes
        // which has no relation to proof-of-work
        Self::from_header(header)
    }

    /// Add the work from a header to this cumulative work
    pub fn add_header(self, header: &BlockHeader) -> Self {
        let header_work = Self::from_header(header);
        self.combine(header_work)
    }

    /// Add two ChainWork values
    pub fn combine(self, other: Self) -> Self {
        let mut result = [0u8; 32];
        let mut carry = 0u16;

        // Add from least significant byte (right) to most significant (left)
        for i in (0..32).rev() {
            let sum = self.work[i] as u16 + other.work[i] as u16 + carry;
            result[i] = (sum & 0xff) as u8;
            carry = sum >> 8;
        }

        Self {
            work: result,
        }
    }

    /// Get the work as a byte array
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.work
    }

    /// Create from a byte array
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            work: bytes,
        }
    }

    /// Check if this work is zero
    pub fn is_zero(&self) -> bool {
        self.work.iter().all(|&b| b == 0)
    }

    /// Create ChainWork from a hex string
    pub fn from_hex(hex: &str) -> Result<Self, String> {
        // Remove 0x prefix if present
        let hex = hex.strip_prefix("0x").unwrap_or(hex);

        // Parse hex string to bytes
        let bytes = hex::decode(hex).map_err(|e| format!("Invalid hex: {}", e))?;

        if bytes.len() != 32 {
            return Err(format!("Invalid work length: expected 32 bytes, got {}", bytes.len()));
        }

        let mut work = [0u8; 32];
        work.copy_from_slice(&bytes);

        Ok(Self {
            work,
        })
    }
}

impl Ord for ChainWork {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare as big-endian integers
        for i in 0..32 {
            match self.work[i].cmp(&other.work[i]) {
                Ordering::Equal => continue,
                other => return other,
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for ChainWork {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Default for ChainWork {
    fn default() -> Self {
        Self::zero()
    }
}

impl Add for ChainWork {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        self.combine(other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::blockdata::constants::genesis_block;
    use dashcore::Network;

    #[test]
    fn test_chain_work_comparison() {
        let work1 = ChainWork::dummy(0);
        let work2 = ChainWork::dummy(1);

        assert!(work1 < work2);
        assert!(work2 > work1);
        assert_eq!(work1, work1);
    }

    #[test]
    fn test_chain_work_addition() {
        let work1 = ChainWork::dummy(100);
        let work2 = ChainWork::dummy(200);

        let sum = work1.add(work2);
        assert_eq!(sum.work[31], 44); // 100 + 200 = 300, which is 44 + 256
        assert_eq!(sum.work[30], 1); // Carry
    }

    #[test]
    fn test_chain_work_from_header() {
        let genesis = genesis_block(Network::Dash).header;
        let work = ChainWork::from_header(&genesis);
        assert!(!work.is_zero());
    }

    #[test]
    fn test_chain_work_ordering() {
        let works: Vec<ChainWork> = (0..5).map(ChainWork::dummy).collect();

        for i in 0..4 {
            assert!(works[i] < works[i + 1]);
        }
    }

    #[test]
    fn test_chain_work_from_target_precision() {
        // Test that lower targets (harder to mine) produce more work
        // Target with leading zeros (harder)
        let mut harder_target_bytes = [0u8; 32];
        harder_target_bytes[8] = 0xff; // 00000000 00000000 ff...
        let harder_target = Target::from_be_bytes(harder_target_bytes);

        // Target with fewer leading zeros (easier)
        let mut easier_target_bytes = [0u8; 32];
        easier_target_bytes[4] = 0xff; // 00000000 ff...
        let easier_target = Target::from_be_bytes(easier_target_bytes);

        let harder_work = ChainWork::from_target(harder_target);
        let easier_work = ChainWork::from_target(easier_target);

        // Harder target should produce more work
        assert!(harder_work > easier_work, "Harder target (lower value) should produce more work");

        // Test that work values are significantly different
        // (not just by 1 byte as in the old implementation)
        let diff_position = harder_work
            .work
            .iter()
            .zip(easier_work.work.iter())
            .position(|(a, b)| a != b)
            .expect("Work values should differ");

        assert!(
            diff_position < 30,
            "Work values should differ in significant bytes, not just the least significant"
        );
    }

    #[test]
    fn test_chain_work_granularity() {
        // Test that similar targets produce slightly different work values
        let mut target1_bytes = [0u8; 32];
        target1_bytes[10] = 0x10;
        target1_bytes[11] = 0x00;
        let target1 = Target::from_be_bytes(target1_bytes);

        let mut target2_bytes = [0u8; 32];
        target2_bytes[10] = 0x10;
        target2_bytes[11] = 0x01; // Slightly different
        let target2 = Target::from_be_bytes(target2_bytes);

        let work1 = ChainWork::from_target(target1);
        let work2 = ChainWork::from_target(target2);

        // Works should be different
        assert_ne!(work1, work2, "Similar targets should produce different work values");

        // Target2 is slightly higher (easier), so should have slightly less work
        assert!(work1 > work2, "Lower target should produce more work");
    }
}
