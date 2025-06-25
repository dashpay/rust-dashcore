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
        Self { work: [0u8; 32] }
    }

    /// Calculate work from a single header
    pub fn from_header(header: &BlockHeader) -> Self {
        let target = header.target();
        Self::from_target(target)
    }

    /// Calculate work from a target
    pub fn from_target(target: Target) -> Self {
        // Work = 2^256 / (target + 1)
        // This is a simplified calculation that avoids big integer arithmetic
        // by using the fact that work ≈ 2^256 / target for our purposes
        
        let target_bytes = target.to_be_bytes();
        let mut work = [0u8; 32];
        
        // Find first non-zero byte in target
        let mut first_nonzero = 0;
        for (i, &byte) in target_bytes.iter().enumerate() {
            if byte != 0 {
                first_nonzero = i;
                break;
            }
        }
        
        // Approximate work calculation
        // Higher targets (easier) = less work
        // Lower targets (harder) = more work
        if first_nonzero < 32 {
            work[31 - first_nonzero] = 255 / target_bytes[first_nonzero].max(1);
        }
        
        Self { work }
    }

    /// Create ChainWork from accumulated work at a given height plus a new header
    pub fn from_height_and_header(height: u32, header: &BlockHeader) -> Self {
        // Approximate total work based on height and current difficulty
        let header_work = Self::from_header(header);
        let mut total_work = header_work.work;
        
        // Add approximate work for all previous blocks
        // This is simplified - in production, we'd track exact cumulative work
        if height > 0 {
            let height_bytes = height.to_be_bytes();
            for i in 0..4 {
                let idx = 31 - i;
                let (sum, overflow) = total_work[idx].overflowing_add(height_bytes[3 - i]);
                total_work[idx] = sum;
                if overflow && idx > 0 {
                    total_work[idx - 1] = total_work[idx - 1].saturating_add(1);
                }
            }
        }
        
        Self { work: total_work }
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
        
        Self { work: result }
    }

    /// Get the work as a byte array
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.work
    }

    /// Create from a byte array
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { work: bytes }
    }

    /// Check if this work is zero
    pub fn is_zero(&self) -> bool {
        self.work.iter().all(|&b| b == 0)
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
        let work1 = ChainWork::from_bytes([0u8; 32]);
        let mut bytes2 = [0u8; 32];
        bytes2[31] = 1;
        let work2 = ChainWork::from_bytes(bytes2);
        
        assert!(work1 < work2);
        assert!(work2 > work1);
        assert_eq!(work1, work1);
    }

    #[test]
    fn test_chain_work_addition() {
        let mut bytes1 = [0u8; 32];
        bytes1[31] = 100;
        let work1 = ChainWork::from_bytes(bytes1);
        
        let mut bytes2 = [0u8; 32];
        bytes2[31] = 200;
        let work2 = ChainWork::from_bytes(bytes2);
        
        let sum = work1.add(work2);
        assert_eq!(sum.work[31], 44); // 100 + 200 = 300, which is 44 + 256
        assert_eq!(sum.work[30], 1);   // Carry
    }

    #[test]
    fn test_chain_work_from_header() {
        let genesis = genesis_block(Network::Dash).header;
        let work = ChainWork::from_header(&genesis);
        assert!(!work.is_zero());
    }

    #[test]
    fn test_chain_work_ordering() {
        let works: Vec<ChainWork> = (0..5)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[31] = i;
                ChainWork::from_bytes(bytes)
            })
            .collect();
        
        for i in 0..4 {
            assert!(works[i] < works[i + 1]);
        }
    }
}