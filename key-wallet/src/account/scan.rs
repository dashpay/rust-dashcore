//! Address scanning results
//!
//! This module contains structures for address scanning operations.

/// Result of address scanning
#[derive(Debug, Default)]
pub struct ScanResult {
    /// Number of external addresses found with activity
    pub external_found: usize,
    /// Number of internal addresses found with activity
    pub internal_found: usize,
    /// Number of CoinJoin addresses found with activity
    pub coinjoin_found: usize,
    /// Total addresses found with activity
    pub total_found: usize,
}
