//! Simplified discovery for masternode data following dash-evo-tool approach.
//!
//! Since we use the direct dash-evo-tool pattern with single QRInfo requests,
//! complex discovery logic is not needed.

use dashcore::BlockHash;

/// Simplified request for QRInfo data (kept for compatibility)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRInfoRequest {
    /// Base block height for the request
    pub base_height: u32,
    /// Tip block height for the request
    pub tip_height: u32,
    /// Base block hash
    pub base_hash: BlockHash,
    /// Tip block hash
    pub tip_hash: BlockHash,
    /// Whether to request extra validation data
    pub extra_share: bool,
}

impl QRInfoRequest {
    /// Create a new QRInfo request
    pub fn new(
        base_height: u32,
        tip_height: u32,
        base_hash: BlockHash,
        tip_hash: BlockHash,
        extra_share: bool,
    ) -> Self {
        Self {
            base_height,
            tip_height,
            base_hash,
            tip_hash,
            extra_share,
        }
    }
}