//! Gap limit management for HD wallet address discovery
//!
//! Implements BIP44 gap limit tracking to determine when to stop generating
//! addresses during wallet recovery and discovery.

#[cfg(feature = "bincode")]
use bincode_derive::{Decode, Encode};
use core::cmp;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Standard gap limit for external addresses (BIP44 recommendation)
pub const DEFAULT_EXTERNAL_GAP_LIMIT: u32 = 35;

/// Standard gap limit for internal (change) addresses
pub const DEFAULT_INTERNAL_GAP_LIMIT: u32 = 35;

/// Standard gap limit for CoinJoin addresses
pub const DEFAULT_COINJOIN_GAP_LIMIT: u32 = 35;

/// Standard gap limit for special purpose keys (identity, provider keys)
pub const DEFAULT_SPECIAL_GAP_LIMIT: u32 = 5;

/// Gap limit for DIP-17 platform payment addresses
pub const DIP17_GAP_LIMIT: u32 = 20;

/// Maximum gap limit to prevent excessive address generation
pub const MAX_GAP_LIMIT: u32 = 1000;

/// Stages of gap limit processing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub enum GapLimitStage {
    /// Initial address generation
    Initial,
    /// Extended search for more addresses
    Extended,
    /// Active scanning for address usage
    Scanning,
    /// Discovery complete
    Complete,
}

/// Gap limit tracker for a single chain (external or internal)
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct GapLimit {
    /// The gap limit value
    pub limit: u32,
    /// Current stage of processing
    pub stage: GapLimitStage,
    /// Count of consecutive unused addresses
    pub current_unused_count: u32,
    /// Highest index that has been used
    pub highest_used_index: Option<u32>,
    /// Highest index that has been generated
    pub highest_generated_index: u32,
    /// Set of all used indices
    pub used_indices: HashSet<u32>,
    /// Whether gap limit has been reached
    pub limit_reached: bool,
}

impl GapLimit {
    /// Create a new gap limit tracker
    pub fn new(limit: u32) -> Self {
        let safe_limit = cmp::min(limit, MAX_GAP_LIMIT);
        Self {
            limit: safe_limit,
            stage: GapLimitStage::Initial,
            current_unused_count: 0,
            highest_used_index: None,
            highest_generated_index: 0,
            used_indices: HashSet::new(),
            limit_reached: false,
        }
    }

    /// Create with a specific stage
    pub fn new_with_stage(limit: u32, stage: GapLimitStage) -> Self {
        let mut gap = Self::new(limit);
        gap.stage = stage;
        gap
    }

    /// Mark an address at the given index as used
    pub fn mark_used(&mut self, index: u32) {
        self.used_indices.insert(index);

        // Update highest used index
        self.highest_used_index = match self.highest_used_index {
            None => Some(index),
            Some(current) => Some(cmp::max(current, index)),
        };

        // Reset unused count if this breaks a gap
        if let Some(highest) = self.highest_used_index {
            if index > highest {
                self.current_unused_count = 0;
            } else {
                // Recalculate unused count from highest used
                self.current_unused_count = self.calculate_current_gap();
            }
        }

        // Update limit reached status
        self.update_limit_reached();

        // Update stage if we're in scanning
        if self.stage == GapLimitStage::Scanning && !self.limit_reached {
            self.stage = GapLimitStage::Extended;
        }
    }

    /// Mark an address as generated (but not necessarily used)
    pub fn mark_generated(&mut self, index: u32) {
        self.highest_generated_index = cmp::max(self.highest_generated_index, index);

        // Update current unused count
        if !self.used_indices.contains(&index) {
            if let Some(highest_used) = self.highest_used_index {
                if index > highest_used {
                    self.current_unused_count = index - highest_used;
                }
            } else {
                // No addresses used yet
                self.current_unused_count = index + 1;
            }
        }

        self.update_limit_reached();
    }

    /// Calculate the current gap (consecutive unused addresses)
    fn calculate_current_gap(&self) -> u32 {
        match self.highest_used_index {
            None => self.highest_generated_index + 1,
            Some(highest_used) => {
                let mut gap = 0;
                for i in (highest_used + 1)..=self.highest_generated_index {
                    if !self.used_indices.contains(&i) {
                        gap += 1;
                    } else {
                        gap = 0; // Reset if we find a used address
                    }
                }
                gap
            }
        }
    }

    /// Update whether the gap limit has been reached
    fn update_limit_reached(&mut self) {
        self.limit_reached = self.current_unused_count >= self.limit;

        if self.limit_reached && self.stage == GapLimitStage::Extended {
            self.stage = GapLimitStage::Complete;
        }
    }

    /// Check if we should generate more addresses
    pub fn should_generate_more(&self) -> bool {
        !self.limit_reached && self.stage != GapLimitStage::Complete
    }

    /// Check if extension is needed (for discovery)
    pub fn needs_extension(&self) -> bool {
        self.stage == GapLimitStage::Initial
            && self.highest_used_index.is_some()
            && !self.limit_reached
    }

    /// Extend the gap limit for deeper search
    pub fn extend(&mut self, new_limit: u32) {
        self.limit = cmp::min(new_limit, MAX_GAP_LIMIT);
        self.stage = GapLimitStage::Extended;
        self.update_limit_reached();
    }

    /// Reset the unused count (used when new activity is detected)
    pub fn reset_unused_count(&mut self) {
        self.current_unused_count = 0;
        self.limit_reached = false;

        if self.stage == GapLimitStage::Complete {
            self.stage = GapLimitStage::Extended;
        }
    }

    /// Get the next index to generate
    pub fn next_index(&self) -> u32 {
        self.highest_generated_index + 1
    }

    /// Get the number of addresses that should be generated
    pub fn addresses_to_generate(&self) -> u32 {
        if self.limit_reached {
            return 0;
        }

        match self.highest_used_index {
            None => {
                // No addresses used yet, generate up to the limit
                self.limit.saturating_sub(self.highest_generated_index)
            }
            Some(highest_used) => {
                // Generate enough to maintain the gap limit
                let target = highest_used + self.limit + 1;
                target.saturating_sub(self.highest_generated_index)
            }
        }
    }

    /// Get statistics about the gap limit
    pub fn stats(&self) -> GapLimitStats {
        GapLimitStats {
            limit: self.limit,
            stage: self.stage,
            current_gap: self.current_unused_count,
            highest_used: self.highest_used_index,
            highest_generated: self.highest_generated_index,
            used_count: self.used_indices.len() as u32,
            unused_count: self.highest_generated_index + 1 - self.used_indices.len() as u32,
            limit_reached: self.limit_reached,
        }
    }
}

/// Statistics about gap limit state
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct GapLimitStats {
    pub limit: u32,
    pub stage: GapLimitStage,
    pub current_gap: u32,
    pub highest_used: Option<u32>,
    pub highest_generated: u32,
    pub used_count: u32,
    pub unused_count: u32,
    pub limit_reached: bool,
}

/// Manager for multiple gap limits (external, internal, CoinJoin)
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct GapLimitManager {
    /// External (receive) address gap limit
    pub external: GapLimit,
    /// Internal (change) address gap limit
    pub internal: GapLimit,
    /// CoinJoin address gap limit (optional)
    pub coinjoin: Option<GapLimit>,
}

impl GapLimitManager {
    /// Create a new gap limit manager with default limits
    pub fn new_default() -> Self {
        Self {
            external: GapLimit::new(DEFAULT_EXTERNAL_GAP_LIMIT),
            internal: GapLimit::new(DEFAULT_INTERNAL_GAP_LIMIT),
            coinjoin: None,
        }
    }

    /// Create with specific limits
    pub fn new(external_limit: u32, internal_limit: u32, coinjoin_limit: Option<u32>) -> Self {
        Self {
            external: GapLimit::new(external_limit),
            internal: GapLimit::new(internal_limit),
            coinjoin: coinjoin_limit.map(GapLimit::new),
        }
    }

    /// Enable CoinJoin gap limit tracking
    pub fn enable_coinjoin(&mut self, limit: u32) {
        self.coinjoin = Some(GapLimit::new(limit));
    }

    /// Check if any limits need more addresses generated
    pub fn needs_generation(&self) -> bool {
        self.external.should_generate_more()
            || self.internal.should_generate_more()
            || self.coinjoin.as_ref().is_some_and(|g| g.should_generate_more())
    }

    /// Check if discovery is complete
    pub fn is_discovery_complete(&self) -> bool {
        let external_complete =
            self.external.stage == GapLimitStage::Complete || self.external.limit_reached;
        let internal_complete =
            self.internal.stage == GapLimitStage::Complete || self.internal.limit_reached;
        let coinjoin_complete = self
            .coinjoin
            .as_ref()
            .is_none_or(|g| g.stage == GapLimitStage::Complete || g.limit_reached);

        external_complete && internal_complete && coinjoin_complete
    }

    /// Get combined statistics
    pub fn stats(&self) -> GapLimitManagerStats {
        GapLimitManagerStats {
            external: self.external.stats(),
            internal: self.internal.stats(),
            coinjoin: self.coinjoin.as_ref().map(|g| g.stats()),
            discovery_complete: self.is_discovery_complete(),
        }
    }

    /// Reset all gap limits (for rescan)
    pub fn reset(&mut self) {
        self.external.reset_unused_count();
        self.internal.reset_unused_count();
        if let Some(ref mut coinjoin) = self.coinjoin {
            coinjoin.reset_unused_count();
        }
    }
}

/// Combined statistics for all gap limits
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct GapLimitManagerStats {
    pub external: GapLimitStats,
    pub internal: GapLimitStats,
    pub coinjoin: Option<GapLimitStats>,
    pub discovery_complete: bool,
}

impl Default for GapLimitManager {
    fn default() -> Self {
        Self::new_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gap_limit_basic() {
        let mut gap = GapLimit::new(20);
        assert_eq!(gap.limit, 20);
        assert_eq!(gap.stage, GapLimitStage::Initial);
        assert!(!gap.limit_reached);

        // Mark some addresses as generated
        for i in 0..20 {
            gap.mark_generated(i);
        }
        assert_eq!(gap.current_unused_count, 20);
        assert!(gap.limit_reached);
    }

    #[test]
    fn test_gap_limit_usage() {
        let mut gap = GapLimit::new(5);

        // Generate 10 addresses
        for i in 0..10 {
            gap.mark_generated(i);
        }

        // Mark some as used
        gap.mark_used(2);
        gap.mark_used(5);
        gap.mark_used(7);

        assert_eq!(gap.highest_used_index, Some(7));
        assert_eq!(gap.current_unused_count, 2); // indices 8 and 9 are unused
        assert!(!gap.limit_reached);

        // Generate more addresses
        for i in 10..13 {
            gap.mark_generated(i);
        }

        assert_eq!(gap.current_unused_count, 5); // indices 8-12 are unused
        assert!(gap.limit_reached);
    }

    #[test]
    fn test_gap_limit_extension() {
        let mut gap = GapLimit::new(5);
        gap.stage = GapLimitStage::Initial;

        for i in 0..5 {
            gap.mark_generated(i);
        }
        gap.mark_used(3);

        assert!(gap.needs_extension());

        gap.extend(10);
        assert_eq!(gap.limit, 10);
        assert_eq!(gap.stage, GapLimitStage::Extended);
        assert!(!gap.limit_reached);
    }

    #[test]
    fn test_gap_limit_manager() {
        let mut manager = GapLimitManager::new(20, 10, Some(5));

        assert!(manager.needs_generation());
        assert!(!manager.is_discovery_complete());

        // Mark external as complete
        manager.external.current_unused_count = 20;
        manager.external.update_limit_reached();

        // Mark internal as complete
        manager.internal.current_unused_count = 10;
        manager.internal.update_limit_reached();

        // Mark coinjoin as complete
        if let Some(ref mut coinjoin) = manager.coinjoin {
            coinjoin.current_unused_count = 5;
            coinjoin.update_limit_reached();
        }

        assert!(manager.is_discovery_complete());
    }

    #[test]
    fn test_addresses_to_generate() {
        let mut gap = GapLimit::new(5);

        // Initially should generate up to limit
        assert_eq!(gap.addresses_to_generate(), 5);

        // After generating 5
        for i in 0..5 {
            gap.mark_generated(i);
        }
        assert_eq!(gap.addresses_to_generate(), 0);

        // After using one
        gap.mark_used(2);
        // target = 2 + 5 + 1 = 8, highest_generated = 4, so need 8 - 4 = 4 more
        assert_eq!(gap.addresses_to_generate(), 4); // Need to generate 5, 6, 7, 8 to maintain gap
    }
}
