//! Chain tip management for tracking multiple blockchain tips
//!
//! This module manages multiple chain tips to support fork handling
//! and chain reorganization.

use super::ChainWork;
use dashcore::{BlockHash, Header as BlockHeader};
use std::collections::HashMap;

/// Represents a chain tip with its metadata
#[derive(Debug, Clone, PartialEq)]
pub struct ChainTip {
    /// The block hash of this tip
    pub hash: BlockHash,
    /// The height of this tip
    pub height: u32,
    /// The header at this tip
    pub header: BlockHeader,
    /// Cumulative chain work up to this tip
    pub chain_work: ChainWork,
    /// Whether this is currently the active (best) chain
    pub is_active: bool,
}

impl ChainTip {
    /// Create a new chain tip
    pub fn new(header: BlockHeader, height: u32, chain_work: ChainWork) -> Self {
        Self {
            hash: header.block_hash(),
            height,
            header,
            chain_work,
            is_active: false,
        }
    }
}

/// Manages multiple chain tips for fork handling
pub struct ChainTipManager {
    /// All known chain tips indexed by their hash
    tips: HashMap<BlockHash, ChainTip>,
    /// The hash of the current active (best) chain tip
    active_tip: Option<BlockHash>,
    /// Maximum number of tips to track
    max_tips: usize,
}

impl ChainTipManager {
    /// Create a new chain tip manager
    pub fn new(max_tips: usize) -> Self {
        Self {
            tips: HashMap::new(),
            active_tip: None,
            max_tips,
        }
    }

    /// Add a new chain tip
    pub fn add_tip(&mut self, tip: ChainTip) -> Result<(), &'static str> {
        let hash = tip.hash;

        // Check if we need to make space
        if self.tips.len() >= self.max_tips && !self.tips.contains_key(&hash) {
            self.evict_weakest_tip()?;
        }

        self.tips.insert(hash, tip);

        // Update active tip if this has more work
        self.update_active_tip();

        Ok(())
    }

    /// Update a tip with a new header extending it
    pub fn extend_tip(
        &mut self,
        tip_hash: &BlockHash,
        header: BlockHeader,
        new_work: ChainWork,
    ) -> Result<(), &'static str> {
        let new_height = {
            let tip = self.tips.get(tip_hash).ok_or("Tip not found")?;
            tip.height + 1
        };

        let new_tip = ChainTip {
            hash: header.block_hash(),
            height: new_height,
            header,
            chain_work: new_work,
            is_active: false,
        };

        // Store the old tip temporarily in case we need to restore it
        let old_tip = self.tips.remove(tip_hash);

        // Attempt to add the new tip
        match self.add_tip(new_tip) {
            Ok(()) => Ok(()),
            Err(e) => {
                // Restore the old tip if adding the new one failed
                if let Some(tip) = old_tip {
                    self.tips.insert(*tip_hash, tip);
                }
                Err(e)
            }
        }
    }

    /// Get the current active (best) chain tip
    pub fn get_active_tip(&self) -> Option<&ChainTip> {
        self.active_tip.as_ref().and_then(|hash| self.tips.get(hash))
    }

    /// Get a specific tip by hash
    pub fn get_tip(&self, hash: &BlockHash) -> Option<&ChainTip> {
        self.tips.get(hash)
    }

    /// Get all tips sorted by chain work (descending)
    pub fn get_all_tips(&self) -> Vec<&ChainTip> {
        let mut tips: Vec<_> = self.tips.values().collect();
        tips.sort_by(|a, b| b.chain_work.cmp(&a.chain_work));
        tips
    }

    /// Remove a tip
    pub fn remove_tip(&mut self, hash: &BlockHash) -> Option<ChainTip> {
        let tip = self.tips.remove(hash);

        // If we removed the active tip, update to the next best
        if self.active_tip.as_ref() == Some(hash) {
            self.update_active_tip();
        }

        tip
    }

    /// Check if a block hash is a known tip
    pub fn is_tip(&self, hash: &BlockHash) -> bool {
        self.tips.contains_key(hash)
    }

    /// Get the number of tracked tips
    pub fn tip_count(&self) -> usize {
        self.tips.len()
    }

    /// Update the active tip to the one with most work
    fn update_active_tip(&mut self) {
        // Clear active flag on all tips
        for tip in self.tips.values_mut() {
            tip.is_active = false;
        }

        // Find tip with most work
        let best_tip =
            self.tips.iter().max_by_key(|(_, tip)| &tip.chain_work).map(|(hash, _)| *hash);

        if let Some(ref hash) = best_tip {
            if let Some(tip) = self.tips.get_mut(hash) {
                tip.is_active = true;
            }
        }

        self.active_tip = best_tip;
    }

    /// Evict the tip with least work
    fn evict_weakest_tip(&mut self) -> Result<(), &'static str> {
        // Don't evict the active tip
        let weakest = self
            .tips
            .iter()
            .filter(|(hash, _)| self.active_tip.as_ref() != Some(hash))
            .min_by_key(|(_, tip)| &tip.chain_work)
            .map(|(hash, _)| *hash);

        if let Some(hash) = weakest {
            self.tips.remove(&hash);
            Ok(())
        } else {
            Err("Cannot evict: the only tip present is active")
        }
    }

    /// Clear all tips
    pub fn clear(&mut self) {
        self.tips.clear();
        self.active_tip = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tip_manager() {
        let mut manager = ChainTipManager::new(5);

        // Add some tips with different work
        for i in 0..3 {
            let tip = ChainTip::dummy(i, i as u8);
            manager.add_tip(tip).expect("Failed to add tip");
        }

        assert_eq!(manager.tip_count(), 3);

        // The tip with most work should be active
        let active = manager.get_active_tip().expect("Should have an active tip");
        assert_eq!(active.height, 2);
        assert!(active.is_active);

        // Add a tip with more work
        let better_tip = ChainTip::dummy(1, 10);
        manager.add_tip(better_tip).expect("Failed to add better tip");

        // Active tip should update
        let active = manager.get_active_tip().expect("Should have an active tip");
        assert_eq!(active.chain_work.as_bytes()[31], 10);
    }

    #[test]
    fn test_tip_eviction() {
        let mut manager = ChainTipManager::new(2);

        // Fill to capacity
        manager.add_tip(ChainTip::dummy(1, 5)).expect("Failed to add first tip");
        manager.add_tip(ChainTip::dummy(2, 10)).expect("Failed to add second tip");

        // Adding another should evict the weakest
        manager.add_tip(ChainTip::dummy(3, 7)).expect("Failed to add third tip");

        assert_eq!(manager.tip_count(), 2);

        // The tip with work=5 should have been evicted
        let tips = manager.get_all_tips();
        assert!(tips.iter().all(|t| t.chain_work.as_bytes()[31] >= 7));
    }

    #[test]
    fn test_extend_tip_atomic() {
        let mut manager = ChainTipManager::new(2);

        // Add two tips to fill capacity
        let tip1 = ChainTip::dummy(1, 5);
        let tip1_hash = tip1.hash;
        manager.add_tip(tip1).expect("Failed to add tip1");

        let tip2 = ChainTip::dummy(2, 10);
        manager.add_tip(tip2).expect("Failed to add tip2");

        // Extend tip1 successfully - since we remove tip1 first, there's room for the new tip
        let new_header = ChainTip::dummy(3, 6).header;
        let new_work = ChainWork::dummy(7);

        // The extend operation should succeed
        let result = manager.extend_tip(&tip1_hash, new_header, new_work);
        assert!(result.is_ok());

        // The old tip should be gone
        assert!(manager.get_tip(&tip1_hash).is_none());

        // The new tip should exist
        let new_tip_hash = new_header.block_hash();
        assert!(manager.get_tip(&new_tip_hash).is_some());
        assert_eq!(manager.tip_count(), 2);
    }

    #[test]
    fn test_extend_tip_atomic_with_failure() {
        // To properly test atomic behavior, we need a custom scenario where add_tip can fail
        // Since add_tip only fails when eviction fails (all tips are active), and only one
        // tip can be active at a time, we need to test the restoration logic differently.

        // For now, we'll test that the extend operation is atomic when it succeeds
        // A more complex test would require mocking or a different failure scenario
        let mut manager = ChainTipManager::new(3);

        // Add three tips
        let tip1 = ChainTip::dummy(1, 5);
        let tip1_hash = tip1.hash;
        manager.add_tip(tip1).expect("Failed to add tip1");

        let tip2 = ChainTip::dummy(2, 10);
        manager.add_tip(tip2).expect("Failed to add tip2");

        let tip3 = ChainTip::dummy(3, 8);
        manager.add_tip(tip3).expect("Failed to add tip3");

        // Verify initial state
        assert_eq!(manager.tip_count(), 3);
        assert!(manager.get_tip(&tip1_hash).is_some());

        // Extend tip1 - this should work and be atomic
        let new_header = ChainTip::dummy(4, 6).header;
        let new_work = ChainWork::dummy(6);

        let result = manager.extend_tip(&tip1_hash, new_header, new_work);
        assert!(result.is_ok());

        // Verify final state - old tip gone, new tip present
        assert!(manager.get_tip(&tip1_hash).is_none());
        assert!(manager.get_tip(&new_header.block_hash()).is_some());
        assert_eq!(manager.tip_count(), 3);
    }
}
