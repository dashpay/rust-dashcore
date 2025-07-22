//! Engine-driven discovery of missing masternode data.
//!
//! This module provides intelligent discovery of missing masternode lists
//! using the masternode list engine's built-in methods rather than manual
//! height tracking. It identifies gaps in masternode data and creates
//! optimal QRInfo requests to fill those gaps.

use dashcore::{
    BlockHash,
    sml::{
        llmq_entry_verification::LLMQEntryVerificationStatus,
        llmq_type::LLMQType,
        masternode_list_engine::MasternodeListEngine,
    },
};
use std::collections::{BTreeMap, BTreeSet};
use tracing;

/// Service for discovering missing masternode data using engine methods
#[derive(Debug)]
pub struct MasternodeDiscoveryService {
    /// LLMQ types to exclude from discovery (configurable)
    excluded_quorum_types: Vec<LLMQType>,
}

impl MasternodeDiscoveryService {
    /// Create a new discovery service with default configuration.
    pub fn new() -> Self {
        Self {
            // Exclude types we don't need for SPV
            excluded_quorum_types: vec![
                LLMQType::Llmqtype60_75,  // Too small for meaningful validation
                LLMQType::Llmqtype50_60, // Platform-specific, not needed for SPV
            ],
        }
    }
    
    /// Discover which masternode lists are missing from the engine.
    ///
    /// This uses the engine's `latest_masternode_list_non_rotating_quorum_hashes`
    /// method to identify block hashes where we need masternode lists but don't
    /// have them.
    pub fn discover_missing_masternode_lists(
        &self,
        engine: &MasternodeListEngine,
    ) -> DiscoveryResult {
        // Use engine's built-in discovery method
        let missing_hashes = engine.latest_masternode_list_non_rotating_quorum_hashes(
            &self.excluded_quorum_types,
            true  // only_return_block_hashes_with_missing_masternode_lists_from_engine
        );
        
        tracing::info!("Discovered {} missing masternode lists", missing_hashes.len());
        
        // Convert block hashes to heights using engine's block container
        let mut missing_by_height = BTreeMap::new();
        for hash in missing_hashes {
            if let Some(height) = engine.block_container.get_height(&hash) {
                missing_by_height.insert(height, hash);
                tracing::debug!("Missing masternode list at height {}: {:x}", height, hash);
            } else {
                tracing::warn!("Found missing hash {:x} but no height mapping", hash);
            }
        }
        
        let total_discovered = missing_by_height.len();
        let requires_qr_info = !missing_by_height.is_empty();
        
        DiscoveryResult {
            missing_by_height,
            total_discovered,
            requires_qr_info,
        }
    }
    
    /// Discover rotating quorums that need validation.
    ///
    /// This identifies rotating quorums that either:
    /// - Need validation (verification status is Unknown)
    /// - Are missing cycle data needed for rotation
    pub fn discover_rotating_quorum_needs(
        &self,
        engine: &MasternodeListEngine,
    ) -> RotatingQuorumDiscovery {
        let rotating_hashes = engine.latest_masternode_list_rotating_quorum_hashes(
            &self.excluded_quorum_types
        );
        
        let mut needs_validation = Vec::new();
        let mut missing_cycle_data = Vec::new();
        
        for hash in rotating_hashes {
            if let Some(height) = engine.block_container.get_height(&hash) {
                // Check if we have the quorum cycle data
                if !engine.rotated_quorums_per_cycle.contains_key(&hash) {
                    missing_cycle_data.push((height, hash));
                }
                
                // Check if quorum needs validation
                if let Some(list) = engine.masternode_lists.get(&height) {
                    for (llmq_type, quorums) in &list.quorums {
                        if llmq_type.is_rotating_quorum_type() {
                            for (_, quorum_entry) in quorums {
                                if quorum_entry.verified == LLMQEntryVerificationStatus::Unknown {
                                    needs_validation.push((height, hash, *llmq_type));
                                }
                            }
                        }
                    }
                }
            }
        }
        
        RotatingQuorumDiscovery {
            needs_validation,
            missing_cycle_data,
        }
    }
    
    /// Create optimal QRInfo requests based on discovery results.
    ///
    /// This groups missing heights into efficient ranges for QRInfo requests,
    /// taking into account:
    /// - Maximum span for QRInfo requests
    /// - Network efficiency (batching nearby heights)
    /// - Priority (more recent blocks have higher priority for SPV)
    pub fn plan_qr_info_requests(
        &self,
        discovery: &DiscoveryResult,
        max_request_span: u32,
    ) -> Vec<QRInfoRequest> {
        let mut requests = Vec::new();
        
        if discovery.missing_by_height.is_empty() {
            return requests;
        }
        
        // Group missing heights into ranges for efficient QRInfo requests
        let heights: Vec<u32> = discovery.missing_by_height.keys().cloned().collect();
        let mut current_range_start = heights[0];
        let mut current_range_end = heights[0];
        
        for &height in &heights[1..] {
            if height - current_range_end <= max_request_span && 
               height - current_range_start <= max_request_span * 3 {
                // Extend current range
                current_range_end = height;
            } else {
                // Finalize current range and start new one
                requests.push(QRInfoRequest {
                    base_height: current_range_start.saturating_sub(8), // h-8 for validation
                    tip_height: current_range_end,
                    base_hash: discovery.missing_by_height[&current_range_start],
                    tip_hash: discovery.missing_by_height[&current_range_end],
                    extra_share: true, // Always request extra validation data
                    priority: self.calculate_priority(current_range_start, current_range_end),
                });
                
                current_range_start = height;
                current_range_end = height;
            }
        }
        
        // Add final range
        requests.push(QRInfoRequest {
            base_height: current_range_start.saturating_sub(8),
            tip_height: current_range_end,
            base_hash: discovery.missing_by_height[&current_range_start],
            tip_hash: discovery.missing_by_height[&current_range_end],
            extra_share: true,
            priority: self.calculate_priority(current_range_start, current_range_end),
        });
        
        // Sort by priority (most recent first for SPV)
        requests.sort_by(|a, b| b.priority.cmp(&a.priority));
        
        tracing::info!(
            "Planned {} QRInfo requests covering {} heights",
            requests.len(),
            discovery.total_discovered
        );
        
        requests
    }
    
    fn calculate_priority(&self, _start_height: u32, end_height: u32) -> u32 {
        // More recent blocks have higher priority for SPV
        end_height
    }
}

impl Default for MasternodeDiscoveryService {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of masternode list discovery
#[derive(Debug)]
pub struct DiscoveryResult {
    /// Map of heights to block hashes where masternode lists are missing
    pub missing_by_height: BTreeMap<u32, BlockHash>,
    /// Total number of missing masternode lists discovered
    pub total_discovered: usize,
    /// Whether QRInfo requests are needed
    pub requires_qr_info: bool,
}

/// Result of rotating quorum discovery
#[derive(Debug)]
pub struct RotatingQuorumDiscovery {
    /// Quorums that need validation: (height, block_hash, llmq_type)
    pub needs_validation: Vec<(u32, BlockHash, LLMQType)>,
    /// Heights missing quorum cycle data: (height, block_hash)
    pub missing_cycle_data: Vec<(u32, BlockHash)>,
}

/// A planned QRInfo request
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
    /// Whether to request extra share data
    pub extra_share: bool,
    /// Priority of this request (higher = more important)
    pub priority: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::Network;
    
    fn create_test_engine() -> MasternodeListEngine {
        MasternodeListEngine::default_for_network(Network::Testnet)
    }
    
    #[test]
    fn test_discovery_with_no_missing_lists() {
        let engine = create_test_engine();
        let discovery_service = MasternodeDiscoveryService::new();
        
        let result = discovery_service.discover_missing_masternode_lists(&engine);
        
        assert_eq!(result.total_discovered, 0);
        assert!(!result.requires_qr_info);
        assert!(result.missing_by_height.is_empty());
    }
    
    #[test]
    fn test_qr_info_request_planning() {
        let discovery_service = MasternodeDiscoveryService::new();
        
        // Create discovery result with scattered missing heights
        let mut missing_by_height = BTreeMap::new();
        missing_by_height.insert(1000, BlockHash::all_zeros());
        missing_by_height.insert(1001, BlockHash::all_zeros());
        missing_by_height.insert(1002, BlockHash::all_zeros());
        missing_by_height.insert(1100, BlockHash::all_zeros()); // Gap
        missing_by_height.insert(1200, BlockHash::all_zeros()); // Another gap
        
        let discovery = DiscoveryResult {
            missing_by_height,
            total_discovered: 5,
            requires_qr_info: true,
        };
        
        let requests = discovery_service.plan_qr_info_requests(&discovery, 50);
        
        // Should group 1000-1002 together, 1100 separate, 1200 separate
        assert_eq!(requests.len(), 3);
        
        // Check priorities (higher for more recent)
        assert!(requests[0].priority >= requests[1].priority);
    }
}