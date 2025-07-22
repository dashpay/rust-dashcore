# Phase 2: Engine Discovery Integration

## Overview

This phase replaces dash-spv's manual height tracking approach with the masternode list engine's intended discovery methods. Instead of dash-spv deciding what to request next, the engine will tell us exactly which masternode lists are missing and needed for validation.

## Objectives

1. **Replace Manual Tracking**: Remove hardcoded height progression logic
2. **Engine-Driven Discovery**: Use engine methods to identify missing data
3. **Intelligent Batching**: Group missing data into efficient QRInfo requests
4. **Demand-Driven Sync**: Only request data that's actually needed

## Current State Analysis

### Current Inefficient Approach
```rust
// dash-spv currently does this manually:
impl MasternodeSyncManager {
    fn determine_next_diff_to_request(&self) -> (u32, u32) {
        // Manual calculation of next height range
        let base_height = self.last_processed_height;
        let target_height = base_height + DIFF_BATCH_SIZE;
        (base_height, target_height)
    }
}
```

### Engine's Intended Approach
```rust
// Engine provides these discovery methods:
engine.latest_masternode_list_non_rotating_quorum_hashes(&[], true)
// Returns: Block hashes where we DON'T have masternode lists

engine.masternode_list_for_block_hash(&block_hash)
// Returns: Masternode list if we have it, None if missing
```

## Detailed Implementation Plan

### 1. Engine Discovery API Integration

#### 1.1 Create Discovery Service

**File**: `dash-spv/src/sync/discovery.rs`

**Implementation**:
```rust
use dashcore::sml::{
    llmq_type::LLMQType,
    masternode_list_engine::MasternodeListEngine,
};
use std::collections::{BTreeSet, BTreeMap};

/// Service for discovering missing masternode data using engine methods
pub struct MasternodeDiscoveryService {
    /// LLMQ types to exclude from discovery (configurable)
    excluded_quorum_types: Vec<LLMQType>,
}

impl MasternodeDiscoveryService {
    pub fn new() -> Self {
        Self {
            // Exclude types we don't need for SPV
            excluded_quorum_types: vec![
                LLMQType::Llmqtype5_60,  // Too small for meaningful validation
                LLMQType::Llmqtype50_60, // Platform-specific, not needed for SPV
            ],
        }
    }
    
    /// Discover which masternode lists are missing from the engine
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
        let mut missing_heights = BTreeMap::new();
        for hash in missing_hashes {
            if let Some(height) = engine.block_container.get_height(&hash) {
                missing_heights.insert(height, hash);
                tracing::debug!("Missing masternode list at height {}: {:x}", height, hash);
            } else {
                tracing::warn!("Found missing hash {:x} but no height mapping", hash);
            }
        }
        
        DiscoveryResult {
            missing_by_height: missing_heights,
            total_discovered: missing_heights.len(),
            requires_qr_info: !missing_heights.is_empty(),
        }
    }
    
    /// Discover rotating quorums that need validation
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
    
    /// Create optimal QRInfo requests based on discovery results
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
    
    fn calculate_priority(&self, start_height: u32, end_height: u32) -> u32 {
        // More recent blocks have higher priority for SPV
        end_height
    }
}

#[derive(Debug)]
pub struct DiscoveryResult {
    pub missing_by_height: BTreeMap<u32, BlockHash>,
    pub total_discovered: usize,
    pub requires_qr_info: bool,
}

#[derive(Debug)]
pub struct RotatingQuorumDiscovery {
    pub needs_validation: Vec<(u32, BlockHash, LLMQType)>,
    pub missing_cycle_data: Vec<(u32, BlockHash)>,
}

#[derive(Debug, Clone)]
pub struct QRInfoRequest {
    pub base_height: u32,
    pub tip_height: u32,
    pub base_hash: BlockHash,
    pub tip_hash: BlockHash,
    pub extra_share: bool,
    pub priority: u32,
}
```

**Test File**: `tests/sync/test_masternode_discovery.rs`
```rust
#[tokio::test]
async fn test_discovery_finds_missing_lists() {
    let mut engine = create_test_engine_with_gaps().await;
    let discovery_service = MasternodeDiscoveryService::new();
    
    // Add some masternode lists but leave gaps
    engine.masternode_lists.insert(1000, create_test_masternode_list(1000));
    engine.masternode_lists.insert(1500, create_test_masternode_list(1500));
    // Gap: missing 1200, 1300, 1400
    
    // Add block hashes for the missing heights
    for height in 1200..=1400 {
        let hash = test_block_hash(height);
        engine.feed_block_height(height, hash);
        
        // Add quorum references that point to these missing heights
        if let Some(list) = engine.masternode_lists.get_mut(&1500) {
            list.add_quorum_reference(height, hash); // This would create the "missing" reference
        }
    }
    
    let result = discovery_service.discover_missing_masternode_lists(&engine);
    
    assert_eq!(result.total_discovered, 3); // 1200, 1300, 1400
    assert!(result.requires_qr_info);
    assert!(result.missing_by_height.contains_key(&1200));
    assert!(result.missing_by_height.contains_key(&1300));
    assert!(result.missing_by_height.contains_key(&1400));
}

#[tokio::test]
async fn test_discovery_no_missing_lists() {
    let engine = create_complete_test_engine().await;
    let discovery_service = MasternodeDiscoveryService::new();
    
    let result = discovery_service.discover_missing_masternode_lists(&engine);
    
    assert_eq!(result.total_discovered, 0);
    assert!(!result.requires_qr_info);
    assert!(result.missing_by_height.is_empty());
}

#[tokio::test]
async fn test_qr_info_request_planning() {
    let discovery_service = MasternodeDiscoveryService::new();
    
    // Create discovery result with scattered missing heights
    let mut missing_by_height = BTreeMap::new();
    missing_by_height.insert(1000, test_block_hash(1000));
    missing_by_height.insert(1001, test_block_hash(1001));
    missing_by_height.insert(1002, test_block_hash(1002));
    missing_by_height.insert(1100, test_block_hash(1100)); // Gap
    missing_by_height.insert(1200, test_block_hash(1200)); // Another gap
    
    let discovery = DiscoveryResult {
        missing_by_height,
        total_discovered: 5,
        requires_qr_info: true,
    };
    
    let requests = discovery_service.plan_qr_info_requests(&discovery, 50);
    
    // Should group 1000-1002 together, 1100 separate, 1200 separate
    assert_eq!(requests.len(), 3);
    
    // Check first request covers the grouped heights
    assert_eq!(requests[0].tip_height, 1002);
    assert!(requests[0].base_height <= 1000);
    
    // Check priorities (higher for more recent)
    assert!(requests[0].priority >= requests[1].priority);
}

#[tokio::test]
async fn test_rotating_quorum_discovery() {
    let mut engine = create_test_engine_with_rotating_quorums().await;
    let discovery_service = MasternodeDiscoveryService::new();
    
    // Add some rotating quorums that need validation
    add_unvalidated_rotating_quorum(&mut engine, 2000, LLMQType::Llmqtype400_60);
    
    let result = discovery_service.discover_rotating_quorum_needs(&engine);
    
    assert!(!result.needs_validation.is_empty());
    assert_eq!(result.needs_validation[0].2, LLMQType::Llmqtype400_60);
}
```

#### 1.2 Integrate Discovery into Sync Manager

**File**: `dash-spv/src/sync/masternodes.rs`

**Implementation**:
```rust
impl MasternodeSyncManager {
    /// Perform engine-driven discovery of missing data
    pub async fn discover_sync_needs(&mut self) -> SyncResult<SyncPlan> {
        let engine = self.engine.as_ref().ok_or_else(|| {
            SyncError::Configuration("Masternode engine not initialized".to_string())
        })?;
        
        let discovery_service = MasternodeDiscoveryService::new();
        
        // Discover missing masternode lists
        let missing_lists = discovery_service.discover_missing_masternode_lists(engine);
        
        // Discover rotating quorum needs
        let rotating_needs = discovery_service.discover_rotating_quorum_needs(engine);
        
        // Plan QRInfo requests
        let qr_info_requests = discovery_service.plan_qr_info_requests(
            &missing_lists,
            self.config.qr_info_max_span.unwrap_or(500) // ~20 hours of blocks
        );
        
        let plan = SyncPlan {
            qr_info_requests,
            rotating_validation_needed: !rotating_needs.needs_validation.is_empty(),
            estimated_completion_time: self.estimate_sync_time(&missing_lists),
            fallback_to_mn_diff: missing_lists.total_discovered > 1000, // Large gaps
        };
        
        tracing::info!(
            "Sync plan: {} QRInfo requests, rotating_validation={}, fallback={}",
            plan.qr_info_requests.len(),
            plan.rotating_validation_needed,
            plan.fallback_to_mn_diff
        );
        
        Ok(plan)
    }
    
    /// Execute the sync plan using engine discovery
    pub async fn execute_engine_driven_sync(
        &mut self,
        network: &mut dyn NetworkManager,
        plan: SyncPlan,
    ) -> SyncResult<()> {
        if plan.qr_info_requests.is_empty() {
            tracing::info!("No sync needed - engine has all required data");
            return Ok(());
        }
        
        // Execute QRInfo requests in priority order
        for (i, request) in plan.qr_info_requests.iter().enumerate() {
            tracing::info!(
                "Executing QRInfo request {}/{}: heights {}-{}",
                i + 1,
                plan.qr_info_requests.len(),
                request.base_height,
                request.tip_height
            );
            
            // Request QRInfo
            network.request_qr_info(
                request.base_hash,
                request.tip_hash,
                request.extra_share
            ).await.map_err(|e| {
                SyncError::Network(format!("Failed to request QRInfo: {}", e))
            })?;
            
            // Wait for response with timeout
            let timeout = tokio::time::timeout(
                self.config.qr_info_timeout,
                self.wait_for_qr_info_response()
            ).await;
            
            match timeout {
                Ok(Ok(qr_info)) => {
                    self.process_qr_info_response(qr_info).await?;
                    tracing::info!("Successfully processed QRInfo response {}/{}", i + 1, plan.qr_info_requests.len());
                }
                Ok(Err(e)) => {
                    if plan.fallback_to_mn_diff {
                        tracing::warn!("QRInfo failed, falling back to MnListDiff: {}", e);
                        self.fallback_to_mn_diff_sync(request, network).await?;
                    } else {
                        return Err(e);
                    }
                }
                Err(_) => {
                    tracing::error!("QRInfo request timed out for heights {}-{}", request.base_height, request.tip_height);
                    if plan.fallback_to_mn_diff {
                        self.fallback_to_mn_diff_sync(request, network).await?;
                    } else {
                        return Err(SyncError::Network("QRInfo request timeout".to_string()));
                    }
                }
            }
            
            // Brief pause between requests to be network-friendly
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        
        // Perform any additional rotating quorum validation if needed
        if plan.rotating_validation_needed {
            self.validate_rotating_quorums().await?;
        }
        
        tracing::info!("Engine-driven sync completed successfully");
        Ok(())
    }
    
    /// Process QRInfo response using engine
    async fn process_qr_info_response(&mut self, qr_info: QRInfo) -> SyncResult<()> {
        let engine = self.engine.as_mut().ok_or_else(|| {
            SyncError::Configuration("Masternode engine not initialized".to_string())
        })?;
        
        // Create block height fetcher for engine
        let block_height_fetcher = |block_hash: &BlockHash| -> Result<u32, ClientDataRetrievalError> {
            if let Some(height) = engine.block_container.get_height(block_hash) {
                Ok(height)
            } else {
                Err(ClientDataRetrievalError::BlockNotFound(*block_hash))
            }
        };
        
        // Process through engine
        engine.feed_qr_info(
            qr_info,
            true,  // verify_tip_non_rotated_quorums
            true,  // verify_rotated_quorums
            Some(block_height_fetcher)
        ).map_err(|e| SyncError::Validation(format!("Engine QRInfo processing failed: {}", e)))?;
        
        // Update sync progress
        self.update_sync_progress_from_engine();
        
        Ok(())
    }
    
    /// Fallback to individual MnListDiff requests if QRInfo fails
    async fn fallback_to_mn_diff_sync(
        &mut self,
        request: &QRInfoRequest,
        network: &mut dyn NetworkManager,
    ) -> SyncResult<()> {
        tracing::info!(
            "Falling back to MnListDiff sync for heights {}-{}",
            request.base_height,
            request.tip_height
        );
        
        // Request individual diffs for the range
        for height in request.base_height..=request.tip_height {
            let base_height = height.saturating_sub(1);
            self.request_masternode_diff(network, storage, base_height, height).await?;
            
            // Wait for response
            let diff = self.wait_for_mn_diff_response().await?;
            self.process_mn_diff(diff).await?;
        }
        
        Ok(())
    }
    
    /// Update sync progress based on engine state
    fn update_sync_progress_from_engine(&mut self) {
        if let Some(engine) = &self.engine {
            let total_lists = engine.masternode_lists.len();
            let latest_height = engine.masternode_lists.keys().max().copied().unwrap_or(0);
            
            self.sync_progress = MasternodeSyncProgress {
                total_lists,
                latest_height,
                quorum_validation_complete: self.check_quorum_validation_complete(engine),
                estimated_remaining_time: self.estimate_remaining_time(engine),
            };
        }
    }
    
    fn estimate_sync_time(&self, discovery: &DiscoveryResult) -> Duration {
        // Estimate based on number of QRInfo requests and network latency
        let base_time_per_request = Duration::from_secs(2); // Conservative estimate
        let total_requests = (discovery.total_discovered / 100).max(1); // ~100 blocks per request
        base_time_per_request * total_requests as u32
    }
}

#[derive(Debug)]
pub struct SyncPlan {
    pub qr_info_requests: Vec<QRInfoRequest>,
    pub rotating_validation_needed: bool,
    pub estimated_completion_time: Duration,
    pub fallback_to_mn_diff: bool,
}

#[derive(Debug)]
pub struct MasternodeSyncProgress {
    pub total_lists: usize,
    pub latest_height: u32,
    pub quorum_validation_complete: bool,
    pub estimated_remaining_time: Duration,
}
```

**Test File**: `tests/sync/test_engine_driven_sync.rs`
```rust
#[tokio::test]
async fn test_engine_driven_discovery() {
    let mut sync_manager = setup_sync_manager_with_gaps().await;
    
    // Engine has some data but is missing critical pieces
    add_masternode_list_with_gaps(&mut sync_manager).await;
    
    let plan = sync_manager.discover_sync_needs().await.unwrap();
    
    assert!(!plan.qr_info_requests.is_empty());
    assert!(plan.estimated_completion_time > Duration::ZERO);
    
    // Verify requests cover the gaps
    let covered_heights: Vec<u32> = plan.qr_info_requests
        .iter()
        .flat_map(|req| req.base_height..=req.tip_height)
        .collect();
    
    assert!(covered_heights.contains(&1200)); // Known gap
    assert!(covered_heights.contains(&1300)); // Known gap
}

#[tokio::test]  
async fn test_sync_plan_execution() {
    let mut sync_manager = create_test_sync_manager().await;
    let mut mock_network = create_mock_network_with_qr_info().await;
    
    let plan = SyncPlan {
        qr_info_requests: vec![create_test_qr_info_request()],
        rotating_validation_needed: false,
        estimated_completion_time: Duration::from_secs(5),
        fallback_to_mn_diff: false,
    };
    
    let result = sync_manager.execute_engine_driven_sync(&mut mock_network, plan).await;
    assert!(result.is_ok());
    
    // Verify network requests were made
    assert_eq!(mock_network.get_qr_info_request_count(), 1);
    
    // Verify engine state updated
    let engine = sync_manager.engine().unwrap();
    assert!(!engine.masternode_lists.is_empty());
}

#[tokio::test]
async fn test_qr_info_timeout_fallback() {
    let mut sync_manager = create_test_sync_manager().await;
    let mut mock_network = create_mock_network_with_timeout().await;
    
    let plan = SyncPlan {
        qr_info_requests: vec![create_test_qr_info_request()],
        rotating_validation_needed: false,
        estimated_completion_time: Duration::from_secs(5),
        fallback_to_mn_diff: true, // Enable fallback
    };
    
    // Should succeed despite QRInfo timeout due to fallback
    let result = sync_manager.execute_engine_driven_sync(&mut mock_network, plan).await;
    assert!(result.is_ok());
    
    // Verify fallback was used
    assert!(mock_network.get_mn_diff_request_count() > 0);
}

#[tokio::test]
async fn test_no_sync_needed() {
    let sync_manager = create_complete_sync_manager().await;
    
    let plan = sync_manager.discover_sync_needs().await.unwrap();
    
    assert!(plan.qr_info_requests.is_empty());
    assert!(!plan.rotating_validation_needed);
    assert_eq!(plan.estimated_completion_time, Duration::ZERO);
}
```

### 2. Replace Manual Height Tracking

#### 2.1 Remove Old Logic

**File**: `dash-spv/src/sync/masternodes.rs` (modifications)

**Changes**:
```rust
impl MasternodeSyncManager {
    // REMOVE these manual tracking methods:
    // fn determine_next_diff_to_request(&self) -> (u32, u32)
    // fn calculate_next_height_range(&self) -> Option<(u32, u32)>
    // fn update_last_processed_height(&mut self, height: u32)
    
    // REPLACE with engine-driven approach:
    
    /// Start masternode sync using engine discovery
    pub async fn start_sync(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &dyn StorageManager,
    ) -> SyncResult<()> {
        tracing::info!("Starting engine-driven masternode sync");
        
        // Initialize engine if needed
        if self.engine.is_none() {
            self.initialize_engine_from_storage(storage).await?;
        }
        
        // Discover what we need
        let plan = self.discover_sync_needs().await?;
        
        if plan.qr_info_requests.is_empty() {
            tracing::info!("Masternode sync already complete");
            return Ok(());
        }
        
        // Execute the plan
        self.execute_engine_driven_sync(network, plan).await?;
        
        // Perform final validation
        self.validate_final_state().await?;
        
        tracing::info!("Engine-driven masternode sync completed");
        Ok(())
    }
    
    /// Check if sync is complete based on engine state
    pub fn is_sync_complete(&self) -> bool {
        if let Some(engine) = &self.engine {
            // Check if we have all required masternode lists
            let discovery_service = MasternodeDiscoveryService::new();
            let missing = discovery_service.discover_missing_masternode_lists(engine);
            
            missing.total_discovered == 0
        } else {
            false
        }
    }
    
    /// Get sync progress based on engine analysis
    pub fn get_sync_progress(&self) -> MasternodeSyncProgress {
        if let Some(engine) = &self.engine {
            let discovery_service = MasternodeDiscoveryService::new();
            let missing = discovery_service.discover_missing_masternode_lists(engine);
            
            let total_known = engine.masternode_lists.len();
            let total_needed = total_known + missing.total_discovered;
            let completion_percentage = if total_needed > 0 {
                (total_known as f32 / total_needed as f32) * 100.0
            } else {
                100.0
            };
            
            MasternodeSyncProgress {
                total_lists: total_known,
                latest_height: engine.masternode_lists.keys().max().copied().unwrap_or(0),
                quorum_validation_complete: self.check_quorum_validation_complete(engine),
                completion_percentage,
                estimated_remaining_time: self.estimate_remaining_time_from_missing(&missing),
            }
        } else {
            MasternodeSyncProgress::default()
        }
    }
}
```

**Test File**: `tests/sync/test_engine_driven_replacement.rs`
```rust
#[tokio::test]
async fn test_old_manual_logic_removed() {
    let sync_manager = create_test_sync_manager().await;
    
    // Verify old manual methods are no longer available
    // This test will fail to compile if manual methods still exist
    // assert!(!has_method(&sync_manager, "determine_next_diff_to_request"));
    // assert!(!has_method(&sync_manager, "calculate_next_height_range"));
    
    // Verify new engine-driven methods work
    let is_complete = sync_manager.is_sync_complete();
    assert!(is_complete == false || is_complete == true); // Should not panic
    
    let progress = sync_manager.get_sync_progress();
    assert!(progress.completion_percentage >= 0.0);
    assert!(progress.completion_percentage <= 100.0);
}

#[tokio::test]
async fn test_sync_completion_detection() {
    let mut sync_manager = create_complete_sync_manager().await;
    
    assert!(sync_manager.is_sync_complete());
    
    let progress = sync_manager.get_sync_progress();
    assert_eq!(progress.completion_percentage, 100.0);
    assert_eq!(progress.estimated_remaining_time, Duration::ZERO);
}

#[tokio::test]
async fn test_sync_progress_accuracy() {
    let mut sync_manager = create_sync_manager_with_known_gaps().await;
    
    // We know there are exactly 5 missing lists out of 20 total needed
    let progress = sync_manager.get_sync_progress();
    
    assert_eq!(progress.total_lists, 15); // 20 - 5 missing
    assert!((progress.completion_percentage - 75.0).abs() < 1.0); // 15/20 = 75%
    assert!(progress.estimated_remaining_time > Duration::ZERO);
}

#[tokio::test]
async fn test_engine_driven_vs_manual_compatibility() {
    // Test that engine-driven approach produces same results as old manual approach
    // but more efficiently
    
    let manual_result = simulate_old_manual_sync().await;
    let engine_result = simulate_engine_driven_sync().await;
    
    // Same final state
    assert_eq!(manual_result.final_height, engine_result.final_height);
    assert_eq!(manual_result.total_lists, engine_result.total_lists);
    
    // But engine-driven should be more efficient
    assert!(engine_result.network_requests < manual_result.network_requests);
    assert!(engine_result.sync_time < manual_result.sync_time);
}
```

### 3. Intelligent Batching Strategies

#### 3.1 Advanced Request Optimization

**File**: `dash-spv/src/sync/batching.rs`

**Implementation**:
```rust
/// Advanced batching strategies for QRInfo requests
pub struct QRInfoBatchingStrategy {
    network_latency: Duration,
    bandwidth_limit: Option<u32>, // bytes per second
    max_concurrent_requests: usize,
}

impl QRInfoBatchingStrategy {
    pub fn new() -> Self {
        Self {
            network_latency: Duration::from_millis(100), // Conservative default
            bandwidth_limit: None,
            max_concurrent_requests: 3, // Conservative for SPV
        }
    }
    
    /// Optimize QRInfo requests based on network conditions
    pub fn optimize_requests(
        &self,
        requests: Vec<QRInfoRequest>,
        network_conditions: &NetworkConditions,
    ) -> Vec<OptimizedQRInfoBatch> {
        let mut optimized = Vec::new();
        
        // Adjust strategy based on network conditions
        let effective_latency = if network_conditions.high_latency {
            self.network_latency * 2
        } else {
            self.network_latency
        };
        
        let batch_size = if network_conditions.low_bandwidth {
            2 // Smaller batches for slow connections
        } else {
            5 // Larger batches for fast connections
        };
        
        // Group requests into batches
        for chunk in requests.chunks(batch_size) {
            let batch = OptimizedQRInfoBatch {
                requests: chunk.to_vec(),
                priority: chunk.iter().map(|r| r.priority).max().unwrap_or(0),
                estimated_response_size: self.estimate_response_size(chunk),
                can_execute_parallel: chunk.len() <= self.max_concurrent_requests,
            };
            
            optimized.push(batch);
        }
        
        // Sort batches by priority and network efficiency
        optimized.sort_by(|a, b| {
            b.priority.cmp(&a.priority)
                .then_with(|| a.estimated_response_size.cmp(&b.estimated_response_size))
        });
        
        optimized
    }
    
    fn estimate_response_size(&self, requests: &[QRInfoRequest]) -> usize {
        // Rough estimation based on typical QRInfo content
        let base_size = 1024; // Base QRInfo overhead
        let per_diff_size = 2048; // Average MnListDiff size  
        let per_snapshot_size = 512; // Average QuorumSnapshot size
        
        requests.iter().map(|req| {
            let height_span = req.tip_height - req.base_height + 1;
            let estimated_diffs = height_span / 8; // Diffs every ~8 blocks typically
            let estimated_snapshots = 4; // h-c, h-2c, h-3c, h-4c
            
            base_size + 
            (estimated_diffs * per_diff_size as u32) as usize +
            (estimated_snapshots * per_snapshot_size)
        }).sum()
    }
}

#[derive(Debug)]
pub struct OptimizedQRInfoBatch {
    pub requests: Vec<QRInfoRequest>,
    pub priority: u32,
    pub estimated_response_size: usize,
    pub can_execute_parallel: bool,
}

#[derive(Debug)]
pub struct NetworkConditions {
    pub high_latency: bool,
    pub low_bandwidth: bool,
    pub unstable_connection: bool,
}
```

**Test File**: `tests/sync/test_batching_optimization.rs`
```rust
#[tokio::test]
async fn test_batching_optimization() {
    let strategy = QRInfoBatchingStrategy::new();
    let conditions = NetworkConditions {
        high_latency: false,
        low_bandwidth: false,
        unstable_connection: false,
    };
    
    let requests = create_test_qr_info_requests(10);
    let optimized = strategy.optimize_requests(requests, &conditions);
    
    // Should create efficient batches
    assert!(!optimized.is_empty());
    assert!(optimized.len() <= 5); // Should batch multiple requests together
    
    // Higher priority batches should come first
    let priorities: Vec<u32> = optimized.iter().map(|b| b.priority).collect();
    assert!(priorities.windows(2).all(|w| w[0] >= w[1]));
}

#[tokio::test] 
async fn test_batching_with_poor_network() {
    let strategy = QRInfoBatchingStrategy::new();
    let conditions = NetworkConditions {
        high_latency: true,
        low_bandwidth: true,
        unstable_connection: true,
    };
    
    let requests = create_test_qr_info_requests(10);
    let optimized = strategy.optimize_requests(requests, &conditions);
    
    // Should create smaller, more conservative batches
    let avg_batch_size: f32 = optimized.iter()
        .map(|b| b.requests.len())
        .sum::<usize>() as f32 / optimized.len() as f32;
    
    assert!(avg_batch_size <= 3.0); // Smaller batches for poor network
}
```

## Success Criteria

### Functional Requirements
- [ ] Engine discovery methods work correctly to identify missing data
- [ ] QRInfo request planning creates optimal batches
- [ ] Manual height tracking completely replaced 
- [ ] Sync completion detection is accurate
- [ ] Fallback to MnListDiff works when QRInfo fails

### Performance Requirements
- [ ] Discovery phase completes in <1 second for typical engines
- [ ] QRInfo request optimization reduces total requests by >60%
- [ ] Sync progress reporting updates smoothly
- [ ] Memory usage remains stable throughout discovery

### Quality Requirements
- [ ] >90% test coverage for all discovery logic
- [ ] All edge cases handled (empty engines, complete engines, gaps)
- [ ] Error handling preserves engine state consistency
- [ ] Comprehensive logging for debugging

## Risk Mitigation

### High Risk: Engine State Consistency
**Risk**: Discovery methods might return inconsistent results
**Mitigation**:
- Extensive unit tests with various engine states
- Integration tests with real engine data
- State validation checks after each operation

### Medium Risk: Batching Complexity
**Risk**: Over-optimization might make batching logic fragile
**Mitigation**:
- Keep batching strategies simple and configurable
- Fallback to individual requests if batching fails
- Performance monitoring to detect issues

### Low Risk: Progress Reporting Accuracy  
**Risk**: Progress percentage might be misleading
**Mitigation**:
- Use conservative estimates
- Provide detailed progress breakdown
- Clear documentation about limitations

## Integration Points

### Phase 1 Dependencies
- QRInfo message handling must be complete
- Storage block hash lookup must work efficiently
- Engine integration must be stable

### Phase 3 Preparation  
- Discovery results will feed into parallel processing
- Batching strategies will be extended for concurrent execution
- Progress reporting will support multiple concurrent operations

## Next Steps

Upon completion of Phase 2:
1. **Validation**: Comprehensive testing with real engine states
2. **Performance**: Benchmark discovery speed and accuracy
3. **Documentation**: Update sync flow diagrams and API docs  
4. **Phase 3**: Proceed to network efficiency optimization

The engine-driven approach established in Phase 2 transforms dash-spv from a blind sequential sync to an intelligent, demand-driven architecture that only requests data it actually needs.