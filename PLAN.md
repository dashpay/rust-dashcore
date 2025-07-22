# Smart Quorum Fetching Algorithm Plan

## Overview

This plan describes an optimized algorithm for fetching masternode lists in dash-spv. Instead of requesting all 30,000 blocks individually (current approach), we'll use knowledge of DKG (Distributed Key Generation) intervals and mining windows to request only blocks that are likely to contain quorum commitments.

## Problem Statement

Currently, when Platform SDK needs masternode lists for recent blocks, dash-spv requests diffs for every single block in the last 30,000 blocks. However:
- Most blocks don't contain quorum updates
- Quorums are only mined during specific DKG mining windows
- This results in ~95% wasted network requests

## Solution Overview

Use a smart, adaptive algorithm that:
1. Calculates DKG windows for all active quorum types
2. Starts by checking the first block of each mining window
3. If quorum not found, checks the next block (adaptive search)
4. Stops when quorum is found or window is exhausted

## Implementation Plan

### Phase 1: Core Infrastructure in rust-dashcore

**File**: `/Users/quantum/src/rust-dashcore/dash/src/sml/llmq_type/mod.rs`

```rust
/// Represents a DKG (Distributed Key Generation) mining window
/// This is the range of blocks where a quorum commitment can be mined
#[derive(Clone, Debug, PartialEq)]
pub struct DKGWindow {
    /// The first block of the DKG cycle (e.g., 0, 24, 48, 72...)
    pub cycle_start: u32,
    /// First block where mining can occur (cycle_start + mining_window_start)
    pub mining_start: u32,
    /// Last block where mining can occur (cycle_start + mining_window_end)
    pub mining_end: u32,
    /// The quorum type this window is for
    pub llmq_type: LLMQType,
}

impl LLMQType {
    /// Calculate the cycle base height for a given block height
    /// (This may already exist but adding for clarity)
    pub fn get_cycle_base_height(&self, height: u32) -> u32 {
        let interval = self.params().dkg_params.interval;
        (height / interval) * interval
    }
    
    /// Get the DKG window that would contain a commitment mined at the given height
    pub fn get_dkg_window_for_height(&self, height: u32) -> DKGWindow {
        let params = self.params();
        let cycle_start = self.get_cycle_base_height(height);
        
        // For rotating quorums, the mining window calculation is different
        let mining_start = if self.is_rotating_quorum_type() {
            // For rotating quorums: signingActiveQuorumCount + dkgPhaseBlocks * 5
            cycle_start + params.signing_active_quorum_count + params.dkg_params.phase_blocks * 5
        } else {
            // For non-rotating quorums: use the standard mining window start
            cycle_start + params.dkg_params.mining_window_start
        };
        
        let mining_end = cycle_start + params.dkg_params.mining_window_end;
        
        DKGWindow {
            cycle_start,
            mining_start,
            mining_end,
            llmq_type: *self,
        }
    }
    
    /// Get all DKG windows that could have mining activity in the given range
    /// 
    /// Example: If range is 100-200 and DKG interval is 24:
    /// - Cycles: 96, 120, 144, 168, 192
    /// - For each cycle, check if its mining window (e.g., cycle+10 to cycle+18) 
    ///   overlaps with our range [100, 200]
    /// - Return only windows where mining could occur within our range
    pub fn get_dkg_windows_in_range(&self, start: u32, end: u32) -> Vec<DKGWindow> {
        let params = self.params();
        let interval = params.dkg_params.interval;
        
        let mut windows = Vec::new();
        
        // Start from the cycle that could contain 'start'
        // Go back one full cycle to catch windows that might extend into our range
        let first_possible_cycle = ((start.saturating_sub(params.dkg_params.mining_window_end)) / interval) * interval;
        
        let mut cycle_start = first_possible_cycle;
        while cycle_start <= end {
            let window = self.get_dkg_window_for_height(cycle_start);
            
            // Include this window if its mining period overlaps with [start, end]
            if window.mining_end >= start && window.mining_start <= end {
                windows.push(window);
            }
            
            cycle_start += interval;
        }
        
        windows
    }
}
```

**File**: `/Users/quantum/src/rust-dashcore/dash/src/sml/llmq_type/network.rs`

```rust
use std::collections::BTreeMap;
use super::{LLMQType, DKGWindow};

/// Extension trait for Network to provide LLMQ-specific functionality
pub trait NetworkLLMQExt {
    fn enabled_llmq_types(&self) -> Vec<LLMQType>;
    fn get_all_dkg_windows(&self, start: u32, end: u32) -> BTreeMap<u32, Vec<DKGWindow>>;
    fn should_skip_quorum_type(&self, llmq_type: &LLMQType, height: u32) -> bool;
}

impl NetworkLLMQExt for Network {
    /// Get all enabled LLMQ types for this network
    fn enabled_llmq_types(&self) -> Vec<LLMQType> {
        match self {
            Network::Dash => vec![
                LLMQType::Llmqtype50_60,    // InstantSend
                LLMQType::Llmqtype60_75,    // InstantSend DIP24 (rotating)
                LLMQType::Llmqtype400_60,   // ChainLocks
                LLMQType::Llmqtype400_85,   // Platform/Evolution
                LLMQType::Llmqtype100_67,   // Platform consensus
            ],
            Network::Testnet => vec![
                LLMQType::Llmqtype50_60,    // InstantSend & ChainLocks on testnet
                LLMQType::Llmqtype60_75,    // InstantSend DIP24 (rotating)
                // Note: 400_60 and 400_85 are included but may not mine on testnet
                LLMQType::Llmqtype25_67,    // Platform consensus (smaller for testnet)
            ],
            Network::Devnet => vec![
                LLMQType::LlmqtypeDevnet,
                LLMQType::LlmqtypeDevnetDIP0024,
                LLMQType::LlmqtypeDevnetPlatform,
            ],
            Network::Regtest => vec![
                LLMQType::LlmqtypeTest,
                LLMQType::LlmqtypeTestDIP0024,
                LLMQType::LlmqtypeTestInstantSend,
            ],
        }
    }
    
    /// Get all DKG windows in the given range for all active quorum types
    fn get_all_dkg_windows(&self, start: u32, end: u32) -> BTreeMap<u32, Vec<DKGWindow>> {
        let mut windows_by_height: BTreeMap<u32, Vec<DKGWindow>> = BTreeMap::new();
        
        for llmq_type in self.enabled_llmq_types() {
            // Skip platform quorums before activation if needed
            if self.should_skip_quorum_type(&llmq_type, start) {
                continue;
            }
            
            for window in llmq_type.get_dkg_windows_in_range(start, end) {
                // Group windows by their mining start for efficient fetching
                windows_by_height
                    .entry(window.mining_start)
                    .or_insert_with(Vec::new)
                    .push(window);
            }
        }
        
        windows_by_height
    }
    
    /// Check if a quorum type should be skipped at the given height
    fn should_skip_quorum_type(&self, llmq_type: &LLMQType, height: u32) -> bool {
        match (self, llmq_type) {
            (Network::Dash, LLMQType::Llmqtype100_67) => height < 1_888_888, // Platform activation on mainnet
            (Network::Testnet, LLMQType::Llmqtype25_67) => height < 1_289_520, // Platform activation on testnet
            _ => false,
        }
    }
}
```

### Phase 2: Smart Fetching State Machine in dash-spv

**File**: `/Users/quantum/src/rust-dashcore/dash-spv/src/sync/masternodes.rs`

```rust
use std::collections::{BTreeMap, BTreeSet};
use dashcore::sml::llmq_type::{LLMQType, DKGWindow};
use dashcore::sml::llmq_type::network::NetworkLLMQExt;
use crate::network::message_mnlistdiff::MnListDiff;

// Buffer size for masternode list (40,000 blocks)
const MASTERNODE_LIST_BUFFER_SIZE: u32 = 40_000;

/// Tracks the state of smart DKG-based masternode diff fetching
#[derive(Debug, Clone)]
struct DKGFetchState {
    /// DKG windows we haven't started checking yet
    /// Grouped by mining_start height for efficient processing
    pending_windows: BTreeMap<u32, Vec<DKGWindow>>,
    
    /// Windows we're currently checking
    /// Each entry is (window, current_block_to_check)
    active_windows: Vec<(DKGWindow, u32)>,
    
    /// Cycles we've finished checking (either found quorum or exhausted window)
    /// Key is (quorum_type, cycle_start) to uniquely identify each DKG cycle
    completed_cycles: BTreeSet<(LLMQType, u32)>,
    
    /// Blocks we've already requested to avoid duplicates
    requested_blocks: BTreeSet<u32>,
    
    /// Track if we found expected quorums for reporting
    quorums_found: usize,
    windows_exhausted: usize,
}

impl MasternodeSyncManager {
    /// Request masternode diffs using smart DKG window-based algorithm
    /// 
    /// The algorithm works as follows:
    /// 1. For large ranges, do a bulk fetch first to get close to target
    /// 2. For the recent blocks, calculate DKG windows for all active quorum types
    /// 3. Start checking the first block of each mining window
    /// 4. If quorum not found, check next block in window (adaptive search)
    /// 5. Stop checking a window once quorum is found or window is exhausted
    async fn request_masternode_diffs_smart(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &dyn StorageManager,
        base_height: u32,
        target_height: u32,
    ) -> SyncResult<()> {
        use dashcore::sml::llmq_type::network::NetworkLLMQExt;
        
        if target_height <= base_height {
            return Ok(());
        }
        
        // Step 1: For very large ranges, do bulk fetch to get most of the way
        // This avoids checking thousands of DKG windows
        let bulk_end = target_height.saturating_sub(MASTERNODE_LIST_BUFFER_SIZE);
        if bulk_end > base_height {
                tracing::info!(
                    "Large range detected: bulk fetching {} to {}, then smart fetch {} to {}",
                    base_height, bulk_end, bulk_end, target_height
                );
                
                self.request_masternode_diff(network, storage, base_height, bulk_end).await?;
                self.expected_diffs_count = 1;
                self.bulk_diff_target_height = Some(bulk_end);
                self.smart_fetch_range = Some((bulk_end, target_height));
                
                // Initialize state for smart fetch after bulk completes
                self.dkg_fetch_state = Some(DKGFetchState {
                    pending_windows: BTreeMap::new(),
                    active_windows: Vec::new(),
                    completed_cycles: BTreeSet::new(),
                    requested_blocks: BTreeSet::new(),
                    quorums_found: 0,
                    windows_exhausted: 0,
                });
                
                return Ok(());
            }
        
        // Step 2: Calculate all DKG windows for the range
        let all_windows = self.config.network.get_all_dkg_windows(base_height, target_height);
        
        // Initialize fetch state
        let mut fetch_state = DKGFetchState {
            pending_windows: all_windows,
            active_windows: Vec::new(),
            completed_cycles: BTreeSet::new(),
            requested_blocks: BTreeSet::new(),
            quorums_found: 0,
            windows_exhausted: 0,
        };
        
        // Calculate estimates for logging
        let total_windows: usize = fetch_state.pending_windows.values()
            .map(|v| v.len())
            .sum();
        let total_possible_blocks: usize = fetch_state.pending_windows.values()
            .flat_map(|windows| windows.iter())
            .map(|w| (w.mining_end - w.mining_start + 1) as usize)
            .sum();
        
        tracing::info!(
            "Smart masternode sync: checking {} DKG windows ({} possible blocks) out of {} total blocks",
            total_windows,
            total_possible_blocks,
            target_height - base_height
        );
        
        self.dkg_fetch_state = Some(fetch_state);
        
        // Step 3: Start fetching
        self.fetch_next_dkg_blocks(network, storage).await?;
        
        Ok(())
    }
    
    /// Fetch the next batch of blocks based on DKG window state
    /// 
    /// This function:
    /// 1. Moves pending windows to active (up to MAX_ACTIVE_WINDOWS)
    /// 2. For each active window, requests the current block being checked
    /// 3. Batches requests for efficiency (up to MAX_REQUESTS_PER_BATCH)
    /// 
    /// Note: We await here because we're making network requests
    async fn fetch_next_dkg_blocks(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &dyn StorageManager,
    ) -> SyncResult<()> {
        let Some(state) = &mut self.dkg_fetch_state else {
            return Ok(());
        };
        
        // Step 1: Activate pending windows if we have capacity
        // MAX_ACTIVE_WINDOWS: Limits how many DKG windows we're tracking simultaneously
        // This prevents memory bloat and helps us focus on completing windows before starting new ones
        const MAX_ACTIVE_WINDOWS: usize = 10;
        while state.active_windows.len() < MAX_ACTIVE_WINDOWS {
            if let Some((mining_start, windows)) = state.pending_windows.pop_first() {
                // Start each window at its mining_start block
                for window in windows {
                    tracing::trace!(
                        "Activating {} window: cycle {} (mining {}-{})",
                        window.llmq_type,
                        window.cycle_start,
                        window.mining_start,
                        window.mining_end
                    );
                    state.active_windows.push((window, mining_start));
                }
            } else {
                break; // No more pending windows
            }
        }
        
        // Step 2: Request blocks for active windows
        let mut requests_made = 0;
        // MAX_REQUESTS_PER_BATCH: Limits network requests per call to avoid overwhelming peers
        // Different from MAX_ACTIVE_WINDOWS - we may have 10 active windows but only request 5 blocks at once
        const MAX_REQUESTS_PER_BATCH: usize = 5;
        
        for (window, current_block) in &state.active_windows {
            if requests_made >= MAX_REQUESTS_PER_BATCH {
                break;
            }
            
            // Only request if:
            // 1. We're still within the mining window
            // 2. We haven't already requested this block
            if *current_block <= window.mining_end && !state.requested_blocks.contains(current_block) {
                tracing::debug!(
                    "Requesting block {} for {} quorum (cycle {}, window {}-{})",
                    current_block,
                    window.llmq_type,
                    window.cycle_start,
                    window.mining_start,
                    window.mining_end
                );
                
                self.request_masternode_diff(network, storage, *current_block, *current_block + 1).await?;
                state.requested_blocks.insert(*current_block);
                requests_made += 1;
            }
        }
        
        self.expected_diffs_count += requests_made as u32;
        
        Ok(())
    }
    
    /// Process a masternode diff and update DKG fetch state
    /// 
    /// This is called after process_masternode_diff completes successfully
    async fn process_masternode_diff_smart(
        &mut self,
        diff: MnListDiff,
        diff_height: u32,
        storage: &mut dyn StorageManager,
        network: &mut dyn NetworkManager,
    ) -> SyncResult<()> {
        let Some(state) = &mut self.dkg_fetch_state else {
            return Ok(());
        };
        
        // Check which windows this diff might satisfy
        let window_updates = self.check_diff_against_active_windows(&diff, diff_height, state);
        
        // Apply the updates
        self.apply_window_updates(window_updates, state);
        
        // Continue fetching if we have more work
        if !state.pending_windows.is_empty() || !state.active_windows.is_empty() {
            self.fetch_next_dkg_blocks(network, storage).await?;
        } else {
            // All done! Log summary
            tracing::info!(
                "Smart masternode sync complete: found {} quorums, exhausted {} windows, requested {} blocks",
                state.quorums_found,
                state.windows_exhausted,
                state.requested_blocks.len()
            );
            self.dkg_fetch_state = None;
        }
        
        Ok(())
    }
    
    /// Check which active windows are affected by this diff
    /// Returns a list of (window_index, action) where action is either:
    /// - Advance(next_block): Try next block in window
    /// - Complete(found): Window complete, quorum found
    /// - Exhaust: Window complete, no quorum found
    fn check_diff_against_active_windows(
        &self,
        diff: &MnListDiff,
        diff_height: u32,
        state: &DKGFetchState,
    ) -> Vec<(usize, WindowAction)> {
        let mut updates = Vec::new();
        
        for (i, (window, current_block)) in state.active_windows.iter().enumerate() {
            if *current_block == diff_height {
                // This diff is for a block we're checking
                
                // Check if we found the quorum type we're looking for
                let found_expected_quorum = diff.new_quorums.iter()
                    .any(|q| q.llmq_type == window.llmq_type);
                
                if found_expected_quorum {
                    // Success! Found the quorum
                    updates.push((i, WindowAction::Complete));
                } else if diff_height < window.mining_end {
                    // Didn't find it yet, try next block
                    updates.push((i, WindowAction::Advance(diff_height + 1)));
                } else {
                    // Reached end of window without finding quorum
                    updates.push((i, WindowAction::Exhaust));
                }
            }
        }
        
        updates
    }
    
    /// Apply window updates from check_diff_against_active_windows
    fn apply_window_updates(
        &mut self,
        updates: Vec<(usize, WindowAction)>,
        state: &mut DKGFetchState,
    ) {
        // Process in reverse order to maintain indices
        for (i, action) in updates.iter().rev() {
            let (window, _) = &state.active_windows[*i];
            
            match action {
                WindowAction::Advance(next_block) => {
                    // Update to check next block
                    state.active_windows[*i].1 = *next_block;
                }
                WindowAction::Complete => {
                    // Remove from active and mark as complete
                    let (window, _) = state.active_windows.remove(*i);
                    state.completed_cycles.insert((window.llmq_type, window.cycle_start));
                    state.quorums_found += 1;
                    
                    tracing::debug!(
                        "Found {} quorum at cycle {} after checking {} blocks",
                        window.llmq_type,
                        window.cycle_start,
                        state.requested_blocks.iter()
                            .filter(|&&b| b >= window.mining_start && b <= window.mining_end)
                            .count()
                    );
                }
                WindowAction::Exhaust => {
                    // Remove from active, window exhausted
                    let (window, _) = state.active_windows.remove(*i);
                    state.completed_cycles.insert((window.llmq_type, window.cycle_start));
                    state.windows_exhausted += 1;
                    
                    tracing::debug!(
                        "No {} quorum found in cycle {} mining window ({}-{})",
                        window.llmq_type,
                        window.cycle_start,
                        window.mining_start,
                        window.mining_end
                    );
                }
            }
        }
    }
}

/// Actions to take on a DKG window after processing a diff
enum WindowAction {
    /// Continue checking at the specified next block
    Advance(u32),
    /// Window is complete - quorum was found
    Complete,
    /// Window exhausted without finding quorum (reached end of mining window)
    Exhaust,
}
```

### Phase 3: Integration Points

**Update MasternodeSyncManager struct to include new state**:
```rust
pub struct MasternodeSyncManager {
    // ... existing fields ...
    
    /// Range for smart fetch after bulk completes
    smart_fetch_range: Option<(u32, u32)>,
    
    /// Target height for bulk diff fetch
    bulk_diff_target_height: Option<u32>,
    
    /// DKG-based fetch state
    dkg_fetch_state: Option<DKGFetchState>,
}
```

**Update existing caller to use smart algorithm**:
```rust
// Replace existing request_masternode_diffs_for_chainlock_validation
// with request_masternode_diffs_smart
pub async fn request_masternode_diffs_for_chainlock_validation(
    &mut self,
    network: &mut dyn NetworkManager,
    storage: &dyn StorageManager,
    base_height: u32,
    target_height: u32,
) -> SyncResult<()> {
    // Now uses smart algorithm for ALL ranges
    self.request_masternode_diffs_smart(network, storage, base_height, target_height).await
}
```

**Update process_masternode_diff to handle smart fetch**:
```rust
// In process_masternode_diff, after successfully processing:
if self.dkg_fetch_state.is_some() {
    // Check if this diff is part of smart fetch
    if let Some((start, end)) = self.smart_fetch_range {
        if diff_height >= start && diff_height <= end {
            self.process_masternode_diff_smart(diff, diff_height, storage, network).await?;
        }
    }
}

// Handle transition from bulk to smart fetch
if let Some(bulk_target) = self.bulk_diff_target_height {
    if diff_height == bulk_target {
        // Bulk fetch complete, start smart fetch
        if let Some((start, end)) = self.smart_fetch_range {
            let all_windows = self.config.network.get_all_dkg_windows(start, end);
            self.dkg_fetch_state = Some(DKGFetchState {
                pending_windows: all_windows,
                active_windows: Vec::new(),
                completed_cycles: BTreeSet::new(),
                requested_blocks: BTreeSet::new(),
                quorums_found: 0,
                windows_exhausted: 0,
            });
            self.fetch_next_dkg_blocks(network, storage).await?;
        }
        self.bulk_diff_target_height = None;
    }
}
```

## Expected Benefits

1. **Network Efficiency**: 
   - Mainnet: ~1,250 requests instead of 30,000 (96% reduction)
   - Only request blocks that actually contain quorums

2. **Correctness**:
   - All quorum types properly handled
   - Mining windows correctly calculated
   - No missing quorums for Platform SDK

3. **Performance**:
   - Faster sync due to fewer requests
   - Batch processing for efficiency
   - Smart range grouping to minimize requests

## Testing Strategy

### 1. Core Algorithm Tests

**DKG Window Calculation Tests**:
```rust
#[test]
fn test_get_cycle_base_height() {
    let llmq = LLMQType::Llmqtype50_60; // interval 24
    assert_eq!(llmq.get_cycle_base_height(0), 0);
    assert_eq!(llmq.get_cycle_base_height(23), 0);
    assert_eq!(llmq.get_cycle_base_height(24), 24);
    assert_eq!(llmq.get_cycle_base_height(50), 48);
}

#[test]
fn test_rotating_quorum_mining_window() {
    let llmq = LLMQType::Llmqtype60_75; // rotating quorum
    let window = llmq.get_dkg_window_for_height(288);
    // For rotating: cycle_start + signingActiveQuorumCount + dkgPhaseBlocks * 5
    // 288 + 32 + 2 * 5 = 330
    assert_eq!(window.mining_start, 330);
    assert_eq!(window.mining_end, 338);
}

#[test]
fn test_get_dkg_windows_in_range_edge_cases() {
    // Test range that starts in middle of mining window
    // Test range smaller than one DKG interval
    // Test range that spans multiple quorum types with different intervals
}
```

**State Machine Tests**:
```rust
#[test]
fn test_window_activation_limits() {
    // Verify MAX_ACTIVE_WINDOWS is respected
    // Add 20 pending windows, verify only 10 become active
}

#[test]
fn test_request_batching() {
    // Verify MAX_REQUESTS_PER_BATCH limits network calls
    // With 10 active windows, should only make 5 requests per batch
}

#[test]
fn test_duplicate_request_prevention() {
    // Verify same block isn't requested twice
    // Important when multiple quorum types have overlapping windows
}
```

### 2. Adaptive Search Tests

```rust
#[test]
fn test_quorum_found_first_block() {
    // Mock diff with quorum at mining_start
    // Verify window marked complete, no additional requests
}

#[test]
fn test_quorum_found_middle_of_window() {
    // Mock empty diffs for first 3 blocks
    // Mock quorum found on 4th block
    // Verify exactly 4 requests made
}

#[test]
fn test_window_exhaustion() {
    // Mock all diffs in window without quorum
    // Verify window marked as exhausted
    // Verify stats track exhausted windows correctly
}
```

### 3. Edge Case Tests

```rust
#[test]
fn test_platform_quorum_activation() {
    // Test mainnet at height 1,888,887 (no platform quorums)
    // Test mainnet at height 1,888,888 (platform quorums active)
    // Verify Llmqtype100_67 only included after activation
}

#[test]
fn test_overlapping_mining_windows() {
    // Some quorum types may have overlapping mining windows
    // Verify we don't miss quorums due to shared blocks
}

#[test]
fn test_bulk_to_smart_transition() {
    // Test range 0 to 40,000
    // Verify bulk fetch to 10,000, then smart fetch 10,000-40,000
    // Verify state properly initialized after bulk completes
}
```

### 4. Performance Benchmarks

```rust
#[bench]
fn bench_calculate_windows_mainnet_30k() {
    // Benchmark window calculation for 30k block range
    // Should complete in microseconds, not milliseconds
}

#[bench]
fn bench_smart_vs_brute_force() {
    // Mock network that counts requests
    // Compare smart algorithm vs requesting every block
    // Verify 96% reduction in requests
}
```

### 5. Integration Tests

```rust
#[tokio::test]
async fn test_real_network_sync() {
    // Test against actual testnet/devnet
    // Pick known height ranges with documented quorums
    // Verify all expected quorums found
}

#[test]
fn test_masternode_list_continuity() {
    // Verify masternode lists remain valid after smart sync
    // Check merkle roots match expected values
    // Ensure Platform SDK can verify proofs
}
```

### 6. Regression Tests

```rust
#[test]
fn test_known_problematic_heights() {
    // Test specific heights that caused issues:
    // - Height 1260379 (original quorum not found error)
    // - Heights with multiple quorum types mining
    // - Heights at DKG interval boundaries
}
```

### 7. Monitoring and Metrics

- Add metrics for:
  - Total windows checked vs windows with quorums
  - Average blocks checked per window before finding quorum
  - Time saved vs brute force approach
  - Memory usage of active window tracking

### 8. Failure Mode Tests

```rust
#[test]
fn test_network_failure_recovery() {
    // Simulate network failures mid-sync
    // Verify state can resume properly
}

#[test]
fn test_malformed_diff_handling() {
    // Test diffs with unexpected quorum types
    // Test diffs at wrong heights
    // Verify graceful handling
}
```

## Implementation Order

1. Add core DKG window calculations to rust-dashcore
2. Add network-specific quorum type enumeration
3. Implement smart fetch state machine in dash-spv
4. Add integration points to existing code
5. Add comprehensive test coverage
6. Performance testing and validation

## Resolved Questions

1. **DKG Interval for Platform Quorums**: The `Llmqtype100_67` interval was corrected from 2 to 24.

2. **Testnet Quorum Types**: The active quorum types for Testnet are `Llmqtype50_60`, `Llmqtype60_75`, and `Llmqtype25_67`. The other types are not active on testnet.

3. **MnListDiff Structure**: The `new_quorums` field in `MnListDiff` is a `Vec<QuorumEntry>`. The `llmq_type` is a direct field of `QuorumEntry`.

4. **Parallel Requests**: We will not parallelize requests within a batch for now.

5. **Error Handling**: We will not worry about partial window fetches if the network fails mid-window.