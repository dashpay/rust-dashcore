# Sequential Sync Design Document

## Overview

This document outlines the design for transforming dash-spv from an interleaved sync approach to a strict sequential sync pipeline.

## State Machine Design

### Core State Enum

```rust
#[derive(Debug, Clone, PartialEq)]
pub enum SyncPhase {
    /// Not syncing, waiting to start
    Idle,
    
    /// Phase 1: Downloading headers
    DownloadingHeaders {
        start_time: Instant,
        start_height: u32,
        current_height: u32,
        target_height: Option<u32>,
        last_progress: Instant,
        headers_per_second: f64,
    },
    
    /// Phase 2: Downloading masternode lists
    DownloadingMnList {
        start_time: Instant,
        start_height: u32,
        current_height: u32,
        target_height: u32,
        last_progress: Instant,
    },
    
    /// Phase 3: Downloading compact filter headers
    DownloadingCFHeaders {
        start_time: Instant,
        start_height: u32,
        current_height: u32,
        target_height: u32,
        last_progress: Instant,
        cfheaders_per_second: f64,
    },
    
    /// Phase 4: Downloading compact filters
    DownloadingFilters {
        start_time: Instant,
        requested_ranges: HashMap<(u32, u32), Instant>,
        completed_heights: HashSet<u32>,
        total_filters: u32,
        last_progress: Instant,
    },
    
    /// Phase 5: Downloading full blocks
    DownloadingBlocks {
        start_time: Instant,
        pending_blocks: VecDeque<(BlockHash, u32)>,
        downloading: HashMap<BlockHash, Instant>,
        completed: Vec<BlockHash>,
        last_progress: Instant,
    },
    
    /// Fully synchronized
    FullySynced {
        sync_completed_at: Instant,
        total_sync_time: Duration,
    },
}
```

### Phase Manager

```rust
pub struct SequentialSyncManager {
    /// Current sync phase
    current_phase: SyncPhase,
    
    /// Phase-specific managers (existing, but controlled)
    header_sync: HeaderSyncManager,
    filter_sync: FilterSyncManager,
    masternode_sync: MasternodeSyncManager,
    
    /// Configuration
    config: ClientConfig,
    
    /// Phase transition history
    phase_history: Vec<PhaseTransition>,
    
    /// Phase-specific request queue
    pending_requests: VecDeque<NetworkRequest>,
    
    /// Active request tracking
    active_requests: HashMap<RequestId, ActiveRequest>,
}

#[derive(Debug)]
struct PhaseTransition {
    from_phase: SyncPhase,
    to_phase: SyncPhase,
    timestamp: Instant,
    reason: String,
}
```

## Phase Lifecycle

### 1. Phase Entry
Each phase has strict entry conditions:

```rust
impl SequentialSyncManager {
    fn can_enter_phase(&self, phase: &SyncPhase) -> Result<bool, SyncError> {
        match phase {
            SyncPhase::DownloadingHeaders { .. } => Ok(true), // Always can start
            
            SyncPhase::DownloadingMnList { .. } => {
                // Headers must be 100% complete
                self.are_headers_complete()
            }
            
            SyncPhase::DownloadingCFHeaders { .. } => {
                // Headers complete AND MnList complete (or disabled)
                Ok(self.are_headers_complete()? && 
                   (self.are_masternodes_complete()? || !self.config.enable_masternodes))
            }
            
            SyncPhase::DownloadingFilters { .. } => {
                // CFHeaders must be 100% complete
                self.are_cfheaders_complete()
            }
            
            SyncPhase::DownloadingBlocks { .. } => {
                // Filters complete (or no blocks needed)
                Ok(self.are_filters_complete()? || self.no_blocks_needed())
            }
            
            _ => Ok(false),
        }
    }
}
```

### 2. Phase Execution
Each phase follows a standard pattern:

```rust
async fn execute_current_phase(&mut self, network: &mut dyn NetworkManager, storage: &mut dyn StorageManager) -> Result<PhaseAction> {
    match &self.current_phase {
        SyncPhase::DownloadingHeaders { .. } => {
            self.execute_headers_phase(network, storage).await
        }
        SyncPhase::DownloadingMnList { .. } => {
            self.execute_mnlist_phase(network, storage).await
        }
        // ... etc
    }
}

enum PhaseAction {
    Continue,           // Keep working on current phase
    TransitionTo(SyncPhase), // Move to next phase
    Error(SyncError),   // Handle error
    Complete,           // Sync fully complete
}
```

### 3. Phase Completion
Strict completion criteria for each phase:

```rust
impl SequentialSyncManager {
    async fn is_phase_complete(&self, storage: &dyn StorageManager) -> Result<bool> {
        match &self.current_phase {
            SyncPhase::DownloadingHeaders { current_height, .. } => {
                // Headers complete when we receive empty headers response
                // AND we've verified chain continuity
                let tip = storage.get_tip_height().await?;
                let peer_height = self.get_peer_reported_height().await?;
                Ok(tip == Some(peer_height) && self.last_headers_response_was_empty())
            }
            
            SyncPhase::DownloadingCFHeaders { current_height, target_height, .. } => {
                // Complete when current matches target exactly
                Ok(current_height >= target_height)
            }
            
            // ... etc
        }
    }
}
```

### 4. Phase Transition
Clean handoff between phases:

```rust
async fn transition_to_next_phase(&mut self, storage: &mut dyn StorageManager) -> Result<()> {
    let next_phase = match &self.current_phase {
        SyncPhase::Idle => SyncPhase::DownloadingHeaders { /* ... */ },
        
        SyncPhase::DownloadingHeaders { .. } => {
            if self.config.enable_masternodes {
                SyncPhase::DownloadingMnList { /* ... */ }
            } else if self.config.enable_filters {
                SyncPhase::DownloadingCFHeaders { /* ... */ }
            } else {
                SyncPhase::FullySynced { /* ... */ }
            }
        }
        
        // ... etc
    };
    
    // Log transition
    info!("📊 Phase transition: {:?} -> {:?}", self.current_phase, next_phase);
    
    // Record history
    self.phase_history.push(PhaseTransition {
        from_phase: self.current_phase.clone(),
        to_phase: next_phase.clone(),
        timestamp: Instant::now(),
        reason: "Phase completed successfully".to_string(),
    });
    
    // Clean up current phase
    self.cleanup_current_phase().await?;
    
    // Initialize next phase
    self.current_phase = next_phase;
    self.initialize_current_phase().await?;
    
    Ok(())
}
```

## Request Management

### Request Control Flow

```rust
impl SequentialSyncManager {
    /// All requests must go through this method
    pub async fn request(&mut self, request_type: RequestType, network: &mut dyn NetworkManager) -> Result<()> {
        // Phase validation
        if !self.is_request_allowed_in_phase(&request_type) {
            debug!("Rejecting {:?} request in phase {:?}", request_type, self.current_phase);
            return Err(SyncError::InvalidPhase);
        }
        
        // Rate limiting
        if !self.can_send_request(&request_type) {
            self.pending_requests.push_back(NetworkRequest {
                request_type,
                queued_at: Instant::now(),
            });
            return Ok(());
        }
        
        // Send request
        self.send_request(request_type, network).await
    }
    
    fn is_request_allowed_in_phase(&self, request_type: &RequestType) -> bool {
        match (&self.current_phase, request_type) {
            (SyncPhase::DownloadingHeaders { .. }, RequestType::GetHeaders(_)) => true,
            (SyncPhase::DownloadingMnList { .. }, RequestType::GetMnListDiff(_)) => true,
            (SyncPhase::DownloadingCFHeaders { .. }, RequestType::GetCFHeaders(_)) => true,
            (SyncPhase::DownloadingFilters { .. }, RequestType::GetCFilters(_)) => true,
            (SyncPhase::DownloadingBlocks { .. }, RequestType::GetBlock(_)) => true,
            _ => false,
        }
    }
}
```

### Message Filtering

```rust
impl SequentialSyncManager {
    /// Filter incoming messages based on current phase
    pub async fn handle_message(&mut self, msg: NetworkMessage, network: &mut dyn NetworkManager, storage: &mut dyn StorageManager) -> Result<()> {
        // Check if message is expected in current phase
        if !self.is_message_expected(&msg) {
            debug!("Ignoring unexpected {:?} message in phase {:?}", msg, self.current_phase);
            return Ok(());
        }
        
        // Route to appropriate handler
        match (&mut self.current_phase, msg) {
            (SyncPhase::DownloadingHeaders { .. }, NetworkMessage::Headers(headers)) => {
                self.handle_headers_in_phase(headers, network, storage).await
            }
            (SyncPhase::DownloadingCFHeaders { .. }, NetworkMessage::CFHeaders(cfheaders)) => {
                self.handle_cfheaders_in_phase(cfheaders, network, storage).await
            }
            // ... etc
            _ => Ok(()), // Ignore messages for other phases
        }
    }
}
```

## Progress Tracking

### Per-Phase Progress

```rust
impl SyncPhase {
    pub fn progress(&self) -> PhaseProgress {
        match self {
            SyncPhase::DownloadingHeaders { start_height, current_height, target_height, .. } => {
                PhaseProgress {
                    phase_name: "Headers",
                    items_completed: current_height - start_height,
                    items_total: target_height.map(|t| t - start_height),
                    percentage: calculate_percentage(*start_height, *current_height, *target_height),
                    rate: self.calculate_rate(),
                    eta: self.calculate_eta(),
                }
            }
            // ... etc
        }
    }
}
```

### Overall Progress

```rust
pub struct OverallSyncProgress {
    pub current_phase: String,
    pub phase_progress: PhaseProgress,
    pub phases_completed: Vec<String>,
    pub phases_remaining: Vec<String>,
    pub total_elapsed: Duration,
    pub estimated_total_time: Option<Duration>,
}
```

## Error Recovery

### Phase-Specific Recovery

```rust
impl SequentialSyncManager {
    async fn handle_phase_error(&mut self, error: SyncError, network: &mut dyn NetworkManager, storage: &mut dyn StorageManager) -> Result<()> {
        match &self.current_phase {
            SyncPhase::DownloadingHeaders { .. } => {
                // Retry from last known good header
                let last_good = storage.get_tip_height().await?.unwrap_or(0);
                self.restart_headers_from(last_good).await
            }
            
            SyncPhase::DownloadingCFHeaders { current_height, .. } => {
                // Retry from current_height (already validated)
                self.restart_cfheaders_from(*current_height).await
            }
            
            // ... etc
        }
    }
}
```

## Implementation Strategy

### Step 1: Create New Module Structure
```
src/sync/
├── mod.rs              # Keep existing
├── sequential/
│   ├── mod.rs          # New SequentialSyncManager
│   ├── phases.rs       # Phase definitions and state machine
│   ├── transitions.rs  # Phase transition logic
│   ├── progress.rs     # Progress tracking
│   └── recovery.rs     # Error recovery
```

### Step 2: Refactor Existing Managers
- Keep existing sync managers but make them phase-aware
- Add phase validation to their request methods
- Remove automatic interleaving behavior

### Step 3: Integration Points
- Modify `client/mod.rs` to use SequentialSyncManager
- Update `client/message_handler.rs` to route through sequential manager
- Add phase information to monitoring and logging

### Step 4: Migration Path
1. Add feature flag for sequential sync
2. Run both implementations in parallel for testing
3. Gradually migrate to sequential as default
4. Remove old interleaved code

## Testing Strategy

### Unit Tests
- Test each phase in isolation
- Test phase transitions
- Test error recovery
- Test progress calculation

### Integration Tests
- Full sync from genesis with phase verification
- Interruption and resume testing
- Network failure recovery
- Performance benchmarks

### Phase Boundary Tests
```rust
#[test]
async fn test_headers_must_complete_before_cfheaders() {
    // Setup
    let mut sync = create_test_sync_manager();
    
    // Start headers sync
    sync.start_sync().await.unwrap();
    assert_eq!(sync.current_phase(), SyncPhase::DownloadingHeaders { .. });
    
    // Try to request cfheaders - should fail
    let result = sync.request(RequestType::GetCFHeaders(..), network).await;
    assert!(matches!(result, Err(SyncError::InvalidPhase)));
    
    // Complete headers
    complete_headers_phase(&mut sync).await;
    
    // Now cfheaders should be allowed
    let result = sync.request(RequestType::GetCFHeaders(..), network).await;
    assert!(result.is_ok());
}
```

## Benefits

1. **Clarity**: Single active phase, clear state machine
2. **Reliability**: No race conditions or dependency issues  
3. **Debuggability**: Phase transitions clearly logged
4. **Performance**: Better request batching within phases
5. **Maintainability**: Easier to reason about and extend