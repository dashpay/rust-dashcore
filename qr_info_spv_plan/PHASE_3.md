# Phase 3: Network Efficiency Optimization

## Overview

This phase optimizes network efficiency by integrating parallel QRInfo processing, intelligent request scheduling, and robust error recovery with dash-spv's existing interfaces. Rather than creating new parallel components, we extend the existing sequential sync framework to support concurrent operations while maintaining compatibility.

## Objectives

1. **Integrated Parallel Processing**: Extend existing MasternodeSyncManager for concurrent QRInfo requests
2. **Enhanced Request Control**: Augment existing RequestController with parallel scheduling capabilities
3. **Extended Error Recovery**: Build upon existing RecoveryManager for parallel-aware error handling
4. **Consolidated Configuration**: Integrate parallel settings with existing client config
5. **Message Handler Integration**: Wire QRInfo correlation into existing message routing

## Integration Strategy

### 1. Extend MasternodeSyncManager for Parallel QRInfo Processing

**File**: `dash-spv/src/sync/masternodes.rs` (extend existing implementation)

**Enhancement**: Add parallel processing capability while maintaining current sequential path:

```rust
impl MasternodeSyncManager {
    /// Request multiple QRInfo requests in parallel (feature-gated enhancement)
    #[cfg(feature = "parallel-qrinfo")]
    pub async fn request_qrinfo_parallel(
        &mut self,
        network: Arc<Mutex<dyn NetworkManager>>,
        requests: Vec<QRInfoRequestSpec>,
        max_concurrent: usize,
    ) -> Result<(), String> {
        // Use existing request_qrinfo infrastructure with parallel execution
        let semaphore = Arc::new(Semaphore::new(max_concurrent));
        let mut join_set = JoinSet::new();
        
        for request_spec in requests {
            let semaphore = semaphore.clone();
            let network = network.clone();
            let mut self_clone = self.clone(); // or use Arc<Mutex<Self>>
            
            let task = async move {
                let _permit = semaphore.acquire().await?;
                
                // Reuse existing request_qrinfo method
                let mut network_guard = network.lock().await;
                self_clone.request_qrinfo(
                    &mut *network_guard,
                    request_spec.base_block_hash,
                    request_spec.block_hash,
                ).await
            };
            
            join_set.spawn(task);
        }
        
        // Wait for all requests to complete
        while let Some(result) = join_set.join_next().await {
            if let Err(e) = result? {
                tracing::warn!("Parallel QRInfo request failed: {}", e);
            }
        }
        
        Ok(())
    }
}

#[cfg(feature = "parallel-qrinfo")]
#[derive(Debug, Clone)]
pub struct QRInfoRequestSpec {
    pub base_block_hash: BlockHash,
    pub block_hash: BlockHash,
    pub priority: RequestPriority,
}

#[cfg(feature = "parallel-qrinfo")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RequestPriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}
```

### 2. Enhance RequestController for Parallel Scheduling

**File**: `dash-spv/src/sync/sequential/request_control.rs` (extend existing implementation)

**Enhancement**: Add parallel scheduling while maintaining existing rate limiting and validation:

```rust
impl RequestController {
    /// Enhanced batch processing with parallel-aware scheduling
    pub async fn process_pending_requests_with_concurrency(
        &mut self,
        phase: &SyncPhase,
        network: &mut dyn NetworkManager,
        storage: &dyn StorageManager,
        max_concurrent: Option<usize>,
    ) -> SyncResult<()> {
        let phase_name = phase.name().to_string();
        let base_max_concurrent = self.max_concurrent_requests.get(&phase_name).copied().unwrap_or(1);
        
        // Use provided concurrency limit or fall back to existing config
        let effective_max_concurrent = max_concurrent.unwrap_or(base_max_concurrent);
        
        // If concurrency is 1, use existing sequential logic
        if effective_max_concurrent <= 1 {
            return self.process_pending_requests(phase, network, storage).await;
        }
        
        // Parallel processing for higher concurrency
        let mut active_requests = Vec::new();
        let semaphore = Arc::new(Semaphore::new(effective_max_concurrent));
        
        while !self.pending_requests.is_empty() && active_requests.len() < effective_max_concurrent {
            // Check rate limit using existing logic
            if !self.check_rate_limit(&phase_name) {
                break;
            }
            
            if let Some(request) = self.pending_requests.pop_front() {
                // Validate using existing logic
                if !self.is_request_allowed(phase, &request.request_type) {
                    continue;
                }
                
                // Launch parallel request
                let permit = semaphore.clone().acquire_owned().await
                    .map_err(|_| SyncError::Network("Semaphore error".to_string()))?;
                
                let task = self.send_request_async(request, network, storage, permit);
                active_requests.push(tokio::spawn(task));
            }
        }
        
        // Wait for active requests to complete
        for task in active_requests {
            if let Err(e) = task.await {
                tracing::error!("Parallel request task failed: {}", e);
            }
        }
        
        Ok(())
    }
    
    /// Async version of send_request that releases semaphore permit on completion
    async fn send_request_async(
        &mut self,
        request: NetworkRequest,
        network: &mut dyn NetworkManager,
        storage: &dyn StorageManager,
        _permit: tokio::sync::OwnedSemaphorePermit,
    ) -> SyncResult<()> {
        // Reuse existing send_request logic
        self.send_request(request, network, storage).await
        // Permit is automatically released when dropped
    }
    
    /// Add configuration for parallel limits per phase
    pub fn set_parallel_limits(&mut self, phase: &str, max_concurrent: usize) {
        self.max_concurrent_requests.insert(phase.to_string(), max_concurrent);
    }
}
```

### 3. Extend RecoveryManager for Parallel-Aware Recovery

**File**: `dash-spv/src/sync/sequential/recovery.rs` (extend existing implementation)

**Enhancement**: Add parallel processing support to existing recovery strategies:

```rust
impl RecoveryManager {
    /// Enhanced recovery for parallel request failures
    pub fn determine_parallel_strategy(
        &mut self,
        phase: &SyncPhase,
        errors: &[SyncError],
        concurrent_failures: usize,
    ) -> Vec<RecoveryStrategy> {
        let mut strategies = Vec::new();
        
        // Check for systematic failures that indicate need to reduce concurrency
        let failure_rate = concurrent_failures as f64 / errors.len().max(1) as f64;
        
        if failure_rate > 0.5 {
            // High failure rate - reduce to sequential
            strategies.push(RecoveryStrategy::ReduceConcurrency { target_concurrent: 1 });
        } else if failure_rate > 0.3 {
            // Moderate failure rate - reduce concurrency
            strategies.push(RecoveryStrategy::ReduceConcurrency { 
                target_concurrent: (concurrent_failures / 2).max(1) 
            });
        }
        
        // Apply existing error classification to each error
        for error in errors {
            let strategy = self.determine_strategy(phase, error);
            strategies.push(strategy);
        }
        
        strategies
    }
    
    /// Track parallel request statistics
    pub fn record_parallel_attempt(&mut self, concurrent_count: usize, success_count: usize) {
        // Extend existing retry tracking with parallel metrics
        let success_rate = success_count as f64 / concurrent_count as f64;
        
        // Store in recovery history for pattern analysis
        self.recovery_history.push(RecoveryEvent {
            timestamp: std::time::Instant::now(),
            phase: "ParallelProcessing".to_string(),
            error: format!("Concurrent batch: {}/{} successful", success_count, concurrent_count),
            strategy: RecoveryStrategy::Retry { delay: Duration::ZERO },
            success: success_rate > 0.7,
        });
    }
}

// Extend existing RecoveryStrategy enum
#[derive(Debug, Clone)]
pub enum RecoveryStrategy {
    // ... existing variants ...
    
    /// Reduce concurrency for future parallel operations
    ReduceConcurrency {
        target_concurrent: usize,
    },
    
    /// Temporarily disable parallel processing
    FallbackToSequential {
        duration: Duration,
    },
}
```

### 4. Enhance ClientConfig for Consolidated Parallel Settings

**File**: `dash-spv/src/client/config.rs` (extend existing configuration)

**Enhancement**: Add parallel-specific settings to existing config structure:

```rust
impl ClientConfig {
    // Extend existing max_concurrent_filter_requests pattern
    
    /// Maximum concurrent QRInfo requests (default: 3, feature-gated)
    #[cfg(feature = "parallel-qrinfo")]
    pub max_concurrent_qrinfo_requests: usize,
    
    /// Enable adaptive concurrency based on network conditions (default: true)
    #[cfg(feature = "parallel-qrinfo")]
    pub enable_adaptive_qrinfo_concurrency: bool,
    
    /// QRInfo request timeout for parallel operations (default: 30s)
    #[cfg(feature = "parallel-qrinfo")]
    pub qrinfo_parallel_timeout: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            // ... existing defaults ...
            #[cfg(feature = "parallel-qrinfo")]
            max_concurrent_qrinfo_requests: 3,
            #[cfg(feature = "parallel-qrinfo")]
            enable_adaptive_qrinfo_concurrency: true,
            #[cfg(feature = "parallel-qrinfo")]
            qrinfo_parallel_timeout: Duration::from_secs(30),
        }
    }
}

impl ClientConfig {
    /// Configure parallel QRInfo settings (feature-gated)
    #[cfg(feature = "parallel-qrinfo")]
    pub fn with_parallel_qrinfo_settings(
        mut self,
        max_concurrent: usize,
        enable_adaptive: bool,
        timeout: Duration,
    ) -> Self {
        self.max_concurrent_qrinfo_requests = max_concurrent;
        self.enable_adaptive_qrinfo_concurrency = enable_adaptive;
        self.qrinfo_parallel_timeout = timeout;
        self
    }
    
    /// Validate parallel settings are compatible with existing limits
    pub fn validate(&self) -> Result<(), String> {
        // ... existing validation ...
        
        #[cfg(feature = "parallel-qrinfo")]
        {
            if self.max_concurrent_qrinfo_requests == 0 {
                return Err("max_concurrent_qrinfo_requests must be > 0".to_string());
            }
            
            // Ensure parallel limits don't exceed filter limits
            if self.max_concurrent_qrinfo_requests > self.max_concurrent_filter_requests {
                return Err("QRInfo concurrency should not exceed filter concurrency".to_string());
            }
        }
        
        Ok(())
    }
}
```

### 5. Integrate QRInfo Response Correlation into Message Handler

**File**: `dash-spv/src/client/message_handler.rs` (extend existing message routing)

**Enhancement**: Add QRInfo correlation without replacing existing message handling:

```rust
pub struct MessageHandler {
    // ... existing fields ...
    
    #[cfg(feature = "parallel-qrinfo")]
    qrinfo_correlator: Option<QRInfoCorrelationManager>,
}

impl MessageHandler {
    /// Initialize with optional QRInfo correlation support
    pub fn new_with_parallel_qrinfo() -> Self {
        Self {
            // ... existing initialization ...
            #[cfg(feature = "parallel-qrinfo")]
            qrinfo_correlator: Some(QRInfoCorrelationManager::new()),
        }
    }
    
    /// Enhanced QRInfo message handling with correlation support
    pub async fn handle_qrinfo_message(
        &mut self,
        qr_info: QRInfo,
        mn_sync: &mut MasternodeSyncManager,
        storage: &mut dyn StorageManager,
        network: &mut dyn NetworkManager,
        sync_base_height: u32,
    ) -> Result<bool, String> {
        #[cfg(feature = "parallel-qrinfo")]
        {
            // Try correlation first for parallel requests
            if let Some(correlator) = &mut self.qrinfo_correlator {
                if correlator.handle_qr_info_response(qr_info.clone()).is_ok() {
                    tracing::debug!("QRInfo response correlated to parallel request");
                    return Ok(true);
                }
            }
        }
        
        // Fall back to existing sequential handling
        mn_sync.handle_qrinfo_message(qr_info, storage, network, sync_base_height).await;
        Ok(true)
    }
    
    /// Register QRInfo request for correlation (feature-gated)
    #[cfg(feature = "parallel-qrinfo")]
    pub fn register_qrinfo_request(
        &mut self,
        base_hash: BlockHash,
        tip_hash: BlockHash,
    ) -> Option<oneshot::Receiver<QRInfo>> {
        self.qrinfo_correlator
            .as_mut()
            .map(|correlator| correlator.register_request(base_hash, tip_hash).1)
    }
}

/// QRInfo correlation manager for parallel request handling
#[cfg(feature = "parallel-qrinfo")]
pub struct QRInfoCorrelationManager {
    pending_requests: HashMap<BlockHash, oneshot::Sender<QRInfo>>,
    request_timeouts: VecDeque<(BlockHash, Instant)>,
}

#[cfg(feature = "parallel-qrinfo")]
impl QRInfoCorrelationManager {
    pub fn new() -> Self {
        Self {
            pending_requests: HashMap::new(),
            request_timeouts: VecDeque::new(),
        }
    }
    
    pub fn register_request(
        &mut self,
        base_hash: BlockHash,
        tip_hash: BlockHash,
    ) -> (BlockHash, oneshot::Receiver<QRInfo>) {
        let (tx, rx) = oneshot::channel();
        
        self.pending_requests.insert(tip_hash, tx);
        self.request_timeouts.push_back((tip_hash, Instant::now()));
        
        tracing::debug!("Registered QRInfo request correlation for tip_hash: {}", tip_hash);
        
        (tip_hash, rx)
    }
    
    pub fn handle_qr_info_response(&mut self, qr_info: QRInfo) -> Result<(), String> {
        // Match response to request using tip hash
        let tip_hash = qr_info.mn_list_diff_tip.block_hash;
        
        if let Some(sender) = self.pending_requests.remove(&tip_hash) {
            if sender.send(qr_info).is_err() {
                tracing::warn!("Failed to send QRInfo response - receiver dropped");
            }
            Ok(())
        } else {
            Err(format!("No pending request found for tip_hash: {}", tip_hash))
        }
    }
    
    pub fn cleanup_expired_requests(&mut self, timeout: Duration) {
        let now = Instant::now();
        
        while let Some(&(tip_hash, timestamp)) = self.request_timeouts.front() {
            if now.duration_since(timestamp) > timeout {
                self.pending_requests.remove(&tip_hash);
                self.request_timeouts.pop_front();
                tracing::warn!("Cleaned up expired QRInfo request for tip_hash: {}", tip_hash);
            } else {
                break; // Queue is ordered by time
            }
        }
    }
}
```

### 6. Extend Tests to Use Existing MockNetworkManager

**File**: `tests/sync/test_parallel_qrinfo.rs` (new test file using existing mocks)

**Implementation**: Build upon existing MockNetworkManager instead of creating new mocks:

```rust
use dash_spv::network::mock::MockNetworkManager;
use dash_spv::sync::masternodes::MasternodeSyncManager;
use dash_spv::storage::memory::MemoryStorageManager;

#[cfg(feature = "parallel-qrinfo")]
#[tokio::test]
async fn test_parallel_qrinfo_with_existing_mocks() {
    // Use existing MockNetworkManager
    let mut mock_network = MockNetworkManager::new();
    mock_network.connect().await.unwrap();
    
    // Use existing MemoryStorageManager  
    let mut storage = MemoryStorageManager::new().await.unwrap();
    
    // Use existing MasternodeSyncManager with parallel enhancement
    let config = ClientConfig::default()
        .with_parallel_qrinfo_settings(3, true, Duration::from_secs(10));
    let mut mn_sync = MasternodeSyncManager::new(&config);
    
    // Test parallel QRInfo requests
    let requests = vec![
        QRInfoRequestSpec {
            base_block_hash: test_block_hash(100),
            block_hash: test_block_hash(200),
            priority: RequestPriority::Normal,
        },
        QRInfoRequestSpec {
            base_block_hash: test_block_hash(200),
            block_hash: test_block_hash(300),
            priority: RequestPriority::High,
        },
    ];
    
    let network_arc = Arc::new(Mutex::new(mock_network));
    let result = mn_sync.request_qrinfo_parallel(network_arc, requests, 3).await;
    
    assert!(result.is_ok(), "Parallel QRInfo requests should succeed");
}

#[cfg(feature = "parallel-qrinfo")]
#[tokio::test]
async fn test_enhanced_request_controller_concurrency() {
    let config = ClientConfig::default()
        .with_max_concurrent_filter_requests(8)
        .with_parallel_qrinfo_settings(4, true, Duration::from_secs(15));
    
    let mut request_controller = RequestController::new(&config);
    
    // Test that parallel limits are properly integrated
    request_controller.set_parallel_limits("QRInfoPhase", 4);
    
    // Verify existing validation still works
    assert!(config.validate().is_ok());
}
```

## Success Criteria

### Integration Requirements
- [ ] Parallel processing uses existing NetworkManager trait without modification
- [ ] QRInfo correlation integrates with existing message_handler.rs routing
- [ ] Rate limiting and backoff reuse existing RequestController logic  
- [ ] Error recovery extends existing RecoveryManager strategies
- [ ] Configuration consolidates with existing ClientConfig validation
- [ ] Tests reuse existing MockNetworkManager and storage mocks

### Performance Requirements (feature-gated)
- [ ] >50% reduction in QRInfo sync time with parallel processing enabled
- [ ] Maintain existing sequential performance when parallel features disabled
- [ ] Memory usage increases <20% during parallel operations
- [ ] Graceful degradation to sequential on high failure rates

### Compatibility Requirements
- [ ] All existing sync tests pass without parallel features enabled
- [ ] Sequential sync path remains unchanged and is the default
- [ ] Existing client configurations continue to work without modification
- [ ] No breaking changes to public APIs

## Risk Mitigation

### High Risk: API Compatibility
**Risk**: Changes might break existing dash-spv integrations
**Mitigation**: 
- All parallel features behind `#[cfg(feature = "parallel-qrinfo")]`
- Existing APIs unchanged, only extended with optional parallel methods
- Default behavior remains sequential

### Medium Risk: Resource Usage
**Risk**: Parallel processing might overwhelm network or memory
**Mitigation**:
- Conservative default concurrency limits (3 concurrent requests)
- Reuse existing rate limiting and circuit breaker patterns
- Adaptive concurrency reduction on failures

### Low Risk: Request Correlation
**Risk**: QRInfo responses might be mismatched in parallel mode
**Mitigation**:
- Simple tip_hash-based correlation with fallback matching
- Timeout-based cleanup of stale requests
- Comprehensive correlation testing

## Integration Points

### Existing Components Integration
- **MasternodeSyncManager**: Extend with optional parallel request methods
- **RequestController**: Add parallel scheduling while preserving existing validation
- **RecoveryManager**: Enhance with parallel-aware strategies
- **ClientConfig**: Consolidate parallel settings with existing rate limits
- **MockNetworkManager**: Reuse for testing parallel functionality

### Backward Compatibility
- All parallel features are opt-in via feature flags
- Sequential sync remains the default and unchanged
- Existing client code works without modification
- Configuration migration is automatic

## Implementation Plan

1. **Phase 3.1**: Extend MasternodeSyncManager with parallel QRInfo support
2. **Phase 3.2**: Enhance RequestController for parallel request scheduling  
3. **Phase 3.3**: Add QRInfo correlation to existing message handler
4. **Phase 3.4**: Integrate parallel configuration with ClientConfig
5. **Phase 3.5**: Extend RecoveryManager for parallel-aware recovery
6. **Phase 3.6**: Add comprehensive testing using existing mock infrastructure

Each phase maintains full backward compatibility and can be deployed independently.