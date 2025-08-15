# Phase 3: Network Efficiency Optimization

## Overview

This phase optimizes network efficiency by implementing parallel QRInfo processing, intelligent request scheduling, and robust error recovery. Building on the discovery foundation from Phase 2, we'll maximize sync speed while maintaining reliability and network-friendly behavior.

## Objectives

1. **Parallel Processing**: Execute multiple QRInfo requests concurrently
2. **Request Scheduling**: Intelligent timing and prioritization of requests
3. **Error Recovery**: Robust handling of network failures and timeouts
4. **Bandwidth Management**: Efficient use of available network capacity
5. **Progress Tracking**: Real-time progress reporting for parallel operations

## Network Efficiency Analysis

### Current Sequential Bottlenecks
```rust
// Phase 2 approach (sequential):
for request in qr_info_requests {
    network.request_qr_info(request).await?;
    let response = wait_for_response().await?;
    process_response(response).await?;
}
// Total time: N * (network_latency + processing_time)
```

### Target Parallel Efficiency
```rust
// Phase 3 approach (parallel):
let futures = qr_info_requests.map(|req| async {
    let response = network.request_qr_info(req).await?;
    process_response(response).await
});
join_all(futures).await;
// Total time: max(network_latency + processing_time) + scheduling_overhead
```

## Detailed Implementation Plan

### 1. Parallel Request Executor

#### 1.1 Concurrent QRInfo Request Manager

**File**: `dash-spv/src/sync/parallel.rs`

**Implementation**:
```rust
use tokio::{sync::Semaphore, task::JoinSet, time::timeout};
use std::sync::Arc;
use dashcore::BlockHash;

/// Manages parallel execution of QRInfo requests with concurrency control
pub struct ParallelQRInfoExecutor {
    /// Maximum concurrent requests
    max_concurrent: usize,
    /// Semaphore for controlling concurrency  
    semaphore: Arc<Semaphore>,
    /// Network timeout for individual requests
    request_timeout: Duration,
    /// Progress reporting channel
    progress_tx: Option<mpsc::UnboundedSender<SyncProgress>>,
}

impl ParallelQRInfoExecutor {
    pub fn new(max_concurrent: usize, request_timeout: Duration) -> Self {
        Self {
            max_concurrent,
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            request_timeout,
            progress_tx: None,
        }
    }
    
    pub fn with_progress_reporting(mut self, tx: mpsc::UnboundedSender<SyncProgress>) -> Self {
        self.progress_tx = Some(tx);
        self
    }
    
    /// Execute multiple QRInfo requests in parallel with controlled concurrency
    pub async fn execute_parallel_requests(
        &self,
        requests: Vec<QRInfoRequest>,
        network: Arc<Mutex<dyn NetworkManager>>,
        processor: Arc<Mutex<dyn QRInfoProcessor>>,
    ) -> Result<Vec<QRInfoResult>, ParallelExecutionError> {
        if requests.is_empty() {
            return Ok(Vec::new());
        }
        
        tracing::info!(
            "Starting parallel execution of {} QRInfo requests with max_concurrent={}",
            requests.len(),
            self.max_concurrent
        );
        
        let mut join_set = JoinSet::new();
        let total_requests = requests.len();
        let completed = Arc::new(AtomicUsize::new(0));
        
        // Launch parallel tasks
        for (index, request) in requests.into_iter().enumerate() {
            let semaphore = self.semaphore.clone();
            let network = network.clone();
            let processor = processor.clone();
            let completed = completed.clone();
            let progress_tx = self.progress_tx.clone();
            let timeout_duration = self.request_timeout;
            
            let task = async move {
                // Acquire semaphore permit for concurrency control
                let _permit = semaphore.acquire().await
                    .map_err(|_| ParallelExecutionError::SemaphoreError)?;
                
                tracing::debug!("Starting QRInfo request {}/{}: heights {}-{}", 
                    index + 1, total_requests, request.base_height, request.tip_height);
                
                // Capture start time for processing duration measurement
                let start_time = std::time::Instant::now();
                
                // Execute request with timeout
                let result = timeout(timeout_duration, async {
                    // Send network request
                    {
                        let mut net = network.lock().await;
                        net.request_qr_info(
                            request.base_hash,
                            request.tip_hash,
                            request.extra_share
                        ).await?;
                    }
                    
                    // Wait for and process response
                    let qr_info = Self::wait_for_qr_info_response(&request).await?;
                    
                    {
                        let mut proc = processor.lock().await;
                        proc.process_qr_info(qr_info).await?;
                    }
                    
                    // Calculate elapsed processing time
                    let processing_time = start_time.elapsed();
                    
                    Ok::<QRInfoResult, ParallelExecutionError>(QRInfoResult {
                        request: request.clone(),
                        success: true,
                        processing_time,
                        error: None,
                    })
                }).await;
                
                // Update progress
                let completed_count = completed.fetch_add(1, Ordering::Relaxed) + 1;
                if let Some(ref tx) = progress_tx {
                    let _ = tx.send(SyncProgress {
                        completed_requests: completed_count,
                        total_requests,
                        current_operation: format!("QRInfo {}/{}", completed_count, total_requests),
                        estimated_remaining: Self::estimate_remaining_time(
                            completed_count, total_requests, timeout_duration
                        ),
                    });
                }
                
                match result {
                    Ok(Ok(success_result)) => {
                        tracing::debug!("Completed QRInfo request {}/{} successfully", 
                            index + 1, total_requests);
                        Ok(success_result)
                    }
                    Ok(Err(e)) => {
                        tracing::warn!("QRInfo request {}/{} failed: {}", 
                            index + 1, total_requests, e);
                        // Calculate elapsed processing time for failed request
                        let processing_time = start_time.elapsed();
                        
                        Ok(QRInfoResult {
                            request,
                            success: false,
                            processing_time,
                            error: Some(e),
                        })
                    }
                    Err(_) => {
                        tracing::error!("QRInfo request {}/{} timed out after {:?}", 
                            index + 1, total_requests, timeout_duration);
                        // Calculate elapsed processing time for timed out request
                        let processing_time = start_time.elapsed();
                        
                        Ok(QRInfoResult {
                            request,
                            success: false,
                            processing_time,
                            error: Some(ParallelExecutionError::Timeout),
                        })
                    }
                }
            };
            
            join_set.spawn(task);
        }
        
        // Collect all results
        let mut results = Vec::with_capacity(total_requests);
        while let Some(task_result) = join_set.join_next().await {
            match task_result {
                Ok(qr_info_result) => results.push(qr_info_result?),
                Err(e) => {
                    tracing::error!("Task execution error: {}", e);
                    return Err(ParallelExecutionError::TaskError(e.to_string()));
                }
            }
        }
        
        // Sort results back to original request order for consistency
        results.sort_by_key(|r| r.request.priority);
        
        let success_count = results.iter().filter(|r| r.success).count();
        let failure_count = results.len() - success_count;
        
        tracing::info!(
            "Parallel QRInfo execution completed: {}/{} successful, {} failed",
            success_count, total_requests, failure_count
        );
        
        Ok(results)
    }
    
    /// Wait for QRInfo response for a specific request
    async fn wait_for_qr_info_response(request: &QRInfoRequest) -> Result<QRInfo, ParallelExecutionError> {
        use tokio::time::timeout;
        use std::sync::Arc;
        
        // Get global correlation manager (would be dependency-injected in real implementation)
        let correlation_manager = QRInfoCorrelationManager::global();
        
        // Register request and get response receiver
        let (request_id, response_rx) = {
            let mut manager = correlation_manager.lock().await;
            manager.register_request(request.base_hash, request.tip_hash)
        };
        
        // Wait for response with configurable timeout
        let response_timeout = Duration::from_secs(30); // Configurable timeout
        let result = timeout(response_timeout, response_rx).await;
        
        // Cleanup: ensure request is removed from pending list on all paths
        let cleanup_result = {
            let mut manager = correlation_manager.lock().await;
            manager.cleanup_request(request_id)
        };
        
        match result {
            Ok(Ok(qr_info)) => {
                // Validate the QRInfo payload
                Self::validate_qr_info_response(&qr_info, request)?;
                
                tracing::debug!(
                    "Successfully received and validated QRInfo response for request {:?}",
                    request_id
                );
                Ok(qr_info)
            }
            Ok(Err(_)) => {
                // Response channel was closed/dropped (sender error)
                tracing::error!("QRInfo response channel closed for request {:?}", request_id);
                Err(ParallelExecutionError::Network(
                    "Response channel closed before receiving QRInfo".to_string()
                ))
            }
            Err(_) => {
                // Timeout waiting for response
                tracing::warn!(
                    "Timeout waiting for QRInfo response for request {:?} after {:?}",
                    request_id, response_timeout
                );
                Err(ParallelExecutionError::Timeout)
            }
        }
    }
    
    /// Validate QRInfo response matches the original request
    fn validate_qr_info_response(qr_info: &QRInfo, request: &QRInfoRequest) -> Result<(), ParallelExecutionError> {
        // Validate that the response corresponds to our request
        let tip_hash = qr_info.mn_list_diff_tip.block_hash;
        if tip_hash != request.tip_hash {
            return Err(ParallelExecutionError::Processing(
                format!("QRInfo response tip hash {:x} doesn't match request tip hash {:x}",
                        tip_hash, request.tip_hash)
            ));
        }
        
        // Validate base hash if available in the response
        let base_hash = qr_info.mn_list_diff_tip.base_block_hash;
        if base_hash != request.base_hash {
            return Err(ParallelExecutionError::Processing(
                format!("QRInfo response base hash {:x} doesn't match request base hash {:x}",
                        base_hash, request.base_hash)
            ));
        }
        
        // Additional validation: check that diffs are reasonable
        if qr_info.mn_list_diff_list.is_empty() && 
           qr_info.mn_list_diff_h.added_mns.is_empty() && 
           qr_info.mn_list_diff_h.deleted_mns.is_empty() {
            tracing::warn!("Received QRInfo with no diffs - this might indicate an empty response");
        }
        
        Ok(())
    }
    
    fn estimate_remaining_time(completed: usize, total: usize, avg_time: Duration) -> Duration {
        if completed == 0 || completed >= total {
            return Duration::ZERO;
        }
        
        let remaining = total - completed;
        let completion_rate = completed as f32 / avg_time.as_secs_f32();
        Duration::from_secs_f32(remaining as f32 / completion_rate)
    }
}

#[derive(Debug, Clone)]
pub struct QRInfoResult {
    pub request: QRInfoRequest,
    pub success: bool,
    pub processing_time: std::time::Duration,
    pub error: Option<ParallelExecutionError>,
}

#[derive(Debug, thiserror::Error)]
pub enum ParallelExecutionError {
    #[error("Network error: {0}")]
    Network(String),
    #[error("Processing error: {0}")]
    Processing(String),
    #[error("Request timed out")]
    Timeout,
    #[error("Semaphore error")]
    SemaphoreError,
    #[error("Task error: {0}")]
    TaskError(String),
}
```

**Test File**: `tests/sync/test_parallel_execution.rs`
```rust
#[tokio::test]
async fn test_parallel_qr_info_execution() {
    let executor = ParallelQRInfoExecutor::new(3, Duration::from_secs(5));
    
    let requests = create_test_qr_info_requests(10);
    let mock_network = Arc::new(Mutex::new(create_mock_network()));
    let mock_processor = Arc::new(Mutex::new(create_mock_processor()));
    
    let start_time = Instant::now();
    let results = executor.execute_parallel_requests(
        requests, 
        mock_network, 
        mock_processor
    ).await.unwrap();
    let elapsed = start_time.elapsed();
    
    assert_eq!(results.len(), 10);
    assert!(results.iter().all(|r| r.success));
    
    // Should be much faster than sequential (which would be ~10 * request_time)
    // With 3 concurrent, should be roughly ~4 * request_time
    assert!(elapsed < Duration::from_secs(8)); // Allow some buffer
}

#[tokio::test]
async fn test_concurrency_limiting() {
    let executor = ParallelQRInfoExecutor::new(2, Duration::from_secs(1));
    
    let slow_network = Arc::new(Mutex::new(create_slow_mock_network()));
    let mock_processor = Arc::new(Mutex::new(create_mock_processor()));
    let requests = create_test_qr_info_requests(5);
    
    let concurrent_count = Arc::new(AtomicUsize::new(0));
    let max_concurrent = Arc::new(AtomicUsize::new(0));
    
    // Track maximum concurrency achieved
    let counter_clone = concurrent_count.clone();
    let max_clone = max_concurrent.clone();
    
    tokio::spawn(async move {
        loop {
            let current = counter_clone.load(Ordering::Relaxed);
            let max = max_clone.load(Ordering::Relaxed);
            if current > max {
                max_clone.store(current, Ordering::Relaxed);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
    
    let results = executor.execute_parallel_requests(
        requests,
        slow_network,
        mock_processor
    ).await.unwrap();
    
    assert_eq!(results.len(), 5);
    
    // Should never exceed our concurrency limit
    let max_achieved = max_concurrent.load(Ordering::Relaxed);
    assert!(max_achieved <= 2, "Max concurrency {} exceeded limit 2", max_achieved);
}

#[tokio::test]
async fn test_error_handling_and_partial_failure() {
    let executor = ParallelQRInfoExecutor::new(3, Duration::from_secs(2));
    
    // Network that fails 50% of requests
    let flaky_network = Arc::new(Mutex::new(create_flaky_mock_network(0.5)));
    let mock_processor = Arc::new(Mutex::new(create_mock_processor()));
    let requests = create_test_qr_info_requests(10);
    
    let results = executor.execute_parallel_requests(
        requests,
        flaky_network, 
        mock_processor
    ).await.unwrap();
    
    assert_eq!(results.len(), 10); // Should get results for all requests
    
    let success_count = results.iter().filter(|r| r.success).count();
    let failure_count = results.iter().filter(|r| !r.success).count();
    
    assert!(success_count > 0, "At least some requests should succeed");
    assert!(failure_count > 0, "Some requests should fail with flaky network");
    assert_eq!(success_count + failure_count, 10);
    
    // Failed results should have error information
    for result in results.iter().filter(|r| !r.success) {
        assert!(result.error.is_some());
    }
}

#[tokio::test]
async fn test_progress_reporting() {
    let executor = ParallelQRInfoExecutor::new(2, Duration::from_secs(1));
    let (progress_tx, mut progress_rx) = mpsc::unbounded_channel();
    let executor = executor.with_progress_reporting(progress_tx);
    
    let requests = create_test_qr_info_requests(5);
    let mock_network = Arc::new(Mutex::new(create_mock_network()));
    let mock_processor = Arc::new(Mutex::new(create_mock_processor()));
    
    let execution_handle = tokio::spawn(async move {
        executor.execute_parallel_requests(requests, mock_network, mock_processor).await
    });
    
    let mut progress_updates = Vec::new();
    
    // Collect progress updates
    while let Some(progress) = progress_rx.recv().await {
        progress_updates.push(progress);
        if progress.completed_requests >= 5 {
            break;
        }
    }
    
    let results = execution_handle.await.unwrap().unwrap();
    assert_eq!(results.len(), 5);
    
    // Should have received progress updates
    assert!(!progress_updates.is_empty());
    assert!(progress_updates.len() <= 5); // At most one per request
    
    // Progress should increase monotonically
    let completed_counts: Vec<usize> = progress_updates.iter()
        .map(|p| p.completed_requests)
        .collect();
    
    assert!(completed_counts.windows(2).all(|w| w[0] <= w[1]));
    assert_eq!(completed_counts.last(), Some(&5));
}
```

#### 1.2 Request Correlation and Response Matching

**File**: `dash-spv/src/network/correlation.rs`

**Implementation**:
```rust
use std::collections::HashMap;
use tokio::sync::{oneshot, Mutex};
use dashcore::{BlockHash, network::message_qrinfo::QRInfo};

/// Correlates QRInfo requests with responses for parallel processing
pub struct QRInfoCorrelationManager {
    /// Pending requests waiting for responses
    pending_requests: Mutex<HashMap<RequestId, PendingQRInfoRequest>>,
    /// Next request ID
    next_request_id: AtomicU64,
}

impl QRInfoCorrelationManager {
    pub fn new() -> Self {
        Self {
            pending_requests: HashMap::new(),
            next_request_id: AtomicU64::new(1),
        }
    }
    
    /// Register a QRInfo request and get a channel to wait for the response
    pub fn register_request(
        &mut self,
        base_hash: BlockHash,
        tip_hash: BlockHash,
    ) -> (RequestId, oneshot::Receiver<Result<QRInfo, CorrelationError>>) {
        let request_id = RequestId(self.next_request_id.fetch_add(1, Ordering::Relaxed));
        let (response_tx, response_rx) = oneshot::channel();
        
        let pending = PendingQRInfoRequest {
            base_hash,
            tip_hash,
            response_sender: response_tx,
            timestamp: Instant::now(),
        };
        
        self.pending_requests.insert(request_id, pending);
        
        tracing::debug!(
            "Registered QRInfo request {} for range {:x} to {:x}",
            request_id.0, base_hash, tip_hash
        );
        
        (request_id, response_rx)
    }
    
    /// Handle incoming QRInfo response and match it to pending request
    pub fn handle_qr_info_response(&mut self, qr_info: QRInfo) -> Result<(), CorrelationError> {
        // Find matching request based on QRInfo content
        // We need to match based on the diff ranges in the QRInfo
        let matching_request_id = self.find_matching_request(&qr_info)?;
        
        if let Some(pending) = self.pending_requests.remove(&matching_request_id) {
            if pending.response_sender.send(Ok(qr_info)).is_err() {
                tracing::warn!(
                    "Failed to send QRInfo response for request {} - receiver dropped",
                    matching_request_id.0
                );
            } else {
                tracing::debug!("Successfully correlated QRInfo response to request {}", matching_request_id.0);
            }
            
            Ok(())
        } else {
            Err(CorrelationError::RequestNotFound(matching_request_id))
        }
    }
    
    /// Clean up expired requests (requests that have been waiting too long)
    pub fn cleanup_expired_requests(&mut self, timeout: Duration) {
        let now = Instant::now();
        let expired_ids: Vec<RequestId> = self.pending_requests
            .iter()
            .filter(|(_, pending)| now.duration_since(pending.timestamp) > timeout)
            .map(|(id, _)| *id)
            .collect();
        
        for request_id in expired_ids {
            if let Some(pending) = self.pending_requests.remove(&request_id) {
                let _ = pending.response_sender.send(Err(CorrelationError::Timeout));
                tracing::warn!("Cleaned up expired QRInfo request {}", request_id.0);
            }
        }
    }
    
    /// Clean up a specific request by ID (used for explicit cleanup)
    pub fn cleanup_request(&mut self, request_id: RequestId) -> Result<(), CorrelationError> {
        if self.pending_requests.remove(&request_id).is_some() {
            tracing::debug!("Cleaned up completed QRInfo request {}", request_id.0);
            Ok(())
        } else {
            // Request might have already been cleaned up or never existed
            tracing::debug!("Request {} not found during cleanup (already processed?)", request_id.0);
            Ok(())
        }
    }
    
    /// Get global correlation manager instance (for dependency injection in real implementation)
    pub fn global() -> Arc<tokio::sync::Mutex<Self>> {
        // In a real implementation, this would be a proper singleton or dependency injection
        // For the planning document, this is a placeholder showing the integration pattern
        use std::sync::OnceLock;
        static GLOBAL_MANAGER: OnceLock<Arc<tokio::sync::Mutex<QRInfoCorrelationManager>>> = OnceLock::new();
        
        GLOBAL_MANAGER.get_or_init(|| {
            Arc::new(tokio::sync::Mutex::new(QRInfoCorrelationManager::new()))
        }).clone()
    }
    
    /// Find the pending request that matches this QRInfo response
    fn find_matching_request(&self, qr_info: &QRInfo) -> Result<RequestId, CorrelationError> {
        // Strategy: Match based on the block hashes in the QRInfo diffs
        // The tip diff should match our request's tip_hash
        let tip_hash = qr_info.mn_list_diff_tip.block_hash;
        
        for (request_id, pending) in &self.pending_requests {
            if pending.tip_hash == tip_hash {
                return Ok(*request_id);
            }
        }
        
        // Fallback: Try to match based on height ranges if we can derive them
        // This is more complex but handles edge cases
        self.find_matching_request_by_content(qr_info)
    }
    
    fn find_matching_request_by_content(&self, qr_info: &QRInfo) -> Result<RequestId, CorrelationError> {
        // More sophisticated matching based on analyzing all diffs in QRInfo
        // This is a backup strategy if simple tip_hash matching fails
        
        for (request_id, pending) in &self.pending_requests {
            // Check if any of the diffs in QRInfo match our expected range
            let diffs = [
                &qr_info.mn_list_diff_tip,
                &qr_info.mn_list_diff_h,
                &qr_info.mn_list_diff_at_h_minus_c,
                &qr_info.mn_list_diff_at_h_minus_2c,
                &qr_info.mn_list_diff_at_h_minus_3c,
            ];
            
            for diff in diffs {
                if diff.base_block_hash == pending.base_hash || diff.block_hash == pending.tip_hash {
                    return Ok(*request_id);
                }
            }
            
            // Check additional diffs if present
            for diff in &qr_info.mn_list_diff_list {
                if diff.base_block_hash == pending.base_hash || diff.block_hash == pending.tip_hash {
                    return Ok(*request_id);
                }
            }
        }
        
        Err(CorrelationError::NoMatchFound)
    }
    
    pub fn pending_count(&self) -> usize {
        self.pending_requests.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestId(u64);

#[derive(Debug)]
struct PendingQRInfoRequest {
    base_hash: BlockHash,
    tip_hash: BlockHash,
    response_sender: oneshot::Sender<Result<QRInfo, CorrelationError>>,
    timestamp: Instant,
}

#[derive(Debug, thiserror::Error)]
pub enum CorrelationError {
    #[error("Request {0:?} not found")]
    RequestNotFound(RequestId),
    #[error("No matching request found for QRInfo response")]
    NoMatchFound,
    #[error("Request timed out")]
    Timeout,
}
```

**Test File**: `tests/network/test_qr_info_correlation.rs`
```rust
#[tokio::test]
async fn test_request_response_correlation() {
    let mut correlator = QRInfoCorrelationManager::new();
    
    let base_hash = test_block_hash(1000);
    let tip_hash = test_block_hash(1100);
    
    let (request_id, response_rx) = correlator.register_request(base_hash, tip_hash);
    
    // Create matching QRInfo response
    let mut qr_info = create_test_qr_info();
    qr_info.mn_list_diff_tip.block_hash = tip_hash;
    qr_info.mn_list_diff_tip.base_block_hash = base_hash;
    
    // Handle the response
    let result = correlator.handle_qr_info_response(qr_info.clone());
    assert!(result.is_ok());
    
    // Should receive the response
    let received_qr_info = response_rx.await.unwrap();
    assert_eq!(received_qr_info.mn_list_diff_tip.block_hash, tip_hash);
}

#[tokio::test] 
async fn test_multiple_concurrent_requests() {
    let mut correlator = QRInfoCorrelationManager::new();
    
    let mut request_receivers = Vec::new();
    let mut expected_responses = Vec::new();
    
    // Register multiple requests
    for i in 0..5 {
        let base_hash = test_block_hash(i * 100);
        let tip_hash = test_block_hash(i * 100 + 50);
        
        let (_, response_rx) = correlator.register_request(base_hash, tip_hash);
        request_receivers.push(response_rx);
        
        let mut qr_info = create_test_qr_info();
        qr_info.mn_list_diff_tip.block_hash = tip_hash;
        expected_responses.push(qr_info);
    }
    
    // Send responses in different order
    let response_order = [2, 0, 4, 1, 3];
    for &index in &response_order {
        let result = correlator.handle_qr_info_response(expected_responses[index].clone());
        assert!(result.is_ok(), "Failed to handle response {}", index);
    }
    
    // All requests should receive their responses
    for (i, response_rx) in request_receivers.into_iter().enumerate() {
        let received = response_rx.await.unwrap();
        assert_eq!(
            received.mn_list_diff_tip.block_hash,
            expected_responses[i].mn_list_diff_tip.block_hash
        );
    }
    
    assert_eq!(correlator.pending_count(), 0);
}

#[tokio::test]
async fn test_expired_request_cleanup() {
    let mut correlator = QRInfoCorrelationManager::new();
    
    let (_, response_rx) = correlator.register_request(
        test_block_hash(1000),
        test_block_hash(1100)
    );
    
    assert_eq!(correlator.pending_count(), 1);
    
    // Clean up with very short timeout
    correlator.cleanup_expired_requests(Duration::from_millis(1));
    
    // Wait a bit to ensure expiration
    tokio::time::sleep(Duration::from_millis(10)).await;
    correlator.cleanup_expired_requests(Duration::from_millis(1));
    
    assert_eq!(correlator.pending_count(), 0);
    
    // Should receive timeout error
    let result = response_rx.await;
    assert!(result.is_err()); // Channel was closed due to timeout
}
```

### 2. Intelligent Request Scheduling

#### 2.1 Priority-Based Scheduler

**File**: `dash-spv/src/sync/scheduler.rs`

**Implementation**:
```rust
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use tokio::time::{interval, Interval};

/// Intelligent scheduler for QRInfo requests with priority and rate limiting
pub struct QRInfoScheduler {
    /// Priority queue of pending requests
    request_queue: BinaryHeap<ScheduledRequest>,
    /// Rate limiter for network requests
    rate_limiter: RateLimiter,
    /// Maximum requests per time window
    max_requests_per_window: usize,
    /// Time window for rate limiting
    rate_limit_window: Duration,
    /// Network condition monitor
    network_monitor: NetworkConditionMonitor,
}

impl QRInfoScheduler {
    pub fn new(max_requests_per_window: usize, rate_limit_window: Duration) -> Self {
        Self {
            request_queue: BinaryHeap::new(),
            rate_limiter: RateLimiter::new(max_requests_per_window, rate_limit_window),
            max_requests_per_window,
            rate_limit_window,
            network_monitor: NetworkConditionMonitor::new(),
        }
    }
    
    /// Schedule a QRInfo request with priority and timing
    pub fn schedule_request(&mut self, request: QRInfoRequest, priority: SchedulePriority) {
        let scheduled = ScheduledRequest {
            request,
            priority,
            scheduled_time: Instant::now(),
            retry_count: 0,
            max_retries: 3,
        };
        
        self.request_queue.push(scheduled);
        
        tracing::debug!(
            "Scheduled QRInfo request with priority {:?}, queue size: {}",
            priority, self.request_queue.len()
        );
    }
    
    /// Get the next batch of requests ready for execution
    pub async fn get_next_batch(&mut self, max_batch_size: usize) -> Vec<QRInfoRequest> {
        let mut batch = Vec::new();
        let network_conditions = self.network_monitor.get_current_conditions().await;
        
        // Adjust batch size based on network conditions
        let effective_batch_size = self.calculate_effective_batch_size(max_batch_size, &network_conditions);
        
        while batch.len() < effective_batch_size && !self.request_queue.is_empty() {
            // Check rate limiting
            if !self.rate_limiter.can_make_request().await {
                tracing::debug!("Rate limit reached, deferring requests");
                break;
            }
            
            // Get highest priority request
            if let Some(scheduled) = self.request_queue.pop() {
                // Check if it's time to execute this request
                if self.is_ready_for_execution(&scheduled, &network_conditions) {
                    batch.push(scheduled.request);
                    self.rate_limiter.record_request().await;
                } else {
                    // Put it back for later
                    self.request_queue.push(scheduled);
                    break;
                }
            }
        }
        
        if !batch.is_empty() {
            tracing::info!(
                "Scheduled batch of {} requests (conditions: {:?})",
                batch.len(),
                network_conditions
            );
        }
        
        batch
    }
    
    /// Handle a failed request - reschedule with backoff if retries available
    pub fn handle_request_failure(&mut self, mut request: QRInfoRequest, error: &ParallelExecutionError) {
        if let Some(mut scheduled) = self.find_scheduled_request(&request) {
            scheduled.retry_count += 1;
            
            if scheduled.retry_count <= scheduled.max_retries {
                // Reschedule with exponential backoff
                let backoff_delay = Duration::from_secs(2_u64.pow(scheduled.retry_count as u32));
                scheduled.scheduled_time = Instant::now() + backoff_delay;
                scheduled.priority = self.adjust_priority_for_retry(scheduled.priority, &error);
                
                self.request_queue.push(scheduled);
                
                tracing::info!(
                    "Rescheduled failed request (retry {}/{}) with {}s backoff",
                    scheduled.retry_count, scheduled.max_retries, backoff_delay.as_secs()
                );
            } else {
                tracing::error!(
                    "Request failed permanently after {} retries: {:?}",
                    scheduled.max_retries, error
                );
            }
        }
    }
    
    /// Calculate effective batch size based on network conditions
    fn calculate_effective_batch_size(&self, max_batch_size: usize, conditions: &NetworkConditions) -> usize {
        let mut effective_size = max_batch_size;
        
        if conditions.high_latency {
            effective_size = (effective_size * 80 / 100).max(1); // Reduce by 20%
        }
        
        if conditions.low_bandwidth {
            effective_size = (effective_size * 50 / 100).max(1); // Reduce by 50%
        }
        
        if conditions.unstable_connection {
            effective_size = (effective_size * 60 / 100).max(1); // Reduce by 40%
        }
        
        effective_size
    }
    
    /// Check if a request is ready for execution
    fn is_ready_for_execution(&self, scheduled: &ScheduledRequest, conditions: &NetworkConditions) -> bool {
        let now = Instant::now();
        
        // Basic time check
        if now < scheduled.scheduled_time {
            return false;
        }
        
        // Network condition checks
        match scheduled.priority {
            SchedulePriority::Critical => true, // Critical requests always go through
            SchedulePriority::High => !conditions.unstable_connection,
            SchedulePriority::Normal => !conditions.high_latency && !conditions.unstable_connection,
            SchedulePriority::Low => conditions.is_optimal(),
        }
    }
    
    fn adjust_priority_for_retry(&self, current: SchedulePriority, error: &ParallelExecutionError) -> SchedulePriority {
        match error {
            ParallelExecutionError::Timeout => {
                // Timeouts might be due to network congestion - lower priority
                match current {
                    SchedulePriority::Critical => SchedulePriority::High,
                    SchedulePriority::High => SchedulePriority::Normal,
                    _ => SchedulePriority::Low,
                }
            }
            ParallelExecutionError::Network(_) => {
                // Network errors might be temporary - keep same priority
                current
            }
            _ => current,
        }
    }
    
    pub fn pending_count(&self) -> usize {
        self.request_queue.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScheduledRequest {
    request: QRInfoRequest,
    priority: SchedulePriority,
    scheduled_time: Instant,
    retry_count: u32,
    max_retries: u32,
}

impl Ord for ScheduledRequest {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Higher priority first, then earlier scheduled time
        self.priority.cmp(&other.priority)
            .then_with(|| other.scheduled_time.cmp(&self.scheduled_time))
    }
}

impl PartialOrd for ScheduledRequest {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SchedulePriority {
    Low = 0,
    Normal = 1,
    High = 2, 
    Critical = 3,
}

/// Simple rate limiter using token bucket algorithm
struct RateLimiter {
    tokens: Arc<AtomicUsize>,
    max_tokens: usize,
    refill_interval: Interval,
    refill_amount: usize,
}

impl RateLimiter {
    fn new(max_requests: usize, window: Duration) -> Self {
        let refill_amount = max_requests;
        let refill_interval = interval(window);
        
        Self {
            tokens: Arc::new(AtomicUsize::new(max_requests)),
            max_tokens: max_requests,
            refill_interval,
            refill_amount,
        }
    }
    
    async fn can_make_request(&self) -> bool {
        self.tokens.load(Ordering::Relaxed) > 0
    }
    
    async fn record_request(&mut self) {
        let current = self.tokens.fetch_sub(1, Ordering::Relaxed);
        if current == 0 {
            // Wait for refill
            self.refill_interval.tick().await;
            self.tokens.store(self.max_tokens, Ordering::Relaxed);
        }
    }
}

/// Monitor network conditions for scheduling decisions
struct NetworkConditionMonitor {
    last_measurement: Arc<Mutex<Option<(NetworkConditions, Instant)>>>,
    measurement_interval: Duration,
}

impl NetworkConditionMonitor {
    fn new() -> Self {
        Self {
            last_measurement: Arc::new(Mutex::new(None)),
            measurement_interval: Duration::from_secs(30),
        }
    }
    
    async fn get_current_conditions(&mut self) -> NetworkConditions {
        let mut measurement = self.last_measurement.lock().await;
        
        if let Some((conditions, timestamp)) = &*measurement {
            if timestamp.elapsed() < self.measurement_interval {
                return *conditions;
            }
        }
        
        // Perform fresh measurement
        let conditions = self.measure_network_conditions().await;
        *measurement = Some((conditions, Instant::now()));
        conditions
    }
    
    async fn measure_network_conditions(&self) -> NetworkConditions {
        // Implementation would measure actual network conditions
        // This is simplified for the example
        NetworkConditions {
            high_latency: false,
            low_bandwidth: false,
            unstable_connection: false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct NetworkConditions {
    pub high_latency: bool,
    pub low_bandwidth: bool,
    pub unstable_connection: bool,
}

impl NetworkConditions {
    pub fn is_optimal(&self) -> bool {
        !self.high_latency && !self.low_bandwidth && !self.unstable_connection
    }
}
```

**Test File**: `tests/sync/test_request_scheduling.rs`
```rust
#[tokio::test]
async fn test_priority_based_scheduling() {
    let mut scheduler = QRInfoScheduler::new(10, Duration::from_secs(60));
    
    // Schedule requests with different priorities
    let low_priority_req = create_test_qr_info_request();
    let high_priority_req = create_test_qr_info_request();
    let critical_req = create_test_qr_info_request();
    
    scheduler.schedule_request(low_priority_req.clone(), SchedulePriority::Low);
    scheduler.schedule_request(high_priority_req.clone(), SchedulePriority::High);
    scheduler.schedule_request(critical_req.clone(), SchedulePriority::Critical);
    
    // Get next batch - should return critical first
    let batch = scheduler.get_next_batch(3).await;
    
    assert_eq!(batch.len(), 3);
    // First request should be critical (highest priority)
    assert_eq!(batch[0].priority, critical_req.priority);
}

#[tokio::test]
async fn test_rate_limiting() {
    let mut scheduler = QRInfoScheduler::new(2, Duration::from_secs(1)); // Only 2 per second
    
    // Schedule more requests than rate limit allows
    for i in 0..5 {
        let request = create_test_qr_info_request_with_id(i);
        scheduler.schedule_request(request, SchedulePriority::Normal);
    }
    
    // First batch should be limited by rate limit
    let batch1 = scheduler.get_next_batch(5).await;
    assert_eq!(batch1.len(), 2); // Rate limited to 2
    
    // Immediate second batch should be empty (rate limited)
    let batch2 = scheduler.get_next_batch(5).await;
    assert_eq!(batch2.len(), 0);
    
    // After rate limit window, should get more
    tokio::time::sleep(Duration::from_secs(1)).await;
    let batch3 = scheduler.get_next_batch(5).await;
    assert_eq!(batch3.len(), 2); // Next 2 requests
}

#[tokio::test]
async fn test_retry_with_backoff() {
    let mut scheduler = QRInfoScheduler::new(10, Duration::from_secs(60));
    let request = create_test_qr_info_request();
    
    scheduler.schedule_request(request.clone(), SchedulePriority::High);
    
    // Get and "fail" the request
    let batch = scheduler.get_next_batch(1).await;
    assert_eq!(batch.len(), 1);
    
    // Handle failure - should reschedule with backoff
    scheduler.handle_request_failure(request, &ParallelExecutionError::Timeout);
    
    // Should not be immediately available (backoff delay)
    let immediate_batch = scheduler.get_next_batch(1).await;
    assert_eq!(immediate_batch.len(), 0);
    
    // Should still have pending request
    assert_eq!(scheduler.pending_count(), 1);
}

#[tokio::test]
async fn test_network_condition_adaptation() {
    let mut scheduler = QRInfoScheduler::new(10, Duration::from_secs(60));
    
    // Schedule requests
    for i in 0..8 {
        let request = create_test_qr_info_request_with_id(i);
        scheduler.schedule_request(request, SchedulePriority::Normal);
    }
    
    // Simulate poor network conditions
    // This would be done through the NetworkConditionMonitor in real implementation
    // For testing, we can simulate by observing batch size changes
    
    let batch_good_conditions = scheduler.get_next_batch(5).await;
    // In good conditions, should get full batch (limited by rate limit)
    
    assert!(batch_good_conditions.len() <= 5);
    assert!(batch_good_conditions.len() > 0);
}
```

### 3. Error Recovery and Resilience

#### 3.1 Comprehensive Error Recovery System

**File**: `dash-spv/src/sync/recovery.rs`

**Implementation**:
```rust
/// Comprehensive error recovery system for parallel QRInfo sync
pub struct QRInfoRecoveryManager {
    /// Failed requests awaiting retry
    failed_requests: VecDeque<FailedRequest>,
    /// Error statistics for adaptive behavior
    error_stats: ErrorStatistics,
    /// Recovery strategies
    recovery_strategies: Vec<Box<dyn RecoveryStrategy>>,
    /// Circuit breaker for catastrophic failures
    circuit_breaker: CircuitBreaker,
}

impl QRInfoRecoveryManager {
    pub fn new() -> Self {
        let mut recovery_strategies: Vec<Box<dyn RecoveryStrategy>> = vec![
            Box::new(ExponentialBackoffStrategy::new()),
            Box::new(NetworkSwitchStrategy::new()),
            Box::new(FallbackToSequentialStrategy::new()),
            Box::new(MnListDiffFallbackStrategy::new()),
        ];
        
        Self {
            failed_requests: VecDeque::new(),
            error_stats: ErrorStatistics::new(),
            recovery_strategies,
            circuit_breaker: CircuitBreaker::new(5, Duration::from_secs(300)), // 5 failures in 5 minutes
        }
    }
    
    /// Handle a failed QRInfo request and determine recovery action
    pub async fn handle_failure(
        &mut self,
        request: QRInfoRequest,
        error: ParallelExecutionError,
        attempt_count: u32,
    ) -> RecoveryAction {
        // Record error statistics
        self.error_stats.record_error(&error);
        
        // Check circuit breaker
        if self.circuit_breaker.should_block() {
            tracing::error!("Circuit breaker activated - too many failures");
            return RecoveryAction::StopSync;
        }
        
        let failed_request = FailedRequest {
            request,
            error: error.clone(),
            attempt_count,
            first_failure_time: Instant::now(),
            last_attempt_time: Instant::now(),
        };
        
        // Try each recovery strategy until one accepts the request
        for strategy in &self.recovery_strategies {
            if let Some(action) = strategy.handle_failure(&failed_request, &self.error_stats).await {
                match &action {
                    RecoveryAction::Retry { delay, .. } => {
                        tracing::info!(
                            "Scheduling retry for request with {}ms delay using strategy: {}",
                            delay.as_millis(),
                            strategy.name()
                        );
                        self.failed_requests.push_back(failed_request);
                    }
                    RecoveryAction::FallbackStrategy { strategy_name } => {
                        tracing::warn!(
                            "Switching to fallback strategy: {} for request",
                            strategy_name
                        );
                    }
                    RecoveryAction::SkipRequest => {
                        tracing::warn!("Permanently skipping failed request after exhausting retries");
                    }
                    RecoveryAction::StopSync => {
                        tracing::error!("Recovery manager recommends stopping sync due to persistent failures");
                    }
                }
                
                return action;
            }
        }
        
        // No strategy could handle this - default to skip
        tracing::error!("No recovery strategy could handle failed request - skipping");
        RecoveryAction::SkipRequest
    }
    
    /// Get requests that are ready for retry
    pub async fn get_retry_requests(&mut self) -> Vec<RetryRequest> {
        let now = Instant::now();
        let mut ready_requests = Vec::new();
        
        while let Some(failed_request) = self.failed_requests.front() {
            if self.is_ready_for_retry(failed_request, now) {
                let failed_request = self.failed_requests.pop_front().unwrap();
                ready_requests.push(RetryRequest {
                    original_request: failed_request.request,
                    retry_count: failed_request.attempt_count,
                    recovery_metadata: RecoveryMetadata::default(),
                });
            } else {
                break; // Queue is ordered by retry time
            }
        }
        
        if !ready_requests.is_empty() {
            tracing::info!("Found {} requests ready for retry", ready_requests.len());
        }
        
        ready_requests
    }
    
    /// Check if sync should continue based on error patterns
    pub fn should_continue_sync(&self) -> bool {
        !self.circuit_breaker.should_block() && 
        self.error_stats.success_rate() > 0.1 // At least 10% success rate
    }
    
    /// Get current error statistics
    pub fn get_error_statistics(&self) -> &ErrorStatistics {
        &self.error_stats
    }
    
    fn is_ready_for_retry(&self, failed_request: &FailedRequest, now: Instant) -> bool {
        // Calculate exponential backoff delay
        let base_delay = Duration::from_secs(2);
        let backoff_delay = base_delay * 2_u32.pow(failed_request.attempt_count.saturating_sub(1));
        let max_delay = Duration::from_secs(300); // Cap at 5 minutes
        
        let effective_delay = backoff_delay.min(max_delay);
        
        now >= failed_request.last_attempt_time + effective_delay
    }
}

#[derive(Debug)]
struct FailedRequest {
    request: QRInfoRequest,
    error: ParallelExecutionError,
    attempt_count: u32,
    first_failure_time: Instant,
    last_attempt_time: Instant,
}

#[derive(Debug)]
pub struct RetryRequest {
    pub original_request: QRInfoRequest,
    pub retry_count: u32,
    pub recovery_metadata: RecoveryMetadata,
}

#[derive(Debug, Default)]
pub struct RecoveryMetadata {
    pub use_different_peer: bool,
    pub reduce_batch_size: bool,
    pub fallback_to_mn_diff: bool,
}

pub enum RecoveryAction {
    Retry { 
        delay: Duration,
        metadata: RecoveryMetadata,
    },
    FallbackStrategy { 
        strategy_name: String,
        metadata: RecoveryMetadata,
    },
    SkipRequest,
    StopSync,
}

/// Statistics tracking for error analysis and adaptive recovery
#[derive(Debug)]
pub struct ErrorStatistics {
    total_requests: AtomicU64,
    successful_requests: AtomicU64,
    timeout_errors: AtomicU64,
    network_errors: AtomicU64,
    processing_errors: AtomicU64,
    recent_errors: Mutex<VecDeque<(Instant, ParallelExecutionError)>>,
}

impl ErrorStatistics {
    fn new() -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            successful_requests: AtomicU64::new(0),
            timeout_errors: AtomicU64::new(0),
            network_errors: AtomicU64::new(0),
            processing_errors: AtomicU64::new(0),
            recent_errors: Mutex::new(VecDeque::new()),
        }
    }
    
    pub fn record_success(&self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.successful_requests.fetch_add(1, Ordering::Relaxed);
    }
    
    pub fn record_error(&self, error: &ParallelExecutionError) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        
        match error {
            ParallelExecutionError::Timeout => {
                self.timeout_errors.fetch_add(1, Ordering::Relaxed);
            }
            ParallelExecutionError::Network(_) => {
                self.network_errors.fetch_add(1, Ordering::Relaxed);
            }
            ParallelExecutionError::Processing(_) => {
                self.processing_errors.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
        
        // Track recent errors for pattern analysis
        if let Ok(mut recent) = self.recent_errors.lock() {
            recent.push_back((Instant::now(), error.clone()));
            
            // Keep only last 100 errors
            while recent.len() > 100 {
                recent.pop_front();
            }
        }
    }
    
    pub fn success_rate(&self) -> f64 {
        let total = self.total_requests.load(Ordering::Relaxed);
        if total == 0 {
            return 1.0;
        }
        
        let successful = self.successful_requests.load(Ordering::Relaxed);
        successful as f64 / total as f64
    }
    
    pub fn timeout_rate(&self) -> f64 {
        let total = self.total_requests.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        
        let timeouts = self.timeout_errors.load(Ordering::Relaxed);
        timeouts as f64 / total as f64
    }
}

/// Circuit breaker to prevent catastrophic failure cascades
struct CircuitBreaker {
    failure_threshold: u32,
    reset_timeout: Duration,
    state: Mutex<CircuitState>,
}

impl CircuitBreaker {
    fn new(failure_threshold: u32, reset_timeout: Duration) -> Self {
        Self {
            failure_threshold,
            reset_timeout,
            state: Mutex::new(CircuitState::Closed { failure_count: 0 }),
        }
    }
    
    fn should_block(&self) -> bool {
        if let Ok(state) = self.state.lock() {
            matches!(*state, CircuitState::Open { .. })
        } else {
            false
        }
    }
    
    fn record_failure(&self) {
        if let Ok(mut state) = self.state.lock() {
            match *state {
                CircuitState::Closed { failure_count } => {
                    if failure_count + 1 >= self.failure_threshold {
                        *state = CircuitState::Open { 
                            opened_at: Instant::now(),
                        };
                    } else {
                        *state = CircuitState::Closed { 
                            failure_count: failure_count + 1,
                        };
                    }
                }
                CircuitState::HalfOpen => {
                    *state = CircuitState::Open {
                        opened_at: Instant::now(),
                    };
                }
                _ => {} // Already open
            }
        }
    }
    
    fn record_success(&self) {
        if let Ok(mut state) = self.state.lock() {
            match *state {
                CircuitState::HalfOpen => {
                    *state = CircuitState::Closed { failure_count: 0 };
                }
                CircuitState::Closed { .. } => {
                    *state = CircuitState::Closed { failure_count: 0 };
                }
                _ => {}
            }
        }
    }
}

#[derive(Debug)]
enum CircuitState {
    Closed { failure_count: u32 },
    Open { opened_at: Instant },
    HalfOpen,
}

/// Trait for different recovery strategies
#[async_trait::async_trait]
trait RecoveryStrategy: Send + Sync {
    fn name(&self) -> &'static str;
    
    async fn handle_failure(
        &self,
        failed_request: &FailedRequest,
        error_stats: &ErrorStatistics,
    ) -> Option<RecoveryAction>;
}

/// Exponential backoff with jitter
struct ExponentialBackoffStrategy {
    max_retries: u32,
    base_delay: Duration,
    max_delay: Duration,
}

#[async_trait::async_trait]
impl RecoveryStrategy for ExponentialBackoffStrategy {
    fn name(&self) -> &'static str {
        "ExponentialBackoff"
    }
    
    async fn handle_failure(
        &self,
        failed_request: &FailedRequest,
        _error_stats: &ErrorStatistics,
    ) -> Option<RecoveryAction> {
        if failed_request.attempt_count >= self.max_retries {
            return None; // Let next strategy handle it
        }
        
        let exponential_delay = self.base_delay * 2_u32.pow(failed_request.attempt_count);
        let delay = exponential_delay.min(self.max_delay);
        
        // Add jitter to prevent thundering herd
        let jitter = Duration::from_millis(rand::random::<u64>() % 1000);
        let final_delay = delay + jitter;
        
        Some(RecoveryAction::Retry {
            delay: final_delay,
            metadata: RecoveryMetadata::default(),
        })
    }
}
```

## Success Criteria

### Performance Requirements
- [ ] >80% reduction in total sync time compared to sequential approach
- [ ] Maintain <3 concurrent requests per peer to be network-friendly
- [ ] Handle up to 50% network failure rate gracefully
- [ ] Memory usage remains stable during parallel operations

### Reliability Requirements  
- [ ] Error recovery succeeds in >90% of transient failure cases
- [ ] Circuit breaker prevents cascade failures
- [ ] Progress reporting accuracy within 5% of actual completion
- [ ] No data corruption during parallel processing

### Network Efficiency Requirements
- [ ] Intelligent batching reduces total network requests by >70%
- [ ] Request scheduling adapts to network conditions
- [ ] Rate limiting prevents overwhelming network peers
- [ ] Correlation system handles out-of-order responses correctly

## Risk Mitigation

### High Risk: Request/Response Correlation
**Risk**: Responses might be matched to wrong requests in parallel execution
**Mitigation**:
- Comprehensive correlation testing with concurrent requests
- Fallback matching algorithms for edge cases
- Request ID validation and logging

### Medium Risk: Network Congestion
**Risk**: Too many parallel requests might overwhelm network or peers
**Mitigation**: 
- Configurable concurrency limits with conservative defaults
- Network condition monitoring and adaptive batch sizing
- Circuit breaker to stop when network is struggling

### Low Risk: Memory Usage Growth
**Risk**: Parallel processing might increase memory usage significantly
**Mitigation**:
- Memory profiling throughout development
- Bounded queues and cleanup of completed requests
- Configurable limits on pending requests

## Integration Points

### Phase 2 Dependencies
- Discovery results feed into parallel execution planning
- Engine state must remain consistent during parallel updates
- Batching strategies from Phase 2 are extended for concurrency

### Phase 4 Preparation
- Parallel processing will extend to validation operations
- Error recovery will incorporate validation-specific strategies
- Progress reporting will include validation status

## Next Steps

Upon completion of Phase 3:
1. **Performance Testing**: Comprehensive benchmarks vs sequential approach
2. **Network Stress Testing**: Test with various network conditions and failures
3. **Memory Profiling**: Ensure no memory leaks or excessive usage
4. **Phase 4**: Proceed to enhanced validation with parallel support

The network efficiency optimizations in Phase 3 transform dash-spv into a high-performance, resilient sync system that can handle real-world network conditions while maximizing throughput and maintaining reliability.