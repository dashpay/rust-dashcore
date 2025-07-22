//! Comprehensive error recovery system for parallel QRInfo synchronization.
//!
//! This module provides robust error recovery strategies including
//! exponential backoff, circuit breakers, and adaptive recovery based
//! on error patterns.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::sync::discovery::QRInfoRequest;
use crate::sync::parallel::ParallelExecutionError;

/// Comprehensive error recovery system for parallel QRInfo sync.
pub struct QRInfoRecoveryManager {
    /// Failed requests awaiting retry.
    failed_requests: VecDeque<FailedRequest>,
    /// Error statistics for adaptive behavior.
    error_stats: ErrorStatistics,
    /// Recovery strategies.
    recovery_strategies: Vec<Box<dyn RecoveryStrategy>>,
    /// Circuit breaker for catastrophic failures.
    circuit_breaker: CircuitBreaker,
}

impl QRInfoRecoveryManager {
    /// Create a new recovery manager.
    pub fn new() -> Self {
        let recovery_strategies: Vec<Box<dyn RecoveryStrategy>> = vec![
            Box::new(ExponentialBackoffStrategy::new(
                3,
                Duration::from_secs(2),
                Duration::from_secs(300),
            )),
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

    /// Handle a failed QRInfo request and determine recovery action.
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
                        self.circuit_breaker.record_retry();
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
                        self.circuit_breaker.trip();
                    }
                }

                return action;
            }
        }

        // No strategy could handle this - default to skip
        tracing::error!("No recovery strategy could handle failed request - skipping");
        RecoveryAction::SkipRequest
    }

    /// Get requests that are ready for retry.
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

    /// Check if sync should continue based on error patterns.
    pub fn should_continue_sync(&self) -> bool {
        !self.circuit_breaker.should_block() && self.error_stats.success_rate() > 0.1 // At least 10% success rate
    }

    /// Get current error statistics.
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

impl Default for QRInfoRecoveryManager {
    fn default() -> Self {
        Self::new()
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

/// Request ready for retry with metadata.
#[derive(Debug)]
pub struct RetryRequest {
    pub original_request: QRInfoRequest,
    pub retry_count: u32,
    pub recovery_metadata: RecoveryMetadata,
}

/// Metadata for recovery strategies.
#[derive(Debug, Default)]
pub struct RecoveryMetadata {
    pub use_different_peer: bool,
    pub reduce_batch_size: bool,
    pub fallback_to_mn_diff: bool,
}

/// Recovery action to take for a failed request.
pub enum RecoveryAction {
    Retry {
        delay: Duration,
        metadata: RecoveryMetadata,
    },
    FallbackStrategy {
        strategy_name: String,
    },
    SkipRequest,
    StopSync,
}

/// Statistics tracking for error analysis and adaptive recovery.
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
        if let Ok(mut recent) = self.recent_errors.try_lock() {
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

/// Circuit breaker to prevent catastrophic failure cascades.
struct CircuitBreaker {
    failure_threshold: u32,
    reset_timeout: Duration,
    state: Mutex<CircuitState>,
    retry_count: AtomicUsize,
}

impl CircuitBreaker {
    fn new(failure_threshold: u32, reset_timeout: Duration) -> Self {
        Self {
            failure_threshold,
            reset_timeout,
            state: Mutex::new(CircuitState::Closed { failure_count: 0 }),
            retry_count: AtomicUsize::new(0),
        }
    }

    fn should_block(&self) -> bool {
        if let Ok(state) = self.state.try_lock() {
            match &*state {
                CircuitState::Open { opened_at } => {
                    // Check if we should transition to half-open
                    if opened_at.elapsed() > self.reset_timeout {
                        drop(state);
                        self.try_half_open();
                        false
                    } else {
                        true
                    }
                }
                CircuitState::HalfOpen => {
                    // Allow one request through
                    false
                }
                CircuitState::Closed { .. } => false,
            }
        } else {
            false
        }
    }

    fn record_retry(&self) {
        self.retry_count.fetch_add(1, Ordering::Relaxed);
    }

    fn record_failure(&self) {
        if let Ok(mut state) = self.state.try_lock() {
            match &*state {
                CircuitState::Closed { failure_count } => {
                    let new_failure_count = *failure_count + 1;
                    if new_failure_count >= self.failure_threshold {
                        *state = CircuitState::Open {
                            opened_at: Instant::now(),
                        };
                        tracing::error!("Circuit breaker opened due to {} failures", new_failure_count);
                    } else {
                        *state = CircuitState::Closed {
                            failure_count: new_failure_count,
                        };
                    }
                }
                CircuitState::HalfOpen => {
                    *state = CircuitState::Open {
                        opened_at: Instant::now(),
                    };
                    tracing::warn!("Circuit breaker re-opened from half-open state");
                }
                _ => {} // Already open
            }
        }
    }

    fn record_success(&self) {
        if let Ok(mut state) = self.state.try_lock() {
            match &*state {
                CircuitState::HalfOpen => {
                    *state = CircuitState::Closed { failure_count: 0 };
                    tracing::info!("Circuit breaker closed after successful recovery");
                }
                CircuitState::Closed { .. } => {
                    *state = CircuitState::Closed { failure_count: 0 };
                }
                _ => {}
            }
        }
    }

    fn try_half_open(&self) {
        if let Ok(mut state) = self.state.try_lock() {
            if matches!(&*state, CircuitState::Open { .. }) {
                *state = CircuitState::HalfOpen;
                tracing::info!("Circuit breaker transitioned to half-open state");
            }
        }
    }

    fn trip(&self) {
        if let Ok(mut state) = self.state.try_lock() {
            *state = CircuitState::Open {
                opened_at: Instant::now(),
            };
            tracing::error!("Circuit breaker manually tripped");
        }
    }
}

#[derive(Debug)]
enum CircuitState {
    Closed { failure_count: u32 },
    Open { opened_at: Instant },
    HalfOpen,
}

/// Trait for different recovery strategies.
#[async_trait::async_trait]
trait RecoveryStrategy: Send + Sync {
    fn name(&self) -> &'static str;

    async fn handle_failure(
        &self,
        failed_request: &FailedRequest,
        error_stats: &ErrorStatistics,
    ) -> Option<RecoveryAction>;
}

/// Exponential backoff with jitter.
struct ExponentialBackoffStrategy {
    max_retries: u32,
    base_delay: Duration,
    max_delay: Duration,
}

impl ExponentialBackoffStrategy {
    fn new(max_retries: u32, base_delay: Duration, max_delay: Duration) -> Self {
        Self {
            max_retries,
            base_delay,
            max_delay,
        }
    }
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

/// Strategy to switch to a different network peer.
struct NetworkSwitchStrategy;

impl NetworkSwitchStrategy {
    fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl RecoveryStrategy for NetworkSwitchStrategy {
    fn name(&self) -> &'static str {
        "NetworkSwitch"
    }

    async fn handle_failure(
        &self,
        failed_request: &FailedRequest,
        _error_stats: &ErrorStatistics,
    ) -> Option<RecoveryAction> {
        // Only use this strategy for network errors after some retries
        if failed_request.attempt_count >= 2
            && matches!(failed_request.error, ParallelExecutionError::Network(_))
        {
            Some(RecoveryAction::Retry {
                delay: Duration::from_secs(5),
                metadata: RecoveryMetadata {
                    use_different_peer: true,
                    ..Default::default()
                },
            })
        } else {
            None
        }
    }
}

/// Fallback to sequential processing.
struct FallbackToSequentialStrategy;

impl FallbackToSequentialStrategy {
    fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl RecoveryStrategy for FallbackToSequentialStrategy {
    fn name(&self) -> &'static str {
        "FallbackToSequential"
    }

    async fn handle_failure(
        &self,
        failed_request: &FailedRequest,
        error_stats: &ErrorStatistics,
    ) -> Option<RecoveryAction> {
        // Use when timeout rate is too high
        if failed_request.attempt_count >= 3 && error_stats.timeout_rate() > 0.5 {
            Some(RecoveryAction::FallbackStrategy {
                strategy_name: "Sequential".to_string(),
            })
        } else {
            None
        }
    }
}

/// Fallback to masternode list diff requests.
struct MnListDiffFallbackStrategy;

impl MnListDiffFallbackStrategy {
    fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl RecoveryStrategy for MnListDiffFallbackStrategy {
    fn name(&self) -> &'static str {
        "MnListDiffFallback"
    }

    async fn handle_failure(
        &self,
        failed_request: &FailedRequest,
        _error_stats: &ErrorStatistics,
    ) -> Option<RecoveryAction> {
        // Use when QRInfo consistently fails
        if failed_request.attempt_count >= 4 {
            Some(RecoveryAction::Retry {
                delay: Duration::from_secs(10),
                metadata: RecoveryMetadata {
                    fallback_to_mn_diff: true,
                    ..Default::default()
                },
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_recovery_manager_creation() {
        let manager = QRInfoRecoveryManager::new();
        assert_eq!(manager.failed_requests.len(), 0);
        assert!(manager.should_continue_sync());
    }

    #[tokio::test]
    async fn test_circuit_breaker() {
        let breaker = CircuitBreaker::new(3, Duration::from_secs(60));
        
        assert!(!breaker.should_block());
        
        // Record failures
        for _ in 0..3 {
            breaker.record_failure();
        }
        
        // Should now block
        assert!(breaker.should_block());
        
        // Record success doesn't help when open
        breaker.record_success();
        assert!(breaker.should_block());
    }

    #[tokio::test]
    async fn test_error_statistics() {
        let stats = ErrorStatistics::new();
        
        stats.record_success();
        stats.record_success();
        stats.record_error(&ParallelExecutionError::Timeout);
        
        assert_eq!(stats.success_rate(), 2.0 / 3.0);
        assert_eq!(stats.timeout_rate(), 1.0 / 3.0);
    }
}