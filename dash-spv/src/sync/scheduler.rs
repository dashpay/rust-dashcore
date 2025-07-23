//! Intelligent request scheduling for QRInfo synchronization.
//!
//! This module provides priority-based scheduling with rate limiting,
//! network condition adaptation, and retry with exponential backoff.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use tokio::time::{interval, Interval};

use crate::sync::discovery::QRInfoRequest;
use crate::sync::parallel::ParallelExecutionError;

/// Intelligent scheduler for QRInfo requests with priority and rate limiting.
pub struct QRInfoScheduler {
    /// Priority queue of pending requests.
    request_queue: BinaryHeap<ScheduledRequest>,
    /// Rate limiter for network requests.
    rate_limiter: RateLimiter,
    /// Maximum requests per time window.
    max_requests_per_window: usize,
    /// Time window for rate limiting.
    rate_limit_window: Duration,
    /// Network condition monitor.
    network_monitor: NetworkConditionMonitor,
}

impl QRInfoScheduler {
    /// Create a new scheduler.
    pub fn new(max_requests_per_window: usize, rate_limit_window: Duration) -> Self {
        Self {
            request_queue: BinaryHeap::new(),
            rate_limiter: RateLimiter::new(max_requests_per_window, rate_limit_window),
            max_requests_per_window,
            rate_limit_window,
            network_monitor: NetworkConditionMonitor::new(),
        }
    }

    /// Schedule a QRInfo request with priority and timing.
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
            priority,
            self.request_queue.len()
        );
    }

    /// Get the next batch of requests ready for execution.
    pub async fn get_next_batch(&mut self, max_batch_size: usize) -> Vec<QRInfoRequest> {
        let mut batch = Vec::new();
        let network_conditions = self.network_monitor.get_current_conditions().await;

        // Adjust batch size based on network conditions
        let effective_batch_size =
            self.calculate_effective_batch_size(max_batch_size, &network_conditions);

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

    /// Handle a failed request - reschedule with backoff if retries available.
    pub fn handle_request_failure(
        &mut self,
        request: QRInfoRequest,
        error: &ParallelExecutionError,
    ) {
        // Find if this request was already scheduled (for retry tracking)
        let mut scheduled = ScheduledRequest {
            request: request.clone(),
            priority: SchedulePriority::Normal,
            scheduled_time: Instant::now(),
            retry_count: 0,
            max_retries: 3,
        };

        // Check if we can find existing retry information
        let temp_queue: Vec<_> = self.request_queue.drain().collect();
        for existing in &temp_queue {
            if existing.request == request {
                scheduled.retry_count = existing.retry_count;
                scheduled.max_retries = existing.max_retries;
                break;
            }
        }
        // Restore queue
        for item in temp_queue {
            if item.request != request {
                self.request_queue.push(item);
            }
        }

        scheduled.retry_count += 1;
        let retry_count = scheduled.retry_count;
        let max_retries = scheduled.max_retries;

        if retry_count <= max_retries {
            // Reschedule with exponential backoff
            let backoff_delay = Duration::from_secs(2_u64.pow(retry_count as u32));
            scheduled.scheduled_time = Instant::now() + backoff_delay;
            scheduled.priority = self.adjust_priority_for_retry(scheduled.priority, error);

            self.request_queue.push(scheduled);

            tracing::info!(
                "Rescheduled failed request (retry {}/{}) with {}s backoff",
                retry_count,
                max_retries,
                backoff_delay.as_secs()
            );
        } else {
            tracing::error!(
                "Request failed permanently after {} retries: {:?}",
                max_retries,
                error
            );
        }
    }

    /// Calculate effective batch size based on network conditions.
    fn calculate_effective_batch_size(
        &self,
        max_batch_size: usize,
        conditions: &NetworkConditions,
    ) -> usize {
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

    /// Check if a request is ready for execution.
    fn is_ready_for_execution(
        &self,
        scheduled: &ScheduledRequest,
        conditions: &NetworkConditions,
    ) -> bool {
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

    fn adjust_priority_for_retry(
        &self,
        current: SchedulePriority,
        error: &ParallelExecutionError,
    ) -> SchedulePriority {
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

    /// Get the number of pending requests.
    pub fn pending_count(&self) -> usize {
        self.request_queue.len()
    }

    /// Clear all pending requests.
    pub fn clear(&mut self) {
        self.request_queue.clear();
    }
}

#[derive(Debug, Clone)]
struct ScheduledRequest {
    request: QRInfoRequest,
    priority: SchedulePriority,
    scheduled_time: Instant,
    retry_count: u32,
    max_retries: u32,
}

impl PartialEq for ScheduledRequest {
    fn eq(&self, other: &Self) -> bool {
        self.request == other.request && self.priority == other.priority
    }
}

impl Eq for ScheduledRequest {}

impl Ord for ScheduledRequest {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Higher priority first, then earlier scheduled time
        self.priority
            .cmp(&other.priority)
            .then_with(|| other.scheduled_time.cmp(&self.scheduled_time))
    }
}

impl PartialOrd for ScheduledRequest {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Priority levels for request scheduling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SchedulePriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

/// Simple rate limiter using token bucket algorithm.
struct RateLimiter {
    tokens: Arc<AtomicUsize>,
    max_tokens: usize,
    refill_interval: Interval,
    refill_amount: usize,
}

impl RateLimiter {
    fn new(max_requests: usize, window: Duration) -> Self {
        let refill_amount = max_requests;
        let mut refill_interval = interval(window);
        refill_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

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

    async fn refill(&mut self) {
        self.refill_interval.tick().await;
        self.tokens.store(self.max_tokens, Ordering::Relaxed);
    }
}

/// Monitor network conditions for scheduling decisions.
struct NetworkConditionMonitor {
    last_measurement: Arc<Mutex<Option<(NetworkConditions, Instant)>>>,
    measurement_interval: Duration,
    recent_latencies: Arc<Mutex<VecDeque<Duration>>>,
    recent_failures: Arc<AtomicUsize>,
    total_requests: Arc<AtomicUsize>,
}

impl NetworkConditionMonitor {
    fn new() -> Self {
        Self {
            last_measurement: Arc::new(Mutex::new(None)),
            measurement_interval: Duration::from_secs(30),
            recent_latencies: Arc::new(Mutex::new(VecDeque::with_capacity(100))),
            recent_failures: Arc::new(AtomicUsize::new(0)),
            total_requests: Arc::new(AtomicUsize::new(0)),
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
        // Calculate average latency from recent requests
        let avg_latency = {
            let latencies = self.recent_latencies.lock().await;
            if latencies.is_empty() {
                Duration::from_millis(100) // Default estimate
            } else {
                let sum: Duration = latencies.iter().sum();
                sum / latencies.len() as u32
            }
        };
        
        // Calculate failure rate
        let total = self.total_requests.load(Ordering::Relaxed);
        let failures = self.recent_failures.load(Ordering::Relaxed);
        let failure_rate = if total > 0 {
            failures as f32 / total as f32
        } else {
            0.0
        };
        
        // Determine network conditions based on metrics
        NetworkConditions {
            high_latency: avg_latency > Duration::from_secs(2),
            low_bandwidth: avg_latency > Duration::from_secs(5), // Very high latency suggests bandwidth issues
            unstable_connection: failure_rate > 0.1, // More than 10% failure rate
        }
    }
    
    /// Record a successful request with its latency.
    pub async fn record_success(&self, latency: Duration) {
        let mut latencies = self.recent_latencies.lock().await;
        latencies.push_back(latency);
        if latencies.len() > 100 {
            latencies.pop_front();
        }
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Record a failed request.
    pub fn record_failure(&self) {
        self.recent_failures.fetch_add(1, Ordering::Relaxed);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Reset statistics periodically to keep them fresh.
    pub fn reset_statistics(&self) {
        self.recent_failures.store(0, Ordering::Relaxed);
        self.total_requests.store(0, Ordering::Relaxed);
    }
}

/// Network condition information.
#[derive(Debug, Clone, Copy)]
pub struct NetworkConditions {
    pub high_latency: bool,
    pub low_bandwidth: bool,
    pub unstable_connection: bool,
}

impl NetworkConditions {
    /// Check if network conditions are optimal.
    pub fn is_optimal(&self) -> bool {
        !self.high_latency && !self.low_bandwidth && !self.unstable_connection
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::BlockHash;

    fn create_test_qr_info_request_with_id(id: u32) -> QRInfoRequest {
        QRInfoRequest {
            base_hash: BlockHash::from_byte_array([id as u8; 32]),
            tip_hash: BlockHash::from_byte_array([(id + 1) as u8; 32]),
            base_height: id * 100,
            tip_height: (id + 1) * 100,
            priority: id,
            extra_share: false,
        }
    }

    #[tokio::test]
    async fn test_priority_based_scheduling() {
        let mut scheduler = QRInfoScheduler::new(10, Duration::from_secs(60));

        // Schedule requests with different priorities
        let low_priority_req = create_test_qr_info_request_with_id(1);
        let high_priority_req = create_test_qr_info_request_with_id(2);
        let critical_req = create_test_qr_info_request_with_id(3);

        scheduler.schedule_request(low_priority_req.clone(), SchedulePriority::Low);
        scheduler.schedule_request(high_priority_req.clone(), SchedulePriority::High);
        scheduler.schedule_request(critical_req.clone(), SchedulePriority::Critical);

        // Get next batch - should return critical first
        let batch = scheduler.get_next_batch(3).await;

        assert_eq!(batch.len(), 3);
        // First request should be critical (highest priority)
        assert_eq!(batch[0].tip_hash, critical_req.tip_hash);
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
        let request = create_test_qr_info_request_with_id(1);

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

        // Get batch under good conditions
        let batch_good_conditions = scheduler.get_next_batch(5).await;
        
        assert!(batch_good_conditions.len() <= 5);
        assert!(batch_good_conditions.len() > 0);
    }

    #[tokio::test]
    async fn test_clear_scheduler() {
        let mut scheduler = QRInfoScheduler::new(10, Duration::from_secs(60));

        // Schedule some requests
        for i in 0..5 {
            let request = create_test_qr_info_request_with_id(i);
            scheduler.schedule_request(request, SchedulePriority::Normal);
        }

        assert_eq!(scheduler.pending_count(), 5);

        // Clear all requests
        scheduler.clear();
        assert_eq!(scheduler.pending_count(), 0);

        // Getting next batch should return empty
        let batch = scheduler.get_next_batch(10).await;
        assert_eq!(batch.len(), 0);
    }
}