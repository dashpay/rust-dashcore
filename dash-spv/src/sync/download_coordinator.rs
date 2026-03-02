//! Generic download coordinator for pipelined downloads.
//!
//! Provides a single abstraction for managing concurrent downloads with:
//! - Pending queue management
//! - In-flight tracking with timestamps
//! - Timeout detection and retry logic
//! - Configurable concurrency limits

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::time::{Duration, Instant};

/// Configuration for download coordination.
#[derive(Debug, Clone)]
pub struct DownloadConfig {
    /// Maximum concurrent in-flight requests.
    max_concurrent: usize,
    /// Base timeout duration for first attempt.
    timeout: Duration,
    /// Maximum timeout after backoff (caps exponential growth).
    max_timeout: Duration,
    /// Maximum retry attempts before giving up.
    max_retries: u32,
}

impl Default for DownloadConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 10,
            timeout: Duration::from_secs(10),
            max_timeout: Duration::from_secs(120),
            max_retries: 6,
        }
    }
}

impl DownloadConfig {
    /// Create config with custom max concurrent.
    pub(crate) fn with_max_concurrent(mut self, max: usize) -> Self {
        self.max_concurrent = max;
        self
    }

    /// Create config with custom base timeout.
    #[cfg(test)]
    pub(crate) fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Create config with custom max retries.
    #[cfg(test)]
    pub(crate) fn with_max_retries(mut self, max: u32) -> Self {
        self.max_retries = max;
        self
    }
}

/// Generic download coordinator.
///
/// Handles the common mechanics of pipelined downloads:
/// - Queue management (pending items)
/// - In-flight tracking with timestamps
/// - Timeout detection and retry
/// - Concurrency limits
///
/// Generic over the key type `K` which identifies download items.
/// Use `u32` for height-based downloads, `BlockHash` for hash-based.
#[derive(Debug)]
pub(crate) struct DownloadCoordinator<K: Hash + Eq + Clone> {
    /// Items waiting to be requested.
    pending: VecDeque<K>,
    /// Items currently in-flight (key -> sent time).
    in_flight: HashMap<K, Instant>,
    /// Retry counts per key.
    retry_counts: HashMap<K, u32>,
    /// Configuration.
    config: DownloadConfig,
    /// Last time progress was made.
    last_progress: Instant,
}

impl<K: Hash + Eq + Clone> Default for DownloadCoordinator<K> {
    fn default() -> Self {
        Self::new(DownloadConfig::default())
    }
}

impl<K: Hash + Eq + Clone> DownloadCoordinator<K> {
    /// Create a new coordinator with the given configuration.
    pub(crate) fn new(config: DownloadConfig) -> Self {
        Self {
            pending: VecDeque::new(),
            in_flight: HashMap::new(),
            retry_counts: HashMap::new(),
            config,
            last_progress: Instant::now(),
        }
    }

    /// Clear all state.
    pub(crate) fn clear(&mut self) {
        self.pending.clear();
        self.in_flight.clear();
        self.retry_counts.clear();
        self.last_progress = Instant::now();
    }

    /// Queue items for download.
    pub(crate) fn enqueue(&mut self, items: impl IntoIterator<Item = K>) {
        for item in items {
            self.pending.push_back(item);
        }
    }

    /// Queue an item for retry (goes to front of queue).
    ///
    /// Returns false if max retries exceeded.
    pub(crate) fn enqueue_retry(&mut self, item: K) -> bool {
        let count = self.retry_counts.entry(item.clone()).or_insert(0);
        if *count >= self.config.max_retries {
            tracing::warn!("Max retries ({}) exceeded, giving up", self.config.max_retries);
            return false;
        }
        *count += 1;
        self.pending.push_front(item);
        true
    }

    /// Get the number of items available to send (respecting concurrency limit).
    pub(crate) fn available_to_send(&self) -> usize {
        self.config.max_concurrent.saturating_sub(self.in_flight.len()).min(self.pending.len())
    }

    /// Take items from the pending queue (up to count).
    ///
    /// Items are removed from pending but NOT yet marked as in-flight.
    /// Call `mark_sent` after successfully sending the request.
    pub(crate) fn take_pending(&mut self, count: usize) -> Vec<K> {
        let actual = count.min(self.pending.len());
        let mut items = Vec::with_capacity(actual);
        for _ in 0..actual {
            if let Some(item) = self.pending.pop_front() {
                items.push(item);
            }
        }
        items
    }

    /// Mark items as sent (now in-flight).
    pub(crate) fn mark_sent(&mut self, items: &[K]) {
        let now = Instant::now();
        for item in items {
            self.in_flight.insert(item.clone(), now);
        }
    }

    /// Handle a received item.
    ///
    /// Returns true if the item was being tracked, false if unexpected.
    pub(crate) fn receive(&mut self, key: &K) -> bool {
        if self.in_flight.remove(key).is_some() {
            self.last_progress = Instant::now();
            true
        } else {
            false
        }
    }

    /// Check if an item is currently in-flight.
    pub(crate) fn is_in_flight(&self, key: &K) -> bool {
        self.in_flight.contains_key(key)
    }

    /// Compute the effective timeout for an item based on its retry count.
    ///
    /// Uses exponential backoff: `min(base_timeout * 2^retry_count, max_timeout)`.
    fn effective_timeout(&self, key: &K) -> Duration {
        let retries = self.retry_counts.get(key).copied().unwrap_or(0);
        let multiplier = 1u32.checked_shl(retries).unwrap_or(u32::MAX);
        let backed_off = self.config.timeout.saturating_mul(multiplier);
        backed_off.min(self.config.max_timeout)
    }

    /// Check for timed-out items.
    ///
    /// Returns items that have timed out. They are removed from in-flight tracking.
    /// Caller should call `enqueue_retry` for items that should be retried.
    /// Each item's timeout is computed with exponential backoff based on its retry count.
    pub(crate) fn check_timeouts(&mut self) -> Vec<K> {
        let now = Instant::now();
        let timed_out: Vec<K> = self
            .in_flight
            .iter()
            .filter(|(key, sent_time)| {
                now.duration_since(**sent_time) > self.effective_timeout(key)
            })
            .map(|(key, _)| key.clone())
            .collect();

        for key in &timed_out {
            self.in_flight.remove(key);
        }

        if !timed_out.is_empty() {
            tracing::debug!("{} items timed out", timed_out.len());
        }

        timed_out
    }

    /// Check if the coordinator has no work (empty pending and in-flight).
    pub(crate) fn is_empty(&self) -> bool {
        self.pending.is_empty() && self.in_flight.is_empty()
    }

    /// Get the number of pending items.
    pub(crate) fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Get the number of in-flight items.
    pub(crate) fn active_count(&self) -> usize {
        self.in_flight.len()
    }

    /// Get the total remaining items (pending + in-flight).
    pub(crate) fn remaining(&self) -> usize {
        self.pending.len() + self.in_flight.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_coordinator() {
        let coord: DownloadCoordinator<u32> = DownloadCoordinator::default();
        assert!(coord.is_empty());
        assert_eq!(coord.pending_count(), 0);
        assert_eq!(coord.active_count(), 0);
    }

    #[test]
    fn test_enqueue() {
        let mut coord: DownloadCoordinator<u32> = DownloadCoordinator::default();
        coord.enqueue([1, 2, 3, 4, 5]);

        assert_eq!(coord.pending_count(), 5);
    }

    #[test]
    fn test_enqueue_retry_goes_to_front() {
        let mut coord: DownloadCoordinator<u32> = DownloadCoordinator::default();
        coord.enqueue([1, 2]);
        coord.enqueue_retry(99);

        let items = coord.take_pending(3);
        assert_eq!(items, vec![99, 1, 2]);
    }

    #[test]
    fn test_max_retries() {
        let mut coord: DownloadCoordinator<u32> =
            DownloadCoordinator::new(DownloadConfig::default().with_max_retries(2));

        assert!(coord.enqueue_retry(1));
        assert!(coord.enqueue_retry(1));
        assert!(!coord.enqueue_retry(1)); // Exceeds max
    }

    #[test]
    fn test_take_pending() {
        let mut coord: DownloadCoordinator<u32> = DownloadCoordinator::default();
        coord.enqueue([1, 2, 3, 4, 5]);

        let items = coord.take_pending(3);
        assert_eq!(items, vec![1, 2, 3]);
        assert_eq!(coord.pending_count(), 2);
    }

    #[test]
    fn test_mark_sent() {
        let mut coord: DownloadCoordinator<u32> = DownloadCoordinator::default();
        coord.enqueue([1, 2, 3]);

        let items = coord.take_pending(2);
        coord.mark_sent(&items);

        assert_eq!(coord.pending_count(), 1);
        assert_eq!(coord.active_count(), 2);
        assert!(coord.is_in_flight(&1));
        assert!(coord.is_in_flight(&2));
        assert!(!coord.is_in_flight(&3));
    }

    #[test]
    fn test_receive() {
        let mut coord: DownloadCoordinator<u32> = DownloadCoordinator::default();
        coord.mark_sent(&[1]);
        coord.mark_sent(&[2]);

        assert!(coord.receive(&1));
        assert_eq!(coord.active_count(), 1);

        assert!(!coord.receive(&99)); // Not tracked
        assert_eq!(coord.active_count(), 1);
    }

    #[test]
    fn test_available_to_send() {
        let mut coord: DownloadCoordinator<u32> =
            DownloadCoordinator::new(DownloadConfig::default().with_max_concurrent(3));

        coord.enqueue([1, 2, 3, 4, 5]);
        assert_eq!(coord.available_to_send(), 3);

        coord.mark_sent(&[1]);
        coord.mark_sent(&[2]);
        assert_eq!(coord.available_to_send(), 1);

        coord.mark_sent(&[3]);
        assert_eq!(coord.available_to_send(), 0);
    }

    #[test]
    fn test_check_timeouts() {
        let mut coord: DownloadCoordinator<u32> = DownloadCoordinator::new(
            DownloadConfig::default().with_timeout(Duration::from_millis(50)),
        );

        coord.mark_sent(&[1]);
        coord.mark_sent(&[2]);

        // Immediately, nothing timed out
        let timed_out = coord.check_timeouts();
        assert!(timed_out.is_empty());

        // Wait well past timeout
        std::thread::sleep(Duration::from_millis(200));

        let timed_out = coord.check_timeouts();
        assert_eq!(timed_out.len(), 2);
        assert!(coord.in_flight.is_empty());
    }

    #[test]
    fn test_clear() {
        let mut coord: DownloadCoordinator<u32> = DownloadCoordinator::default();
        coord.enqueue([1, 2, 3]);
        coord.mark_sent(&[4]);
        coord.enqueue_retry(5);

        coord.clear();

        assert!(coord.is_empty());
        assert_eq!(coord.pending_count(), 0);
        assert_eq!(coord.active_count(), 0);
    }

    #[test]
    fn test_remaining() {
        let mut coord: DownloadCoordinator<u32> = DownloadCoordinator::default();
        coord.enqueue([1, 2, 3]);
        coord.mark_sent(&[4]);
        coord.mark_sent(&[5]);

        assert_eq!(coord.remaining(), 5);
    }

    #[test]
    fn test_config_builders() {
        let config = DownloadConfig::default()
            .with_max_concurrent(20)
            .with_timeout(Duration::from_secs(60))
            .with_max_retries(5);

        assert_eq!(config.max_concurrent, 20);
        assert_eq!(config.timeout, Duration::from_secs(60));
        assert_eq!(config.max_retries, 5);
    }

    #[test]
    fn test_with_string_keys() {
        let mut coord: DownloadCoordinator<String> = DownloadCoordinator::default();
        coord.enqueue(["block_a".to_string(), "block_b".to_string()]);

        let items = coord.take_pending(1);
        coord.mark_sent(&items);

        assert!(coord.receive(&"block_a".to_string()));
        assert!(!coord.receive(&"block_c".to_string()));
    }

    #[test]
    fn test_default_config_values() {
        let config = DownloadConfig::default();
        assert_eq!(config.timeout, Duration::from_secs(10));
        assert_eq!(config.max_timeout, Duration::from_secs(120));
        assert_eq!(config.max_retries, 6);
        assert_eq!(config.max_concurrent, 10);
    }

    #[test]
    fn test_effective_timeout_scales_exponentially() {
        let mut coord: DownloadCoordinator<u32> = DownloadCoordinator::default();

        // No retries yet: base timeout (10s)
        assert_eq!(coord.effective_timeout(&1), Duration::from_secs(10));

        // Build up retry counts via the public API
        coord.enqueue_retry(1); // retry_count = 1
        assert_eq!(coord.effective_timeout(&1), Duration::from_secs(20));

        coord.enqueue_retry(1); // retry_count = 2
        assert_eq!(coord.effective_timeout(&1), Duration::from_secs(40));

        coord.enqueue_retry(1); // retry_count = 3
        assert_eq!(coord.effective_timeout(&1), Duration::from_secs(80));

        coord.enqueue_retry(1); // retry_count = 4
        assert_eq!(coord.effective_timeout(&1), Duration::from_secs(120));

        coord.enqueue_retry(1); // retry_count = 5
        assert_eq!(coord.effective_timeout(&1), Duration::from_secs(120));

        coord.enqueue_retry(1); // retry_count = 6 — hits max, rejected
        assert_eq!(coord.effective_timeout(&1), Duration::from_secs(120));
    }
}
