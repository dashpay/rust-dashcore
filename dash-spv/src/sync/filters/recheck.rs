//! Filter re-checking infrastructure
//!
//! When gap limits change during block processing, we need to re-check compact filters
//! with the new set of addresses. This module provides the infrastructure to track
//! which filters need re-checking and manage the re-check iterations.

use std::collections::VecDeque;

/// Configuration for filter re-checking behavior
#[derive(Debug, Clone)]
pub struct FilterRecheckConfig {
    /// Whether filter re-checking is enabled
    pub enabled: bool,
    /// Maximum number of re-check iterations to prevent infinite loops
    pub max_iterations: u32,
}

impl Default for FilterRecheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_iterations: 10,
        }
    }
}

/// Represents a range of block heights that need filter re-checking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecheckRange {
    /// Starting height (inclusive)
    pub start: u32,
    /// Ending height (inclusive)
    pub end: u32,
    /// Which iteration this is (for loop detection)
    pub iteration: u32,
}

impl RecheckRange {
    /// Create a new recheck range
    pub fn new(start: u32, end: u32, iteration: u32) -> Self {
        Self {
            start,
            end,
            iteration,
        }
    }

    /// Check if this range contains a height
    pub fn contains(&self, height: u32) -> bool {
        height >= self.start && height <= self.end
    }

    /// Get the number of blocks in this range
    pub fn len(&self) -> u32 {
        self.end.saturating_sub(self.start).saturating_add(1)
    }

    /// Check if the range is empty
    pub fn is_empty(&self) -> bool {
        self.end < self.start
    }
}

/// Queue for managing filter re-check operations
#[derive(Debug)]
pub struct FilterRecheckQueue {
    /// Queue of ranges that need re-checking
    pending_ranges: VecDeque<RecheckRange>,
    /// Configuration
    config: FilterRecheckConfig,
    /// Total number of ranges added (for statistics)
    total_ranges_added: u64,
    /// Total number of ranges completed (for statistics)
    total_ranges_completed: u64,
}

impl FilterRecheckQueue {
    /// Create a new filter recheck queue
    pub fn new(config: FilterRecheckConfig) -> Self {
        Self {
            pending_ranges: VecDeque::new(),
            config,
            total_ranges_added: 0,
            total_ranges_completed: 0,
        }
    }

    /// Add a range to be re-checked
    ///
    /// Returns Ok(()) if the range was added, or Err with a message if it was rejected
    /// (e.g., due to exceeding max iterations)
    pub fn add_range(&mut self, start: u32, end: u32, iteration: u32) -> Result<(), String> {
        if !self.config.enabled {
            return Err("Filter re-checking is disabled".to_string());
        }

        if iteration >= self.config.max_iterations {
            return Err(format!(
                "Maximum re-check iterations ({}) exceeded for range {}-{}",
                self.config.max_iterations, start, end
            ));
        }

        let range = RecheckRange::new(start, end, iteration);

        // Check if we already have this range queued
        if self.pending_ranges.iter().any(|r| r.start == start && r.end == end) {
            tracing::debug!("Range {}-{} already queued for re-check, skipping", start, end);
            return Ok(());
        }

        tracing::info!(
            "📋 Queuing filter re-check for heights {}-{} (iteration {}/{})",
            start,
            end,
            iteration + 1,
            self.config.max_iterations
        );

        self.pending_ranges.push_back(range);
        self.total_ranges_added += 1;
        Ok(())
    }

    /// Get the next range to re-check
    pub fn next_range(&mut self) -> Option<RecheckRange> {
        self.pending_ranges.pop_front()
    }

    /// Mark a range as completed
    pub fn mark_completed(&mut self, _range: &RecheckRange) {
        self.total_ranges_completed += 1;
    }

    /// Check if there are any pending re-checks
    pub fn has_pending(&self) -> bool {
        !self.pending_ranges.is_empty()
    }

    /// Get the number of pending ranges
    pub fn pending_count(&self) -> usize {
        self.pending_ranges.len()
    }

    /// Clear all pending ranges
    pub fn clear(&mut self) {
        self.pending_ranges.clear();
    }

    /// Get statistics about re-check operations
    pub fn stats(&self) -> RecheckStats {
        RecheckStats {
            pending_ranges: self.pending_ranges.len(),
            total_added: self.total_ranges_added,
            total_completed: self.total_ranges_completed,
            config: self.config.clone(),
        }
    }

    /// Check if re-checking is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

/// Statistics about filter re-check operations
#[derive(Debug, Clone)]
pub struct RecheckStats {
    /// Number of ranges currently pending
    pub pending_ranges: usize,
    /// Total ranges added since creation
    pub total_added: u64,
    /// Total ranges completed
    pub total_completed: u64,
    /// Configuration
    pub config: FilterRecheckConfig,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recheck_range_basic() {
        let range = RecheckRange::new(100, 200, 0);
        assert_eq!(range.start, 100);
        assert_eq!(range.end, 200);
        assert_eq!(range.iteration, 0);
        assert_eq!(range.len(), 101);
        assert!(!range.is_empty());
    }

    #[test]
    fn test_recheck_range_contains() {
        let range = RecheckRange::new(100, 200, 0);
        assert!(!range.contains(99));
        assert!(range.contains(100));
        assert!(range.contains(150));
        assert!(range.contains(200));
        assert!(!range.contains(201));
    }

    #[test]
    fn test_recheck_queue_add_and_retrieve() {
        let mut queue = FilterRecheckQueue::new(FilterRecheckConfig::default());

        // Add a range
        assert!(queue.add_range(100, 200, 0).is_ok());
        assert_eq!(queue.pending_count(), 1);
        assert!(queue.has_pending());

        // Retrieve it
        let range = queue.next_range().unwrap();
        assert_eq!(range.start, 100);
        assert_eq!(range.end, 200);
        assert_eq!(queue.pending_count(), 0);
        assert!(!queue.has_pending());
    }

    #[test]
    fn test_recheck_queue_max_iterations() {
        let config = FilterRecheckConfig {
            enabled: true,
            max_iterations: 3,
        };
        let mut queue = FilterRecheckQueue::new(config);

        // These should succeed
        assert!(queue.add_range(100, 200, 0).is_ok());
        assert!(queue.add_range(100, 200, 1).is_ok());
        assert!(queue.add_range(100, 200, 2).is_ok());

        // This should fail (iteration 3 >= max_iterations 3)
        assert!(queue.add_range(100, 200, 3).is_err());
    }

    #[test]
    fn test_recheck_queue_disabled() {
        let config = FilterRecheckConfig {
            enabled: false,
            max_iterations: 10,
        };
        let mut queue = FilterRecheckQueue::new(config);

        // Should fail when disabled
        assert!(queue.add_range(100, 200, 0).is_err());
    }

    #[test]
    fn test_recheck_queue_duplicate_detection() {
        let mut queue = FilterRecheckQueue::new(FilterRecheckConfig::default());

        // Add the same range twice
        assert!(queue.add_range(100, 200, 0).is_ok());
        assert!(queue.add_range(100, 200, 0).is_ok()); // Should succeed but not add

        // Should only have one range
        assert_eq!(queue.pending_count(), 1);
    }

    #[test]
    fn test_recheck_queue_stats() {
        let mut queue = FilterRecheckQueue::new(FilterRecheckConfig::default());

        queue.add_range(100, 200, 0).unwrap();
        queue.add_range(201, 300, 0).unwrap();

        let stats = queue.stats();
        assert_eq!(stats.pending_ranges, 2);
        assert_eq!(stats.total_added, 2);
        assert_eq!(stats.total_completed, 0);

        // Complete one
        let range = queue.next_range().unwrap();
        queue.mark_completed(&range);

        let stats = queue.stats();
        assert_eq!(stats.pending_ranges, 1);
        assert_eq!(stats.total_completed, 1);
    }

    #[test]
    fn test_recheck_queue_clear() {
        let mut queue = FilterRecheckQueue::new(FilterRecheckConfig::default());

        queue.add_range(100, 200, 0).unwrap();
        queue.add_range(201, 300, 0).unwrap();
        assert_eq!(queue.pending_count(), 2);

        queue.clear();
        assert_eq!(queue.pending_count(), 0);
        assert!(!queue.has_pending());
    }
}
