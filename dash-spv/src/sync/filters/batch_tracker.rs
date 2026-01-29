use dashcore::bip158::BlockFilter;
use dashcore::BlockHash;
use key_wallet_manager::wallet_manager::FilterMatchKey;
use std::collections::{HashMap, HashSet};

/// Tracks individual filters within a batch.
///
/// CFilter are requested in batched and requests result in one response per filter/block.
/// This struct tracks which heights within a batch have been received
/// and buffers the filter data for batch verification/matching.
#[derive(Debug)]
pub(super) struct BatchTracker {
    /// Ending height of this batch (inclusive).
    end_height: u32,
    /// Heights within this batch that have been received.
    received: HashSet<u32>,
    /// Buffered filters of this batch.
    filters: HashMap<FilterMatchKey, BlockFilter>,
}

impl BatchTracker {
    /// Create a new batch tracker.
    pub(super) fn new(end_height: u32) -> Self {
        Self {
            end_height,
            received: HashSet::new(),
            filters: HashMap::new(),
        }
    }

    /// Insert a filter with its data.
    pub(super) fn insert_filter(&mut self, height: u32, block_hash: BlockHash, filter_data: &[u8]) {
        self.received.insert(height);
        let key = FilterMatchKey::new(height, block_hash);
        let filter = BlockFilter::new(filter_data);
        self.filters.insert(key, filter);
    }

    /// Take the buffered filters.
    pub(super) fn take_filters(&mut self) -> HashMap<FilterMatchKey, BlockFilter> {
        std::mem::take(&mut self.filters)
    }

    /// Check if all filters in this batch have been received.
    pub(super) fn is_complete(&self, start_height: u32) -> bool {
        let expected = (self.end_height - start_height + 1) as usize;
        self.received.len() >= expected
    }

    /// Get the heights that are missing from this batch.
    pub(super) fn missing_heights(&self, start_height: u32) -> Vec<u32> {
        (start_height..=self.end_height).filter(|h| !self.received.contains(h)).collect()
    }
    pub(super) fn end_height(&self) -> u32 {
        self.end_height
    }
    pub(super) fn received(&self) -> u32 {
        self.received.len() as u32
    }
}

#[cfg(test)]
mod tests {
    use crate::sync::filters::batch_tracker::BatchTracker;
    use dashcore::Header;

    /// Generate dummy filter data for testing.
    fn dummy_filter_data(height: u32) -> Vec<u8> {
        vec![height as u8, (height >> 8) as u8, 0x01, 0x02]
    }

    #[test]
    fn test_batch_tracker_new() {
        let tracker = BatchTracker::new(999);
        assert_eq!(tracker.end_height(), 999);
        assert_eq!(tracker.received(), 0);
        assert!(tracker.filters.is_empty());
    }

    #[test]
    fn test_batch_tracker_insert_filter() {
        let mut tracker = BatchTracker::new(10);
        let hash = Header::dummy(5).block_hash();
        let data = dummy_filter_data(5);

        tracker.insert_filter(5, hash, &data);

        assert_eq!(tracker.received(), 1);
        assert!(tracker.received.contains(&5));
        assert_eq!(tracker.filters.len(), 1);
    }

    #[test]
    fn test_batch_tracker_is_complete() {
        let mut tracker = BatchTracker::new(2);
        let start_height = 0;

        // Not complete initially
        assert!(!tracker.is_complete(start_height));

        // Add filters
        for h in 0..=2 {
            let hash = Header::dummy(h).block_hash();
            tracker.insert_filter(h, hash, &dummy_filter_data(h));
        }

        // Now complete (3 filters: 0, 1, 2)
        assert!(tracker.is_complete(start_height));
    }

    #[test]
    fn test_batch_tracker_missing_heights() {
        let mut tracker = BatchTracker::new(4);
        let start_height = 0;

        // Insert some but not all
        tracker.insert_filter(0, Header::dummy(0).block_hash(), &dummy_filter_data(0));
        tracker.insert_filter(2, Header::dummy(2).block_hash(), &dummy_filter_data(2));
        tracker.insert_filter(4, Header::dummy(4).block_hash(), &dummy_filter_data(4));

        let missing = tracker.missing_heights(start_height);
        assert_eq!(missing, vec![1, 3]);
    }

    #[test]
    fn test_batch_tracker_take_filters() {
        let mut tracker = BatchTracker::new(1);

        tracker.insert_filter(0, Header::dummy(0).block_hash(), &dummy_filter_data(0));
        tracker.insert_filter(1, Header::dummy(1).block_hash(), &dummy_filter_data(1));

        assert_eq!(tracker.filters.len(), 2);

        let taken = tracker.take_filters();
        assert_eq!(taken.len(), 2);
        assert!(tracker.filters.is_empty());
    }
}
