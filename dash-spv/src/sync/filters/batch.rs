use dashcore::bip158::BlockFilter;
use key_wallet_manager::wallet_manager::FilterMatchKey;
use std::collections::HashMap;

/// A completed batch of compact block filters ready for verification.
///
/// Represents a contiguous range of filters that have all been received
/// and can now be verified against their expected filter headers.
/// Ordered by start_height for sequential processing.
#[derive(Debug)]
pub(super) struct FiltersBatch {
    /// Start height of this batch (inclusive).
    start_height: u32,
    /// Ending height of this batch (inclusive).
    end_height: u32,
    /// Filters of this batch.
    filters: HashMap<FilterMatchKey, BlockFilter>,
    /// Whether this batch was verified already (loaded from storage).
    verified: bool,
    /// Whether this batch was scanned already.
    scanned: bool,
    /// Number of blocks still being downloaded for this batch.
    pending_blocks: u32,
    /// Whether rescan has been completed for this batch.
    rescan_complete: bool,
}

impl FiltersBatch {
    /// Create a new batch with given filter data.
    pub(super) fn new(
        start_height: u32,
        end_height: u32,
        filters: HashMap<FilterMatchKey, BlockFilter>,
    ) -> Self {
        Self {
            start_height,
            end_height,
            filters,
            verified: false,
            scanned: false,
            pending_blocks: 0,
            rescan_complete: false,
        }
    }
    /// Start height of this batch (inclusive).
    pub(super) fn start_height(&self) -> u32 {
        self.start_height
    }
    /// Ending height of this batch (inclusive).
    pub(super) fn end_height(&self) -> u32 {
        self.end_height
    }
    /// Reference to the loaded filters map of this batch.
    pub(super) fn filters(&self) -> &HashMap<FilterMatchKey, BlockFilter> {
        &self.filters
    }
    /// Mutable reference to the loaded filters map of this batch.
    pub(super) fn filters_mut(&mut self) -> &mut HashMap<FilterMatchKey, BlockFilter> {
        &mut self.filters
    }
    /// Returns whether this batch is verified (filters verified against their headers).
    pub(super) fn verified(&self) -> bool {
        self.verified
    }
    /// Mark this batch as scanned (filters have been matched against the wallet addresses).
    pub(super) fn mark_scanned(&mut self) {
        self.scanned = true;
    }
    /// Returns whether this batch was scanned already.
    pub(super) fn scanned(&self) -> bool {
        self.scanned
    }
    /// Returns the number of pending blocks for this batch.
    pub(super) fn pending_blocks(&self) -> u32 {
        self.pending_blocks
    }
    /// Set the number of pending blocks for this batch.
    pub(super) fn set_pending_blocks(&mut self, count: u32) {
        self.pending_blocks = count;
    }
    /// Decrement pending blocks count, returning the new count.
    pub(super) fn decrement_pending_blocks(&mut self) -> u32 {
        self.pending_blocks = self.pending_blocks.saturating_sub(1);
        self.pending_blocks
    }
    /// Returns whether rescan has been completed for this batch.
    pub(super) fn rescan_complete(&self) -> bool {
        self.rescan_complete
    }
    /// Mark rescan as complete for this batch.
    pub(super) fn mark_rescan_complete(&mut self) {
        self.rescan_complete = true;
    }
}

impl PartialEq for FiltersBatch {
    fn eq(&self, other: &Self) -> bool {
        self.start_height == other.start_height
    }
}

impl Eq for FiltersBatch {}

impl PartialOrd for FiltersBatch {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FiltersBatch {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.start_height.cmp(&other.start_height)
    }
}

#[cfg(test)]
mod tests {
    use crate::sync::filters::batch::FiltersBatch;
    use dashcore::bip158::BlockFilter;
    use dashcore::Header;
    use key_wallet_manager::wallet_manager::FilterMatchKey;
    use std::collections::{BTreeSet, HashMap};

    #[test]
    fn test_filters_batch_new() {
        let filters = HashMap::new();
        let batch = FiltersBatch::new(100, 199, filters);

        assert_eq!(batch.start_height(), 100);
        assert_eq!(batch.end_height(), 199);
        assert!(!batch.verified());
    }

    #[test]
    fn test_filters_batch_getters() {
        let mut filters = HashMap::new();
        let key = FilterMatchKey::new(100, Header::dummy(100).block_hash());
        filters.insert(key, BlockFilter::new(&[0x01]));

        let batch = FiltersBatch::new(100, 100, filters);

        assert_eq!(batch.start_height(), 100);
        assert_eq!(batch.end_height(), 100);
        assert_eq!(batch.filters().len(), 1);
        assert!(!batch.verified());
    }

    #[test]
    fn test_filters_batch_ordering() {
        let batch1 = FiltersBatch::new(0, 99, HashMap::new());
        let batch2 = FiltersBatch::new(100, 199, HashMap::new());
        let batch3 = FiltersBatch::new(200, 299, HashMap::new());

        let mut set = BTreeSet::new();
        set.insert(batch2);
        set.insert(batch1);
        set.insert(batch3);

        let heights: Vec<_> = set.iter().map(|b| b.start_height()).collect();
        assert_eq!(heights, vec![0, 100, 200]);
    }

    #[test]
    fn test_filters_batch_equality() {
        let batch1 = FiltersBatch::new(100, 199, HashMap::new());
        let mut filters = HashMap::new();
        filters.insert(
            FilterMatchKey::new(100, Header::dummy(100).block_hash()),
            BlockFilter::new(&[0x01]),
        );
        let batch2 = FiltersBatch::new(100, 199, filters);

        // Equal based on start_height only
        assert_eq!(batch1, batch2);
    }
}
