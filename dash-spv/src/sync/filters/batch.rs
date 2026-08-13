use dashcore::bip158::BlockFilter;
use dashcore::ScriptBuf;
use key_wallet_manager::{FilterMatchKey, WalletId};
use std::collections::{BTreeMap, HashMap, HashSet};

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
    /// Wallets that were behind for this batch's height range at scan time —
    /// and therefore need their `synced_height` advanced when the batch
    /// commits — each mapped to the wallet's `account_generation` at scan
    /// time. Commit refuses to advance a wallet whose generation has changed
    /// since the scan: an account added mid-flight means the scan did not test
    /// the new account's scripts, so the batch cannot certify coverage for the
    /// current account set (dashpay/rust-dashcore#649). Already-synced wallets
    /// must not be touched.
    scanned_wallets: BTreeMap<WalletId, u64>,
    /// Cached scriptPubKeys discovered during block processing that still
    /// need rescan, attributed per wallet so we can rerun matching only
    /// against the wallet that produced each new script.
    collected_scripts: HashMap<WalletId, HashSet<ScriptBuf>>,
    /// The manager's script-derivation generation observed the last time
    /// this batch's filters were matched against the wallets' FULL script
    /// sets (the initial scan, or a commit-time verification rescan).
    ///
    /// Commit compares this against the current generation to decide
    /// whether a verification rescan is still needed: scripts derived from
    /// blocks owned by OTHER batches never land in this batch's
    /// `collected_scripts`, so "no collected scripts left" alone does not
    /// prove this batch has nothing more to match.
    full_match_generation: u64,
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
            scanned_wallets: BTreeMap::new(),
            collected_scripts: HashMap::new(),
            full_match_generation: 0,
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
    /// Mark this batch as verified (filters matched their expected headers).
    pub(super) fn mark_verified(&mut self) {
        self.verified = true;
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
    /// The script-derivation generation at this batch's last full-set match.
    pub(super) fn full_match_generation(&self) -> u64 {
        self.full_match_generation
    }
    /// Record the script-derivation generation this batch was fully matched at.
    pub(super) fn set_full_match_generation(&mut self, generation: u64) {
        self.full_match_generation = generation;
    }
    /// Mark rescan as complete for this batch.
    pub(super) fn mark_rescan_complete(&mut self) {
        self.rescan_complete = true;
    }
    /// Add scriptPubKeys discovered during block processing for later rescan.
    pub(super) fn add_scripts_for_wallet(
        &mut self,
        wallet_id: WalletId,
        scripts: impl IntoIterator<Item = ScriptBuf>,
    ) {
        self.collected_scripts.entry(wallet_id).or_default().extend(scripts);
    }
    /// Take collected per-wallet scripts for rescan, leaving the map empty.
    pub(super) fn take_collected_scripts(&mut self) -> HashMap<WalletId, HashSet<ScriptBuf>> {
        std::mem::take(&mut self.collected_scripts)
    }
    /// Record the wallets that were behind for this batch at scan time, each
    /// with its `account_generation` snapshot.
    pub(super) fn set_scanned_wallets(&mut self, wallets: BTreeMap<WalletId, u64>) {
        self.scanned_wallets = wallets;
    }
    /// Wallets that were behind at scan time (with their generation snapshot)
    /// and must have their synced_height advanced when this batch commits.
    pub(super) fn scanned_wallets(&self) -> &BTreeMap<WalletId, u64> {
        &self.scanned_wallets
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
    use key_wallet_manager::FilterMatchKey;
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
    fn test_filters_batch_mark_verified() {
        let mut batch = FiltersBatch::new(100, 199, HashMap::new());
        assert!(!batch.verified());
        batch.mark_verified();
        assert!(batch.verified());
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
