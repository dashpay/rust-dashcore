//! Per-block tracking state used by `FiltersManager` while filter matches
//! flow through the block download and apply pipeline.
//!
//! Owns two related maps:
//!
//! - `blocks_remaining`: in-flight matched blocks awaiting `BlockProcessed`,
//!   keyed by block hash. The associated `(height, batch_start)` lets the
//!   `BlockProcessed` handler decrement the right batch's `pending_blocks`.
//! - `processed_blocks_per_wallet`: which wallets have already had each
//!   processed block applied to their state, keyed by height (so commit-time
//!   pruning is one `split_off` call) then by hash. Lets a runtime-added
//!   wallet still receive a block that was previously processed for another
//!   wallet only: the gate is per-wallet, not global.
//!
//! These two maps are coupled: every call site that consults one consults the
//! other, and the lifecycle (track on filter match, record on
//! `BlockProcessed`, prune on commit, clear on reset) is shared. Splitting
//! them out keeps `FiltersManager` focused on batch orchestration.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use dashcore::BlockHash;
use key_wallet_manager::{FilterMatchKey, WalletId};

/// Result of recording a filter match for a block against a candidate wallet
/// set. The wallet set carried by `NewlyTracked` and `InFlight` is the
/// residual after subtracting wallets that have already had this block
/// processed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum BlockTrackResult {
    /// Block was newly tracked for the residual wallets. Caller should emit a
    /// `BlocksNeeded` event with this set and account for the block in the
    /// batch's `pending_blocks` count.
    NewlyTracked {
        wallets: BTreeSet<WalletId>,
    },
    /// Block is already in flight. Caller should still emit a `BlocksNeeded`
    /// event with the residual wallets so the `BlocksPipeline` merges them
    /// into the pending wallet set, but must NOT increment the batch's
    /// `pending_blocks` count (already counted on first match).
    InFlight {
        wallets: BTreeSet<WalletId>,
    },
    /// All candidate wallets already have this block applied. Caller skips it.
    AlreadyProcessed,
}

/// Per-block tracking state for matched blocks flowing through the filter →
/// block → wallet pipeline. See module-level docs for the invariants.
#[derive(Debug, Default)]
pub(super) struct BlockMatchTracker {
    /// In-flight matched blocks awaiting `BlockProcessed`. Maps
    /// `block_hash → (height, batch_start)` so the `BlockProcessed` handler
    /// can decrement the right batch's `pending_blocks` count.
    blocks_remaining: BTreeMap<BlockHash, (u32, u32)>,
    /// Per-(height, hash) record of which wallets have had this block
    /// applied. Bounded by `prune_at_or_below` after every commit, since
    /// below `committed_height` a new wallet can only re-enter via the `tick`
    /// rescan trigger which calls `clear` outright.
    processed_blocks_per_wallet: BTreeMap<u32, HashMap<BlockHash, BTreeSet<WalletId>>>,
}

impl BlockMatchTracker {
    /// Create an empty tracker.
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Track a filter match for a block against a candidate wallet set,
    /// returning only the wallets that still need the block applied. See
    /// `BlockTrackResult` for per-case caller responsibilities.
    pub(super) fn track(
        &mut self,
        key: &FilterMatchKey,
        batch_start: u32,
        candidate_wallets: BTreeSet<WalletId>,
    ) -> BlockTrackResult {
        let processed = self.already_processed_wallets(key);
        let residual: BTreeSet<WalletId> =
            candidate_wallets.difference(&processed).copied().collect();
        if residual.is_empty() {
            return BlockTrackResult::AlreadyProcessed;
        }
        if self.blocks_remaining.contains_key(key.hash()) {
            return BlockTrackResult::InFlight {
                wallets: residual,
            };
        }
        self.blocks_remaining.insert(*key.hash(), (key.height(), batch_start));
        BlockTrackResult::NewlyTracked {
            wallets: residual,
        }
    }

    /// Record that `wallets` have had the block at `(height, hash)` applied
    /// to their state. Idempotent: existing entries merge, never shrink.
    pub(super) fn record_processed(
        &mut self,
        height: u32,
        hash: BlockHash,
        wallets: &BTreeSet<WalletId>,
    ) {
        if wallets.is_empty() {
            return;
        }
        self.processed_blocks_per_wallet
            .entry(height)
            .or_default()
            .entry(hash)
            .or_default()
            .extend(wallets.iter().copied());
    }

    /// Remove the in-flight entry for `hash`, returning its
    /// `(height, batch_start)` if it was tracked.
    pub(super) fn finish_in_flight(&mut self, hash: &BlockHash) -> Option<(u32, u32)> {
        self.blocks_remaining.remove(hash)
    }

    /// Drop every per-wallet processing record at or below `height`. Called
    /// after `try_commit_batches` advances `committed_height`: below the new
    /// committed height a new wallet can only re-enter via the `tick` rescan
    /// trigger, which already wipes the map outright via `clear`.
    pub(super) fn prune_at_or_below(&mut self, height: u32) {
        self.processed_blocks_per_wallet =
            self.processed_blocks_per_wallet.split_off(&(height + 1));
    }

    /// True when there is no in-flight or processed-record state.
    pub(super) fn is_empty(&self) -> bool {
        self.blocks_remaining.is_empty() && self.processed_blocks_per_wallet.is_empty()
    }

    /// Drop all in-flight and processed-record state.
    pub(super) fn clear(&mut self) {
        self.blocks_remaining.clear();
        self.processed_blocks_per_wallet.clear();
    }

    /// Wallets that have already had this block applied to their state.
    fn already_processed_wallets(&self, key: &FilterMatchKey) -> BTreeSet<WalletId> {
        self.processed_blocks_per_wallet
            .get(&key.height())
            .and_then(|m| m.get(key.hash()))
            .cloned()
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_n(n: u8) -> BlockHash {
        dashcore::block::Header::dummy(n as u32).block_hash()
    }

    /// `track` walks through the full state machine: NewlyTracked on first
    /// match, InFlight on re-match while the block is awaiting processing,
    /// NewlyTracked again for a residual wallet after the first wallet's
    /// processing is recorded, and AlreadyProcessed once every candidate is
    /// covered.
    #[test]
    fn track_state_machine() {
        let mut tracker = BlockMatchTracker::new();
        let hash = hash_n(0);
        let key = FilterMatchKey::new(100, hash);
        let wallet_a: WalletId = [0xA1; 32];
        let wallet_b: WalletId = [0xB2; 32];

        // First match for {A}: nothing tracked yet, helper records the block.
        assert_eq!(
            tracker.track(&key, 0, BTreeSet::from([wallet_a])),
            BlockTrackResult::NewlyTracked {
                wallets: BTreeSet::from([wallet_a])
            }
        );
        assert_eq!(tracker.finish_in_flight(&hash), Some((100, 0)));
        // Put it back in flight to continue the scenario.
        assert!(matches!(
            tracker.track(&key, 0, BTreeSet::from([wallet_a])),
            BlockTrackResult::NewlyTracked { .. }
        ));

        // Re-match for {A} while still in flight: residual is {A}, InFlight.
        assert_eq!(
            tracker.track(&key, 0, BTreeSet::from([wallet_a])),
            BlockTrackResult::InFlight {
                wallets: BTreeSet::from([wallet_a])
            }
        );

        // Block is delivered and processed for {A}.
        assert!(tracker.finish_in_flight(&hash).is_some());
        tracker.record_processed(100, hash, &BTreeSet::from([wallet_a]));

        // Late-added B's filter matches the same block: residual is {B} and
        // it gets re-queued via NewlyTracked.
        assert_eq!(
            tracker.track(&key, 5000, BTreeSet::from([wallet_a, wallet_b])),
            BlockTrackResult::NewlyTracked {
                wallets: BTreeSet::from([wallet_b])
            }
        );

        // After B is processed, both wallets are covered: AlreadyProcessed.
        assert!(tracker.finish_in_flight(&hash).is_some());
        tracker.record_processed(100, hash, &BTreeSet::from([wallet_b]));
        assert_eq!(
            tracker.track(&key, 5000, BTreeSet::from([wallet_a, wallet_b])),
            BlockTrackResult::AlreadyProcessed
        );
    }

    /// `prune_at_or_below` drops every entry at or below the given height
    /// while retaining strictly higher entries. Idempotent under repeated
    /// calls with the same threshold.
    #[test]
    fn prune_at_or_below_drops_low_entries() {
        let mut tracker = BlockMatchTracker::new();
        let wallet: WalletId = [0xFA; 32];
        let h_low = hash_n(1);
        let h_mid = hash_n(2);
        let h_high = hash_n(3);

        tracker.record_processed(2500, h_low, &BTreeSet::from([wallet]));
        tracker.record_processed(4999, h_mid, &BTreeSet::from([wallet]));
        tracker.record_processed(7500, h_high, &BTreeSet::from([wallet]));

        tracker.prune_at_or_below(4999);

        // Entries at or below 4999 are gone, the 7500 entry survives.
        let key_low = FilterMatchKey::new(2500, h_low);
        let key_mid = FilterMatchKey::new(4999, h_mid);
        let key_high = FilterMatchKey::new(7500, h_high);
        assert!(tracker.already_processed_wallets(&key_low).is_empty());
        assert!(tracker.already_processed_wallets(&key_mid).is_empty());
        assert!(tracker.already_processed_wallets(&key_high).contains(&wallet));

        // Repeat call is a no-op.
        tracker.prune_at_or_below(4999);
        assert!(tracker.already_processed_wallets(&key_high).contains(&wallet));
    }

    /// `is_empty` and `clear` cover both maps together: populating either
    /// flips `is_empty`, and `clear` returns to the initial state.
    #[test]
    fn is_empty_and_clear_cover_both_maps() {
        let mut tracker = BlockMatchTracker::new();
        let wallet: WalletId = [0xCC; 32];
        let hash = hash_n(0);
        let key = FilterMatchKey::new(100, hash);

        assert!(tracker.is_empty());

        // Only blocks_remaining populated.
        tracker.track(&key, 0, BTreeSet::from([wallet]));
        assert!(!tracker.is_empty());
        tracker.clear();
        assert!(tracker.is_empty());

        // Only processed_blocks_per_wallet populated.
        tracker.record_processed(100, hash, &BTreeSet::from([wallet]));
        assert!(!tracker.is_empty());
        tracker.clear();
        assert!(tracker.is_empty());
    }
}
