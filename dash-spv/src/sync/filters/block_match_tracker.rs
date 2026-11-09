//! Per-block tracking state used by `FiltersManager` while filter matches
//! flow through the block download and apply pipeline.
//!
//! Owns two related maps:
//!
//! - `blocks_remaining`: in-flight matched blocks awaiting `BlockProcessed`,
//!   keyed by block hash. The associated `(height, batch_start)` lets the
//!   `BlockProcessed` handler decrement the right batch's `pending_blocks`
//!   once every requested wallet has reported. The wallets still waiting keep
//!   a rescan from requesting the block again for them.
//! - `processed_blocks_per_wallet`: which wallets have already had each
//!   processed block applied to their state, keyed by height (so commit-time
//!   pruning is one `split_off` call) then by hash. Lets a runtime-added
//!   wallet still receive a block that was previously processed for another
//!   wallet only: the gate is per-wallet, not global. The number of each
//!   wallet's last pass lets a rescan skip a block that already saw its scripts.
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
    /// All candidate wallets already have this block applied, or for
    /// `track_for_new_scripts` are already queued for it. Caller skips it.
    AlreadyProcessed,
}

/// A matched block awaiting `BlockProcessed`.
#[derive(Debug)]
struct InFlightBlock {
    height: u32,
    batch_start: u32,
    /// Requested wallets whose pass has not reported yet.
    awaiting: BTreeSet<WalletId>,
}

/// Per-block tracking state for matched blocks flowing through the filter →
/// block → wallet pipeline. See module-level docs for the invariants.
#[derive(Debug, Default)]
pub(super) struct BlockMatchTracker {
    /// In-flight matched blocks awaiting `BlockProcessed`, keyed by hash.
    blocks_remaining: BTreeMap<BlockHash, InFlightBlock>,
    /// Per-(height, hash) record of which wallets have had this block
    /// applied, with the number of each wallet's last pass. Bounded by
    /// `prune_at_or_below` after every commit, since below `committed_height`
    /// a new wallet can only re-enter via the `tick` rescan trigger which
    /// calls `clear` outright.
    processed_blocks_per_wallet: BTreeMap<u32, HashMap<BlockHash, BTreeMap<WalletId, u64>>>,
    /// Number of the last pass given to `record_processed`. Never reset, so a
    /// record that outlives a `clear` can't look newer than a later pass.
    passes: u64,
    /// Whether the wallet checks a block against the addresses it derives
    /// while applying it, so the deriving pass already saw its own scripts.
    checks_derived_addresses: bool,
}

impl BlockMatchTracker {
    /// Create an empty tracker for a wallet that does or does not check a block
    /// against the addresses it derives, see `WalletInterface::checks_derived_addresses`.
    pub(super) fn new(checks_derived_addresses: bool) -> Self {
        Self {
            checks_derived_addresses,
            ..Self::default()
        }
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
        if let Some(in_flight) = self.blocks_remaining.get_mut(key.hash()) {
            in_flight.awaiting.extend(residual.iter().copied());
            return BlockTrackResult::InFlight {
                wallets: residual,
            };
        }
        self.insert_in_flight(key, batch_start, &residual);
        BlockTrackResult::NewlyTracked {
            wallets: residual,
        }
    }

    /// Like [`Self::track`], but for matches on newly derived scripts. Each
    /// candidate wallet maps to the pass that derived its matching scripts. A
    /// wallet whose last pass of this block ran later already saw them and is
    /// skipped, and so is a wallet the block is already queued for. The deriving
    /// pass itself saw them only if the wallet checks derived addresses.
    pub(super) fn track_for_new_scripts(
        &mut self,
        key: &FilterMatchKey,
        batch_start: u32,
        candidate_wallets: BTreeMap<WalletId, u64>,
    ) -> BlockTrackResult {
        let processed = self.processed_passes(key);
        let residual: BTreeSet<WalletId> = candidate_wallets
            .into_iter()
            .filter(|(id, derived_at)| {
                processed.and_then(|p| p.get(id)).is_none_or(|pass| {
                    if self.checks_derived_addresses {
                        pass < derived_at
                    } else {
                        pass <= derived_at
                    }
                })
            })
            .map(|(id, _)| id)
            .collect();
        if residual.is_empty() {
            return BlockTrackResult::AlreadyProcessed;
        }
        if let Some(in_flight) = self.blocks_remaining.get_mut(key.hash()) {
            // Passes report in the order they ran and the pass that derived the
            // scripts has reported, so the queued pass runs after it and sees them.
            let added: BTreeSet<WalletId> =
                residual.difference(&in_flight.awaiting).copied().collect();
            if added.is_empty() {
                return BlockTrackResult::AlreadyProcessed;
            }
            in_flight.awaiting.extend(added.iter().copied());
            return BlockTrackResult::InFlight {
                wallets: added,
            };
        }
        self.insert_in_flight(key, batch_start, &residual);
        BlockTrackResult::NewlyTracked {
            wallets: residual,
        }
    }

    /// Records that `wallets` have had the block at `(height, hash)` applied
    /// and returns the number of this pass. Passes are numbered in the order
    /// their `BlockProcessed` arrives, which is the order they ran.
    pub(super) fn record_processed(
        &mut self,
        height: u32,
        hash: BlockHash,
        wallets: &BTreeSet<WalletId>,
    ) -> u64 {
        self.passes += 1;
        let pass = self.passes;
        if !wallets.is_empty() {
            self.processed_blocks_per_wallet
                .entry(height)
                .or_default()
                .entry(hash)
                .or_default()
                .extend(wallets.iter().map(|id| (*id, pass)));
        }
        pass
    }

    /// Marks the pass of the in-flight block `hash` for `wallets` as reported.
    /// Returns its `(height, batch_start)` and stops tracking it once no
    /// requested wallet is still waiting. A pass for only some of them, such as
    /// a re-application, leaves the block in flight for the others.
    pub(super) fn finish_in_flight(
        &mut self,
        hash: &BlockHash,
        wallets: &BTreeSet<WalletId>,
    ) -> Option<(u32, u32)> {
        let block = self.blocks_remaining.get_mut(hash)?;
        block.awaiting.retain(|id| !wallets.contains(id));
        if !block.awaiting.is_empty() {
            return None;
        }
        self.blocks_remaining.remove(hash).map(|block| (block.height, block.batch_start))
    }

    /// The number of the last pass that applied the block at `key` to `wallet_id`.
    pub(super) fn last_pass(&self, key: &FilterMatchKey, wallet_id: &WalletId) -> Option<u64> {
        self.processed_passes(key).and_then(|passes| passes.get(wallet_id)).copied()
    }

    fn insert_in_flight(
        &mut self,
        key: &FilterMatchKey,
        batch_start: u32,
        wallets: &BTreeSet<WalletId>,
    ) {
        let block = InFlightBlock {
            height: key.height(),
            batch_start,
            awaiting: wallets.clone(),
        };
        self.blocks_remaining.insert(*key.hash(), block);
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
        self.processed_passes(key).map(|p| p.keys().copied().collect()).unwrap_or_default()
    }

    /// The last pass that applied this block, per wallet.
    fn processed_passes(&self, key: &FilterMatchKey) -> Option<&BTreeMap<WalletId, u64>> {
        self.processed_blocks_per_wallet.get(&key.height()).and_then(|m| m.get(key.hash()))
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
    /// covered. `track_for_new_scripts` re-queues the block only for wallets
    /// whose last pass ran no later than the pass that derived the scripts, or
    /// earlier than it for a wallet that checks the addresses it derives. A
    /// block stays in flight until every requested wallet has reported.
    #[test]
    fn track_state_machine() {
        let mut tracker = BlockMatchTracker::new(false);
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
        assert_eq!(tracker.finish_in_flight(&hash, &BTreeSet::from([wallet_a])), Some((100, 0)));
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
        assert!(tracker.finish_in_flight(&hash, &BTreeSet::from([wallet_a])).is_some());
        let pass_a = tracker.record_processed(100, hash, &BTreeSet::from([wallet_a]));

        // Late-added B's filter matches the same block: residual is {B} and
        // it gets re-queued via NewlyTracked.
        assert_eq!(
            tracker.track(&key, 5000, BTreeSet::from([wallet_a, wallet_b])),
            BlockTrackResult::NewlyTracked {
                wallets: BTreeSet::from([wallet_b])
            }
        );

        // After B is processed, both wallets are covered: AlreadyProcessed.
        assert!(tracker.finish_in_flight(&hash, &BTreeSet::from([wallet_b])).is_some());
        tracker.record_processed(100, hash, &BTreeSet::from([wallet_b]));
        assert_eq!(
            tracker.track(&key, 5000, BTreeSet::from([wallet_a, wallet_b])),
            BlockTrackResult::AlreadyProcessed
        );

        // Scripts derived by A's pass re-queue the block for A, since that
        // pass derived them only after checking the block. B's pass ran later.
        let derived_by_a = BTreeMap::from([(wallet_a, pass_a), (wallet_b, pass_a)]);
        assert_eq!(
            tracker.track_for_new_scripts(&key, 5000, derived_by_a.clone()),
            BlockTrackResult::NewlyTracked {
                wallets: BTreeSet::from([wallet_a])
            }
        );

        // The re-queued pass ran after the derivation.
        assert!(tracker.finish_in_flight(&hash, &BTreeSet::from([wallet_a])).is_some());
        tracker.record_processed(100, hash, &BTreeSet::from([wallet_a]));
        assert_eq!(
            tracker.track_for_new_scripts(&key, 5000, derived_by_a),
            BlockTrackResult::AlreadyProcessed
        );

        // A block queued for A and B stays in flight until both have reported.
        // A pass for A alone, such as a re-application, leaves it waiting for B.
        let both = BTreeSet::from([wallet_a, wallet_b]);
        let other = hash_n(1);
        tracker.track(&FilterMatchKey::new(200, other), 0, both.clone());
        assert_eq!(tracker.finish_in_flight(&other, &BTreeSet::from([wallet_a])), None);
        assert_eq!(tracker.finish_in_flight(&other, &both), Some((200, 0)));

        // A wallet that checks a block against the addresses it derives saw
        // them in the deriving pass. Scripts of a later pass still re-queue it.
        let mut checking = BlockMatchTracker::new(true);
        let pass = checking.record_processed(100, hash, &BTreeSet::from([wallet_a]));
        assert_eq!(
            checking.track_for_new_scripts(&key, 5000, BTreeMap::from([(wallet_a, pass)])),
            BlockTrackResult::AlreadyProcessed
        );
        assert_eq!(
            checking.track_for_new_scripts(&key, 5000, BTreeMap::from([(wallet_a, pass + 1)])),
            BlockTrackResult::NewlyTracked {
                wallets: BTreeSet::from([wallet_a])
            }
        );
    }

    /// `prune_at_or_below` drops every entry at or below the given height
    /// while retaining strictly higher entries. Idempotent under repeated
    /// calls with the same threshold.
    #[test]
    fn prune_at_or_below_drops_low_entries() {
        let mut tracker = BlockMatchTracker::new(false);
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
        let mut tracker = BlockMatchTracker::new(false);
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
