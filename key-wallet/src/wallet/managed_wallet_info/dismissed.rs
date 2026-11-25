use std::collections::{HashMap, HashSet, VecDeque};

use dashcore::Txid;

/// The most abandoned, and separately the most swept, transactions kept; the oldest goes first.
const MAX_DISMISSED: usize = 4_096;

/// The most spends of dismissed transactions kept; the oldest goes first.
const MAX_SPENDS: usize = 4_096;

/// The most dismissed transactions one spend is released by.
const MAX_PARENTS: usize = 16;

/// A change to the wallet's own dismissals, for a persister to mirror. Spends held back with a
/// dismissed transaction are not included: a delivery after a restart holds them back again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DismissalChange {
    /// A locked or mined conflict beat the transaction, and the user did not abandon it.
    Dismissed(Txid),
    /// The user abandoned the transaction.
    Abandoned(Txid),
    /// The transaction is no longer dismissed: it was locked or mined, or pushed out at capacity.
    Forgotten(Txid),
}

/// Unconfirmed transactions the wallet dropped as dead (swept losers, abandoned transactions),
/// and unlocked spends of them held back until what they spend settles. Anyone can cause a sweep
/// or send such a spend, so each kind has its own cap and cannot push out the user's abandons.
#[derive(Debug, Clone, Default)]
pub(crate) struct DismissedTxids {
    abandoned: Fifo<MAX_DISMISSED>,
    swept: Fifo<MAX_DISMISSED>,
    spends: Fifo<MAX_SPENDS>,
    /// The unsettled dismissed transactions each remembered spend spends. Empty once released.
    held_by: HashMap<Txid, HashSet<Txid>>,
    /// Spends of more than [`MAX_PARENTS`] dismissed transactions, held until they settle.
    pinned: HashSet<Txid>,
    /// For each dismissed transaction, the remembered spends it holds back.
    holds: HashMap<Txid, HashSet<Txid>>,
    /// Changes not yet taken, in order. They accumulate until taken.
    changes: Vec<Pending>,
}

#[derive(Debug, Clone, Copy)]
struct Pending {
    change: DismissalChange,
    /// Whether the change waits for the report of the sweep that caused it.
    awaits_sweep: bool,
}

impl DismissedTxids {
    /// Dismisses `txid` because the user abandoned it.
    pub(crate) fn abandon(&mut self, txid: Txid) {
        if !self.abandoned.contains(&txid) {
            self.record(DismissalChange::Abandoned(txid), false);
        }
        if let Some(evicted) = self.abandoned.insert(txid) {
            self.pushed_out(evicted);
        }
    }

    /// Dismisses `txid` because a locked or mined conflict beat it.
    pub(crate) fn sweep(&mut self, txid: Txid) {
        if !self.swept.contains(&txid) && !self.abandoned.contains(&txid) {
            self.record(DismissalChange::Dismissed(txid), true);
        }
        if let Some(evicted) = self.swept.insert(txid) {
            self.pushed_out(evicted);
        }
    }

    /// Dismisses again, oldest first, the transactions a persister kept. Only an entry pushed out
    /// at capacity is a change.
    pub(crate) fn restore(
        &mut self,
        abandoned: impl IntoIterator<Item = Txid>,
        swept: impl IntoIterator<Item = Txid>,
    ) {
        for txid in abandoned {
            if let Some(evicted) = self.abandoned.insert(txid) {
                self.pushed_out(evicted);
            }
        }
        for txid in swept {
            if let Some(evicted) = self.swept.insert(txid) {
                self.pushed_out(evicted);
            }
        }
    }

    /// Returns the changes since the last call, in order.
    pub(crate) fn take_changes(&mut self) -> Vec<DismissalChange> {
        self.changes.drain(..).map(|pending| pending.change).collect()
    }

    /// Whether a change not yet taken waits for the report of the sweep that caused it.
    pub(crate) fn awaits_sweep(&self) -> bool {
        self.changes.iter().any(|pending| pending.awaits_sweep)
    }

    /// Drops the changes not yet taken that wait for the report of a sweep.
    pub(crate) fn drop_unreported(&mut self) {
        self.changes.retain(|pending| !pending.awaits_sweep);
    }

    fn record(&mut self, change: DismissalChange, awaits_sweep: bool) {
        self.changes.push(Pending {
            change,
            awaits_sweep,
        });
    }

    /// Records what pushing `txid` out of one set changed, and releases its spends if it is no
    /// longer dismissed.
    fn pushed_out(&mut self, txid: Txid) {
        if self.swept.contains(&txid) {
            self.record(DismissalChange::Dismissed(txid), false);
        } else if !self.abandoned.contains(&txid) {
            self.record(DismissalChange::Forgotten(txid), false);
        }
        self.release_unless_dismissed(txid);
    }

    fn is_own(&self, txid: &Txid) -> bool {
        self.abandoned.contains(txid) || self.swept.contains(txid)
    }

    /// Releases the spends `txid` held back once it is no longer dismissed. So an entry pushed out
    /// at capacity lets its spends through, which bounds what is held.
    fn release_unless_dismissed(&mut self, txid: Txid) {
        if !self.contains(&txid) {
            self.release_spends_of(txid);
        }
    }

    /// Holds `txid` back as a spend of the dismissed transactions among `parents`. Returns
    /// whether any of them is dismissed.
    pub(crate) fn hold_spend(
        &mut self,
        txid: Txid,
        parents: impl IntoIterator<Item = Txid>,
    ) -> bool {
        let mut parents: HashSet<Txid> = parents.into_iter().filter(|p| self.contains(p)).collect();
        if parents.is_empty() {
            return false;
        }
        if let Some(evicted) = self.spends.insert(txid) {
            self.forget_spend(&evicted);
            self.release_unless_dismissed(evicted);
            parents.retain(|parent| self.contains(parent));
            if parents.is_empty() {
                return false;
            }
        }
        let held =
            self.held_by.get(&txid).map_or(parents.len(), |held| held.union(&parents).count());
        if self.pinned.contains(&txid) || held > MAX_PARENTS {
            self.forget_spend(&txid);
            self.pinned.insert(txid);
            return true;
        }
        for parent in &parents {
            self.holds.entry(*parent).or_default().insert(txid);
        }
        self.held_by.entry(txid).or_default().extend(parents);
        true
    }

    /// Whether `txid` is dismissed, or held back as a spend of one.
    pub(crate) fn contains(&self, txid: &Txid) -> bool {
        self.is_own(txid)
            || self.pinned.contains(txid)
            || self.held_by.get(txid).is_some_and(|parents| !parents.is_empty())
    }

    /// Whether a lock for `txid` should have it fetched again: it is dismissed, or a remembered
    /// spend of a dismissed transaction, released or not.
    pub(crate) fn refetch_on_lock(&self, txid: &Txid) -> bool {
        self.is_own(txid) || self.spends.contains(txid)
    }

    /// Marks `txid` locked or mined: it is not dead, and the spends it held back are released,
    /// recursively. A spend the wallet dismissed in its own right stays dismissed.
    pub(crate) fn settled(&mut self, txid: &Txid) {
        let was_abandoned = self.abandoned.remove(txid);
        let was_swept = self.swept.remove(txid);
        if was_abandoned || was_swept {
            self.record(DismissalChange::Forgotten(*txid), false);
        }
        if self.spends.remove(txid) {
            self.forget_spend(txid);
        }
        self.release_spends_of(*txid);
    }

    fn release_spends_of(&mut self, parent: Txid) {
        let mut released = vec![parent];
        while let Some(parent) = released.pop() {
            for spend in self.holds.remove(&parent).unwrap_or_default() {
                let Some(parents) = self.held_by.get_mut(&spend) else {
                    continue;
                };
                parents.remove(&parent);
                if parents.is_empty() && !self.is_own(&spend) && !self.pinned.contains(&spend) {
                    released.push(spend);
                }
            }
        }
    }

    fn forget_spend(&mut self, txid: &Txid) {
        self.pinned.remove(txid);
        for parent in self.held_by.remove(txid).unwrap_or_default() {
            if let Some(spends) = self.holds.get_mut(&parent) {
                spends.remove(txid);
                if spends.is_empty() {
                    self.holds.remove(&parent);
                }
            }
        }
    }
}

/// A set of at most `CAP` txids; the oldest goes first.
#[derive(Debug, Clone, Default)]
struct Fifo<const CAP: usize> {
    order: VecDeque<Txid>,
    set: HashSet<Txid>,
}

impl<const CAP: usize> Fifo<CAP> {
    /// Inserts `txid`, returning the entry pushed out at capacity, if any.
    fn insert(&mut self, txid: Txid) -> Option<Txid> {
        if !self.set.insert(txid) {
            return None;
        }
        self.order.push_back(txid);
        if self.order.len() <= CAP {
            return None;
        }
        let oldest = self.order.pop_front()?;
        self.set.remove(&oldest);
        Some(oldest)
    }

    fn contains(&self, txid: &Txid) -> bool {
        self.set.contains(txid)
    }

    fn remove(&mut self, txid: &Txid) -> bool {
        let removed = self.set.remove(txid);
        if removed {
            self.order.retain(|t| t != txid);
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn txid(n: u32) -> Txid {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&n.to_le_bytes());
        Txid::from_byte_array(bytes)
    }

    #[test]
    fn changes_to_the_wallets_own_dismissals_are_kept_in_order_until_taken() {
        use DismissalChange::{Abandoned, Dismissed, Forgotten};
        let mut dismissed = DismissedTxids::default();
        let (a, b, spend) = (txid(1), txid(2), txid(3));
        dismissed.abandon(a);
        dismissed.abandon(a);
        dismissed.sweep(b);
        dismissed.sweep(a);
        assert!(dismissed.hold_spend(spend, [a]));
        dismissed.settled(&a);
        dismissed.settled(&spend);
        assert_eq!(dismissed.take_changes(), vec![Abandoned(a), Dismissed(b), Forgotten(a)]);
        assert!(dismissed.take_changes().is_empty());
        dismissed.settled(&a);
        assert!(dismissed.take_changes().is_empty(), "a second settle is no change");
    }

    #[test]
    fn an_abandon_of_a_swept_transaction_and_its_push_out_change_its_kind() {
        use DismissalChange::{Abandoned, Dismissed, Forgotten};
        let mut dismissed = DismissedTxids::default();
        let swept = txid(0);
        dismissed.sweep(swept);
        dismissed.abandon(swept);
        assert_eq!(dismissed.take_changes(), vec![Dismissed(swept), Abandoned(swept)]);
        dismissed.restore((1..MAX_DISMISSED as u32).map(txid), []);
        assert!(dismissed.take_changes().is_empty(), "a restore records nothing");
        let newest = txid(MAX_DISMISSED as u32);
        dismissed.abandon(newest);
        assert_eq!(dismissed.take_changes(), vec![Abandoned(newest), Dismissed(swept)]);
        assert!(dismissed.contains(&swept));
        dismissed.abandon(swept);
        assert_eq!(dismissed.take_changes(), vec![Abandoned(swept), Forgotten(txid(1))]);
    }

    #[test]
    fn a_swept_transaction_pushed_out_while_abandoned_is_no_change() {
        let mut dismissed = DismissedTxids::default();
        let abandoned = txid(0);
        dismissed.sweep(abandoned);
        dismissed.abandon(abandoned);
        dismissed.restore([], (1..MAX_DISMISSED as u32).map(txid));
        dismissed.take_changes();
        dismissed.sweep(txid(MAX_DISMISSED as u32));
        assert_eq!(
            dismissed.take_changes(),
            vec![DismissalChange::Dismissed(txid(MAX_DISMISSED as u32))]
        );
        assert!(dismissed.contains(&abandoned));
    }

    #[test]
    fn a_dismissal_pushed_out_at_capacity_is_forgotten() {
        use DismissalChange::{Dismissed, Forgotten};
        let mut dismissed = DismissedTxids::default();
        dismissed.restore([], (0..MAX_DISMISSED as u32).map(txid));
        assert!(dismissed.take_changes().is_empty());
        let newest = txid(MAX_DISMISSED as u32);
        dismissed.sweep(newest);
        assert_eq!(dismissed.take_changes(), vec![Dismissed(newest), Forgotten(txid(0))]);
        assert!(!dismissed.contains(&txid(0)));
        dismissed.restore([], [txid(MAX_DISMISSED as u32 + 1)]);
        assert_eq!(
            dismissed.take_changes(),
            vec![Forgotten(txid(1))],
            "the restore pushed one out"
        );
    }

    #[test]
    fn only_a_sweeps_dismissal_waits_for_its_report() {
        use DismissalChange::{Abandoned, Forgotten};
        let mut dismissed = DismissedTxids::default();
        let (swept, abandoned, settled) = (txid(1), txid(2), txid(3));
        dismissed.abandon(settled);
        dismissed.settled(&settled);
        dismissed.abandon(abandoned);
        assert!(!dismissed.awaits_sweep());
        dismissed.sweep(swept);
        assert!(dismissed.awaits_sweep());
        dismissed.drop_unreported();
        assert!(!dismissed.awaits_sweep());
        assert!(dismissed.contains(&swept), "dropping the change keeps the dismissal");
        assert_eq!(
            dismissed.take_changes(),
            vec![Abandoned(settled), Forgotten(settled), Abandoned(abandoned)]
        );
    }

    #[test]
    fn the_oldest_dismissal_goes_first_at_capacity() {
        let mut dismissed = DismissedTxids::default();
        for n in 0..=MAX_DISMISSED as u32 {
            dismissed.abandon(txid(n));
        }
        assert!(!dismissed.contains(&txid(0)));
        assert!(dismissed.contains(&txid(1)));
        assert!(dismissed.contains(&txid(MAX_DISMISSED as u32)));
        dismissed.settled(&txid(1));
        assert!(!dismissed.contains(&txid(1)));
        assert_eq!(dismissed.abandoned.order.len(), MAX_DISMISSED - 1);
    }

    #[test]
    fn sweeps_do_not_push_out_an_abandon() {
        let mut dismissed = DismissedTxids::default();
        let abandoned = txid(u32::MAX);
        dismissed.abandon(abandoned);
        for n in 0..=2 * MAX_DISMISSED as u32 {
            dismissed.sweep(txid(n));
        }
        assert!(dismissed.contains(&abandoned));
        assert!(!dismissed.contains(&txid(0)), "the oldest sweep went");
    }

    #[test]
    fn a_spend_whose_only_held_parent_is_pushed_out_by_it_is_not_held() {
        let mut dismissed = DismissedTxids::default();
        let root = txid(0);
        dismissed.abandon(root);
        let oldest = txid(1);
        assert!(dismissed.hold_spend(oldest, [root]));
        for n in 2..=MAX_SPENDS as u32 {
            assert!(dismissed.hold_spend(txid(n), [root]));
        }
        let child = txid(u32::MAX);
        assert!(!dismissed.hold_spend(child, [oldest]));
        assert!(!dismissed.contains(&oldest));
        assert!(!dismissed.contains(&child));
    }

    #[test]
    fn a_dismissal_pushed_out_releases_its_held_spends() {
        let mut dismissed = DismissedTxids::default();
        let (parent, child, grandchild) = (txid(u32::MAX), txid(u32::MAX - 1), txid(u32::MAX - 2));
        dismissed.sweep(parent);
        assert!(dismissed.hold_spend(child, [parent]));
        assert!(dismissed.hold_spend(grandchild, [child]));
        for n in 0..MAX_DISMISSED as u32 {
            dismissed.sweep(txid(n));
        }
        assert!(!dismissed.contains(&parent));
        assert!(!dismissed.contains(&child));
        assert!(!dismissed.contains(&grandchild));
        assert!(dismissed.holds.is_empty());
    }

    #[test]
    fn spends_do_not_push_out_the_wallets_own_dismissals() {
        let mut dismissed = DismissedTxids::default();
        let (own, parent) = (txid(u32::MAX), txid(u32::MAX - 1));
        dismissed.abandon(own);
        dismissed.abandon(parent);
        for n in 0..=2 * MAX_SPENDS as u32 {
            assert!(dismissed.hold_spend(txid(n), [parent]));
        }
        assert!(dismissed.contains(&own));
        assert!(dismissed.contains(&parent));
        assert!(!dismissed.contains(&txid(0)), "the oldest spend went");
        assert!(dismissed.contains(&txid(2 * MAX_SPENDS as u32)));
        assert_eq!(dismissed.spends.order.len(), MAX_SPENDS);
        assert_eq!(dismissed.held_by.len(), MAX_SPENDS);
        assert_eq!(dismissed.holds[&parent].len(), MAX_SPENDS);
    }

    #[test]
    fn settling_a_dismissed_transaction_releases_its_spends_but_not_an_abandon() {
        let mut dismissed = DismissedTxids::default();
        let (parent, other) = (txid(1), txid(2));
        let (child, abandoned_child, two_parents, grandchild) =
            (txid(3), txid(4), txid(5), txid(6));
        dismissed.abandon(parent);
        dismissed.abandon(other);
        assert!(!dismissed.hold_spend(txid(9), [txid(8)]), "it spends nothing dismissed");
        assert!(dismissed.hold_spend(child, [parent]));
        assert!(dismissed.hold_spend(abandoned_child, [parent]));
        dismissed.abandon(abandoned_child);
        assert!(dismissed.hold_spend(two_parents, [parent, other]));
        assert!(dismissed.hold_spend(grandchild, [child]));

        dismissed.settled(&parent);
        assert!(!dismissed.contains(&parent));
        assert!(!dismissed.contains(&child));
        assert!(!dismissed.contains(&grandchild), "released with its parent");
        assert!(dismissed.contains(&abandoned_child), "abandoned in its own right");
        assert!(dismissed.contains(&two_parents), "it still spends a dismissed one");
        assert!(dismissed.refetch_on_lock(&child), "its lock still fetches it");
        assert!(!dismissed.refetch_on_lock(&parent));

        dismissed.settled(&child);
        assert!(!dismissed.refetch_on_lock(&child));
        assert!(!dismissed.held_by.contains_key(&child));
    }

    #[test]
    fn a_spend_of_many_dismissed_transactions_is_held_until_it_settles() {
        let mut dismissed = DismissedTxids::default();
        let parents: Vec<Txid> = (0..=MAX_PARENTS as u32).map(txid).collect();
        for parent in &parents {
            dismissed.abandon(*parent);
        }
        let again = txid(u32::MAX - 1);
        for _ in 0..2 {
            assert!(dismissed.hold_spend(again, parents[..MAX_PARENTS].iter().copied()));
        }
        assert!(!dismissed.pinned.contains(&again), "parents counted once each");
        dismissed.settled(&again);
        let spend = txid(u32::MAX);
        assert!(dismissed.hold_spend(spend, parents.iter().copied()));
        assert!(dismissed.holds.is_empty(), "no parent index is kept for it");
        for parent in &parents {
            dismissed.settled(parent);
        }
        assert!(dismissed.contains(&spend));
        dismissed.settled(&spend);
        assert!(!dismissed.contains(&spend));
        assert!(dismissed.pinned.is_empty());
    }
}
