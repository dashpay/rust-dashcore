//! Ephemeral reservation of UTXOs selected by in-flight transaction builds.
//!
//! Coin selection reads the UTXO set, but a freshly built transaction is not
//! reflected in that set until the broadcast transaction is processed back into
//! the wallet (its inputs leave `utxos`). In the window between selecting inputs
//! and that processing, a second build sees the same UTXOs and can pick them
//! again, producing a double-spend the network rejects.
//!
//! A [`ReservationSet`] bridges exactly that window: selected inputs are
//! reserved at build time and skipped by subsequent coin selection. The set is
//! shared via `Arc<Mutex<_>>` so a reservation taken while the wallet lock is
//! held survives the lock being released and is observed by the next build. It
//! is never persisted: after a restart it is empty, where chain and mempool
//! sync are the source of truth for which coins are already spent.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

use dashcore::blockdata::transaction::OutPoint;

/// Number of blocks after which a stale reservation is reclaimed, about one
/// hour at the mainnet 2.5-minute block target.
///
/// A reservation is normally released the moment its broadcast transaction is
/// processed (the input leaves the UTXO set), and a restart drops all
/// reservations, so this backstop only matters for a reservation whose
/// transaction was built but never processed in a long-running process, e.g. a
/// silently failed broadcast. The value is kept comfortably above the real
/// selection-to-processing latency (seconds): reclaiming a still-in-flight
/// reservation too early would let coin selection re-pick the input and rebuild
/// the very double-spend this guards against.
const RESERVATION_TTL_BLOCKS: u32 = 24;

/// Ephemeral, in-memory set of reserved outpoints. Cloning shares the
/// underlying state, which is what lets a build's reservation outlive the
/// wallet lock and be seen by the next build.
#[derive(Debug, Clone, Default)]
pub(crate) struct ReservationSet {
    inner: Arc<Mutex<HashMap<OutPoint, u32>>>,
}

impl ReservationSet {
    /// Recovers from a poisoned mutex rather than panicking: the guarded data is
    /// a plain `HashMap` with no invariant a partial write could break, and
    /// panicking here would strand all later coin selection in a long-running
    /// node.
    fn lock(&self) -> MutexGuard<'_, HashMap<OutPoint, u32>> {
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn sweep(reserved: &mut HashMap<OutPoint, u32>, current_height: u32) {
        // Height 0 means the wallet has no processed height yet, so the elapsed
        // span is unknown and no entry can be reliably judged stale. An entry
        // stamped at height 0 therefore relies on a later non-zero height being
        // presented before it can ever be reclaimed by the TTL backstop.
        if current_height == 0 {
            return;
        }
        reserved.retain(|_, reserved_at| {
            current_height.saturating_sub(*reserved_at) < RESERVATION_TTL_BLOCKS
        });
    }

    /// Reserve `outpoints` as of `current_height`, dropping expired entries
    /// first. Re-reserving an outpoint refreshes its height.
    pub(crate) fn reserve(&self, outpoints: &[OutPoint], current_height: u32) {
        let mut reserved = self.lock();
        Self::sweep(&mut reserved, current_height);
        for outpoint in outpoints {
            reserved.insert(*outpoint, current_height);
        }
    }

    /// Return the currently reserved outpoints, dropping expired entries first.
    pub(crate) fn reserved(&self, current_height: u32) -> HashSet<OutPoint> {
        let mut reserved = self.lock();
        Self::sweep(&mut reserved, current_height);
        reserved.keys().copied().collect()
    }

    /// Release the given outpoints. Idempotent: releasing an outpoint that is
    /// not reserved does nothing.
    pub(crate) fn release<'a>(&self, outpoints: impl IntoIterator<Item = &'a OutPoint>) {
        let mut reserved = self.lock();
        for outpoint in outpoints {
            reserved.remove(outpoint);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::Txid;

    fn outpoint(byte: u8, vout: u32) -> OutPoint {
        OutPoint::new(Txid::from([byte; 32]), vout)
    }

    #[test]
    fn reserve_then_skip_then_release() {
        let set = ReservationSet::default();
        let a = outpoint(0x01, 0);
        let b = outpoint(0x02, 1);

        set.reserve(&[a], 100);
        assert!(set.reserved(100).contains(&a));
        assert!(!set.reserved(100).contains(&b));
        assert_eq!(set.reserved(100), HashSet::from([a]));

        set.release([&a]);
        assert!(set.reserved(100).is_empty());
    }

    #[test]
    fn release_is_idempotent() {
        let set = ReservationSet::default();
        let a = outpoint(0x03, 0);
        // Releasing an unreserved outpoint is a no-op.
        set.release([&a]);
        set.reserve(&[a], 10);
        set.release([&a]);
        set.release([&a]);
        assert!(!set.reserved(10).contains(&a));
    }

    #[test]
    fn ttl_reclaims_stale_reservation_by_height() {
        let set = ReservationSet::default();
        let a = outpoint(0x04, 0);
        set.reserve(&[a], 100);

        // The boundary is exclusive, so the entry survives until exactly
        // `reserved_at + RESERVATION_TTL_BLOCKS`.
        assert_eq!(set.reserved(100 + RESERVATION_TTL_BLOCKS - 1), HashSet::from([a]));
        // At that height the sweep's strict less-than drops the entry.
        assert!(set.reserved(100 + RESERVATION_TTL_BLOCKS).is_empty());
    }

    #[test]
    fn zero_height_disables_sweep() {
        let set = ReservationSet::default();
        let a = outpoint(0x07, 0);
        set.reserve(&[a], 0);

        // Height 0 means the wallet has no processed height yet, so the elapsed
        // span is unknown and the sweep is suppressed: the reservation stands.
        assert!(set.reserved(0).contains(&a));

        // Once a real height is known the TTL backstop applies again.
        set.reserve(&[a], 1);
        assert!(set.reserved(1 + RESERVATION_TTL_BLOCKS).is_empty());
    }

    #[test]
    fn re_reserving_refreshes_the_ttl_height() {
        let set = ReservationSet::default();
        let a = outpoint(0x06, 0);
        set.reserve(&[a], 100);
        // A later reserve replaces the stored height, so the TTL is measured
        // from the most recent reservation, not the first.
        set.reserve(&[a], 150);

        assert_eq!(set.reserved(150 + RESERVATION_TTL_BLOCKS - 1), HashSet::from([a]));
        assert!(set.reserved(150 + RESERVATION_TTL_BLOCKS).is_empty());
    }

    #[test]
    fn clone_shares_state() {
        let set = ReservationSet::default();
        let clone = set.clone();
        let a = outpoint(0x05, 0);
        // A reservation taken on one handle is visible through the other, which
        // is what lets a build's reservation outlive the wallet lock.
        set.reserve(&[a], 1);
        assert!(clone.reserved(1).contains(&a));
    }
}
