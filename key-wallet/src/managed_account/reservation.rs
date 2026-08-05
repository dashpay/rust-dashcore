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
//!
//! # Why reservations carry an owner token
//!
//! Releasing a reservation by outpoint alone is unsafe once *releasing* and
//! *re-reserving* can interleave. Every reservation is therefore stamped with a
//! [`ReservationToken`] identifying the build that made it, and the
//! abandon/rejected-broadcast release path ([`ReservationSet::release_if_owner`])
//! removes an outpoint only if it is *still owned by the releasing build*. See
//! [`ReservationSet::release_if_owner`] for the concrete hazard this closes and
//! why the check must be atomic under this set's mutex (`dashpay/platform#4185`).

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

/// Opaque, per-`reserve`-call identity stamped onto every outpoint that call
/// reserves.
///
/// A token is the *proof of ownership* a build presents to the reservation
/// set's `release_if_owner` so a release only removes the build's own
/// reservation. Each `reserve` call mints a fresh token from a monotonic
/// counter, so two reservations never share one — not even two reservations
/// taken at the same block height, which is why the height (which collides
/// freely) cannot serve as the identity.
///
/// The inner counter is private and there is no public constructor: a token can
/// only originate from a real `reserve` call. That is deliberate — it prevents a
/// caller from forging a token that happens to match another build's ownership
/// and releasing inputs out from under it.
///
/// Copy semantics let a build hold its token cheaply across an `.await` (e.g.
/// the platform broadcast path in `dashpay/platform#4185`) and present it again
/// when releasing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReservationToken(u64);

/// A single reserved outpoint: when it was reserved (for the TTL backstop) and
/// which build owns it (for owner-guarded release).
#[derive(Debug, Clone, Copy)]
struct Reservation {
    /// Block height at which the reservation was taken; drives the TTL sweep.
    reserved_at_height: u32,
    /// The build that reserved this outpoint. Only this owner may release it via
    /// [`ReservationSet::release_if_owner`].
    owner: ReservationToken,
}

/// Mutex-guarded interior: the reservations keyed by outpoint plus the counter
/// that mints the next [`ReservationToken`].
#[derive(Debug, Default)]
struct Reserved {
    entries: HashMap<OutPoint, Reservation>,
    /// Monotonically increasing source of unique tokens. Never persisted and
    /// only ever incremented, so within a process every issued token is unique.
    /// (Wraparound would need ~2^64 reserves in one process lifetime, which is
    /// unreachable in practice.)
    next_token: u64,
}

/// Ephemeral, in-memory set of reserved outpoints. Cloning shares the
/// underlying state, which is what lets a build's reservation outlive the
/// wallet lock and be seen by the next build.
#[derive(Debug, Clone, Default)]
pub(crate) struct ReservationSet {
    inner: Arc<Mutex<Reserved>>,
}

impl ReservationSet {
    /// Recovers from a poisoned mutex rather than panicking: the guarded data is
    /// a plain map plus a counter with no invariant a partial write could break,
    /// and panicking here would strand all later coin selection in a
    /// long-running node.
    fn lock(&self) -> MutexGuard<'_, Reserved> {
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn sweep(reserved: &mut Reserved, current_height: u32) {
        // Height 0 means the wallet has no processed height yet, so the elapsed
        // span is unknown and no entry can be reliably judged stale. An entry
        // stamped at height 0 therefore relies on a later non-zero height being
        // presented before it can ever be reclaimed by the TTL backstop.
        if current_height == 0 {
            return;
        }
        reserved.entries.retain(|_, reservation| {
            current_height.saturating_sub(reservation.reserved_at_height) < RESERVATION_TTL_BLOCKS
        });
    }

    /// Reserve `outpoints` as of `current_height`, dropping expired entries
    /// first, and return the [`ReservationToken`] stamped onto all of them.
    ///
    /// Every outpoint in a single call shares the one returned token: the caller
    /// keeps it and later presents it to [`Self::release_if_owner`] to release
    /// only what this call reserved. Re-reserving an outpoint (a later `reserve`
    /// naming it again) refreshes its height *and* transfers ownership to the new
    /// token — the previous owner's [`Self::release_if_owner`] then becomes a
    /// no-op for it, which is precisely the behavior that closes the
    /// release/re-reserve race described in the module docs (`platform#4185`).
    pub(crate) fn reserve(&self, outpoints: &[OutPoint], current_height: u32) -> ReservationToken {
        let mut reserved = self.lock();
        Self::sweep(&mut reserved, current_height);

        let owner = ReservationToken(reserved.next_token);
        // Increment even on an empty `outpoints` slice so a token is never
        // reissued; wrapping is documented-unreachable but avoids a debug panic.
        reserved.next_token = reserved.next_token.wrapping_add(1);

        for outpoint in outpoints {
            reserved.entries.insert(
                *outpoint,
                Reservation {
                    reserved_at_height: current_height,
                    owner,
                },
            );
        }
        owner
    }

    /// Return the currently reserved outpoints, dropping expired entries first.
    pub(crate) fn reserved(&self, current_height: u32) -> HashSet<OutPoint> {
        let mut reserved = self.lock();
        Self::sweep(&mut reserved, current_height);
        reserved.entries.keys().copied().collect()
    }

    /// Unconditionally release the given outpoints, regardless of owner.
    /// Idempotent: releasing an outpoint that is not reserved does nothing.
    ///
    /// This is correct only where the coins are *known spent* and so must leave
    /// the set no matter which build reserved them — e.g. when a processed spend
    /// hands its inputs from this ephemeral set to the durable spent set. A
    /// caller that is merely abandoning an in-flight build (rejected broadcast,
    /// cancelled send) must use [`Self::release_if_owner`] instead, so it cannot
    /// free a reservation another build has since taken over.
    pub(crate) fn release<'a>(&self, outpoints: impl IntoIterator<Item = &'a OutPoint>) {
        let mut reserved = self.lock();
        for outpoint in outpoints {
            reserved.entries.remove(outpoint);
        }
    }

    /// Release only the `outpoints` still owned by `token`, atomically under this
    /// set's mutex. An outpoint reserved by a different owner — because the TTL
    /// sweep reclaimed this build's reservation and another build re-reserved it
    /// meanwhile — is left untouched.
    ///
    /// This is the owner-guarded counterpart to [`Self::release`] and the whole
    /// reason reservations carry a [`ReservationToken`]; it is the canonical
    /// explanation the rest of the reservation machinery points back to. It is
    /// the release a build must use when it abandons an in-flight transaction
    /// after having `.await`ed something (a broadcast, an external signer):
    /// during that await the TTL sweep can reclaim this build's reservation and a
    /// *different* concurrent build can re-reserve the very same outpoint under a
    /// new token (same wallet generation, so any `Arc::ptr_eq` generation guard
    /// still matches). An unconditional release-by-outpoint would then free that
    /// other build's inputs, letting coin selection hand them to a second
    /// transaction — a double-spend window (`dashpay/platform#4185`). The
    /// platform layer cannot detect this because the sweep happens inside
    /// key-wallet invisibly; because the ownership check and the removal happen
    /// together while the mutex is held, no sweep or re-reserve can interleave
    /// between them.
    ///
    /// Idempotent and a no-op for any outpoint that is unreserved or owned by a
    /// different token — including one this build's own reservation already lost
    /// to a sweep, so a late release after reclamation is harmless.
    pub(crate) fn release_if_owner(&self, outpoints: &[OutPoint], token: ReservationToken) {
        use std::collections::hash_map::Entry;
        let mut reserved = self.lock();
        for outpoint in outpoints {
            // Single hash lookup per outpoint: the `Entry` locates the slot once,
            // and `remove` reuses it — "remove only if still mine", no second
            // `get` before the `remove`.
            if let Entry::Occupied(entry) = reserved.entries.entry(*outpoint) {
                if entry.get().owner == token {
                    entry.remove();
                }
            }
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

    #[test]
    fn each_reserve_call_mints_a_distinct_token() {
        let set = ReservationSet::default();
        // Two reserves at the SAME height must still get different tokens — the
        // whole point of not keying ownership on height, which collides.
        let token_a = set.reserve(&[outpoint(0x10, 0)], 100);
        let token_b = set.reserve(&[outpoint(0x11, 0)], 100);
        assert_ne!(token_a, token_b);
    }

    #[test]
    fn release_if_owner_releases_only_the_owning_builds_outpoints() {
        let set = ReservationSet::default();
        let mine = outpoint(0x20, 0);
        let theirs = outpoint(0x21, 0);

        let my_token = set.reserve(&[mine], 100);
        let _their_token = set.reserve(&[theirs], 100);

        // Releasing with my token frees only my outpoint; theirs is untouched.
        set.release_if_owner(&[mine, theirs], my_token);
        assert!(!set.reserved(100).contains(&mine));
        assert!(set.reserved(100).contains(&theirs));
    }

    #[test]
    fn release_if_owner_is_a_noop_for_unreserved_or_wrong_token() {
        let set = ReservationSet::default();
        let a = outpoint(0x22, 0);
        let stale_token = set.reserve(&[a], 100);

        // Simulate the outpoint being released and re-reserved by someone else.
        set.release([&a]);
        let _new_token = set.reserve(&[a], 100);

        // The stale token no longer owns `a`, so its release must not remove it.
        set.release_if_owner(&[a], stale_token);
        assert!(set.reserved(100).contains(&a));

        // A token for an outpoint that was never reserved is simply ignored.
        let never = outpoint(0x23, 0);
        set.release_if_owner(&[never], stale_token);
        assert!(!set.reserved(100).contains(&never));
    }

    /// The core TOCTOU regression: reserve X under token A, then simulate the
    /// TTL sweep reclaiming X and a *different* concurrent build re-reserving X
    /// under token B. Token A's late `release_if_owner` (the rejected-broadcast
    /// cleanup) must NOT remove X, because X now belongs to build B — releasing
    /// it would hand B's input to coin selection and open a double-spend window.
    /// See `dashpay/platform#4185`.
    #[test]
    fn release_if_owner_does_not_free_a_reservation_taken_over_after_a_sweep() {
        let set = ReservationSet::default();
        let x = outpoint(0x30, 0);

        // Build A reserves X.
        let token_a = set.reserve(&[x], 100);
        assert!(set.reserved(100).contains(&x));

        // TTL sweep reclaims A's reservation mid-await (modeled by advancing the
        // height past the TTL so the next reserve's sweep drops A's entry)...
        let swept_height = 100 + RESERVATION_TTL_BLOCKS;
        // ...and build B re-reserves the very same outpoint under a new token.
        let token_b = set.reserve(&[x], swept_height);
        assert_ne!(token_a, token_b);
        assert!(set.reserved(swept_height).contains(&x));

        // Build A's rejected-broadcast cleanup releases by (outpoint, token A).
        set.release_if_owner(&[x], token_a);

        // X must still be reserved — it is now owned by build B.
        assert!(
            set.reserved(swept_height).contains(&x),
            "release_if_owner with the stale owner token must not free B's reservation"
        );

        // And B can still release its own reservation normally.
        set.release_if_owner(&[x], token_b);
        assert!(!set.reserved(swept_height).contains(&x));
    }
}
