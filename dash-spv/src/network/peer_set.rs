//! The connected-peer set, which announces every change made to it.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::atomic::{AtomicU32, Ordering};

use tokio::sync::{broadcast, Mutex, MutexGuard};
use tokio_util::sync::CancellationToken;

use crate::network::manager::NetworkEvent;
use crate::network::peer::{ConnectedPeer, PeerId};

/// The connected peers. Every change is announced while the set's lock is held, so
/// subscribers that mirror the set from the events see the changes in the order they
/// happened, and the last `PeersUpdated` always lists the current peers.
pub(crate) struct PeerSet {
    peers: Mutex<Vec<ConnectedPeer>>,
    events: broadcast::Sender<NetworkEvent>,
    /// Best tip height advertised by any peer that completed a handshake.
    best_tip: AtomicU32,
}

/// What [`PeerSet::admit`] did with a handshaken peer.
pub(crate) enum Admission {
    Joined,
    /// Joined in place of this peer, which the caller has to close.
    Swapped(ConnectedPeer),
    /// The set is full and the peer to swap out is not in it, so this one is handed back.
    Full(ConnectedPeer),
    /// The session stopped, so this peer is handed back for the caller to close.
    Stopped(ConnectedPeer),
}

/// Read access to the peers while holding the set's lock.
pub(crate) struct Peers<'a>(MutexGuard<'a, Vec<ConnectedPeer>>);

impl Deref for Peers<'_> {
    type Target = [ConnectedPeer];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PeerSet {
    pub(crate) fn new(capacity: usize) -> Self {
        PeerSet {
            peers: Mutex::new(Vec::with_capacity(capacity)),
            events: broadcast::channel(4096).0,
            best_tip: AtomicU32::new(0),
        }
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<NetworkEvent> {
        self.events.subscribe()
    }

    pub(crate) fn best_tip(&self) -> u32 {
        self.best_tip.load(Ordering::Relaxed)
    }

    pub(crate) fn raise_best_tip(&self, height: u32) {
        self.best_tip.fetch_max(height, Ordering::Relaxed);
    }

    pub(crate) async fn read(&self) -> Peers<'_> {
        Peers(self.peers.lock().await)
    }

    pub(crate) async fn len(&self) -> usize {
        self.peers.lock().await.len()
    }

    /// Adds `peer` if the set holds fewer than `capacity` peers, otherwise in place of
    /// the peer at `slow`. Refuses it once `session` is cancelled. `stop` cancels the
    /// session before it clears the set, so every peer admitted is announced as gone.
    pub(crate) async fn admit(
        &self,
        peer: ConnectedPeer,
        session: &CancellationToken,
        capacity: usize,
        slow: Option<SocketAddr>,
    ) -> Admission {
        let mut peers = self.peers.lock().await;
        if session.is_cancelled() {
            return Admission::Stopped(peer);
        }
        let arrived = peer.addr();
        if peers.len() < capacity {
            peers.push(peer);
            self.announce(&peers, None, Some(arrived));
            return Admission::Joined;
        }
        // Re-find by address under the lock: the laggard may already be gone.
        let Some(pos) = slow.and_then(|s| peers.iter().position(|p| p.addr() == s)) else {
            return Admission::Full(peer);
        };
        let old = peers.swap_remove(pos);
        peers.push(peer);
        self.announce(&peers, Some(old.addr()), Some(arrived));
        Admission::Swapped(old)
    }

    /// Removes the connections `ids` that are still in the set and returns them, with
    /// the number of peers left. A connection already gone is not announced again.
    pub(crate) async fn remove(&self, ids: &HashSet<PeerId>) -> (Vec<ConnectedPeer>, usize) {
        let mut peers = self.peers.lock().await;
        let removed: Vec<_> = peers.extract_if(.., |p| ids.contains(&p.id())).collect();
        self.announce(&peers, removed.iter().map(|p| p.addr()), None);
        (removed, peers.len())
    }

    /// Removes every peer and returns their addresses.
    pub(crate) async fn clear(&self) -> Vec<SocketAddr> {
        let mut peers = self.peers.lock().await;
        let removed: Vec<_> = peers.drain(..).map(|p| p.addr()).collect();
        self.announce(&peers, removed.iter().copied(), None);
        removed
    }

    /// Announces the peers at `departed` and `arrived` against the `remaining` set,
    /// then the `remaining` peers if anything changed.
    fn announce(
        &self,
        remaining: &[ConnectedPeer],
        departed: impl IntoIterator<Item = SocketAddr>,
        arrived: Option<SocketAddr>,
    ) {
        let mut changed = false;
        for addr in departed {
            changed = true;
            // Subscribers know peers by address only, so a live connection to the
            // same address keeps it.
            if !remaining.iter().any(|p| p.addr() == addr) {
                let _ = self.events.send(NetworkEvent::PeerDisconnected(addr));
            }
        }
        if let Some(addr) = arrived {
            changed = true;
            let _ = self.events.send(NetworkEvent::PeerConnected(addr));
        }
        if changed {
            let _ = self.events.send(NetworkEvent::PeersUpdated {
                addresses: remaining.iter().map(|p| p.addr()).collect(),
                best_height: self.best_tip(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::test_socket_address;

    fn conn(addr: u8) -> PeerId {
        PeerId::for_test(test_socket_address(addr), 0)
    }

    fn queued(events: &mut broadcast::Receiver<NetworkEvent>) -> Vec<NetworkEvent> {
        let mut out = Vec::new();
        while let Ok(event) = events.try_recv() {
            out.push(event);
        }
        out
    }

    /// A swap announces the old peer out and the new one in exactly once, and a peer
    /// that is not in the full set is no reason to make room.
    #[tokio::test]
    async fn a_swap_announces_old_out_and_new_in_once() {
        let set = PeerSet::new(2);
        let session = CancellationToken::new();
        for n in [1, 2] {
            let peer = ConnectedPeer::for_test(conn(n)).await;
            assert!(matches!(set.admit(peer, &session, 2, None).await, Admission::Joined));
        }
        let mut events = set.subscribe();

        let peer = ConnectedPeer::for_test(conn(3)).await;
        let absent = Some(test_socket_address(9));
        assert!(matches!(set.admit(peer, &session, 2, absent).await, Admission::Full(_)));

        let peer = ConnectedPeer::for_test(conn(3)).await;
        let slow = Some(conn(1).addr());
        let Admission::Swapped(old) = set.admit(peer, &session, 2, slow).await else {
            panic!("the slow peer is in the full set");
        };
        assert_eq!(old.id(), conn(1));
        assert_eq!(
            queued(&mut events),
            [
                NetworkEvent::PeerDisconnected(conn(1).addr()),
                NetworkEvent::PeerConnected(conn(3).addr()),
                NetworkEvent::PeersUpdated {
                    addresses: vec![conn(2).addr(), conn(3).addr()],
                    best_height: 0,
                },
            ]
        );

        // The swapped out connection's own disconnect finds it gone.
        let (removed, remaining) = set.remove(&HashSet::from([conn(1)])).await;
        assert!(removed.is_empty());
        assert_eq!(remaining, 2);
        assert!(queued(&mut events).is_empty());
    }
}
