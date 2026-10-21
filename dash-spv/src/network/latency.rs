//! Per-peer response-latency tracking used to route sync requests.
//!
//! Routing quality is deliberately separate from the misbehavior score in
//! [`super::reputation`]. That score is an accusation: it only ever rises, and a
//! peer carrying no accusations is indistinguishable from one that has never been
//! tried. Routing needs the opposite property, evidence that expires back to
//! "unknown", so a peer that lost an early race is retried instead of starved.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Weight of the newest observation when folding it into a peer's mean, in
/// percent. Low enough that one slow response does not drop a peer out of
/// rotation, high enough that a peer going bad is demoted within a few requests.
const NEW_SAMPLE_WEIGHT: u32 = 30;

/// How long an observation stays authoritative. Past this the peer counts as
/// unmeasured and is routed to again whatever its last mean, which is what stops
/// a peer from being frozen out permanently. This must exceed the stall timeout
/// plus a maintenance tick: a peer that is actually stalling then keeps refreshing
/// a bad mean and stays out of rotation, rather than aging back into it.
const SAMPLE_TTL: Duration = Duration::from_secs(30);

/// A peer keeps receiving requests while its mean stays within this multiple of
/// the best measured peer's.
///
/// Deliberately generous. Requests pipeline across peers, so a merely slower peer
/// still adds throughput and is worth keeping in rotation, and dropping it would
/// concentrate load on fewer peers for no gain. The job here is to shed peers that
/// have effectively stopped answering, which stand out by an order of magnitude
/// (a stall is recorded at ten seconds against sub-second healthy responses), not
/// to rank healthy peers against each other.
const SLOW_MULTIPLIER: u32 = 4;

/// Absolute slack allowed alongside `SLOW_MULTIPLIER`, so that when peers are all
/// fast in absolute terms the multiple does not split hairs over normal jitter.
const SLOW_MARGIN: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Copy)]
struct Observation {
    mean: Duration,
    at: Instant,
}

/// Rolling response-time means for connected peers.
#[derive(Debug, Default)]
pub(super) struct PeerLatency {
    observations: HashMap<SocketAddr, Observation>,
}

impl PeerLatency {
    /// Fold an observed response time into `addr`'s mean.
    ///
    /// A stalling request is recorded with the time it has been outstanding, which
    /// is by definition at least the stall timeout, so a stalling peer's mean
    /// climbs clear of any healthy peer's without needing a sentinel value.
    pub(super) fn record(&mut self, addr: SocketAddr, elapsed: Duration) {
        let now = Instant::now();
        match self.observations.get_mut(&addr) {
            Some(observation) => {
                observation.mean = blend(observation.mean, elapsed);
                observation.at = now;
            }
            None => {
                self.observations.insert(
                    addr,
                    Observation {
                        mean: elapsed,
                        at: now,
                    },
                );
            }
        }
    }

    /// Drop observations for peers that are no longer connected.
    pub(super) fn retain_connected(&mut self, connected: &[SocketAddr]) {
        self.observations.retain(|addr, _| connected.contains(addr));
    }

    /// The subset of `addrs` that should receive requests.
    ///
    /// Peers with no fresh observation are always eligible. We have no evidence
    /// about them, and since only a request can produce evidence, excluding them
    /// would make that lack of evidence permanent. The measured peers stay
    /// eligible while they remain within reach of the best of them.
    pub(super) fn eligible(&self, addrs: &[SocketAddr]) -> HashSet<SocketAddr> {
        let now = Instant::now();
        let fresh = |addr: &SocketAddr| {
            self.observations
                .get(addr)
                .filter(|observation| now.saturating_duration_since(observation.at) < SAMPLE_TTL)
        };

        let Some(best) = addrs.iter().filter_map(fresh).map(|observation| observation.mean).min()
        else {
            return addrs.iter().copied().collect();
        };
        let threshold = best.saturating_mul(SLOW_MULTIPLIER).max(best.saturating_add(SLOW_MARGIN));

        addrs
            .iter()
            .copied()
            .filter(|addr| fresh(addr).is_none_or(|observation| observation.mean <= threshold))
            .collect()
    }
}

/// Fold `sample` into `mean`, weighting the sample by `NEW_SAMPLE_WEIGHT`.
fn blend(mean: Duration, sample: Duration) -> Duration {
    let old = mean.as_micros().saturating_mul(u128::from(100 - NEW_SAMPLE_WEIGHT));
    let new = sample.as_micros().saturating_mul(u128::from(NEW_SAMPLE_WEIGHT));
    let micros = (old.saturating_add(new) / 100).min(u128::from(u64::MAX));
    Duration::from_micros(micros as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(last_octet: u8) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, last_octet], 9999))
    }

    #[test]
    fn unmeasured_peers_are_always_eligible() {
        let latency = PeerLatency::default();
        let peers = [addr(1), addr(2), addr(3)];

        assert_eq!(latency.eligible(&peers).len(), 3);
    }

    #[test]
    fn slow_peer_drops_out_but_a_starved_peer_returns_when_its_sample_expires() {
        let mut latency = PeerLatency::default();
        let (fast, slow) = (addr(1), addr(2));
        latency.record(fast, Duration::from_millis(50));
        latency.record(slow, Duration::from_secs(5));

        let eligible = latency.eligible(&[fast, slow]);
        assert!(eligible.contains(&fast));
        assert!(!eligible.contains(&slow), "a clearly slower peer stays out of rotation");

        // Starvation is the failure this guards: once out of rotation the peer
        // receives nothing, so only expiry can ever make it measurable again.
        latency.observations.get_mut(&slow).expect("recorded above").at =
            Instant::now() - SAMPLE_TTL - Duration::from_secs(1);

        assert!(
            latency.eligible(&[fast, slow]).contains(&slow),
            "an expired observation must put the peer back in rotation"
        );
    }

    #[test]
    fn comparable_peers_share_rotation() {
        let mut latency = PeerLatency::default();
        let (a, b) = (addr(1), addr(2));
        latency.record(a, Duration::from_millis(20));
        latency.record(b, Duration::from_millis(90));

        assert_eq!(
            latency.eligible(&[a, b]).len(),
            2,
            "peers that are all fast in absolute terms stay in rotation together"
        );
    }

    #[test]
    fn a_single_slow_response_does_not_evict_a_proven_peer() {
        let mut latency = PeerLatency::default();
        let (fast, blip) = (addr(1), addr(2));
        latency.record(fast, Duration::from_millis(50));
        for _ in 0..10 {
            latency.record(blip, Duration::from_millis(50));
        }
        latency.record(blip, Duration::from_secs(1));

        assert!(
            latency.eligible(&[fast, blip]).contains(&blip),
            "one blip should not undo a peer's track record"
        );
    }

    #[test]
    fn repeated_stalls_demote_a_peer() {
        let mut latency = PeerLatency::default();
        let (fast, stalling) = (addr(1), addr(2));
        latency.record(fast, Duration::from_millis(50));
        latency.record(stalling, Duration::from_millis(50));
        for _ in 0..3 {
            latency.record(stalling, Duration::from_secs(10));
        }

        assert!(!latency.eligible(&[fast, stalling]).contains(&stalling));
    }

    #[test]
    fn disconnected_peers_are_forgotten() {
        let mut latency = PeerLatency::default();
        latency.record(addr(1), Duration::from_millis(50));
        latency.record(addr(2), Duration::from_millis(50));

        latency.retain_connected(&[addr(1)]);

        assert_eq!(latency.observations.len(), 1);
        assert!(latency.observations.contains_key(&addr(1)));
    }
}
