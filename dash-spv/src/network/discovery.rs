//! Peer discovery for Dash network.
//!
//! Peer discovery is seeded from two sources, in priority order:
//!
//! 1. A hardcoded masternode IP list for the network, embedded at compile time
//!    from `dash-spv/seeds/<network>.txt`. This file is regenerated weekly by
//!    CI from a live Dash Core node (see `masternode-seeds-fetcher`).
//! 2. DNS seed queries as a backup. DNS resolution failures are logged but are
//!    not fatal — as long as the embedded list yields at least one peer, the
//!    client can bootstrap.
//!
//! Results from both sources are merged and deduplicated. Addresses gossiped by
//! connected peers are folded in later via [`PeerDiscoverer::learn`].
//!
//! Most masternodes of a network can sit in one address block, so [`PeerDiscoverer::get`]
//! spreads its picks across [`NetGroup`]s instead of sampling addresses uniformly.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use dashcore::Network;
use rand::seq::SliceRandom;

use crate::network::peer::DisconnectedPeer;
use crate::ClientConfig;

const DNS_LOOKUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const MAX_LEARNED: usize = 2000;
const MAX_ADDR_AGE: u32 = 7 * 24 * 60 * 60;
const MAX_ADDR_FUTURE: u32 = 10 * 60;
const MAX_PROBED: usize = 32;

/// The address block a peer belongs to, a /16 for IPv4 and a /32 for IPv6. Peers of one
/// block tend to share an operator and an uplink, so they slow down together.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum NetGroup {
    V4(u8, u8),
    V6(u16, u16),
}

impl NetGroup {
    pub(crate) fn of(addr: SocketAddr) -> Self {
        match addr.ip().to_canonical() {
            IpAddr::V4(ip) => {
                let [a, b, ..] = ip.octets();
                NetGroup::V4(a, b)
            }
            IpAddr::V6(ip) => {
                let [a, b, ..] = ip.segments();
                NetGroup::V6(a, b)
            }
        }
    }
}

pub struct PeerDiscoverer {
    network: Network,
    // Empty means "discover" from the compiled-in seeds, then DNS.
    fixed: Vec<SocketAddr>,
    /// Only the configured peers are dialed, whatever their network groups.
    exclusive: bool,
    /// Resolved once and kept. Not consumed as handed out: the reconnector comes back
    /// on every drop, and a drained pool would leave the client nothing to reconnect to.
    discovered: Option<Vec<SocketAddr>>,
    learned: HashMap<SocketAddr, u32>,
    /// Handshake ping of peers probed but not kept, tried first next time.
    probed: HashMap<SocketAddr, u32>,
}

impl PeerDiscoverer {
    pub fn new(config: &ClientConfig) -> PeerDiscoverer {
        PeerDiscoverer {
            network: config.network,
            fixed: config.peers.clone(),
            exclusive: config.exclusive_peers(),
            discovered: None,
            learned: HashMap::new(),
            probed: HashMap::new(),
        }
    }

    pub fn learn(&mut self, addresses: impl IntoIterator<Item = (SocketAddr, u32)>) -> usize {
        if self.exclusive {
            return 0;
        }
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as u32);
        let mut added = 0;
        for (addr, time) in addresses {
            if time < now.saturating_sub(MAX_ADDR_AGE) || time > now + MAX_ADDR_FUTURE {
                continue;
            }
            match self.learned.insert(addr, time) {
                None => added += 1,
                Some(old) if old > time => {
                    self.learned.insert(addr, old);
                }
                Some(_) => {}
            }
        }
        if self.learned.len() > MAX_LEARNED {
            let mut learned: Vec<_> = self.learned.drain().collect();
            learned.sort_by_key(|(_, time)| std::cmp::Reverse(*time));
            learned.truncate(MAX_LEARNED);
            self.learned.extend(learned);
        }
        added
    }

    pub fn probed(&mut self, addr: SocketAddr, lag_ms: u32) {
        let lag_ms = if lag_ms == 0 {
            u32::MAX
        } else {
            lag_ms
        };
        let best = self.probed.entry(addr).or_insert(lag_ms);
        *best = (*best).min(lag_ms);
        if self.probed.len() > MAX_PROBED {
            let worst = self.probed.iter().max_by_key(|(_, lag)| **lag).map(|(addr, _)| *addr);
            worst.map(|addr| self.probed.remove(&addr));
        }
    }

    /// Up to `count` addresses to dial, none of them `connected` or `banned`. The best
    /// probed come first, then a random sample. Unless the peers are exclusive, this order
    /// spreads across network groups, see [`spread_across_groups`]. With `new_groups_only`
    /// no address from a group of the `connected` peers is returned, and no configured one.
    pub async fn get(
        &mut self,
        count: usize,
        connected: &HashSet<SocketAddr>,
        banned: &HashSet<SocketAddr>,
        new_groups_only: bool,
    ) -> Vec<DisconnectedPeer> {
        if self.exclusive && new_groups_only {
            return Vec::new();
        }
        let mut pool = if self.exclusive {
            self.fixed.clone()
        } else {
            if self.discovered.is_none() {
                let found = Self::discover(self.network).await;
                self.discovered = Some(found);
            }
            let mut pool = self.discovered.clone().expect("just set");
            pool.extend(self.learned.keys());
            pool
        };
        pool.extend(self.probed.keys());
        pool.sort();
        pool.dedup();
        pool.retain(|addr| !connected.contains(addr) && !banned.contains(addr));
        pool.shuffle(&mut rand::rng());
        pool.sort_by_key(|addr| self.probed.get(addr).copied().unwrap_or(u32::MAX));
        if !self.exclusive {
            pool = spread_across_groups(pool, connected, new_groups_only);
        }
        pool.truncate(count);
        for addr in &pool {
            self.probed.remove(addr);
        }
        pool.into_iter().map(|addr| DisconnectedPeer::new(addr, self.network)).collect()
    }

    async fn discover(network: Network) -> Vec<SocketAddr> {
        let mut addresses = dash_network_seeds::addresses(network);

        let port = network.default_p2p_port();
        for seed in network.dns_seeds() {
            match tokio::time::timeout(DNS_LOOKUP_TIMEOUT, tokio::net::lookup_host((*seed, port)))
                .await
            {
                Ok(Ok(iter)) => {
                    let resolved: Vec<SocketAddr> = iter.collect();
                    tracing::info!("DNS seed {} returned {} addresses", seed, resolved.len());
                    addresses.extend(resolved);
                }
                Ok(Err(e)) => {
                    tracing::warn!("Failed to resolve DNS seed {} (backup source): {}", seed, e);
                }
                Err(_) => {
                    tracing::warn!(
                        "DNS seed {} did not resolve within {:?} (backup source)",
                        seed,
                        DNS_LOOKUP_TIMEOUT
                    );
                }
            }
        }

        addresses.sort();
        addresses.dedup();
        // Dedup needs the sort above, but a sorted list makes every client pick
        // the same lowest-address peers via `take`/`truncate`, herding testers
        // onto a handful of nodes. Shuffle so clients fan out across the set.
        addresses.shuffle(&mut rand::rng());

        addresses
    }
}

/// Reorders `pool` so groups without a `connected` peer come first, one address per
/// group in turn. Addresses of a group keep their order in `pool`. The groups of the
/// `connected` peers follow, so a network of few groups still fills, unless
/// `new_groups_only` drops them.
fn spread_across_groups(
    pool: Vec<SocketAddr>,
    connected: &HashSet<SocketAddr>,
    new_groups_only: bool,
) -> Vec<SocketAddr> {
    let covered: HashSet<NetGroup> = connected.iter().map(|addr| NetGroup::of(*addr)).collect();
    let mut turns: HashMap<NetGroup, usize> = HashMap::new();
    let mut ranked: Vec<(bool, usize, SocketAddr)> = pool
        .into_iter()
        .map(|addr| {
            let group = NetGroup::of(addr);
            let turn = turns.entry(group).or_default();
            *turn += 1;
            (covered.contains(&group), *turn, addr)
        })
        .filter(|(is_covered, ..)| !(new_groups_only && *is_covered))
        .collect();
    ranked.sort_by_key(|&(is_covered, turn, _)| (is_covered, turn));
    ranked.into_iter().map(|(.., addr)| addr).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("a socket address")
    }

    /// A regtest discoverer, which has no seeds, that learned `addresses`.
    fn discoverer(addresses: &[&str]) -> PeerDiscoverer {
        let mut discoverer = PeerDiscoverer::new(&ClientConfig::regtest());
        let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("after epoch").as_secs();
        discoverer.learn(addresses.iter().map(|a| (addr(a), now as u32)));
        discoverer
    }

    fn set(addresses: &[&str]) -> HashSet<SocketAddr> {
        addresses.iter().map(|a| addr(a)).collect()
    }

    fn set_of(addresses: &[SocketAddr]) -> HashSet<SocketAddr> {
        addresses.iter().copied().collect()
    }

    async fn picks(
        discoverer: &mut PeerDiscoverer,
        count: usize,
        connected: &[&str],
        new_groups_only: bool,
    ) -> Vec<SocketAddr> {
        let connected = set(connected);
        let peers = discoverer.get(count, &connected, &HashSet::new(), new_groups_only).await;
        peers.iter().map(|p| p.addr()).collect()
    }

    #[test_case("68.67.122.1:1", "68.67.200.2:2" => true; "ipv4 in one /16")]
    #[test_case("68.67.122.1:1", "68.68.122.1:1" => false; "ipv4 across /16s")]
    #[test_case("[2a0e:b781:55d1:f32e::]:1", "[2a0e:b781:1::1]:1" => true; "ipv6 in one /32")]
    #[test_case("[2a0e:b781::1]:1", "[2a0e:b782::1]:1" => false; "ipv6 across /32s")]
    #[test_case("[::ffff:68.67.122.1]:1", "68.67.0.1:1" => true; "a mapped ipv4 is ipv4")]
    #[test_case("127.0.0.1:1", "127.0.0.1:2" => true; "loopback peers share a group")]
    fn net_groups(a: &str, b: &str) -> bool {
        NetGroup::of(addr(a)) == NetGroup::of(addr(b))
    }

    /// A crowded block must not crowd out the only address of another block.
    #[tokio::test]
    async fn dials_a_group_not_yet_connected() {
        let block: Vec<String> = (1..=50).map(|n| format!("68.67.122.{n}:1")).collect();
        let mut addresses: Vec<&str> = block.iter().map(String::as_str).collect();
        addresses.push("206.245.167.63:1");
        let mut discoverer = discoverer(&addresses);

        let got = picks(&mut discoverer, 1, &["68.67.122.1:1"], false).await;

        assert_eq!(got, [addr("206.245.167.63:1")]);
    }

    /// A batch for an empty set takes one address per group before it takes a second one.
    #[tokio::test]
    async fn a_batch_spreads_over_the_groups() {
        let mut discoverer = discoverer(&[
            "68.67.122.1:1",
            "68.67.122.2:1",
            "68.67.122.3:1",
            "206.245.167.63:1",
            "85.209.243.1:1",
        ]);

        let got = picks(&mut discoverer, 3, &[], false).await;

        let groups: HashSet<NetGroup> = got.iter().map(|a| NetGroup::of(*a)).collect();
        assert_eq!(groups.len(), 3, "got {got:?}");
    }

    /// Regtest peers are all loopback: a single group must still fill the set.
    #[tokio::test]
    async fn falls_back_to_a_connected_group() {
        let mut discoverer = discoverer(&["127.0.0.1:1", "127.0.0.1:2", "127.0.0.1:3"]);

        let got = picks(&mut discoverer, 2, &["127.0.0.1:1"], false).await;

        assert_eq!(set_of(&got), set(&["127.0.0.1:2", "127.0.0.1:3"]));
    }

    #[tokio::test]
    async fn new_groups_only_never_falls_back() {
        let mut discoverer = discoverer(&["68.67.122.1:1", "68.67.122.2:1"]);

        assert!(picks(&mut discoverer, 2, &["68.67.122.1:1"], true).await.is_empty());
    }

    /// A probed address waits its group's turn, but goes first within that turn. One not
    /// returned stays remembered.
    #[tokio::test]
    async fn a_probed_address_keeps_its_priority_within_the_groups() {
        let mut discoverer =
            discoverer(&["68.67.122.2:1", "68.67.122.3:1", "206.245.167.63:1", "206.245.167.64:1"]);
        discoverer.probed(addr("68.67.122.2:1"), 10);
        discoverer.probed(addr("206.245.167.64:1"), 50);

        let got = picks(&mut discoverer, 1, &["68.67.122.1:1"], false).await;
        assert_eq!(got, [addr("206.245.167.64:1")]);
        assert!(discoverer.probed.contains_key(&addr("68.67.122.2:1")));
        assert!(!discoverer.probed.contains_key(&addr("206.245.167.64:1")));

        let got = picks(&mut discoverer, 1, &["206.245.167.63:1"], false).await;
        assert_eq!(got, [addr("68.67.122.2:1")]);
    }

    #[tokio::test]
    async fn skips_connected_and_banned_addresses() {
        let mut discoverer = discoverer(&["68.67.122.1:1", "206.245.167.63:1", "85.209.243.1:1"]);

        let got =
            discoverer.get(3, &set(&["68.67.122.1:1"]), &set(&["206.245.167.63:1"]), false).await;

        let got: Vec<SocketAddr> = got.iter().map(|p| p.addr()).collect();
        assert_eq!(got, [addr("85.209.243.1:1")]);
    }

    /// Configured peers are dialed whatever their groups, the best probed first, and
    /// never offered in place of a connected peer for its group.
    #[tokio::test]
    async fn exclusive_peers_are_not_grouped() {
        let mut config = ClientConfig::regtest();
        config.peers = vec![addr("68.67.122.1:1"), addr("68.67.122.2:1"), addr("206.245.167.63:1")];
        let mut discoverer = PeerDiscoverer::new(&config);
        discoverer.probed(addr("68.67.122.2:1"), 10);

        let got = picks(&mut discoverer, 1, &["206.245.167.64:1"], false).await;
        assert_eq!(got, [addr("68.67.122.2:1")]);

        assert!(picks(&mut discoverer, 3, &["206.245.167.64:1"], true).await.is_empty());
    }

    #[tokio::test]
    async fn test_dns_discovery_testnet_returns_embedded_when_dns_fails() {
        // This test does not require network access: even if DNS resolution
        // fails, the embedded seed file must yield peers.
        let peers = PeerDiscoverer::discover(Network::Testnet).await;

        assert!(
            peers.len() >= 29,
            "expected at least the 29 embedded testnet HP-MN seeds, got {}",
            peers.len()
        );
        for peer in &peers {
            assert_eq!(peer.port(), Network::Testnet.default_p2p_port());
        }
    }

    #[tokio::test]
    async fn test_dns_discovery_regtest() {
        let peers = PeerDiscoverer::discover(Network::Regtest).await;

        // Should return empty for regtest (no DNS seeds and no embedded list)
        assert!(peers.is_empty());
    }
}
