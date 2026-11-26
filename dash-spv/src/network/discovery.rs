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

use std::cmp::Reverse;
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
enum NetGroup {
    V4(u8, u8),
    V6(u16, u16),
}

impl NetGroup {
    fn of(addr: SocketAddr) -> Self {
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

/// When a gossiped address was last seen, and the group of the seed that gossiped it first
/// or that gossiped the peer it came from. `None` if that is not known.
struct Gossip {
    time: u32,
    source: Option<NetGroup>,
}

/// Whose turn an address takes in a batch. One peer can gossip addresses of any number of
/// groups, so all of them share the turn of their source.
#[derive(PartialEq, Eq, Hash)]
enum Turn {
    Seed(NetGroup),
    Gossip(Option<NetGroup>),
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum ProbeRank {
    Backup,
    Untried,
    TurnedAway,
}

pub struct PeerDiscoverer {
    network: Network,
    // Empty means "discover" from the compiled-in seeds, then DNS.
    fixed: Vec<SocketAddr>,
    /// Only the configured peers are dialed, whatever their network groups. Configuring any
    /// peer replaces discovery, with or without `restrict_to_configured_peers`.
    exclusive: bool,
    /// Resolved once and kept. Not consumed as handed out: the reconnector comes back
    /// on every drop, and a drained pool would leave the client nothing to reconnect to.
    discovered: Option<Vec<SocketAddr>>,
    learned: HashMap<SocketAddr, Gossip>,
    /// Peers probed but not kept: whether their handshake ping turned them away, and that ping.
    /// Those turned away are tried last next time, the others first.
    probed: HashMap<SocketAddr, (bool, u32)>,
}

impl PeerDiscoverer {
    pub fn new(config: &ClientConfig) -> PeerDiscoverer {
        PeerDiscoverer {
            network: config.network,
            fixed: config.peers.clone(),
            exclusive: !config.peers.is_empty() || config.restrict_to_configured_peers,
            discovered: None,
            learned: HashMap::new(),
            probed: HashMap::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn set_seeds(&mut self, seeds: Vec<SocketAddr>) {
        self.discovered = Some(seeds);
    }

    /// Adds the addresses gossiped by the peer at `from`. Returns how many are new.
    pub fn learn(
        &mut self,
        from: SocketAddr,
        addresses: impl IntoIterator<Item = (SocketAddr, u32)>,
    ) -> usize {
        if self.exclusive {
            return 0;
        }
        // A gossiped peer passes its own source on, so peers that gossip each other stay one.
        let source = if self.discovered.iter().flatten().any(|seed| *seed == from) {
            Some(NetGroup::of(from))
        } else {
            self.learned.get(&from).and_then(|gossip| gossip.source)
        };
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as u32);
        let mut added = 0;
        for (addr, time) in addresses {
            if time < now.saturating_sub(MAX_ADDR_AGE) || time > now + MAX_ADDR_FUTURE {
                continue;
            }
            let gossip = self.learned.entry(addr).or_insert_with(|| {
                added += 1;
                Gossip {
                    time,
                    source,
                }
            });
            gossip.time = gossip.time.max(time);
        }
        if self.learned.len() > MAX_LEARNED {
            let mut learned: Vec<_> = self.learned.drain().collect();
            learned.sort_by_key(|(_, gossip)| Reverse(gossip.time));
            learned.truncate(MAX_LEARNED);
            self.learned.extend(learned);
        }
        added
    }

    pub fn probed(&mut self, addr: SocketAddr, lag_ms: u32, turned_away: bool) {
        let lag_ms = if lag_ms == 0 {
            u32::MAX
        } else {
            lag_ms
        };
        self.probed.insert(addr, (turned_away, lag_ms));
        if self.probed.len() > MAX_PROBED {
            // A forgotten address ranks as untried, so forget the slowest backup before any
            // address turned away.
            let worst = self
                .probed
                .iter()
                .max_by_key(|(_, &(turned_away, lag))| (!turned_away, lag))
                .map(|(addr, _)| *addr);
            worst.map(|addr| self.probed.remove(&addr));
        }
    }

    /// Up to `count` addresses to dial, none of them `connected` or `banned`. Backups go first
    /// and those turned away last, and all but exclusive ones go by
    /// [`Self::spread_across_groups`].
    pub async fn get(
        &mut self,
        count: usize,
        connected: &HashSet<SocketAddr>,
        banned: &HashSet<SocketAddr>,
    ) -> Vec<DisconnectedPeer> {
        let mut seeds = HashSet::new();
        let mut pool = if self.exclusive {
            self.fixed.clone()
        } else {
            let discovered = match self.discovered.take() {
                Some(found) => found,
                None => Self::discover(self.network).await,
            };
            let mut pool = self.discovered.insert(discovered).clone();
            seeds.extend(pool.iter().copied());
            pool.extend(self.learned.keys());
            pool
        };
        pool.extend(self.probed.keys());
        pool.sort();
        pool.dedup();
        pool.retain(|addr| !connected.contains(addr) && !banned.contains(addr));
        pool.shuffle(&mut rand::rng());
        pool.sort_by_key(|addr| self.probe_rank(*addr));
        if !self.exclusive {
            pool = self.spread_across_groups(pool, &seeds, connected);
        }
        pool.truncate(count);
        for addr in &pool {
            self.probed.remove(addr);
        }
        pool.into_iter().map(|addr| DisconnectedPeer::new(addr, self.network)).collect()
    }

    /// Sort key that puts backups first and those turned away last, the fastest of each in
    /// front.
    fn probe_rank(&self, addr: SocketAddr) -> (ProbeRank, u32) {
        match self.probed.get(&addr) {
            Some(&(false, lag)) => (ProbeRank::Backup, lag),
            None => (ProbeRank::Untried, 0),
            Some(&(true, lag)) => (ProbeRank::TurnedAway, lag),
        }
    }

    /// Reorders `pool` to one address per [`Turn`] in turn, in each the groups without a
    /// `connected` peer first. A turn takes those groups first too, then goes by the order of
    /// `pool`. Those turned away go last whatever their group, or they would take every batch.
    fn spread_across_groups(
        &self,
        mut pool: Vec<SocketAddr>,
        seeds: &HashSet<SocketAddr>,
        connected: &HashSet<SocketAddr>,
    ) -> Vec<SocketAddr> {
        let covered: HashSet<NetGroup> = connected.iter().map(|addr| NetGroup::of(*addr)).collect();
        pool.sort_by_key(|addr| {
            let (rank, lag) = self.probe_rank(*addr);
            (rank == ProbeRank::TurnedAway, covered.contains(&NetGroup::of(*addr)), rank, lag)
        });
        let mut turns: HashMap<Turn, usize> = HashMap::new();
        let mut ranked: Vec<(bool, usize, SocketAddr)> = pool
            .into_iter()
            .map(|addr| {
                let group = NetGroup::of(addr);
                let turn = turns
                    .entry(if seeds.contains(&addr) {
                        Turn::Seed(group)
                    } else {
                        Turn::Gossip(self.learned.get(&addr).and_then(|gossip| gossip.source))
                    })
                    .or_default();
                *turn += 1;
                (covered.contains(&group), *turn, addr)
            })
            .collect();
        // A source of many addresses is likely to have one near the front of `pool`. Its turn
        // must not come early for that.
        ranked.shuffle(&mut rand::rng());
        ranked.sort_by_key(|&(is_covered, turn, addr)| {
            let (rank, lag) = self.probe_rank(addr);
            (rank == ProbeRank::TurnedAway, turn, is_covered, rank, lag)
        });
        ranked.into_iter().map(|(.., addr)| addr).collect()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::test_socket_address;
    use test_case::test_case;

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("a socket address")
    }

    /// A discoverer with `seeds`.
    fn discoverer(seeds: &[&str]) -> PeerDiscoverer {
        let mut discoverer = PeerDiscoverer::new(&ClientConfig::regtest());
        discoverer.set_seeds(seeds.iter().map(|a| addr(a)).collect());
        discoverer
    }

    fn set(addresses: &[&str]) -> HashSet<SocketAddr> {
        addresses.iter().map(|a| addr(a)).collect()
    }

    async fn picks(
        discoverer: &mut PeerDiscoverer,
        count: usize,
        connected: &[&str],
    ) -> Vec<SocketAddr> {
        let connected = set(connected);
        let peers = discoverer.get(count, &connected, &HashSet::new()).await;
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

        // A random batch covers all three groups in 3 of 10 rounds.
        for _ in 0..20 {
            let got = picks(&mut discoverer, 3, &[]).await;

            let groups: HashSet<NetGroup> = got.iter().map(|a| NetGroup::of(*a)).collect();
            assert_eq!(groups.len(), 3, "got {got:?}");
        }
    }

    /// Regtest peers are all loopback, so a single group must still fill the set.
    #[tokio::test]
    async fn a_single_group_fills_the_set() {
        let mut discoverer = discoverer(&["127.0.0.1:1", "127.0.0.1:2", "127.0.0.1:3"]);

        assert_eq!(picks(&mut discoverer, 2, &["127.0.0.1:1"]).await.len(), 2);
    }

    /// A probed address waits its group's turn, but goes first within that turn. One not
    /// returned stays remembered.
    #[tokio::test]
    async fn a_probed_address_keeps_its_priority_within_the_groups() {
        let mut discoverer =
            discoverer(&["68.67.122.2:1", "68.67.122.3:1", "206.245.167.63:1", "206.245.167.64:1"]);
        discoverer.probed(addr("68.67.122.2:1"), 10, false);
        discoverer.probed(addr("206.245.167.64:1"), 50, false);

        let got = picks(&mut discoverer, 1, &["68.67.122.1:1"]).await;
        assert_eq!(got, [addr("206.245.167.64:1")]);
        assert!(discoverer.probed.contains_key(&addr("68.67.122.2:1")));
        assert!(!discoverer.probed.contains_key(&addr("206.245.167.64:1")));

        let got = picks(&mut discoverer, 1, &["206.245.167.63:1"]).await;
        assert_eq!(got, [addr("68.67.122.2:1")]);

        // Of two turned away, one without a ping goes last.
        discoverer.probed(addr("68.67.122.2:1"), 0, true);
        discoverer.probed(addr("68.67.122.3:1"), 2000, true);
        let others = ["206.245.167.63:1", "206.245.167.64:1"];
        let got = picks(&mut discoverer, 2, &others).await;
        assert_eq!(got, [addr("68.67.122.3:1"), addr("68.67.122.2:1")]);
    }

    /// A full probe cache forgets its slowest backup, and an address turned away only once no
    /// backup is left.
    #[test]
    fn a_full_probe_cache_forgets_backups_first() {
        let mut discoverer = discoverer(&[]);
        let backup = |n: usize| SocketAddr::from(([10, 0, 0, n as u8], 1));
        for n in 0..MAX_PROBED {
            discoverer.probed(backup(n), 10 + n as u32, false);
        }
        discoverer.probed(addr("10.1.0.1:1"), 0, true);
        assert!(discoverer.probed.contains_key(&addr("10.1.0.1:1")));
        assert!(!discoverer.probed.contains_key(&backup(MAX_PROBED - 1)));

        for n in 0..MAX_PROBED {
            discoverer.probed(SocketAddr::from(([10, 2, 0, n as u8], 1)), 2000, true);
        }
        assert!(!discoverer.probed.contains_key(&addr("10.1.0.1:1")));
        assert_eq!(discoverer.probed.len(), MAX_PROBED);
    }

    /// Seeds that fill a batch and were turned away for their ping go after every other one,
    /// even one of a connected group.
    #[test_case(&["10.1.0.1:1"], "10.1.0.2:1", false; "untried of the same group")]
    #[test_case(&["10.1.0.1:1", "10.2.0.1:1"], "10.3.0.1:1", false; "untried of another group")]
    #[test_case(&["10.1.0.1:1"], "68.67.122.2:1", false; "untried of a connected group")]
    #[test_case(&["10.1.0.1:1"], "68.67.122.2:1", true; "backup of a connected group")]
    #[tokio::test]
    async fn seeds_turned_away_go_last(turned_away: &[&str], other: &str, is_backup: bool) {
        let mut discoverer = discoverer(&[turned_away, &[other]].concat());
        for seed in turned_away {
            discoverer.probed(addr(seed), 2000, true);
        }
        if is_backup {
            discoverer.probed(addr(other), 20, false);
        }

        let count = turned_away.len() + 1;
        let got = picks(&mut discoverer, count, &["68.67.122.1:1"]).await;
        assert_eq!((got[0], got.len()), (addr(other), count));
    }

    /// Addresses of many groups gossiped by one seed, or by peers it gossiped, share one turn.
    /// So do those of peers of unknown origin.
    #[test_case(&["206.245.167.63:1"], 1; "one seed")]
    #[test_case(&["206.245.167.63:1", "100.0.0.1:1"], 1; "a seed and a peer it gossiped")]
    #[test_case(&["206.245.167.63:1", "68.67.122.1:1"], 2; "a seed and another it gossiped")]
    #[test_case(&["9.9.9.9:1", "8.8.8.8:1"], 1; "unknown peers")]
    #[tokio::test]
    async fn gossip_shares_the_turn_of_its_source(from: &[&str], sources: usize) {
        let seeds = ["68.67.122.1:1", "68.67.122.2:1", "206.245.167.63:1", "206.245.167.64:1"];
        let mut discoverer = discoverer(&seeds);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("after epoch").as_secs();
        for (n, from) in from.iter().enumerate() {
            let gossip = (0..30)
                .map(|group| SocketAddr::from(([100 + n as u8, group, 0, 1], 1)))
                .chain([addr(seeds[0])]);
            discoverer.learn(addr(from), gossip.map(|addr| (addr, now as u32)));
        }

        let seeds = set(&seeds);
        // Not even with a peer of every seed group connected does gossip get more.
        for connected in [&[][..], &["68.67.122.9:1", "206.245.167.9:1"]] {
            for _ in 0..20 {
                let got = picks(&mut discoverer, 2 + sources, connected).await;
                let gossiped = got.iter().filter(|addr| !seeds.contains(addr)).count();
                assert_eq!(gossiped, sources, "got {got:?}");
            }
        }
        // Nor does its turn come first because it has more addresses than a seed group.
        let mut first = 0;
        for _ in 0..200 {
            let got = picks(&mut discoverer, 1, &[]).await;
            first += usize::from(!seeds.contains(&got[0]));
        }
        let due = 200 * sources / (2 + sources);
        assert!((due - 50..due + 50).contains(&first), "{first} of 200, due {due}");
    }

    /// Of the addresses gossiped by one source, those of groups without a connected peer go
    /// first, even past faster ones of a connected group.
    #[tokio::test]
    async fn gossip_of_a_new_group_goes_first_within_its_source() {
        let seed = "206.245.167.63:1";
        let mut discoverer = discoverer(&[seed]);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("after epoch").as_secs();
        let gossip = ["100.0.0.1:1", "100.0.0.2:1", "100.0.0.3:1", "101.0.0.1:1"].map(addr);
        discoverer.learn(addr(seed), gossip.iter().map(|addr| (*addr, now as u32)));
        for (n, addr) in gossip.iter().enumerate() {
            discoverer.probed(*addr, 10 + n as u32, false);
        }

        let got = picks(&mut discoverer, 1, &[seed, "100.0.0.9:1"]).await;
        assert_eq!(got, [addr("101.0.0.1:1")]);
    }

    #[tokio::test]
    async fn skips_connected_and_banned_addresses() {
        let mut discoverer = discoverer(&["68.67.122.1:1", "206.245.167.63:1", "85.209.243.1:1"]);

        let got = discoverer.get(3, &set(&["68.67.122.1:1"]), &set(&["206.245.167.63:1"])).await;

        let got: Vec<SocketAddr> = got.iter().map(|p| p.addr()).collect();
        assert_eq!(got, [addr("85.209.243.1:1")]);
    }

    /// Configured peers are dialed whatever their groups, even one of a connected group first.
    #[tokio::test]
    async fn exclusive_peers_are_not_grouped() {
        let mut config = ClientConfig::regtest();
        config.peers = vec![addr("68.67.122.1:1"), addr("68.67.122.2:1"), addr("206.245.167.63:1")];
        let mut discoverer = PeerDiscoverer::new(&config);
        discoverer.probed(addr("206.245.167.63:1"), 10, false);

        let got = picks(&mut discoverer, 1, &["206.245.167.64:1"]).await;
        assert_eq!(got, [addr("206.245.167.63:1")]);
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

    /// Skipped addresses are left out before sampling, so the one eligible address in a
    /// mostly banned pool is still handed out, once even if configured twice. A skipped
    /// probed peer keeps its rank.
    #[tokio::test]
    async fn get_samples_only_addresses_not_skipped() {
        let mut config = ClientConfig::regtest();
        let addrs: Vec<SocketAddr> = (1..=10).map(test_socket_address).collect();
        for addr in &addrs {
            config.add_peer(*addr);
        }
        config.add_peer(addrs[0]);
        let mut discoverer = PeerDiscoverer::new(&config);
        let (eligible, skip) = (addrs[0], addrs[1..].iter().copied().collect());

        for _ in 0..20 {
            let got: Vec<SocketAddr> =
                discoverer.get(3, &HashSet::new(), &skip).await.iter().map(|p| p.addr()).collect();
            assert_eq!(got, [eligible]);
        }

        discoverer.probed(addrs[1], 10, false);
        discoverer.probed(addrs[2], 20, false);
        let got = discoverer.get(1, &HashSet::new(), &HashSet::from([addrs[1]])).await;
        assert_eq!(got.iter().map(|p| p.addr()).collect::<Vec<_>>(), [addrs[2]]);
        let got = discoverer.get(1, &HashSet::new(), &HashSet::new()).await;
        assert_eq!(got.iter().map(|p| p.addr()).collect::<Vec<_>>(), [addrs[1]]);
    }

    #[tokio::test]
    async fn test_dns_discovery_regtest() {
        let peers = PeerDiscoverer::discover(Network::Regtest).await;

        // Should return empty for regtest (no DNS seeds and no embedded list)
        assert!(peers.is_empty());
    }
}
