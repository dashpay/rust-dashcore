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

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use dashcore::Network;
use rand::seq::{IndexedRandom, SliceRandom};

use crate::network::peer::DisconnectedPeer;
use crate::ClientConfig;

const DNS_LOOKUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const MAX_LEARNED: usize = 2000;
const MAX_ADDR_AGE: u32 = 7 * 24 * 60 * 60;
const MAX_ADDR_FUTURE: u32 = 10 * 60;
const MAX_PROBED: usize = 32;

pub struct PeerDiscoverer {
    network: Network,
    // Empty means "discover" from the compiled-in seeds, then DNS.
    fixed: Vec<SocketAddr>,
    restrict_to_configured_peers: bool,
    /// Resolved once and kept. Not consumed as handed out: the reconnector comes back
    /// on every drop, and a drained pool would leave the client nothing to reconnect to.
    discovered: Option<Vec<SocketAddr>>,
    learned: HashMap<SocketAddr, u32>,
    /// Handshake ping of peers probed but not kept, tried first next time.
    probed: HashMap<SocketAddr, u32>,
}

impl PeerDiscoverer {
    pub fn new(config: &ClientConfig) -> PeerDiscoverer {
        let mut fixed = config.peers.clone();
        fixed.sort();
        fixed.dedup();
        PeerDiscoverer {
            network: config.network,
            fixed,
            restrict_to_configured_peers: config.restrict_to_configured_peers,
            discovered: None,
            learned: HashMap::new(),
            probed: HashMap::new(),
        }
    }

    pub fn learn(&mut self, addresses: impl IntoIterator<Item = (SocketAddr, u32)>) -> usize {
        if !self.fixed.is_empty() || self.restrict_to_configured_peers {
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

    /// Up to `count` distinct addresses to try, none of them in `skip`: the best probed
    /// first, then a random sample. `skip` is applied before sampling, so excluded
    /// addresses never take a slot an eligible one could have had.
    pub async fn get(&mut self, count: usize, skip: &HashSet<SocketAddr>) -> Vec<DisconnectedPeer> {
        let mut best: Vec<(SocketAddr, u32)> = self
            .probed
            .iter()
            .filter(|(addr, _)| !skip.contains(addr))
            .map(|(addr, lag)| (*addr, *lag))
            .collect();
        best.sort_by_key(|(_, lag)| *lag);
        best.truncate(count);
        for (addr, _) in &best {
            self.probed.remove(addr);
        }
        let mut out: Vec<DisconnectedPeer> =
            best.into_iter().map(|(addr, _)| DisconnectedPeer::new(addr, self.network)).collect();
        let count = count - out.len();

        let pool = if !self.fixed.is_empty() {
            self.fixed.clone()
        } else if self.restrict_to_configured_peers {
            return Vec::new();
        } else {
            if self.discovered.is_none() {
                let found = Self::discover(self.network).await;
                self.discovered = Some(found);
            }
            let mut pool = self.discovered.clone().expect("just set");
            pool.extend(self.learned.keys());
            pool.sort();
            pool.dedup();
            pool
        };

        let taken: HashSet<SocketAddr> = out.iter().map(|p| p.addr()).collect();
        let pool: Vec<SocketAddr> =
            pool.into_iter().filter(|addr| !skip.contains(addr) && !taken.contains(addr)).collect();
        out.extend(
            pool.choose_multiple(&mut rand::rng(), count)
                .map(|addr| DisconnectedPeer::new(*addr, self.network)),
        );
        out
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
                discoverer.get(3, &skip).await.iter().map(|p| p.addr()).collect();
            assert_eq!(got, [eligible]);
        }

        discoverer.probed(addrs[1], 10);
        discoverer.probed(addrs[2], 20);
        let got = discoverer.get(1, &HashSet::from([addrs[1]])).await;
        assert_eq!(got.iter().map(|p| p.addr()).collect::<Vec<_>>(), [addrs[2]]);
        let got = discoverer.get(1, &HashSet::new()).await;
        assert_eq!(got.iter().map(|p| p.addr()).collect::<Vec<_>>(), [addrs[1]]);
    }

    #[tokio::test]
    async fn test_dns_discovery_regtest() {
        let peers = PeerDiscoverer::discover(Network::Regtest).await;

        // Should return empty for regtest (no DNS seeds and no embedded list)
        assert!(peers.is_empty());
    }
}
