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

use std::net::SocketAddr;

use dashcore::Network;
use rand::seq::SliceRandom;

use crate::network::peer::DisconnectedPeer;
use crate::ClientConfig;

const DNS_LOOKUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub struct PeerDiscoverer {
    network: Network,
    // Empty means "discover" from the compiled-in seeds, then DNS.
    fixed: Vec<SocketAddr>,
    restrict_to_configured_peers: bool,
    /// Discovered addresses, resolved once and then kept.
    ///
    /// Deliberately not consumed as it is handed out: the reconnector comes back here
    /// every time the peer set drops, and a pool that drained itself would leave a client
    /// with one known peer unable to reconnect after its second disconnect.
    discovered: Option<Vec<SocketAddr>>,
}

impl PeerDiscoverer {
    pub fn new(config: &ClientConfig) -> PeerDiscoverer {
        PeerDiscoverer {
            network: config.network,
            fixed: config.peers.clone(),
            restrict_to_configured_peers: config.restrict_to_configured_peers,
            discovered: None,
        }
    }

    /// Fold addresses learned from a connected peer (`addr`/`addrv2` gossip) into
    /// the pool.
    ///
    /// Without this the pool is whatever the seeds and one DNS lookup produced at
    /// startup and never grows, so a client whose known addresses all go stale has
    /// nothing left to try. Ignored when the client was pinned to configured peers:
    /// there, "these peers and no others" is the point.
    ///
    /// Returns how many were new, so the caller can wake the supervisor only when
    /// there is genuinely something fresh to connect to.
    pub fn learn(&mut self, addresses: impl IntoIterator<Item = SocketAddr>) -> usize {
        if !self.fixed.is_empty() || self.restrict_to_configured_peers {
            return 0;
        }
        // Only extend a pool that exists: before the first `get` there is nothing
        // to add to, and discovery will run anyway.
        let Some(pool) = self.discovered.as_mut() else {
            return 0;
        };
        let known: std::collections::HashSet<SocketAddr> = pool.iter().copied().collect();
        let fresh: Vec<SocketAddr> = addresses.into_iter().filter(|a| !known.contains(a)).collect();
        // Dedup within the batch too — one `addrv2` can repeat an address.
        let mut seen = std::collections::HashSet::new();
        let mut added = 0;
        for addr in fresh {
            if seen.insert(addr) {
                pool.push(addr);
                added += 1;
            }
        }
        added
    }

    /// Up to `count` addresses to try, sampled at random from whatever source applies.
    pub async fn get(&mut self, count: usize) -> Vec<DisconnectedPeer> {
        let pool = if !self.fixed.is_empty() {
            &self.fixed
        } else if self.restrict_to_configured_peers {
            return Vec::new();
        } else {
            if self.discovered.is_none() {
                let found = Self::discover(self.network).await;
                self.discovered = Some(found);
            }
            self.discovered.as_ref().expect("just set")
        };

        pool.choose_multiple(&mut rand::thread_rng(), count)
            .map(|addr| DisconnectedPeer::new(*addr, self.network))
            .collect()
    }

    /// Addresses to try: the compiled-in seeds, then DNS
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
        addresses.shuffle(&mut rand::thread_rng());

        addresses
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
