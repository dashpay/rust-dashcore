use std::net::SocketAddr;

use dashcore::Network;
use rand::seq::SliceRandom;

use crate::network::peer::DisconnectedPeer;
use crate::ClientConfig;

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
            match tokio::net::lookup_host((*seed, port)).await {
                Ok(iter) => {
                    let resolved: Vec<SocketAddr> = iter.collect();
                    tracing::info!("DNS seed {} returned {} addresses", seed, resolved.len());
                    addresses.extend(resolved);
                }
                Err(e) => {
                    tracing::warn!("Failed to resolve DNS seed {} (backup source): {}", seed, e);
                }
            }
        }

        addresses.sort();
        addresses.dedup();

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
