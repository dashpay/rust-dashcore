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
//! Results from both sources are merged and deduplicated.

use dashcore::Network;
use std::net::SocketAddr;

/// DNS discovery for finding initial peers.
///
/// Despite the name (kept for backwards compatibility), this type also returns
/// hardcoded masternode seeds embedded at compile time; DNS is used as a
/// fallback.
#[derive(Default)]
pub struct DnsDiscovery {}

impl DnsDiscovery {
    /// Create a new DNS discovery instance
    pub fn new() -> Self {
        Self {}
    }

    /// Discover peers for the given network.
    ///
    /// Returns the union of the embedded hardcoded masternode seeds and any
    /// addresses resolved via DNS. DNS resolution failures are logged at warn
    /// level but do not cause this function to fail — the embedded list acts
    /// as the primary source and DNS is a best-effort backup.
    pub async fn discover_peers(&self, network: Network) -> Vec<SocketAddr> {
        let seeds = network.dns_seeds();
        let port = network.default_p2p_port();
        let mut addresses = dash_network_seeds::addresses(network);

        let embedded_count = addresses.len();
        tracing::info!("Loaded {} hardcoded masternode seed(s) for {:?}", embedded_count, network);

        for seed in seeds {
            tracing::debug!("Querying DNS seed: {}", seed);

            match tokio::net::lookup_host((*seed, port)).await {
                Ok(iter) => {
                    let resolved: Vec<SocketAddr> = iter.collect();
                    tracing::info!("DNS seed {} returned {} addresses", seed, resolved.len());
                    addresses.extend(resolved);
                }
                Err(e) => {
                    // DNS is a best-effort backup; do not propagate the error.
                    tracing::warn!("Failed to resolve DNS seed {} (backup source): {}", seed, e);
                }
            }
        }

        addresses.sort();
        addresses.dedup();

        tracing::info!(
            "Discovered {} unique peer addresses for {:?} ({} from embedded seeds + DNS)",
            addresses.len(),
            network,
            embedded_count
        );
        addresses
    }

    /// Discover peers with a limit on the number returned
    pub async fn discover_peers_limited(&self, network: Network, limit: usize) -> Vec<SocketAddr> {
        let mut peers = self.discover_peers(network).await;
        peers.truncate(limit);
        peers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_dns_discovery_mainnet() {
        let discovery = DnsDiscovery::new();
        let peers = discovery.discover_peers(Network::Mainnet).await;

        // Print discovered peers for debugging
        println!("Discovered {} mainnet peers:", peers.len());
        for peer in &peers {
            println!("  {}", peer);
        }

        // All peers should use the correct port
        for peer in &peers {
            assert_eq!(peer.port(), Network::Mainnet.default_p2p_port());
        }
    }

    #[tokio::test]
    async fn test_dns_discovery_testnet_returns_embedded_when_dns_fails() {
        // This test does not require network access: even if DNS resolution
        // fails, the embedded seed file must yield peers.
        let discovery = DnsDiscovery::new();
        let peers = discovery.discover_peers(Network::Testnet).await;

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
        let discovery = DnsDiscovery::new();
        let peers = discovery.discover_peers(Network::Regtest).await;

        // Should return empty for regtest (no DNS seeds and no embedded list)
        assert!(peers.is_empty());
    }
}
