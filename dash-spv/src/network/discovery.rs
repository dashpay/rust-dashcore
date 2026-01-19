//! DNS-based peer discovery for Dash network

use dashcore::Network;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioResolver;
use std::net::{IpAddr, SocketAddr};

use crate::network::constants::{MAINNET_DNS_SEEDS, TESTNET_DNS_SEEDS};

/// DNS discovery for finding initial peers
pub struct DnsDiscovery {
    resolver: TokioResolver,
}

impl DnsDiscovery {
    /// Create a new DNS discovery instance
    pub async fn new() -> Result<Self, crate::Error> {
        let resolver = hickory_resolver::Resolver::builder_with_config(
            ResolverConfig::default(),
            TokioConnectionProvider::default(),
        )
        .with_options(ResolverOpts::default())
        .build();

        Ok(Self {
            resolver,
        })
    }

    /// Discover peers for the given network
    pub async fn discover_peers(&self, network: Network) -> Vec<SocketAddr> {
        let (seeds, port) = match network {
            Network::Dash => (MAINNET_DNS_SEEDS, 9999),
            Network::Testnet => (TESTNET_DNS_SEEDS, 19999),
            _ => {
                log::debug!("No DNS seeds for {:?} network", network);
                return vec![];
            }
        };

        let mut addresses = Vec::new();

        for seed in seeds {
            log::debug!("Querying DNS seed: {}", seed);

            match self.resolver.lookup_ip(*seed).await {
                Ok(lookup) => {
                    let ips: Vec<IpAddr> = lookup.iter().collect();
                    log::info!("DNS seed {} returned {} addresses", seed, ips.len());

                    for ip in ips {
                        addresses.push(SocketAddr::new(ip, port));
                    }
                }
                Err(e) => {
                    log::warn!("Failed to resolve DNS seed {}: {}", seed, e);
                }
            }
        }

        // Deduplicate addresses
        addresses.sort();
        addresses.dedup();

        log::info!("Discovered {} unique peer addresses from DNS seeds", addresses.len());
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
        let discovery = DnsDiscovery::new().await.expect("Failed to create DNS discovery for test");
        let peers = discovery.discover_peers(Network::Dash).await;

        // Print discovered peers for debugging
        println!("Discovered {} mainnet peers:", peers.len());
        for peer in &peers {
            println!("  {}", peer);
        }

        // Should find at least some peers
        assert!(!peers.is_empty());

        // All peers should use the correct port
        for peer in &peers {
            assert_eq!(peer.port(), 9999);
        }
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_dns_discovery_testnet() {
        let discovery = DnsDiscovery::new().await.expect("Failed to create DNS discovery for test");
        let peers = discovery.discover_peers(Network::Testnet).await;

        // Print discovered peers for debugging
        println!("Discovered {} testnet peers:", peers.len());
        for peer in &peers {
            println!("  {}", peer);
        }

        // Should find at least some peers
        assert!(!peers.is_empty());

        // All peers should use the correct port
        for peer in &peers {
            assert_eq!(peer.port(), 19999);
        }
    }

    #[tokio::test]
    async fn test_dns_discovery_regtest() {
        let discovery = DnsDiscovery::new().await.expect("Failed to create DNS discovery for test");
        let peers = discovery.discover_peers(Network::Regtest).await;

        // Should return empty for regtest (no DNS seeds)
        assert!(peers.is_empty());
    }
}
