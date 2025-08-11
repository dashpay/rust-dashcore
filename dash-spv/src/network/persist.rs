//! Peer persistence for saving and loading known peers

use dashcore::Network;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::error::{SpvError as Error, StorageError};

/// Peer persistence for saving and loading known peer addresses
pub struct PeerStore {
    network: Network,
    path: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct SavedPeers {
    version: u32,
    network: String,
    peers: Vec<SavedPeer>,
}

#[derive(Serialize, Deserialize)]
struct SavedPeer {
    address: String,
    services: u64,
    last_seen: u64,
}

impl PeerStore {
    /// Create a new peer store for the given network
    pub fn new(network: Network, data_dir: PathBuf) -> Self {
        let filename = format!("peers_{}.json", network);
        let path = data_dir.join(filename);

        Self {
            network,
            path,
        }
    }

    /// Save peers to disk
    pub async fn save_peers(
        &self,
        peers: &[dashcore::network::address::AddrV2Message],
    ) -> Result<(), Error> {
        let saved = SavedPeers {
            version: 1,
            network: format!("{:?}", self.network),
            peers: peers
                .iter()
                .filter_map(|p| {
                    p.socket_addr().ok().map(|addr| SavedPeer {
                        address: addr.to_string(),
                        services: p.services.as_u64(),
                        last_seen: p.time as u64,
                    })
                })
                .collect(),
        };

        let json = serde_json::to_string_pretty(&saved)
            .map_err(|e| Error::Storage(StorageError::Serialization(e.to_string())))?;

        tokio::fs::write(&self.path, json)
            .await
            .map_err(|e| Error::Storage(StorageError::WriteFailed(e.to_string())))?;

        log::debug!("Saved {} peers to {:?}", saved.peers.len(), self.path);
        Ok(())
    }

    /// Load peers from disk
    pub async fn load_peers(&self) -> Result<Vec<std::net::SocketAddr>, Error> {
        match tokio::fs::read_to_string(&self.path).await {
            Ok(json) => {
                let saved: SavedPeers = serde_json::from_str(&json).map_err(|e| {
                    Error::Storage(StorageError::Corruption(format!(
                        "Failed to parse peers file: {}",
                        e
                    )))
                })?;

                // Verify network matches
                if saved.network != format!("{:?}", self.network) {
                    return Err(Error::Storage(StorageError::Corruption(format!(
                        "Peers file is for network {} but we are on {:?}",
                        saved.network, self.network
                    ))));
                }

                let addresses: Vec<_> =
                    saved.peers.iter().filter_map(|p| p.address.parse().ok()).collect();

                log::info!("Loaded {} peers from {:?}", addresses.len(), self.path);
                Ok(addresses)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                log::debug!("No saved peers file found at {:?}", self.path);
                Ok(vec![])
            }
            Err(e) => Err(Error::Storage(StorageError::ReadFailed(e.to_string()))),
        }
    }

    /// Delete the peers file
    pub async fn clear(&self) -> Result<(), Error> {
        match tokio::fs::remove_file(&self.path).await {
            Ok(_) => {
                log::info!("Cleared peer store at {:?}", self.path);
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::Storage(StorageError::WriteFailed(e.to_string()))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::network::address::{AddrV2, AddrV2Message};
    use dashcore::network::constants::ServiceFlags;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_peer_store_save_load() {
        let temp_dir = TempDir::new().expect("Failed to create temporary directory for test");
        let store = PeerStore::new(Network::Dash, temp_dir.path().to_path_buf());

        // Create test peer messages
        let addr: std::net::SocketAddr = "192.168.1.1:9999".parse().expect("Failed to parse test address");
        let msg = AddrV2Message {
            time: 1234567890,
            services: ServiceFlags::from(1),
            addr: AddrV2::Ipv4(addr.ip().to_string().parse().expect("Failed to parse IPv4 address")),
            port: addr.port(),
        };

        // Save peers
        store.save_peers(&[msg]).await.expect("Failed to save peers in test");

        // Load peers
        let loaded = store.load_peers().await.expect("Failed to load peers in test");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0], addr);
    }

    #[tokio::test]
    async fn test_peer_store_empty() {
        let temp_dir = TempDir::new().expect("Failed to create temporary directory for test");
        let store = PeerStore::new(Network::Testnet, temp_dir.path().to_path_buf());

        // Load from non-existent file
        let loaded = store.load_peers().await.expect("Failed to load peers from empty store");
        assert!(loaded.is_empty());
    }
}
