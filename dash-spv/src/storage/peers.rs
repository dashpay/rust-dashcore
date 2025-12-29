use std::{
    fs::{self, File},
    io::BufReader,
    path::PathBuf,
};

use async_trait::async_trait;
use dashcore::{
    consensus::{encode, Decodable, Encodable},
    network::address::AddrV2Message,
};

use crate::{
    error::StorageResult,
    storage::{io::atomic_write, PersistentStorage},
    StorageError,
};

#[async_trait]
pub trait PeerStorage {
    async fn save_peers(
        &self,
        peers: &[dashcore::network::address::AddrV2Message],
    ) -> StorageResult<()>;

    async fn load_peers(&self) -> StorageResult<Vec<std::net::SocketAddr>>;
}

pub struct PersistentPeerStorage {
    storage_path: PathBuf,
}

impl PersistentPeerStorage {
    const FOLDER_NAME: &str = "peers";
}

#[async_trait]
impl PersistentStorage for PersistentPeerStorage {
    async fn open(storage_path: impl Into<PathBuf> + Send) -> StorageResult<Self> {
        Ok(PersistentPeerStorage {
            storage_path: storage_path.into().join(Self::FOLDER_NAME),
        })
    }

    async fn persist(&mut self, _storage_path: impl Into<PathBuf> + Send) -> StorageResult<()> {
        // Current implementation persists data everytime data is stored
        Ok(())
    }
}

#[async_trait]
impl PeerStorage for PersistentPeerStorage {
    async fn save_peers(
        &self,
        peers: &[dashcore::network::address::AddrV2Message],
    ) -> StorageResult<()> {
        let peers_file = self.storage_path.join("peers.dat");

        if let Err(e) = fs::create_dir_all(peers_file.parent().unwrap()) {
            return Err(StorageError::WriteFailed(format!("Failed to persist peers: {}", e)));
        }

        let mut buffer = Vec::new();

        for item in peers.iter() {
            item.consensus_encode(&mut buffer)
                .map_err(|e| StorageError::WriteFailed(format!("Failed to encode peer: {}", e)))?;
        }

        atomic_write(&peers_file, &buffer).await?;

        Ok(())
    }

    async fn load_peers(&self) -> StorageResult<Vec<std::net::SocketAddr>> {
        let peers_file = self.storage_path.join("peers.dat");

        let peers = if peers_file.exists() {
            let file = File::open(&peers_file)?;
            let mut reader = BufReader::new(file);
            let mut peers = Vec::new();

            loop {
                match AddrV2Message::consensus_decode(&mut reader) {
                    Ok(peer) => peers.push(peer),
                    Err(encode::Error::Io(ref e))
                        if e.kind() == std::io::ErrorKind::UnexpectedEof =>
                    {
                        break
                    }
                    Err(e) => {
                        return Err(StorageError::ReadFailed(format!("Failed to decode peer: {e}")))
                    }
                }
            }

            peers
        } else {
            Vec::new()
        };

        let peers = peers.into_iter().filter_map(|p| p.socket_addr().ok()).collect();

        Ok(peers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::network::address::{AddrV2, AddrV2Message};
    use dashcore::network::constants::ServiceFlags;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_persistent_peer_storage_save_load() {
        let temp_dir = TempDir::new().expect("Failed to create temporary directory for test");
        let store = PersistentPeerStorage::open(temp_dir.path())
            .await
            .expect("Failed to open persistent peer storage");

        // Create test peer messages
        let addr: std::net::SocketAddr =
            "192.168.1.1:9999".parse().expect("Failed to parse test address");
        let msg = AddrV2Message {
            time: 1234567890,
            services: ServiceFlags::from(1),
            addr: AddrV2::Ipv4(
                addr.ip().to_string().parse().expect("Failed to parse IPv4 address"),
            ),
            port: addr.port(),
        };

        store.save_peers(&[msg]).await.expect("Failed to save peers in test");

        let loaded = store.load_peers().await.expect("Failed to load peers in test");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0], addr);
    }

    #[tokio::test]
    async fn test_persistent_peer_storage_empty() {
        let temp_dir = TempDir::new().expect("Failed to create temporary directory for test");
        let store = PersistentPeerStorage::open(temp_dir.path())
            .await
            .expect("Failed to open persistent peer storage");

        // Load from non-existent file
        let loaded = store.load_peers().await.expect("Failed to load peers from empty store");
        assert!(loaded.is_empty());
    }
}
