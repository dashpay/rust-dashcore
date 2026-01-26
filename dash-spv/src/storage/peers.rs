use std::{collections::HashMap, fs::File, io::BufReader, net::SocketAddr, path::PathBuf};

use tokio::fs;

use async_trait::async_trait;
use dashcore::{
    consensus::{encode, Decodable, Encodable},
    network::address::AddrV2Message,
};

use crate::{
    error::StorageResult,
    network::PeerReputation,
    storage::{io::atomic_write, PersistentStorage},
    StorageError,
};

#[async_trait]
pub trait PeerStorage {
    async fn save_peers(
        &self,
        peers: &[dashcore::network::address::AddrV2Message],
    ) -> StorageResult<()>;

    async fn load_peers(&self) -> StorageResult<Vec<SocketAddr>>;

    async fn save_peers_reputation(
        &self,
        reputations: &HashMap<SocketAddr, PeerReputation>,
    ) -> StorageResult<()>;

    async fn load_peers_reputation(&self) -> StorageResult<HashMap<SocketAddr, PeerReputation>>;
}

pub struct PersistentPeerStorage {
    storage_path: PathBuf,
}

impl PersistentPeerStorage {
    const FOLDER_NAME: &str = "peers";

    fn peers_data_file(&self) -> PathBuf {
        self.storage_path.join("peers.dat")
    }

    fn peers_reputation_file(&self) -> PathBuf {
        self.storage_path.join("reputations.json")
    }
}

#[async_trait]
impl PersistentStorage for PersistentPeerStorage {
    async fn open(storage_path: impl Into<PathBuf> + Send) -> StorageResult<Self> {
        let storage_path = storage_path.into();

        Ok(PersistentPeerStorage {
            storage_path: storage_path.join(Self::FOLDER_NAME),
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
        let peers_file = self.peers_data_file();

        let mut buffer = Vec::new();

        for item in peers.iter() {
            item.consensus_encode(&mut buffer)
                .map_err(|e| StorageError::WriteFailed(format!("Failed to encode peer: {}", e)))?;
        }

        let peers_file_parent = peers_file
            .parent()
            .ok_or(StorageError::NotFound("peers_file doesn't have a parent".to_string()))?;

        tokio::fs::create_dir_all(peers_file_parent).await?;

        atomic_write(&peers_file, &buffer).await?;

        Ok(())
    }

    async fn load_peers(&self) -> StorageResult<Vec<SocketAddr>> {
        let peers_file = self.peers_data_file();

        if !fs::try_exists(&peers_file).await? {
            return Ok(Vec::new());
        };

        let peers = tokio::task::spawn_blocking(move || {
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
            Ok(peers)
        })
        .await
        .map_err(|e| StorageError::ReadFailed(format!("Failed to load peers: {e}")))??;

        let peers = peers.into_iter().filter_map(|p| p.socket_addr().ok()).collect();

        Ok(peers)
    }

    async fn save_peers_reputation(
        &self,
        reputations: &HashMap<SocketAddr, PeerReputation>,
    ) -> StorageResult<()> {
        let reputation_file = self.peers_reputation_file();

        let json = serde_json::to_string_pretty(reputations).map_err(|e| {
            StorageError::Serialization(format!("Failed to serialize peers reputations: {e}"))
        })?;

        let reputation_file_parent = reputation_file
            .parent()
            .ok_or(StorageError::NotFound("reputation_file doesn't have a parent".to_string()))?;

        fs::create_dir_all(reputation_file_parent).await?;

        atomic_write(&reputation_file, json.as_bytes()).await
    }

    async fn load_peers_reputation(&self) -> StorageResult<HashMap<SocketAddr, PeerReputation>> {
        let reputation_file = self.peers_reputation_file();

        if !fs::try_exists(&reputation_file).await? {
            return Ok(HashMap::new());
        }

        let json = fs::read_to_string(reputation_file).await?;
        serde_json::from_str(&json).map_err(|e| {
            StorageError::ReadFailed(format!("Failed to deserialize peers reputations: {e}"))
        })
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
