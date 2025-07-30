//! Integration tests for ChainLock validation flow with masternode engine

use dash_spv::client::{ClientConfig, DashSpvClient};
use dash_spv::error::Result;
use dash_spv::network::NetworkManager;
use dash_spv::storage::{DiskStorageManager, StorageManager};
use dash_spv::types::{ChainState, ValidationMode};
use dashcore::block::Header;
use dashcore::blockdata::constants::genesis_block;
use dashcore::network::Network;
use dashcore::sml::masternode_list_engine::MasternodeListEngine;
use dashcore::{BlockHash, ChainLock, UInt256};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::RwLock;
use tracing::{info, Level};

/// Mock network manager that simulates ChainLock messages
struct MockNetworkManager {
    chain_locks: Vec<ChainLock>,
    chain_locks_sent: Arc<RwLock<usize>>,
}

impl MockNetworkManager {
    fn new() -> Self {
        Self {
            chain_locks: Vec::new(),
            chain_locks_sent: Arc::new(RwLock::new(0)),
        }
    }

    fn add_chain_lock(&mut self, chain_lock: ChainLock) {
        self.chain_locks.push(chain_lock);
    }
}

#[async_trait::async_trait]
impl NetworkManager for MockNetworkManager {
    fn network(&self) -> Network {
        Network::Dash
    }

    async fn connect(&mut self) -> Result<()> {
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        Ok(())
    }

    async fn send_message(
        &mut self,
        _message: dashcore::network::message::NetworkMessage,
    ) -> Result<()> {
        Ok(())
    }

    async fn receive_message(&mut self) -> Result<dashcore::network::message::NetworkMessage> {
        // Simulate receiving ChainLock messages
        let mut sent = self.chain_locks_sent.write().await;
        if *sent < self.chain_locks.len() {
            let chain_lock = self.chain_locks[*sent].clone();
            *sent += 1;
            Ok(dashcore::network::message::NetworkMessage::CLSig(chain_lock))
        } else {
            // No more messages, wait forever
            tokio::time::sleep(Duration::from_secs(3600)).await;
            unreachable!()
        }
    }

    async fn broadcast_transaction(
        &mut self,
        _tx: dashcore::Transaction,
    ) -> Result<dashcore::Txid> {
        unimplemented!()
    }

    async fn fetch_headers(&mut self, _start_height: u32, _count: u32) -> Result<Vec<Header>> {
        Ok(Vec::new())
    }

    async fn is_connected(&self) -> bool {
        true
    }

    async fn get_peer_info(&self) -> Result<dash_spv::network::PeerInfo> {
        Ok(dash_spv::network::PeerInfo {
            peer_id: 1,
            address: "127.0.0.1:9999".parse().unwrap(),
            services: dashcore::ServiceFlags::NONE,
            user_agent: "/MockNode/".to_string(),
            start_height: 0,
            relay: true,
            last_send: std::time::Instant::now(),
            last_recv: std::time::Instant::now(),
            ping_time: Duration::from_millis(10),
            protocol_version: 70232,
        })
    }

    async fn handle_ping(&mut self, _nonce: u64) -> Result<()> {
        Ok(())
    }

    fn handle_pong(&mut self, _nonce: u64) -> Result<()> {
        Ok(())
    }

    async fn update_peer_dsq_preference(&mut self, _wants_dsq: bool) -> Result<()> {
        Ok(())
    }

    async fn mark_peer_sent_headers2(&mut self) -> Result<()> {
        Ok(())
    }
}

fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .with_target(false)
        .with_thread_ids(true)
        .with_line_number(true)
        .try_init();
}

/// Create a test ChainLock with minimal valid data
fn create_test_chainlock(height: u32, block_hash: BlockHash) -> ChainLock {
    ChainLock {
        block_height: height,
        block_hash,
        signature: vec![0; 96], // BLS signature placeholder
    }
}

#[tokio::test]
async fn test_chainlock_validation_without_masternode_engine() {
    init_logging();

    // Create temp directory for storage
    let temp_dir = TempDir::new().unwrap();
    let storage_path = temp_dir.path().to_path_buf();

    // Create storage and network managers
    let storage = Box::new(DiskStorageManager::new(storage_path).unwrap());
    let network = Box::new(MockNetworkManager::new());

    // Create client config
    let config = ClientConfig {
        network: Network::Dash,
        enable_filters: false,
        enable_masternodes: false,
        validation_mode: ValidationMode::Basic,
        ..Default::default()
    };

    // Create the SPV client
    let mut client = DashSpvClient::new(config, storage, network).await.unwrap();

    // Add a test header to storage
    let genesis = genesis_block(Network::Dash).header;
    let storage = client.storage_mut();
    storage.store_header(&genesis, 0).await.unwrap();

    // Create a test ChainLock for genesis block
    let chain_lock = create_test_chainlock(0, genesis.block_hash());

    // Process the ChainLock (should queue it since no masternode engine)
    let chainlock_manager = client.chainlock_manager();
    let chain_state = ChainState::new(Network::Dash);
    let result =
        chainlock_manager.process_chain_lock(chain_lock.clone(), &chain_state, storage).await;

    // Should succeed but queue for later validation
    assert!(result.is_ok());

    // Verify it was queued
    let pending = chainlock_manager.pending_chainlocks.read().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].block_height, 0);
}

#[tokio::test]
async fn test_chainlock_validation_with_masternode_engine() {
    init_logging();

    // Create temp directory for storage
    let temp_dir = TempDir::new().unwrap();
    let storage_path = temp_dir.path().to_path_buf();

    // Create storage and network managers
    let storage = Box::new(DiskStorageManager::new(storage_path).unwrap());
    let mut network = Box::new(MockNetworkManager::new());

    // Add a test ChainLock to be received
    let genesis = genesis_block(Network::Dash).header;
    let chain_lock = create_test_chainlock(0, genesis.block_hash());
    network.add_chain_lock(chain_lock.clone());

    // Create client config with masternodes enabled
    let config = ClientConfig {
        network: Network::Dash,
        enable_filters: false,
        enable_masternodes: true,
        validation_mode: ValidationMode::Basic,
        ..Default::default()
    };

    // Create the SPV client
    let mut client = DashSpvClient::new(config, storage, network).await.unwrap();

    // Add genesis header
    let storage = client.storage_mut();
    storage.store_header(&genesis, 0).await.unwrap();

    // Simulate masternode sync completion by creating a mock engine
    // In a real scenario, this would be populated by the masternode sync
    let mock_engine = MasternodeListEngine::new(
        Network::Dash,
        0,
        dashcore::UInt256::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap(),
    );

    // Update the ChainLock manager with the engine
    let updated = client.update_chainlock_validation().await.unwrap();
    assert!(!updated); // Should be false since we don't have a real engine

    // For testing, directly set a mock engine
    let engine_arc = Arc::new(mock_engine);
    client.chainlock_manager().set_masternode_engine(engine_arc).await;

    // Process pending ChainLocks
    let chain_state = ChainState::new(Network::Dash);
    let storage = client.storage_mut();
    let result =
        client.chainlock_manager().validate_pending_chainlocks(&chain_state, storage).await;

    // Should fail validation due to invalid signature
    // This is expected since our mock ChainLock has an invalid signature
    assert!(result.is_ok()); // The validation process itself should complete
}

#[tokio::test]
async fn test_chainlock_queue_and_process_flow() {
    init_logging();

    // Create temp directory for storage
    let temp_dir = TempDir::new().unwrap();
    let storage_path = temp_dir.path().to_path_buf();

    // Create storage
    let storage = Box::new(DiskStorageManager::new(storage_path).unwrap());
    let network = Box::new(MockNetworkManager::new());

    // Create client config
    let config = ClientConfig {
        network: Network::Dash,
        enable_filters: false,
        enable_masternodes: false,
        validation_mode: ValidationMode::Basic,
        ..Default::default()
    };

    // Create the SPV client
    let client = DashSpvClient::new(config, storage, network).await.unwrap();
    let chainlock_manager = client.chainlock_manager();

    // Queue multiple ChainLocks
    let chain_lock1 = create_test_chainlock(100, BlockHash::from_slice(&[1; 32]).unwrap());
    let chain_lock2 = create_test_chainlock(200, BlockHash::from_slice(&[2; 32]).unwrap());
    let chain_lock3 = create_test_chainlock(300, BlockHash::from_slice(&[3; 32]).unwrap());

    chainlock_manager.queue_pending_chainlock(chain_lock1).unwrap();
    chainlock_manager.queue_pending_chainlock(chain_lock2).unwrap();
    chainlock_manager.queue_pending_chainlock(chain_lock3).unwrap();

    // Verify all are queued
    {
        let pending = chainlock_manager.pending_chainlocks.read().unwrap();
        assert_eq!(pending.len(), 3);
        assert_eq!(pending[0].block_height, 100);
        assert_eq!(pending[1].block_height, 200);
        assert_eq!(pending[2].block_height, 300);
    }

    // Process pending (will fail validation but clear the queue)
    let chain_state = ChainState::new(Network::Dash);
    let storage = client.storage();
    let _ = chainlock_manager.validate_pending_chainlocks(&chain_state, storage).await;

    // Verify queue is cleared
    {
        let pending = chainlock_manager.pending_chainlocks.read().unwrap();
        assert_eq!(pending.len(), 0);
    }
}

#[tokio::test]
async fn test_chainlock_manager_cache_operations() {
    init_logging();

    // Create temp directory for storage
    let temp_dir = TempDir::new().unwrap();
    let storage_path = temp_dir.path().to_path_buf();

    // Create storage
    let mut storage = Box::new(DiskStorageManager::new(storage_path).unwrap());
    let network = Box::new(MockNetworkManager::new());

    // Create client config
    let config = ClientConfig {
        network: Network::Dash,
        enable_filters: false,
        enable_masternodes: false,
        validation_mode: ValidationMode::Basic,
        ..Default::default()
    };

    // Create the SPV client
    let client = DashSpvClient::new(config, storage, network).await.unwrap();
    let chainlock_manager = client.chainlock_manager();

    // Add test headers
    let genesis = genesis_block(Network::Dash).header;
    let storage = client.storage();
    storage.store_header(&genesis, 0).await.unwrap();

    // Create and process a ChainLock
    let chain_lock = create_test_chainlock(0, genesis.block_hash());
    let chain_state = ChainState::new(Network::Dash);
    let storage = client.storage();
    let _ = chainlock_manager.process_chain_lock(chain_lock.clone(), &chain_state, storage).await;

    // Test cache operations
    assert!(chainlock_manager.has_chain_lock_at_height(0).await);

    let entry = chainlock_manager.get_chain_lock_by_height(0).await;
    assert!(entry.is_some());
    assert_eq!(entry.unwrap().chain_lock.block_height, 0);

    let entry_by_hash = chainlock_manager.get_chain_lock_by_hash(&genesis.block_hash()).await;
    assert!(entry_by_hash.is_some());
    assert_eq!(entry_by_hash.unwrap().chain_lock.block_height, 0);

    // Check stats
    let stats = chainlock_manager.get_stats().await;
    assert!(stats.total_chain_locks > 0);
    assert_eq!(stats.highest_locked_height, Some(0));
    assert_eq!(stats.lowest_locked_height, Some(0));
}

#[tokio::test]
async fn test_client_chainlock_update_flow() {
    init_logging();

    // Create temp directory for storage
    let temp_dir = TempDir::new().unwrap();
    let storage_path = temp_dir.path().to_path_buf();

    // Create storage and network
    let storage = Box::new(DiskStorageManager::new(storage_path).unwrap());
    let network = Box::new(MockNetworkManager::new());

    // Create client config with masternodes enabled
    let config = ClientConfig {
        network: Network::Dash,
        enable_filters: false,
        enable_masternodes: true,
        validation_mode: ValidationMode::Basic,
        ..Default::default()
    };

    // Create the SPV client
    let mut client = DashSpvClient::new(config, storage, network).await.unwrap();

    // Initially, update should fail (no masternode engine)
    let updated = client.update_chainlock_validation().await.unwrap();
    assert!(!updated);

    // Simulate masternode sync by manually setting sequential sync state
    // In real usage, this would happen automatically during sync
    client.sync_manager.set_phase(dash_spv::sync::sequential::phases::SyncPhase::FullySynced {
        sync_completed_at: std::time::Instant::now(),
        total_sync_time: Duration::from_secs(10),
        headers_synced: 1000,
        filters_synced: 0,
        blocks_downloaded: 0,
    });

    // Create a mock masternode list engine
    let mock_engine = MasternodeListEngine::new(
        Network::Dash,
        0,
        dashcore::UInt256::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap(),
    );

    // Manually inject the engine (in real usage, this would come from masternode sync)
    client.sync_manager.masternode_sync_mut().set_engine(Some(mock_engine));

    // Now update should succeed
    let updated = client.update_chainlock_validation().await.unwrap();
    assert!(updated);

    info!("ChainLock validation update flow test completed");
}
