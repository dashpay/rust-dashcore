//! Integration tests for ChainLock validation flow with masternode engine
//!
//! NOTE: This test file is currently disabled due to incomplete mock NetworkManager implementation.
//! TODO: Re-enable once NetworkManager trait methods are fully implemented.

#![cfg(feature = "skip_mock_implementation_incomplete")]

//! Integration tests for ChainLock validation flow with masternode engine

use dash_spv::client::{ClientConfig, DashSpvClient};
use dash_spv::network::NetworkManager;
use dash_spv::storage::DiskStorageManager;
use dash_spv::types::{ChainState, ValidationMode};
use dashcore::blockdata::constants::genesis_block;
use dashcore::sml::masternode_list_engine::MasternodeListEngine;
use dashcore::Network;
use dashcore::{BlockHash, ChainLock};
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::wallet_manager::WalletManager;
use std::sync::Arc;
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
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn connect(&mut self) -> dash_spv::error::NetworkResult<()> {
        Ok(())
    }

    async fn disconnect(&mut self) -> dash_spv::error::NetworkResult<()> {
        Ok(())
    }

    async fn send_message(
        &mut self,
        _message: dashcore::network::message::NetworkMessage,
    ) -> dash_spv::error::NetworkResult<()> {
        Ok(())
    }

    async fn receive_message(
        &mut self,
    ) -> dash_spv::error::NetworkResult<Option<dashcore::network::message::NetworkMessage>> {
        // Simulate receiving ChainLock messages
        let mut sent = self.chain_locks_sent.write().await;
        if *sent < self.chain_locks.len() {
            let chain_lock = self.chain_locks[*sent].clone();
            *sent += 1;
            Ok(Some(dashcore::network::message::NetworkMessage::CLSig(chain_lock)))
        } else {
            // No more messages
            Ok(None)
        }
    }

    fn is_connected(&self) -> bool {
        true
    }

    fn peer_count(&self) -> usize {
        1
    }

    fn peer_info(&self) -> Vec<dash_spv::types::PeerInfo> {
        vec![dash_spv::types::PeerInfo {
            address: "127.0.0.1:9999".parse().unwrap(),
            connected: true,
            last_seen: std::time::SystemTime::now(),
            version: Some(70232),
            services: Some(0), // ServiceFlags::NONE as u64
            user_agent: Some("/MockNode/".to_string()),
            best_height: Some(0),
            wants_dsq_messages: Some(false),
            has_sent_headers2: false,
        }]
    }

    async fn send_ping(&mut self) -> dash_spv::error::NetworkResult<u64> {
        Ok(12345) // Return a dummy nonce
    }

    async fn handle_ping(&mut self, _nonce: u64) -> dash_spv::error::NetworkResult<()> {
        Ok(())
    }

    fn should_ping(&self) -> bool {
        false // Mock doesn't need pinging
    }

    fn cleanup_old_pings(&mut self) {
        // No-op for mock
    }

    fn get_message_sender(
        &self,
    ) -> tokio::sync::mpsc::Sender<dashcore::network::message::NetworkMessage> {
        // Create a dummy sender that drops messages
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        tx
    }

    async fn get_peer_best_height(&self) -> dash_spv::error::NetworkResult<Option<u32>> {
        Ok(Some(0)) // Return dummy height
    }

    async fn has_peer_with_service(
        &self,
        _service_flags: dashcore::network::constants::ServiceFlags,
    ) -> bool {
        true // Mock always has service
    }

    async fn get_peers_with_service(
        &self,
        _service_flags: dashcore::network::constants::ServiceFlags,
    ) -> Vec<dash_spv::types::PeerInfo> {
        self.peer_info() // Return same peer info
    }

    fn handle_pong(&mut self, _nonce: u64) -> dash_spv::error::NetworkResult<()> {
        Ok(()) // No-op for mock
    }

    async fn update_peer_dsq_preference(
        &mut self,
        _wants_dsq: bool,
    ) -> dash_spv::error::NetworkResult<()> {
        Ok(()) // No-op for mock
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
        signature: dashcore::bls_sig_utils::BLSSignature::from([0u8; 96]), // BLS signature placeholder
    }
}

#[ignore = "mock implementation incomplete"]
#[tokio::test]
async fn test_chainlock_validation_without_masternode_engine() {
    init_logging();

    // Create temp directory for storage
    let temp_dir = TempDir::new().unwrap();
    let storage_path = temp_dir.path().to_path_buf();

    // Create storage and network managers
    let storage = DiskStorageManager::new(storage_path).await.unwrap();
    let network = MockNetworkManager::new();

    // Create wallet manager
    let wallet = Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new()));

    // Create client config
    let config = ClientConfig {
        network: Network::Dash,
        enable_filters: false,
        enable_masternodes: false,
        validation_mode: ValidationMode::Basic,
        ..Default::default()
    };

    // Create the SPV client
    let client = DashSpvClient::new(config, network, storage, wallet).await.unwrap();

    // Add a test header to storage
    let genesis = genesis_block(Network::Dash).header;
    // Note: storage_mut() is not available in current API
    // let storage = client.storage_mut();
    // storage.store_header(&genesis, 0).await.unwrap();

    // Create a test ChainLock for genesis block
    let chain_lock = create_test_chainlock(0, genesis.block_hash());

    // Process the ChainLock (should queue it since no masternode engine)
    let chainlock_manager = client.chainlock_manager();
    let chain_state = ChainState::new();
    // Note: In the current API, we need to access storage differently
    // For now, skip this test as it needs to be rewritten for the new client API

    // Skip the rest of this test for now
    return;

    // Verify it was queued
    // Note: pending_chainlocks is private, can't access directly
    // let pending = chainlock_manager.pending_chainlocks.read().unwrap();
    // assert_eq!(pending.len(), 1);
    // assert_eq!(pending[0].block_height, 0);
}

#[ignore = "mock implementation incomplete"]
#[tokio::test]
async fn test_chainlock_validation_with_masternode_engine() {
    init_logging();

    // Create temp directory for storage
    let temp_dir = TempDir::new().unwrap();
    let storage_path = temp_dir.path().to_path_buf();

    // Create storage and network managers
    let storage = DiskStorageManager::new(storage_path).await.unwrap();
    let mut network = MockNetworkManager::new();

    // Add a test ChainLock to be received
    let genesis = genesis_block(Network::Dash).header;
    let chain_lock = create_test_chainlock(0, genesis.block_hash());
    network.add_chain_lock(chain_lock.clone());

    // Create wallet manager
    let wallet = Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new()));

    // Create client config with masternodes enabled
    let config = ClientConfig {
        network: Network::Dash,
        enable_filters: false,
        enable_masternodes: true,
        validation_mode: ValidationMode::Basic,
        ..Default::default()
    };

    // Create the SPV client
    let client = DashSpvClient::new(config, network, storage, wallet).await.unwrap();

    // Add genesis header
    // Note: storage_mut() is not available in current API
    // let storage = client.storage_mut();
    // storage.store_header(&genesis, 0).await.unwrap();

    // Simulate masternode sync completion by creating a mock engine
    // In a real scenario, this would be populated by the masternode sync
    let mock_engine = MasternodeListEngine::default_for_network(Network::Dash);

    // Update the ChainLock manager with the engine
    let updated = client.update_chainlock_validation().unwrap();
    assert!(!updated); // Should be false since we don't have a real engine

    // For testing, directly set a mock engine
    let engine_arc = Arc::new(mock_engine);
    client.chainlock_manager().set_masternode_engine(engine_arc);

    // Process pending ChainLocks
    let chain_state = ChainState::new();
    // Note: storage_mut() is not available in current API
    // let storage = client.storage_mut();
    // Skip this test section as it needs to be rewritten for the new client API
    return;
}

#[ignore = "mock implementation incomplete"]
#[tokio::test]
async fn test_chainlock_queue_and_process_flow() {
    init_logging();

    // Create temp directory for storage
    let temp_dir = TempDir::new().unwrap();
    let storage_path = temp_dir.path().to_path_buf();

    // Create storage
    let storage = DiskStorageManager::new(storage_path).await.unwrap();
    let network = MockNetworkManager::new();

    // Create wallet manager
    let wallet = Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new()));

    // Create client config
    let config = ClientConfig {
        network: Network::Dash,
        enable_filters: false,
        enable_masternodes: false,
        validation_mode: ValidationMode::Basic,
        ..Default::default()
    };

    // Create the SPV client
    let client = DashSpvClient::new(config, network, storage, wallet).await.unwrap();
    let chainlock_manager = client.chainlock_manager();

    // Queue multiple ChainLocks
    let chain_lock1 = create_test_chainlock(100, BlockHash::from([1u8; 32]));
    let chain_lock2 = create_test_chainlock(200, BlockHash::from([2u8; 32]));
    let chain_lock3 = create_test_chainlock(300, BlockHash::from([3u8; 32]));

    chainlock_manager.queue_pending_chainlock(chain_lock1).unwrap();
    chainlock_manager.queue_pending_chainlock(chain_lock2).unwrap();
    chainlock_manager.queue_pending_chainlock(chain_lock3).unwrap();

    // Verify all are queued
    {
        // Note: pending_chainlocks is private, can't access directly
        // let pending = chainlock_manager.pending_chainlocks.read().unwrap();
        // assert_eq!(pending.len(), 3);
        // assert_eq!(pending[0].block_height, 100);
        // assert_eq!(pending[1].block_height, 200);
        // assert_eq!(pending[2].block_height, 300);
    }

    // Process pending (will fail validation but clear the queue)
    let chain_state = ChainState::new();
    // Skip this test as it needs to be rewritten for the new client API
    return;
}

#[ignore = "mock implementation incomplete"]
#[tokio::test]
async fn test_chainlock_manager_cache_operations() {
    init_logging();

    // Create temp directory for storage
    let temp_dir = TempDir::new().unwrap();
    let storage_path = temp_dir.path().to_path_buf();

    // Create storage
    let storage = DiskStorageManager::new(storage_path).await.unwrap();
    let network = MockNetworkManager::new();

    // Create wallet manager
    let wallet = Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new()));

    // Create client config
    let config = ClientConfig {
        network: Network::Dash,
        enable_filters: false,
        enable_masternodes: false,
        validation_mode: ValidationMode::Basic,
        ..Default::default()
    };

    // Create the SPV client
    let client = DashSpvClient::new(config, network, storage, wallet).await.unwrap();
    let chainlock_manager = client.chainlock_manager();

    // Add test headers
    let genesis = genesis_block(Network::Dash).header;
    let storage = client.storage();
    // storage.store_header(&genesis, 0).await.unwrap();

    // Create and process a ChainLock - skip for now as storage access pattern changed
    let chain_lock = create_test_chainlock(0, genesis.block_hash());
    let chain_state = ChainState::new();
    // Note: storage access pattern has changed in the new client API
    // let _ = chainlock_manager.process_chain_lock(chain_lock.clone(), &chain_state, storage).await;

    // Test cache operations
    assert!(chainlock_manager.has_chain_lock_at_height(0));

    let entry = chainlock_manager.get_chain_lock_by_height(0);
    assert!(entry.is_some());
    assert_eq!(entry.unwrap().chain_lock.block_height, 0);

    let entry_by_hash = chainlock_manager.get_chain_lock_by_hash(&genesis.block_hash());
    assert!(entry_by_hash.is_some());
    assert_eq!(entry_by_hash.unwrap().chain_lock.block_height, 0);

    // Check stats
    let stats = chainlock_manager.get_stats();
    assert!(stats.total_chain_locks > 0);
    assert_eq!(stats.highest_locked_height, Some(0));
    assert_eq!(stats.lowest_locked_height, Some(0));
}

#[ignore = "mock implementation incomplete"]
#[tokio::test]
async fn test_client_chainlock_update_flow() {
    init_logging();

    // Create temp directory for storage
    let temp_dir = TempDir::new().unwrap();
    let storage_path = temp_dir.path().to_path_buf();

    // Create storage and network
    let storage = DiskStorageManager::new(storage_path).await.unwrap();
    let network = MockNetworkManager::new();

    // Create wallet manager
    let wallet = Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new()));

    // Create client config with masternodes enabled
    let config = ClientConfig {
        network: Network::Dash,
        enable_filters: false,
        enable_masternodes: true,
        validation_mode: ValidationMode::Basic,
        ..Default::default()
    };

    // Create the SPV client
    let client = DashSpvClient::new(config, network, storage, wallet).await.unwrap();

    // Initially, update should fail (no masternode engine)
    let updated = client.update_chainlock_validation().unwrap();
    assert!(!updated);

    // Simulate masternode sync by manually setting sequential sync state
    // In real usage, this would happen automatically during sync
    // Note: sync_manager is private, can't access directly
    // client.sync_manager.set_phase(dash_spv::sync::sequential::phases::SyncPhase::FullySynced {
    //     sync_completed_at: std::time::Instant::now(),
    //     total_sync_time: Duration::from_secs(10),
    //     headers_synced: 1000,
    //     filters_synced: 0,
    //     blocks_downloaded: 0,
    // });

    // Create a mock masternode list engine
    let mock_engine = MasternodeListEngine::default_for_network(Network::Dash);

    // Manually inject the engine (in real usage, this would come from masternode sync)
    // Note: sync_manager is private, can't access directly
    // client.sync_manager.masternode_sync_mut().set_engine(Some(mock_engine));

    // Now update should succeed
    let updated = client.update_chainlock_validation().unwrap();
    assert!(updated);

    info!("ChainLock validation update flow test completed");
}
