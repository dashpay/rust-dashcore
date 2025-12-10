//! Integration tests for header synchronization functionality.

use dash_spv::{
    client::{ClientConfig, DashSpvClient},
    network::PeerNetworkManager,
    storage::{BlockHeaderStorage, ChainStateStorage, DiskStorageManager},
    sync::legacy::{HeaderSyncManager, ReorgConfig},
    types::{ChainState, ValidationMode},
};
use dashcore::{block::Header as BlockHeader, block::Version, Network};
use dashcore_hashes::Hash;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::wallet_manager::WalletManager;
use log::info;
use std::sync::Arc;
use tempfile::TempDir;
use test_case::test_case;
use tokio::sync::RwLock;

#[tokio::test]
async fn test_header_sync_with_client_integration() {
    let _ = env_logger::try_init();
    let temp_dir = tempfile::TempDir::new().expect("Failed to create temporary directory");

    // Test header sync integration with the full client
    let config = ClientConfig::new(Network::Dash)
        .with_storage_path(temp_dir.path().to_path_buf())
        .with_validation_mode(ValidationMode::Basic);

    // Create network manager
    let network_manager =
        PeerNetworkManager::new(&config).await.expect("Failed to create network manager");

    // Create storage manager
    let storage_manager = DiskStorageManager::new(&config).await.expect("Failed to create storage");

    // Create wallet manager
    let wallet = Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new(config.network)));

    let client = DashSpvClient::new(config, network_manager, storage_manager, wallet).await;
    assert!(client.is_ok(), "Client creation should succeed");

    let client = client.unwrap();

    // Verify client starts with empty state
    let progress = client.sync_progress();

    assert_eq!(progress.headers().unwrap().current_height(), 0);

    info!("Header sync client integration test completed");
}

// Helper functions for creating test data

fn create_test_header_chain(count: usize) -> Vec<BlockHeader> {
    create_test_header_chain_from(0, count)
}

fn create_test_header_chain_from(start: usize, count: usize) -> Vec<BlockHeader> {
    let mut headers = Vec::new();

    for i in start..(start + count) {
        let header = BlockHeader {
            version: Version::from_consensus(1),
            prev_blockhash: if i == 0 {
                dashcore::BlockHash::all_zeros()
            } else {
                // Create a deterministic previous hash based on height
                dashcore::BlockHash::from_byte_array([(i - 1) as u8; 32])
            },
            merkle_root: dashcore::TxMerkleNode::from_byte_array([(i + 1) as u8; 32]),
            time: 1234567890 + i as u32, // Sequential timestamps
            bits: dashcore::CompactTarget::from_consensus(0x1d00ffff), // Standard difficulty
            nonce: i as u32,             // Sequential nonces
        };
        headers.push(header);
    }

    headers
}

#[test_case(0, 1 ; "genesis_1_block")]
#[test_case(0, 70000 ; "genesis_70000_blocks")]
#[test_case(5000, 1 ; "checkpoint_1_block")]
#[test_case(1000, 70000 ; "checkpoint_70000_blocks")]
#[tokio::test]
async fn test_prepare_sync(sync_base_height: u32, header_count: usize) {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config = ClientConfig::regtest().with_storage_path(temp_dir.path());
    let mut storage = DiskStorageManager::new(&config).await.expect("Failed to create storage");

    let headers = create_test_header_chain(header_count);
    let expected_tip_hash = headers.last().unwrap().block_hash();

    // Create and store chain state
    let mut chain_state = ChainState::new_for_network(Network::Dash);
    chain_state.sync_base_height = sync_base_height;
    storage.store_chain_state(&chain_state).await.expect("Failed to store chain state");
    storage.store_headers(&headers).await.expect("Failed to store headers");

    // Create HeaderSyncManager and load from storage
    let config = ClientConfig::new(Network::Dash);
    let chain_state_arc = Arc::new(RwLock::new(ChainState::new_for_network(Network::Dash)));
    let mut header_sync = HeaderSyncManager::<DiskStorageManager, PeerNetworkManager>::new(
        &config,
        ReorgConfig::default(),
        chain_state_arc.clone(),
    )
    .expect("Failed to create HeaderSyncManager");

    // Call prepare_sync and verify it returns the correct hash
    let result = header_sync.prepare_sync(&mut storage).await;
    let returned_hash = result.unwrap().unwrap();
    assert_eq!(returned_hash, expected_tip_hash, "prepare_sync should return the correct tip hash");
}
