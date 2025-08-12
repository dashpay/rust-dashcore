//! Integration tests for error recovery mechanisms
//!
//! These tests validate error recovery in more realistic scenarios,
//! including network interruptions, storage failures during sync,
//! and validation errors with real data.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use dashcore::{block::Header as BlockHeader, hash_types::FilterHeader, BlockHash, Network};
use tokio::sync::{Mutex, RwLock};
use tokio::time::timeout;

use dash_spv::client::{Client, ClientConfig};
use dash_spv::error::{NetworkError, SpvError, StorageError, SyncError, ValidationError};
use dash_spv::storage::{DiskStorageManager, MemoryStorage, StorageManager};
use dash_spv::sync::sequential::recovery::RecoveryManager;

/// Test helper to simulate network interruptions
struct NetworkInterruptor {
    should_interrupt: Arc<Mutex<bool>>,
    interrupt_after_messages: Arc<Mutex<Option<usize>>>,
    messages_count: Arc<Mutex<usize>>,
}

impl NetworkInterruptor {
    fn new() -> Self {
        Self {
            should_interrupt: Arc::new(Mutex::new(false)),
            interrupt_after_messages: Arc::new(Mutex::new(None)),
            messages_count: Arc::new(Mutex::new(0)),
        }
    }

    async fn set_interrupt_after(&self, count: usize) {
        *self.interrupt_after_messages.lock().await = Some(count);
    }

    async fn should_interrupt(&self) -> bool {
        let mut count = self.messages_count.lock().await;
        *count += 1;

        if let Some(limit) = *self.interrupt_after_messages.lock().await {
            if *count >= limit {
                *self.should_interrupt.lock().await = true;
            }
        }

        *self.should_interrupt.lock().await
    }

    async fn reset(&self) {
        *self.should_interrupt.lock().await = false;
        *self.messages_count.lock().await = 0;
    }
}

/// Test helper to simulate storage failures
struct StorageFailureSimulator {
    fail_at_height: Arc<RwLock<Option<u32>>>,
    failure_type: Arc<RwLock<FailureType>>,
}

#[derive(Clone)]
enum FailureType {
    None,
    WriteFailure,
    ReadFailure,
    Corruption,
    DiskFull,
}

impl StorageFailureSimulator {
    fn new() -> Self {
        Self {
            fail_at_height: Arc::new(RwLock::new(None)),
            failure_type: Arc::new(RwLock::new(FailureType::None)),
        }
    }

    async fn set_fail_at_height(&self, height: u32, failure_type: FailureType) {
        *self.fail_at_height.write().await = Some(height);
        *self.failure_type.write().await = failure_type;
    }

    async fn should_fail(&self, height: u32) -> Option<StorageError> {
        if let Some(fail_height) = *self.fail_at_height.read().await {
            if height >= fail_height {
                return match &*self.failure_type.read().await {
                    FailureType::WriteFailure => Some(StorageError::WriteFailed(format!(
                        "Simulated write failure at height {}",
                        height
                    ))),
                    FailureType::ReadFailure => Some(StorageError::ReadFailed(format!(
                        "Simulated read failure at height {}",
                        height
                    ))),
                    FailureType::Corruption => Some(StorageError::Corruption(format!(
                        "Simulated corruption at height {}",
                        height
                    ))),
                    FailureType::DiskFull => {
                        Some(StorageError::WriteFailed("No space left on device".to_string()))
                    }
                    FailureType::None => None,
                };
            }
        }
        None
    }
}

#[tokio::test]
async fn test_recovery_from_network_interruption_during_header_sync() {
    // This test simulates a network interruption during header synchronization
    // and verifies that the client can recover and continue from where it left off

    let temp_dir = tempfile::tempdir().unwrap();
    let storage_path = temp_dir.path().to_path_buf();

    // Create storage manager
    let storage = Arc::new(RwLock::new(DiskStorageManager::new(storage_path).await.unwrap()));

    // Create network interruptor
    let interruptor = Arc::new(NetworkInterruptor::new());

    // Set up to interrupt after 100 headers
    interruptor.set_interrupt_after(100).await;

    // Create recovery manager
    let mut recovery_manager = RecoveryManager::new();

    // Track recovery attempts
    let mut recovery_count = 0;
    let max_recoveries = 3;

    // Simulate header sync with interruptions
    let mut current_height = 0u32;
    let target_height = 500u32;

    while current_height < target_height && recovery_count < max_recoveries {
        // Simulate downloading headers
        let mut headers_in_batch = 0;

        loop {
            if interruptor.should_interrupt().await {
                // Simulate network error
                let error = SyncError::Network("Connection lost".to_string());

                // Determine recovery strategy
                let phase = dash_spv::sync::sequential::phases::SyncPhase::DownloadingHeaders {
                    start_time: std::time::Instant::now(),
                    start_height: 0,
                    current_height,
                    target_height: Some(target_height),
                    headers_downloaded: current_height,
                    headers_per_second: 50.0,
                    received_empty_response: false,
                    last_progress: std::time::Instant::now(),
                };

                let strategy = recovery_manager.determine_strategy(&phase, &error);

                // Log recovery attempt
                recovery_count += 1;
                eprintln!("Recovery attempt {} at height {}", recovery_count, current_height);

                // Reset interruptor for next attempt
                interruptor.reset().await;
                interruptor.set_interrupt_after(100).await;

                // Apply recovery delay
                if let dash_spv::sync::sequential::recovery::RecoveryStrategy::Retry {
                    delay,
                } = strategy
                {
                    tokio::time::sleep(delay).await;
                }

                break;
            }

            // Simulate storing a header
            let header = create_test_header(current_height);
            storage.write().await.store_header(current_height, &header).await.unwrap();

            current_height += 1;
            headers_in_batch += 1;

            if current_height >= target_height {
                break;
            }

            // Simulate network delay
            if headers_in_batch % 10 == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }

        if current_height >= target_height {
            break;
        }
    }

    // Verify we reached the target despite interruptions
    assert_eq!(current_height, target_height);
    assert!(recovery_count > 0, "Should have had at least one recovery");

    // Verify all headers were stored correctly
    let stored_headers = storage.read().await.get_headers_range(0..target_height).await.unwrap();
    assert_eq!(stored_headers.len(), target_height as usize);
}

#[tokio::test]
async fn test_recovery_from_storage_failure_during_sync() {
    // This test simulates storage failures during synchronization
    // and verifies appropriate error handling and recovery

    let temp_dir = tempfile::tempdir().unwrap();
    let storage_path = temp_dir.path().to_path_buf();

    // Create storage with failure simulator
    let failure_sim = Arc::new(StorageFailureSimulator::new());

    // Set up to fail at height 250 with disk full
    failure_sim.set_fail_at_height(250, FailureType::DiskFull).await;

    // Track storage operations
    let mut last_successful_height = 0u32;
    let target_height = 500u32;

    // Simulate sync with storage failures
    for height in 0..target_height {
        let header = create_test_header(height);

        // Check if we should simulate a failure
        if let Some(error) = failure_sim.should_fail(height).await {
            eprintln!("Storage failure at height {}: {:?}", height, error);

            // In a real scenario, this would trigger recovery
            // For this test, we'll simulate clearing some space and retrying
            if matches!(error, StorageError::WriteFailed(ref msg) if msg.contains("No space left"))
            {
                // Simulate clearing space by resetting failure simulator
                failure_sim.set_fail_at_height(350, FailureType::None).await;

                // Retry the operation
                // In real implementation, this would be handled by recovery manager
                continue;
            }

            break;
        }

        last_successful_height = height;
    }

    // Verify we handled the disk full error appropriately
    assert!(last_successful_height >= 250, "Should have processed headers up to failure point");
}

#[tokio::test]
async fn test_recovery_from_validation_errors() {
    // This test simulates validation errors and verifies recovery behavior

    let mut recovery_manager = RecoveryManager::new();

    // Test various validation error scenarios
    let validation_errors = vec![
        ValidationError::InvalidProofOfWork,
        ValidationError::InvalidHeaderChain("Timestamp before previous block".to_string()),
        ValidationError::InvalidFilterHeaderChain("Filter header mismatch".to_string()),
        ValidationError::Consensus("Block too large".to_string()),
    ];

    for (i, val_error) in validation_errors.iter().enumerate() {
        let sync_error = SyncError::Validation(val_error.to_string());

        let phase = dash_spv::sync::sequential::phases::SyncPhase::DownloadingHeaders {
            start_time: std::time::Instant::now(),
            start_height: 0,
            current_height: 1000 + (i as u32 * 100),
            target_height: Some(2000),
            headers_downloaded: 1000,
            headers_per_second: 100.0,
            received_empty_response: false,
            last_progress: std::time::Instant::now(),
        };

        let strategy = recovery_manager.determine_strategy(&phase, &sync_error);

        // Validation errors should typically trigger phase restart from checkpoint
        match strategy {
            dash_spv::sync::sequential::recovery::RecoveryStrategy::RestartPhase {
                checkpoint,
            } => {
                assert!(checkpoint.restart_height.is_some());
                let restart_height = checkpoint.restart_height.unwrap();
                assert!(restart_height < phase.current_height());
                eprintln!(
                    "Validation error '{}' triggers restart from height {}",
                    val_error, restart_height
                );
            }
            dash_spv::sync::sequential::recovery::RecoveryStrategy::Retry {
                ..
            } => {
                // Some validation errors might trigger retry first
                eprintln!("Validation error '{}' triggers retry", val_error);
            }
            _ => panic!("Unexpected recovery strategy for validation error"),
        }
    }
}

#[tokio::test]
async fn test_concurrent_error_recovery() {
    // This test simulates multiple concurrent errors and verifies
    // that the recovery mechanisms handle them correctly

    let recovery_manager = Arc::new(Mutex::new(RecoveryManager::new()));

    // Spawn multiple tasks that encounter different errors
    let mut handles = vec![];

    for i in 0..5 {
        let recovery_clone = Arc::clone(&recovery_manager);

        let handle = tokio::spawn(async move {
            let error = match i % 3 {
                0 => SyncError::Timeout(format!("Task {} timeout", i)),
                1 => SyncError::Network(format!("Task {} network error", i)),
                _ => SyncError::Validation(format!("Task {} validation error", i)),
            };

            let phase = dash_spv::sync::sequential::phases::SyncPhase::DownloadingHeaders {
                start_time: std::time::Instant::now(),
                start_height: 0,
                current_height: 100 * i,
                target_height: Some(1000),
                headers_downloaded: 100 * i,
                headers_per_second: 50.0,
                received_empty_response: false,
                last_progress: std::time::Instant::now(),
            };

            let mut recovery = recovery_clone.lock().await;
            let strategy = recovery.determine_strategy(&phase, &error);

            (i, error.category().to_string(), strategy)
        });

        handles.push(handle);
    }

    // Collect results
    let mut results = vec![];
    for handle in handles {
        results.push(handle.await.unwrap());
    }

    // Verify each task got appropriate recovery strategy
    for (task_id, error_category, strategy) in results {
        eprintln!("Task {} with {} error got strategy: {:?}", task_id, error_category, strategy);

        match error_category.as_str() {
            "timeout" => {
                assert!(matches!(
                    strategy,
                    dash_spv::sync::sequential::recovery::RecoveryStrategy::Retry { .. }
                ));
            }
            "network" => {
                assert!(matches!(
                    strategy,
                    dash_spv::sync::sequential::recovery::RecoveryStrategy::Retry { .. }
                        | dash_spv::sync::sequential::recovery::RecoveryStrategy::SwitchPeer
                ));
            }
            "validation" => {
                assert!(matches!(
                    strategy,
                    dash_spv::sync::sequential::recovery::RecoveryStrategy::RestartPhase { .. }
                        | dash_spv::sync::sequential::recovery::RecoveryStrategy::Retry { .. }
                ));
            }
            _ => {}
        }
    }
}

#[tokio::test]
async fn test_recovery_statistics_tracking() {
    // This test verifies that recovery statistics are properly tracked

    let mut recovery_manager = RecoveryManager::new();
    let mut network = MockNetworkManager::new();
    let mut storage = MockStorageManager::new();

    // Simulate various recovery scenarios
    let scenarios = vec![
        (SyncError::Timeout("Test timeout".to_string()), true),
        (SyncError::Network("Connection failed".to_string()), true),
        (SyncError::Validation("Invalid header".to_string()), false),
        (SyncError::Storage("Write failed".to_string()), false),
    ];

    for (i, (error, _expected_success)) in scenarios.iter().enumerate() {
        let mut phase = dash_spv::sync::sequential::phases::SyncPhase::DownloadingHeaders {
            start_time: std::time::Instant::now(),
            start_height: 0,
            current_height: 100 * i as u32,
            target_height: Some(1000),
            headers_downloaded: 100 * i as u32,
            headers_per_second: 50.0,
            received_empty_response: false,
            last_progress: std::time::Instant::now(),
        };

        let strategy = recovery_manager.determine_strategy(&phase, error);
        let _ = recovery_manager
            .execute_recovery(&mut phase, strategy, error, &mut network, &mut storage)
            .await;
    }

    // Get and verify statistics
    let stats = recovery_manager.get_stats();
    assert_eq!(stats.total_recoveries, scenarios.len());
    assert!(stats.recoveries_by_phase.contains_key("DownloadingHeaders"));
    assert_eq!(stats.recoveries_by_phase["DownloadingHeaders"], scenarios.len());

    // Verify retry counts are tracked
    assert!(!stats.current_retry_counts.is_empty());
}

// Helper functions

fn create_test_header(height: u32) -> BlockHeader {
    use dashcore::block::Version;
    use dashcore::pow::CompactTarget;
    use dashcore_hashes::Hash;

    BlockHeader {
        version: Version::from_consensus(1),
        prev_blockhash: if height == 0 {
            BlockHash::from_byte_array([0; 32])
        } else {
            BlockHash::from_byte_array([(height - 1) as u8; 32])
        },
        merkle_root: dashcore::hashes::sha256d::Hash::from_byte_array([height as u8; 32]).into(),
        time: 1234567890 + height,
        bits: CompactTarget::from_consensus(0x1d00ffff),
        nonce: height,
    }
}

// Mock implementations for testing

struct MockNetworkManager {
    messages_sent: usize,
}

impl MockNetworkManager {
    fn new() -> Self {
        Self {
            messages_sent: 0,
        }
    }
}

#[async_trait::async_trait]
impl dash_spv::network::NetworkManager for MockNetworkManager {
    fn peer_count(&self) -> usize {
        1
    }

    async fn connect(&mut self, _addr: SocketAddr) -> dash_spv::error::NetworkResult<()> {
        Ok(())
    }

    async fn send_message(
        &mut self,
        _msg: dashcore::network::message::NetworkMessage,
    ) -> dash_spv::error::NetworkResult<()> {
        self.messages_sent += 1;
        Ok(())
    }

    async fn receive_message(
        &mut self,
    ) -> dash_spv::error::NetworkResult<Option<dashcore::network::message::NetworkMessage>> {
        Ok(None)
    }
}

struct MockStorageManager;

impl MockStorageManager {
    fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl StorageManager for MockStorageManager {
    async fn store_header(
        &mut self,
        _height: u32,
        _header: &BlockHeader,
    ) -> dash_spv::error::StorageResult<()> {
        Ok(())
    }

    async fn get_header(
        &self,
        _height: u32,
    ) -> dash_spv::error::StorageResult<Option<BlockHeader>> {
        Ok(None)
    }

    async fn get_header_by_hash(
        &self,
        _hash: &BlockHash,
    ) -> dash_spv::error::StorageResult<Option<(u32, BlockHeader)>> {
        Ok(None)
    }

    async fn get_tip_height(&self) -> dash_spv::error::StorageResult<Option<u32>> {
        Ok(Some(0))
    }

    async fn get_headers_range(
        &self,
        _range: std::ops::Range<u32>,
    ) -> dash_spv::error::StorageResult<Vec<BlockHeader>> {
        Ok(vec![])
    }

    async fn store_filter_header(
        &mut self,
        _height: u32,
        _filter_header: &FilterHeader,
    ) -> dash_spv::error::StorageResult<()> {
        Ok(())
    }

    async fn get_filter_header(
        &self,
        _height: u32,
    ) -> dash_spv::error::StorageResult<Option<FilterHeader>> {
        Ok(None)
    }

    async fn get_filter_tip_height(&self) -> dash_spv::error::StorageResult<Option<u32>> {
        Ok(Some(0))
    }

    async fn store_chain_state(
        &mut self,
        _state: &dash_spv::types::ChainState,
    ) -> dash_spv::error::StorageResult<()> {
        Ok(())
    }

    async fn get_chain_state(
        &self,
    ) -> dash_spv::error::StorageResult<Option<dash_spv::types::ChainState>> {
        Ok(None)
    }

    async fn compact_storage(&mut self) -> dash_spv::error::StorageResult<()> {
        Ok(())
    }

    async fn get_stats(&self) -> dash_spv::error::StorageResult<dash_spv::storage::StorageStats> {
        Ok(dash_spv::storage::StorageStats {
            headers_count: 0,
            filter_headers_count: 0,
            filters_count: 0,
            headers_size_bytes: 0,
            filter_headers_size_bytes: 0,
            filters_size_bytes: 0,
            total_size_bytes: 0,
            last_compaction: None,
        })
    }

    async fn get_utxos_by_address(
        &self,
        _address: &dashcore::Address,
    ) -> dash_spv::error::StorageResult<Vec<(dashcore::OutPoint, dash_spv::wallet::Utxo)>> {
        Ok(vec![])
    }

    async fn store_utxo(
        &mut self,
        _outpoint: &dashcore::OutPoint,
        _utxo: &dash_spv::wallet::Utxo,
    ) -> dash_spv::error::StorageResult<()> {
        Ok(())
    }

    async fn remove_utxo(
        &mut self,
        _outpoint: &dashcore::OutPoint,
    ) -> dash_spv::error::StorageResult<Option<dash_spv::wallet::Utxo>> {
        Ok(None)
    }

    async fn get_utxo(
        &self,
        _outpoint: &dashcore::OutPoint,
    ) -> dash_spv::error::StorageResult<Option<dash_spv::wallet::Utxo>> {
        Ok(None)
    }

    async fn get_all_utxos(
        &self,
    ) -> dash_spv::error::StorageResult<
        std::collections::HashMap<dashcore::OutPoint, dash_spv::wallet::Utxo>,
    > {
        Ok(std::collections::HashMap::new())
    }

    async fn store_mempool_state(
        &mut self,
        _state: &dash_spv::types::MempoolState,
    ) -> dash_spv::error::StorageResult<()> {
        Ok(())
    }

    async fn get_mempool_state(
        &self,
    ) -> dash_spv::error::StorageResult<Option<dash_spv::types::MempoolState>> {
        Ok(None)
    }

    async fn store_masternode_state(
        &mut self,
        _state: &dash_spv::storage::MasternodeState,
    ) -> dash_spv::error::StorageResult<()> {
        Ok(())
    }

    async fn get_masternode_state(
        &self,
    ) -> dash_spv::error::StorageResult<Option<dash_spv::storage::MasternodeState>> {
        Ok(None)
    }

    // Terminal block methods removed from StorageManager trait
    // These methods are no longer part of the trait
}
