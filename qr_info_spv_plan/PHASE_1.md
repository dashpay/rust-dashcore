# Phase 1: Add QRInfo Support to dash-spv

## Overview

This phase adds comprehensive QRInfo message handling to dash-spv, establishing the foundation for efficient batch-based masternode synchronization. We'll implement the network protocol, message processing, and basic integration with the masternode sync manager.

## Objectives

1. **Add QRInfo Protocol Support**: Implement network message handling
2. **Basic Integration**: Connect QRInfo to masternode sync manager
3. **Test Infrastructure**: Comprehensive test suite with real data
4. **Fallback Compatibility**: Maintain existing MnListDiff functionality

## Detailed Implementation Plan

### 1. Network Layer Implementation

#### 1.1 Add QRInfo Message Types

**File**: `dash-spv/src/network/message_handler.rs`

**Implementation**:
```rust
// Add QRInfo imports
use dashcore::network::message_qrinfo::{QRInfo, GetQRInfo};

// Add to NetworkMessage handling
pub async fn handle_message(&mut self, message: NetworkMessage) -> Result<(), NetworkError> {
    match message {
        // ... existing cases ...
        NetworkMessage::QRInfo(qr_info) => {
            self.handle_qr_info(qr_info).await?;
        }
        // Add to request handling
        NetworkMessage::GetQRInfo(get_qr_info) => {
            // We don't serve QRInfo requests, only make them
            tracing::warn!("Received unexpected GetQRInfo request");
        }
        _ => {} // existing catch-all
    }
    Ok(())
}

async fn handle_qr_info(&mut self, qr_info: QRInfo) -> Result<(), NetworkError> {
    // Route to masternode sync manager
    if let Some(sync_sender) = &self.masternode_sync_sender {
        sync_sender.send(MasternodeSyncMessage::QRInfo(qr_info))
            .await
            .map_err(|e| NetworkError::Internal(format!("Failed to send QRInfo: {}", e)))?;
    }
    Ok(())
}
```

**Test File**: `tests/network/test_qr_info_message_handling.rs`
```rust
#[tokio::test]
async fn test_qr_info_message_parsing() {
    // Load real QRInfo test vector
    let qr_info_bytes = load_test_vector("qr_info_mainnet_height_2240504.bin");
    let qr_info: QRInfo = deserialize(&qr_info_bytes).expect("Failed to parse QRInfo");
    
    // Verify all components present
    assert!(!qr_info.mn_list_diff_list.is_empty());
    assert!(!qr_info.last_commitment_per_index.is_empty());
    assert!(qr_info.quorum_snapshot_and_mn_list_diff_at_h_minus_4c.is_some());
}

#[tokio::test] 
async fn test_qr_info_network_routing() {
    let mut handler = setup_test_message_handler().await;
    let test_qr_info = create_test_qr_info();
    
    let result = handler.handle_message(NetworkMessage::QRInfo(test_qr_info)).await;
    assert!(result.is_ok());
    
    // Verify message was routed to sync manager
    let received_message = handler.sync_receiver.recv().await.unwrap();
    assert!(matches!(received_message, MasternodeSyncMessage::QRInfo(_)));
}
```

#### 1.2 Add QRInfo Request Capability

**File**: `dash-spv/src/network/network_manager.rs`

**Implementation**:
```rust
impl NetworkManagerImpl {
    /// Request QRInfo from the network
    pub async fn request_qr_info(
        &mut self,
        base_block_hash: BlockHash,
        block_hash: BlockHash,
        extra_share: bool,
    ) -> Result<(), NetworkError> {
        let get_qr_info = GetQRInfo {
            base_block_hash,
            block_hash,
            extra_share,
        };
        
        self.send_message(NetworkMessage::GetQRInfo(get_qr_info)).await?;
        
        tracing::debug!(
            "Requested QRInfo from {} to {}, extra_share={}",
            base_block_hash,
            block_hash, 
            extra_share
        );
        
        Ok(())
    }
}
```

**Test File**: `tests/network/test_qr_info_requests.rs`
```rust
#[tokio::test]
async fn test_qr_info_request_construction() {
    let mut network = setup_test_network().await;
    let base_hash = BlockHash::from_str("000000000000000fcc3b58235989afa1962b6d6f238a2201190452123231a704").unwrap();
    let tip_hash = BlockHash::from_str("000000000000001912a0ac17300c5b7bfd1385a418137c3bc8d273ac3d9f85d7").unwrap();
    
    let result = network.request_qr_info(base_hash, tip_hash, true).await;
    assert!(result.is_ok());
    
    // Verify message was sent
    let sent_message = network.get_last_sent_message().unwrap();
    assert!(matches!(sent_message, NetworkMessage::GetQRInfo(_)));
}

#[tokio::test]
async fn test_qr_info_request_extra_share_flag() {
    let mut network = setup_test_network().await;
    let base_hash = test_genesis_hash();
    let tip_hash = test_block_hash(100);
    
    // Test with extra_share = false
    network.request_qr_info(base_hash, tip_hash, false).await.unwrap();
    let message = network.get_last_sent_message().unwrap();
    if let NetworkMessage::GetQRInfo(req) = message {
        assert!(!req.extra_share);
    } else {
        panic!("Expected GetQRInfo message");
    }
}
```

### 2. Masternode Sync Manager Integration

#### 2.1 Add QRInfo Message Channel

**File**: `dash-spv/src/sync/masternodes.rs`

**Implementation**:
```rust
// Add to MasternodeSyncMessage enum
#[derive(Debug)]
pub enum MasternodeSyncMessage {
    MnListDiff(MnListDiff),
    QRInfo(QRInfo),  // NEW
    Reset,
    Status,
}

impl MasternodeSyncManager {
    /// Process received QRInfo message
    pub async fn handle_qr_info(
        &mut self,
        qr_info: QRInfo,
        storage: &dyn StorageManager,
    ) -> SyncResult<()> {
        tracing::info!(
            "Received QRInfo with {} diffs and {} snapshots",
            qr_info.mn_list_diff_list.len(),
            qr_info.quorum_snapshot_list.len()
        );
        
        // Get engine or return early
        let engine = self.engine.as_mut().ok_or_else(|| {
            SyncError::Configuration("Masternode engine not initialized".to_string())
        })?;
        
        // Create block height fetcher
        let block_height_fetcher = |block_hash: &BlockHash| -> Result<u32, ClientDataRetrievalError> {
            self.get_block_height_from_storage(block_hash, storage)
        };
        
        // Process QRInfo through engine
        engine.feed_qr_info(
            qr_info,
            true,  // verify_tip_non_rotated_quorums
            true,  // verify_rotated_quorums  
            Some(block_height_fetcher)
        ).map_err(|e| SyncError::Validation(format!("QRInfo processing failed: {}", e)))?;
        
        tracing::info!("Successfully processed QRInfo");
        Ok(())
    }
    
    /// Get block height from storage for QRInfo processing
    fn get_block_height_from_storage(
        &self,
        block_hash: &BlockHash,
        storage: &dyn StorageManager,
    ) -> Result<u32, ClientDataRetrievalError> {
        // First check if it's in our block container
        if let Some(engine) = &self.engine {
            if let Some(height) = engine.block_container.get_height(block_hash) {
                return Ok(height);
            }
        }
        
        // Fall back to storage lookup (convert storage height to blockchain height)
        let sync_base = self.sync_base_height;
        
        // TODO: Implement efficient block hash -> height lookup in storage
        // For now, we'll need to search or maintain an index
        for height in 0..=1000 { // Reasonable search range
            if let Ok(Some(header)) = futures::executor::block_on(storage.get_header(height)) {
                if header.block_hash() == *block_hash {
                    return Ok(height + sync_base);
                }
            }
        }
        
        Err(ClientDataRetrievalError::BlockNotFound(*block_hash))
    }
}
```

**Test File**: `tests/sync/test_qr_info_processing.rs`
```rust
#[tokio::test]
async fn test_qr_info_basic_processing() {
    let mut sync_manager = setup_test_sync_manager().await;
    let storage = setup_test_storage().await;
    let qr_info = load_test_qr_info("mainnet_2240504");
    
    let result = sync_manager.handle_qr_info(qr_info, &storage).await;
    assert!(result.is_ok());
    
    // Verify engine state was updated
    let engine = sync_manager.engine().unwrap();
    assert!(!engine.masternode_lists.is_empty());
    assert!(!engine.known_snapshots.is_empty());
}

#[tokio::test]
async fn test_qr_info_block_height_fetching() {
    let sync_manager = setup_sync_manager_with_blocks().await;
    let storage = setup_storage_with_headers().await;
    let test_hash = BlockHash::from_str("000000000000001912a0ac17300c5b7bfd1385a418137c3bc8d273ac3d9f85d7").unwrap();
    
    let height = sync_manager.get_block_height_from_storage(&test_hash, &storage)
        .expect("Should find block height");
    
    assert_eq!(height, 2240504);
}

#[tokio::test]
async fn test_qr_info_engine_integration() {
    let mut sync_manager = setup_test_sync_manager().await;
    let storage = setup_test_storage().await;
    
    // Load real QRInfo with known expected state
    let qr_info = load_test_qr_info("mainnet_rotation_cycle");
    let initial_list_count = sync_manager.engine().unwrap().masternode_lists.len();
    
    sync_manager.handle_qr_info(qr_info, &storage).await.unwrap();
    
    let engine = sync_manager.engine().unwrap();
    assert!(engine.masternode_lists.len() > initial_list_count);
    assert!(!engine.rotated_quorums_per_cycle.is_empty());
    
    // Verify we can look up quorums now
    let quorum_hashes = engine.latest_masternode_list_quorum_hashes(&[]);
    assert!(!quorum_hashes.is_empty());
}
```

#### 2.2 Add Storage Block Hash Lookup

**File**: `dash-spv/src/storage/mod.rs`

**Implementation** (Using Existing Efficient Storage):
```rust
// NO NEW METHODS NEEDED - Use existing StorageManager interface
// The existing StorageManager already provides efficient O(1) hash-to-height lookups:

use crate::storage::StorageManager;
use crate::sml::quorum_validation_error::ClientDataRetrievalError;

/// Create block height fetcher using storage's existing efficient O(1) index
/// 
/// Note: dash-spv already implements HashMap<BlockHash, u32> for O(1) lookups
/// in disk.rs via header_hash_index. No linear scan required!
pub fn create_block_height_fetcher<S: StorageManager>(
    storage: &S,
) -> impl Fn(&BlockHash) -> Result<u32, ClientDataRetrievalError> + '_ {
    |block_hash: &BlockHash| {
        // Use existing efficient storage method
        storage.get_header_height(block_hash)
            .map_err(|e| ClientDataRetrievalError::StorageError(e.to_string()))?
            .ok_or_else(|| ClientDataRetrievalError::BlockNotFound(*block_hash))
    }
}

/// Async wrapper for block height fetching (if needed)
pub struct AsyncBlockHeightFetcher<'a, S: StorageManager> {
    storage: &'a S,
}

impl<'a, S: StorageManager> AsyncBlockHeightFetcher<'a, S> {
    pub fn new(storage: &'a S) -> Self {
        Self { storage }
    }
    
    /// Fetch block height using storage's efficient O(1) index
    pub async fn fetch_height(
        &self,
        block_hash: &BlockHash,
    ) -> Result<u32, ClientDataRetrievalError> {
        // Use storage's existing O(1) hash-to-height lookup
        self.storage
            .get_header_height(block_hash)
            .await
            .map_err(|e| ClientDataRetrievalError::StorageError(e.to_string()))?
            .ok_or_else(|| ClientDataRetrievalError::BlockNotFound(*block_hash))
    }
}
```

**Storage Integration** (No changes to existing storage layer needed):
```rust
// The existing storage layer already provides what we need:
impl StorageManager for DiskStorageManager {
    // ALREADY EXISTS: O(1) hash-to-height lookup
    async fn get_header_height_by_hash(&self, hash: &BlockHash) -> StorageResult<Option<u32>> {
        // Uses existing header_hash_index (HashMap / Arc<RwLock<...>>) to return
        // StorageResult<Option<u32>> - this is already implemented and tested!
    }
}
```
```

**Test File**: `tests/storage/test_block_hash_lookup.rs`
```rust
#[tokio::test]
async fn test_block_hash_index_creation() {
    let storage = setup_test_disk_storage().await;
    
    // Add some test headers
    for i in 0..100 {
        let header = create_test_header(i);
        storage.store_header(i, &header).await.unwrap();
    }
    
    // Build index
    storage.build_block_hash_index().await.unwrap();
    
    // Test lookups
    let test_hash = storage.get_header(50).await.unwrap().unwrap().block_hash();
    let found_height = storage.get_block_height(&test_hash).await.unwrap();
    assert_eq!(found_height, Some(50));
}

#[tokio::test] 
async fn test_block_hash_lookup_performance() {
    let storage = setup_large_test_storage(10000).await; // 10k headers
    storage.build_block_hash_index().await.unwrap();
    
    let start = std::time::Instant::now();
    
    // Test 100 random lookups
    for _ in 0..100 {
        let random_height = rand::random::<u32>() % 10000;
        let header = storage.get_header(random_height).await.unwrap().unwrap();
        let hash = header.block_hash();
        
        let found_height = storage.get_block_height(&hash).await.unwrap();
        assert_eq!(found_height, Some(random_height));
    }
    
    let elapsed = start.elapsed();
    assert!(elapsed < std::time::Duration::from_millis(100)); // Should be very fast
}
```

### 3. Test Infrastructure

#### 3.1 QRInfo Test Data Generation

**File**: `tests/fixtures/qr_info_generator.rs`
```rust
/// Generate test QRInfo messages for various scenarios
pub struct QRInfoTestGenerator {
    network: Network,
    base_height: u32,
}

impl QRInfoTestGenerator {
    pub fn new(network: Network, base_height: u32) -> Self {
        Self { network, base_height }
    }
    
    /// Generate QRInfo for normal sync scenario
    pub fn generate_normal_sync(&self, tip_height: u32) -> QRInfo {
        let base_hash = self.block_hash_at_height(self.base_height);
        let tip_hash = self.block_hash_at_height(tip_height);
        
        QRInfo {
            // Generate required snapshots at h-c, h-2c, h-3c
            quorum_snapshot_at_h_minus_c: self.generate_snapshot(tip_height - self.cycle_length()),
            quorum_snapshot_at_h_minus_2c: self.generate_snapshot(tip_height - 2 * self.cycle_length()),
            quorum_snapshot_at_h_minus_3c: self.generate_snapshot(tip_height - 3 * self.cycle_length()),
            
            // Generate required diffs
            mn_list_diff_tip: self.generate_diff(tip_height - 1, tip_height),
            mn_list_diff_h: self.generate_diff(tip_height - 8, tip_height),
            mn_list_diff_at_h_minus_c: self.generate_diff(tip_height - self.cycle_length() - 8, tip_height - self.cycle_length()),
            mn_list_diff_at_h_minus_2c: self.generate_diff(tip_height - 2 * self.cycle_length() - 8, tip_height - 2 * self.cycle_length()),
            mn_list_diff_at_h_minus_3c: self.generate_diff(tip_height - 3 * self.cycle_length() - 8, tip_height - 3 * self.cycle_length()),
            
            // Optional h-4c data for extra validation
            quorum_snapshot_and_mn_list_diff_at_h_minus_4c: Some((
                self.generate_snapshot(tip_height - 4 * self.cycle_length()),
                self.generate_diff(tip_height - 4 * self.cycle_length() - 8, tip_height - 4 * self.cycle_length())
            )),
            
            // Last commitment per index for rotating quorums
            last_commitment_per_index: self.generate_last_commitments(tip_height),
            
            // Additional snapshots and diffs
            quorum_snapshot_list: vec![],
            mn_list_diff_list: vec![],
        }
    }
    
    /// Generate QRInfo with rotation cycle
    pub fn generate_with_rotation(&self, tip_height: u32) -> QRInfo {
        let mut qr_info = self.generate_normal_sync(tip_height);
        
        // Add rotating quorum data
        qr_info.last_commitment_per_index = self.generate_rotating_commitments(tip_height);
        
        qr_info
    }
    
    fn cycle_length(&self) -> u32 {
        match self.network {
            Network::Dash => 576,  // ~24 hours at 2.5min blocks
            Network::Testnet => 24,
            _ => 24
        }
    }
    
    fn generate_snapshot(&self, height: u32) -> QuorumSnapshot {
        // Generate realistic quorum snapshot
        let mut active_quorum_members = Vec::new();
        
        // Add some test quorum members
        for i in 0..10 {
            active_quorum_members.push([i as u8; 32]); // Dummy member IDs
        }
        
        QuorumSnapshot {
            active_quorum_members,
        }
    }
    
    fn generate_diff(&self, base_height: u32, tip_height: u32) -> MnListDiff {
        let base_hash = self.block_hash_at_height(base_height);
        let tip_hash = self.block_hash_at_height(tip_height);
        
        MnListDiff {
            base_block_hash: base_hash,
            block_hash: tip_hash,
            cb_tx_merkle_tree: vec![],
            cb_tx: None,
            deleted_mns: vec![],
            mn_list: vec![],
            deleted_quorums: vec![],
            new_quorums: self.generate_test_quorums(tip_height),
        }
    }
    
    fn generate_last_commitments(&self, tip_height: u32) -> Vec<QuorumEntry> {
        // Generate test quorum entries for last commitments
        (0..4).map(|i| {
            QuorumEntry {
                llmq_type: LLMQType::Llmqtype400_60,
                quorum_hash: self.block_hash_at_height(tip_height - i * 100),
                quorum_index: Some(i as u32),
                quorum_public_key: BLSPublicKey::default(),
                quorum_vvec_hash: [0u8; 32],
                quorum_sig: BLSSignature::default(),
                sig: BLSSignature::default(),
            }
        }).collect()
    }
    
    fn block_hash_at_height(&self, height: u32) -> BlockHash {
        // Generate deterministic test block hashes
        let mut hasher = Sha256::new();
        hasher.update(b"test_block_");
        hasher.update(&height.to_le_bytes());
        let hash = hasher.finalize();
        BlockHash::from_byte_array(hash.into())
    }
}
```

**Test File**: `tests/fixtures/test_qr_info_generation.rs`
```rust
#[test]
fn test_qr_info_generation_normal() {
    let generator = QRInfoTestGenerator::new(Network::Testnet, 1000);
    let qr_info = generator.generate_normal_sync(2000);
    
    // Verify structure
    assert_eq!(qr_info.mn_list_diff_list.len(), 0); // Normal sync has no extra diffs
    assert!(!qr_info.last_commitment_per_index.is_empty());
    assert!(qr_info.quorum_snapshot_and_mn_list_diff_at_h_minus_4c.is_some());
    
    // Verify diffs are properly constructed
    assert_ne!(qr_info.mn_list_diff_tip.base_block_hash, qr_info.mn_list_diff_tip.block_hash);
}

#[test]
fn test_qr_info_generation_with_rotation() {
    let generator = QRInfoTestGenerator::new(Network::Testnet, 1000);  
    let qr_info = generator.generate_with_rotation(2000);
    
    // Should have rotating quorum commitments
    assert!(!qr_info.last_commitment_per_index.is_empty());
    
    // Verify quorum types are appropriate for rotation
    for commitment in &qr_info.last_commitment_per_index {
        assert!(commitment.llmq_type.is_rotating_quorum_type());
    }
}
```

#### 3.2 Integration Test Suite

**File**: `tests/integration/test_qr_info_sync_flow.rs`
```rust
use dashcore::Network;
use dash_spv::test_utils::*;

#[tokio::test]
async fn test_complete_qr_info_sync_flow() {
    let config = test_client_config(Network::Testnet);
    let mut client = create_test_client(config).await;
    
    // Set up mock network to provide QRInfo responses
    let mut mock_network = MockNetworkManager::new();
    mock_network.expect_request_qr_info()
        .returning(|base, tip, extra| {
            let generator = QRInfoTestGenerator::new(Network::Testnet, 0);
            let qr_info = generator.generate_normal_sync(1000);
            // Simulate async network response
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(100)).await;
                client.handle_qr_info(qr_info).await;
            });
            Ok(())
        });
    
    // Start sync
    client.start_sync().await.unwrap();
    
    // Wait for completion  
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        client.wait_for_masternode_sync()
    ).await.unwrap();
    
    assert!(result.is_ok());
    
    // Verify final state
    let engine = client.masternode_list_engine().unwrap();
    assert!(!engine.masternode_lists.is_empty());
    assert!(!engine.known_snapshots.is_empty());
}

#[tokio::test]
async fn test_qr_info_error_recovery() {
    let mut client = create_test_client_with_error_network().await;
    
    // First QRInfo request fails
    client.network.set_next_qr_info_response(Err(NetworkError::Timeout));
    
    let sync_result = tokio::time::timeout(
        Duration::from_secs(5),
        client.start_sync()
    ).await;
    
    // Should handle error gracefully and retry
    assert!(sync_result.is_err() || sync_result.unwrap().is_err());
    
    // Second attempt succeeds
    let qr_info = QRInfoTestGenerator::new(Network::Testnet, 0).generate_normal_sync(1000);
    client.network.set_next_qr_info_response(Ok(qr_info));
    
    let retry_result = client.retry_sync().await;
    assert!(retry_result.is_ok());
}

#[tokio::test]
async fn test_qr_info_vs_mn_diff_compatibility() {
    // Test that QRInfo and MnListDiff can work together
    let mut client = create_test_client(test_client_config(Network::Testnet)).await;
    
    // Start with some MnListDiff data
    let mn_diff = create_test_mn_list_diff(0, 500);
    client.handle_mn_list_diff(mn_diff).await.unwrap();
    
    // Then add QRInfo data
    let qr_info = QRInfoTestGenerator::new(Network::Testnet, 500).generate_normal_sync(1000);
    client.handle_qr_info(qr_info).await.unwrap();
    
    // Verify combined state is consistent
    let engine = client.masternode_list_engine().unwrap();
    
    // Should have masternode lists from both sources
    assert!(engine.masternode_lists.contains_key(&500)); // From MnListDiff
    assert!(engine.masternode_lists.contains_key(&1000)); // From QRInfo
    
    // State should be internally consistent
    let all_heights: Vec<u32> = engine.masternode_lists.keys().cloned().collect();
    assert!(all_heights.windows(2).all(|w| w[0] < w[1])); // Sorted
}
```

### 4. Configuration and Feature Flags

#### 4.1 Add Configuration Options

**File**: `dash-spv/src/client/config.rs`
```rust
#[derive(Clone, Debug)]
pub struct ClientConfig {
    // ... existing fields ...
    
    /// Enable QRInfo-based masternode sync (default: true)
    pub enable_qr_info: bool,
    
    /// Fall back to MnListDiff if QRInfo fails (default: true)
    pub qr_info_fallback: bool,
    
    /// Request extra share data in QRInfo (default: true for better validation)
    pub qr_info_extra_share: bool,
    
    /// Timeout for QRInfo requests (default: 30 seconds)
    pub qr_info_timeout: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            // ... existing defaults ...
            enable_qr_info: true,
            qr_info_fallback: true,
            qr_info_extra_share: true,
            qr_info_timeout: Duration::from_secs(30),
        }
    }
}
```

**Test File**: `tests/config/test_qr_info_config.rs`
```rust
#[test]
fn test_qr_info_config_defaults() {
    let config = ClientConfig::default();
    assert!(config.enable_qr_info);
    assert!(config.qr_info_fallback);
    assert!(config.qr_info_extra_share);
    assert_eq!(config.qr_info_timeout, Duration::from_secs(30));
}

#[test] 
fn test_qr_info_config_disabled() {
    let mut config = ClientConfig::default();
    config.enable_qr_info = false;
    
    // When QRInfo is disabled, should fall back to old MnListDiff behavior
    let client = create_test_client(config);
    // Test that only MnListDiff requests are made
}
```

## Success Criteria

### Functional Requirements
- [ ] QRInfo messages can be parsed and processed successfully
- [ ] QRInfo data integrates properly with masternode list engine
- [ ] Block hash lookups work efficiently with storage layer
- [ ] Existing MnListDiff functionality remains unbroken
- [ ] Configuration options work as expected

### Performance Requirements  
- [ ] QRInfo processing completes within 5 seconds for typical data
- [ ] Block hash lookup performance < 1ms average
- [ ] Memory usage increase < 10% during QRInfo processing
- [ ] No performance regression in existing sync paths

### Quality Requirements
- [ ] >90% test coverage for all new code
- [ ] All integration tests pass with real QRInfo data
- [ ] Error handling covers all failure scenarios
- [ ] Logging provides sufficient debugging information

## Risk Mitigation

### High Risk: QRInfo Protocol Complexity
**Risk**: QRInfo message format is complex with many nested structures
**Mitigation**: 
- Use real network test vectors for validation
- Implement comprehensive parsing tests
- Add detailed error messages for parsing failures

### Medium Risk: Storage Performance Impact  
**Risk**: Block hash index might impact storage performance
**Mitigation**:
- Implement lazy index building
- Add configuration option to disable if needed
- Monitor storage performance in tests

### Low Risk: Configuration Complexity
**Risk**: Too many configuration options might confuse users
**Mitigation**:
- Provide sensible defaults for all options
- Clear documentation for each setting
- Simple enable/disable for main QRInfo functionality

## Next Steps

Upon completion of Phase 1:
1. **Validate** all tests pass with real network data
2. **Performance** benchmark QRInfo processing vs MnListDiff
3. **Documentation** update API docs and examples
4. **Phase 2** proceed to engine discovery integration

The foundation established in Phase 1 enables the more advanced optimizations in subsequent phases while maintaining full backward compatibility and comprehensive test coverage.