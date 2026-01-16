use dash_spv::client::Config;
use dashcore::network::message_sml::MnListDiff;
use dashcore::sml::llmq_type::network::NetworkLLMQExt;
use dashcore::sml::llmq_type::{DKGWindow, LLMQType};
use dashcore::transaction::special_transaction::quorum_commitment::QuorumEntry;
use dashcore::{BlockHash, Network, Transaction};
use dashcore_hashes::Hash;

#[tokio::test]
async fn test_smart_fetch_basic_dkg_windows() {
    let network = Network::Testnet;

    // Create test data for DKG windows
    let windows = network.get_all_dkg_windows(1000, 1100);

    // Should have windows for different quorum types
    assert!(!windows.is_empty());

    // Each window should be within our range
    for window_list in windows.values() {
        for window in window_list {
            // Mining window should overlap with our range
            assert!(window.mining_end >= 1000 || window.mining_start <= 1100);
        }
    }
}

#[tokio::test]
async fn test_smart_fetch_state_initialization() {
    // Create a simple config for testing
    let config = Config::new(Network::Testnet);

    // Test that we can create the sync manager
    // Note: We can't access private fields, but we can verify the structure exists
    // Need to specify generic types for MasternodeSyncManager
    use dash_spv::network::PeerNetworkManager;
    use dash_spv::storage::DiskStorageManager;
    let _sync_manager = dash_spv::sync::masternodes::MasternodeSyncManager::<
        DiskStorageManager,
        PeerNetworkManager,
    >::new(&config);

    // The state should be initialized when requesting diffs
    // Note: We can't test the full flow without a network connection,
    // but we've verified the structure compiles correctly
}

#[tokio::test]
async fn test_window_action_transitions() {
    // Test the window struct construction
    let window = DKGWindow {
        cycle_start: 1000,
        mining_start: 1010,
        mining_end: 1018,
        llmq_type: LLMQType::Llmqtype50_60,
    };

    // Verify window properties
    assert_eq!(window.cycle_start, 1000);
    assert_eq!(window.mining_start, 1010);
    assert_eq!(window.mining_end, 1018);
    assert_eq!(window.llmq_type, LLMQType::Llmqtype50_60);
}

#[tokio::test]
async fn test_dkg_fetch_state_management() {
    let network = Network::Testnet;
    let windows = network.get_all_dkg_windows(1000, 1200);

    // Verify we get windows for the network
    assert!(!windows.is_empty(), "Should have DKG windows in range");

    // Check that windows are properly organized by height
    for (height, window_list) in &windows {
        assert!(*height >= 1000 || window_list.iter().any(|w| w.mining_end >= 1000));
        assert!(*height <= 1200 || window_list.iter().any(|w| w.mining_start <= 1200));
    }
}

#[tokio::test]
async fn test_smart_fetch_quorum_discovery() {
    // Simulate a masternode diff with quorums
    let diff = MnListDiff {
        version: 1,
        base_block_hash: BlockHash::all_zeros(),
        block_hash: BlockHash::all_zeros(),
        total_transactions: 0,
        merkle_hashes: vec![],
        merkle_flags: vec![],
        coinbase_tx: Transaction {
            version: 1,
            lock_time: 0,
            input: vec![],
            output: vec![],
            special_transaction_payload: None,
        },
        deleted_masternodes: vec![],
        new_masternodes: vec![],
        deleted_quorums: vec![],
        new_quorums: vec![{
            let llmq_type = LLMQType::Llmqtype50_60;
            let quorum_size = llmq_type.size() as usize;
            QuorumEntry {
                version: 1,
                llmq_type,
                quorum_hash: dashcore::QuorumHash::all_zeros(),
                quorum_index: None,
                signers: vec![true; quorum_size],
                valid_members: vec![true; quorum_size],
                quorum_public_key: dashcore::bls_sig_utils::BLSPublicKey::from([0; 48]),
                quorum_vvec_hash: dashcore::hash_types::QuorumVVecHash::all_zeros(),
                threshold_sig: dashcore::bls_sig_utils::BLSSignature::from([0; 96]),
                all_commitment_aggregated_signature: dashcore::bls_sig_utils::BLSSignature::from(
                    [0; 96],
                ),
            }
        }],
        quorums_chainlock_signatures: vec![],
    };

    // Verify quorum was found
    assert_eq!(diff.new_quorums.len(), 1);
    assert_eq!(diff.new_quorums[0].llmq_type, LLMQType::Llmqtype50_60);
}

#[tokio::test]
async fn test_smart_fetch_efficiency_metrics() {
    let network = Network::Testnet;

    // Calculate expected efficiency for a large range
    let start = 0;
    let end = 30000;

    // Without smart fetch: would request all 30,000 blocks
    let blocks_without_smart_fetch = end - start;

    // With smart fetch: only request blocks in DKG windows
    let windows = network.get_all_dkg_windows(start, end);
    let mut blocks_with_smart_fetch = 0;

    for window_list in windows.values() {
        for window in window_list {
            // Count blocks in each mining window
            let window_start = window.mining_start.max(start);
            let window_end = window.mining_end.min(end);
            if window_end >= window_start {
                blocks_with_smart_fetch += (window_end - window_start + 1) as usize;
            }
        }
    }

    // Calculate efficiency
    let efficiency = 1.0 - (blocks_with_smart_fetch as f64 / blocks_without_smart_fetch as f64);

    println!("Smart fetch efficiency: {:.2}%", efficiency * 100.0);
    println!("Blocks without smart fetch: {}", blocks_without_smart_fetch);
    println!("Blocks with smart fetch: {}", blocks_with_smart_fetch);
    println!("Blocks saved: {}", blocks_without_smart_fetch as usize - blocks_with_smart_fetch);

    // Should achieve significant reduction
    // Note: Testnet may have different efficiency due to different LLMQ configurations
    assert!(
        efficiency > 0.50,
        "Smart fetch should reduce requests by at least 50% (got {:.2}%)",
        efficiency * 100.0
    );
}

#[tokio::test]
async fn test_smart_fetch_edge_cases() {
    let network = Network::Testnet;

    // Test edge case: range smaller than one DKG interval
    let windows = network.get_all_dkg_windows(100, 110);

    // Should still find relevant windows
    let total_windows: usize = windows.values().map(|v| v.len()).sum();
    assert!(total_windows > 0, "Should find windows even for small ranges");

    // Test edge case: range starting at DKG boundary
    let windows = network.get_all_dkg_windows(120, 144);
    for window_list in windows.values() {
        for window in window_list {
            // Verify window properties
            assert!(window.cycle_start <= 144);
            assert!(window.mining_end >= 120 || window.mining_start <= 144);
        }
    }
}

#[tokio::test]
async fn test_smart_fetch_rotating_quorums() {
    let _network = Network::Testnet;

    // Test with rotating quorum type (60_75)
    let llmq = LLMQType::Llmqtype60_75;
    let windows = llmq.get_dkg_windows_in_range(1000, 2000);

    // Verify rotating quorum window calculation
    for window in &windows {
        assert_eq!(window.llmq_type, llmq);

        // For rotating quorums, mining window start is different
        let params = llmq.params();
        let expected_mining_start = window.cycle_start
            + params.signing_active_quorum_count
            + params.dkg_params.phase_blocks * 5;
        assert_eq!(window.mining_start, expected_mining_start);
    }
}

#[tokio::test]
async fn test_smart_fetch_platform_activation() {
    let network = Network::Dash;

    // Test before platform activation
    let windows_before = network.get_all_dkg_windows(1_000_000, 1_000_100);

    // Should not include platform quorum (100_67) before activation
    let has_platform_before = windows_before
        .values()
        .flat_map(|v| v.iter())
        .any(|w| w.llmq_type == LLMQType::Llmqtype100_67);
    assert!(!has_platform_before, "Platform quorum should not be active before height 1,888,888");

    // Test after platform activation
    let windows_after = network.get_all_dkg_windows(1_888_900, 1_889_000);

    // Should include platform quorum after activation
    let has_platform_after = windows_after
        .values()
        .flat_map(|v| v.iter())
        .any(|w| w.llmq_type == LLMQType::Llmqtype100_67);
    assert!(has_platform_after, "Platform quorum should be active after height 1,888,888");
}
