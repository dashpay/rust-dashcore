//! Tests for terminal block functionality with pre-calculated masternode data.

use dash_spv::sync::terminal_blocks::TerminalBlockManager;
use dashcore::Network;

#[test]
fn test_terminal_block_data_loading() {
    // Test testnet terminal blocks
    let testnet_manager = TerminalBlockManager::new(Network::Testnet);
    
    // Check that we have pre-calculated data for terminal block 900000
    assert!(testnet_manager.has_masternode_data(900000), "Should have terminal block 900000");
    
    // Get the data and verify it's valid
    let terminal_data = testnet_manager.get_masternode_data(900000).unwrap();
    assert_eq!(terminal_data.height, 900000);
    assert_eq!(terminal_data.masternode_count, 514);
    assert_eq!(terminal_data.merkle_root_mn_list, "bb98f57eb724d5447b979cf2107f15b872a7289d95fb66ba2a92774e1f4b7748");
    
    // Test mainnet terminal blocks
    let mainnet_manager = TerminalBlockManager::new(Network::Dash);
    
    // Currently we don't have pre-calculated mainnet data in the embedded files
    // This is expected - mainnet data can be added later if needed
}

#[test]
fn test_find_best_terminal_block_with_data() {
    let manager = TerminalBlockManager::new(Network::Testnet);
    
    // Test finding best terminal block for various heights
    // Note: We only have masternode data for block 900000
    let test_cases = vec![
        (899999, None),          // Before terminal block with data
        (900000, Some(900000)),  // Exact match at terminal block with data
        (1000000, Some(900000)), // Beyond highest terminal block
        (100000, None),          // Before any terminal block with data
    ];
    
    for (target_height, expected_height) in test_cases {
        let best = manager.find_best_terminal_block_with_data(target_height);
        match expected_height {
            Some(expected) => {
                assert!(best.is_some(), "Expected terminal block for height {}", target_height);
                assert_eq!(best.unwrap().height, expected, 
                    "Wrong terminal block for height {}: expected {}, got {}", 
                    target_height, expected, best.unwrap().height);
            }
            None => {
                assert!(best.is_none(), "Expected no terminal block for height {}", target_height);
            }
        }
    }
}

#[test]
fn test_terminal_block_validation() {
    use dash_spv::sync::terminal_block_data::{TerminalBlockMasternodeState, StoredMasternodeEntry};
    
    // Create a valid terminal block state
    let valid_state = TerminalBlockMasternodeState {
        height: 100000,
        block_hash: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        merkle_root_mn_list: "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
        masternode_list: vec![
            StoredMasternodeEntry {
                pro_tx_hash: "2222222222222222222222222222222222222222222222222222222222222222".to_string(),
                service: "192.168.1.1:9999".to_string(),
                pub_key_operator: "333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333".to_string(),
                voting_address: "yXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".to_string(),
                is_valid: true,
                n_type: 0,
            }
        ],
        masternode_count: 1,
        fetched_at: 1234567890,
    };
    
    // Should validate successfully
    assert!(valid_state.validate().is_ok());
    
    // Test invalid block hash length
    let mut invalid_state = valid_state.clone();
    invalid_state.block_hash = "00000".to_string();
    assert!(invalid_state.validate().is_err());
    
    // Test masternode count mismatch
    let mut invalid_state = valid_state.clone();
    invalid_state.masternode_count = 2; // But only 1 in list
    assert!(invalid_state.validate().is_err());
    
    // Test invalid ProTxHash
    let mut invalid_state = valid_state.clone();
    invalid_state.masternode_list[0].pro_tx_hash = "invalid".to_string();
    assert!(invalid_state.validate().is_err());
    
    // Test invalid service address
    let mut invalid_state = valid_state.clone();
    invalid_state.masternode_list[0].service = "no-port".to_string();
    assert!(invalid_state.validate().is_err());
    
    // Test invalid BLS key length
    let mut invalid_state = valid_state.clone();
    invalid_state.masternode_list[0].pub_key_operator = "tooshort".to_string();
    assert!(invalid_state.validate().is_err());
    
    // Test invalid masternode type
    let mut invalid_state = valid_state;
    invalid_state.masternode_list[0].n_type = 5;
    assert!(invalid_state.validate().is_err());
}

#[test]
fn test_data_manager_validation() {
    use dash_spv::sync::terminal_block_data::{TerminalBlockDataManager, TerminalBlockMasternodeState, StoredMasternodeEntry};
    
    let mut manager = TerminalBlockDataManager::new();
    
    // Add a valid state
    let valid_state = TerminalBlockMasternodeState {
        height: 100000,
        block_hash: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        merkle_root_mn_list: "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
        masternode_list: vec![],
        masternode_count: 0,
        fetched_at: 1234567890,
    };
    
    manager.add_state(valid_state);
    assert!(manager.has_state(100000));
    
    // Try to add an invalid state (should be rejected)
    let invalid_state = TerminalBlockMasternodeState {
        height: 200000,
        block_hash: "invalid".to_string(), // Too short
        merkle_root_mn_list: "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
        masternode_list: vec![],
        masternode_count: 0,
        fetched_at: 1234567890,
    };
    
    manager.add_state(invalid_state);
    assert!(!manager.has_state(200000), "Invalid state should not be added");
}