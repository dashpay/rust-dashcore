//! Integration tests for SPV wallet functionality

use dashcore::blockdata::block::{Block, Header, Version};
use dashcore::blockdata::script::ScriptBuf;
use dashcore::blockdata::transaction::{OutPoint, Transaction};
use dashcore::pow::CompactTarget;
use dashcore::{BlockHash, Txid};
use dashcore::{TxIn, TxOut};
use dashcore_hashes::Hash;

use dashcore::bip158::{BlockFilter, BlockFilterWriter};
use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet::Network;
use key_wallet_manager::wallet_interface::WalletInterface;
use key_wallet_manager::wallet_manager::WalletManager;

/// Create a test transaction
fn create_test_transaction(value: u64) -> Transaction {
    Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([1u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: dashcore::Witness::default(),
        }],
        output: vec![TxOut {
            value,
            script_pubkey: ScriptBuf::new(),
        }],
        special_transaction_payload: None,
    }
}

/// Create a test block
fn create_test_block(height: u32, transactions: Vec<Transaction>) -> Block {
    Block {
        header: Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::from_byte_array([0u8; 32]),
            merkle_root: dashcore::TxMerkleNode::from_byte_array([0u8; 32]),
            time: height,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 0,
        },
        txdata: transactions,
    }
}

/// Create a mock filter that matches everything (for testing)
fn create_mock_filter(block: &Block) -> BlockFilter {
    let mut content = Vec::new();
    let mut writer = BlockFilterWriter::new(&mut content, block);

    // Add output scripts from the block
    writer.add_output_scripts();

    // Finish writing and construct the filter
    writer.finish().expect("Failed to finish filter");
    BlockFilter::new(&content)
}

#[tokio::test]
async fn test_filter_checking() {
    let mut manager = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);

    // Add a test address to monitor - simplified for testing
    // In reality, addresses would be generated from wallet accounts

    let _wallet_id = manager
        .create_wallet_with_random_mnemonic(WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet");

    // Create a test block with a transaction
    let tx = create_test_transaction(100000);
    let block = create_test_block(100, vec![tx]);
    let filter = create_mock_filter(&block);
    let block_hash = block.block_hash();

    // Check the filter
    let should_download = manager.check_compact_filter(&filter, &block_hash).await;

    // The filter matching depends on whether the wallet has any addresses
    // being watched. Since we just created an empty wallet, it may or may not match.
    // We'll just check that the method doesn't panic
    let _ = should_download;

    // Test filter caching - calling again should use cached result
    let should_download_cached = manager.check_compact_filter(&filter, &block_hash).await;
    assert_eq!(should_download, should_download_cached, "Cached result should match original");
}

#[tokio::test]
async fn test_block_processing() {
    let mut manager = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);

    // Create a test wallet
    let _wallet_id = manager
        .create_wallet_with_random_mnemonic(WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet");

    // Create a transaction
    let tx = create_test_transaction(100000);

    // Create a block with this transaction
    let block = create_test_block(100, vec![tx.clone()]);

    // Process the block
    let result = manager.process_block(&block, 100).await;

    // Since we're not watching specific addresses, no transactions should be relevant
    assert_eq!(result.len(), 0);
}

#[tokio::test]
async fn test_filter_caching() {
    let mut manager = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);

    // Create a wallet with some addresses
    let _wallet_id = manager
        .create_wallet_with_random_mnemonic(WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet");

    // Create multiple blocks with different hashes
    let block1 = create_test_block(100, vec![create_test_transaction(1000)]);
    let block2 = create_test_block(101, vec![create_test_transaction(2000)]);

    let filter1 = create_mock_filter(&block1);
    let filter2 = create_mock_filter(&block2);

    let hash1 = block1.block_hash();
    let hash2 = block2.block_hash();

    // Check filters for both blocks
    let result1 = manager.check_compact_filter(&filter1, &hash1).await;
    let result2 = manager.check_compact_filter(&filter2, &hash2).await;

    // Check again - should use cached results
    let cached1 = manager.check_compact_filter(&filter1, &hash1).await;
    let cached2 = manager.check_compact_filter(&filter2, &hash2).await;

    // Cached results should match originals
    assert_eq!(result1, cached1, "Cached result for block1 should match");
    assert_eq!(result2, cached2, "Cached result for block2 should match");
}

fn assert_wallet_heights(manager: &WalletManager<ManagedWalletInfo>, expected_height: u32) {
    assert_eq!(manager.current_height(), expected_height, "height should be {}", expected_height);
    for wallet_info in manager.get_all_wallet_infos().values() {
        assert_eq!(
            wallet_info.synced_height(),
            expected_height,
            "synced_height should be {}",
            expected_height
        );
    }
}

/// Test that the wallet heights are updated after block processing.
#[tokio::test]
async fn test_height_updated_after_block_processing() {
    let mut manager = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);

    // Create a wallet
    let _wallet_id = manager
        .create_wallet_with_random_mnemonic(WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet");

    // Initial state - no blocks processed yet
    assert_wallet_heights(&manager, 0);

    for height in [1000, 2000, 3000] {
        let block = create_test_block(height, vec![create_test_transaction(1000)]);
        manager.process_block(&block, height).await;
        assert_wallet_heights(&manager, height);
    }
}
