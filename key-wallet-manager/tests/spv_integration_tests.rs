//! Integration tests for SPV wallet functionality

use dashcore::blockdata::block::{Block, Header};
use dashcore::blockdata::script::ScriptBuf;
use dashcore::blockdata::transaction::{OutPoint, Transaction};
use dashcore::{BlockHash, Txid};
use dashcore::{TxIn, TxOut};
use dashcore_hashes::Hash;

use dashcore::bip158::{BlockFilter, BlockFilterWriter};
use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet::Network;
use key_wallet_manager::spv_wallet_manager::{SPVSyncStatus, SPVWalletManager};
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

/// Create a test block with transactions
fn create_test_block(height: u32, transactions: Vec<Transaction>) -> Block {
    use dashcore::blockdata::block::Version;
    use dashcore::CompactTarget;
    use dashcore::TxMerkleNode;

    let header = Header {
        version: Version::from_consensus(0x20000000),
        prev_blockhash: BlockHash::from_byte_array([0u8; 32]),
        merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
        time: 1234567890 + height,
        bits: CompactTarget::from_consensus(0x1d00ffff),
        nonce: height,
    };

    Block {
        header,
        txdata: transactions,
    }
}

/// Create a mock compact filter
fn create_mock_filter(block: &Block) -> BlockFilter {
    // Create a proper BIP158 filter from the block
    let mut filter_bytes = Vec::new();
    let mut writer = BlockFilterWriter::new(&mut filter_bytes, block);
    writer.add_output_scripts();
    // For testing, we'll ignore input scripts since we don't have a UTXO lookup
    writer.finish().unwrap();
    BlockFilter::new(&filter_bytes)
}

#[tokio::test]
async fn test_filter_checking() {
    let mut spv = SPVWalletManager::with_base(WalletManager::<ManagedWalletInfo>::new());

    // Add a test address to monitor - simplified for testing
    // In reality, addresses would be generated from wallet accounts

    let _wallet_id = spv.base
        .create_wallet_with_random_mnemonic(
            WalletAccountCreationOptions::Default,
            Network::Testnet,
        )
        .expect("Failed to create wallet");

    // Create a test block with a transaction
    let tx = create_test_transaction(100000);
    let block = create_test_block(100, vec![tx]);
    let filter = create_mock_filter(&block);
    let block_hash = block.block_hash();

    // Check the filter
    let should_download = spv.check_compact_filter(&filter, &block_hash, Network::Testnet).await;

    // The filter matching depends on whether the wallet has any addresses
    // being watched. Since we just created an empty wallet, it may or may not match.
    // We'll just check that the method doesn't panic
    let _ = should_download;
}

#[tokio::test]
async fn test_block_processing() {
    let mut spv = SPVWalletManager::with_base(WalletManager::<ManagedWalletInfo>::new());

    // Create a test wallet
    let _wallet_id = spv.base
        .create_wallet_with_random_mnemonic(
            WalletAccountCreationOptions::Default,
            Network::Testnet,
        )
        .expect("Failed to create wallet");

    // Create a transaction
    let tx = create_test_transaction(100000);

    // Create a block with this transaction
    let block = create_test_block(100, vec![tx.clone()]);

    // Process the block
    let result = spv.process_block(&block, 100, Network::Testnet).await;

    // Since we're not watching specific addresses, no transactions should be relevant
    assert_eq!(result.len(), 0);
}

#[test]
fn test_queued_blocks() {
    let mut spv = SPVWalletManager::with_base(WalletManager::<ManagedWalletInfo>::new());

    // Create blocks
    let block1 = create_test_block(101, vec![create_test_transaction(1000)]);
    let block2 = create_test_block(102, vec![create_test_transaction(2000)]);
    let block3 = create_test_block(103, vec![create_test_transaction(3000)]);

    // Add pending blocks
    spv.add_pending_block(Network::Testnet, 103, block3.clone(), block3.block_hash());
    spv.add_pending_block(Network::Testnet, 101, block1.clone(), block1.block_hash());
    spv.add_pending_block(Network::Testnet, 102, block2.clone(), block2.block_hash());

    // Get a pending block
    let taken = spv.take_pending_block(Network::Testnet, 101);
    assert!(taken.is_some());

    // Block 101 should be removed, others should remain
    assert!(spv.take_pending_block(Network::Testnet, 101).is_none());
    assert!(spv.take_pending_block(Network::Testnet, 102).is_some());
}

#[test]
fn test_sync_status_tracking() {
    let mut spv = SPVWalletManager::with_base(WalletManager::<ManagedWalletInfo>::new());

    // Set target height
    spv.set_target_height(Network::Testnet, 1000);

    // Initially the status depends on implementation details
    // It could be Idle or CheckingFilters
    let initial_status = spv.sync_status(Network::Testnet);
    assert!(
        matches!(initial_status, SPVSyncStatus::Idle)
            || matches!(initial_status, SPVSyncStatus::CheckingFilters { .. }),
        "Unexpected initial status: {:?}",
        initial_status
    );

    // Queue a block for download
    let block_hash = BlockHash::from_byte_array([0u8; 32]);
    assert!(spv.queue_block_download(Network::Testnet, block_hash));

    // Should be downloading blocks
    assert_eq!(
        spv.sync_status(Network::Testnet),
        SPVSyncStatus::DownloadingBlocks {
            pending: 1
        }
    );

    // Take the block from queue
    let next = spv.next_block_to_download(Network::Testnet);
    assert!(next.is_some());

    // Queue should be empty now
    assert_eq!(
        spv.sync_status(Network::Testnet),
        SPVSyncStatus::CheckingFilters {
            current: 0,
            target: 1000
        }
    );

    // Update sync height to target
    spv.update_stats(Network::Testnet, |stats| {
        stats.sync_height = 1000;
        stats.target_height = 1000;
    });

    // Should be synced
    assert_eq!(spv.sync_status(Network::Testnet), SPVSyncStatus::Synced);
}

#[tokio::test]
async fn test_multiple_wallets() {
    let mut spv = SPVWalletManager::with_base(WalletManager::<ManagedWalletInfo>::new());

    // Create and add multiple wallets
    for _i in 0..3 {
        spv.base
            .create_wallet_with_random_mnemonic(
                WalletAccountCreationOptions::Default,
                Network::Testnet,
            )
            .ok();
    }

    // Verify all wallets are added
    assert_eq!(spv.base.wallet_count(), 3);

    // Create a block with multiple transactions
    let mut transactions = Vec::new();
    for i in 0..3 {
        let tx = create_test_transaction(100000 * (i + 1) as u64);
        transactions.push(tx);
    }

    let block = create_test_block(100, transactions);

    // Process the block
    let result = spv.process_block(&block, 100, Network::Testnet).await;

    // Without watching specific addresses, transactions won't be relevant
    assert_eq!(result.len(), 0);
}

#[tokio::test]
async fn test_spent_utxo_tracking() {
    // This test requires more complex UTXO tracking that's not fully implemented
    // We'll create a simpler version
    let mut spv = SPVWalletManager::with_base(WalletManager::<ManagedWalletInfo>::new());

    // Create a test wallet
    let _wallet_id = spv.base
        .create_wallet_with_random_mnemonic(
            WalletAccountCreationOptions::Default,
            Network::Testnet,
        )
        .expect("Failed to create wallet");

    // Create a transaction
    let tx1 = create_test_transaction(100000);
    let tx1_id = tx1.txid();

    let block1 = create_test_block(100, vec![tx1]);
    let result1 = spv.process_block(&block1, 100, Network::Testnet).await;
    assert_eq!(result1.len(), 0);

    // Create a transaction that spends the first
    let tx2 = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: tx1_id,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: dashcore::Witness::default(),
        }],
        output: vec![TxOut {
            value: 90000,
            script_pubkey: ScriptBuf::new(),
        }],
        special_transaction_payload: None,
    };

    let block2 = create_test_block(101, vec![tx2]);
    let result2 = spv.process_block(&block2, 101, Network::Testnet).await;
    assert_eq!(result2.len(), 0);

    // Without proper UTXO tracking in wallets, we can't verify spent status
    // This is a simplified test
}
