//! Integration tests for SPV wallet functionality

use dashcore::bip158::{BlockFilter, BlockFilterWriter};
use dashcore::blockdata::block::{Block, Header, Version};
use dashcore::blockdata::script::ScriptBuf;
use dashcore::blockdata::transaction::Transaction;
use dashcore::constants::COINBASE_MATURITY;
use dashcore::pow::CompactTarget;
use dashcore::{BlockHash, OutPoint, TxIn, TxOut, Txid};
use dashcore_hashes::Hash;
use dashcore_test_utils::create_transaction_to_address;
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
    let _wallet_id = manager
        .create_wallet_with_random_mnemonic(WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet");

    let addresses = manager.monitored_addresses();
    assert!(!addresses.is_empty());
    let external = dashcore::Address::p2pkh(
        &dashcore::PublicKey::from_slice(&[0x02; 33]).expect("valid pubkey"),
        Network::Testnet,
    );

    let addresses_before = manager.monitored_addresses();
    assert!(!addresses_before.is_empty());

    let tx1 = create_transaction_to_address(&addresses[0], 100_000);
    let tx2 = create_transaction_to_address(&addresses[1], 200_000);
    let tx3 = create_transaction_to_address(&external, 300_000);

    let block = create_test_block(100, vec![tx1.clone(), tx2.clone(), tx3.clone()]);
    let result = manager.process_block(&block, 100).await;

    assert_eq!(result.relevant_txids.len(), 2);
    assert!(result.relevant_txids.contains(&tx1.txid()));
    assert!(result.relevant_txids.contains(&tx2.txid()));
    assert!(!result.relevant_txids.contains(&tx3.txid()));
    assert_eq!(result.new_addresses.len(), 2);

    let addresses_after = manager.monitored_addresses();
    let actual_increase = addresses_after.len() - addresses_before.len();
    assert_eq!(result.new_addresses.len(), actual_increase);

    for new_addr in &result.new_addresses {
        assert!(addresses_after.contains(new_addr));
    }
}

#[tokio::test]
async fn test_block_processing_result_empty() {
    let mut manager = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);
    let _wallet_id = manager
        .create_wallet_with_random_mnemonic(WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet");

    let external = dashcore::Address::p2pkh(
        &dashcore::PublicKey::from_slice(&[0x02; 33]).expect("valid pubkey"),
        Network::Testnet,
    );
    let tx1 = create_transaction_to_address(&external, 100_000);
    let tx2 = create_transaction_to_address(&external, 200_000);

    let block = create_test_block(100, vec![tx1, tx2]);
    let result = manager.process_block(&block, 100).await;

    assert!(result.relevant_txids.is_empty());
    assert!(result.new_addresses.is_empty());
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

/// Create a coinbase transaction paying to the given script
/// TODO: Unify with other `create_coinbase_transaction` helpers into `dashcore` crate.
fn create_coinbase_transaction(script_pubkey: ScriptBuf, value: u64) -> Transaction {
    Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::all_zeros(),
                vout: 0xffffffff,
            },
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: dashcore::Witness::default(),
        }],
        output: vec![TxOut {
            value,
            script_pubkey,
        }],
        special_transaction_payload: None,
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

#[tokio::test]
async fn test_immature_balance_matures_during_block_processing() {
    let mut manager = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);

    // Create a wallet and get an address to receive the coinbase
    let wallet_id = manager
        .create_wallet_with_random_mnemonic(WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet");

    let account_xpub = {
        let wallet = manager.get_wallet(&wallet_id).expect("Wallet should exist");
        wallet.accounts.standard_bip44_accounts.get(&0).expect("Should have account").account_xpub
    };

    // Get the first receive address from the wallet
    let receive_address = {
        let wallet_info =
            manager.get_wallet_info_mut(&wallet_id).expect("Wallet info should exist");
        wallet_info
            .first_bip44_managed_account_mut()
            .expect("Should have managed account")
            .next_receive_address(Some(&account_xpub), true)
            .expect("Should get address")
    };

    // Create a coinbase transaction paying to our wallet
    let coinbase_value = 100;
    let coinbase_tx = create_coinbase_transaction(receive_address.script_pubkey(), coinbase_value);

    // Process the coinbase at height 1000
    let coinbase_height = 1000;
    let coinbase_block = create_test_block(coinbase_height, vec![coinbase_tx.clone()]);
    manager.process_block(&coinbase_block, coinbase_height).await;

    // Verify the coinbase is detected and stored as immature
    let wallet_info = manager.get_wallet_info(&wallet_id).expect("Wallet info should exist");
    assert!(
        wallet_info.immature_transactions().contains(&coinbase_tx),
        "Coinbase should be in immature transactions"
    );
    assert_eq!(
        wallet_info.balance().immature(),
        coinbase_value,
        "Immature balance should reflect coinbase"
    );

    // Process 99 more blocks up to just before maturity
    let maturity_height = coinbase_height + COINBASE_MATURITY;
    for height in (coinbase_height + 1)..maturity_height {
        let block = create_test_block(height, vec![create_test_transaction(1000)]);
        manager.process_block(&block, height).await;
    }

    // Verify still immature just before maturity
    let wallet_info = manager.get_wallet_info(&wallet_id).expect("Wallet info should exist");
    assert!(
        wallet_info.immature_transactions().contains(&coinbase_tx),
        "Coinbase should still be immature at height {}",
        maturity_height - 1
    );

    // Process the maturity block
    let maturity_block = create_test_block(maturity_height, vec![create_test_transaction(1000)]);
    manager.process_block(&maturity_block, maturity_height).await;

    // Verify the coinbase has matured
    let wallet_info = manager.get_wallet_info(&wallet_id).expect("Wallet info should exist");
    assert!(
        !wallet_info.immature_transactions().contains(&coinbase_tx),
        "Coinbase should no longer be immature after maturity height"
    );
    assert_eq!(
        wallet_info.balance().immature(),
        0,
        "Immature balance should be zero after maturity"
    );
}
