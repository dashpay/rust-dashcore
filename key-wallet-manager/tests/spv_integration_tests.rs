//! Integration tests for SPV wallet functionality

use dashcore::blockdata::block::{Block, Header};
use dashcore::blockdata::script::ScriptBuf;
use dashcore::blockdata::transaction::{OutPoint, Transaction};
use dashcore::{Address as DashAddress, BlockHash, Network as DashNetwork, Txid};
use dashcore::{TxIn, TxOut};
use dashcore_hashes::Hash;

use key_wallet::mnemonic::Language;
use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet::{Mnemonic, Network, Wallet, WalletConfig};
use key_wallet_manager::compact_filter::{CompactFilter, FilterType};
use key_wallet_manager::enhanced_wallet_manager::EnhancedWalletManager;
use key_wallet_manager::spv_client_integration::{SPVSyncStatus, SPVWalletIntegration};
use key_wallet_manager::wallet_manager::WalletError;

/// Create a test wallet with known mnemonic
fn create_test_wallet() -> (Wallet, ManagedWalletInfo) {
    let mnemonic = Mnemonic::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        Language::English,
    ).unwrap();

    let wallet = Wallet::from_mnemonic(
        mnemonic,
        WalletConfig::default(),
        Network::Testnet,
        WalletAccountCreationOptions::Default,
    )
    .unwrap();
    let info = ManagedWalletInfo::with_name(wallet.wallet_id, "Test Wallet".to_string());

    (wallet, info)
}

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
fn create_mock_filter(scripts: &[ScriptBuf]) -> CompactFilter {
    // For testing, we'll create a simple filter that matches specific scripts
    // In reality, this would be a proper Golomb-coded set
    let elements: Vec<Vec<u8>> = scripts.iter().map(|s| s.to_bytes()).collect();
    let block_hash = [0u8; 32];
    let key = [0u8; 16];

    let filter = key_wallet_manager::compact_filter::GolombCodedSet::new(
        &elements,
        key_wallet_manager::compact_filter::FilterType::Basic.p_value(),
        key_wallet_manager::compact_filter::FilterType::Basic.m_value(),
        &key,
    );

    CompactFilter {
        filter_type: key_wallet_manager::compact_filter::FilterType::Basic,
        block_hash,
        filter,
    }
}

#[test]
fn test_spv_integration_basic() {
    let mut spv = SPVWalletIntegration::new(Network::Testnet);

    // Create and add a test wallet
    let (wallet, info) = create_test_wallet();
    let wallet_id = "test_wallet".to_string();

    spv.wallet_manager_mut().add_wallet(wallet_id.clone(), wallet, info).unwrap();

    // Verify initial state
    assert_eq!(spv.sync_status(), SPVSyncStatus::Idle);
    assert!(spv.get_download_queue().is_empty());
    assert_eq!(spv.sync_progress(), 0.0);
}

#[test]
fn test_filter_checking() {
    let mut spv = SPVWalletIntegration::new(Network::Testnet);

    // Create and add a test wallet
    let (wallet, mut info) = create_test_wallet();
    let wallet_id = "test_wallet".to_string();

    // Add a test address to monitor
    let test_address = key_wallet::Address::p2pkh(
        &dashcore::PublicKey::from_slice(&[
            0x02, 0x50, 0x86, 0x3a, 0xd6, 0x4a, 0x87, 0xae, 0x8a, 0x2f, 0xe8, 0x3c, 0x1a, 0xf1,
            0xa8, 0x40, 0x3c, 0xb5, 0x3f, 0x53, 0xe4, 0x86, 0xd8, 0x51, 0x1d, 0xad, 0x8a, 0x04,
            0x88, 0x7e, 0x5b, 0x23, 0x52,
        ])
        .unwrap(),
        DashNetwork::Testnet,
    );
    info.add_monitored_address(test_address.clone());

    spv.wallet_manager_mut().add_wallet(wallet_id.clone(), wallet, info).unwrap();

    // Add monitored address to wallet manager
    spv.wallet_manager_mut().base_mut().add_monitored_address(&wallet_id, test_address.clone());

    // Update watched scripts
    spv.wallet_manager_mut().update_watched_scripts_for_wallet(&wallet_id).unwrap();

    // Verify that scripts are being watched
    let watched_count = spv.wallet_manager().watched_scripts_count();
    assert!(watched_count > 0, "No scripts are being watched! Count: {}", watched_count);

    // Create a filter that matches our address
    let script = test_address.script_pubkey();
    let filter = create_mock_filter(&[script]);
    let block_hash = BlockHash::all_zeros();

    // Check the filter
    let should_download = spv.check_filter(&filter, &block_hash);

    // Should match since we're watching that script
    assert!(should_download);
    assert_eq!(spv.stats().filters_checked, 1);
    assert_eq!(spv.stats().filters_matched, 1);
    assert!(!spv.get_download_queue().is_empty());
}

#[test]
fn test_block_processing() {
    let mut spv = SPVWalletIntegration::new(Network::Testnet);

    // Create and add a test wallet
    let (wallet, mut info) = create_test_wallet();
    let wallet_id = "test_wallet".to_string();

    // Add a test address to monitor
    let test_address = key_wallet::Address::p2pkh(
        &dashcore::PublicKey::from_slice(&[
            0x02, 0x50, 0x86, 0x3a, 0xd6, 0x4a, 0x87, 0xae, 0x8a, 0x2f, 0xe8, 0x3c, 0x1a, 0xf1,
            0xa8, 0x40, 0x3c, 0xb5, 0x3f, 0x53, 0xe4, 0x86, 0xd8, 0x51, 0x1d, 0xad, 0x8a, 0x04,
            0x88, 0x7e, 0x5b, 0x23, 0x52,
        ])
        .unwrap(),
        DashNetwork::Testnet,
    );
    info.add_monitored_address(test_address.clone());

    spv.wallet_manager_mut().add_wallet(wallet_id.clone(), wallet, info).unwrap();

    // Add monitored address to wallet manager
    spv.wallet_manager_mut().base_mut().add_monitored_address(&wallet_id, test_address.clone());

    spv.wallet_manager_mut().update_watched_scripts_for_wallet(&wallet_id).unwrap();

    // Create a transaction that sends to our address
    let mut tx = create_test_transaction(100000);
    tx.output[0].script_pubkey = test_address.script_pubkey();

    // Create a block with this transaction
    let block = create_test_block(100, vec![tx.clone()]);

    // Process the block
    let result = spv.process_block(block, 100);

    // Verify the transaction was found
    assert!(!result.relevant_transactions.is_empty());
    assert_eq!(result.relevant_transactions[0].txid(), tx.txid());
    assert!(result.affected_wallets.contains(&wallet_id));
    assert!(!result.new_utxos.is_empty());
    assert_eq!(spv.stats().blocks_downloaded, 1);
    assert_eq!(spv.stats().transactions_found, 1);
}

#[test]
fn test_mempool_transaction() {
    let mut spv = SPVWalletIntegration::new(Network::Testnet);

    // Create and add a test wallet
    let (wallet, mut info) = create_test_wallet();
    let wallet_id = "test_wallet".to_string();

    // Add a test address to monitor
    let test_address = key_wallet::Address::p2pkh(
        &dashcore::PublicKey::from_slice(&[
            0x02, 0x50, 0x86, 0x3a, 0xd6, 0x4a, 0x87, 0xae, 0x8a, 0x2f, 0xe8, 0x3c, 0x1a, 0xf1,
            0xa8, 0x40, 0x3c, 0xb5, 0x3f, 0x53, 0xe4, 0x86, 0xd8, 0x51, 0x1d, 0xad, 0x8a, 0x04,
            0x88, 0x7e, 0x5b, 0x23, 0x52,
        ])
        .unwrap(),
        DashNetwork::Testnet,
    );
    info.add_monitored_address(test_address.clone());

    spv.wallet_manager_mut().add_wallet(wallet_id.clone(), wallet, info).unwrap();

    // Add monitored address to wallet manager
    spv.wallet_manager_mut().base_mut().add_monitored_address(&wallet_id, test_address.clone());

    spv.wallet_manager_mut().update_watched_scripts_for_wallet(&wallet_id).unwrap();

    // Create a mempool transaction to our address
    let mut tx = create_test_transaction(50000);
    tx.output[0].script_pubkey = test_address.script_pubkey();

    // Process as mempool transaction
    let result = spv.process_mempool_transaction(&tx);

    // Should be recognized as relevant
    assert!(result.is_relevant);
    assert!(result.affected_wallets.contains(&wallet_id));
    assert!(!result.new_utxos.is_empty());
}

#[test]
fn test_queued_blocks() {
    let mut spv = SPVWalletIntegration::new(Network::Testnet);

    // Queue blocks out of order
    let block1 = create_test_block(101, vec![create_test_transaction(1000)]);
    let block2 = create_test_block(102, vec![create_test_transaction(2000)]);
    let block3 = create_test_block(103, vec![create_test_transaction(3000)]);

    spv.queue_block(block3, 103);
    spv.queue_block(block1, 101);
    spv.queue_block(block2, 102);

    // Process queued blocks up to height 102
    let results = spv.process_queued_blocks(102);

    // Should process blocks 101 and 102
    assert_eq!(results.len(), 2);

    // Block 103 should still be pending
    assert_eq!(spv.pending_blocks_count(), 1);
    assert!(spv.has_pending_block(103));
}

#[test]
fn test_sync_status_tracking() {
    let mut spv = SPVWalletIntegration::new(Network::Testnet);

    // Set target height
    spv.set_target_height(1000);

    // Should be checking filters
    assert_eq!(
        spv.sync_status(),
        SPVSyncStatus::CheckingFilters {
            current: 0,
            target: 1000
        }
    );

    // Simulate filter match and add to download queue
    spv.test_add_to_download_queue(BlockHash::from_byte_array([0u8; 32]));

    // Should be downloading blocks
    assert_eq!(
        spv.sync_status(),
        SPVSyncStatus::DownloadingBlocks {
            pending: 1
        }
    );

    // Clear queue and update height
    spv.clear_download_queue();
    spv.test_set_sync_height(500);

    // Should be checking filters again
    assert_eq!(
        spv.sync_status(),
        SPVSyncStatus::CheckingFilters {
            current: 500,
            target: 1000
        }
    );

    // Sync to target
    spv.test_set_sync_height(1000);

    // Should be synced
    assert_eq!(spv.sync_status(), SPVSyncStatus::Synced);
    assert!(spv.is_synced());
    assert_eq!(spv.sync_progress(), 100.0);
}

#[test]
fn test_reorg_handling() {
    let mut spv = SPVWalletIntegration::new(Network::Testnet);

    // Set initial state
    spv.test_set_sync_height(150);
    spv.set_target_height(200);

    // Queue some blocks
    spv.queue_block(create_test_block(151, vec![]), 151);
    spv.queue_block(create_test_block(152, vec![]), 152);
    spv.queue_block(create_test_block(153, vec![]), 153);

    // Add to download queue
    spv.test_add_to_download_queue(BlockHash::from_byte_array([0u8; 32]));

    // Handle reorg back to height 140
    spv.handle_reorg(140).unwrap();

    // Verify state after reorg
    assert_eq!(spv.stats().sync_height, 140);
    assert!(spv.is_download_queue_empty());
    // Blocks above 140 should be removed
    assert!(!spv.has_pending_block(151));
    assert!(!spv.has_pending_block(152));
    assert!(!spv.has_pending_block(153));
}

#[test]
fn test_multiple_wallets() {
    let mut spv = SPVWalletIntegration::new(Network::Testnet);

    // Create and add multiple wallets
    for i in 0..3 {
        let (wallet, mut info) = create_test_wallet();
        let wallet_id = format!("wallet_{}", i);

        // Add unique address for each wallet
        // Create different valid public keys for each wallet
        let mut pubkey_bytes = vec![
            0x02, 0x50, 0x86, 0x3a, 0xd6, 0x4a, 0x87, 0xae, 0x8a, 0x2f, 0xe8, 0x3c, 0x1a, 0xf1,
            0xa8, 0x40, 0x3c, 0xb5, 0x3f, 0x53, 0xe4, 0x86, 0xd8, 0x51, 0x1d, 0xad, 0x8a, 0x04,
            0x88, 0x7e, 0x5b, 0x23, 0x52,
        ];
        pubkey_bytes[1] = (0x50 + i) as u8; // Make each key unique
        let test_address = key_wallet::Address::p2pkh(
            &dashcore::PublicKey::from_slice(&pubkey_bytes).unwrap(),
            DashNetwork::Testnet,
        );
        info.add_monitored_address(test_address.clone());

        spv.wallet_manager_mut().add_wallet(wallet_id.clone(), wallet, info).unwrap();

        // Add monitored address to wallet manager
        spv.wallet_manager_mut().base_mut().add_monitored_address(&wallet_id, test_address.clone());

        spv.wallet_manager_mut().update_watched_scripts_for_wallet(&wallet_id).unwrap();
    }

    // Verify all wallets are being watched
    let watched_scripts = spv.get_watched_scripts();
    assert_eq!(watched_scripts.len(), 3);

    // Create a block with transactions for different wallets
    let mut transactions = Vec::new();
    for i in 0..3 {
        let mut tx = create_test_transaction(100000 * (i + 1) as u64);
        let mut pubkey_bytes = vec![
            0x02, 0x50, 0x86, 0x3a, 0xd6, 0x4a, 0x87, 0xae, 0x8a, 0x2f, 0xe8, 0x3c, 0x1a, 0xf1,
            0xa8, 0x40, 0x3c, 0xb5, 0x3f, 0x53, 0xe4, 0x86, 0xd8, 0x51, 0x1d, 0xad, 0x8a, 0x04,
            0x88, 0x7e, 0x5b, 0x23, 0x52,
        ];
        pubkey_bytes[1] = (0x50 + i) as u8; // Make each key unique
        let address = key_wallet::Address::p2pkh(
            &dashcore::PublicKey::from_slice(&pubkey_bytes).unwrap(),
            DashNetwork::Testnet,
        );
        tx.output[0].script_pubkey = address.script_pubkey();
        transactions.push(tx);
    }

    let block = create_test_block(100, transactions);

    // Process the block
    let result = spv.process_block(block, 100);

    // All wallets should be affected
    assert_eq!(result.affected_wallets.len(), 3);
    assert_eq!(result.relevant_transactions.len(), 3);
    assert_eq!(result.new_utxos.len(), 3);
}

#[test]
fn test_spent_utxo_tracking() {
    let mut spv = SPVWalletIntegration::new(Network::Testnet);

    // Create and add a test wallet
    let (wallet, mut info) = create_test_wallet();
    let wallet_id = "test_wallet".to_string();

    // Add a test address to monitor
    let test_address = key_wallet::Address::p2pkh(
        &dashcore::PublicKey::from_slice(&[
            0x02, 0x50, 0x86, 0x3a, 0xd6, 0x4a, 0x87, 0xae, 0x8a, 0x2f, 0xe8, 0x3c, 0x1a, 0xf1,
            0xa8, 0x40, 0x3c, 0xb5, 0x3f, 0x53, 0xe4, 0x86, 0xd8, 0x51, 0x1d, 0xad, 0x8a, 0x04,
            0x88, 0x7e, 0x5b, 0x23, 0x52,
        ])
        .unwrap(),
        DashNetwork::Testnet,
    );
    info.add_monitored_address(test_address.clone());

    spv.wallet_manager_mut().add_wallet(wallet_id.clone(), wallet, info).unwrap();

    // Add monitored address to wallet manager
    spv.wallet_manager_mut().base_mut().add_monitored_address(&wallet_id, test_address.clone());

    spv.wallet_manager_mut().update_watched_scripts_for_wallet(&wallet_id).unwrap();

    // First, create a UTXO
    let mut tx1 = create_test_transaction(100000);
    tx1.output[0].script_pubkey = test_address.script_pubkey();
    let tx1_id = tx1.txid(); // Get the actual txid after modifying the output

    let block1 = create_test_block(100, vec![tx1]);
    let result1 = spv.process_block(block1, 100);

    assert_eq!(result1.new_utxos.len(), 1);
    let created_utxo = &result1.new_utxos[0];

    // Update watched outpoints after creating UTXO
    spv.wallet_manager_mut().update_watched_scripts_for_wallet(&wallet_id).unwrap();

    // Verify the outpoint is being watched
    let watched_outpoints = spv.get_watched_outpoints();
    assert!(
        watched_outpoints.contains(&created_utxo.outpoint),
        "Created UTXO outpoint not being watched: {:?}",
        created_utxo.outpoint
    );

    // Now spend that UTXO
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
            value: 90000,                    // Less due to fee
            script_pubkey: ScriptBuf::new(), // Sending elsewhere
        }],
        special_transaction_payload: None,
    };

    let block2 = create_test_block(101, vec![tx2.clone()]);
    let result2 = spv.process_block(block2, 101);

    // Debug output
    println!("Transaction spending UTXO: input={:?}", tx2.input[0].previous_output);
    println!("Created UTXO outpoint: {:?}", created_utxo.outpoint);
    println!("Result2 spent UTXOs: {:?}", result2.spent_utxos);
    println!("Result2 is relevant: {:?}", result2.relevant_transactions.len());

    // The UTXO should be marked as spent
    assert!(
        result2.spent_utxos.contains(&created_utxo.outpoint),
        "Expected spent UTXO {:?} not in result2.spent_utxos",
        created_utxo.outpoint
    );

    // Verify outpoint is no longer watched
    let watched_after = spv.get_watched_outpoints();
    println!("Watched outpoints after spending: {:?}", watched_after);
    assert!(
        !watched_after.contains(&created_utxo.outpoint),
        "Outpoint {:?} still in watched set after being spent",
        created_utxo.outpoint
    );
}
