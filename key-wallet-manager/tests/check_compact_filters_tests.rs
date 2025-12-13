//! Integration tests for WalletInterface::check_compact_filters

use dashcore::blockdata::script::ScriptBuf;
use dashcore_test_utils::{
    create_filter_for_block, create_test_block, create_test_transaction_to_script,
};
use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet::Network;
use key_wallet_manager::wallet_interface::{FilterMatchKey, WalletInterface};
use key_wallet_manager::wallet_manager::matching::FilterMatchInput;
use key_wallet_manager::wallet_manager::WalletManager;

#[tokio::test]
async fn test_check_compact_filters_empty_input() {
    let mut manager = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);

    let _wallet_id = manager
        .create_wallet_with_random_mnemonic(WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet");

    let input = FilterMatchInput::new();
    let output = manager.check_compact_filters(input).await;

    assert!(output.is_empty());
}

#[tokio::test]
async fn test_check_compact_filters_no_matches() {
    let mut manager = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);

    let _wallet_id = manager
        .create_wallet_with_random_mnemonic(WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet");

    let tx1 = create_test_transaction_to_script(ScriptBuf::new());
    let block1 = create_test_block(100, vec![tx1]);
    let filter1 = create_filter_for_block(&block1);
    let key1 = FilterMatchKey::new(100, block1.block_hash());

    let tx2 = create_test_transaction_to_script(ScriptBuf::new());
    let block2 = create_test_block(200, vec![tx2]);
    let filter2 = create_filter_for_block(&block2);
    let key2 = FilterMatchKey::new(200, block2.block_hash());

    let mut input = FilterMatchInput::new();
    input.insert(key1, filter1);
    input.insert(key2, filter2);

    let output = manager.check_compact_filters(input).await;

    assert!(output.is_empty());
}

#[tokio::test]
async fn test_check_compact_filters_batch_mixed_results() {
    let mut manager = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);

    let _wallet_id = manager
        .create_wallet_with_random_mnemonic(WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet");

    let addresses = manager.monitored_addresses();
    assert!(!addresses.is_empty());
    let wallet_script = addresses[0].script_pubkey();

    let tx_match = create_test_transaction_to_script(wallet_script);
    let block_match = create_test_block(100, vec![tx_match]);
    let filter_match = create_filter_for_block(&block_match);
    let key_match = FilterMatchKey::new(100, block_match.block_hash());

    let tx_no_match = create_test_transaction_to_script(ScriptBuf::new());
    let block_no_match = create_test_block(200, vec![tx_no_match]);
    let filter_no_match = create_filter_for_block(&block_no_match);
    let key_no_match = FilterMatchKey::new(200, block_no_match.block_hash());

    let mut input = FilterMatchInput::new();
    input.insert(key_match.clone(), filter_match);
    input.insert(key_no_match.clone(), filter_no_match);

    let output = manager.check_compact_filters(input).await;

    assert_eq!(output.len(), 1);
    assert!(output.contains(&key_match));
    assert!(!output.contains(&key_no_match));
}

#[tokio::test]
async fn test_check_compact_filters_multiple_matching_addresses() {
    let mut manager = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);

    let _wallet_id = manager
        .create_wallet_with_random_mnemonic(WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet");

    let addresses = manager.monitored_addresses();
    assert!(addresses.len() >= 2, "Need at least 2 addresses for this test");

    let tx1 = create_test_transaction_to_script(addresses[0].script_pubkey());
    let tx2 = create_test_transaction_to_script(addresses[1].script_pubkey());
    let block = create_test_block(100, vec![tx1, tx2]);
    let filter = create_filter_for_block(&block);
    let key = FilterMatchKey::new(100, block.block_hash());

    let mut input = FilterMatchInput::new();
    input.insert(key.clone(), filter);

    let output = manager.check_compact_filters(input).await;

    assert!(output.contains(&key));
}

#[tokio::test]
async fn test_check_compact_filters_all_match() {
    let mut manager = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);

    let _wallet_id = manager
        .create_wallet_with_random_mnemonic(WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet");

    let addresses = manager.monitored_addresses();
    assert!(addresses.len() >= 2, "Need at least 2 addresses");
    let script1 = addresses[0].script_pubkey();
    let script2 = addresses[1].script_pubkey();

    let tx1 = create_test_transaction_to_script(script1);
    let block1 = create_test_block(100, vec![tx1]);
    let filter1 = create_filter_for_block(&block1);
    let key1 = FilterMatchKey::new(100, block1.block_hash());

    let tx2 = create_test_transaction_to_script(script2);
    let block2 = create_test_block(200, vec![tx2]);
    let filter2 = create_filter_for_block(&block2);
    let key2 = FilterMatchKey::new(200, block2.block_hash());

    let mut input = FilterMatchInput::new();
    input.insert(key1.clone(), filter1);
    input.insert(key2.clone(), filter2);

    let output = manager.check_compact_filters(input).await;

    assert_eq!(output.len(), 2);
    assert!(output.contains(&key1));
    assert!(output.contains(&key2));
}
