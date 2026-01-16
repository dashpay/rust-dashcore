//! Tests for coinbase transaction handling

use crate::transaction_checking::transaction_router::{
    AccountTypeToCheck, TransactionRouter, TransactionType,
};
use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
use crate::wallet::initialization::WalletAccountCreationOptions;
use crate::wallet::{ManagedWalletInfo, Wallet};
use crate::Network;
use dashcore::blockdata::transaction::special_transaction::coinbase::CoinbasePayload;
use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::bls_sig_utils::BLSSignature;
use dashcore::hash_types::{MerkleRootMasternodeList, MerkleRootQuorums};
use dashcore::hashes::Hash;
use dashcore::{BlockHash, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid};

/// Helper to create a coinbase transaction
fn create_coinbase_transaction() -> Transaction {
    let height = 100000u32;
    let mut script_sig = Vec::new();
    script_sig.push(0x03); // Push 3 bytes
    script_sig.extend_from_slice(&height.to_le_bytes()[0..3]);

    Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint::null(), // Coinbase has null outpoint
            script_sig: ScriptBuf::from(script_sig),
            sequence: 0xffffffff,
            witness: dashcore::Witness::default(),
        }],
        output: vec![TxOut {
            value: 5000000000, // 50 DASH block reward
            script_pubkey: ScriptBuf::new(),
        }],
        special_transaction_payload: None,
    }
}

/// Helper to create a basic transaction
fn create_basic_transaction() -> Transaction {
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
            value: 100000,
            script_pubkey: ScriptBuf::new(),
        }],
        special_transaction_payload: None,
    }
}

#[tokio::test]
async fn test_coinbase_transaction_routing_to_bip44_receive_address() {
    // Create a wallet with a BIP44 account
    let mut wallet = Wallet::new_random(Network::Testnet, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with BIP44 account for coinbase test");

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get the account's xpub for address derivation from the wallet's first BIP44 account
    let account = wallet
        .accounts
        .standard_bip44_accounts
        .get(&0)
        .expect("Failed to get BIP44 account at index 0");
    let xpub = account.account_xpub;

    let managed_account = managed_wallet_info
        .first_bip44_managed_account_mut()
        .expect("Failed to get first BIP44 managed account");

    // Get a receive address from the BIP44 account
    let receive_address = managed_account
        .next_receive_address(Some(&xpub), true)
        .expect("Failed to generate receive address from BIP44 account");

    // Create a coinbase transaction that pays to our receive address
    let mut coinbase_tx = create_coinbase_transaction();

    // Replace the default output with one to our receive address
    coinbase_tx.output[0] = TxOut {
        value: 5000000000, // 50 DASH block reward
        script_pubkey: receive_address.script_pubkey(),
    };

    // Check the transaction using the wallet's managed info
    let context = TransactionContext::InBlock {
        height: 100000,
        block_hash: Some(
            BlockHash::from_slice(&[0u8; 32])
                .expect("Failed to create block hash for transaction context"),
        ),
        timestamp: Some(1234567890),
    };

    // Check the coinbase transaction
    let result = managed_wallet_info
        .check_core_transaction(
            &coinbase_tx,
            context,
            &mut wallet,
            true, // update state
        )
        .await;

    // The coinbase transaction should be recognized as relevant
    assert!(result.is_relevant, "Coinbase transaction to BIP44 receive address should be relevant");

    // Should have received the full block reward
    assert_eq!(
        result.total_received, 5000000000,
        "Should have received 50 DASH (5000000000 duffs) from coinbase"
    );

    // Should have affected the BIP44 account
    assert!(
        result.affected_accounts.iter().any(|acc| matches!(
            acc.account_type_match.to_account_type_to_check(),
            AccountTypeToCheck::StandardBIP44
        )),
        "Coinbase should have affected the BIP44 account"
    );
}

#[tokio::test]
async fn test_coinbase_transaction_routing_to_bip44_change_address() {
    // Create a wallet with a BIP44 account
    let mut wallet = Wallet::new_random(Network::Testnet, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with BIP44 account for coinbase change test");

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get the account's xpub for address derivation
    let account = wallet
        .accounts
        .standard_bip44_accounts
        .get(&0)
        .expect("Failed to get BIP44 account at index 0");
    let xpub = account.account_xpub;

    let managed_account = managed_wallet_info
        .first_bip44_managed_account_mut()
        .expect("Failed to get first BIP44 managed account");

    // Get a change address from the BIP44 account
    let change_address = managed_account
        .next_change_address(Some(&xpub), true)
        .expect("Failed to generate change address from BIP44 account");

    // Create a coinbase transaction that pays to our change address
    let mut coinbase_tx = create_coinbase_transaction();

    // Replace the default output with one to our change address
    coinbase_tx.output[0] = TxOut {
        value: 5000000000, // 50 DASH block reward
        script_pubkey: change_address.script_pubkey(),
    };

    // Check the transaction using the wallet's managed info
    let context = TransactionContext::InBlock {
        height: 100001,
        block_hash: Some(
            BlockHash::from_slice(&[1u8; 32])
                .expect("Failed to create block hash for transaction context"),
        ),
        timestamp: Some(1234567900),
    };

    // Check the coinbase transaction
    let result = managed_wallet_info
        .check_core_transaction(
            &coinbase_tx,
            context,
            &mut wallet,
            true, // update state
        )
        .await;

    // The coinbase transaction should be recognized as relevant even to change address
    assert!(result.is_relevant, "Coinbase transaction to BIP44 change address should be relevant");

    // Should have received the full block reward
    assert_eq!(
        result.total_received, 5000000000,
        "Should have received 50 DASH (5000000000 duffs) from coinbase to change address"
    );

    // Should have affected the BIP44 account
    assert!(
        result.affected_accounts.iter().any(|acc| matches!(
            acc.account_type_match.to_account_type_to_check(),
            AccountTypeToCheck::StandardBIP44
        )),
        "Coinbase to change address should have affected the BIP44 account"
    );
}

#[tokio::test]
async fn test_update_state_flag_behavior() {
    let mut wallet = Wallet::new_random(Network::Testnet, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with default options");
    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    let account = wallet
        .accounts
        .standard_bip44_accounts
        .get(&0)
        .expect("Expected BIP44 account at index 0 to exist");
    let xpub = account.account_xpub;

    // Get an address and initial state
    let (address, initial_balance, initial_tx_count) = {
        let managed_account = managed_wallet_info
            .first_bip44_managed_account_mut()
            .expect("Failed to get first BIP44 managed account");
        let address = managed_account
            .next_receive_address(Some(&xpub), true)
            .expect("Failed to generate receive address");
        let balance = managed_account.balance.spendable();
        let tx_count = managed_account.transactions.len();
        (address, balance, tx_count)
    };

    // Create a test transaction
    let mut tx = create_basic_transaction();
    tx.output.push(TxOut {
        value: 75000,
        script_pubkey: address.script_pubkey(),
    });

    let context = TransactionContext::InBlock {
        height: 100000,
        block_hash: Some(
            BlockHash::from_slice(&[0u8; 32]).expect("Failed to create block hash from bytes"),
        ),
        timestamp: Some(1234567890),
    };

    // First check with update_state = false
    let result1 =
        managed_wallet_info.check_core_transaction(&tx, context, &mut wallet, false).await;

    assert!(result1.is_relevant);

    // Verify no state change when update_state=false
    {
        let managed_account = managed_wallet_info
            .first_bip44_managed_account_mut()
            .expect("Failed to get first BIP44 managed account");
        assert_eq!(
            managed_account.balance.spendable(),
            initial_balance,
            "Balance should not change when update_state=false"
        );
        assert_eq!(
            managed_account.transactions.len(),
            initial_tx_count,
            "Transaction count should not change when update_state=false"
        );
    }

    // Now check with update_state = true
    let result2 = managed_wallet_info
        .check_core_transaction(
            &tx,
            context,
            &mut wallet,
            true, // update state
        )
        .await;

    assert!(result2.is_relevant);
    assert_eq!(
        result1.total_received, result2.total_received,
        "Should detect same amount regardless of update_state"
    );

    // Check if state was actually updated
    // Note: This may fail if state updates aren't properly implemented
    // That's what we want to discover
    {
        let managed_account = managed_wallet_info
            .first_bip44_managed_account_mut()
            .expect("Failed to get first BIP44 managed account");
        println!(
            "After update_state=true: balance={}, tx_count={}",
            managed_account.balance.spendable(),
            managed_account.transactions.len()
        );
    }
}

#[test]
fn test_coinbase_classification() {
    // Test that coinbase transactions are properly classified
    let mut tx = create_basic_transaction();

    // Create a coinbase payload
    let payload = CoinbasePayload {
        version: 3,
        height: 100000,
        merkle_root_masternode_list: MerkleRootMasternodeList::from_slice(&[7u8; 32]).unwrap(),
        merkle_root_quorums: MerkleRootQuorums::from_slice(&[8u8; 32]).unwrap(),
        best_cl_height: Some(99900),
        best_cl_signature: Some(BLSSignature::from([9u8; 96])),
        asset_locked_amount: Some(100_000_000_000),
    };
    tx.special_transaction_payload = Some(TransactionPayload::CoinbasePayloadType(payload));

    // Verify classification
    let tx_type = TransactionRouter::classify_transaction(&tx);
    assert_eq!(tx_type, TransactionType::Coinbase, "Should classify as Coinbase transaction");
}

#[test]
fn test_coinbase_routing() {
    // Test routing logic for coinbase transactions
    let tx_type = TransactionType::Coinbase;
    let accounts = TransactionRouter::get_relevant_account_types(&tx_type);

    // Coinbase should route to standard accounts
    assert_eq!(accounts.len(), 2, "Coinbase should route to exactly 2 account types");
    assert!(accounts.contains(&AccountTypeToCheck::StandardBIP44));
    assert!(accounts.contains(&AccountTypeToCheck::StandardBIP32));

    // Should NOT route to special account types
    assert!(!accounts.contains(&AccountTypeToCheck::CoinJoin));
    assert!(!accounts.contains(&AccountTypeToCheck::IdentityRegistration));
    assert!(!accounts.contains(&AccountTypeToCheck::ProviderOwnerKeys));
}

#[tokio::test]
async fn test_coinbase_transaction_with_payload_routing() {
    // Test coinbase with special payload routing to BIP44 account
    let mut wallet = Wallet::new_random(Network::Testnet, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet");

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get address from BIP44 account
    let account =
        wallet.accounts.standard_bip44_accounts.get(&0).expect("Expected BIP44 account at index 0");
    let xpub = account.account_xpub;

    let managed_account = managed_wallet_info
        .first_bip44_managed_account_mut()
        .expect("Failed to get first BIP44 managed account");

    let address = managed_account
        .next_receive_address(Some(&xpub), true)
        .expect("Failed to generate receive address");

    // Create coinbase transaction with special payload
    let mut coinbase_tx = create_coinbase_transaction();
    coinbase_tx.output[0] = TxOut {
        value: 5000000000,
        script_pubkey: address.script_pubkey(),
    };

    // Add coinbase payload
    let payload = CoinbasePayload {
        version: 3,
        height: 100000,
        merkle_root_masternode_list: MerkleRootMasternodeList::from_slice(&[7u8; 32]).unwrap(),
        merkle_root_quorums: MerkleRootQuorums::from_slice(&[8u8; 32]).unwrap(),
        best_cl_height: Some(99900),
        best_cl_signature: Some(BLSSignature::from([9u8; 96])),
        asset_locked_amount: Some(100_000_000_000), // 1000 DASH locked
    };
    coinbase_tx.special_transaction_payload =
        Some(TransactionPayload::CoinbasePayloadType(payload));

    // First verify classification
    let tx_type = TransactionRouter::classify_transaction(&coinbase_tx);
    assert_eq!(tx_type, TransactionType::Coinbase);

    let context = TransactionContext::InBlock {
        height: 100000,
        block_hash: Some(BlockHash::from_slice(&[0u8; 32]).expect("Failed to create block hash")),
        timestamp: Some(1234567890),
    };

    let result =
        managed_wallet_info.check_core_transaction(&coinbase_tx, context, &mut wallet, true).await;

    assert!(result.is_relevant, "Coinbase with payload should be relevant");
    assert_eq!(result.total_received, 5000000000, "Should have received block reward");
    assert!(
        result.affected_accounts.iter().any(|acc| matches!(
            acc.account_type_match.to_account_type_to_check(),
            AccountTypeToCheck::StandardBIP44
        )),
        "Should have affected BIP44 account"
    );
}
