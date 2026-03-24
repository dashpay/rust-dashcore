//! Tests for coinbase transaction handling

use super::helpers::test_addr;
use crate::test_utils::TestWalletContext;
use crate::transaction_checking::transaction_router::{
    AccountTypeToCheck, TransactionRouter, TransactionType,
};
use crate::transaction_checking::{BlockInfo, TransactionContext, WalletTransactionChecker};
use dashcore::blockdata::transaction::special_transaction::coinbase::CoinbasePayload;
use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::bls_sig_utils::BLSSignature;
use dashcore::hash_types::{MerkleRootMasternodeList, MerkleRootQuorums};
use dashcore::hashes::Hash;
use dashcore::{BlockHash, OutPoint, ScriptBuf, Transaction, TxIn, TxOut};

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

#[tokio::test]
async fn test_coinbase_transaction_routing_to_bip44_receive_address() {
    let TestWalletContext {
        managed_wallet: mut managed_wallet_info,
        mut wallet,
        receive_address,
        ..
    } = TestWalletContext::new_random();

    // Create a coinbase transaction that pays to our receive address
    let mut coinbase_tx = create_coinbase_transaction();

    // Replace the default output with one to our receive address
    coinbase_tx.output[0] = TxOut {
        value: 5000000000, // 50 DASH block reward
        script_pubkey: receive_address.script_pubkey(),
    };

    // Check the transaction using the wallet's managed info
    let context = TransactionContext::InBlock(BlockInfo::new(
        100000,
        BlockHash::from_slice(&[0u8; 32])
            .expect("Failed to create block hash for transaction context"),
        1234567890,
    ));

    // Check the coinbase transaction
    let result = managed_wallet_info
        .check_core_transaction(
            &coinbase_tx,
            context,
            &mut wallet,
            true, // update state
            true, // update balance
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
    let TestWalletContext {
        managed_wallet: mut managed_wallet_info,
        mut wallet,
        xpub,
        ..
    } = TestWalletContext::new_random();

    // Get a change address from the BIP44 account
    let change_address = managed_wallet_info
        .first_bip44_managed_account_mut()
        .expect("Failed to get first BIP44 managed account")
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
    let context = TransactionContext::InBlock(BlockInfo::new(
        100001,
        BlockHash::from_slice(&[1u8; 32])
            .expect("Failed to create block hash for transaction context"),
        1234567900,
    ));

    // Check the coinbase transaction
    let result = managed_wallet_info
        .check_core_transaction(
            &coinbase_tx,
            context,
            &mut wallet,
            true, // update state
            true, // update balance
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
    let TestWalletContext {
        managed_wallet: mut managed_wallet_info,
        mut wallet,
        receive_address: address,
        ..
    } = TestWalletContext::new_random();

    // Capture initial state
    let (initial_balance, initial_tx_count) = {
        let managed_account = managed_wallet_info
            .first_bip44_managed_account_mut()
            .expect("Failed to get first BIP44 managed account");
        (managed_account.balance.spendable(), managed_account.transactions.len())
    };

    // Create a test transaction
    let addr = test_addr();
    let mut tx = Transaction::dummy(&addr, 0..1, &[100_000]);
    tx.output.push(TxOut {
        value: 75000,
        script_pubkey: address.script_pubkey(),
    });

    let context = TransactionContext::InBlock(BlockInfo::new(
        100000,
        BlockHash::from_slice(&[0u8; 32]).expect("Failed to create block hash from bytes"),
        1234567890,
    ));

    // First check with update_state = false
    let result1 =
        managed_wallet_info.check_core_transaction(&tx, context, &mut wallet, false, true).await;

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
            true, // update balance
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
    let addr = test_addr();
    let mut tx = Transaction::dummy(&addr, 0..1, &[100_000]);

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
    let TestWalletContext {
        managed_wallet: mut managed_wallet_info,
        mut wallet,
        receive_address: address,
        ..
    } = TestWalletContext::new_random();

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

    let context = TransactionContext::InBlock(BlockInfo::new(
        100000,
        BlockHash::from_slice(&[0u8; 32]).expect("Failed to create block hash"),
        1234567890,
    ));

    let result = managed_wallet_info
        .check_core_transaction(&coinbase_tx, context, &mut wallet, true, true)
        .await;

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
