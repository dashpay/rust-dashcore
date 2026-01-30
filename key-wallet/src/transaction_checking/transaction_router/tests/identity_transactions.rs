//! Tests for identity-related transaction handling

use super::helpers::*;
use crate::account::AccountType;
use crate::transaction_checking::transaction_router::{
    AccountTypeToCheck, TransactionRouter, TransactionType,
};
use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
use crate::wallet::initialization::WalletAccountCreationOptions;
use crate::wallet::{ManagedWalletInfo, Wallet};
use crate::Network;
use dashcore::blockdata::script::ScriptBuf;
use dashcore::blockdata::transaction::special_transaction::asset_lock::AssetLockPayload;
use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::hashes::Hash;
use dashcore::{BlockHash, OutPoint, Transaction, TxIn, TxOut, Txid};

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
        }],
        output: vec![TxOut {
            value: 100000,
            script_pubkey: ScriptBuf::new(),
        }],
        special_transaction_payload: None,
    }
}

#[test]
fn test_identity_registration() {
    // Asset lock for identity registration
    let tx = create_asset_lock_transaction(
        1,
        100_000_000, // 1 DASH for identity registration
    );

    let tx_type = TransactionRouter::classify_transaction(&tx);
    assert_eq!(tx_type, TransactionType::AssetLock);

    let accounts = TransactionRouter::get_relevant_account_types(&tx_type);
    assert!(accounts.contains(&AccountTypeToCheck::IdentityRegistration));
    assert!(accounts.contains(&AccountTypeToCheck::IdentityTopUp));
}

#[tokio::test]
async fn test_identity_registration_account_routing() {
    let network = Network::Testnet;

    let mut wallet = Wallet::new_random(network, WalletAccountCreationOptions::None)
        .expect("Failed to create wallet without default accounts");

    // Add identity registration account
    let account_type = AccountType::IdentityRegistration;
    wallet.add_account(account_type, None).expect("Failed to add account to wallet");

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get the identity registration account
    let account = wallet
        .accounts
        .identity_registration
        .as_ref()
        .expect("Expected identity registration account to exist");
    let xpub = account.account_xpub;

    let managed_account = managed_wallet_info
        .identity_registration_managed_account_mut()
        .expect("Failed to get identity registration managed account");

    // Use the new next_address method for identity registration account
    let address = managed_account.next_address(Some(&xpub), true).expect("expected an address");

    // Create an Asset Lock transaction that funds identity registration
    use dashcore::opcodes;
    use dashcore::script::Builder;

    let tx = Transaction {
        version: 3, // Version 3 for special transactions
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([1u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
        }],
        output: vec![
            // Asset lock transactions have regular outputs
            // First output is an OP_RETURN with the locked amount
            TxOut {
                value: 100_000_000, // 1 DASH being locked
                script_pubkey: Builder::new()
                    .push_opcode(opcodes::all::OP_RETURN)
                    .push_slice([0u8; 20]) // Can contain identity hash or other data
                    .into_script(),
            },
            // Change output back to sender
            TxOut {
                value: 50_000_000, // 0.5 DASH change
                script_pubkey: dashcore::Address::p2pkh(
                    &dashcore::PublicKey::from_slice(&[
                        0x03, // compressed public key prefix
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                    ])
                    .expect("Failed to create public key from bytes"),
                    network,
                )
                .script_pubkey(),
            },
        ],
        special_transaction_payload: Some(TransactionPayload::AssetLockPayloadType(
            AssetLockPayload {
                version: 1,
                credit_outputs: vec![TxOut {
                    value: 100_000_000, // 1 DASH for identity registration credit
                    script_pubkey: address.script_pubkey(),
                }],
            },
        )),
    };

    let context = TransactionContext::InBlock {
        height: 100000,
        block_hash: Some(
            BlockHash::from_slice(&[0u8; 32]).expect("Failed to create block hash from bytes"),
        ),
        timestamp: Some(1234567890),
    };

    // First check without updating state
    let result = managed_wallet_info.check_transaction(&tx, context, &mut wallet, true).await;

    println!(
        "Identity registration transaction result: is_relevant={}, received={}, credit_conversion={}",
        result.is_relevant, result.total_received, result.total_received_for_credit_conversion
    );

    // The transaction SHOULD be recognized as relevant to identity registration
    assert!(
        result.is_relevant,
        "AssetLock transaction should be recognized as relevant to identity registration account"
    );

    assert!(
        result.affected_accounts.iter().any(|acc| matches!(
            acc.account_type_match.to_account_type_to_check(),
            AccountTypeToCheck::IdentityRegistration
        )),
        "Should have affected the identity registration account"
    );

    // AssetLock funds are for credit conversion, not regular spending
    assert_eq!(result.total_received, 0, "AssetLock should not provide spendable funds");

    assert_eq!(
        result.total_received_for_credit_conversion, 100_000_000,
        "Should detect 1 DASH (100,000,000 duffs) for Platform credit conversion from AssetLock payload"
    );
}

#[tokio::test]
async fn test_normal_payment_to_identity_address_not_detected() {
    let network = Network::Testnet;

    let mut wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with default options");
    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    let account = wallet
        .accounts
        .identity_registration
        .as_ref()
        .expect("Expected identity registration account to exist");
    let xpub = account.account_xpub;

    let managed_account = managed_wallet_info
        .identity_registration_managed_account_mut()
        .expect("Failed to get identity registration managed account");

    // Get an identity registration address
    let address = managed_account.next_address(Some(&xpub), true).unwrap_or_else(|_| {
        // Generate a dummy address for testing
        dashcore::Address::p2pkh(
            &dashcore::PublicKey::from_slice(&[0x03; 33])
                .expect("Failed to create public key from bytes"),
            network,
        )
    });

    // Create a NORMAL transaction (not a special transaction) to the identity address
    let mut normal_tx = create_basic_transaction();
    normal_tx.output.push(TxOut {
        value: 50000,
        script_pubkey: address.script_pubkey(),
    });

    let context = TransactionContext::InBlock {
        height: 100000,
        block_hash: Some(
            BlockHash::from_slice(&[0u8; 32]).expect("Failed to create block hash from bytes"),
        ),
        timestamp: Some(1234567890),
    };

    let result = managed_wallet_info
        .check_transaction(
            &normal_tx,
            context,
            &mut wallet,
            true, // update state
        )
        .await;

    // A normal transaction to an identity registration address should NOT be detected
    // Identity addresses are only for special transactions (AssetLock)
    assert!(
        !result.is_relevant,
        "Normal payment to identity address should not be detected as relevant. Got is_relevant={}",
        result.is_relevant
    );

    assert_eq!(
        result.total_received, 0,
        "Should not have received any funds from normal payment to identity address. Got {} duffs",
        result.total_received
    );

    // Verify that identity registration account is not in the affected accounts
    assert!(
        !result.affected_accounts.iter().any(|acc| matches!(
            acc.account_type_match.to_account_type_to_check(),
            AccountTypeToCheck::IdentityRegistration
        )),
        "Identity registration account should not be affected by normal payment"
    );
}

#[test]
fn test_identity_topup() {
    // Asset lock for topping up an identity
    let tx = create_asset_lock_transaction(
        1, 50_000_000, // 0.5 DASH top-up
    );

    let tx_type = TransactionRouter::classify_transaction(&tx);
    assert_eq!(tx_type, TransactionType::AssetLock);

    let accounts = TransactionRouter::get_relevant_account_types(&tx_type);
    // All identity-related accounts should be checked
    assert!(accounts.contains(&AccountTypeToCheck::IdentityTopUp));
    assert!(accounts.contains(&AccountTypeToCheck::IdentityTopUpNotBound));
}

#[test]
fn test_multiple_topups_single_transaction() {
    // Asset lock with multiple outputs for bulk top-ups
    let mut tx = create_test_transaction(
        2,
        vec![
            25_000_000, // Top-up 1
            25_000_000, // Top-up 2
            25_000_000, // Top-up 3
            24_900_000, // Change
        ],
    );

    // Add asset lock payload with multiple credit outputs
    let credit_outputs = vec![
        TxOut {
            value: 25_000_000,
            script_pubkey: ScriptBuf::new(),
        },
        TxOut {
            value: 25_000_000,
            script_pubkey: ScriptBuf::new(),
        },
        TxOut {
            value: 25_000_000,
            script_pubkey: ScriptBuf::new(),
        },
    ];
    let payload = AssetLockPayload {
        version: 1,
        credit_outputs,
    };
    tx.special_transaction_payload = Some(TransactionPayload::AssetLockPayloadType(payload));

    let tx_type = TransactionRouter::classify_transaction(&tx);
    assert_eq!(tx_type, TransactionType::AssetLock);

    let accounts = TransactionRouter::get_relevant_account_types(&tx_type);
    assert!(accounts.contains(&AccountTypeToCheck::IdentityTopUp));
    assert!(accounts.contains(&AccountTypeToCheck::IdentityTopUpNotBound));
    assert!(accounts.contains(&AccountTypeToCheck::IdentityRegistration));
}

#[test]
fn test_identity_topup_from_coinjoin() {
    // Asset lock funded from CoinJoin output (privacy-preserving top-up)
    // This tests that asset lock transactions check all relevant account types
    let tx = create_asset_lock_transaction(
        3,           // Multiple inputs (could be from CoinJoin)
        100_000_000, // 1 DASH denomination (typical CoinJoin output)
    );

    let tx_type = TransactionRouter::classify_transaction(&tx);
    assert_eq!(tx_type, TransactionType::AssetLock);

    let accounts = TransactionRouter::get_relevant_account_types(&tx_type);
    // Should check standard accounts (including potential CoinJoin sources)
    assert!(accounts.contains(&AccountTypeToCheck::StandardBIP44));
    assert!(accounts.contains(&AccountTypeToCheck::StandardBIP32));
    // And all identity accounts
    assert!(accounts.contains(&AccountTypeToCheck::IdentityTopUp));
    assert!(accounts.contains(&AccountTypeToCheck::IdentityRegistration));
}
