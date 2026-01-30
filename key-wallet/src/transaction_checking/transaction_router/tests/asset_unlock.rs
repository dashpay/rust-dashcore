//! Tests for asset unlock transaction handling

use super::helpers::create_test_transaction;
use crate::transaction_checking::transaction_router::{
    AccountTypeToCheck, TransactionRouter, TransactionType,
};
use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
use crate::wallet::initialization::WalletAccountCreationOptions;
use crate::wallet::{ManagedWalletInfo, Wallet};
use crate::Network;
use dashcore::blockdata::transaction::special_transaction::asset_unlock::qualified_asset_unlock::AssetUnlockPayload;
use dashcore::blockdata::transaction::special_transaction::asset_unlock::request_info::AssetUnlockRequestInfo;
use dashcore::blockdata::transaction::special_transaction::asset_unlock::unqualified_asset_unlock::AssetUnlockBasePayload;
use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::bls_sig_utils::BLSSignature;
use dashcore::hashes::Hash;
use dashcore::{BlockHash, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid};

#[test]
fn test_asset_unlock_routing() {
    // Test routing logic for asset unlock transactions
    let tx_type = TransactionType::AssetUnlock;
    let accounts = TransactionRouter::get_relevant_account_types(&tx_type);

    // Asset unlock only goes to standard accounts
    assert_eq!(accounts.len(), 2);
    assert!(accounts.contains(&AccountTypeToCheck::StandardBIP44));
    assert!(accounts.contains(&AccountTypeToCheck::StandardBIP32));

    // Should NOT check identity accounts - those are for locks only
    assert!(!accounts.contains(&AccountTypeToCheck::IdentityRegistration));
    assert!(!accounts.contains(&AccountTypeToCheck::IdentityTopUp));
    assert!(!accounts.contains(&AccountTypeToCheck::IdentityTopUpNotBound));
    assert!(!accounts.contains(&AccountTypeToCheck::IdentityInvitation));
}

#[test]
fn test_asset_unlock_classification() {
    // Test that AssetUnlock transactions are properly classified
    let mut tx = create_test_transaction(1, vec![100_000_000]);

    // Create an asset unlock payload
    let base = AssetUnlockBasePayload {
        version: 1,
        index: 42,
        fee: 1000,
    };
    let request_info = AssetUnlockRequestInfo {
        request_height: 500000,
        quorum_hash: [5u8; 32].into(),
    };
    let payload = AssetUnlockPayload {
        base,
        request_info,
        quorum_sig: BLSSignature::from([6u8; 96]),
    };
    tx.special_transaction_payload = Some(TransactionPayload::AssetUnlockPayloadType(payload));

    // Verify classification
    let tx_type = TransactionRouter::classify_transaction(&tx);
    assert_eq!(tx_type, TransactionType::AssetUnlock, "Should classify as AssetUnlock transaction");

    // Verify routing for AssetUnlock
    let accounts = TransactionRouter::get_relevant_account_types(&tx_type);
    assert_eq!(accounts.len(), 2, "AssetUnlock should route to exactly 2 account types");
    assert!(accounts.contains(&AccountTypeToCheck::StandardBIP44));
    assert!(accounts.contains(&AccountTypeToCheck::StandardBIP32));
}

#[tokio::test]
async fn test_asset_unlock_transaction_routing() {
    let mut wallet = Wallet::new_random(Network::Testnet, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with default options");

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get the BIP44 account
    let account = wallet
        .accounts
        .standard_bip44_accounts
        .get(&0)
        .expect("Expected BIP44 account at index 0 to exist");
    let xpub = account.account_xpub;

    let managed_account = managed_wallet_info
        .first_bip44_managed_account_mut()
        .expect("Failed to get first BIP44 managed account");

    // Get an address from standard account (where unlocked funds go)
    let address = managed_account
        .next_receive_address(Some(&xpub), true)
        .expect("Failed to generate receive address");

    // Create an asset unlock transaction
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
        output: vec![TxOut {
            value: 100_000_000, // 1 DASH unlocked
            script_pubkey: address.script_pubkey(),
        }],
        special_transaction_payload: Some(TransactionPayload::AssetUnlockPayloadType(
            AssetUnlockPayload {
                base: AssetUnlockBasePayload {
                    version: 1,
                    index: 42,
                    fee: 1000,
                },
                request_info: AssetUnlockRequestInfo {
                    request_height: 500000,
                    quorum_hash: [5u8; 32].into(),
                },
                quorum_sig: BLSSignature::from([6u8; 96]),
            },
        )),
    };

    let context = TransactionContext::InBlock {
        height: 500100,
        block_hash: Some(
            BlockHash::from_slice(&[0u8; 32]).expect("Failed to create block hash from bytes"),
        ),
        timestamp: Some(1234567890),
    };

    let result = managed_wallet_info.check_transaction(&tx, context, &mut wallet, true).await;

    // The transaction should be recognized as relevant
    assert!(result.is_relevant, "Asset unlock transaction should be recognized as relevant");

    // Should have received the unlocked funds
    assert_eq!(
        result.total_received, 100_000_000,
        "Should have received 1 DASH (100000000 duffs) from asset unlock"
    );

    // Should have affected the BIP44 account
    assert!(
        result.affected_accounts.iter().any(|acc| matches!(
            acc.account_type_match.to_account_type_to_check(),
            AccountTypeToCheck::StandardBIP44
        )),
        "Asset unlock should have affected the BIP44 account"
    );
}

#[tokio::test]
async fn test_asset_unlock_routing_to_bip32_account() {
    // Test AssetUnlock routing to BIP32 accounts

    // Create wallet with default options (includes both BIP44 and BIP32)
    let mut wallet = Wallet::new_random(Network::Testnet, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet");

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get address from BIP44 account (we'll use BIP44 to test the routing)
    let managed_account = managed_wallet_info
        .first_bip44_managed_account_mut()
        .expect("Failed to get first BIP44 managed account");

    // Get the account's xpub from wallet
    let account =
        wallet.accounts.standard_bip44_accounts.get(&0).expect("Expected BIP44 account at index 0");
    let xpub = account.account_xpub;

    let address = managed_account
        .next_receive_address(Some(&xpub), true)
        .expect("Failed to generate receive address");

    // Create an asset unlock transaction to our address
    let mut tx = create_test_transaction(0, vec![]);
    tx.output.push(TxOut {
        value: 200_000_000, // 2 DASH unlocked
        script_pubkey: address.script_pubkey(),
    });

    // Add AssetUnlock payload
    let base = AssetUnlockBasePayload {
        version: 1,
        index: 100,
        fee: 2000,
    };
    let request_info = AssetUnlockRequestInfo {
        request_height: 600000,
        quorum_hash: [7u8; 32].into(),
    };
    let payload = AssetUnlockPayload {
        base,
        request_info,
        quorum_sig: BLSSignature::from([8u8; 96]),
    };
    tx.special_transaction_payload = Some(TransactionPayload::AssetUnlockPayloadType(payload));

    let context = TransactionContext::InBlock {
        height: 600100,
        block_hash: Some(BlockHash::from_slice(&[0u8; 32]).expect("Failed to create block hash")),
        timestamp: Some(1234567890),
    };

    let result = managed_wallet_info.check_transaction(&tx, context, &mut wallet, true).await;

    // Should be recognized as relevant
    assert!(result.is_relevant, "Asset unlock transaction to BIP32 account should be relevant");

    // Should have received the unlocked funds
    assert_eq!(result.total_received, 200_000_000, "Should have received 2 DASH from asset unlock");

    // Should have affected the BIP44 account (since we used BIP44 for the address)
    assert!(
        result.affected_accounts.iter().any(|acc| matches!(
            acc.account_type_match.to_account_type_to_check(),
            AccountTypeToCheck::StandardBIP44
        )),
        "Asset unlock should have affected the BIP44 account"
    );
}
