//! Tests for asset unlock transaction handling

use super::helpers::test_addr;
use crate::test_utils::TestWalletContext;
use crate::transaction_checking::transaction_router::{
    AccountTypeToCheck, TransactionRouter, TransactionType,
};
use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
use dashcore::blockdata::transaction::special_transaction::asset_unlock::qualified_asset_unlock::AssetUnlockPayload;
use dashcore::blockdata::transaction::special_transaction::asset_unlock::request_info::AssetUnlockRequestInfo;
use dashcore::blockdata::transaction::special_transaction::asset_unlock::unqualified_asset_unlock::AssetUnlockBasePayload;
use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::blockdata::transaction::Transaction;
use dashcore::bls_sig_utils::BLSSignature;
use dashcore::hashes::Hash;
use dashcore::{BlockHash, OutPoint, ScriptBuf, TxIn, TxOut, Txid};

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
    let addr = test_addr();
    let mut tx = Transaction::dummy(&addr, 0..1, &[100_000_000]);

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
    let TestWalletContext {
        managed_wallet: mut managed_wallet_info,
        mut wallet,
        receive_address: address,
        ..
    } = TestWalletContext::new_random();

    // Create an asset unlock transaction
    let tx = dashcore::Transaction {
        version: 3, // Version 3 for special transactions
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

    let result =
        managed_wallet_info.check_core_transaction(&tx, context, &mut wallet, true, true).await;

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
    let TestWalletContext {
        managed_wallet: mut managed_wallet_info,
        mut wallet,
        receive_address: address,
        ..
    } = TestWalletContext::new_random();

    // Create an asset unlock transaction to our address
    let addr = test_addr();
    let mut tx = Transaction::dummy(&addr, 0..0, &[]);
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

    let result =
        managed_wallet_info.check_core_transaction(&tx, context, &mut wallet, true, true).await;

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
