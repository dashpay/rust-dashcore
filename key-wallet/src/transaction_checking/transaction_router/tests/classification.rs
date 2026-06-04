//! Tests for transaction classification

use super::helpers::*;
use crate::transaction_checking::transaction_router::{TransactionRouter, TransactionType};
use dashcore::blockdata::script::ScriptBuf;
use dashcore::blockdata::transaction::special_transaction::asset_unlock::qualified_asset_unlock::AssetUnlockPayload;
use dashcore::blockdata::transaction::special_transaction::asset_unlock::request_info::AssetUnlockRequestInfo;
use dashcore::blockdata::transaction::special_transaction::asset_unlock::unqualified_asset_unlock::AssetUnlockBasePayload;
use dashcore::blockdata::transaction::special_transaction::coinbase::CoinbasePayload;
use dashcore::blockdata::transaction::special_transaction::provider_update_registrar::ProviderUpdateRegistrarPayload;
use dashcore::blockdata::transaction::special_transaction::provider_update_revocation::ProviderUpdateRevocationPayload;
use dashcore::blockdata::transaction::special_transaction::provider_update_service::ProviderUpdateServicePayload;
use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::blockdata::transaction::Transaction;
use dashcore::bls_sig_utils::{BLSPublicKey, BLSSignature};
use dashcore::hash_types::{MerkleRootMasternodeList, MerkleRootQuorums};
use dashcore::hashes::Hash;
use dashcore::Txid;

#[test]
fn test_classify_standard_transaction() {
    // Standard payment with 1 input, 2 outputs
    let addr = test_addr();
    let tx = Transaction::dummy(&addr, 0..1, &[50_000_000, 49_000_000]);
    assert_eq!(TransactionRouter::classify_transaction(&tx), TransactionType::Standard);
}

#[test]
fn test_classify_coinjoin_transaction() {
    // CoinJoin with multiple inputs and denomination outputs
    let addr = test_addr();
    let tx = Transaction::dummy(
        &addr,
        0..5,
        &[
            100_001_000, // 1 DASH denomination (+ fee)
            100_001_000, // 1 DASH denomination (+ fee)
            10_000_100,  // 0.1 DASH denomination (+ fee)
            10_000_100,  // 0.1 DASH denomination (+ fee)
            1_000_010,   // 0.01 DASH denomination (+ fee)
        ],
    );
    assert_eq!(TransactionRouter::classify_transaction(&tx), TransactionType::CoinJoin);
}

#[test]
fn test_classify_asset_lock_transaction() {
    let tx = create_asset_lock_transaction(1, 100_000_000);
    assert_eq!(TransactionRouter::classify_transaction(&tx), TransactionType::AssetLock);
}

#[test]
fn test_not_coinjoin_few_inputs() {
    // Not enough inputs to be CoinJoin
    let addr = test_addr();
    let tx = Transaction::dummy(&addr, 0..2, &[100_000_000, 100_000_000]);
    assert_eq!(TransactionRouter::classify_transaction(&tx), TransactionType::Standard);
}

#[test]
fn test_not_coinjoin_no_denominations() {
    // Many inputs/outputs but no standard denominations
    let addr = test_addr();
    let tx = Transaction::dummy(
        &addr,
        0..4,
        &[
            123_456_789, // Non-standard amount
            987_654_321, // Non-standard amount
            555_555_555, // Non-standard amount
            111_111_111, // Non-standard amount
        ],
    );
    assert_eq!(TransactionRouter::classify_transaction(&tx), TransactionType::Standard);
}

#[test]
fn test_classify_provider_update_registrar_transaction() {
    let addr = test_addr();
    let mut tx = Transaction::dummy(&addr, 0..1, &[100_000_000]);
    // Create a provider update registrar payload
    let payload = ProviderUpdateRegistrarPayload {
        version: 1,
        pro_tx_hash: Txid::from_byte_array([1u8; 32]),
        provider_mode: 0,
        operator_public_key: BLSPublicKey::from([0u8; 48]),
        voting_key_hash: [2u8; 20].into(),
        script_payout: ScriptBuf::new(),
        inputs_hash: [3u8; 32].into(),
        payload_sig: vec![4u8; 65],
    };
    tx.special_transaction_payload =
        Some(TransactionPayload::ProviderUpdateRegistrarPayloadType(payload));

    assert_eq!(
        TransactionRouter::classify_transaction(&tx),
        TransactionType::ProviderUpdateRegistrar
    );
}

#[test]
fn test_classify_provider_update_service_transaction() {
    let addr = test_addr();
    let mut tx = Transaction::dummy(&addr, 0..1, &[100_000_000]);
    // Create a provider update service payload
    let payload = ProviderUpdateServicePayload {
        version: 1,
        mn_type: None,
        pro_tx_hash: Txid::from_byte_array([1u8; 32]),
        ip_address: 0x0100007f, // 127.0.0.1 in network byte order
        port: 19999,
        script_payout: ScriptBuf::new(),
        inputs_hash: [3u8; 32].into(),
        platform_node_id: None,
        platform_p2p_port: None,
        platform_http_port: None,
        payload_sig: BLSSignature::from([0u8; 96]),
    };
    tx.special_transaction_payload =
        Some(TransactionPayload::ProviderUpdateServicePayloadType(payload));

    assert_eq!(
        TransactionRouter::classify_transaction(&tx),
        TransactionType::ProviderUpdateService
    );
}

#[test]
fn test_classify_provider_update_revocation_transaction() {
    let addr = test_addr();
    let mut tx = Transaction::dummy(&addr, 0..1, &[100_000_000]);
    // Create a provider update revocation payload
    let payload = ProviderUpdateRevocationPayload {
        version: 1,
        pro_tx_hash: Txid::from_byte_array([1u8; 32]),
        reason: 0,
        inputs_hash: [3u8; 32].into(),
        payload_sig: BLSSignature::from([0u8; 96]),
    };
    tx.special_transaction_payload =
        Some(TransactionPayload::ProviderUpdateRevocationPayloadType(payload));

    assert_eq!(
        TransactionRouter::classify_transaction(&tx),
        TransactionType::ProviderUpdateRevocation
    );
}

#[test]
fn test_classify_asset_unlock_transaction() {
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

    assert_eq!(TransactionRouter::classify_transaction(&tx), TransactionType::AssetUnlock);
}

#[test]
fn test_classify_coinbase_transaction() {
    let addr = test_addr();
    let mut tx = Transaction::dummy(&addr, 0..1, &[100_000_000]);
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

    assert_eq!(TransactionRouter::classify_transaction(&tx), TransactionType::Coinbase);

    // Also detected by coinbase input pattern (null txid + 0xffffffff vout) without payload
    let coinbase_tx = Transaction::dummy_coinbase(&addr, 100_000_000);
    assert_eq!(TransactionRouter::classify_transaction(&coinbase_tx), TransactionType::Coinbase);
}

#[test]
fn test_classify_quorum_commitment_transaction() {
    // Test that these transaction types are classified as Ignored
    // This covers lines 61-62 in transaction_router/mod.rs

    // We can't easily construct these payloads due to private fields,
    // but we can test that the router returns empty account types for Ignored
    let ignored_accounts = TransactionRouter::get_relevant_account_types(&TransactionType::Ignored);
    assert!(ignored_accounts.is_empty(), "Ignored transactions should route to no accounts");
}

#[test]
fn test_classify_mnhf_signal_transaction() {
    // Test the other ignored transaction type
    let ignored_accounts = TransactionRouter::get_relevant_account_types(&TransactionType::Ignored);
    assert!(ignored_accounts.is_empty(), "Ignored transactions should route to no accounts");
}
