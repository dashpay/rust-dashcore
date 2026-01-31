//! Tests for provider/masternode transaction handling

use super::helpers::*;
use crate::transaction_checking::transaction_router::{
    AccountTypeToCheck, TransactionRouter, TransactionType,
};
use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
use crate::wallet::initialization::WalletAccountCreationOptions;
use crate::wallet::{ManagedWalletInfo, Wallet};
use crate::Network;
use dashcore::blockdata::transaction::special_transaction::provider_registration::{
    ProviderMasternodeType, ProviderRegistrationPayload,
};
use dashcore::blockdata::transaction::special_transaction::provider_update_registrar::ProviderUpdateRegistrarPayload;
use dashcore::blockdata::transaction::special_transaction::provider_update_revocation::ProviderUpdateRevocationPayload;
use dashcore::blockdata::transaction::special_transaction::provider_update_service::ProviderUpdateServicePayload;
use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::bls_sig_utils::BLSSignature;
use dashcore::hashes::Hash;
use dashcore::{BlockHash, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid};

#[test]
fn test_provider_update_registrar_classification() {
    // Test ProviderUpdateRegistrar classification
    let mut tx = create_test_transaction(1, vec![100_000_000]);

    let payload = ProviderUpdateRegistrarPayload {
        version: 1,
        pro_tx_hash: Txid::from_byte_array([1u8; 32]),
        provider_mode: 0,
        operator_public_key: dashcore::bls_sig_utils::BLSPublicKey::from([0u8; 48]),
        voting_key_hash: [2u8; 20].into(),
        script_payout: ScriptBuf::new(),
        inputs_hash: [3u8; 32].into(),
        payload_sig: vec![4u8; 65],
    };

    tx.special_transaction_payload =
        Some(TransactionPayload::ProviderUpdateRegistrarPayloadType(payload));

    // Verify classification
    let tx_type = TransactionRouter::classify_transaction(&tx);
    assert_eq!(
        tx_type,
        TransactionType::ProviderUpdateRegistrar,
        "Should classify as ProviderUpdateRegistrar"
    );
}

#[test]
fn test_provider_update_service_classification() {
    // Test ProviderUpdateService classification
    let mut tx = create_test_transaction(1, vec![100_000_000]);

    let payload = ProviderUpdateServicePayload {
        version: 1,
        mn_type: None,
        pro_tx_hash: Txid::from_byte_array([1u8; 32]),
        ip_address: 0x0100007f, // 127.0.0.1
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

    // Verify classification
    let tx_type = TransactionRouter::classify_transaction(&tx);
    assert_eq!(
        tx_type,
        TransactionType::ProviderUpdateService,
        "Should classify as ProviderUpdateService"
    );
}

#[test]
fn test_provider_update_revocation_classification() {
    // Test ProviderUpdateRevocation classification
    let mut tx = create_test_transaction(1, vec![100_000_000]);

    let payload = ProviderUpdateRevocationPayload {
        version: 1,
        pro_tx_hash: Txid::from_byte_array([1u8; 32]),
        reason: 0,
        inputs_hash: [3u8; 32].into(),
        payload_sig: BLSSignature::from([0u8; 96]),
    };

    tx.special_transaction_payload =
        Some(TransactionPayload::ProviderUpdateRevocationPayloadType(payload));

    // Verify classification
    let tx_type = TransactionRouter::classify_transaction(&tx);
    assert_eq!(
        tx_type,
        TransactionType::ProviderUpdateRevocation,
        "Should classify as ProviderUpdateRevocation"
    );
}

#[test]
fn test_provider_registration_routing() {
    // Test routing logic for provider registration transactions
    // We focus on testing the routing, not creating valid provider payloads
    let tx_type = TransactionType::ProviderRegistration;
    let accounts = TransactionRouter::get_relevant_account_types(&tx_type);

    // Should check all provider key types and standard accounts
    assert!(accounts.contains(&AccountTypeToCheck::ProviderOwnerKeys));
    assert!(accounts.contains(&AccountTypeToCheck::ProviderOperatorKeys));
    assert!(accounts.contains(&AccountTypeToCheck::ProviderVotingKeys));
    assert!(accounts.contains(&AccountTypeToCheck::ProviderPlatformKeys));
    assert!(accounts.contains(&AccountTypeToCheck::StandardBIP44));
    assert!(accounts.contains(&AccountTypeToCheck::StandardBIP32));
    assert!(accounts.contains(&AccountTypeToCheck::CoinJoin));
}

#[tokio::test]
async fn test_provider_registration_transaction_routing_check_owner_only() {
    let network = Network::Testnet;

    // We create another wallet that will hold keys not in our main wallet
    let other_wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with default options");

    let mut wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with default options");

    let mut other_managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&other_wallet, "Other".to_string());

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get addresses from provider accounts
    let managed_owner = managed_wallet_info
        .provider_owner_keys_managed_account_mut()
        .expect("Failed to get provider owner keys managed account");
    let owner_address = managed_owner.next_address(None, true).expect("expected owner address");

    let voting_address = other_managed_wallet_info
        .provider_voting_keys_managed_account_mut()
        .expect("Failed to get provider voting keys managed account")
        .next_address(None, true)
        .expect("expected voting address");

    let operator_public_key = other_managed_wallet_info
        .provider_operator_keys_managed_account_mut()
        .expect("Failed to get provider operator keys managed account")
        .next_bls_operator_key(None, true)
        .expect("expected voting address");

    // Payout addresses for providers are just regular addresses, not a separate account
    // For testing, we'll use the first standard account's address
    let payout_address = other_managed_wallet_info
        .first_bip44_managed_account_mut()
        .and_then(|acc| acc.next_receive_address(None, true).ok())
        .unwrap_or_else(|| {
            dashcore::Address::p2pkh(
                &dashcore::PublicKey::from_slice(&[0x02; 33])
                    .expect("Failed to create public key from bytes"),
                network,
            )
        });

    // Create a ProRegTx transaction
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
            // Change output
            TxOut {
                value: 50_000_000,
                script_pubkey: payout_address.script_pubkey(),
            },
        ],
        special_transaction_payload: Some(TransactionPayload::ProviderRegistrationPayloadType(
            ProviderRegistrationPayload {
                version: 1,
                masternode_type: ProviderMasternodeType::Regular,
                masternode_mode: 0,
                collateral_outpoint: OutPoint {
                    txid: Txid::from_byte_array([1u8; 32]),
                    vout: 0,
                },
                service_address: "127.0.0.1:19999"
                    .parse()
                    .expect("Failed to parse service address"),
                owner_key_hash: *owner_address
                    .payload()
                    .as_pubkey_hash()
                    .expect("Owner address should be P2PKH"),
                operator_public_key: operator_public_key.0.to_compressed().into(),
                voting_key_hash: *voting_address
                    .payload()
                    .as_pubkey_hash()
                    .expect("Voting address should be P2PKH"),
                operator_reward: 0,
                script_payout: payout_address.script_pubkey(),
                inputs_hash: dashcore::hash_types::InputsHash::from_slice(&[6u8; 32])
                    .expect("Failed to create inputs hash from bytes"),
                signature: vec![7u8; 65], // Simplified signature
                platform_node_id: None,
                platform_p2p_port: None,
                platform_http_port: None,
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

    let result = managed_wallet_info.check_transaction(&tx, context, &mut wallet, true).await;

    println!(
        "Provider registration transaction result: is_relevant={}, received={}",
        result.is_relevant, result.total_received
    );

    // The transaction SHOULD be recognized as relevant to provider accounts
    assert!(
        result.is_relevant,
        "Provider registration transaction should be recognized as relevant"
    );

    // Should detect funds received by owner and payout addresses
    assert_eq!(result.total_received, 0, "Should not have received funds");

    assert!(
        result
            .affected_accounts
            .iter()
            .all(|acc| matches!(acc.account_type_match.to_account_type_to_check(),
            crate::transaction_checking::transaction_router::AccountTypeToCheck::ProviderOwnerKeys
        )),
        "Should have affected provider owner accounts"
    );
}

#[tokio::test]
async fn test_provider_registration_transaction_routing_check_voting_only() {
    let network = Network::Testnet;

    // We create another wallet that will hold keys not in our main wallet
    let other_wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with default options");

    let mut wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with default options");

    let mut other_managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&other_wallet, "Other".to_string());

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get addresses from provider accounts
    let owner_address = other_managed_wallet_info
        .provider_owner_keys_managed_account_mut()
        .expect("Failed to get provider owner keys managed account")
        .next_address(None, true)
        .expect("expected owner address");

    let managed_voting = managed_wallet_info
        .provider_voting_keys_managed_account_mut()
        .expect("Failed to get provider voting keys managed account");
    let voting_address = managed_voting.next_address(None, true).expect("expected voting address");

    let operator_public_key = other_managed_wallet_info
        .provider_operator_keys_managed_account_mut()
        .expect("Failed to get provider operator keys managed account")
        .next_bls_operator_key(None, true)
        .expect("expected operator key");

    // Payout addresses for providers are just regular addresses, not a separate account
    // For testing, we'll use the first standard account's address
    let payout_address = other_managed_wallet_info
        .first_bip44_managed_account_mut()
        .and_then(|acc| acc.next_receive_address(None, true).ok())
        .unwrap_or_else(|| {
            dashcore::Address::p2pkh(
                &dashcore::PublicKey::from_slice(&[0x02; 33])
                    .expect("Failed to create public key from bytes"),
                network,
            )
        });

    // Create a ProRegTx transaction
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
            // Change output
            TxOut {
                value: 50_000_000,
                script_pubkey: payout_address.script_pubkey(),
            },
        ],
        special_transaction_payload: Some(TransactionPayload::ProviderRegistrationPayloadType(
            ProviderRegistrationPayload {
                version: 1,
                masternode_type: ProviderMasternodeType::Regular,
                masternode_mode: 0,
                collateral_outpoint: OutPoint {
                    txid: Txid::from_byte_array([1u8; 32]),
                    vout: 0,
                },
                service_address: "127.0.0.1:19999"
                    .parse()
                    .expect("Failed to parse service address"),
                owner_key_hash: *owner_address
                    .payload()
                    .as_pubkey_hash()
                    .expect("Owner address should be P2PKH"),
                operator_public_key: operator_public_key.0.to_compressed().into(),
                voting_key_hash: *voting_address
                    .payload()
                    .as_pubkey_hash()
                    .expect("Voting address should be P2PKH"),
                operator_reward: 0,
                script_payout: payout_address.script_pubkey(),
                inputs_hash: dashcore::hash_types::InputsHash::from_slice(&[6u8; 32])
                    .expect("Failed to create inputs hash from bytes"),
                signature: vec![7u8; 65], // Simplified signature
                platform_node_id: None,
                platform_p2p_port: None,
                platform_http_port: None,
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

    let result = managed_wallet_info.check_transaction(&tx, context, &mut wallet, true).await;

    println!(
        "Provider registration transaction result (voting): is_relevant={}, received={}",
        result.is_relevant, result.total_received
    );

    // The transaction SHOULD be recognized as relevant to provider accounts
    assert!(
        result.is_relevant,
        "Provider registration transaction should be recognized as relevant for voting keys"
    );

    // Should detect funds received by voting addresses
    assert_eq!(result.total_received, 0, "Should not have received funds");

    assert!(
        result
            .affected_accounts
            .iter()
            .all(|acc| matches!(acc.account_type_match.to_account_type_to_check(),
            crate::transaction_checking::transaction_router::AccountTypeToCheck::ProviderVotingKeys
        )),
        "Should have affected provider voting accounts"
    );
}

#[tokio::test]
async fn test_provider_registration_transaction_routing_check_operator_only() {
    let network = Network::Testnet;

    // We create another wallet that will hold keys not in our main wallet
    let other_wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with default options");

    let mut wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with default options");

    let mut other_managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&other_wallet, "Other".to_string());

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get addresses from provider accounts
    let owner_address = other_managed_wallet_info
        .provider_owner_keys_managed_account_mut()
        .expect("Failed to get provider owner keys managed account")
        .next_address(None, true)
        .expect("expected owner address");

    let voting_address = other_managed_wallet_info
        .provider_voting_keys_managed_account_mut()
        .expect("Failed to get provider voting keys managed account")
        .next_address(None, true)
        .expect("expected voting address");

    let managed_operator = managed_wallet_info
        .provider_operator_keys_managed_account_mut()
        .expect("Failed to get provider operator keys managed account");
    let operator_public_key =
        managed_operator.next_bls_operator_key(None, true).expect("expected operator key");

    // Payout addresses for providers are just regular addresses, not a separate account
    // For testing, we'll use the first standard account's address
    let payout_address = other_managed_wallet_info
        .first_bip44_managed_account_mut()
        .and_then(|acc| acc.next_receive_address(None, true).ok())
        .unwrap_or_else(|| {
            dashcore::Address::p2pkh(
                &dashcore::PublicKey::from_slice(&[0x02; 33])
                    .expect("Failed to create public key from bytes"),
                network,
            )
        });

    // Create a ProRegTx transaction
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
            // Change output
            TxOut {
                value: 50_000_000,
                script_pubkey: payout_address.script_pubkey(),
            },
        ],
        special_transaction_payload: Some(TransactionPayload::ProviderRegistrationPayloadType(
            ProviderRegistrationPayload {
                version: 1,
                masternode_type: ProviderMasternodeType::Regular,
                masternode_mode: 0,
                collateral_outpoint: OutPoint {
                    txid: Txid::from_byte_array([1u8; 32]),
                    vout: 0,
                },
                service_address: "127.0.0.1:19999"
                    .parse()
                    .expect("Failed to parse service address"),
                owner_key_hash: *owner_address
                    .payload()
                    .as_pubkey_hash()
                    .expect("Owner address should be P2PKH"),
                operator_public_key: operator_public_key.0.to_compressed().into(),
                voting_key_hash: *voting_address
                    .payload()
                    .as_pubkey_hash()
                    .expect("Voting address should be P2PKH"),
                operator_reward: 0,
                script_payout: payout_address.script_pubkey(),
                inputs_hash: dashcore::hash_types::InputsHash::from_slice(&[6u8; 32])
                    .expect("Failed to create inputs hash from bytes"),
                signature: vec![7u8; 65], // Simplified signature
                platform_node_id: None,
                platform_p2p_port: None,
                platform_http_port: None,
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

    let result = managed_wallet_info.check_transaction(&tx, context, &mut wallet, true).await;

    println!(
        "Provider registration transaction result (operator): is_relevant={}, received={}",
        result.is_relevant, result.total_received
    );

    // The transaction SHOULD be recognized as relevant to provider accounts
    assert!(
        result.is_relevant,
        "Provider registration transaction should be recognized as relevant for operator keys"
    );

    // Should detect operator key usage
    assert_eq!(result.total_received, 0, "Should not have received funds");

    assert!(
        result
            .affected_accounts
            .iter()
            .all(|acc| matches!(acc.account_type_match.to_account_type_to_check(),
            crate::transaction_checking::transaction_router::AccountTypeToCheck::ProviderOperatorKeys
        )),
        "Should have affected provider operator accounts"
    );
}

#[test]
fn test_provider_update_service_routing() {
    // Test routing logic for provider update service transactions
    let tx_type = TransactionType::ProviderUpdateService;
    let accounts = TransactionRouter::get_relevant_account_types(&tx_type);

    // Should check operator keys, platform keys, and standard accounts
    assert!(accounts.contains(&AccountTypeToCheck::ProviderOperatorKeys));
    assert!(accounts.contains(&AccountTypeToCheck::ProviderPlatformKeys));
    assert!(accounts.contains(&AccountTypeToCheck::StandardBIP44));
    assert!(accounts.contains(&AccountTypeToCheck::StandardBIP32));
    assert!(accounts.contains(&AccountTypeToCheck::CoinJoin));
}

#[test]
fn test_provider_update_registrar_routing() {
    // Test routing logic for provider update registrar transactions
    let tx_type = TransactionType::ProviderUpdateRegistrar;
    let accounts = TransactionRouter::get_relevant_account_types(&tx_type);

    // Should check voting keys, operator keys, and standard accounts
    assert!(accounts.contains(&AccountTypeToCheck::ProviderVotingKeys));
    assert!(accounts.contains(&AccountTypeToCheck::ProviderOperatorKeys));
    assert!(accounts.contains(&AccountTypeToCheck::StandardBIP44));
    assert!(accounts.contains(&AccountTypeToCheck::StandardBIP32));
    assert!(accounts.contains(&AccountTypeToCheck::CoinJoin));
}

#[test]
fn test_provider_update_revocation_routing() {
    // Test routing logic for provider update revocation transactions
    let tx_type = TransactionType::ProviderUpdateRevocation;
    let accounts = TransactionRouter::get_relevant_account_types(&tx_type);

    // Should check standard accounts and CoinJoin
    assert!(accounts.contains(&AccountTypeToCheck::StandardBIP44));
    assert!(accounts.contains(&AccountTypeToCheck::StandardBIP32));
    assert!(accounts.contains(&AccountTypeToCheck::CoinJoin));
    // Should NOT check provider-specific keys for revocation
    assert!(!accounts.contains(&AccountTypeToCheck::ProviderOwnerKeys));
    assert!(!accounts.contains(&AccountTypeToCheck::ProviderOperatorKeys));
    assert!(!accounts.contains(&AccountTypeToCheck::ProviderVotingKeys));
    assert!(!accounts.contains(&AccountTypeToCheck::ProviderPlatformKeys));
}

#[tokio::test]
async fn test_provider_registration_transaction_routing_check_platform_only() {
    let network = Network::Testnet;

    // We create another wallet that will hold keys not in our main wallet
    let other_wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with default options");

    let mut wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with default options");

    let mut other_managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&other_wallet, "Other".to_string());

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get addresses from provider accounts
    let owner_address = other_managed_wallet_info
        .provider_owner_keys_managed_account_mut()
        .expect("Failed to get provider owner keys managed account")
        .next_address(None, true)
        .expect("expected owner address");

    let voting_address = other_managed_wallet_info
        .provider_voting_keys_managed_account_mut()
        .expect("Failed to get provider voting keys managed account")
        .next_address(None, true)
        .expect("expected voting address");

    let operator_public_key = other_managed_wallet_info
        .provider_operator_keys_managed_account_mut()
        .expect("Failed to get provider operator keys managed account")
        .next_bls_operator_key(None, true)
        .expect("expected operator key");

    // Get platform key from our wallet
    let managed_platform = managed_wallet_info
        .provider_platform_keys_managed_account_mut()
        .expect("Failed to get provider platform keys managed account");

    // For platform keys, we need to get the EdDSA key and derive the node ID
    // We need to provide the extended private key for EdDSA
    // In a real scenario this would come from the wallet's key derivation
    let root_key = wallet.root_extended_priv_key().expect("Expected root extended priv key");
    let eddsa_extended_key =
        root_key.to_eddsa_extended_priv_key(network).expect("expected EdDSA key");
    let (_platform_key, info) = managed_platform
        .next_eddsa_platform_key(eddsa_extended_key, true)
        .expect("expected platform key");

    let platform_node_id = info.address;

    // Payout addresses for providers are just regular addresses, not a separate account
    // For testing, we'll use the first standard account's address
    let payout_address = other_managed_wallet_info
        .first_bip44_managed_account_mut()
        .and_then(|acc| acc.next_receive_address(None, true).ok())
        .unwrap_or_else(|| {
            dashcore::Address::p2pkh(
                &dashcore::PublicKey::from_slice(&[0x02; 33])
                    .expect("Failed to create public key from bytes"),
                network,
            )
        });

    // Create a ProRegTx transaction with platform fields (HighPerformance/EvoNode)
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
            // Change output
            TxOut {
                value: 50_000_000,
                script_pubkey: payout_address.script_pubkey(),
            },
        ],
        special_transaction_payload: Some(TransactionPayload::ProviderRegistrationPayloadType(
            ProviderRegistrationPayload {
                version: 1,
                masternode_type: ProviderMasternodeType::HighPerformance,
                masternode_mode: 0,
                collateral_outpoint: OutPoint {
                    txid: Txid::from_byte_array([1u8; 32]),
                    vout: 0,
                },
                service_address: "127.0.0.1:19999"
                    .parse()
                    .expect("Failed to parse service address"),
                owner_key_hash: *owner_address
                    .payload()
                    .as_pubkey_hash()
                    .expect("Owner address should be P2PKH"),
                operator_public_key: operator_public_key.0.to_compressed().into(),
                voting_key_hash: *voting_address
                    .payload()
                    .as_pubkey_hash()
                    .expect("Voting address should be P2PKH"),
                operator_reward: 0,
                script_payout: payout_address.script_pubkey(),
                inputs_hash: dashcore::hash_types::InputsHash::from_slice(&[6u8; 32])
                    .expect("Failed to create inputs hash from bytes"),
                signature: vec![7u8; 65], // Simplified signature
                platform_node_id: Some(
                    *platform_node_id
                        .payload()
                        .as_pubkey_hash()
                        .expect("Platform node ID address should be P2PKH"),
                ),
                platform_p2p_port: Some(26656),
                platform_http_port: Some(8080),
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

    let result = managed_wallet_info.check_transaction(&tx, context, &mut wallet, true).await;

    println!(
        "Provider registration transaction result (platform): is_relevant={}, received={}",
        result.is_relevant, result.total_received
    );

    // The transaction SHOULD be recognized as relevant to provider accounts
    assert!(
        result.is_relevant,
        "Provider registration transaction should be recognized as relevant for platform keys"
    );

    // Should detect platform key usage
    assert_eq!(result.total_received, 0, "Should not have received funds");

    assert!(
        result
            .affected_accounts
            .iter()
            .all(|acc| matches!(acc.account_type_match.to_account_type_to_check(),
            crate::transaction_checking::transaction_router::AccountTypeToCheck::ProviderPlatformKeys
        )),
        "Should have affected provider platform accounts"
    );
}

#[test]
fn test_provider_update_service_with_operator_key() {
    let mut tx = create_test_transaction(1, vec![100_000_000]);

    // Create provider update service payload
    use dashcore::blockdata::transaction::special_transaction::provider_update_service::ProviderUpdateServicePayload;
    use dashcore::bls_sig_utils::BLSSignature;
    let payload = ProviderUpdateServicePayload {
        version: 1, // LegacyBLS version
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

    // Verify classification
    let tx_type = TransactionRouter::classify_transaction(&tx);
    assert_eq!(
        tx_type,
        TransactionType::ProviderUpdateService,
        "Should classify as provider update service"
    );

    // Verify routing
    let accounts = TransactionRouter::get_relevant_account_types(&tx_type);
    assert!(
        accounts.contains(&AccountTypeToCheck::ProviderOperatorKeys),
        "Should route to provider operator keys"
    );
    assert!(
        accounts.contains(&AccountTypeToCheck::ProviderPlatformKeys),
        "Should route to provider platform keys"
    );
}

#[tokio::test]
async fn test_provider_update_registrar_with_voting_and_operator() {
    // Test provider update registrar classification and routing
    let mut wallet = Wallet::new_random(Network::Testnet, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with default options");

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get voting address
    let voting_address = managed_wallet_info
        .provider_voting_keys_managed_account_mut()
        .expect("Failed to get provider voting keys managed account")
        .next_address(None, true)
        .expect("expected voting address");

    // Get BLS operator key
    let operator_public_key = managed_wallet_info
        .provider_operator_keys_managed_account_mut()
        .expect("Failed to get provider operator keys managed account")
        .next_bls_operator_key(None, true)
        .expect("expected operator key");

    let mut tx = create_test_transaction(1, vec![100_000_000]);

    // Create provider update registrar payload
    use dashcore::blockdata::transaction::special_transaction::provider_update_registrar::ProviderUpdateRegistrarPayload;
    let payload = ProviderUpdateRegistrarPayload {
        version: 1,
        pro_tx_hash: Txid::from_byte_array([1u8; 32]),
        provider_mode: 0,
        operator_public_key: operator_public_key.0.to_compressed().into(),
        voting_key_hash: *voting_address
            .payload()
            .as_pubkey_hash()
            .expect("Voting should be P2PKH"),
        script_payout: ScriptBuf::new(),
        inputs_hash: [3u8; 32].into(),
        payload_sig: vec![4u8; 65],
    };

    tx.special_transaction_payload =
        Some(TransactionPayload::ProviderUpdateRegistrarPayloadType(payload));

    let context = TransactionContext::InBlock {
        height: 100000,
        block_hash: Some(BlockHash::from_slice(&[0u8; 32]).expect("Failed to create block hash")),
        timestamp: Some(1234567890),
    };

    let result = managed_wallet_info.check_transaction(&tx, context, &mut wallet, true).await;

    // Should be recognized as relevant due to voting and operator keys
    assert!(result.is_relevant, "Provider update registrar should be relevant");

    let affected_types: Vec<_> = result
        .affected_accounts
        .iter()
        .map(|acc| acc.account_type_match.to_account_type_to_check())
        .collect();

    assert!(
        affected_types.contains(&AccountTypeToCheck::ProviderVotingKeys),
        "Should have affected provider voting accounts"
    );
    assert!(
        affected_types.contains(&AccountTypeToCheck::ProviderOperatorKeys),
        "Should have affected provider operator accounts"
    );
}

#[tokio::test]
async fn test_provider_revocation_classification_and_routing() {
    // Test that provider revocation transactions are properly classified and routed
    let mut wallet = Wallet::new_random(Network::Testnet, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with default options");

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get a standard address for collateral return
    let account = wallet
        .accounts
        .standard_bip44_accounts
        .get(&0)
        .expect("Expected BIP44 account at index 0 to exist");
    let xpub = account.account_xpub;

    let managed_account = managed_wallet_info
        .first_bip44_managed_account_mut()
        .expect("Failed to get first BIP44 managed account");

    let return_address = managed_account
        .next_receive_address(Some(&xpub), true)
        .expect("Failed to generate receive address");

    let mut tx = create_test_transaction(1, vec![1_000_000_000]); // 10 DASH returned collateral

    // Add output for returned collateral
    tx.output.push(TxOut {
        value: 1_000_000_000,
        script_pubkey: return_address.script_pubkey(),
    });

    // Create provider update revocation payload
    use dashcore::blockdata::transaction::special_transaction::provider_update_revocation::ProviderUpdateRevocationPayload;
    use dashcore::bls_sig_utils::BLSSignature;
    let payload = ProviderUpdateRevocationPayload {
        version: 1,
        pro_tx_hash: Txid::from_byte_array([1u8; 32]),
        reason: 1, // Reason code for termination
        inputs_hash: [3u8; 32].into(),
        payload_sig: BLSSignature::from([0u8; 96]),
    };

    tx.special_transaction_payload =
        Some(TransactionPayload::ProviderUpdateRevocationPayloadType(payload));

    // First verify classification
    let tx_type = TransactionRouter::classify_transaction(&tx);
    assert_eq!(
        tx_type,
        TransactionType::ProviderUpdateRevocation,
        "Should classify as provider update revocation"
    );

    // Verify routing
    let accounts = TransactionRouter::get_relevant_account_types(&tx_type);
    assert!(
        accounts.contains(&AccountTypeToCheck::StandardBIP44),
        "Should route to standard BIP44 accounts for collateral return"
    );
    assert!(
        !accounts.contains(&AccountTypeToCheck::ProviderOwnerKeys),
        "Should NOT route to provider owner keys"
    );

    let context = TransactionContext::InBlock {
        height: 100000,
        block_hash: Some(BlockHash::from_slice(&[0u8; 32]).expect("Failed to create block hash")),
        timestamp: Some(1234567890),
    };

    let result = managed_wallet_info.check_transaction(&tx, context, &mut wallet, true).await;

    // Should be recognized as relevant due to collateral return
    assert!(result.is_relevant, "Provider revocation with collateral return should be relevant");

    // Should have received the collateral
    assert_eq!(
        result.total_received, 1_000_000_000,
        "Should have received 10 DASH collateral return"
    );

    assert!(
        result.affected_accounts.iter().any(|acc| matches!(
            acc.account_type_match.to_account_type_to_check(),
            AccountTypeToCheck::StandardBIP44
        )),
        "Should have affected standard BIP44 account"
    );
}
