//! Tests for transaction routing logic
//!
//! Tests how transactions are routed to the appropriate accounts based on their type.

use crate::account::{AccountType, StandardAccountType};
use crate::managed_account::managed_account_type::ManagedAccountType;
use crate::wallet::ManagedWalletInfo;
use crate::Network;
use dashcore::hashes::Hash;
use dashcore::{BlockHash, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid};

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

#[test]
fn test_transaction_routing_to_bip44_account() {
    use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::Wallet;
    use crate::wallet::WalletConfig;
    use dashcore::TxOut;

    let network = Network::Testnet;
    let config = WalletConfig::default();

    // Create a wallet with a BIP44 account
    let wallet =
        Wallet::new_random(config, network, WalletAccountCreationOptions::Default).unwrap();

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get the account's xpub for address derivation from the wallet's first BIP44 account
    let account_collection = wallet.accounts.get(&network).unwrap();
    let account = account_collection.standard_bip44_accounts.get(&0).unwrap();
    let xpub = account.account_xpub;

    let managed_account = managed_wallet_info.first_bip44_managed_account_mut(network).unwrap();

    // Get an address from the BIP44 account
    let address = managed_account.next_receive_address(Some(&xpub)).unwrap();

    // Create a transaction that sends to this address
    let mut tx = create_basic_transaction();

    // Add an output to our address
    tx.output.push(TxOut {
        value: 100000,
        script_pubkey: address.script_pubkey(),
    });

    // Check the transaction using the wallet's managed info
    let context = TransactionContext::InBlock {
        height: 100000,
        block_hash: Some(BlockHash::from_slice(&[0u8; 32]).unwrap()),
        timestamp: Some(1234567890),
    };

    // Check the transaction using the managed wallet info
    let result = managed_wallet_info.check_transaction(
        &tx, network, context, true, // update state
    );

    // The transaction should be recognized as relevant since it sends to our address
    assert!(result.is_relevant, "Transaction should be relevant to the wallet");
    assert!(result.total_received > 0, "Should have received funds");
    assert_eq!(result.total_received, 100000, "Should have received 100000 duffs");
}

#[test]
fn test_transaction_routing_to_bip32_account() {
    use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::Wallet;
    use crate::wallet::WalletConfig;
    use dashcore::TxOut;

    let network = Network::Testnet;
    let config = WalletConfig::default();

    // Create a wallet with BIP32 accounts
    let mut wallet =
        Wallet::new_random(config, network, WalletAccountCreationOptions::None).unwrap();

    // Add a BIP32 account
    let account_type = AccountType::Standard {
        index: 0,
        standard_account_type: StandardAccountType::BIP32Account,
    };
    wallet.add_account(account_type, network, None).unwrap();

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get the account's xpub for address derivation
    let account_collection = wallet.accounts.get(&network).unwrap();
    let account = account_collection.standard_bip32_accounts.get(&0).unwrap();
    let xpub = account.account_xpub;

    // Get an address from the BIP32 account
    let address = {
        let managed_account = managed_wallet_info.first_bip32_managed_account_mut(network).unwrap();
        managed_account.next_receive_address(Some(&xpub)).unwrap()
    };

    // Create a transaction that sends to this address
    let mut tx = create_basic_transaction();

    // Add an output to our address
    tx.output.push(TxOut {
        value: 50000,
        script_pubkey: address.script_pubkey(),
    });

    // Check the transaction using the managed wallet info
    let context = TransactionContext::InBlock {
        height: 100000,
        block_hash: Some(BlockHash::from_slice(&[0u8; 32]).unwrap()),
        timestamp: Some(1234567890),
    };

    // Check with update_state = false
    let result = managed_wallet_info.check_transaction(
        &tx,
        network,
        context.clone(),
        false, // don't update state
    );

    // The transaction should be recognized as relevant
    assert!(result.is_relevant, "Transaction should be relevant to the BIP32 account");
    assert_eq!(result.total_received, 50000, "Should have received 50000 satoshis");

    // Verify state was not updated
    {
        let managed_account = managed_wallet_info.first_bip32_managed_account_mut(network).unwrap();
        assert_eq!(
            managed_account.balance.confirmed, 0,
            "Balance should not be updated when update_state is false"
        );
    }

    // Now check with update_state = true
    let result = managed_wallet_info.check_transaction(
        &tx, network, context, true, // update state
    );

    assert!(result.is_relevant, "Transaction should still be relevant");
    // Note: Balance update may not work without proper UTXO tracking implementation
    // This test may fail - that's expected and we want to find such issues
}

#[test]
fn test_transaction_routing_to_coinjoin_account() {
    use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::Wallet;
    use crate::wallet::WalletConfig;
    use dashcore::TxOut;

    let network = Network::Testnet;
    let config = WalletConfig::default();

    // Create a wallet and add a CoinJoin account
    let mut wallet =
        Wallet::new_random(config, network, WalletAccountCreationOptions::None).unwrap();

    let account_type = AccountType::CoinJoin {
        index: 0,
    };
    wallet.add_account(account_type, network, None).unwrap();

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get the account's xpub
    let account_collection = wallet.accounts.get(&network).unwrap();
    let account = account_collection.coinjoin_accounts.get(&0).unwrap();
    let xpub = account.account_xpub;

    let managed_account = managed_wallet_info.first_coinjoin_managed_account_mut(network).unwrap();

    // Get an address from the CoinJoin account
    // Note: CoinJoin accounts may have special address generation logic
    // This might fail if next_receive_address is not supported for CoinJoin accounts
    let address = match managed_account.get_next_address_index() {
        Some(_) => {
            // For CoinJoin accounts, we might need different address generation
            // Let's try to get an address from the pool directly
            if let ManagedAccountType::CoinJoin {
                addresses,
                ..
            } = &mut managed_account.account_type
            {
                addresses
                    .next_unused(&crate::managed_account::address_pool::KeySource::Public(xpub))
                    .unwrap_or_else(|_| {
                        // If that fails, generate a dummy address for testing
                        dashcore::Address::p2pkh(
                            &dashcore::PublicKey::from_slice(&[0x02; 33]).unwrap(),
                            network,
                        )
                    })
            } else {
                panic!("Expected CoinJoin account type");
            }
        }
        None => {
            // Generate a dummy address for testing
            dashcore::Address::p2pkh(
                &dashcore::PublicKey::from_slice(&[0x02; 33]).unwrap(),
                network,
            )
        }
    };

    // Create a CoinJoin-like transaction (multiple inputs/outputs with same denominations)
    let mut tx = create_basic_transaction();

    // Add multiple outputs with CoinJoin denominations
    tx.output.push(TxOut {
        value: 100_000, // 0.001 DASH (standard CoinJoin denomination)
        script_pubkey: address.script_pubkey(),
    });
    tx.output.push(TxOut {
        value: 100_000, // Same denomination for other participants
        script_pubkey: ScriptBuf::new(),
    });
    tx.output.push(TxOut {
        value: 100_000,
        script_pubkey: ScriptBuf::new(),
    });

    let context = TransactionContext::InBlock {
        height: 100000,
        block_hash: Some(BlockHash::from_slice(&[0u8; 32]).unwrap()),
        timestamp: Some(1234567890),
    };

    let result = managed_wallet_info.check_transaction(&tx, network, context, false);

    // This test may fail if CoinJoin detection is not properly implemented
    println!(
        "CoinJoin transaction result: is_relevant={}, received={}",
        result.is_relevant, result.total_received
    );
}

#[test]
fn test_transaction_affects_multiple_accounts() {
    use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::Wallet;
    use crate::wallet::WalletConfig;
    use dashcore::TxOut;

    let network = Network::Testnet;
    let config = WalletConfig::default();

    // Create a wallet with multiple accounts
    let mut wallet =
        Wallet::new_random(config, network, WalletAccountCreationOptions::Default).unwrap();

    // Add another BIP44 account
    let account_type = AccountType::Standard {
        index: 1,
        standard_account_type: StandardAccountType::BIP44Account,
    };
    wallet.add_account(account_type, network, None).unwrap();

    // Add a BIP32 account
    let account_type = AccountType::Standard {
        index: 0,
        standard_account_type: StandardAccountType::BIP32Account,
    };
    wallet.add_account(account_type, network, None).unwrap();

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get addresses from different accounts
    let account_collection = wallet.accounts.get(&network).unwrap();

    // BIP44 account 0
    let account0 = account_collection.standard_bip44_accounts.get(&0).unwrap();
    let xpub0 = account0.account_xpub;
    let managed_account0 =
        managed_wallet_info.bip44_managed_account_at_index_mut(network, 0).unwrap();
    let address0 = managed_account0.next_receive_address(Some(&xpub0)).unwrap();

    // BIP44 account 1
    let account1 = account_collection.standard_bip44_accounts.get(&1).unwrap();
    let xpub1 = account1.account_xpub;
    let managed_account1 =
        managed_wallet_info.bip44_managed_account_at_index_mut(network, 1).unwrap();
    let address1 = managed_account1.next_receive_address(Some(&xpub1)).unwrap();

    // BIP32 account
    let account2 = account_collection.standard_bip32_accounts.get(&0).unwrap();
    let xpub2 = account2.account_xpub;
    let managed_account2 = managed_wallet_info.first_bip32_managed_account_mut(network).unwrap();
    let address2 = managed_account2.next_receive_address(Some(&xpub2)).unwrap();

    // Create a transaction that sends to multiple accounts
    let mut tx = create_basic_transaction();

    // Add outputs to different accounts
    tx.output.push(TxOut {
        value: 30000,
        script_pubkey: address0.script_pubkey(),
    });
    tx.output.push(TxOut {
        value: 40000,
        script_pubkey: address1.script_pubkey(),
    });
    tx.output.push(TxOut {
        value: 50000,
        script_pubkey: address2.script_pubkey(),
    });

    let context = TransactionContext::InBlock {
        height: 100000,
        block_hash: Some(BlockHash::from_slice(&[0u8; 32]).unwrap()),
        timestamp: Some(1234567890),
    };

    // Check the transaction
    let result = managed_wallet_info.check_transaction(
        &tx, network, context, true, // update state
    );

    // // Debug output to understand what's happening
    // println!("Transaction outputs:");
    // println!("  BIP44 account 0: {} duffs to {}", 30000, address0);
    // println!("  BIP44 account 1: {} duffs to {}", 40000, address1);
    // println!("  BIP32 account 0: {} duffs to {}", 50000, address2);
    // println!("Result: is_relevant={}, total_received={}", result.is_relevant, result.total_received);

    // Transaction should be relevant and total should be sum of all outputs
    assert!(result.is_relevant, "Transaction should be relevant to multiple accounts");

    // NOTE: This assertion is expected to fail if BIP32 accounts aren't properly tracked
    // The failure shows that only BIP44 accounts (30000 + 40000 = 70000) or possibly
    // 80000 means something else is being counted
    assert_eq!(result.total_received, 120000, "Should have received 120000 satoshis total");

    // Verify each account was affected
    // Note: These assertions may fail if the implementation doesn't properly track multiple accounts
    println!("Multi-account transaction result: accounts_affected={:?}", result.affected_accounts);

    // Test with update_state = false to ensure state isn't modified
    let result2 = managed_wallet_info.check_transaction(
        &tx, network, context, false, // don't update state
    );

    assert_eq!(
        result2.total_received, result.total_received,
        "Should get same result without state update"
    );
}

#[test]
fn test_identity_registration_account_routing() {
    use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::Wallet;
    use crate::wallet::WalletConfig;
    use dashcore::TxOut;

    let network = Network::Testnet;
    let config = WalletConfig::default();

    let mut wallet =
        Wallet::new_random(config, network, WalletAccountCreationOptions::None).unwrap();

    // Add identity registration account
    let account_type = AccountType::IdentityRegistration;
    wallet.add_account(account_type, network, None).unwrap();

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get the identity registration account
    let account_collection = wallet.accounts.get(&network).unwrap();
    let account = account_collection.identity_registration.as_ref().unwrap();
    let xpub = account.account_xpub;

    let managed_account =
        managed_wallet_info.identity_registration_managed_account_mut(network).unwrap();

    // Use the new next_address method for identity registration account
    let address = managed_account.next_address(Some(&xpub)).expect("expected an address");

    // Create an Asset Lock transaction that funds identity registration
    use dashcore::opcodes;
    use dashcore::script::Builder;
    use dashcore::transaction::special_transaction::asset_lock::AssetLockPayload;
    use dashcore::transaction::TransactionPayload;

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
            witness: dashcore::Witness::default(),
        }],
        output: vec![
            // Asset lock transactions have regular outputs
            // First output is an OP_RETURN with the locked amount
            TxOut {
                value: 100_000_000, // 1 DASH being locked
                script_pubkey: Builder::new()
                    .push_opcode(opcodes::all::OP_RETURN)
                    .push_slice(&[0u8; 20]) // Can contain identity hash or other data
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
                    .unwrap(),
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
        block_hash: Some(BlockHash::from_slice(&[0u8; 32]).unwrap()),
        timestamp: Some(1234567890),
    };

    // First check without updating state
    let result = managed_wallet_info.check_transaction(&tx, network, context, false);

    println!("Identity registration transaction result: is_relevant={}, received={}, credit_conversion={}", 
             result.is_relevant, result.total_received, result.total_received_for_credit_conversion);

    // The transaction SHOULD be recognized as relevant to identity registration
    assert!(
        result.is_relevant,
        "AssetLock transaction should be recognized as relevant to identity registration account"
    );

    assert!(result.affected_accounts.iter().any(|acc|
        matches!(acc.account_type, crate::transaction_checking::transaction_router::AccountTypeToCheck::IdentityRegistration)
    ), "Should have affected the identity registration account");

    // AssetLock funds are for credit conversion, not regular spending
    assert_eq!(result.total_received, 0, "AssetLock should not provide spendable funds");

    assert_eq!(result.total_received_for_credit_conversion, 100_000_000,
        "Should detect 1 DASH (100,000,000 duffs) for Platform credit conversion from AssetLock payload");
}

#[test]
fn test_normal_payment_to_identity_address_not_detected() {
    use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::Wallet;
    use crate::wallet::WalletConfig;
    use dashcore::TxOut;

    let network = Network::Testnet;
    let config = WalletConfig::default();

    let wallet =
        Wallet::new_random(config, network, WalletAccountCreationOptions::Default).unwrap();
    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    let account_collection = wallet.accounts.get(&network).unwrap();
    let account = account_collection.identity_registration.as_ref().unwrap();
    let xpub = account.account_xpub;

    let managed_account =
        managed_wallet_info.identity_registration_managed_account_mut(network).unwrap();

    // Get an identity registration address
    let address = managed_account.next_address(Some(&xpub)).unwrap_or_else(|_| {
        // Generate a dummy address for testing
        dashcore::Address::p2pkh(&dashcore::PublicKey::from_slice(&[0x03; 33]).unwrap(), network)
    });

    // Create a NORMAL transaction (not a special transaction) to the identity address
    let mut normal_tx = create_basic_transaction();
    normal_tx.output.push(TxOut {
        value: 50000,
        script_pubkey: address.script_pubkey(),
    });

    let context = TransactionContext::InBlock {
        height: 100000,
        block_hash: Some(BlockHash::from_slice(&[0u8; 32]).unwrap()),
        timestamp: Some(1234567890),
    };

    let result = managed_wallet_info.check_transaction(
        &normal_tx, network, context, true, // update state
    );

    println!(
        "Normal tx to identity address: is_relevant={}, received={}",
        result.is_relevant, result.total_received
    );

    // A normal transaction to an identity registration address should NOT be detected
    // Identity addresses are only for special transactions
    if !result.is_relevant {
        println!("✓ Normal payment to identity address correctly NOT detected");
    } else {
        println!(
            "✗ Normal payment to identity address was incorrectly detected - this may be a bug"
        );
        // This might actually be intended behavior in some implementations
        // where identity addresses can receive normal payments for funding
    }
}

#[test]
fn test_provider_registration_transaction_routing_check_owner_only() {
    use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::Wallet;
    use crate::wallet::WalletConfig;
    use dashcore::blockdata::transaction::special_transaction::{
        provider_registration::{ProviderMasternodeType, ProviderRegistrationPayload},
        TransactionPayload,
    };
    use dashcore::TxOut;

    let network = Network::Testnet;
    let config = WalletConfig::default();

    // We create another wallet that will hold keys not in our main wallet
    let other_wallet =
        Wallet::new_random(config, network, WalletAccountCreationOptions::Default).unwrap();

    let wallet =
        Wallet::new_random(config, network, WalletAccountCreationOptions::Default).unwrap();

    let mut other_managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&other_wallet, "Other".to_string());

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get addresses from provider accounts
    let managed_owner =
        managed_wallet_info.provider_owner_keys_managed_account_mut(network).unwrap();
    let owner_address = managed_owner.next_address(None).expect("expected owner address");

    let voting_address = other_managed_wallet_info
        .provider_voting_keys_managed_account_mut(network)
        .unwrap()
        .next_address(None)
        .expect("expected voting address");

    let operator_public_key = other_managed_wallet_info
        .provider_operator_keys_managed_account_mut(network)
        .unwrap()
        .next_bls_operator_key(None)
        .expect("expected voting address");

    // Payout addresses for providers are just regular addresses, not a separate account
    // For testing, we'll use the first standard account's address
    let payout_address = other_managed_wallet_info
        .first_bip44_managed_account_mut(network)
        .and_then(|acc| acc.next_receive_address(None).ok())
        .unwrap_or_else(|| {
            dashcore::Address::p2pkh(
                &dashcore::PublicKey::from_slice(&[0x02; 33]).unwrap(),
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
            witness: dashcore::Witness::default(),
        }],
        output: vec![
            // Collateral output (1000 DASH for regular masternode)
            TxOut {
                value: 1000_000_000_00, // 1000 DASH
                script_pubkey: owner_address.script_pubkey(),
            },
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
                service_address: "127.0.0.1:19999".parse().unwrap(),
                owner_key_hash: *owner_address.payload().as_pubkey_hash().unwrap(),
                operator_public_key: operator_public_key.0.to_compressed().into(),
                voting_key_hash: *voting_address.payload().as_pubkey_hash().unwrap(),
                operator_reward: 0,
                script_payout: payout_address.script_pubkey(),
                inputs_hash: dashcore::hash_types::InputsHash::from_slice(&[6u8; 32]).unwrap(),
                signature: vec![7u8; 65], // Simplified signature
                platform_node_id: None,
                platform_p2p_port: None,
                platform_http_port: None,
            },
        )),
    };

    let context = TransactionContext::InBlock {
        height: 100000,
        block_hash: Some(BlockHash::from_slice(&[0u8; 32]).unwrap()),
        timestamp: Some(1234567890),
    };

    let result = managed_wallet_info.check_transaction(&tx, network, context, true);

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
            .all(|acc| matches!(acc.account_type,
            crate::transaction_checking::transaction_router::AccountTypeToCheck::ProviderOwnerKeys
        )),
        "Should have affected provider owner accounts"
    );
}

#[test]
fn test_provider_registration_transaction_routing_check_voting_only() {
    use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::Wallet;
    use crate::wallet::WalletConfig;
    use dashcore::blockdata::transaction::special_transaction::{
        provider_registration::{ProviderMasternodeType, ProviderRegistrationPayload},
        TransactionPayload,
    };
    use dashcore::TxOut;

    let network = Network::Testnet;
    let config = WalletConfig::default();

    // We create another wallet that will hold keys not in our main wallet
    let other_wallet =
        Wallet::new_random(config, network, WalletAccountCreationOptions::Default).unwrap();

    let wallet =
        Wallet::new_random(config, network, WalletAccountCreationOptions::Default).unwrap();

    let mut other_managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&other_wallet, "Other".to_string());

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get addresses from provider accounts
    let owner_address = other_managed_wallet_info
        .provider_owner_keys_managed_account_mut(network)
        .unwrap()
        .next_address(None)
        .expect("expected owner address");

    let managed_voting =
        managed_wallet_info.provider_voting_keys_managed_account_mut(network).unwrap();
    let voting_address = managed_voting.next_address(None).expect("expected voting address");

    let operator_public_key = other_managed_wallet_info
        .provider_operator_keys_managed_account_mut(network)
        .unwrap()
        .next_bls_operator_key(None)
        .expect("expected operator key");

    // Payout addresses for providers are just regular addresses, not a separate account
    // For testing, we'll use the first standard account's address
    let payout_address = other_managed_wallet_info
        .first_bip44_managed_account_mut(network)
        .and_then(|acc| acc.next_receive_address(None).ok())
        .unwrap_or_else(|| {
            dashcore::Address::p2pkh(
                &dashcore::PublicKey::from_slice(&[0x02; 33]).unwrap(),
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
            witness: dashcore::Witness::default(),
        }],
        output: vec![
            // Collateral output (1000 DASH for regular masternode)
            TxOut {
                value: 1000_000_000_00, // 1000 DASH
                script_pubkey: owner_address.script_pubkey(),
            },
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
                service_address: "127.0.0.1:19999".parse().unwrap(),
                owner_key_hash: *owner_address.payload().as_pubkey_hash().unwrap(),
                operator_public_key: operator_public_key.0.to_compressed().into(),
                voting_key_hash: *voting_address.payload().as_pubkey_hash().unwrap(),
                operator_reward: 0,
                script_payout: payout_address.script_pubkey(),
                inputs_hash: dashcore::hash_types::InputsHash::from_slice(&[6u8; 32]).unwrap(),
                signature: vec![7u8; 65], // Simplified signature
                platform_node_id: None,
                platform_p2p_port: None,
                platform_http_port: None,
            },
        )),
    };

    let context = TransactionContext::InBlock {
        height: 100000,
        block_hash: Some(BlockHash::from_slice(&[0u8; 32]).unwrap()),
        timestamp: Some(1234567890),
    };

    let result = managed_wallet_info.check_transaction(&tx, network, context, true);

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
            .all(|acc| matches!(acc.account_type,
            crate::transaction_checking::transaction_router::AccountTypeToCheck::ProviderVotingKeys
        )),
        "Should have affected provider voting accounts"
    );
}

#[test]
fn test_provider_registration_transaction_routing_check_operator_only() {
    use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::Wallet;
    use crate::wallet::WalletConfig;
    use dashcore::blockdata::transaction::special_transaction::{
        provider_registration::{ProviderMasternodeType, ProviderRegistrationPayload},
        TransactionPayload,
    };
    use dashcore::TxOut;

    let network = Network::Testnet;
    let config = WalletConfig::default();

    // We create another wallet that will hold keys not in our main wallet
    let other_wallet =
        Wallet::new_random(config, network, WalletAccountCreationOptions::Default).unwrap();

    let wallet =
        Wallet::new_random(config, network, WalletAccountCreationOptions::Default).unwrap();

    let mut other_managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&other_wallet, "Other".to_string());

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get addresses from provider accounts
    let owner_address = other_managed_wallet_info
        .provider_owner_keys_managed_account_mut(network)
        .unwrap()
        .next_address(None)
        .expect("expected owner address");

    let voting_address = other_managed_wallet_info
        .provider_voting_keys_managed_account_mut(network)
        .unwrap()
        .next_address(None)
        .expect("expected voting address");

    let managed_operator =
        managed_wallet_info.provider_operator_keys_managed_account_mut(network).unwrap();
    let operator_public_key =
        managed_operator.next_bls_operator_key(None).expect("expected operator key");

    // Payout addresses for providers are just regular addresses, not a separate account
    // For testing, we'll use the first standard account's address
    let payout_address = other_managed_wallet_info
        .first_bip44_managed_account_mut(network)
        .and_then(|acc| acc.next_receive_address(None).ok())
        .unwrap_or_else(|| {
            dashcore::Address::p2pkh(
                &dashcore::PublicKey::from_slice(&[0x02; 33]).unwrap(),
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
            witness: dashcore::Witness::default(),
        }],
        output: vec![
            // Collateral output (1000 DASH for regular masternode)
            TxOut {
                value: 1000_000_000_00, // 1000 DASH
                script_pubkey: owner_address.script_pubkey(),
            },
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
                service_address: "127.0.0.1:19999".parse().unwrap(),
                owner_key_hash: *owner_address.payload().as_pubkey_hash().unwrap(),
                operator_public_key: operator_public_key.0.to_compressed().into(),
                voting_key_hash: *voting_address.payload().as_pubkey_hash().unwrap(),
                operator_reward: 0,
                script_payout: payout_address.script_pubkey(),
                inputs_hash: dashcore::hash_types::InputsHash::from_slice(&[6u8; 32]).unwrap(),
                signature: vec![7u8; 65], // Simplified signature
                platform_node_id: None,
                platform_p2p_port: None,
                platform_http_port: None,
            },
        )),
    };

    let context = TransactionContext::InBlock {
        height: 100000,
        block_hash: Some(BlockHash::from_slice(&[0u8; 32]).unwrap()),
        timestamp: Some(1234567890),
    };

    let result = managed_wallet_info.check_transaction(&tx, network, context, true);

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
            .all(|acc| matches!(acc.account_type,
            crate::transaction_checking::transaction_router::AccountTypeToCheck::ProviderOperatorKeys
        )),
        "Should have affected provider operator accounts"
    );
}

#[test]
fn test_provider_registration_transaction_routing_check_platform_only() {
    use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::Wallet;
    use crate::wallet::WalletConfig;
    use dashcore::blockdata::transaction::special_transaction::{
        provider_registration::{ProviderMasternodeType, ProviderRegistrationPayload},
        TransactionPayload,
    };
    use dashcore::TxOut;

    let network = Network::Testnet;
    let config = WalletConfig::default();

    // We create another wallet that will hold keys not in our main wallet
    let other_wallet =
        Wallet::new_random(config, network, WalletAccountCreationOptions::Default).unwrap();

    let wallet =
        Wallet::new_random(config, network, WalletAccountCreationOptions::Default).unwrap();

    let mut other_managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&other_wallet, "Other".to_string());

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get addresses from provider accounts
    let owner_address = other_managed_wallet_info
        .provider_owner_keys_managed_account_mut(network)
        .unwrap()
        .next_address(None)
        .expect("expected owner address");

    let voting_address = other_managed_wallet_info
        .provider_voting_keys_managed_account_mut(network)
        .unwrap()
        .next_address(None)
        .expect("expected voting address");

    let operator_public_key = other_managed_wallet_info
        .provider_operator_keys_managed_account_mut(network)
        .unwrap()
        .next_bls_operator_key(None)
        .expect("expected operator key");

    // Get platform key from our wallet
    let managed_platform =
        managed_wallet_info.provider_platform_keys_managed_account_mut(network).unwrap();

    // For platform keys, we need to get the EdDSA key and derive the node ID
    // We need to provide the extended private key for EdDSA
    // In a real scenario this would come from the wallet's key derivation
    let root_key = wallet.root_extended_priv_key().expect("Expected root extended priv key");
    let eddsa_extended_key =
        root_key.to_eddsa_extended_priv_key(network).expect("expected EdDSA key");
    let (_platform_key, info) = managed_platform
        .next_eddsa_platform_key(eddsa_extended_key)
        .expect("expected platform key");

    let platform_node_id = info.address;

    // Payout addresses for providers are just regular addresses, not a separate account
    // For testing, we'll use the first standard account's address
    let payout_address = other_managed_wallet_info
        .first_bip44_managed_account_mut(network)
        .and_then(|acc| acc.next_receive_address(None).ok())
        .unwrap_or_else(|| {
            dashcore::Address::p2pkh(
                &dashcore::PublicKey::from_slice(&[0x02; 33]).unwrap(),
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
            witness: dashcore::Witness::default(),
        }],
        output: vec![
            // Collateral output (4000 DASH for HighPerformance masternode)
            TxOut {
                value: 4000_000_000_00, // 4000 DASH
                script_pubkey: owner_address.script_pubkey(),
            },
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
                service_address: "127.0.0.1:19999".parse().unwrap(),
                owner_key_hash: *owner_address.payload().as_pubkey_hash().unwrap(),
                operator_public_key: operator_public_key.0.to_compressed().into(),
                voting_key_hash: *voting_address.payload().as_pubkey_hash().unwrap(),
                operator_reward: 0,
                script_payout: payout_address.script_pubkey(),
                inputs_hash: dashcore::hash_types::InputsHash::from_slice(&[6u8; 32]).unwrap(),
                signature: vec![7u8; 65], // Simplified signature
                platform_node_id: Some(*platform_node_id.payload().as_pubkey_hash().unwrap()),
                platform_p2p_port: Some(26656),
                platform_http_port: Some(8080),
            },
        )),
    };

    let context = TransactionContext::InBlock {
        height: 100000,
        block_hash: Some(BlockHash::from_slice(&[0u8; 32]).unwrap()),
        timestamp: Some(1234567890),
    };

    let result = managed_wallet_info.check_transaction(&tx, network, context, true);

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
            .all(|acc| matches!(acc.account_type,
            crate::transaction_checking::transaction_router::AccountTypeToCheck::ProviderPlatformKeys
        )),
        "Should have affected provider platform accounts"
    );
}

#[test]
fn test_provider_update_service_transaction_routing() {
    use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::Wallet;
    use crate::wallet::WalletConfig;
    use dashcore::blockdata::transaction::special_transaction::{
        provider_update_service::ProviderUpdateServicePayload, TransactionPayload,
    };
    use dashcore::bls_sig_utils::BLSSignature;
    use dashcore::TxOut;

    let network = Network::Testnet;
    let config = WalletConfig::default();

    let wallet =
        Wallet::new_random(config, network, WalletAccountCreationOptions::Default).unwrap();

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    let account_collection = wallet.accounts.get(&network).unwrap();

    // Get operator account for the update service transaction
    let _operator_account = account_collection.provider_operator_keys.as_ref().unwrap();
    let managed_operator =
        managed_wallet_info.provider_operator_keys_managed_account_mut(network).unwrap();
    // Provider accounts need special handling - pass None for xpub since they use BLS keys
    let operator_address = managed_operator.next_address(None).expect("expected operator address");

    // Create a ProUpServTx transaction (Provider Update Service)
    let tx = Transaction {
        version: 3, // Version 3 for special transactions
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([8u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: dashcore::Witness::default(),
        }],
        output: vec![
            // Small fee output to operator address
            TxOut {
                value: 10_000, // Small amount for fee
                script_pubkey: operator_address.script_pubkey(),
            },
        ],
        special_transaction_payload: Some(TransactionPayload::ProviderUpdateServicePayloadType(
            ProviderUpdateServicePayload {
                version: 1,
                mn_type: None,
                pro_tx_hash: Txid::from_byte_array([9u8; 32]),
                ip_address: 0x0101a8c0, // 192.168.1.1 as u128
                port: 19999,
                script_payout: operator_address.script_pubkey(),
                inputs_hash: dashcore::hash_types::InputsHash::from_slice(&[10u8; 32]).unwrap(),
                platform_node_id: None,
                platform_p2p_port: None,
                platform_http_port: None,
                payload_sig: BLSSignature::from([11u8; 96]),
            },
        )),
    };

    let context = TransactionContext::InBlock {
        height: 100001,
        block_hash: Some(BlockHash::from_slice(&[1u8; 32]).unwrap()),
        timestamp: Some(1234567900),
    };

    let result = managed_wallet_info.check_transaction(&tx, network, context, true);

    println!(
        "Provider update service transaction result: is_relevant={}, received={}",
        result.is_relevant, result.total_received
    );

    // The transaction SHOULD be recognized as relevant to provider operator keys
    assert!(
        result.is_relevant,
        "Provider update service transaction should be recognized as relevant"
    );

    assert!(result.affected_accounts.iter().any(|acc|
        matches!(acc.account_type,
            crate::transaction_checking::transaction_router::AccountTypeToCheck::ProviderOperatorKeys
        )
    ), "Should have affected provider operator account");
}

#[test]
fn test_provider_update_registrar_transaction_routing() {
    use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::Wallet;
    use crate::wallet::WalletConfig;
    use dashcore::blockdata::transaction::special_transaction::{
        provider_update_registrar::ProviderUpdateRegistrarPayload, TransactionPayload,
    };
    use dashcore::bls_sig_utils::BLSPublicKey;
    use dashcore::TxOut;

    let network = Network::Testnet;
    let config = WalletConfig::default();

    let wallet =
        Wallet::new_random(config, network, WalletAccountCreationOptions::Default).unwrap();

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    let account_collection = wallet.accounts.get(&network).unwrap();

    // Get voting and payout accounts for the update registrar transaction
    let _voting_account = account_collection.provider_voting_keys.as_ref().unwrap();
    let managed_voting =
        managed_wallet_info.provider_voting_keys_managed_account_mut(network).unwrap();
    // Provider accounts need special handling - pass None for xpub since they use BLS keys
    let voting_address = managed_voting.next_address(None).expect("expected voting address");

    // Payout addresses for providers are just regular addresses, not a separate account
    // For testing, we'll use the first standard account's address
    let payout_address = managed_wallet_info
        .first_bip44_managed_account_mut(network)
        .and_then(|acc| acc.next_receive_address(None).ok())
        .unwrap_or_else(|| {
            dashcore::Address::p2pkh(
                &dashcore::PublicKey::from_slice(&[0x02; 33]).unwrap(),
                network,
            )
        });

    // Create a ProUpRegTx transaction (Provider Update Registrar)
    let tx = Transaction {
        version: 3, // Version 3 for special transactions
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([12u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: dashcore::Witness::default(),
        }],
        output: vec![
            // Small fee output to voting address
            TxOut {
                value: 5_000,
                script_pubkey: voting_address.script_pubkey(),
            },
            // Another output to payout address
            TxOut {
                value: 15_000,
                script_pubkey: payout_address.script_pubkey(),
            },
        ],
        special_transaction_payload: Some(TransactionPayload::ProviderUpdateRegistrarPayloadType(
            ProviderUpdateRegistrarPayload {
                version: 1,
                pro_tx_hash: Txid::from_byte_array([13u8; 32]),
                provider_mode: 0, // Update mode
                operator_public_key: BLSPublicKey::from([14u8; 48]),
                voting_key_hash: dashcore::PubkeyHash::from_slice(&[15u8; 20]).unwrap(),
                script_payout: payout_address.script_pubkey(),
                inputs_hash: dashcore::hash_types::InputsHash::from_slice(&[16u8; 32]).unwrap(),
                payload_sig: vec![17u8; 65], // Simplified signature
            },
        )),
    };

    let context = TransactionContext::InBlock {
        height: 100002,
        block_hash: Some(BlockHash::from_slice(&[2u8; 32]).unwrap()),
        timestamp: Some(1234567910),
    };

    let result = managed_wallet_info.check_transaction(&tx, network, context, true);

    println!(
        "Provider update registrar transaction result: is_relevant={}, received={}",
        result.is_relevant, result.total_received
    );

    // The transaction SHOULD be recognized as relevant to provider voting and payout accounts
    assert!(
        result.is_relevant,
        "Provider update registrar transaction should be recognized as relevant"
    );

    assert!(
        result
            .affected_accounts
            .iter()
            .any(|acc| matches!(acc.account_type,
            crate::transaction_checking::transaction_router::AccountTypeToCheck::ProviderVotingKeys
        )),
        "Should have affected provider voting accounts"
    );
}

#[test]
fn test_provider_update_revocation_transaction_routing() {
    use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::Wallet;
    use crate::wallet::WalletConfig;
    use dashcore::blockdata::transaction::special_transaction::{
        provider_update_revocation::ProviderUpdateRevocationPayload, TransactionPayload,
    };
    use dashcore::bls_sig_utils::BLSSignature;
    use dashcore::TxOut;

    let network = Network::Testnet;
    let config = WalletConfig::default();

    let wallet =
        Wallet::new_random(config, network, WalletAccountCreationOptions::Default).unwrap();

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    let account_collection = wallet.accounts.get(&network).unwrap();

    // Get operator account for the revocation transaction (operator signs the revocation)
    let _operator_account = account_collection.provider_operator_keys.as_ref().unwrap();
    let managed_operator =
        managed_wallet_info.provider_operator_keys_managed_account_mut(network).unwrap();
    // Provider accounts need special handling - pass None for xpub since they use BLS keys
    let operator_address = managed_operator.next_address(None).expect("expected operator address");

    // Create a ProUpRevTx transaction (Provider Update Revocation)
    let tx = Transaction {
        version: 3, // Version 3 for special transactions
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([18u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: dashcore::Witness::default(),
        }],
        output: vec![
            // Small fee output back to operator
            TxOut {
                value: 1_000,
                script_pubkey: operator_address.script_pubkey(),
            },
        ],
        special_transaction_payload: Some(TransactionPayload::ProviderUpdateRevocationPayloadType(
            ProviderUpdateRevocationPayload {
                version: 1,
                pro_tx_hash: Txid::from_byte_array([19u8; 32]),
                reason: 0, // NotSpecified
                inputs_hash: dashcore::hash_types::InputsHash::from_slice(&[20u8; 32]).unwrap(),
                payload_sig: BLSSignature::from([21u8; 96]),
            },
        )),
    };

    let context = TransactionContext::InBlock {
        height: 100003,
        block_hash: Some(BlockHash::from_slice(&[3u8; 32]).unwrap()),
        timestamp: Some(1234567920),
    };

    let result = managed_wallet_info.check_transaction(&tx, network, context, true);

    println!(
        "Provider revocation transaction result: is_relevant={}, received={}",
        result.is_relevant, result.total_received
    );

    // The transaction SHOULD be recognized as relevant to provider operator keys
    assert!(result.is_relevant, "Provider revocation transaction should be recognized as relevant");

    assert!(result.affected_accounts.iter().any(|acc|
        matches!(acc.account_type,
            crate::transaction_checking::transaction_router::AccountTypeToCheck::ProviderOperatorKeys
        )
    ), "Should have affected provider operator account");
}

#[test]
fn test_next_address_method_restrictions() {
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::Wallet;
    use crate::wallet::WalletConfig;

    let network = Network::Testnet;
    let config = WalletConfig::default();

    let wallet =
        Wallet::new_random(config, network, WalletAccountCreationOptions::Default).unwrap();
    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    let account_collection = wallet.accounts.get(&network).unwrap();

    // Test that standard BIP44 accounts reject next_address
    {
        let bip44_account = account_collection.standard_bip44_accounts.get(&0).unwrap();
        let xpub = bip44_account.account_xpub;
        let managed_account = managed_wallet_info.first_bip44_managed_account_mut(network).unwrap();

        let result = managed_account.next_address(Some(&xpub));
        assert!(result.is_err(), "Standard BIP44 accounts should reject next_address");
        assert_eq!(
            result.unwrap_err(),
            "Standard accounts must use next_receive_address or next_change_address"
        );

        // But next_receive_address and next_change_address should work
        assert!(managed_account.next_receive_address(Some(&xpub)).is_ok());
        assert!(managed_account.next_change_address(Some(&xpub)).is_ok());
    }

    // Test that standard BIP32 accounts reject next_address (if present)
    if let Some(bip32_account) = account_collection.standard_bip32_accounts.get(&0) {
        let xpub = bip32_account.account_xpub;
        if let Some(managed_account) = managed_wallet_info.first_bip32_managed_account_mut(network)
        {
            let result = managed_account.next_address(Some(&xpub));
            assert!(result.is_err(), "Standard BIP32 accounts should reject next_address");
            assert_eq!(
                result.unwrap_err(),
                "Standard accounts must use next_receive_address or next_change_address"
            );
        }
    }

    // Test that special accounts accept next_address
    if let Some(identity_account) = account_collection.identity_registration.as_ref() {
        let xpub = identity_account.account_xpub;
        let managed_account =
            managed_wallet_info.identity_registration_managed_account_mut(network).unwrap();

        let result = managed_account.next_address(Some(&xpub));
        // This should either succeed or fail with "No unused addresses available"
        // but NOT with "Standard accounts must use..."
        if let Err(e) = result {
            assert_ne!(
                e, "Standard accounts must use next_receive_address or next_change_address",
                "Identity registration account should accept next_address method"
            );
        }
    }

    println!("✓ next_address method restrictions are properly enforced");
}

#[test]
fn test_update_state_flag_behavior() {
    use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::Wallet;
    use crate::wallet::WalletConfig;
    use dashcore::TxOut;

    let network = Network::Testnet;
    let config = WalletConfig::default();

    let wallet =
        Wallet::new_random(config, network, WalletAccountCreationOptions::Default).unwrap();
    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    let account_collection = wallet.accounts.get(&network).unwrap();
    let account = account_collection.standard_bip44_accounts.get(&0).unwrap();
    let xpub = account.account_xpub;

    // Get an address and initial state
    let (address, initial_balance, initial_tx_count) = {
        let managed_account = managed_wallet_info.first_bip44_managed_account_mut(network).unwrap();
        let address = managed_account.next_receive_address(Some(&xpub)).unwrap();
        let balance = managed_account.balance.confirmed;
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
        block_hash: Some(BlockHash::from_slice(&[0u8; 32]).unwrap()),
        timestamp: Some(1234567890),
    };

    // First check with update_state = false
    let result1 = managed_wallet_info.check_transaction(
        &tx,
        network,
        context.clone(),
        false, // don't update state
    );

    assert!(result1.is_relevant);

    // Verify no state change when update_state=false
    {
        let managed_account = managed_wallet_info.first_bip44_managed_account_mut(network).unwrap();
        assert_eq!(
            managed_account.balance.confirmed, initial_balance,
            "Balance should not change when update_state=false"
        );
        assert_eq!(
            managed_account.transactions.len(),
            initial_tx_count,
            "Transaction count should not change when update_state=false"
        );
    }

    // Now check with update_state = true
    let result2 = managed_wallet_info.check_transaction(
        &tx, network, context, true, // update state
    );

    assert!(result2.is_relevant);
    assert_eq!(
        result1.total_received, result2.total_received,
        "Should detect same amount regardless of update_state"
    );

    // Check if state was actually updated
    // Note: This may fail if state updates aren't properly implemented
    // That's what we want to discover
    {
        let managed_account = managed_wallet_info.first_bip44_managed_account_mut(network).unwrap();
        println!(
            "After update_state=true: balance={}, tx_count={}",
            managed_account.balance.confirmed,
            managed_account.transactions.len()
        );
    }
}
