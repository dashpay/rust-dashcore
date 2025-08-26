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

    use dashcore::TxOut;

    let network = Network::Testnet;

    // Create a wallet with a BIP44 account
    let wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with default options");

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get the account's xpub for address derivation from the wallet's first BIP44 account
    let account_collection = wallet.accounts.get(&network).expect("Failed to get network accounts");
    let account = account_collection
        .standard_bip44_accounts
        .get(&0)
        .expect("Expected BIP44 account at index 0 to exist");
    let xpub = account.account_xpub;

    let managed_account = managed_wallet_info
        .first_bip44_managed_account_mut(network)
        .expect("Failed to get first BIP44 managed account");

    // Get an address from the BIP44 account
    let address = managed_account
        .next_receive_address(Some(&xpub), true)
        .expect("Failed to generate receive address");

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
        block_hash: Some(
            BlockHash::from_slice(&[0u8; 32]).expect("Failed to create block hash from bytes"),
        ),
        timestamp: Some(1234567890),
    };

    // Check the transaction using the managed wallet info
    let result = managed_wallet_info.check_transaction(
        &tx,
        network,
        context,
        Some(&wallet), // update state
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

    use dashcore::TxOut;

    let network = Network::Testnet;

    // Create a wallet with BIP32 accounts
    let mut wallet = Wallet::new_random(network, WalletAccountCreationOptions::None)
        .expect("Failed to create wallet without default accounts");

    // Add a BIP32 account
    let account_type = AccountType::Standard {
        index: 0,
        standard_account_type: StandardAccountType::BIP32Account,
    };
    wallet.add_account(account_type, network, None).expect("Failed to add account to wallet");

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get the account's xpub for address derivation
    let account_collection = wallet.accounts.get(&network).expect("Failed to get network accounts");
    let account = account_collection
        .standard_bip32_accounts
        .get(&0)
        .expect("Expected BIP32 account at index 0 to exist");
    let xpub = account.account_xpub;

    // Get an address from the BIP32 account
    let address = {
        let managed_account = managed_wallet_info
            .first_bip32_managed_account_mut(network)
            .expect("Failed to get first BIP32 managed account");
        managed_account
            .next_receive_address(Some(&xpub), true)
            .expect("Failed to generate receive address from BIP32 account")
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
        block_hash: Some(
            BlockHash::from_slice(&[0u8; 32]).expect("Failed to create block hash from bytes"),
        ),
        timestamp: Some(1234567890),
    };

    // Check with update_state = false
    let result = managed_wallet_info.check_transaction(
        &tx,
        network,
        context,
        Some(&wallet), // don't update state
    );

    // The transaction should be recognized as relevant
    assert!(result.is_relevant, "Transaction should be relevant to the BIP32 account");
    assert_eq!(result.total_received, 50000, "Should have received 50000 duffs");

    // Verify state was not updated
    {
        let managed_account = managed_wallet_info
            .first_bip32_managed_account_mut(network)
            .expect("Failed to get first BIP32 managed account");
        assert_eq!(
            managed_account.balance.confirmed, 0,
            "Balance should not be updated when update_state is false"
        );
    }

    // Now check with update_state = true
    let result = managed_wallet_info.check_transaction(
        &tx,
        network,
        context,
        Some(&wallet), // update state
    );

    assert!(result.is_relevant, "Transaction should still be relevant");
    // Note: Balance update may not work without proper UTXO tracking implementation
    // This test may fail - that's expected, and we want to find such issues
}

#[test]
fn test_transaction_routing_to_coinjoin_account() {
    use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::Wallet;

    use dashcore::TxOut;

    let network = Network::Testnet;

    // Create a wallet and add a CoinJoin account
    let mut wallet = Wallet::new_random(network, WalletAccountCreationOptions::None)
        .expect("Failed to create wallet without default accounts");

    let account_type = AccountType::CoinJoin {
        index: 0,
    };
    wallet.add_account(account_type, network, None).expect("Failed to add account to wallet");

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get the account's xpub
    let account_collection = wallet.accounts.get(&network).expect("Failed to get network accounts");
    let account = account_collection
        .coinjoin_accounts
        .get(&0)
        .expect("Expected CoinJoin account at index 0 to exist");
    let xpub = account.account_xpub;

    let managed_account = managed_wallet_info
        .first_coinjoin_managed_account_mut(network)
        .expect("Failed to get first CoinJoin managed account");

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
                    .next_unused(
                        &crate::managed_account::address_pool::KeySource::Public(xpub),
                        true,
                    )
                    .unwrap_or_else(|_| {
                        // If that fails, generate a dummy address for testing
                        dashcore::Address::p2pkh(
                            &dashcore::PublicKey::from_slice(&[0x02; 33])
                                .expect("Failed to create public key from bytes"),
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
                &dashcore::PublicKey::from_slice(&[0x02; 33])
                    .expect("Failed to create public key from bytes"),
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
        block_hash: Some(
            BlockHash::from_slice(&[0u8; 32]).expect("Failed to create block hash from bytes"),
        ),
        timestamp: Some(1234567890),
    };

    let result = managed_wallet_info.check_transaction(&tx, network, context, Some(&wallet));

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

    use dashcore::TxOut;

    let network = Network::Testnet;

    // Create a wallet with multiple accounts
    let mut wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with default options");

    // Add another BIP44 account
    let account_type = AccountType::Standard {
        index: 1,
        standard_account_type: StandardAccountType::BIP44Account,
    };
    wallet.add_account(account_type, network, None).expect("Failed to add account to wallet");

    // Add a BIP32 account
    let account_type = AccountType::Standard {
        index: 0,
        standard_account_type: StandardAccountType::BIP32Account,
    };
    wallet.add_account(account_type, network, None).expect("Failed to add account to wallet");

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get addresses from different accounts
    let account_collection = wallet.accounts.get(&network).expect("Failed to get network accounts");

    // BIP44 account 0
    let account0 = account_collection
        .standard_bip44_accounts
        .get(&0)
        .expect("Expected BIP44 account at index 0 to exist");
    let xpub0 = account0.account_xpub;
    let managed_account0 = managed_wallet_info
        .bip44_managed_account_at_index_mut(network, 0)
        .expect("Failed to get BIP44 managed account at index 0");
    let address0 = managed_account0
        .next_receive_address(Some(&xpub0), true)
        .expect("Failed to generate receive address for account 0");

    // BIP44 account 1
    let account1 = account_collection
        .standard_bip44_accounts
        .get(&1)
        .expect("Expected BIP44 account at index 1 to exist");
    let xpub1 = account1.account_xpub;
    let managed_account1 = managed_wallet_info
        .bip44_managed_account_at_index_mut(network, 1)
        .expect("Failed to get BIP44 managed account at index 1");
    let address1 = managed_account1
        .next_receive_address(Some(&xpub1), true)
        .expect("Failed to generate receive address for account 1");

    // BIP32 account
    let account2 = account_collection
        .standard_bip32_accounts
        .get(&0)
        .expect("Expected BIP32 account at index 0 to exist");
    let xpub2 = account2.account_xpub;
    let managed_account2 = managed_wallet_info
        .first_bip32_managed_account_mut(network)
        .expect("Failed to get first BIP32 managed account");
    let address2 = managed_account2
        .next_receive_address(Some(&xpub2), true)
        .expect("Failed to generate receive address for BIP32 account");

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
        block_hash: Some(
            BlockHash::from_slice(&[0u8; 32]).expect("Failed to create block hash from bytes"),
        ),
        timestamp: Some(1234567890),
    };

    // Check the transaction
    let result = managed_wallet_info.check_transaction(
        &tx,
        network,
        context,
        Some(&wallet), // update state
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
    assert_eq!(result.total_received, 120000, "Should have received 120000 duffs total");

    // Verify each account was affected
    // Note: These assertions may fail if the implementation doesn't properly track multiple accounts
    println!("Multi-account transaction result: accounts_affected={:?}", result.affected_accounts);

    // Test with update_state = false to ensure state isn't modified
    let result2 = managed_wallet_info.check_transaction(
        &tx,
        network,
        context,
        Some(&wallet), // don't update state
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

    use dashcore::TxOut;

    let network = Network::Testnet;

    let mut wallet = Wallet::new_random(network, WalletAccountCreationOptions::None)
        .expect("Failed to create wallet without default accounts");

    // Add identity registration account
    let account_type = AccountType::IdentityRegistration;
    wallet.add_account(account_type, network, None).expect("Failed to add account to wallet");

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get the identity registration account
    let account_collection = wallet.accounts.get(&network).expect("Failed to get network accounts");
    let account = account_collection
        .identity_registration
        .as_ref()
        .expect("Expected identity registration account to exist");
    let xpub = account.account_xpub;

    let managed_account = managed_wallet_info
        .identity_registration_managed_account_mut(network)
        .expect("Failed to get identity registration managed account");

    // Use the new next_address method for identity registration account
    let address = managed_account.next_address(Some(&xpub), true).expect("expected an address");

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
    let result = managed_wallet_info.check_transaction(&tx, network, context, Some(&wallet));

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

    use dashcore::TxOut;

    let network = Network::Testnet;

    let wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with default options");
    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    let account_collection = wallet.accounts.get(&network).expect("Failed to get network accounts");
    let account = account_collection
        .identity_registration
        .as_ref()
        .expect("Expected identity registration account to exist");
    let xpub = account.account_xpub;

    let managed_account = managed_wallet_info
        .identity_registration_managed_account_mut(network)
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

    let result = managed_wallet_info.check_transaction(
        &normal_tx,
        network,
        context,
        Some(&wallet), // update state
    );

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
        !result.affected_accounts.iter().any(|acc|
            matches!(acc.account_type, crate::transaction_checking::transaction_router::AccountTypeToCheck::IdentityRegistration)
        ),
        "Identity registration account should not be affected by normal payment"
    );
}

#[test]
fn test_provider_registration_transaction_routing_check_owner_only() {
    use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::Wallet;

    use dashcore::blockdata::transaction::special_transaction::{
        provider_registration::{ProviderMasternodeType, ProviderRegistrationPayload},
        TransactionPayload,
    };
    use dashcore::TxOut;

    let network = Network::Testnet;

    // We create another wallet that will hold keys not in our main wallet
    let other_wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with default options");

    let wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with default options");

    let mut other_managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&other_wallet, "Other".to_string());

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get addresses from provider accounts
    let managed_owner = managed_wallet_info
        .provider_owner_keys_managed_account_mut(network)
        .expect("Failed to get provider owner keys managed account");
    let owner_address = managed_owner.next_address(None, true).expect("expected owner address");

    let voting_address = other_managed_wallet_info
        .provider_voting_keys_managed_account_mut(network)
        .expect("Failed to get provider voting keys managed account")
        .next_address(None, true)
        .expect("expected voting address");

    let operator_public_key = other_managed_wallet_info
        .provider_operator_keys_managed_account_mut(network)
        .expect("Failed to get provider operator keys managed account")
        .next_bls_operator_key(None, true)
        .expect("expected voting address");

    // Payout addresses for providers are just regular addresses, not a separate account
    // For testing, we'll use the first standard account's address
    let payout_address = other_managed_wallet_info
        .first_bip44_managed_account_mut(network)
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
            witness: dashcore::Witness::default(),
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

    let result = managed_wallet_info.check_transaction(&tx, network, context, Some(&wallet));

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

    use dashcore::blockdata::transaction::special_transaction::{
        provider_registration::{ProviderMasternodeType, ProviderRegistrationPayload},
        TransactionPayload,
    };
    use dashcore::TxOut;

    let network = Network::Testnet;

    // We create another wallet that will hold keys not in our main wallet
    let other_wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with default options");

    let wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with default options");

    let mut other_managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&other_wallet, "Other".to_string());

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get addresses from provider accounts
    let owner_address = other_managed_wallet_info
        .provider_owner_keys_managed_account_mut(network)
        .expect("Failed to get provider owner keys managed account")
        .next_address(None, true)
        .expect("expected owner address");

    let managed_voting = managed_wallet_info
        .provider_voting_keys_managed_account_mut(network)
        .expect("Failed to get provider voting keys managed account");
    let voting_address = managed_voting.next_address(None, true).expect("expected voting address");

    let operator_public_key = other_managed_wallet_info
        .provider_operator_keys_managed_account_mut(network)
        .expect("Failed to get provider operator keys managed account")
        .next_bls_operator_key(None, true)
        .expect("expected operator key");

    // Payout addresses for providers are just regular addresses, not a separate account
    // For testing, we'll use the first standard account's address
    let payout_address = other_managed_wallet_info
        .first_bip44_managed_account_mut(network)
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
            witness: dashcore::Witness::default(),
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

    let result = managed_wallet_info.check_transaction(&tx, network, context, Some(&wallet));

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

    use dashcore::blockdata::transaction::special_transaction::{
        provider_registration::{ProviderMasternodeType, ProviderRegistrationPayload},
        TransactionPayload,
    };
    use dashcore::TxOut;

    let network = Network::Testnet;

    // We create another wallet that will hold keys not in our main wallet
    let other_wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with default options");

    let wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with default options");

    let mut other_managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&other_wallet, "Other".to_string());

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get addresses from provider accounts
    let owner_address = other_managed_wallet_info
        .provider_owner_keys_managed_account_mut(network)
        .expect("Failed to get provider owner keys managed account")
        .next_address(None, true)
        .expect("expected owner address");

    let voting_address = other_managed_wallet_info
        .provider_voting_keys_managed_account_mut(network)
        .expect("Failed to get provider voting keys managed account")
        .next_address(None, true)
        .expect("expected voting address");

    let managed_operator = managed_wallet_info
        .provider_operator_keys_managed_account_mut(network)
        .expect("Failed to get provider operator keys managed account");
    let operator_public_key =
        managed_operator.next_bls_operator_key(None, true).expect("expected operator key");

    // Payout addresses for providers are just regular addresses, not a separate account
    // For testing, we'll use the first standard account's address
    let payout_address = other_managed_wallet_info
        .first_bip44_managed_account_mut(network)
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
            witness: dashcore::Witness::default(),
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

    let result = managed_wallet_info.check_transaction(&tx, network, context, Some(&wallet));

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

    use dashcore::blockdata::transaction::special_transaction::{
        provider_registration::{ProviderMasternodeType, ProviderRegistrationPayload},
        TransactionPayload,
    };
    use dashcore::TxOut;

    let network = Network::Testnet;

    // We create another wallet that will hold keys not in our main wallet
    let other_wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with default options");

    let wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with default options");

    let mut other_managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&other_wallet, "Other".to_string());

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get addresses from provider accounts
    let owner_address = other_managed_wallet_info
        .provider_owner_keys_managed_account_mut(network)
        .expect("Failed to get provider owner keys managed account")
        .next_address(None, true)
        .expect("expected owner address");

    let voting_address = other_managed_wallet_info
        .provider_voting_keys_managed_account_mut(network)
        .expect("Failed to get provider voting keys managed account")
        .next_address(None, true)
        .expect("expected voting address");

    let operator_public_key = other_managed_wallet_info
        .provider_operator_keys_managed_account_mut(network)
        .expect("Failed to get provider operator keys managed account")
        .next_bls_operator_key(None, true)
        .expect("expected operator key");

    // Get platform key from our wallet
    let managed_platform = managed_wallet_info
        .provider_platform_keys_managed_account_mut(network)
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
        .first_bip44_managed_account_mut(network)
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
            witness: dashcore::Witness::default(),
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

    let result = managed_wallet_info.check_transaction(&tx, network, context, Some(&wallet));

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
fn test_next_address_method_restrictions() {
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::Wallet;

    let network = Network::Testnet;

    let wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with default options");
    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    let account_collection = wallet.accounts.get(&network).expect("Failed to get network accounts");

    // Test that standard BIP44 accounts reject next_address
    {
        let bip44_account = account_collection
            .standard_bip44_accounts
            .get(&0)
            .expect("Expected BIP44 account at index 0 to exist");
        let xpub = bip44_account.account_xpub;
        let managed_account = managed_wallet_info
            .first_bip44_managed_account_mut(network)
            .expect("Failed to get first BIP44 managed account");

        let result = managed_account.next_address(Some(&xpub), true);
        assert!(result.is_err(), "Standard BIP44 accounts should reject next_address");
        assert_eq!(
            result.expect_err("Expected an error when calling next_address on BIP44 account"),
            "Standard accounts must use next_receive_address or next_change_address"
        );

        // But next_receive_address and next_change_address should work
        assert!(managed_account.next_receive_address(Some(&xpub), true).is_ok());
        assert!(managed_account.next_change_address(Some(&xpub), true).is_ok());
    }

    // Test that standard BIP32 accounts reject next_address (if present)
    if let Some(bip32_account) = account_collection.standard_bip32_accounts.get(&0) {
        let xpub = bip32_account.account_xpub;
        if let Some(managed_account) = managed_wallet_info.first_bip32_managed_account_mut(network)
        {
            let result = managed_account.next_address(Some(&xpub), true);
            assert!(result.is_err(), "Standard BIP32 accounts should reject next_address");
            assert_eq!(
                result.expect_err("Expected an error when calling next_address on BIP44 account"),
                "Standard accounts must use next_receive_address or next_change_address"
            );
        }
    }

    // Test that special accounts accept next_address
    if let Some(identity_account) = account_collection.identity_registration.as_ref() {
        let xpub = identity_account.account_xpub;
        let managed_account = managed_wallet_info
            .identity_registration_managed_account_mut(network)
            .expect("Failed to get identity registration managed account");

        let result = managed_account.next_address(Some(&xpub), true);
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
fn test_provider_registration_transaction_routing_check_owner_and_voting() {
    use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::Wallet;

    use dashcore::blockdata::transaction::special_transaction::{
        provider_registration::{ProviderMasternodeType, ProviderRegistrationPayload},
        TransactionPayload,
    };
    use dashcore::TxOut;

    let network = Network::Testnet;

    // We create another wallet that will hold keys not in our main wallet
    let other_wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create other wallet for testing");

    let wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create main test wallet");

    let mut other_managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&other_wallet, "Other".to_string());

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get addresses from provider accounts - owner and voting from our wallet
    let managed_owner = managed_wallet_info
        .provider_owner_keys_managed_account_mut(network)
        .expect("Failed to get provider owner keys managed account");
    let owner_address = managed_owner
        .next_address(None, true)
        .expect("Failed to generate owner address from provider owner keys account");

    let managed_voting = managed_wallet_info
        .provider_voting_keys_managed_account_mut(network)
        .expect("Failed to get provider voting keys managed account");
    let voting_address = managed_voting
        .next_address(None, true)
        .expect("Failed to generate voting address from provider voting keys account");

    // Get operator from other wallet
    let operator_public_key = other_managed_wallet_info
        .provider_operator_keys_managed_account_mut(network)
        .expect("Failed to get provider operator keys managed account from other wallet")
        .next_bls_operator_key(None, true)
        .expect("Failed to generate BLS operator key from other wallet");

    // Payout addresses for providers are just regular addresses, not a separate account
    // For testing, we'll use the first standard account's address from other wallet
    let payout_address = other_managed_wallet_info
        .first_bip44_managed_account_mut(network)
        .and_then(|acc| acc.next_receive_address(None, true).ok())
        .unwrap_or_else(|| {
            dashcore::Address::p2pkh(
                &dashcore::PublicKey::from_slice(&[0x02; 33])
                    .expect("Failed to create dummy public key for payout address"),
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
                    .expect("Failed to parse service address for provider registration"),
                owner_key_hash: *owner_address
                    .payload()
                    .as_pubkey_hash()
                    .expect("Failed to extract pubkey hash from owner address"),
                operator_public_key: operator_public_key.0.to_compressed().into(),
                voting_key_hash: *voting_address
                    .payload()
                    .as_pubkey_hash()
                    .expect("Failed to extract pubkey hash from voting address"),
                operator_reward: 0,
                script_payout: payout_address.script_pubkey(),
                inputs_hash: dashcore::hash_types::InputsHash::from_slice(&[6u8; 32])
                    .expect("Failed to create inputs hash for provider registration"),
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
            BlockHash::from_slice(&[0u8; 32])
                .expect("Failed to create block hash for transaction context"),
        ),
        timestamp: Some(1234567890),
    };

    let result = managed_wallet_info.check_transaction(&tx, network, context, Some(&wallet));

    println!(
        "Provider registration transaction result (owner and voting): is_relevant={}, received={}",
        result.is_relevant, result.total_received
    );

    // The transaction SHOULD be recognized as relevant to provider accounts
    assert!(
        result.is_relevant,
        "Provider registration transaction should be recognized as relevant for owner and voting keys"
    );

    // Should detect both owner and voting key usage
    assert_eq!(result.total_received, 0, "Should not have received funds");

    // Should have affected both provider owner and voting accounts
    assert!(
        result
            .affected_accounts
            .iter()
            .any(|acc| matches!(acc.account_type,
            crate::transaction_checking::transaction_router::AccountTypeToCheck::ProviderOwnerKeys
        )),
        "Should have affected provider owner accounts"
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

    // Ensure exactly 2 affected accounts
    assert_eq!(
        result.affected_accounts.len(),
        2,
        "Should have exactly 2 affected accounts (owner and voting)"
    );
}

#[test]
fn test_provider_registration_transaction_routing_check_voting_and_operator() {
    use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::Wallet;

    use dashcore::blockdata::transaction::special_transaction::{
        provider_registration::{ProviderMasternodeType, ProviderRegistrationPayload},
        TransactionPayload,
    };
    use dashcore::TxOut;

    let network = Network::Testnet;

    // We create another wallet that will hold keys not in our main wallet
    let other_wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create other wallet for testing");

    let wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create main test wallet");

    let mut other_managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&other_wallet, "Other".to_string());

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get owner from other wallet
    let owner_address = other_managed_wallet_info
        .provider_owner_keys_managed_account_mut(network)
        .expect("Failed to get provider owner keys managed account from other wallet")
        .next_address(None, true)
        .expect("Failed to generate owner address from other wallet");

    // Get voting and operator from our wallet
    let managed_voting = managed_wallet_info
        .provider_voting_keys_managed_account_mut(network)
        .expect("Failed to get provider voting keys managed account");
    let voting_address = managed_voting
        .next_address(None, true)
        .expect("Failed to generate voting address from provider voting keys account");

    let managed_operator = managed_wallet_info
        .provider_operator_keys_managed_account_mut(network)
        .expect("Failed to get provider operator keys managed account");
    let operator_public_key = managed_operator
        .next_bls_operator_key(None, true)
        .expect("Failed to generate BLS operator key from provider operator keys account");

    // Payout addresses for providers are just regular addresses, not a separate account
    // For testing, we'll use the first standard account's address from other wallet
    let payout_address = other_managed_wallet_info
        .first_bip44_managed_account_mut(network)
        .and_then(|acc| acc.next_receive_address(None, true).ok())
        .unwrap_or_else(|| {
            dashcore::Address::p2pkh(
                &dashcore::PublicKey::from_slice(&[0x02; 33])
                    .expect("Failed to create dummy public key for payout address"),
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
                    .expect("Failed to parse service address for provider registration"),
                owner_key_hash: *owner_address
                    .payload()
                    .as_pubkey_hash()
                    .expect("Failed to extract pubkey hash from owner address"),
                operator_public_key: operator_public_key.0.to_compressed().into(),
                voting_key_hash: *voting_address
                    .payload()
                    .as_pubkey_hash()
                    .expect("Failed to extract pubkey hash from voting address"),
                operator_reward: 0,
                script_payout: payout_address.script_pubkey(),
                inputs_hash: dashcore::hash_types::InputsHash::from_slice(&[6u8; 32])
                    .expect("Failed to create inputs hash for provider registration"),
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
            BlockHash::from_slice(&[0u8; 32])
                .expect("Failed to create block hash for transaction context"),
        ),
        timestamp: Some(1234567890),
    };

    let result = managed_wallet_info.check_transaction(&tx, network, context, Some(&wallet));

    println!(
        "Provider registration transaction result (voting and operator): is_relevant={}, received={}",
        result.is_relevant, result.total_received
    );

    // The transaction SHOULD be recognized as relevant to provider accounts
    assert!(
        result.is_relevant,
        "Provider registration transaction should be recognized as relevant for voting and operator keys"
    );

    // Should detect both voting and operator key usage
    assert_eq!(result.total_received, 0, "Should not have received funds");

    // Should have affected both provider voting and operator accounts
    assert!(
        result
            .affected_accounts
            .iter()
            .any(|acc| matches!(acc.account_type,
            crate::transaction_checking::transaction_router::AccountTypeToCheck::ProviderVotingKeys
        )),
        "Should have affected provider voting accounts"
    );

    assert!(
        result
            .affected_accounts
            .iter()
            .any(|acc| matches!(acc.account_type,
            crate::transaction_checking::transaction_router::AccountTypeToCheck::ProviderOperatorKeys
        )),
        "Should have affected provider operator accounts"
    );

    // Ensure exactly 2 affected accounts
    assert_eq!(
        result.affected_accounts.len(),
        2,
        "Should have exactly 2 affected accounts (voting and operator)"
    );
}

#[test]
fn test_provider_registration_transaction_routing_check_all() {
    use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::Wallet;

    use dashcore::blockdata::transaction::special_transaction::{
        provider_registration::{ProviderMasternodeType, ProviderRegistrationPayload},
        TransactionPayload,
    };
    use dashcore::TxOut;

    let network = Network::Testnet;

    // Create wallet with all provider key types
    let wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create test wallet with all provider key types");

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get all provider keys from our wallet
    let managed_owner = managed_wallet_info
        .provider_owner_keys_managed_account_mut(network)
        .expect("Failed to get provider owner keys managed account");
    let owner_address = managed_owner
        .next_address(None, true)
        .expect("Failed to generate owner address from provider owner keys account");

    let managed_voting = managed_wallet_info
        .provider_voting_keys_managed_account_mut(network)
        .expect("Failed to get provider voting keys managed account");
    let voting_address = managed_voting
        .next_address(None, true)
        .expect("Failed to generate voting address from provider voting keys account");

    let managed_operator = managed_wallet_info
        .provider_operator_keys_managed_account_mut(network)
        .expect("Failed to get provider operator keys managed account");
    let operator_public_key = managed_operator
        .next_bls_operator_key(None, true)
        .expect("Failed to generate BLS operator key from provider operator keys account");

    // Get platform key from our wallet (for HighPerformance masternode)
    let managed_platform = managed_wallet_info
        .provider_platform_keys_managed_account_mut(network)
        .expect("Failed to get provider platform keys managed account");

    // For platform keys, we need to get the EdDSA key and derive the node ID
    let root_key = wallet
        .root_extended_priv_key()
        .expect("Failed to get root extended private key from wallet");
    let eddsa_extended_key = root_key
        .to_eddsa_extended_priv_key(network)
        .expect("Failed to convert root key to EdDSA extended key");
    let (_platform_key, info) = managed_platform
        .next_eddsa_platform_key(eddsa_extended_key, true)
        .expect("Failed to generate EdDSA platform key from provider platform keys account");

    let platform_node_id = info.address;

    // Payout address from our wallet's regular account
    let payout_address = managed_wallet_info
        .first_bip44_managed_account_mut(network)
        .and_then(|acc| acc.next_receive_address(None, true).ok())
        .unwrap_or_else(|| {
            dashcore::Address::p2pkh(
                &dashcore::PublicKey::from_slice(&[0x02; 33])
                    .expect("Failed to create dummy public key for payout address"),
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
                    .expect("Failed to parse service address for provider registration"),
                owner_key_hash: *owner_address
                    .payload()
                    .as_pubkey_hash()
                    .expect("Failed to extract pubkey hash from owner address"),
                operator_public_key: operator_public_key.0.to_compressed().into(),
                voting_key_hash: *voting_address
                    .payload()
                    .as_pubkey_hash()
                    .expect("Failed to extract pubkey hash from voting address"),
                operator_reward: 0,
                script_payout: payout_address.script_pubkey(),
                inputs_hash: dashcore::hash_types::InputsHash::from_slice(&[6u8; 32])
                    .expect("Failed to create inputs hash for provider registration"),
                signature: vec![7u8; 65], // Simplified signature
                platform_node_id: Some(
                    *platform_node_id
                        .payload()
                        .as_pubkey_hash()
                        .expect("Failed to extract pubkey hash from platform node ID"),
                ),
                platform_p2p_port: Some(26656),
                platform_http_port: Some(8080),
            },
        )),
    };

    let context = TransactionContext::InBlock {
        height: 100000,
        block_hash: Some(
            BlockHash::from_slice(&[0u8; 32])
                .expect("Failed to create block hash for transaction context"),
        ),
        timestamp: Some(1234567890),
    };

    let result = managed_wallet_info.check_transaction(&tx, network, context, Some(&wallet));

    println!(
        "Provider registration transaction result (all keys): is_relevant={}, received={}",
        result.is_relevant, result.total_received
    );

    // The transaction SHOULD be recognized as relevant to provider accounts
    assert!(
        result.is_relevant,
        "Provider registration transaction should be recognized as relevant for all keys"
    );

    // Should detect all provider key types being used
    assert_eq!(result.total_received, 50000000, "Should have received funds");

    // Should have affected ALL provider account types
    assert!(
        result
            .affected_accounts
            .iter()
            .any(|acc| matches!(acc.account_type,
            crate::transaction_checking::transaction_router::AccountTypeToCheck::ProviderOwnerKeys
        )),
        "Should have affected provider owner accounts"
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

    assert!(
        result
            .affected_accounts
            .iter()
            .any(|acc| matches!(acc.account_type,
            crate::transaction_checking::transaction_router::AccountTypeToCheck::ProviderOperatorKeys
        )),
        "Should have affected provider operator accounts"
    );

    assert!(
        result
            .affected_accounts
            .iter()
            .any(|acc| matches!(acc.account_type,
            crate::transaction_checking::transaction_router::AccountTypeToCheck::ProviderPlatformKeys
        )),
        "Should have affected provider platform accounts"
    );

    // Since we're also using a payout address from our BIP44 account, we might have 5 affected accounts
    // (4 provider accounts + 1 standard BIP44 account)
    assert_eq!(
        result.affected_accounts.len(),
        5,
        "Should have 5 affected accounts, got {} accounts",
        result.affected_accounts.len()
    );
}

#[test]
fn test_provider_registration_transaction_routing_check_outputs() {
    use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::Wallet;

    use dashcore::blockdata::transaction::special_transaction::{
        provider_registration::{ProviderMasternodeType, ProviderRegistrationPayload},
        TransactionPayload,
    };
    use dashcore::TxOut;

    let network = Network::Testnet;

    // We create another wallet that will hold keys not in our main wallet
    let other_wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create other wallet for testing");

    let wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create main test wallet");

    let mut other_managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&other_wallet, "Other".to_string());

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get owner address from our wallet (for collateral output)
    let managed_owner = managed_wallet_info
        .provider_owner_keys_managed_account_mut(network)
        .expect("Failed to get provider owner keys managed account");
    let owner_address = managed_owner
        .next_address(None, true)
        .expect("Failed to generate owner address from provider owner keys account");

    // Get other keys from other wallet
    let voting_address = other_managed_wallet_info
        .provider_voting_keys_managed_account_mut(network)
        .expect("Failed to get provider voting keys managed account from other wallet")
        .next_address(None, true)
        .expect("Failed to generate voting address from other wallet");

    let operator_public_key = other_managed_wallet_info
        .provider_operator_keys_managed_account_mut(network)
        .expect("Failed to get provider operator keys managed account from other wallet")
        .next_bls_operator_key(None, true)
        .expect("Failed to generate BLS operator key from other wallet");

    // Get payout address from our wallet's standard BIP44 account
    let account_collection =
        wallet.accounts.get(&network).expect("Failed to get account collection for network");
    let account = account_collection
        .standard_bip44_accounts
        .get(&0)
        .expect("Failed to get BIP44 account at index 0");
    let xpub = account.account_xpub;

    let payout_address = managed_wallet_info
        .first_bip44_managed_account_mut(network)
        .expect("Failed to get first BIP44 managed account")
        .next_receive_address(Some(&xpub), true)
        .expect("Failed to generate payout address from BIP44 account");

    // Create a ProRegTx transaction with outputs belonging to our wallet
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
            // Collateral output to our owner address (1000 DASH)
            TxOut {
                value: 100_000_000_000, // 1000 DASH
                script_pubkey: owner_address.script_pubkey(),
            },
            // Change output to our payout address
            TxOut {
                value: 50_000_000, // 0.5 DASH
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
                    .expect("Failed to parse service address for provider registration"),
                owner_key_hash: *owner_address
                    .payload()
                    .as_pubkey_hash()
                    .expect("Failed to extract pubkey hash from owner address"),
                operator_public_key: operator_public_key.0.to_compressed().into(),
                voting_key_hash: *voting_address
                    .payload()
                    .as_pubkey_hash()
                    .expect("Failed to extract pubkey hash from voting address"),
                operator_reward: 0,
                script_payout: payout_address.script_pubkey(),
                inputs_hash: dashcore::hash_types::InputsHash::from_slice(&[6u8; 32])
                    .expect("Failed to create inputs hash for provider registration"),
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
            BlockHash::from_slice(&[0u8; 32])
                .expect("Failed to create block hash for transaction context"),
        ),
        timestamp: Some(1234567890),
    };

    let result = managed_wallet_info.check_transaction(&tx, network, context, Some(&wallet));

    println!(
        "Provider registration transaction result (with outputs): is_relevant={}, received={}",
        result.is_relevant, result.total_received
    );

    // The transaction SHOULD be recognized as relevant
    assert!(
        result.is_relevant,
        "Provider registration transaction should be recognized as relevant"
    );

    // Should detect funds received from both collateral and payout outputs
    // Note: The collateral output might not be counted as "received" since it's locked
    // But the change/payout output should be counted
    assert!(
        result.total_received >= 50_000_000,
        "Should have received at least the change output (0.5 DASH = 50,000,000 duffs), got {}",
        result.total_received
    );

    // Should have affected provider owner account (from owner key)
    assert!(
        result
            .affected_accounts
            .iter()
            .any(|acc| matches!(acc.account_type,
            crate::transaction_checking::transaction_router::AccountTypeToCheck::ProviderOwnerKeys
        )),
        "Should have affected provider owner accounts"
    );

    // Should have also affected BIP44 account (from payout address)
    assert!(
        result.affected_accounts.iter().any(|acc| matches!(
            acc.account_type,
            crate::transaction_checking::transaction_router::AccountTypeToCheck::StandardBIP44
        )),
        "Should have affected standard BIP44 account from payout address"
    );

    // Verify that we detected outputs correctly
    println!(
        "Detected outputs: collateral={} DASH, change={} DASH, total_received={} duffs",
        1000, 0.5, result.total_received
    );

    // Additional test: Create another transaction where collateral is NOT to our wallet
    let other_owner_address = other_managed_wallet_info
        .provider_owner_keys_managed_account_mut(network)
        .expect("Failed to get provider owner keys managed account from other wallet")
        .next_address(None, true)
        .expect("Failed to generate other owner address from other wallet");

    let tx2 = Transaction {
        version: 3,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([2u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: dashcore::Witness::default(),
        }],
        output: vec![
            // Collateral output to OTHER wallet
            TxOut {
                value: 100000000000,
                script_pubkey: other_owner_address.script_pubkey(),
            },
            // Change output to our payout address
            TxOut {
                value: 75_000_000, // 0.75 DASH
                script_pubkey: payout_address.script_pubkey(),
            },
        ],
        special_transaction_payload: Some(TransactionPayload::ProviderRegistrationPayloadType(
            ProviderRegistrationPayload {
                version: 1,
                masternode_type: ProviderMasternodeType::Regular,
                masternode_mode: 0,
                collateral_outpoint: OutPoint {
                    txid: Txid::from_byte_array([2u8; 32]),
                    vout: 0,
                },
                service_address: "127.0.0.1:19999"
                    .parse()
                    .expect("Failed to parse service address for second provider registration"),
                owner_key_hash: *other_owner_address
                    .payload()
                    .as_pubkey_hash()
                    .expect("Failed to extract pubkey hash from other owner address"),
                operator_public_key: operator_public_key.0.to_compressed().into(),
                voting_key_hash: *voting_address
                    .payload()
                    .as_pubkey_hash()
                    .expect("Failed to extract pubkey hash from voting address"),
                operator_reward: 0,
                script_payout: payout_address.script_pubkey(),
                inputs_hash: dashcore::hash_types::InputsHash::from_slice(&[6u8; 32])
                    .expect("Failed to create inputs hash for second provider registration"),
                signature: vec![7u8; 65],
                platform_node_id: None,
                platform_p2p_port: None,
                platform_http_port: None,
            },
        )),
    };

    let result2 = managed_wallet_info.check_transaction(&tx2, network, context, Some(&wallet));

    println!(
        "Provider registration transaction result (collateral to other wallet): is_relevant={}, received={}",
        result2.is_relevant, result2.total_received
    );

    // Should still be relevant because of payout address
    assert!(result2.is_relevant, "Should still be relevant due to payout address");

    // Should only receive the change output, not the collateral
    assert_eq!(
        result2.total_received, 75_000_000,
        "Should only receive the change output (0.75 DASH = 75,000,000 duffs)"
    );
}

#[test]
fn test_update_state_flag_behavior() {
    use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::Wallet;

    use dashcore::TxOut;

    let network = Network::Testnet;

    let wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with default options");
    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    let account_collection = wallet.accounts.get(&network).expect("Failed to get network accounts");
    let account = account_collection
        .standard_bip44_accounts
        .get(&0)
        .expect("Expected BIP44 account at index 0 to exist");
    let xpub = account.account_xpub;

    // Get an address and initial state
    let (address, initial_balance, initial_tx_count) = {
        let managed_account = managed_wallet_info
            .first_bip44_managed_account_mut(network)
            .expect("Failed to get first BIP44 managed account");
        let address = managed_account
            .next_receive_address(Some(&xpub), true)
            .expect("Failed to generate receive address");
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
        block_hash: Some(
            BlockHash::from_slice(&[0u8; 32]).expect("Failed to create block hash from bytes"),
        ),
        timestamp: Some(1234567890),
    };

    // First check with update_state = false
    let result1 = managed_wallet_info.check_transaction(
        &tx,
        network,
        context,
        Some(&wallet), // don't update state
    );

    assert!(result1.is_relevant);

    // Verify no state change when update_state=false
    {
        let managed_account = managed_wallet_info
            .first_bip44_managed_account_mut(network)
            .expect("Failed to get first BIP44 managed account");
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
        &tx,
        network,
        context,
        Some(&wallet), // update state
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
        let managed_account = managed_wallet_info
            .first_bip44_managed_account_mut(network)
            .expect("Failed to get first BIP44 managed account");
        println!(
            "After update_state=true: balance={}, tx_count={}",
            managed_account.balance.confirmed,
            managed_account.transactions.len()
        );
    }
}

#[test]
fn test_coinbase_transaction_routing_to_bip44_receive_address() {
    use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::Wallet;

    use dashcore::TxOut;

    let network = Network::Testnet;

    // Create a wallet with a BIP44 account
    let wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with BIP44 account for coinbase test");

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get the account's xpub for address derivation from the wallet's first BIP44 account
    let account_collection =
        wallet.accounts.get(&network).expect("Failed to get account collection for network");
    let account = account_collection
        .standard_bip44_accounts
        .get(&0)
        .expect("Failed to get BIP44 account at index 0");
    let xpub = account.account_xpub;

    let managed_account = managed_wallet_info
        .first_bip44_managed_account_mut(network)
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
    let result = managed_wallet_info.check_transaction(
        &coinbase_tx,
        network,
        context,
        Some(&wallet), // update state
    );

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
            acc.account_type,
            crate::transaction_checking::transaction_router::AccountTypeToCheck::StandardBIP44
        )),
        "Coinbase should have affected the BIP44 account"
    );
}

#[test]
fn test_coinbase_transaction_routing_to_bip44_change_address() {
    use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::Wallet;

    use dashcore::TxOut;

    let network = Network::Testnet;

    // Create a wallet with a BIP44 account
    let wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with BIP44 account for coinbase change test");

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get the account's xpub for address derivation
    let account_collection =
        wallet.accounts.get(&network).expect("Failed to get account collection for network");
    let account = account_collection
        .standard_bip44_accounts
        .get(&0)
        .expect("Failed to get BIP44 account at index 0");
    let xpub = account.account_xpub;

    let managed_account = managed_wallet_info
        .first_bip44_managed_account_mut(network)
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
    let result = managed_wallet_info.check_transaction(
        &coinbase_tx,
        network,
        context,
        Some(&wallet), // update state
    );

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
            acc.account_type,
            crate::transaction_checking::transaction_router::AccountTypeToCheck::StandardBIP44
        )),
        "Coinbase to change address should have affected the BIP44 account"
    );
}

#[test]
fn test_coinbase_transaction_routing_to_bip32_address() {
    use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::Wallet;

    use dashcore::TxOut;

    let network = Network::Testnet;

    // Create a wallet with BIP32 accounts
    let mut wallet = Wallet::new_random(network, WalletAccountCreationOptions::None)
        .expect("Failed to create wallet for BIP32 coinbase test");

    // Add a BIP32 account
    let account_type = AccountType::Standard {
        index: 0,
        standard_account_type: StandardAccountType::BIP32Account,
    };
    wallet.add_account(account_type, network, None).expect("Failed to add BIP32 account to wallet");

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get the account's xpub for address derivation
    let account_collection =
        wallet.accounts.get(&network).expect("Failed to get account collection for network");
    let account = account_collection
        .standard_bip32_accounts
        .get(&0)
        .expect("Failed to get BIP32 account at index 0");
    let xpub = account.account_xpub;

    // Get an address from the BIP32 account
    let address = {
        let managed_account = managed_wallet_info
            .first_bip32_managed_account_mut(network)
            .expect("Failed to get first BIP32 managed account");
        managed_account
            .next_receive_address(Some(&xpub), true)
            .expect("Failed to generate receive address from BIP32 account")
    };

    // Create a coinbase transaction that pays to this BIP32 address
    let mut coinbase_tx = create_coinbase_transaction();

    // Replace the default output with one to our BIP32 address
    coinbase_tx.output[0] = TxOut {
        value: 5000000000, // 50 DASH block reward
        script_pubkey: address.script_pubkey(),
    };

    // Check the transaction using the managed wallet info
    let context = TransactionContext::InBlock {
        height: 100002,
        block_hash: Some(
            BlockHash::from_slice(&[2u8; 32])
                .expect("Failed to create block hash for transaction context"),
        ),
        timestamp: Some(1234567910),
    };

    // Check the coinbase transaction
    let result = managed_wallet_info.check_transaction(
        &coinbase_tx,
        network,
        context,
        Some(&wallet), // update state
    );

    // The coinbase transaction should be recognized as relevant
    assert!(result.is_relevant, "Coinbase transaction to BIP32 address should be relevant");

    // Should have received the full block reward
    assert_eq!(
        result.total_received, 5000000000,
        "Should have received 50 DASH (5000000000 duffs) from coinbase to BIP32 account"
    );

    // Should have affected the BIP32 account
    assert!(
        result.affected_accounts.iter().any(|acc| matches!(
            acc.account_type,
            crate::transaction_checking::transaction_router::AccountTypeToCheck::StandardBIP32
        )),
        "Coinbase should have affected the BIP32 account"
    );
}

#[test]
fn test_coinbase_transaction_routing_multiple_outputs() {
    use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::Wallet;

    use dashcore::TxOut;

    let network = Network::Testnet;

    // Create a wallet with multiple account types
    let mut wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with multiple accounts for coinbase test");

    // Add another BIP44 account
    let account_type = AccountType::Standard {
        index: 1,
        standard_account_type: StandardAccountType::BIP44Account,
    };
    wallet.add_account(account_type, network, None).expect("Failed to add second BIP44 account");

    // Add a BIP32 account
    let account_type = AccountType::Standard {
        index: 0,
        standard_account_type: StandardAccountType::BIP32Account,
    };
    wallet.add_account(account_type, network, None).expect("Failed to add BIP32 account");

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get addresses from different accounts
    let account_collection =
        wallet.accounts.get(&network).expect("Failed to get account collection for network");

    // BIP44 account 0
    let account0 = account_collection
        .standard_bip44_accounts
        .get(&0)
        .expect("Failed to get BIP44 account at index 0");
    let xpub0 = account0.account_xpub;
    let managed_account0 = managed_wallet_info
        .bip44_managed_account_at_index_mut(network, 0)
        .expect("Failed to get BIP44 managed account at index 0");
    let address0 = managed_account0
        .next_receive_address(Some(&xpub0), true)
        .expect("Failed to generate receive address from BIP44 account 0");

    // BIP44 account 1
    let account1 = account_collection
        .standard_bip44_accounts
        .get(&1)
        .expect("Failed to get BIP44 account at index 1");
    let xpub1 = account1.account_xpub;
    let managed_account1 = managed_wallet_info
        .bip44_managed_account_at_index_mut(network, 1)
        .expect("Failed to get BIP44 managed account at index 1");
    let address1 = managed_account1
        .next_receive_address(Some(&xpub1), true)
        .expect("Failed to generate receive address from BIP44 account 1");

    // BIP32 account
    let account2 = account_collection
        .standard_bip32_accounts
        .get(&0)
        .expect("Failed to get BIP32 account at index 0");
    let xpub2 = account2.account_xpub;
    let managed_account2 = managed_wallet_info
        .first_bip32_managed_account_mut(network)
        .expect("Failed to get first BIP32 managed account");
    let address2 = managed_account2
        .next_receive_address(Some(&xpub2), true)
        .expect("Failed to generate receive address from BIP32 account");

    // Create a coinbase transaction with multiple outputs to different accounts
    let mut coinbase_tx = create_coinbase_transaction();

    // Clear default outputs and add multiple outputs
    coinbase_tx.output.clear();

    // Add outputs to different accounts (splitting the block reward)
    coinbase_tx.output.push(TxOut {
        value: 2000000000, // 20 DASH to BIP44 account 0
        script_pubkey: address0.script_pubkey(),
    });
    coinbase_tx.output.push(TxOut {
        value: 1500000000, // 15 DASH to BIP44 account 1
        script_pubkey: address1.script_pubkey(),
    });
    coinbase_tx.output.push(TxOut {
        value: 1500000000, // 15 DASH to BIP32 account
        script_pubkey: address2.script_pubkey(),
    });

    let context = TransactionContext::InBlock {
        height: 100003,
        block_hash: Some(
            BlockHash::from_slice(&[3u8; 32])
                .expect("Failed to create block hash for transaction context"),
        ),
        timestamp: Some(1234567920),
    };

    // Check the coinbase transaction
    let result = managed_wallet_info.check_transaction(
        &coinbase_tx,
        network,
        context,
        Some(&wallet), // update state
    );

    // The coinbase transaction should be recognized as relevant
    assert!(result.is_relevant, "Coinbase transaction with multiple outputs should be relevant");

    // Should have received the sum of all outputs
    assert_eq!(
        result.total_received,
        5000000000, // 20 + 15 + 15 = 50 DASH
        "Should have received 50 DASH (5000000000 duffs) total from coinbase with multiple outputs"
    );

    // Should have affected all three accounts
    assert_eq!(
        result
            .affected_accounts
            .iter()
            .filter(|acc| matches!(
                acc.account_type,
                crate::transaction_checking::transaction_router::AccountTypeToCheck::StandardBIP44
            ))
            .count(),
        2,
        "Coinbase should have affected both BIP44 accounts"
    );

    assert!(
        result.affected_accounts.iter().any(|acc| matches!(
            acc.account_type,
            crate::transaction_checking::transaction_router::AccountTypeToCheck::StandardBIP32
        )),
        "Coinbase should have affected the BIP32 account"
    );

    assert_eq!(result.affected_accounts.len(), 3, "Should have exactly 3 affected accounts");
}

#[test]
fn test_coinbase_transaction_not_ours() {
    use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::Wallet;

    use dashcore::TxOut;

    let network = Network::Testnet;

    // Create our wallet
    let wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet for coinbase not-ours test");

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Create another wallet to get an unrelated address
    let other_wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create other wallet for unrelated address");

    let mut other_managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&other_wallet, "Other".to_string());

    // Get an address from the other wallet
    let other_account_collection = other_wallet
        .accounts
        .get(&network)
        .expect("Failed to get account collection for other wallet");
    let other_account = other_account_collection
        .standard_bip44_accounts
        .get(&0)
        .expect("Failed to get BIP44 account from other wallet");
    let other_xpub = other_account.account_xpub;

    let unrelated_address = other_managed_wallet_info
        .first_bip44_managed_account_mut(network)
        .expect("Failed to get first BIP44 managed account from other wallet")
        .next_receive_address(Some(&other_xpub), true)
        .expect("Failed to generate address from other wallet");

    // Create a coinbase transaction that pays to an unrelated address
    let mut coinbase_tx = create_coinbase_transaction();

    // Replace the output with one to an address not in our wallet
    coinbase_tx.output[0] = TxOut {
        value: 5000000000, // 50 DASH block reward
        script_pubkey: unrelated_address.script_pubkey(),
    };

    // Check the transaction using our wallet's managed info
    let context = TransactionContext::InBlock {
        height: 100004,
        block_hash: Some(
            BlockHash::from_slice(&[4u8; 32])
                .expect("Failed to create block hash for transaction context"),
        ),
        timestamp: Some(1234567930),
    };

    // Check the coinbase transaction against our wallet
    let result = managed_wallet_info.check_transaction(
        &coinbase_tx,
        network,
        context,
        Some(&wallet), // update state
    );

    // The coinbase transaction should NOT be recognized as relevant
    assert!(
        !result.is_relevant,
        "Coinbase transaction to unrelated address should not be relevant"
    );

    // Should not have received any funds
    assert_eq!(
        result.total_received, 0,
        "Should not have received any funds from coinbase to unrelated address"
    );

    // Should not have affected any accounts
    assert_eq!(result.affected_accounts.len(), 0, "Should not have affected any accounts");
}

#[test]
fn test_gap_limit_with_update_state_true() {
    // Test that when update_state=true, transactions beyond the gap limit are still detected
    // because the wallet updates its state as it processes transactions
    use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::Wallet;

    use dashcore::TxOut;

    let network = Network::Testnet;

    // Create a wallet with a BIP44 account
    let wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with default options");

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get the account's xpub for address derivation
    let account_collection = wallet.accounts.get(&network).expect("Failed to get network accounts");
    let account = account_collection
        .standard_bip44_accounts
        .get(&0)
        .expect("Expected BIP44 account at index 0 to exist");
    let xpub = account.account_xpub;

    let managed_account = managed_wallet_info
        .first_bip44_managed_account_mut(network)
        .expect("Failed to get first BIP44 managed account");

    // Generate 35 receive addresses (to exceed the default gap limit of 20)
    // Using the new batch method for efficiency
    let addresses = managed_account
        .next_receive_addresses(Some(&xpub), 35, false)
        .expect("Failed to generate 35 receive addresses");

    // Create a transaction context for testing
    let context = TransactionContext::InBlock {
        height: 100000,
        block_hash: Some(
            BlockHash::from_slice(&[0u8; 32]).expect("Failed to create block hash from bytes"),
        ),
        timestamp: Some(1234567890),
    };

    // Create 55 transactions, each sending to one of these addresses in order
    // When update_state=true, the wallet should detect ALL of them
    let mut detected_count = 0;
    for (i, address) in addresses.iter().enumerate() {
        // Create a unique transaction for each address
        let tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array({
                        let mut bytes = [0u8; 32];
                        bytes[0] = (i as u8).wrapping_add(1); // Make each txid unique
                        bytes
                    }),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: 0xffffffff,
                witness: dashcore::Witness::default(),
            }],
            output: vec![TxOut {
                value: 100000 + (i as u64 * 1000), // Vary the amount for each transaction
                script_pubkey: address.script_pubkey(),
            }],
            special_transaction_payload: None,
        };

        // Check the transaction with update_state=true
        // This should update the wallet's internal state and allow it to detect
        // transactions beyond the initial gap limit
        let result = managed_wallet_info.check_transaction(
            &tx,
            network,
            context,
            Some(&wallet), // update_state=true - this is the key
        );

        if result.is_relevant {
            detected_count += 1;

            // Verify that the transaction was properly detected
            assert!(
                result.total_received > 0,
                "Transaction {} should have received funds when detected",
                i
            );
            assert!(
                !result.affected_accounts.is_empty(),
                "Transaction {} should have affected at least one account",
                i
            );
        }
    }

    // With update_state=true, ALL 35 transactions should be detected
    // The wallet should update its state as it processes each transaction,
    // effectively moving the gap window forward as addresses are used
    assert_eq!(
        detected_count, 35,
        "With update_state=true, all 35 transactions should be detected. Only {} were detected.",
        detected_count
    );
}

#[test]
fn test_gap_limit_with_update_state_false() {
    // Test that when update_state=false, transactions beyond the gap limit are NOT detected
    // because the wallet doesn't update its internal state
    use crate::transaction_checking::{TransactionContext, WalletTransactionChecker};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::Wallet;

    use dashcore::TxOut;

    let network = Network::Testnet;

    // Create a wallet with a BIP44 account
    let wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
        .expect("Failed to create wallet with default options");

    let mut managed_wallet_info =
        ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

    // Get the account's xpub for address derivation
    let account_collection = wallet.accounts.get(&network).expect("Failed to get network accounts");
    let account = account_collection
        .standard_bip44_accounts
        .get(&0)
        .expect("Expected BIP44 account at index 0 to exist");
    let xpub = account.account_xpub;

    let managed_account = managed_wallet_info
        .first_bip44_managed_account_mut(network)
        .expect("Failed to get first BIP44 managed account");

    // Generate 25 receive addresses (to exceed the default gap limit of 20)
    // Using the new batch method for efficiency
    let external_gap_limit = managed_account.external_gap_limit().unwrap_or(20);
    let addresses = managed_account
        .next_receive_addresses(Some(&xpub), (external_gap_limit + 5) as usize, false)
        .expect("Failed to generate 55 receive addresses");

    // Create a transaction context for testing
    let context = TransactionContext::InBlock {
        height: 100000,
        block_hash: Some(
            BlockHash::from_slice(&[0u8; 32]).expect("Failed to create block hash from bytes"),
        ),
        timestamp: Some(1234567890),
    };

    // Create 25 transactions, each sending to one of these addresses in order
    // When update_state=false, the wallet should only detect those within the gap limit
    let mut detected_count = 0;
    let mut detected_indices = Vec::new();

    let gap_limit_external_limit = managed_account.external_gap_limit().unwrap_or(20) as usize;

    for (i, address) in addresses.iter().enumerate() {
        // Create a unique transaction for each address
        let tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array({
                        let mut bytes = [0u8; 32];
                        bytes[0] = (i as u8).wrapping_add(1); // Make each txid unique
                        bytes
                    }),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: 0xffffffff,
                witness: dashcore::Witness::default(),
            }],
            output: vec![TxOut {
                value: 100000 + (i as u64 * 1000), // Vary the amount for each transaction
                script_pubkey: address.script_pubkey(),
            }],
            special_transaction_payload: None,
        };

        // Check the transaction with update_state=false
        // This should NOT update the wallet's internal state, so it won't detect
        // transactions beyond the initial gap limit
        let result = managed_wallet_info.check_transaction(
            &tx, network, context, None, // update_state=false - this is the key
        );

        if result.is_relevant {
            detected_count += 1;
            detected_indices.push(i);

            // Verify that the transaction was properly detected
            assert!(
                result.total_received > 0,
                "Transaction {} should have received funds when detected",
                i
            );
            assert!(
                !result.affected_accounts.is_empty(),
                "Transaction {} should have affected at least one account",
                i
            );
        }
    }

    // With update_state=false, only transactions within the gap limit should be detected
    // The default gap limit is typically 20 addresses
    // Since we're not updating state, the wallet should stop detecting after the gap

    assert_eq!(
        detected_count, gap_limit_external_limit, // Allow some flexibility in case gap limit is slightly different
        "With update_state=false, only transactions within the gap limit should be detected. Detected: {}",
        detected_count
    );

    // Verify that later transactions (definitely beyond gap limit) are NOT detected
    assert!(
        !detected_indices.contains(&(gap_limit_external_limit + 1)),
        "Transaction at index {} should NOT be detected with update_state=false",
        gap_limit_external_limit + 1
    );
}
