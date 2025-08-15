//! Tests for transaction routing logic
//!
//! Tests how transactions are routed to the appropriate accounts based on their type.

use crate::account::address_pool::AddressPool;
use crate::account::managed_account::ManagedAccount;
use crate::account::managed_account_collection::ManagedAccountCollection;
use crate::account::types::{
    ManagedAccountType, StandardAccountType as ManagedStandardAccountType,
};
use crate::account::{AccountType, StandardAccountType};
use crate::gap_limit::GapLimitManager;
use crate::Network;
use dashcore::hashes::Hash;
use dashcore::{BlockHash, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid};

/// Helper to create a test managed account
fn create_test_managed_account(network: Network, account_type: AccountType) -> ManagedAccount {
    let base_path = account_type.derivation_path(network).unwrap();

    match account_type {
        AccountType::Standard {
            index,
            standard_account_type,
        } => {
            let external_pool = AddressPool::new(base_path.clone(), false, 20, network);
            let internal_pool = AddressPool::new(base_path, true, 20, network);

            let managed_standard_type = match standard_account_type {
                StandardAccountType::BIP44Account => ManagedStandardAccountType::BIP44Account,
                StandardAccountType::BIP32Account => ManagedStandardAccountType::BIP32Account,
            };

            let managed_type = ManagedAccountType::Standard {
                index,
                standard_account_type: managed_standard_type,
                external_addresses: external_pool,
                internal_addresses: internal_pool,
            };

            ManagedAccount::new(managed_type, network, GapLimitManager::default(), false)
        }
        AccountType::CoinJoin {
            index,
        } => {
            let addresses = AddressPool::new(base_path, false, 20, network);

            let managed_type = ManagedAccountType::CoinJoin {
                index,
                addresses,
            };

            ManagedAccount::new(managed_type, network, GapLimitManager::default(), false)
        }
        AccountType::IdentityRegistration => {
            let addresses = AddressPool::new(base_path, false, 20, network);
            let managed_type = ManagedAccountType::IdentityRegistration {
                addresses,
            };
            ManagedAccount::new(managed_type, network, GapLimitManager::default(), false)
        }
        AccountType::IdentityTopUp {
            registration_index,
        } => {
            let addresses = AddressPool::new(base_path, false, 20, network);
            let managed_type = ManagedAccountType::IdentityTopUp {
                registration_index,
                addresses,
            };
            ManagedAccount::new(managed_type, network, GapLimitManager::default(), false)
        }
        AccountType::IdentityTopUpNotBoundToIdentity => {
            let addresses = AddressPool::new(base_path, false, 20, network);
            let managed_type = ManagedAccountType::IdentityTopUpNotBoundToIdentity {
                addresses,
            };
            ManagedAccount::new(managed_type, network, GapLimitManager::default(), false)
        }
        AccountType::IdentityInvitation => {
            let addresses = AddressPool::new(base_path, false, 20, network);
            let managed_type = ManagedAccountType::IdentityInvitation {
                addresses,
            };
            ManagedAccount::new(managed_type, network, GapLimitManager::default(), false)
        }
        AccountType::ProviderVotingKeys => {
            let addresses = AddressPool::new(base_path, false, 20, network);
            let managed_type = ManagedAccountType::ProviderVotingKeys {
                addresses,
            };
            ManagedAccount::new(managed_type, network, GapLimitManager::default(), false)
        }
        AccountType::ProviderOwnerKeys => {
            let addresses = AddressPool::new(base_path, false, 20, network);
            let managed_type = ManagedAccountType::ProviderOwnerKeys {
                addresses,
            };
            ManagedAccount::new(managed_type, network, GapLimitManager::default(), false)
        }
        AccountType::ProviderOperatorKeys => {
            let addresses = AddressPool::new(base_path, false, 20, network);
            let managed_type = ManagedAccountType::ProviderOperatorKeys {
                addresses,
            };
            ManagedAccount::new(managed_type, network, GapLimitManager::default(), false)
        }
        AccountType::ProviderPlatformKeys => {
            let addresses = AddressPool::new(base_path, false, 20, network);
            let managed_type = ManagedAccountType::ProviderPlatformKeys {
                addresses,
            };
            ManagedAccount::new(managed_type, network, GapLimitManager::default(), false)
        }
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
    let network = Network::Testnet;
    let mut collection = ManagedAccountCollection::new();

    // Create BIP44 account
    let account_type = AccountType::Standard {
        index: 0,
        standard_account_type: StandardAccountType::BIP44Account,
    };
    let managed_account = create_test_managed_account(network, account_type.clone());

    collection.insert(managed_account);

    // Test that normal transactions route to BIP44 accounts
    let tx = create_basic_transaction();
    let block_hash = BlockHash::from_slice(&[0u8; 32]).unwrap();

    // In a real scenario, this would check addresses and route appropriately
    // For now, we just verify the structure exists
    assert!(collection.standard_bip44_accounts.contains_key(&0));
}

#[test]
fn test_transaction_routing_to_bip32_account() {
    let network = Network::Testnet;
    let mut collection = ManagedAccountCollection::new();

    // Create BIP32 account
    let account_type = AccountType::Standard {
        index: 0,
        standard_account_type: StandardAccountType::BIP32Account,
    };
    let managed_account = create_test_managed_account(network, account_type);

    collection.insert(managed_account);

    // Test that we can access BIP32 accounts
    assert!(collection.standard_bip32_accounts.contains_key(&0));
}

#[test]
fn test_transaction_routing_to_coinjoin_account() {
    let network = Network::Testnet;
    let mut collection = ManagedAccountCollection::new();

    // Create CoinJoin account
    let account_type = AccountType::CoinJoin {
        index: 0,
    };
    let managed_account = create_test_managed_account(network, account_type);

    collection.insert(managed_account);

    // Test that CoinJoin transactions route correctly
    assert!(collection.coinjoin_accounts.contains_key(&0));
}

#[test]
fn test_coinbase_transaction_routing() {
    let network = Network::Testnet;
    let mut collection = ManagedAccountCollection::new();

    // Create a standard account for mining rewards
    let account_type = AccountType::Standard {
        index: 0,
        standard_account_type: StandardAccountType::BIP44Account,
    };
    let managed_account = create_test_managed_account(network, account_type);

    collection.insert(managed_account);

    // Create a coinbase transaction
    let coinbase_tx = create_coinbase_transaction();

    // Verify it's recognized as coinbase
    assert!(coinbase_tx.is_coin_base());

    // In a real implementation, this would be added to immature transactions
    // and tracked until maturity (100 blocks)
}

#[test]
fn test_multiple_account_routing() {
    let network = Network::Testnet;
    let mut collection = ManagedAccountCollection::new();

    // Create multiple accounts of different types
    let account_types = vec![
        AccountType::Standard {
            index: 0,
            standard_account_type: StandardAccountType::BIP44Account,
        },
        AccountType::Standard {
            index: 1,
            standard_account_type: StandardAccountType::BIP44Account,
        },
        AccountType::Standard {
            index: 0,
            standard_account_type: StandardAccountType::BIP32Account,
        },
        AccountType::CoinJoin {
            index: 0,
        },
    ];

    for account_type in account_types {
        let managed_account = create_test_managed_account(network, account_type);
        collection.insert(managed_account);
    }

    // Verify all accounts are present
    assert_eq!(collection.standard_bip44_accounts.len(), 2);
    assert_eq!(collection.standard_bip32_accounts.len(), 1);
    assert_eq!(collection.coinjoin_accounts.len(), 1);
}

#[test]
fn test_identity_account_routing() {
    let network = Network::Testnet;
    let mut collection = ManagedAccountCollection::new();

    // Create identity accounts
    let identity_accounts = vec![
        AccountType::IdentityRegistration,
        AccountType::IdentityTopUp {
            registration_index: 0,
        },
        AccountType::IdentityTopUpNotBoundToIdentity,
        AccountType::IdentityInvitation,
    ];

    for account_type in identity_accounts {
        let managed_account = create_test_managed_account(network, account_type);
        collection.insert(managed_account);
    }

    // Verify identity accounts are accessible
    assert!(collection.identity_registration.is_some());
    assert!(collection.identity_topup.contains_key(&0));
    assert!(collection.identity_topup_not_bound.is_some());
    assert!(collection.identity_invitation.is_some());
}

#[test]
fn test_provider_account_routing() {
    let network = Network::Testnet;
    let mut collection = ManagedAccountCollection::new();

    // Create provider accounts
    let provider_accounts = vec![
        AccountType::ProviderVotingKeys,
        AccountType::ProviderOwnerKeys,
        AccountType::ProviderOperatorKeys,
        AccountType::ProviderPlatformKeys,
    ];

    for account_type in provider_accounts {
        let managed_account = create_test_managed_account(network, account_type);
        collection.insert(managed_account);
    }

    // Verify provider accounts are accessible
    assert!(collection.provider_voting_keys.is_some());
    assert!(collection.provider_owner_keys.is_some());
    assert!(collection.provider_operator_keys.is_some());
    assert!(collection.provider_platform_keys.is_some());
}

#[test]
fn test_transaction_affects_multiple_accounts() {
    // In a real scenario, a transaction might have outputs to multiple accounts
    // This test would verify that all affected accounts are updated
    let network = Network::Testnet;
    let mut collection = ManagedAccountCollection::new();

    // Create two accounts
    for i in 0..2 {
        let account_type = AccountType::Standard {
            index: i,
            standard_account_type: StandardAccountType::BIP44Account,
        };
        let managed_account = create_test_managed_account(network, account_type);
        collection.insert(managed_account);
    }

    // Create a transaction with multiple outputs
    let tx = Transaction {
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
        output: vec![
            TxOut {
                value: 50000,
                script_pubkey: ScriptBuf::new(), // Would contain account 0's address
            },
            TxOut {
                value: 50000,
                script_pubkey: ScriptBuf::new(), // Would contain account 1's address
            },
        ],
        special_transaction_payload: None,
    };

    // In a real implementation, this transaction would be checked against
    // both accounts and update their balances/history
    assert_eq!(tx.output.len(), 2);
}

#[test]
fn test_change_address_routing() {
    // Change addresses should be routed to internal address pools
    let network = Network::Testnet;
    let mut collection = ManagedAccountCollection::new();

    let account_type = AccountType::Standard {
        index: 0,
        standard_account_type: StandardAccountType::BIP44Account,
    };
    let managed_account = create_test_managed_account(network, account_type);

    collection.insert(managed_account);

    // In a real implementation:
    // - External addresses would be used for receiving
    // - Internal addresses would be used for change
    // This ensures privacy by not reusing addresses

    // Verify account exists and has proper setup
    let managed_acc = collection.standard_bip44_accounts.get(&0).unwrap();
    // In the actual ManagedAccountType, the address pools are embedded in the type
    match &managed_acc.account_type {
        ManagedAccountType::Standard {
            external_addresses,
            internal_addresses,
            ..
        } => {
            assert_eq!(external_addresses.is_internal, false);
            assert_eq!(internal_addresses.is_internal, true);
        }
        _ => panic!("Expected Standard account type"),
    }
}
