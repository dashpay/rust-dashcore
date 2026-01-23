//! Tests for TryFrom trait conversions from ManagedAccountType to AccountTypeToCheck

use crate::account::account_type::StandardAccountType;
use crate::bip32::DerivationPath;
use crate::managed_account::address_pool::{AddressPool, AddressPoolType};
use crate::managed_account::managed_account_type::ManagedAccountType;
use crate::transaction_checking::transaction_router::AccountTypeToCheck;
use crate::Network;

/// Helper to create a test address pool
fn test_address_pool(pool_type: AddressPoolType) -> AddressPool {
    AddressPool::new_without_generation(
        DerivationPath::from(vec![]),
        pool_type,
        20,
        Network::Testnet,
    )
}

/// Helper to create a single address pool (for non-standard accounts)
fn test_single_pool() -> AddressPool {
    test_address_pool(AddressPoolType::External)
}

#[test]
fn test_try_from_standard_bip44_account() {
    let managed_account = ManagedAccountType::Standard {
        index: 0,
        standard_account_type: StandardAccountType::BIP44Account,
        external_addresses: test_address_pool(AddressPoolType::External),
        internal_addresses: test_address_pool(AddressPoolType::Internal),
    };

    let check_type: AccountTypeToCheck = managed_account.try_into().unwrap();
    assert_eq!(check_type, AccountTypeToCheck::StandardBIP44);
}

#[test]
fn test_try_from_standard_bip32_account() {
    let managed_account = ManagedAccountType::Standard {
        index: 0,
        standard_account_type: StandardAccountType::BIP32Account,
        external_addresses: test_address_pool(AddressPoolType::External),
        internal_addresses: test_address_pool(AddressPoolType::Internal),
    };

    let check_type: AccountTypeToCheck = managed_account.try_into().unwrap();
    assert_eq!(check_type, AccountTypeToCheck::StandardBIP32);
}

#[test]
fn test_try_from_coinjoin_account() {
    let managed_account = ManagedAccountType::CoinJoin {
        index: 0,
        addresses: test_single_pool(),
    };

    let check_type: AccountTypeToCheck = managed_account.try_into().unwrap();
    assert_eq!(check_type, AccountTypeToCheck::CoinJoin);
}

#[test]
fn test_try_from_identity_registration() {
    let managed_account = ManagedAccountType::IdentityRegistration {
        addresses: test_single_pool(),
    };

    let check_type: AccountTypeToCheck = managed_account.try_into().unwrap();
    assert_eq!(check_type, AccountTypeToCheck::IdentityRegistration);
}

#[test]
fn test_try_from_identity_topup() {
    let managed_account = ManagedAccountType::IdentityTopUp {
        registration_index: 1,
        addresses: test_single_pool(),
    };

    let check_type: AccountTypeToCheck = managed_account.try_into().unwrap();
    assert_eq!(check_type, AccountTypeToCheck::IdentityTopUp);
}

#[test]
fn test_try_from_identity_topup_not_bound() {
    let managed_account = ManagedAccountType::IdentityTopUpNotBoundToIdentity {
        addresses: test_single_pool(),
    };

    let check_type: AccountTypeToCheck = managed_account.try_into().unwrap();
    assert_eq!(check_type, AccountTypeToCheck::IdentityTopUpNotBound);
}

#[test]
fn test_try_from_identity_invitation() {
    let managed_account = ManagedAccountType::IdentityInvitation {
        addresses: test_single_pool(),
    };

    let check_type: AccountTypeToCheck = managed_account.try_into().unwrap();
    assert_eq!(check_type, AccountTypeToCheck::IdentityInvitation);
}

#[test]
fn test_try_from_provider_voting_keys() {
    let managed_account = ManagedAccountType::ProviderVotingKeys {
        addresses: test_single_pool(),
    };

    let check_type: AccountTypeToCheck = managed_account.try_into().unwrap();
    assert_eq!(check_type, AccountTypeToCheck::ProviderVotingKeys);
}

#[test]
fn test_try_from_provider_owner_keys() {
    let managed_account = ManagedAccountType::ProviderOwnerKeys {
        addresses: test_single_pool(),
    };

    let check_type: AccountTypeToCheck = managed_account.try_into().unwrap();
    assert_eq!(check_type, AccountTypeToCheck::ProviderOwnerKeys);
}

#[test]
fn test_try_from_provider_operator_keys() {
    let managed_account = ManagedAccountType::ProviderOperatorKeys {
        addresses: test_single_pool(),
    };

    let check_type: AccountTypeToCheck = managed_account.try_into().unwrap();
    assert_eq!(check_type, AccountTypeToCheck::ProviderOperatorKeys);
}

#[test]
fn test_try_from_provider_platform_keys() {
    let managed_account = ManagedAccountType::ProviderPlatformKeys {
        addresses: test_single_pool(),
    };

    let check_type: AccountTypeToCheck = managed_account.try_into().unwrap();
    assert_eq!(check_type, AccountTypeToCheck::ProviderPlatformKeys);
}

#[test]
fn test_try_from_platform_payment_fails() {
    let managed_account = ManagedAccountType::PlatformPayment {
        account: 0,
        key_class: 0,
        addresses: test_single_pool(),
    };

    let result: Result<AccountTypeToCheck, _> = managed_account.try_into();
    assert!(result.is_err());
}

#[test]
fn test_try_from_ref_standard_bip44_account() {
    let managed_account = ManagedAccountType::Standard {
        index: 0,
        standard_account_type: StandardAccountType::BIP44Account,
        external_addresses: test_address_pool(AddressPoolType::External),
        internal_addresses: test_address_pool(AddressPoolType::Internal),
    };

    let check_type: AccountTypeToCheck = (&managed_account).try_into().unwrap();
    assert_eq!(check_type, AccountTypeToCheck::StandardBIP44);
}

#[test]
fn test_try_from_ref_all_account_types() {
    // Test all account types using reference conversion
    let test_cases = vec![
        (
            ManagedAccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP32Account,
                external_addresses: test_address_pool(AddressPoolType::External),
                internal_addresses: test_address_pool(AddressPoolType::Internal),
            },
            AccountTypeToCheck::StandardBIP32,
        ),
        (
            ManagedAccountType::CoinJoin {
                index: 0,
                addresses: test_single_pool(),
            },
            AccountTypeToCheck::CoinJoin,
        ),
        (
            ManagedAccountType::IdentityRegistration {
                addresses: test_single_pool(),
            },
            AccountTypeToCheck::IdentityRegistration,
        ),
        (
            ManagedAccountType::IdentityTopUp {
                registration_index: 1,
                addresses: test_single_pool(),
            },
            AccountTypeToCheck::IdentityTopUp,
        ),
        (
            ManagedAccountType::IdentityTopUpNotBoundToIdentity {
                addresses: test_single_pool(),
            },
            AccountTypeToCheck::IdentityTopUpNotBound,
        ),
        (
            ManagedAccountType::IdentityInvitation {
                addresses: test_single_pool(),
            },
            AccountTypeToCheck::IdentityInvitation,
        ),
        (
            ManagedAccountType::ProviderVotingKeys {
                addresses: test_single_pool(),
            },
            AccountTypeToCheck::ProviderVotingKeys,
        ),
        (
            ManagedAccountType::ProviderOwnerKeys {
                addresses: test_single_pool(),
            },
            AccountTypeToCheck::ProviderOwnerKeys,
        ),
        (
            ManagedAccountType::ProviderOperatorKeys {
                addresses: test_single_pool(),
            },
            AccountTypeToCheck::ProviderOperatorKeys,
        ),
        (
            ManagedAccountType::ProviderPlatformKeys {
                addresses: test_single_pool(),
            },
            AccountTypeToCheck::ProviderPlatformKeys,
        ),
    ];

    for (managed_account, expected) in test_cases {
        let check_type: AccountTypeToCheck = (&managed_account).try_into().unwrap();
        assert_eq!(check_type, expected);
    }
}

#[test]
fn test_try_from_ref_platform_payment_fails() {
    let managed_account = ManagedAccountType::PlatformPayment {
        account: 0,
        key_class: 0,
        addresses: test_single_pool(),
    };

    let result: Result<AccountTypeToCheck, _> = (&managed_account).try_into();
    assert!(result.is_err());
}
