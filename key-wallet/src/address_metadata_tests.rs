//! Tests for address labeling and metadata functionality
//!
//! NOTE: These tests need to be updated to work with the new Account/ManagedAccount split

#[cfg(test)]
mod tests {
    use crate::ChildIndex;
    use crate::{
        account::{AccountType, StandardAccountType},
        Network, Wallet,
    };

    // TODO: Address metadata tests need to be reimplemented with ManagedAccount
    // The following functionality is now in ManagedAccount:
    // - Address pools (external_pool, internal_pool)
    // - Address generation (get_next_receive_address, get_next_change_address)
    // - Address metadata management
    // - Address usage tracking
    // - Pool statistics
    //
    // To properly test this functionality, we would need:
    // 1. Create an Account (immutable identity)
    // 2. Create a corresponding ManagedAccount (mutable state)
    // 3. Test address metadata operations on the ManagedAccount

    #[test]
    fn test_basic_wallet_creation() {
        // Basic test that wallet and accounts can be created

        let wallet = Wallet::new_random(
            Network::Testnet,
            crate::wallet::initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();

        // Verify wallet has a default account
        assert!(wallet.get_bip44_account(ChildIndex::ZERO).is_some());

        let account = wallet.get_bip44_account(ChildIndex::ZERO).unwrap();
        match &account.account_type {
            AccountType::Standard {
                index,
                ..
            } => assert_eq!(*index, ChildIndex::ZERO),
            _ => panic!("Expected Standard account type"),
        }
    }

    #[test]
    fn test_multiple_accounts() {
        let mut wallet = Wallet::new_random(
            Network::Testnet,
            crate::wallet::initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();

        // Add more accounts
        wallet
            .add_account(
                AccountType::Standard {
                    index: ChildIndex::new_const(1),
                    standard_account_type: StandardAccountType::BIP44Account,
                },
                None,
            )
            .unwrap();
        wallet
            .add_account(
                AccountType::Standard {
                    index: ChildIndex::new_const(2),
                    standard_account_type: StandardAccountType::BIP44Account,
                },
                None,
            )
            .unwrap();

        // Verify accounts exist
        assert!(wallet.get_bip44_account(ChildIndex::ZERO).is_some());
        assert!(wallet.get_bip44_account(ChildIndex::new_const(1)).is_some());
        assert!(wallet.get_bip44_account(ChildIndex::new_const(2)).is_some());

        // Verify account indices
        for i in 0..3 {
            let account = wallet.get_bip44_account(ChildIndex::new_const(i)).unwrap();
            match &account.account_type {
                AccountType::Standard {
                    index,
                    ..
                } => assert_eq!(*index, ChildIndex::new_const(i)),
                _ => panic!("Expected Standard account type"),
            }
        }
    }

    // The following tests would need ManagedAccount integration:
    // - test_address_labeling
    // - test_address_pool_info
    // - test_address_usage_tracking
    // - test_gap_limit_handling
    // - test_address_metadata_persistence
    // - test_coinjoin_address_pools
    // - test_change_address_handling
    // - test_concurrent_address_access
    // - test_address_metadata_updates
    // - test_pool_statistics
}
