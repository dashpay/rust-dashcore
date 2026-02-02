//! Platform-level balance checking and management
//!
//! This module provides methods on ManagedWalletInfo for managing
//! Platform Payment account balances (DIP-17).

use crate::account::account_collection::PlatformPaymentAccountKey;
use crate::managed_account::address_pool::KeySource;
use crate::managed_account::platform_address::PlatformP2PKHAddress;
use crate::wallet::managed_wallet_info::ManagedWalletInfo;

/// Extension trait for ManagedWalletInfo to add Platform balance management capabilities
pub trait WalletPlatformChecker {
    /// Get the total platform credit balance across all Platform Payment accounts
    ///
    /// This sums the credit_balance from all platform_payment_accounts.
    fn platform_credit_balance(&self) -> u64;

    /// Get the total platform balance in duffs (credit_balance / 1000)
    fn platform_duff_balance(&self) -> u64;

    /// Set the credit balance for a specific platform address
    ///
    /// The address must belong to one of the Platform Payment accounts.
    /// If `key_source` is provided and the address becomes funded (0 → non-zero),
    /// the address will be marked as used and gap limit will be maintained.
    /// Returns true if the address was found and the balance was set.
    fn set_platform_address_balance(
        &mut self,
        address: &PlatformP2PKHAddress,
        credit_balance: u64,
        key_source: Option<&KeySource>,
    ) -> bool;

    /// Set the credit balance for a specific platform address by account key
    ///
    /// This is more efficient when you know which account the address belongs to.
    /// If `key_source` is provided and the address becomes funded (0 → non-zero),
    /// the address will be marked as used and gap limit will be maintained.
    /// Returns true if the account was found and the balance was set.
    fn set_platform_address_balance_for_account(
        &mut self,
        account_key: &PlatformPaymentAccountKey,
        address: PlatformP2PKHAddress,
        credit_balance: u64,
        key_source: Option<&KeySource>,
    ) -> bool;

    /// Increase the credit balance for a specific platform address
    ///
    /// The address must belong to one of the Platform Payment accounts.
    /// If `key_source` is provided and the address becomes funded (0 → non-zero),
    /// the address will be marked as used and gap limit will be maintained.
    /// Returns the new balance if successful, None if the address was not found.
    fn increase_platform_address_balance(
        &mut self,
        address: &PlatformP2PKHAddress,
        amount: u64,
        key_source: Option<&KeySource>,
    ) -> Option<u64>;

    /// Increase the credit balance for a specific platform address by account key
    ///
    /// This is more efficient when you know which account the address belongs to.
    /// If `key_source` is provided and the address becomes funded (0 → non-zero),
    /// the address will be marked as used and gap limit will be maintained.
    /// Returns the new balance if successful, None if the account was not found.
    fn increase_platform_address_balance_for_account(
        &mut self,
        account_key: &PlatformPaymentAccountKey,
        address: PlatformP2PKHAddress,
        amount: u64,
        key_source: Option<&KeySource>,
    ) -> Option<u64>;

    /// Decrease the credit balance for a specific platform address
    ///
    /// The address must belong to one of the Platform Payment accounts.
    /// The balance will not go below zero (saturating subtraction).
    /// Returns the new balance if successful, None if the address was not found.
    fn decrease_platform_address_balance(
        &mut self,
        address: &PlatformP2PKHAddress,
        amount: u64,
    ) -> Option<u64>;

    /// Get the credit balance for a specific platform address
    ///
    /// Returns the balance if the address was found, None otherwise.
    fn get_platform_address_balance(&self, address: &PlatformP2PKHAddress) -> Option<u64>;
}

impl WalletPlatformChecker for ManagedWalletInfo {
    fn platform_credit_balance(&self) -> u64 {
        self.accounts
            .platform_payment_accounts
            .values()
            .map(|account| account.total_credit_balance())
            .sum()
    }

    fn platform_duff_balance(&self) -> u64 {
        self.platform_credit_balance() / 1000
    }

    fn set_platform_address_balance(
        &mut self,
        address: &PlatformP2PKHAddress,
        credit_balance: u64,
        key_source: Option<&KeySource>,
    ) -> bool {
        // Find the account that contains this address
        for account in self.accounts.platform_payment_accounts.values_mut() {
            if account.contains_platform_address(address) {
                account.set_address_credit_balance(*address, credit_balance, key_source);
                return true;
            }
        }
        false
    }

    fn set_platform_address_balance_for_account(
        &mut self,
        account_key: &PlatformPaymentAccountKey,
        address: PlatformP2PKHAddress,
        credit_balance: u64,
        key_source: Option<&KeySource>,
    ) -> bool {
        if let Some(account) = self.accounts.platform_payment_accounts.get_mut(account_key) {
            // Verify the address belongs to this account before modifying
            if !account.contains_platform_address(&address) {
                return false;
            }
            account.set_address_credit_balance(address, credit_balance, key_source);
            true
        } else {
            false
        }
    }

    fn increase_platform_address_balance(
        &mut self,
        address: &PlatformP2PKHAddress,
        amount: u64,
        key_source: Option<&KeySource>,
    ) -> Option<u64> {
        // Find the account that contains this address
        for account in self.accounts.platform_payment_accounts.values_mut() {
            if account.contains_platform_address(address) {
                let new_balance = account.add_address_credit_balance(*address, amount, key_source);
                return Some(new_balance);
            }
        }
        None
    }

    fn increase_platform_address_balance_for_account(
        &mut self,
        account_key: &PlatformPaymentAccountKey,
        address: PlatformP2PKHAddress,
        amount: u64,
        key_source: Option<&KeySource>,
    ) -> Option<u64> {
        if let Some(account) = self.accounts.platform_payment_accounts.get_mut(account_key) {
            // Verify the address belongs to this account before modifying
            if !account.contains_platform_address(&address) {
                return None;
            }
            let new_balance = account.add_address_credit_balance(address, amount, key_source);
            Some(new_balance)
        } else {
            None
        }
    }

    fn decrease_platform_address_balance(
        &mut self,
        address: &PlatformP2PKHAddress,
        amount: u64,
    ) -> Option<u64> {
        // Find the account that contains this address
        for account in self.accounts.platform_payment_accounts.values_mut() {
            if account.contains_platform_address(address) {
                let new_balance = account.remove_address_credit_balance(*address, amount);
                return Some(new_balance);
            }
        }
        None
    }

    fn get_platform_address_balance(&self, address: &PlatformP2PKHAddress) -> Option<u64> {
        // Find the account that contains this address
        for account in self.accounts.platform_payment_accounts.values() {
            if account.contains_platform_address(address) {
                return Some(account.address_credit_balance(address));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip32::{ChildNumber, DerivationPath};
    use crate::managed_account::address_pool::{AddressPool, AddressPoolType};
    use crate::managed_account::managed_platform_account::ManagedPlatformAccount;
    use crate::Network;

    fn create_test_pool() -> AddressPool {
        let base_path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(9).unwrap(),
            ChildNumber::from_hardened_idx(1).unwrap(),
            ChildNumber::from_hardened_idx(17).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
        ]);
        AddressPool::new_without_generation(
            base_path,
            AddressPoolType::Absent,
            10,
            Network::Testnet,
        )
    }

    fn create_test_wallet_info() -> ManagedWalletInfo {
        ManagedWalletInfo::new(Network::Testnet, [0u8; 32])
    }

    #[test]
    fn test_platform_credit_balance_empty() {
        let wallet_info = create_test_wallet_info();
        assert_eq!(wallet_info.platform_credit_balance(), 0);
        assert_eq!(wallet_info.platform_duff_balance(), 0);
    }

    #[test]
    fn test_platform_credit_balance_with_accounts() {
        let mut wallet_info = create_test_wallet_info();

        // Create and add a platform account
        let pool = create_test_pool();
        let mut account = ManagedPlatformAccount::new(0, 0, pool, false);

        // Add some balance
        let addr = PlatformP2PKHAddress::new([0x11; 20]);
        account.set_address_credit_balance(addr, 5000, None);

        let key = PlatformPaymentAccountKey {
            account: 0,
            key_class: 0,
        };
        wallet_info.accounts.platform_payment_accounts.insert(key, account);

        assert_eq!(wallet_info.platform_credit_balance(), 5000);
        assert_eq!(wallet_info.platform_duff_balance(), 5); // 5000 / 1000 = 5
    }

    #[test]
    fn test_platform_credit_balance_multiple_accounts() {
        let mut wallet_info = create_test_wallet_info();

        // Create first platform account
        let pool1 = create_test_pool();
        let mut account1 = ManagedPlatformAccount::new(0, 0, pool1, false);
        let addr1 = PlatformP2PKHAddress::new([0x11; 20]);
        account1.set_address_credit_balance(addr1, 3000, None);

        // Create second platform account
        let pool2 = create_test_pool();
        let mut account2 = ManagedPlatformAccount::new(1, 0, pool2, false);
        let addr2 = PlatformP2PKHAddress::new([0x22; 20]);
        account2.set_address_credit_balance(addr2, 2000, None);

        wallet_info.accounts.platform_payment_accounts.insert(
            PlatformPaymentAccountKey {
                account: 0,
                key_class: 0,
            },
            account1,
        );
        wallet_info.accounts.platform_payment_accounts.insert(
            PlatformPaymentAccountKey {
                account: 1,
                key_class: 0,
            },
            account2,
        );

        assert_eq!(wallet_info.platform_credit_balance(), 5000);
        assert_eq!(wallet_info.platform_duff_balance(), 5);
    }

    #[test]
    fn test_set_platform_address_balance() {
        let mut wallet_info = create_test_wallet_info();

        // Create platform account
        let pool = create_test_pool();
        let mut account = ManagedPlatformAccount::new(0, 0, pool, false);
        let addr = PlatformP2PKHAddress::new([0x11; 20]);
        account.set_address_credit_balance(addr, 1000, None);

        let key = PlatformPaymentAccountKey {
            account: 0,
            key_class: 0,
        };
        wallet_info.accounts.platform_payment_accounts.insert(key, account);

        // Set balance for existing address
        let result = wallet_info.set_platform_address_balance(&addr, 5000, None);
        assert!(result);
        assert_eq!(wallet_info.platform_credit_balance(), 5000);

        // Try to set balance for non-existent address
        let unknown_addr = PlatformP2PKHAddress::new([0xFF; 20]);
        let result = wallet_info.set_platform_address_balance(&unknown_addr, 1000, None);
        assert!(!result);
    }

    #[test]
    fn test_increase_platform_address_balance() {
        let mut wallet_info = create_test_wallet_info();

        // Create platform account
        let pool = create_test_pool();
        let mut account = ManagedPlatformAccount::new(0, 0, pool, false);
        let addr = PlatformP2PKHAddress::new([0x11; 20]);
        account.set_address_credit_balance(addr, 1000, None);

        let key = PlatformPaymentAccountKey {
            account: 0,
            key_class: 0,
        };
        wallet_info.accounts.platform_payment_accounts.insert(key, account);

        // Increase balance
        let new_balance = wallet_info.increase_platform_address_balance(&addr, 500, None);
        assert_eq!(new_balance, Some(1500));
        assert_eq!(wallet_info.platform_credit_balance(), 1500);

        // Increase again
        let new_balance = wallet_info.increase_platform_address_balance(&addr, 1000, None);
        assert_eq!(new_balance, Some(2500));
        assert_eq!(wallet_info.platform_credit_balance(), 2500);
    }

    #[test]
    fn test_decrease_platform_address_balance() {
        let mut wallet_info = create_test_wallet_info();

        // Create platform account
        let pool = create_test_pool();
        let mut account = ManagedPlatformAccount::new(0, 0, pool, false);
        let addr = PlatformP2PKHAddress::new([0x11; 20]);
        account.set_address_credit_balance(addr, 5000, None);

        let key = PlatformPaymentAccountKey {
            account: 0,
            key_class: 0,
        };
        wallet_info.accounts.platform_payment_accounts.insert(key, account);

        // Decrease balance
        let new_balance = wallet_info.decrease_platform_address_balance(&addr, 1000);
        assert_eq!(new_balance, Some(4000));

        // Decrease more than available (should saturate at 0)
        let new_balance = wallet_info.decrease_platform_address_balance(&addr, 10000);
        assert_eq!(new_balance, Some(0));
    }

    #[test]
    fn test_get_platform_address_balance() {
        let mut wallet_info = create_test_wallet_info();

        // Create platform account
        let pool = create_test_pool();
        let mut account = ManagedPlatformAccount::new(0, 0, pool, false);
        let addr = PlatformP2PKHAddress::new([0x11; 20]);
        account.set_address_credit_balance(addr, 3000, None);

        let key = PlatformPaymentAccountKey {
            account: 0,
            key_class: 0,
        };
        wallet_info.accounts.platform_payment_accounts.insert(key, account);

        // Get balance for existing address
        let balance = wallet_info.get_platform_address_balance(&addr);
        assert_eq!(balance, Some(3000));

        // Get balance for non-existent address
        let unknown_addr = PlatformP2PKHAddress::new([0xFF; 20]);
        let balance = wallet_info.get_platform_address_balance(&unknown_addr);
        assert_eq!(balance, None);
    }

    #[test]
    fn test_set_platform_address_balance_for_account() {
        let mut wallet_info = create_test_wallet_info();

        // Create platform account with an address already having a balance
        let pool = create_test_pool();
        let mut account = ManagedPlatformAccount::new(0, 0, pool, false);
        let addr = PlatformP2PKHAddress::new([0x11; 20]);
        // First set initial balance so the address is known to the account
        account.set_address_credit_balance(addr, 1000, None);

        let key = PlatformPaymentAccountKey {
            account: 0,
            key_class: 0,
        };
        wallet_info.accounts.platform_payment_accounts.insert(key, account);

        // Update balance using account key - should succeed since address is known
        let result = wallet_info.set_platform_address_balance_for_account(&key, addr, 5000, None);
        assert!(result);
        assert_eq!(wallet_info.platform_credit_balance(), 5000);

        // Try with address not belonging to the account - should fail
        let unknown_addr = PlatformP2PKHAddress::new([0xFF; 20]);
        let result =
            wallet_info.set_platform_address_balance_for_account(&key, unknown_addr, 2000, None);
        assert!(!result);
        assert_eq!(wallet_info.platform_credit_balance(), 5000); // Balance unchanged

        // Try with non-existent account
        let bad_key = PlatformPaymentAccountKey {
            account: 99,
            key_class: 0,
        };
        let result =
            wallet_info.set_platform_address_balance_for_account(&bad_key, addr, 1000, None);
        assert!(!result);
    }
}
