//! Tests for address labeling and metadata functionality
//!
//! Tests the ability to associate labels and metadata with addresses.

#[cfg(test)]
mod tests {
    use crate::{Network, Wallet, WalletConfig, WalletType};

    #[test]
    fn test_address_labeling() {
        let config = WalletConfig::default();

        let mut wallet = Wallet::new(config, Network::Testnet).unwrap();
        let account = wallet.get_account_mut(0).unwrap();

        // Generate an address
        let address = account.get_next_receive_address().unwrap();

        // Get address info
        let info = account.external_pool().get_address_info(&address);
        assert!(info.is_some());

        let info = info.unwrap();
        assert_eq!(info.address, address);
        assert_eq!(info.index, 0);
        // External address (not change)
    }

    #[test]
    fn test_address_pool_info() {
        let config = WalletConfig::default();

        let mut wallet = Wallet::new(config, Network::Testnet).unwrap();
        let account = wallet.get_account_mut(0).unwrap();

        // Generate multiple addresses
        let addr1 = account.get_next_receive_address().unwrap();
        let addr2 = account.get_next_receive_address().unwrap();
        let change = account.get_next_change_address().unwrap();

        // Check pool stats
        let external_stats = account.external_pool().stats();
        assert_eq!(external_stats.total_generated, 20); // Pre-generated to gap limit
        assert_eq!(external_stats.used_count, 0);
        // next_index is not a field, highest_generated tracks highest index

        let internal_stats = account.internal_pool().stats();
        assert_eq!(internal_stats.total_generated, 10); // Pre-generated to gap limit
        assert_eq!(internal_stats.used_count, 0);
        // next_index is not a field, highest_generated tracks highest index

        // Verify addresses can be found
        assert!(account.external_pool().get_address_info(&addr1).is_some());
        assert!(account.external_pool().get_address_info(&addr2).is_some());
        assert!(account.internal_pool().get_address_info(&change).is_some());
    }

    #[test]
    fn test_address_usage_tracking() {
        let config = WalletConfig::default();

        let mut wallet = Wallet::new(config, Network::Testnet).unwrap();
        let account = wallet.get_account_mut(0).unwrap();

        // Generate addresses - should be same until marked as used
        let addr1 = account.get_next_receive_address().unwrap();
        let addr2 = account.get_next_receive_address().unwrap();
        assert_eq!(addr1, addr2); // Should be same unused address

        // Mark first address as used
        account.external_pool_mut().mark_used(&addr1);

        // Now get a different address
        let addr3 = account.get_next_receive_address().unwrap();
        assert_ne!(addr1, addr3); // Should be different after marking used

        // Check stats
        let stats = account.external_pool().stats();
        assert_eq!(stats.used_count, 1);
        assert_eq!(stats.total_generated, 20); // Pre-generated to gap limit

        // Mark another as used
        account.external_pool_mut().mark_used(&addr3);
        let stats = account.external_pool().stats();
        assert_eq!(stats.used_count, 2);
    }

    #[test]
    fn test_address_derivation_info() {
        let config = WalletConfig::default();

        let mut wallet = Wallet::new(config, Network::Testnet).unwrap();
        let account = wallet.get_account_mut(0).unwrap();

        // Generate an address
        let address = account.get_next_receive_address().unwrap();

        // Get address info
        let info = account.external_pool().get_address_info(&address).unwrap();

        // Verify derivation info
        assert_eq!(info.index, 0);
        assert_eq!(info.address, address);
        // The address is from external pool (not change)
    }

    #[test]
    fn test_multiple_account_address_tracking() {
        let config = WalletConfig::default();

        let mut wallet = Wallet::new(config, Network::Testnet).unwrap();

        // Generate addresses for each account
        let mut addresses = vec![];
        for i in 0..3 {
            let account = wallet.get_account_mut(i).unwrap();
            let addr = account.get_next_receive_address().unwrap();
            addresses.push((i, addr));
        }

        // Verify each account tracks its own addresses
        for (account_idx, addr) in addresses {
            let account = wallet.get_account(account_idx).unwrap();
            let info = account.external_pool().get_address_info(&addr);
            assert!(info.is_some());

            // Other accounts shouldn't have this address
            for i in 0..3 {
                if i != account_idx {
                    let other_account = wallet.get_account(i).unwrap();
                    assert!(other_account.external_pool().get_address_info(&addr).is_none());
                }
            }
        }
    }

    #[test]
    fn test_address_pool_lookahead() {
        let config = WalletConfig::default();

        let mut wallet = Wallet::new(config, Network::Testnet).unwrap();
        let account = wallet.get_account_mut(0).unwrap();

        // All pre-generated addresses should already exist
        let mut addresses = vec![];
        for i in 0..20 {
            // Get address at specific index since they're pre-generated
            let addr = account.external_pool().get_address_at_index(i).unwrap();
            addresses.push(addr);
        }

        // All addresses should be tracked
        for addr in &addresses {
            assert!(account.external_pool().get_address_info(addr).is_some());
        }

        // Stats should reflect all generated addresses
        let stats = account.external_pool().stats();
        assert_eq!(stats.total_generated, 20);
        // next_index is not a field, highest_generated tracks highest index
    }

    #[test]
    fn test_change_address_tracking() {
        let config = WalletConfig::default();

        let mut wallet = Wallet::new(config, Network::Testnet).unwrap();
        let account = wallet.get_account_mut(0).unwrap();

        // Generate change addresses
        let change1 = account.get_next_change_address().unwrap();
        account.internal_pool_mut().mark_used(&change1); // Mark as used to get different address
        let change2 = account.get_next_change_address().unwrap();

        // Verify they're tracked in the internal pool
        let info1 = account.internal_pool().get_address_info(&change1).unwrap();
        assert_eq!(info1.index, 0);
        // This is a change address from internal pool

        let info2 = account.internal_pool().get_address_info(&change2).unwrap();
        assert_eq!(info2.index, 1);
        // This is a change address from internal pool

        // They shouldn't be in the external pool
        assert!(account.external_pool().get_address_info(&change1).is_none());
        assert!(account.external_pool().get_address_info(&change2).is_none());
    }

    #[test]
    fn test_address_info_consistency() {
        let config = WalletConfig::default();

        let mut wallet = Wallet::new(config, Network::Testnet).unwrap();
        let account = wallet.get_account_mut(0).unwrap();

        // Generate an address
        let address = account.get_next_receive_address().unwrap();

        // Get info multiple times - should be consistent
        let info1 = account.external_pool().get_address_info(&address).unwrap();
        let info2 = account.external_pool().get_address_info(&address).unwrap();

        assert_eq!(info1.address, info2.address);
        assert_eq!(info1.index, info2.index);
        // Both should be from the same pool
    }

    #[test]
    fn test_account_all_addresses() {
        let config = WalletConfig::default();

        let mut wallet = Wallet::new(config, Network::Testnet).unwrap();
        let account = wallet.get_account_mut(0).unwrap();

        // Get some addresses (pre-generated)
        let recv1 = account.external_pool().get_address_at_index(0).unwrap();
        let recv2 = account.external_pool().get_address_at_index(1).unwrap();
        let change1 = account.internal_pool().get_address_at_index(0).unwrap();
        let change2 = account.internal_pool().get_address_at_index(1).unwrap();

        // Get all addresses
        let all_addresses = account.get_all_addresses();

        // Should contain all pre-generated addresses
        assert!(all_addresses.contains(&recv1));
        assert!(all_addresses.contains(&recv2));
        assert!(all_addresses.contains(&change1));
        assert!(all_addresses.contains(&change2));
        assert_eq!(all_addresses.len(), 30); // 20 external + 10 internal pre-generated
    }
}
