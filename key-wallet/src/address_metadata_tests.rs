//! Tests for address labeling and metadata functionality
//!
//! Tests the ability to associate labels and metadata with addresses.

#[cfg(test)]
mod tests {
    use crate::{Wallet, WalletConfig, Network, AddressInfo};
    use alloc::string::ToString;

    #[test]
    fn test_address_labeling() {
        let config = WalletConfig::new()
            .network(Network::Testnet)
            .account_count(1);
        
        let mut wallet = Wallet::new(config).unwrap();
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
        let config = WalletConfig::new()
            .network(Network::Testnet)
            .account_count(1);
        
        let mut wallet = Wallet::new(config).unwrap();
        let account = wallet.get_account_mut(0).unwrap();
        
        // Generate multiple addresses
        let addr1 = account.get_next_receive_address().unwrap();
        let addr2 = account.get_next_receive_address().unwrap();
        let change = account.get_next_change_address().unwrap();
        
        // Check pool stats
        let external_stats = account.external_pool().stats();
        assert_eq!(external_stats.total_generated, 2);
        assert_eq!(external_stats.total_used, 0);
        assert_eq!(external_stats.next_index, 2);
        
        let internal_stats = account.internal_pool().stats();
        assert_eq!(internal_stats.total_generated, 1);
        assert_eq!(internal_stats.total_used, 0);
        assert_eq!(internal_stats.next_index, 1);
        
        // Verify addresses can be found
        assert!(account.external_pool().get_address_info(&addr1).is_some());
        assert!(account.external_pool().get_address_info(&addr2).is_some());
        assert!(account.internal_pool().get_address_info(&change).is_some());
    }

    #[test]
    fn test_address_usage_tracking() {
        let config = WalletConfig::new()
            .network(Network::Testnet)
            .account_count(1);
        
        let mut wallet = Wallet::new(config).unwrap();
        let account = wallet.get_account_mut(0).unwrap();
        
        // Generate addresses
        let addr1 = account.get_next_receive_address().unwrap();
        let addr2 = account.get_next_receive_address().unwrap();
        let addr3 = account.get_next_receive_address().unwrap();
        
        // Mark first address as used
        account.external_pool_mut().mark_used(&addr1);
        
        // Check stats
        let stats = account.external_pool().stats();
        assert_eq!(stats.used_count, 1);
        assert_eq!(stats.total_generated, 3);
        
        // Mark another as used
        account.external_pool_mut().mark_used(&addr3);
        let stats = account.external_pool().stats();
        assert_eq!(stats.used_count, 2);
    }

    #[test]
    fn test_address_derivation_info() {
        let config = WalletConfig::new()
            .network(Network::Testnet)
            .account_count(1);
        
        let mut wallet = Wallet::new(config).unwrap();
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
        let config = WalletConfig::new()
            .network(Network::Testnet)
            .account_count(3);
        
        let mut wallet = Wallet::new(config).unwrap();
        
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
        let config = WalletConfig::new()
            .network(Network::Testnet)
            .account_count(1);
        
        let mut wallet = Wallet::new(config).unwrap();
        let account = wallet.get_account_mut(0).unwrap();
        
        // Generate addresses up to the lookahead window
        let mut addresses = vec![];
        for _ in 0..20 {
            addresses.push(account.get_next_receive_address().unwrap());
        }
        
        // All addresses should be tracked
        for addr in &addresses {
            assert!(account.external_pool().get_address_info(addr).is_some());
        }
        
        // Stats should reflect all generated addresses
        let stats = account.external_pool().stats();
        assert_eq!(stats.total_generated, 20);
        assert_eq!(stats.next_index, 20);
    }

    #[test]
    fn test_change_address_tracking() {
        let config = WalletConfig::new()
            .network(Network::Testnet)
            .account_count(1);
        
        let mut wallet = Wallet::new(config).unwrap();
        let account = wallet.get_account_mut(0).unwrap();
        
        // Generate change addresses
        let change1 = account.get_next_change_address().unwrap();
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
        let config = WalletConfig::new()
            .network(Network::Testnet)
            .account_count(1);
        
        let mut wallet = Wallet::new(config).unwrap();
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
        let config = WalletConfig::new()
            .network(Network::Testnet)
            .account_count(1);
        
        let mut wallet = Wallet::new(config).unwrap();
        let account = wallet.get_account_mut(0).unwrap();
        
        // Generate various addresses
        let recv1 = account.get_next_receive_address().unwrap();
        let recv2 = account.get_next_receive_address().unwrap();
        let change1 = account.get_next_change_address().unwrap();
        let change2 = account.get_next_change_address().unwrap();
        
        // Get all addresses
        let all_addresses = account.get_all_addresses();
        
        // Should contain all generated addresses
        assert!(all_addresses.contains(&recv1));
        assert!(all_addresses.contains(&recv2));
        assert!(all_addresses.contains(&change1));
        assert!(all_addresses.contains(&change2));
        assert!(all_addresses.len() >= 4);
    }
}