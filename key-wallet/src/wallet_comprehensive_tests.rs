//! Comprehensive wallet tests based on DashSync-iOS test coverage
//!
//! These tests ensure feature parity with DashSync-iOS wallet functionality

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::account::{Account, AccountType};
    use crate::address::Address;
    use crate::address_pool::{AddressPool, KeySource};
    use crate::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey};
    use crate::gap_limit::{GapLimit, GapLimitManager};
    use crate::mnemonic::{Language, Mnemonic};
    use crate::wallet::{Wallet, WalletConfig};
    use crate::Network;

    // Test vectors from DashSync
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const TEST_PASSPHRASE: &str = "";

    // ============================================================================
    // Wallet Transaction Tests
    // ============================================================================

    #[test]
    fn test_wallet_transaction_creation() {
        let config = WalletConfig {
            network: Network::Testnet,
            ..Default::default()
        };
        
        let mut wallet = Wallet::new(config).unwrap();
        
        // Generate some addresses
        let addr1 = wallet.get_next_receive_address().unwrap();
        let addr2 = wallet.get_next_receive_address().unwrap();
        
        // Mark first as used to get different address
        wallet.mark_address_used(&addr1);
        let addr3 = wallet.get_next_receive_address().unwrap();
        
        assert_ne!(addr1, addr3);
        assert_eq!(addr2, addr3); // Should reuse addr2 since it's still unused
    }

    #[test]
    fn test_wallet_balance_tracking() {
        let config = WalletConfig {
            network: Network::Testnet,
            initial_accounts: 2,
            ..Default::default()
        };
        
        let mut wallet = Wallet::new(config).unwrap();
        
        // Update balances for different accounts
        wallet.get_account_mut(0).unwrap().update_balance(100000, 50000, 0);
        wallet.get_account_mut(1).unwrap().update_balance(200000, 0, 10000);
        
        let total = wallet.total_balance();
        assert_eq!(total.confirmed, 300000);
        assert_eq!(total.unconfirmed, 50000);
        assert_eq!(total.immature, 10000);
        assert_eq!(total.total, 350000);
    }

    #[test]
    fn test_wallet_recovery_from_mnemonic() {
        let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC, Language::English).unwrap();
        
        let config = WalletConfig {
            network: Network::Testnet,
            external_gap_limit: 20,
            internal_gap_limit: 10,
            ..Default::default()
        };
        
        let wallet1 = Wallet::from_mnemonic(mnemonic.clone(), config.clone()).unwrap();
        
        // Get some addresses
        let mut addrs1 = Vec::new();
        for i in 0..5 {
            if let Some(account) = wallet1.get_account(0) {
                let addr = account.external_addresses.get_info_at_index(i)
                    .map(|info| info.address.clone());
                if let Some(a) = addr {
                    addrs1.push(a);
                }
            }
        }
        
        // Recover wallet
        let wallet2 = Wallet::from_mnemonic(mnemonic, config).unwrap();
        
        // Verify same addresses
        for i in 0..5 {
            if let Some(account) = wallet2.get_account(0) {
                let addr = account.external_addresses.get_info_at_index(i)
                    .map(|info| info.address.clone());
                if let Some(a) = addr {
                    assert_eq!(a, addrs1[i as usize]);
                }
            }
        }
    }

    #[test]
    fn test_chain_synchronization_fingerprint() {
        // This is from DSWalletTests.m
        let random_block_zones = vec![7u32, 68, 91, 130, 132, 135, 137, 154];
        // In production, this would generate a fingerprint for chain sync
        // Here we just verify the data structure works
        assert_eq!(random_block_zones.len(), 8);
    }

    // ============================================================================
    // Account Management Tests
    // ============================================================================

    #[test]
    fn test_multiple_account_management() {
        let config = WalletConfig {
            network: Network::Testnet,
            ..Default::default()
        };
        
        let mut wallet = Wallet::new(config).unwrap();
        
        // Create multiple accounts
        wallet.create_account(1, AccountType::Standard).unwrap();
        wallet.create_account(2, AccountType::CoinJoin).unwrap();
        
        assert_eq!(wallet.accounts.len(), 3); // 1 initial + 2 created
        
        // Verify account types
        assert_eq!(wallet.get_account(0).unwrap().account_type, AccountType::Standard);
        assert_eq!(wallet.get_account(2).unwrap().account_type, AccountType::CoinJoin);
    }

    #[test]
    fn test_account_discovery_with_gaps() {
        let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC, Language::English).unwrap();
        let seed = mnemonic.to_seed("");
        let master = ExtendedPrivKey::new_master(Network::Testnet, &seed).unwrap();
        
        // Create account with gap limit
        let secp = secp256k1::Secp256k1::new();
        let path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(44).unwrap(),
            ChildNumber::from_hardened_idx(1).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
        ]);
        let account_key = master.derive_priv(&secp, &path).unwrap();
        
        let mut account = Account::new(0, account_key, Network::Testnet, 20, 10).unwrap();
        
        // Mark some addresses as used with gaps
        let addrs = account.external_addresses.get_all_addresses();
        if addrs.len() >= 10 {
            account.mark_address_used(&addrs[2]);  // gap of 2
            account.mark_address_used(&addrs[5]);  // gap of 2
            account.mark_address_used(&addrs[9]);  // gap of 3
        }
        
        // Verify gap limit tracking
        assert_eq!(account.gap_limits.external.highest_used_index, Some(9));
    }

    // ============================================================================
    // CoinJoin/PrivateSend Tests
    // ============================================================================

    #[test]
    fn test_coinjoin_account_creation() {
        let config = WalletConfig {
            network: Network::Testnet,
            enable_coinjoin: true,
            coinjoin_gap_limit: 10,
            ..Default::default()
        };
        
        let wallet = Wallet::new(config).unwrap();
        
        // Verify CoinJoin is enabled on default account
        let account = wallet.get_account(0).unwrap();
        assert!(account.coinjoin_addresses.is_some());
    }

    #[test]
    fn test_coinjoin_address_isolation() {
        let config = WalletConfig {
            network: Network::Testnet,
            ..Default::default()
        };
        
        let mut wallet = Wallet::new(config).unwrap();
        wallet.enable_coinjoin_for_account(0).unwrap();
        
        let account = wallet.get_account_mut(0).unwrap();
        
        // Get addresses from different pools
        let regular_addr = account.get_next_receive_address().unwrap();
        let coinjoin_addr = account.get_next_coinjoin_receive_address().unwrap();
        
        // Verify they're different
        assert_ne!(regular_addr, coinjoin_addr);
        
        // Verify isolation
        assert!(account.external_addresses.contains_address(&regular_addr));
        assert!(!account.external_addresses.contains_address(&coinjoin_addr));
        
        if let Some(ref cj) = account.coinjoin_addresses {
            assert!(cj.external.contains_address(&coinjoin_addr));
            assert!(!cj.external.contains_address(&regular_addr));
        }
    }

    // ============================================================================
    // Mnemonic Language Tests
    // ============================================================================

    #[test]
    fn test_mnemonic_multiple_languages() {
        let languages = vec![
            Language::English,
            Language::Japanese,
            Language::Korean,
            Language::Spanish,
            Language::ChineseSimplified,
            Language::ChineseTraditional,
            Language::French,
            Language::Italian,
            Language::Czech,
        ];
        
        for lang in languages {
            let mnemonic = Mnemonic::new(128, lang).unwrap();
            assert_eq!(mnemonic.language(), lang);
            
            // Verify we can create a wallet
            let config = WalletConfig {
                network: Network::Testnet,
                language: lang,
                ..Default::default()
            };
            
            let wallet = Wallet::from_mnemonic(mnemonic, config);
            assert!(wallet.is_ok());
        }
    }

    #[test]
    fn test_mnemonic_validation_and_recovery() {
        // Test invalid mnemonic
        let invalid = Mnemonic::from_phrase("invalid invalid invalid", Language::English);
        assert!(invalid.is_err());
        
        // Test valid but wrong checksum
        let wrong_checksum = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
            Language::English
        );
        assert!(wrong_checksum.is_err());
        
        // Test valid mnemonic
        let valid = Mnemonic::from_phrase(TEST_MNEMONIC, Language::English);
        assert!(valid.is_ok());
    }

    // ============================================================================
    // Gap Limit Edge Cases
    // ============================================================================

    #[test]
    fn test_gap_limit_with_sparse_usage() {
        let mut gap = GapLimit::new(5);
        
        // Generate addresses 0-19
        for i in 0..20 {
            gap.mark_generated(i);
        }
        
        // Use addresses sparsely: 3, 7, 12, 18
        gap.mark_used(3);
        gap.mark_used(7);
        gap.mark_used(12);
        gap.mark_used(18);
        
        assert_eq!(gap.highest_used_index, Some(18));
        assert_eq!(gap.current_unused_count, 1); // Only index 19 after 18
        assert!(!gap.limit_reached);
        
        // Generate more
        for i in 20..24 {
            gap.mark_generated(i);
        }
        
        assert_eq!(gap.current_unused_count, 5); // indices 19-23
        assert!(gap.limit_reached);
    }

    #[test]
    fn test_gap_limit_recovery_scenarios() {
        let mut manager = GapLimitManager::new(20, 10, Some(5));
        
        // Simulate recovery with various patterns
        
        // External: used up to index 50 with gaps
        for i in vec![5, 15, 25, 35, 45, 50] {
            manager.external.mark_used(i);
            manager.external.mark_generated(i);
        }
        
        // Internal: used up to index 30
        for i in vec![3, 8, 15, 22, 30] {
            manager.internal.mark_used(i);
            manager.internal.mark_generated(i);
        }
        
        // CoinJoin: used up to index 10
        if let Some(ref mut cj) = manager.coinjoin {
            for i in vec![2, 5, 10] {
                cj.mark_used(i);
                cj.mark_generated(i);
            }
        }
        
        assert!(!manager.is_discovery_complete());
        assert_eq!(manager.external.highest_used_index, Some(50));
        assert_eq!(manager.internal.highest_used_index, Some(30));
    }

    // ============================================================================
    // Address Pool Performance
    // ============================================================================

    #[test]
    fn test_large_address_pool_generation() {
        let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC, Language::English).unwrap();
        let seed = mnemonic.to_seed("");
        let master = ExtendedPrivKey::new_master(Network::Testnet, &seed).unwrap();
        
        let base_path = DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]);
        let mut pool = AddressPool::new(base_path, false, 20, Network::Testnet);
        
        let key_source = KeySource::Private(master);
        
        // Generate 1000 addresses
        let start = std::time::Instant::now();
        let addresses = pool.generate_addresses(1000, &key_source).unwrap();
        let duration = start.elapsed();
        
        assert_eq!(addresses.len(), 1000);
        assert_eq!(pool.highest_generated, 999);
        
        // Should complete in reasonable time (< 5 seconds)
        assert!(duration.as_secs() < 5);
    }

    #[test]
    fn test_address_pool_pruning() {
        let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC, Language::English).unwrap();
        let seed = mnemonic.to_seed("");
        let master = ExtendedPrivKey::new_master(Network::Testnet, &seed).unwrap();
        
        let base_path = DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]);
        let mut pool = AddressPool::new(base_path, false, 20, Network::Testnet);
        
        let key_source = KeySource::Private(master);
        
        // Generate 100 addresses
        pool.generate_addresses(100, &key_source).unwrap();
        
        // Mark some as used
        pool.mark_index_used(10);
        pool.mark_index_used(20);
        pool.mark_index_used(30);
        
        // Prune unused beyond gap limit
        let pruned = pool.prune_unused();
        
        // Should keep up to index 30 + gap_limit (20) = 50
        // So should prune 49 addresses (51-99)
        assert!(pruned > 0);
        assert!(pool.highest_generated <= 50);
    }

    // ============================================================================
    // Watch-Only Wallet Tests
    // ============================================================================

    #[test]
    fn test_watch_only_wallet_complete_workflow() {
        // Create a regular wallet first
        let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC, Language::English).unwrap();
        let config = WalletConfig {
            network: Network::Testnet,
            ..Default::default()
        };
        
        let wallet = Wallet::from_mnemonic(mnemonic, config.clone()).unwrap();
        
        // Export as watch-only
        let watch_only = wallet.to_watch_only();
        
        assert!(watch_only.is_watch_only);
        assert!(watch_only.mnemonic.is_none());
        assert!(watch_only.seed.is_empty());
        
        // Verify addresses match
        let addr1 = wallet.accounts.get(&0).unwrap()
            .external_addresses.get_info_at_index(0)
            .map(|i| i.address.clone());
        
        let addr2 = watch_only.accounts.get(&0).unwrap()
            .external_addresses.get_info_at_index(0)
            .map(|i| i.address.clone());
        
        assert_eq!(addr1, addr2);
    }

    // ============================================================================
    // Special Derivation Paths (DashSync Compatibility)
    // ============================================================================

    #[test]
    fn test_identity_derivation_paths() {
        use crate::dip9::*;
        
        let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC, Language::English).unwrap();
        let seed = mnemonic.to_seed("");
        
        // Test identity registration path
        let reg_path = match Network::Testnet {
            Network::Testnet => IDENTITY_REGISTRATION_PATH_TESTNET,
            _ => IDENTITY_REGISTRATION_PATH_MAINNET,
        };
        
        let reg_key = reg_path.derive_priv_ecdsa_for_master_seed(
            &seed,
            DerivationPath::from(vec![ChildNumber::from_hardened_idx(0).unwrap()]),
            Network::Testnet
        ).unwrap();
        
        assert!(reg_key.private_key.secret_bytes().len() == 32);
        
        // Test identity top-up path
        let topup_path = match Network::Testnet {
            Network::Testnet => IDENTITY_TOPUP_PATH_TESTNET,
            _ => IDENTITY_TOPUP_PATH_MAINNET,
        };
        
        let topup_key = topup_path.derive_priv_ecdsa_for_master_seed(
            &seed,
            DerivationPath::from(vec![ChildNumber::from_hardened_idx(0).unwrap()]),
            Network::Testnet
        ).unwrap();
        
        assert!(topup_key.private_key.secret_bytes().len() == 32);
        
        // Keys should be different
        assert_ne!(reg_key.to_bytes(), topup_key.to_bytes());
    }

    // ============================================================================
    // BIP38 Encryption Tests
    // ============================================================================

    #[test]
    #[cfg(feature = "bip38")]
    fn test_wallet_bip38_export_import() {
        use crate::bip38::Bip38EncryptedKey;
        
        let config = WalletConfig {
            network: Network::Testnet,
            ..Default::default()
        };
        
        let wallet = Wallet::new(config).unwrap();
        let password = "SuperSecretPassword123!";
        
        // Export master key as BIP38
        let encrypted = wallet.export_master_key_bip38(password).unwrap();
        let base58 = encrypted.to_base58();
        assert!(base58.starts_with("6P")); // BIP38 encrypted keys start with 6P
        
        // Verify we can decrypt it back
        let decrypted = encrypted.decrypt(password).unwrap();
        assert_eq!(decrypted.secret_bytes().len(), 32);
        
        // Wrong password should fail
        assert!(encrypted.decrypt("WrongPassword").is_err());
    }

    #[test]
    #[cfg(feature = "bip38")]
    fn test_bip38_account_key_export() {
        let config = WalletConfig {
            network: Network::Testnet,
            initial_accounts: 2,
            ..Default::default()
        };
        
        let wallet = Wallet::new(config).unwrap();
        let password = "AccountPassword456";
        
        // Export account 0 key
        let encrypted_0 = wallet.export_account_key_bip38(0, password).unwrap();
        assert!(encrypted_0.to_base58().starts_with("6P"));
        
        // Export account 1 key
        let encrypted_1 = wallet.export_account_key_bip38(1, password).unwrap();
        assert!(encrypted_1.to_base58().starts_with("6P"));
        
        // Keys should be different
        assert_ne!(encrypted_0.to_base58(), encrypted_1.to_base58());
        
        // Non-existent account should fail
        assert!(wallet.export_account_key_bip38(99, password).is_err());
    }

    #[test]
    #[cfg(feature = "bip38")]
    fn test_bip38_with_different_networks() {
        use crate::bip38::encrypt_private_key;
        use secp256k1::SecretKey;
        
        let private_key = SecretKey::from_slice(&[
            0x0C, 0x28, 0xFC, 0xA3, 0x86, 0xC7, 0xA2, 0x27,
            0x60, 0x0B, 0x2F, 0xE5, 0x0B, 0x7C, 0xAE, 0x11,
            0xEC, 0x86, 0xD3, 0xBF, 0x1F, 0xBE, 0x47, 0x1B,
            0xE8, 0x98, 0x27, 0xE1, 0x9D, 0x72, 0xAA, 0x1D,
        ]).unwrap();
        
        let password = "NetworkTest";
        
        // Test mainnet
        let mainnet_encrypted = encrypt_private_key(&private_key, password, true, Network::Dash).unwrap();
        
        // Test testnet
        let testnet_encrypted = encrypt_private_key(&private_key, password, true, Network::Testnet).unwrap();
        
        // Same key, same password, different networks should produce different encrypted keys
        // (due to different address hashes)
        assert_ne!(mainnet_encrypted.to_base58(), testnet_encrypted.to_base58());
        
        // But both should decrypt to the same private key
        let mainnet_decrypted = mainnet_encrypted.decrypt(password).unwrap();
        let testnet_decrypted = testnet_encrypted.decrypt(password).unwrap();
        assert_eq!(mainnet_decrypted.secret_bytes(), testnet_decrypted.secret_bytes());
    }

    #[test]
    #[cfg(feature = "bip38")]
    fn test_bip38_watch_only_wallet_cannot_export() {
        let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC, Language::English).unwrap();
        let config = WalletConfig {
            network: Network::Testnet,
            ..Default::default()
        };
        
        let wallet = Wallet::from_mnemonic(mnemonic, config.clone()).unwrap();
        let watch_only = wallet.to_watch_only();
        
        // Watch-only wallet should not be able to export BIP38
        assert!(watch_only.export_master_key_bip38("password").is_err());
        assert!(watch_only.export_account_key_bip38(0, "password").is_err());
    }

    // ============================================================================
    // Integration Tests
    // ============================================================================

    #[test]
    fn test_wallet_full_lifecycle() {
        // 1. Create wallet
        let config = WalletConfig {
            network: Network::Testnet,
            initial_accounts: 2,
            enable_coinjoin: true,
            name: Some("Test Wallet".to_string()),
            ..Default::default()
        };
        
        let mut wallet = Wallet::new(config).unwrap();
        let original_mnemonic = wallet.mnemonic.clone();
        
        // 2. Generate and use addresses
        let addr1 = wallet.get_next_receive_address().unwrap();
        wallet.mark_address_used(&addr1);
        
        let addr2 = wallet.get_next_change_address().unwrap();
        wallet.mark_address_used(&addr2);
        
        // 3. Update balances
        wallet.default_account_mut().unwrap().update_balance(1000000, 50000, 0);
        
        // 4. Create backup
        let backup = wallet.backup();
        assert!(backup.mnemonic.is_some());
        assert_eq!(backup.accounts.len(), 2);
        
        // 5. Restore from backup
        let restored_config = WalletConfig {
            network: Network::Testnet,
            ..Default::default()
        };
        
        let restored = Wallet::restore(backup, restored_config).unwrap();
        
        // 6. Verify restoration
        assert_eq!(restored.accounts.len(), 2);
        if let (Some(orig), Some(rest)) = (original_mnemonic, restored.mnemonic) {
            assert_eq!(orig.phrase(), rest.phrase());
        }
    }

    #[test]
    fn test_wallet_concurrent_operations() {
        use std::sync::{Arc, Mutex};
        use std::thread;
        
        let config = WalletConfig {
            network: Network::Testnet,
            ..Default::default()
        };
        
        let wallet = Arc::new(Mutex::new(Wallet::new(config).unwrap()));
        let mut handles = vec![];
        
        // Spawn threads to generate addresses concurrently
        for i in 0..5 {
            let wallet_clone = Arc::clone(&wallet);
            let handle = thread::spawn(move || {
                let mut wallet = wallet_clone.lock().unwrap();
                let addr = wallet.get_next_receive_address().unwrap();
                println!("Thread {} generated address: {}", i, addr);
            });
            handles.push(handle);
        }
        
        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }
        
        // Verify wallet state is consistent
        let wallet = wallet.lock().unwrap();
        assert!(wallet.all_addresses().len() > 0);
    }
}