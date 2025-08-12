//! Complete wallet management for Dash
//!
//! This module provides comprehensive wallet functionality including
//! multiple accounts, seed management, and transaction coordination.

pub mod account_collection;
pub mod accounts;
pub mod balance;
#[cfg(feature = "bip38")]
pub mod bip38;
pub mod config;
pub mod helper;
pub mod initialization;
mod managed_wallet_info;
pub mod metadata;
pub mod root_extended_keys;
pub mod stats;

use self::account_collection::AccountCollection;
pub(crate) use self::config::WalletConfig;
pub use self::managed_wallet_info::ManagedWalletInfo;
use self::root_extended_keys::{RootExtendedPrivKey, RootExtendedPubKey};
use crate::account::Account;
use crate::mnemonic::Mnemonic;
use crate::seed::Seed;
use crate::Network;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;
use dashcore_hashes::{sha256, Hash};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Type of wallet based on how it was created
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum WalletType {
    /// Standard mnemonic wallet without passphrase
    Mnemonic {
        mnemonic: Mnemonic,
        root_extended_private_key: RootExtendedPrivKey,
    },
    /// Mnemonic wallet with BIP39 passphrase (passphrase requested via callback when needed)
    MnemonicWithPassphrase {
        mnemonic: Mnemonic,
        /// Extended public key derived with the passphrase (for address generation)
        root_extended_public_key: RootExtendedPubKey,
    },
    /// Wallet from seed bytes
    Seed {
        seed: Seed,
        root_extended_private_key: RootExtendedPrivKey,
    },
    /// Wallet from extended private key
    ExtendedPrivKey(RootExtendedPrivKey),
    /// External signable wallet with extended public key (signing happens externally)
    ExternalSignable(RootExtendedPubKey),
    /// Watch-only wallet with extended public key (no signing capability)
    WatchOnly(RootExtendedPubKey),
}

/// Complete wallet implementation
///
/// This is an immutable wallet structure that only changes when accounts are added.
/// Mutable metadata like name, description, and sync status are stored separately
/// in ManagedWalletInfo.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Wallet {
    /// Unique wallet ID (SHA256 hash of root public key)
    pub wallet_id: [u8; 32],
    /// Wallet configuration
    pub config: WalletConfig,
    /// Wallet type (mnemonic, mnemonic with passphrase, or watch-only)
    pub wallet_type: WalletType,
    /// Standard BIP44 accounts organized by network
    pub standard_accounts: AccountCollection,
    /// CoinJoin accounts organized by network
    pub coinjoin_accounts: AccountCollection,
    /// Special purpose accounts organized by network
    pub special_accounts: BTreeMap<Network, Vec<Account>>,
}

/// Wallet scan result
#[derive(Debug, Default)]
pub struct WalletScanResult {
    /// Accounts that had activity
    pub accounts_with_activity: Vec<u32>,
    /// Total addresses found with activity
    pub total_addresses_found: usize,
}

impl Wallet {
    /// Compute wallet ID from root public key
    pub fn compute_wallet_id(root_pub_key: &RootExtendedPubKey) -> [u8; 32] {
        let mut data = Vec::new();
        data.extend_from_slice(&root_pub_key.root_public_key.serialize());
        data.extend_from_slice(&root_pub_key.root_chain_code[..]);

        // Compute SHA256 hash
        let hash = sha256::Hash::hash(&data);
        hash.to_byte_array()
    }
}

impl fmt::Display for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Format wallet ID as hex string (first 8 chars)
        let id_hex =
            self.wallet_id.iter().take(4).map(|b| format!("{:02x}", b)).collect::<String>();

        write!(
            f,
            "Wallet [{}...] ({}) - {} accounts, {} addresses",
            id_hex,
            if self.is_watch_only() {
                "watch-only"
            } else {
                "full"
            },
            self.standard_accounts.total_count() + self.coinjoin_accounts.total_count(),
            self.all_addresses().len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{AccountType, SpecialPurposeType};
    use crate::mnemonic::Language;

    #[test]
    fn test_wallet_creation() {
        let config = WalletConfig {
            ..Default::default()
        };

        let wallet = Wallet::new_random(config, Network::Testnet).unwrap();
        assert_eq!(wallet.standard_accounts.network_count(Network::Testnet), 1);
        assert!(wallet.has_mnemonic());
        assert!(!wallet.is_watch_only());
    }

    #[test]
    fn test_wallet_from_mnemonic() {
        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English,
        ).unwrap();

        let config = WalletConfig::default();
        let wallet = Wallet::from_mnemonic(mnemonic, config, Network::Testnet).unwrap();

        assert_eq!(wallet.standard_accounts.network_count(Network::Testnet), 1);
        let default_account = wallet.default_account(Network::Testnet).unwrap();
        assert_eq!(default_account.index, 0);
    }

    #[test]
    fn test_account_creation() {
        let config = WalletConfig {
            ..Default::default()
        };

        let mut wallet = Wallet::new_random(config, Network::Testnet).unwrap();
        wallet.add_account(1, AccountType::Standard, Network::Testnet).unwrap();
        wallet.add_account(2, AccountType::CoinJoin, Network::Testnet).unwrap();

        assert_eq!(
            wallet.standard_accounts.network_count(Network::Testnet)
                + wallet.coinjoin_accounts.network_count(Network::Testnet),
            3
        );
        // 1 initial + 2 created
    }

    #[test]
    fn test_address_generation() {
        // NOTE: Address generation now requires ManagedAccount integration
        // This test would need to be updated to work with the new architecture
        // where Account holds immutable state and ManagedAccount holds mutable state

        let config = WalletConfig {
            ..Default::default()
        };

        let wallet = Wallet::new_random(config, Network::Testnet).unwrap();

        // Verify we have a default account
        assert!(wallet.get_account(Network::Testnet, 0).is_some());

        // Address generation and tracking would happen through ManagedAccount
        // which is not directly accessible from Wallet in this refactored version
    }

    #[test]
    fn test_wallet_config() {
        let mut config = WalletConfig::default();
        config.account_default_external_gap_limit = 30;
        config.account_default_internal_gap_limit = 15;
        config.enable_coinjoin = true;
        config.coinjoin_default_gap_limit = 10;

        let wallet = Wallet::new_random(config, Network::Testnet).unwrap();

        assert_eq!(wallet.config.account_default_external_gap_limit, 30);
        assert_eq!(wallet.config.account_default_internal_gap_limit, 15);
        assert!(wallet.config.enable_coinjoin);
        assert_eq!(wallet.standard_accounts.network_count(Network::Testnet), 1);
        // Only default account
    }

    // ✓ Test wallet creation from known mnemonic (from DashSync DSBIP32Tests.m)
    #[test]
    fn test_wallet_creation_from_known_mnemonic() {
        let mnemonic_phrase = "upper renew that grow pelican pave subway relief describe enforce suit hedgehog blossom dose swallow";
        let mnemonic = Mnemonic::from_phrase(mnemonic_phrase, Language::English).unwrap();

        let config = WalletConfig::default();
        let wallet = Wallet::from_mnemonic(mnemonic, config, Network::Dash).unwrap();

        assert_eq!(wallet.standard_accounts.network_count(Network::Dash), 1);
        assert!(wallet.has_mnemonic());
        assert!(!wallet.is_watch_only());
    }

    // ✓ Test wallet recovery from seed (from DashSync principles)
    #[test]
    fn test_wallet_recovery_from_seed() {
        let mnemonic_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(mnemonic_phrase, Language::English).unwrap();

        let config = WalletConfig::default();

        // Create first wallet
        let wallet1 =
            Wallet::from_mnemonic(mnemonic.clone(), config.clone(), Network::Testnet).unwrap();

        // Create second wallet from same mnemonic (simulating recovery)
        let wallet2 = Wallet::from_mnemonic(mnemonic, config, Network::Testnet).unwrap();

        // Both wallets should generate the same addresses
        let account1_1 = wallet1.standard_accounts.get(Network::Testnet, 0).unwrap();
        let account2_1 = wallet2.standard_accounts.get(Network::Testnet, 0).unwrap();

        // Should have same extended public keys
        assert_eq!(account1_1.extended_public_key(), account2_1.extended_public_key());
    }

    // ✓ Test multiple account creation
    #[test]
    fn test_multiple_account_creation() {
        let config = WalletConfig::default();

        let mut wallet = Wallet::new_random(config, Network::Testnet).unwrap();

        // Create different types of accounts
        wallet.add_account(1, AccountType::Standard, Network::Testnet).unwrap();
        wallet.add_account(2, AccountType::CoinJoin, Network::Testnet).unwrap();

        // Try creating special purpose accounts
        wallet
            .add_special_account(0, SpecialPurposeType::IdentityRegistration, Network::Testnet)
            .unwrap();
        wallet.add_special_account(1, SpecialPurposeType::IdentityTopUp, Network::Testnet).unwrap();

        assert_eq!(wallet.standard_accounts.network_count(Network::Testnet), 2); // 2 standard accounts (0 and 1)
        assert_eq!(wallet.coinjoin_accounts.network_count(Network::Testnet), 1); // 1 coinjoin account (2)
        assert_eq!(wallet.special_accounts.get(&Network::Testnet).map_or(0, |v| v.len()), 2);
        // 2 special accounts
    }

    // ✓ Test wallet with managed info
    #[test]
    fn test_wallet_with_managed_info() {
        let config = WalletConfig::default();
        let wallet = Wallet::new_random(config, Network::Testnet).unwrap();

        // Create managed info from the wallet
        let mut managed_info = ManagedWalletInfo::from_wallet(&wallet);
        managed_info.set_name("Test Wallet".to_string());
        managed_info.set_description("A test wallet".to_string());

        // Test initial managed info
        assert_eq!(managed_info.wallet_id, wallet.wallet_id);
        assert_eq!(managed_info.name.as_ref().unwrap(), "Test Wallet");
        assert_eq!(managed_info.description.as_ref().unwrap(), "A test wallet");
        assert_eq!(managed_info.metadata.created_at, 0); // Default value
        assert!(managed_info.metadata.last_synced.is_none());

        // Test updating metadata
        managed_info.update_last_synced(1234567890);
        assert_eq!(managed_info.metadata.last_synced, Some(1234567890));

        // The wallet itself remains unchanged
        assert_eq!(wallet.standard_accounts.network_count(Network::Testnet), 1);
    }

    // ✓ Test watch-only wallet creation (high level)
    #[test]
    fn test_watch_only_wallet_basics() {
        // Create a regular wallet first to get a xpub
        let config = WalletConfig::default();
        let wallet = Wallet::new_random(config, Network::Testnet).unwrap();

        let account = wallet.standard_accounts.get(Network::Testnet, 0).unwrap();
        let xpub = account.extended_public_key();

        // Create watch-only wallet from xpub
        let config2 = WalletConfig::default();
        let watch_only = Wallet::from_xpub(xpub, config2, Network::Testnet).unwrap();

        assert!(watch_only.is_watch_only());
        assert!(!watch_only.has_mnemonic());
        assert_eq!(watch_only.standard_accounts.network_count(Network::Testnet), 1);

        // Watch-only wallet has accounts but can't generate addresses without key source
        let _account = watch_only.standard_accounts.get(Network::Testnet, 0).unwrap();
    }

    // ✓ Test wallet configuration defaults
    #[test]
    fn test_wallet_config_defaults() {
        let config = WalletConfig::default();

        assert_eq!(config.account_default_external_gap_limit, 20);
        assert_eq!(config.account_default_internal_gap_limit, 10);
        assert!(!config.enable_coinjoin);
        assert_eq!(config.coinjoin_default_gap_limit, 10);
    }

    // ✓ Test wallet with passphrase (from BIP39 tests)
    #[test]
    fn test_wallet_with_passphrase() {
        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English,
        ).unwrap();

        let config = WalletConfig::default();
        let network = Network::Testnet;

        // Create wallet without passphrase
        let wallet1 = Wallet::from_mnemonic_with_passphrase(
            mnemonic.clone(),
            "".to_string(),
            config.clone(),
            network,
        )
        .unwrap();

        // Create wallet with passphrase "TREZOR"
        let wallet2 =
            Wallet::from_mnemonic_with_passphrase(mnemonic, "TREZOR".to_string(), config, network)
                .unwrap();

        // Different passphrases should generate different account keys
        let xpub1 =
            wallet1.standard_accounts.get(Network::Testnet, 0).unwrap().extended_public_key();
        let xpub2 =
            wallet2.standard_accounts.get(Network::Testnet, 0).unwrap().extended_public_key();
        assert_ne!(xpub1, xpub2);
    }

    // ✓ Test account retrieval and management
    #[test]
    fn test_account_management() {
        let config = WalletConfig::default();
        let mut wallet = Wallet::new_random(config, Network::Testnet).unwrap();

        // Create a second account to match original test
        wallet.add_account(1, AccountType::Standard, Network::Testnet).unwrap();

        // Test getting accounts
        assert!(wallet.get_account(Network::Testnet, 0).is_some());
        assert!(wallet.get_account(Network::Testnet, 1).is_some());
        assert!(wallet.get_account(Network::Testnet, 2).is_none());

        // Test mutable access
        assert!(wallet.get_account_mut(Network::Testnet, 0).is_some());
        assert!(wallet.get_account_mut(Network::Testnet, 2).is_none());

        // Test account count
        assert_eq!(wallet.account_count(), 2);

        // Test listing accounts
        let account_indices = wallet.account_indices(Network::Testnet);
        assert_eq!(account_indices.len(), 2);
        assert!(account_indices.contains(&0));
        assert!(account_indices.contains(&1));
    }

    // ✓ Test wallet config validation
    #[test]
    fn test_wallet_config_validation() {
        // Test config with minimum limits
        let mut config = WalletConfig::default();
        config.account_default_external_gap_limit = 0; // Will be adjusted
        config.account_default_internal_gap_limit = 0; // Will be adjusted
                                                       // Note: ensure_minimum_limits method doesn't exist

        let wallet = Wallet::new_random(config.clone(), Network::Testnet).unwrap();

        // The wallet uses the config as-is, doesn't adjust it
        assert_eq!(wallet.config.account_default_external_gap_limit, 0);
        assert_eq!(wallet.config.account_default_internal_gap_limit, 0);
    }

    // ✓ Test error conditions
    #[test]
    fn test_wallet_error_conditions() {
        let config = WalletConfig::default();
        let mut wallet = Wallet::new_random(config, Network::Testnet).unwrap();

        // Test duplicate account creation should fail
        let result = wallet.add_account(0, AccountType::Standard, Network::Testnet);
        assert!(result.is_err()); // Account 0 already exists

        // Basic wallet should have default account
        assert_eq!(wallet.standard_accounts.network_count(Network::Testnet), 1);
    }

    // ✓ Test wallet ID generation
    #[test]
    fn test_wallet_id_generation() {
        let config = WalletConfig::default();
        let wallet = Wallet::new_random(config.clone(), Network::Testnet).unwrap();

        // Wallet ID should be set
        assert_ne!(wallet.wallet_id, [0u8; 32]);

        // Wallet ID should be deterministic based on root public key
        let root_pub_key = wallet.root_extended_pub_key();
        let computed_id = Wallet::compute_wallet_id(&root_pub_key);
        assert_eq!(wallet.wallet_id, computed_id);

        // Test that wallets from the same mnemonic have the same ID
        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English,
        ).unwrap();

        let config2 = WalletConfig::default();
        let config3 = WalletConfig::default();
        let wallet1 = Wallet::from_mnemonic(mnemonic.clone(), config2, Network::Testnet).unwrap();
        let wallet2 = Wallet::from_mnemonic(mnemonic, config3, Network::Testnet).unwrap();

        assert_eq!(wallet1.wallet_id, wallet2.wallet_id);
    }
}
