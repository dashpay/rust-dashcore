//! Complete wallet management for Dash
//!
//! This module provides comprehensive wallet functionality including
//! multiple accounts, seed management, and transaction coordination.

pub mod accounts;
pub mod backup;
pub mod balance;
#[cfg(feature = "bip38")]
pub mod bip38;
pub mod helper;
pub mod initialization;
pub mod managed_wallet_info;
pub mod metadata;
pub mod root_extended_keys;
pub mod stats;

pub use self::balance::WalletCoreBalance;
pub use self::managed_wallet_info::ManagedWalletInfo;
use self::root_extended_keys::{RootExtendedPrivKey, RootExtendedPubKey};
use crate::account::account_collection::AccountCollection;
use crate::mnemonic::Mnemonic;
use crate::seed::Seed;
use crate::Network;
use alloc::vec::Vec;
#[cfg(feature = "bincode")]
use bincode_derive::{Decode, Encode};
use core::fmt;
use dashcore_hashes::{sha256, Hash};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Type of wallet based on how it was created
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
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
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct Wallet {
    /// Network this wallet is associated with
    pub network: Network,
    /// Unique wallet ID (SHA256 hash of root public key)
    pub wallet_id: [u8; 32],
    /// Wallet type (mnemonic, mnemonic with passphrase, or watch-only)
    pub wallet_type: WalletType,
    /// All accounts organized by network
    pub accounts: AccountCollection,
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
    pub fn compute_wallet_id_from_root_extended_pub_key(
        root_pub_key: &RootExtendedPubKey,
    ) -> [u8; 32] {
        let mut data = Vec::new();
        data.extend_from_slice(&root_pub_key.root_public_key.serialize());
        data.extend_from_slice(&root_pub_key.root_chain_code[..]);

        // Compute SHA256 hash
        let hash = sha256::Hash::hash(&data);
        hash.to_byte_array()
    }

    /// Compute wallet ID
    pub fn compute_wallet_id(&self) -> [u8; 32] {
        Self::compute_wallet_id_from_root_extended_pub_key(&self.root_extended_pub_key_cow())
    }
}

impl fmt::Display for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Format wallet ID as hex string (first 8 chars)
        let id_hex =
            self.wallet_id.iter().take(4).map(|b| format!("{:02x}", b)).collect::<String>();

        let total_accounts: usize = self.accounts.count();

        write!(
            f,
            "Wallet [{}...] ({}) - {} accounts",
            id_hex,
            if self.is_watch_only() {
                "watch-only"
            } else {
                "full"
            },
            total_accounts,
        )
    }
}

// Manual implementation of Zeroize for Wallet
impl Zeroize for Wallet {
    fn zeroize(&mut self) {
        // Zeroize the wallet ID
        self.wallet_id.zeroize();

        // Zeroize the wallet type - handle each variant's sensitive data
        match &mut self.wallet_type {
            WalletType::Mnemonic {
                mnemonic,
                root_extended_private_key,
            } => {
                // Zeroize the mnemonic (now possible since it implements Zeroize)
                mnemonic.zeroize();
                // We can't zeroize SecretKey directly, but we can zeroize the chain code
                root_extended_private_key.zeroize();
                // Note: root_extended_private_key.root_private_key (SecretKey) doesn't implement Zeroize
            }
            WalletType::MnemonicWithPassphrase {
                mnemonic,
                root_extended_public_key,
            } => {
                // Zeroize the mnemonic
                mnemonic.zeroize();
                // Zeroize the public key structure (best effort)
                root_extended_public_key.zeroize();
            }
            WalletType::Seed {
                seed,
                root_extended_private_key,
            } => {
                // We can't zeroize Seed directly as it doesn't implement Zeroize yet
                // But we can zeroize the RootExtendedPrivKey
                root_extended_private_key.zeroize();
                seed.zeroize();
            }
            WalletType::ExtendedPrivKey(root_extended_private_key) => {
                // Zeroize the chain code
                root_extended_private_key.zeroize();
                // Note: root_private_key (SecretKey) doesn't implement Zeroize
            }
            WalletType::ExternalSignable(root_extended_public_key)
            | WalletType::WatchOnly(root_extended_public_key) => {
                // Public keys are not sensitive, but zeroize for consistency
                root_extended_public_key.zeroize();
            }
        }

        // Clear the accounts map, only public keys here so no need to go hardcore on zeroization
        self.accounts.clear();
    }
}

#[cfg(test)]
mod passphrase_test;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::account_collection::AccountCollection;
    use crate::account::{AccountType, StandardAccountType};
    use crate::mnemonic::Language;
    use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;

    #[test]
    fn test_wallet_creation() {
        let wallet = Wallet::new_random(
            Network::Testnet,
            initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();
        // Default creates BIP44 account 0, CoinJoin account 0, and special accounts
        assert!(wallet.accounts.count() >= 2);
        assert!(wallet.has_mnemonic());
        assert!(!wallet.is_watch_only());
    }

    #[test]
    fn test_wallet_from_mnemonic() {
        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English,
        ).unwrap();

        let wallet = Wallet::from_mnemonic(
            mnemonic,
            Network::Testnet,
            initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();

        // Default creates multiple accounts
        assert!(wallet.accounts.count() >= 2);
        let default_account = wallet.get_bip44_account(0).unwrap();
        match &default_account.account_type {
            AccountType::Standard {
                index,
                ..
            } => assert_eq!(*index, 0),
            _ => panic!("Expected standard account"),
        }
    }

    #[test]
    fn test_account_creation() {
        use std::collections::BTreeSet;

        // Create wallet with only BIP44 account 0
        let mut bip44_set = BTreeSet::new();
        bip44_set.insert(0);
        let mut wallet = Wallet::new_random(
            Network::Testnet,
            initialization::WalletAccountCreationOptions::BIP44AccountsOnly(bip44_set),
        )
        .unwrap();

        wallet
            .add_account(
                AccountType::Standard {
                    index: 1,
                    standard_account_type: StandardAccountType::BIP44Account,
                },
                None,
            )
            .unwrap();
        wallet
            .add_account(
                AccountType::CoinJoin {
                    index: 2,
                },
                None,
            )
            .unwrap();

        assert_eq!(wallet.accounts.count(), 3);
        // 1 initial + 2 created
    }

    #[test]
    fn test_address_generation() {
        // NOTE: Address generation now requires ManagedAccount integration
        // This test would need to be updated to work with the new architecture
        // where Account holds immutable state and ManagedAccount holds mutable state

        let wallet = Wallet::new_random(
            Network::Testnet,
            initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();

        // Verify we have a default account
        assert!(wallet.get_bip44_account(0).is_some());

        // Address generation and tracking would happen through ManagedAccount
        // which is not directly accessible from Wallet in this refactored version
    }

    // ✓ Test wallet creation from known mnemonic
    #[test]
    fn test_wallet_creation_from_known_mnemonic() {
        let mnemonic_phrase = "upper renew that grow pelican pave subway relief describe enforce suit hedgehog blossom dose swallow";
        let mnemonic = Mnemonic::from_phrase(mnemonic_phrase, Language::English).unwrap();

        let wallet = Wallet::from_mnemonic(
            mnemonic,
            Network::Dash,
            initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();

        assert!(wallet.accounts.count() >= 2); // Default creates multiple accounts
        assert!(wallet.has_mnemonic());
        assert!(!wallet.is_watch_only());
    }

    // ✓ Test wallet recovery from seed (from DashSync principles)
    #[test]
    fn test_wallet_recovery_from_seed() {
        let mnemonic_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(mnemonic_phrase, Language::English).unwrap();

        // Create first wallet
        let wallet1 = Wallet::from_mnemonic(
            mnemonic.clone(),
            Network::Testnet,
            initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();

        // Create second wallet from same mnemonic (simulating recovery)
        let wallet2 = Wallet::from_mnemonic(
            mnemonic,
            Network::Testnet,
            initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();

        // Both wallets should generate the same addresses
        let account1_1 = wallet1.accounts.standard_bip44_accounts.get(&0).unwrap();
        let account2_1 = wallet2.accounts.standard_bip44_accounts.get(&0).unwrap();

        // Should have same extended public keys
        assert_eq!(account1_1.extended_public_key(), account2_1.extended_public_key());
    }

    // ✓ Test multiple account creation
    #[test]
    fn test_multiple_account_creation() {
        let mut wallet = Wallet::new_random(
            Network::Testnet,
            initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();

        // Create different types of accounts
        wallet
            .add_account(
                AccountType::Standard {
                    index: 1,
                    standard_account_type: StandardAccountType::BIP44Account,
                },
                None,
            )
            .unwrap();
        wallet
            .add_account(
                AccountType::CoinJoin {
                    index: 2,
                },
                None,
            )
            .unwrap();

        // Default already creates IdentityRegistration, just add TopUp
        wallet
            .add_account(
                AccountType::IdentityTopUp {
                    registration_index: 0,
                },
                None,
            )
            .unwrap();

        assert_eq!(wallet.accounts.standard_bip44_accounts.len(), 2); // 2 standard accounts (0 and 1)
        assert_eq!(wallet.accounts.coinjoin_accounts.len(), 2); // 2 coinjoin accounts (0 from Default and 2)
        assert!(wallet.accounts.identity_registration.is_some());
        assert!(wallet.accounts.identity_topup.contains_key(&0));
        // 2 special accounts
    }

    // ✓ Test wallet with managed info
    #[test]
    fn test_wallet_with_managed_info() {
        let wallet = Wallet::new_random(
            Network::Testnet,
            initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();

        // Create managed info from the wallet
        let mut managed_info = ManagedWalletInfo::from_wallet(&wallet);
        managed_info.set_name("Test Wallet".to_string());
        managed_info.set_description(Some("A test wallet".to_string()));

        // Test initial managed info
        assert_eq!(managed_info.wallet_id, wallet.wallet_id);
        assert_eq!(managed_info.name.as_ref().unwrap(), "Test Wallet");
        assert_eq!(managed_info.description.as_ref().unwrap(), "A test wallet");
        assert_eq!(managed_info.metadata.first_loaded_at, 0); // Default value
        assert!(managed_info.metadata.last_synced.is_none());

        // Test updating metadata
        managed_info.update_last_synced(1234567890);
        assert_eq!(managed_info.metadata.last_synced, Some(1234567890));

        // The wallet itself remains unchanged
        assert!(wallet.accounts.count() >= 2);
        // Default creates multiple accounts
    }

    // ✓ Test watch-only wallet creation (high level)
    #[test]
    fn test_watch_only_wallet_basics() {
        // Create a regular wallet first to get the root xpub

        let wallet = Wallet::new_random(
            Network::Testnet,
            initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();

        // Get the root extended public key
        let root_xpub = wallet.root_extended_pub_key();
        let root_xpub_as_extended = root_xpub.to_extended_pub_key(Network::Testnet);

        // Create watch-only wallet from root xpub
        let mut watch_only =
            Wallet::from_xpub(root_xpub_as_extended, AccountCollection::new(), false).unwrap();

        assert!(watch_only.is_watch_only());
        assert!(!watch_only.has_mnemonic());

        // Watch-only wallets start with no accounts
        assert_eq!(watch_only.accounts.count(), 0);

        // But we can add accounts manually by providing their xpubs
        let account = wallet.get_bip44_account(0).unwrap();
        let account_xpub = account.extended_public_key();

        watch_only
            .add_account(
                AccountType::Standard {
                    index: 0,
                    standard_account_type: StandardAccountType::BIP44Account,
                },
                Some(account_xpub),
            )
            .unwrap();

        // Now the watch-only wallet has the account
        assert_eq!(watch_only.accounts.count(), 1);
        let watch_only_account = watch_only.get_bip44_account(0).unwrap();
        assert_eq!(watch_only_account.extended_public_key(), account_xpub);
    }

    // ✓ Test wallet with passphrase (from BIP39 tests)
    #[test]
    fn test_wallet_with_passphrase() {
        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English,
        ).unwrap();

        let network = Network::Testnet;

        // Create wallet without passphrase - use regular from_mnemonic for empty passphrase
        let wallet1 = Wallet::from_mnemonic(
            mnemonic.clone(),
            network,
            initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();

        // Create wallet with passphrase "TREZOR"
        let wallet2 = Wallet::from_mnemonic_with_passphrase(
            mnemonic,
            "TREZOR".to_string(),
            network,
            initialization::WalletAccountCreationOptions::None,
        )
        .unwrap();

        // Different passphrases should generate different root keys
        let root_xpub1 = wallet1.root_extended_pub_key();
        let root_xpub2 = wallet2.root_extended_pub_key();
        assert_ne!(root_xpub1.root_public_key, root_xpub2.root_public_key);
    }

    // ✓ Test account retrieval and management
    #[test]
    fn test_account_management() {
        let mut wallet = Wallet::new_random(
            Network::Testnet,
            initialization::WalletAccountCreationOptions::BIP44AccountsOnly([0].into()),
        )
        .unwrap();

        // Create a second account to match original test
        wallet
            .add_account(
                AccountType::Standard {
                    index: 1,
                    standard_account_type: StandardAccountType::BIP44Account,
                },
                None,
            )
            .unwrap();

        // Test getting accounts
        assert!(wallet.get_bip44_account(0).is_some());
        assert!(wallet.get_bip44_account(1).is_some());
        assert!(wallet.get_bip44_account(2).is_none());

        // Test mutable access
        assert!(wallet.get_bip44_account_mut(0).is_some());
        assert!(wallet.get_bip44_account_mut(2).is_none());

        // Test account count
        assert_eq!(wallet.account_count(), 2);

        // Test listing accounts
        let account_indices = wallet.account_indices();
        assert_eq!(account_indices.len(), 2);
        assert!(account_indices.contains(&0));
        assert!(account_indices.contains(&1));
    }

    // ✓ Test error conditions
    #[test]
    fn test_wallet_error_conditions() {
        let mut wallet = Wallet::new_random(
            Network::Testnet,
            initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();

        // Test duplicate account creation should fail
        let result = wallet.add_account(
            AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            None,
        );
        assert!(result.is_err()); // Account 0 already exists

        // Default creates multiple accounts
        assert!(wallet.accounts.count() >= 2);
    }

    // ✓ Test wallet ID generation
    #[test]
    fn test_wallet_id_generation() {
        let wallet = Wallet::new_random(
            Network::Testnet,
            initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();

        // Wallet ID should be set
        assert_ne!(wallet.wallet_id, [0u8; 32]);

        // Wallet ID should be deterministic based on root public key
        let computed_id = wallet.compute_wallet_id();
        assert_eq!(wallet.wallet_id, computed_id);

        // Test that wallets from the same mnemonic have the same ID
        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English,
        ).unwrap();

        let wallet1 = Wallet::from_mnemonic(
            mnemonic.clone(),
            Network::Testnet,
            initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();
        let wallet2 = Wallet::from_mnemonic(
            mnemonic,
            Network::Testnet,
            initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();

        assert_eq!(wallet1.wallet_id, wallet2.wallet_id);
    }
}
