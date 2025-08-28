//! Managed account creation methods for ManagedWalletInfo
//!
//! This module contains the implementation of ManagedAccountOperations trait for ManagedWalletInfo.

use super::{managed_account_operations::ManagedAccountOperations, ManagedWalletInfo};
#[cfg(feature = "bls")]
use crate::account::BLSAccount;
#[cfg(feature = "eddsa")]
use crate::account::EdDSAAccount;
use crate::account::{Account, AccountType, ManagedAccount};
use crate::bip32::ExtendedPubKey;
use crate::error::{Error, Result};
use crate::wallet::{Wallet, WalletType};
use crate::Network;

impl ManagedAccountOperations for ManagedWalletInfo {
    /// Add a new managed account from an existing wallet account
    ///
    /// This creates a ManagedAccount wrapper around an existing Account in the wallet.
    ///
    /// # Arguments
    /// * `wallet` - The wallet containing the account
    /// * `account_type` - The type of account to manage
    /// * `network` - The network for the account
    ///
    /// # Returns
    /// Ok(()) if the managed account was successfully added
    fn add_managed_account(
        &mut self,
        wallet: &Wallet,
        account_type: AccountType,
        network: Network,
    ) -> Result<()> {
        // First check if the account exists in the wallet
        let account_collection = wallet.accounts.get(&network).ok_or_else(|| {
            Error::InvalidParameter(format!("No accounts for network {:?} in wallet", network))
        })?;

        let account = account_collection.account_of_type(account_type).ok_or_else(|| {
            Error::InvalidParameter(format!(
                "Account type {:?} not found for network {:?}",
                account_type, network
            ))
        })?;

        // Create the ManagedAccount from the Account
        let managed_account = ManagedAccount::from_account(account);

        // Get or create the managed account collection for this network
        let managed_collection = self.accounts.entry(network).or_default();

        // Check if managed account already exists
        if managed_collection.contains_managed_account_type(managed_account.managed_type()) {
            return Err(Error::InvalidParameter(format!(
                "Managed account type {:?} already exists for network {:?}",
                account_type, network
            )));
        }

        // Insert into the collection
        managed_collection.insert(managed_account);
        Ok(())
    }

    /// Add a new managed account with passphrase verification
    ///
    /// This function verifies the passphrase and creates a ManagedAccount.
    /// It only works with wallets created with a passphrase.
    ///
    /// # Arguments
    /// * `wallet` - The wallet containing the account (must be MnemonicWithPassphrase type)
    /// * `account_type` - The type of account to manage
    /// * `network` - The network for the account
    /// * `passphrase` - The passphrase to verify
    ///
    /// # Returns
    /// Ok(()) if the managed account was successfully added
    fn add_managed_account_with_passphrase(
        &mut self,
        wallet: &Wallet,
        account_type: AccountType,
        network: Network,
        passphrase: &str,
    ) -> Result<()> {
        // Verify this is a passphrase wallet
        match &wallet.wallet_type {
            WalletType::MnemonicWithPassphrase { mnemonic, .. } => {
                // Verify the passphrase by deriving and comparing
                let seed = mnemonic.to_seed(passphrase);
                let root_key = crate::wallet::root_extended_keys::RootExtendedPrivKey::new_master(&seed)?;

                // Compare with wallet's stored public key
                let derived_pub = root_key.to_root_extended_pub_key();
                let wallet_pub = wallet.root_extended_pub_key();

                if derived_pub.root_public_key != wallet_pub.root_public_key {
                    return Err(Error::InvalidParameter(
                        "Invalid passphrase".to_string()
                    ));
                }

                // Passphrase is valid, proceed with adding the managed account
                self.add_managed_account(wallet, account_type, network)
            }
            _ => Err(Error::InvalidParameter(
                "add_managed_account_with_passphrase can only be used with wallets created with a passphrase".to_string()
            )),
        }
    }

    fn add_managed_account_from_xpub(
        &mut self,
        account_type: AccountType,
        network: Network,
        account_xpub: ExtendedPubKey,
    ) -> Result<()> {
        // Create an Account with no wallet ID (standalone managed account)
        let account = Account::new(None, account_type, account_xpub, network)?;

        // Create the ManagedAccount from the Account
        let managed_account = ManagedAccount::from_account(&account);

        // Get or create the managed account collection for this network
        let managed_collection = self.accounts.entry(network).or_default();

        // Check if managed account already exists
        if managed_collection.contains_managed_account_type(managed_account.managed_type()) {
            return Err(Error::InvalidParameter(format!(
                "Managed account type {:?} already exists for network {:?}",
                account_type, network
            )));
        }

        // Insert into the collection
        managed_collection.insert(managed_account);
        Ok(())
    }

    #[cfg(feature = "bls")]
    fn add_managed_bls_account(
        &mut self,
        wallet: &Wallet,
        account_type: AccountType,
        network: Network,
    ) -> Result<()> {
        // Validate account type
        if !matches!(account_type, AccountType::ProviderOperatorKeys) {
            return Err(Error::InvalidParameter(
                "BLS accounts can only be ProviderOperatorKeys".to_string(),
            ));
        }

        // First check if the BLS account exists in the wallet
        let account_collection = wallet.accounts.get(&network).ok_or_else(|| {
            Error::InvalidParameter(format!("No accounts for network {:?} in wallet", network))
        })?;

        let bls_account =
            account_collection.bls_account_of_type(account_type).ok_or_else(|| {
                Error::InvalidParameter(format!(
                    "BLS account type {:?} not found for network {:?}",
                    account_type, network
                ))
            })?;

        // Create the ManagedAccount from the BLS Account
        let managed_account = ManagedAccount::from_bls_account(bls_account);

        // Get or create the managed account collection for this network
        let managed_collection = self.accounts.entry(network).or_default();

        // Check if managed account already exists
        if managed_collection.contains_managed_account_type(managed_account.managed_type()) {
            return Err(Error::InvalidParameter(format!(
                "Managed BLS account type {:?} already exists for network {:?}",
                account_type, network
            )));
        }

        // Insert into the collection
        managed_collection.insert(managed_account);
        Ok(())
    }

    #[cfg(feature = "bls")]
    fn add_managed_bls_account_with_passphrase(
        &mut self,
        wallet: &Wallet,
        account_type: AccountType,
        network: Network,
        passphrase: &str,
    ) -> Result<()> {
        // Validate account type
        if !matches!(account_type, AccountType::ProviderOperatorKeys) {
            return Err(Error::InvalidParameter(
                "BLS accounts can only be ProviderOperatorKeys".to_string(),
            ));
        }

        // Verify this is a passphrase wallet
        match &wallet.wallet_type {
            WalletType::MnemonicWithPassphrase { mnemonic, .. } => {
                // Verify the passphrase by deriving and comparing
                let seed = mnemonic.to_seed(passphrase);
                let root_key = crate::wallet::root_extended_keys::RootExtendedPrivKey::new_master(&seed)?;

                // Compare with wallet's stored public key
                let derived_pub = root_key.to_root_extended_pub_key();
                let wallet_pub = wallet.root_extended_pub_key();

                if derived_pub.root_public_key != wallet_pub.root_public_key {
                    return Err(Error::InvalidParameter(
                        "Invalid passphrase".to_string()
                    ));
                }

                // Passphrase is valid, proceed with adding the managed BLS account
                self.add_managed_bls_account(wallet, account_type, network)
            }
            _ => Err(Error::InvalidParameter(
                "add_managed_bls_account_with_passphrase can only be used with wallets created with a passphrase".to_string()
            )),
        }
    }

    #[cfg(feature = "bls")]
    fn add_managed_bls_account_from_public_key(
        &mut self,
        account_type: AccountType,
        network: Network,
        bls_public_key: [u8; 48],
    ) -> Result<()> {
        // Validate account type
        if !matches!(account_type, AccountType::ProviderOperatorKeys) {
            return Err(Error::InvalidParameter(
                "BLS accounts can only be ProviderOperatorKeys".to_string(),
            ));
        }

        // Create a BLS account with no wallet ID (standalone managed account)
        let bls_account =
            BLSAccount::from_public_key_bytes(None, account_type, bls_public_key, network)?;

        // Create the ManagedAccount from the BLS Account
        let managed_account = ManagedAccount::from_bls_account(&bls_account);

        // Get or create the managed account collection for this network
        let managed_collection = self.accounts.entry(network).or_default();

        // Check if managed account already exists
        if managed_collection.contains_managed_account_type(managed_account.managed_type()) {
            return Err(Error::InvalidParameter(format!(
                "Managed BLS account type {:?} already exists for network {:?}",
                account_type, network
            )));
        }

        // Insert into the collection
        managed_collection.insert(managed_account);
        Ok(())
    }

    #[cfg(feature = "eddsa")]
    fn add_managed_eddsa_account(
        &mut self,
        wallet: &Wallet,
        account_type: AccountType,
        network: Network,
    ) -> Result<()> {
        // Validate account type
        if !matches!(account_type, AccountType::ProviderPlatformKeys) {
            return Err(Error::InvalidParameter(
                "EdDSA accounts can only be ProviderPlatformKeys".to_string(),
            ));
        }

        // First check if the EdDSA account exists in the wallet
        let account_collection = wallet.accounts.get(&network).ok_or_else(|| {
            Error::InvalidParameter(format!("No accounts for network {:?} in wallet", network))
        })?;

        let eddsa_account =
            account_collection.eddsa_account_of_type(account_type).ok_or_else(|| {
                Error::InvalidParameter(format!(
                    "EdDSA account type {:?} not found for network {:?}",
                    account_type, network
                ))
            })?;

        // Create the ManagedAccount from the EdDSA Account
        let managed_account = ManagedAccount::from_eddsa_account(eddsa_account);

        // Get or create the managed account collection for this network
        let managed_collection = self.accounts.entry(network).or_default();

        // Check if managed account already exists
        if managed_collection.contains_managed_account_type(managed_account.managed_type()) {
            return Err(Error::InvalidParameter(format!(
                "Managed EdDSA account type {:?} already exists for network {:?}",
                account_type, network
            )));
        }

        // Insert into the collection
        managed_collection.insert(managed_account);
        Ok(())
    }

    #[cfg(feature = "eddsa")]
    fn add_managed_eddsa_account_with_passphrase(
        &mut self,
        wallet: &Wallet,
        account_type: AccountType,
        network: Network,
        passphrase: &str,
    ) -> Result<()> {
        // Validate account type
        if !matches!(account_type, AccountType::ProviderPlatformKeys) {
            return Err(Error::InvalidParameter(
                "EdDSA accounts can only be ProviderPlatformKeys".to_string(),
            ));
        }

        // Verify this is a passphrase wallet
        match &wallet.wallet_type {
            WalletType::MnemonicWithPassphrase { mnemonic, .. } => {
                // Verify the passphrase by deriving and comparing
                let seed = mnemonic.to_seed(passphrase);
                let root_key = crate::wallet::root_extended_keys::RootExtendedPrivKey::new_master(&seed)?;

                // Compare with wallet's stored public key
                let derived_pub = root_key.to_root_extended_pub_key();
                let wallet_pub = wallet.root_extended_pub_key();

                if derived_pub.root_public_key != wallet_pub.root_public_key {
                    return Err(Error::InvalidParameter(
                        "Invalid passphrase".to_string()
                    ));
                }

                // Passphrase is valid, proceed with adding the managed EdDSA account
                self.add_managed_eddsa_account(wallet, account_type, network)
            }
            _ => Err(Error::InvalidParameter(
                "add_managed_eddsa_account_with_passphrase can only be used with wallets created with a passphrase".to_string()
            )),
        }
    }

    #[cfg(feature = "eddsa")]
    fn add_managed_eddsa_account_from_public_key(
        &mut self,
        account_type: AccountType,
        network: Network,
        ed25519_public_key: [u8; 32],
    ) -> Result<()> {
        // Validate account type
        if !matches!(account_type, AccountType::ProviderPlatformKeys) {
            return Err(Error::InvalidParameter(
                "EdDSA accounts can only be ProviderPlatformKeys".to_string(),
            ));
        }

        // Create an EdDSA account with no wallet ID (standalone managed account)
        let eddsa_account =
            EdDSAAccount::from_public_key_bytes(None, account_type, ed25519_public_key, network)?;

        // Create the ManagedAccount from the EdDSA Account
        let managed_account = ManagedAccount::from_eddsa_account(&eddsa_account);

        // Get or create the managed account collection for this network
        let managed_collection = self.accounts.entry(network).or_default();

        // Check if managed account already exists
        if managed_collection.contains_managed_account_type(managed_account.managed_type()) {
            return Err(Error::InvalidParameter(format!(
                "Managed EdDSA account type {:?} already exists for network {:?}",
                account_type, network
            )));
        }

        // Insert into the collection
        managed_collection.insert(managed_account);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::Wallet;

    #[test]
    fn test_add_managed_account() {
        // Create a test wallet without BLS accounts to avoid that complexity
        let mut wallet = Wallet::new_random(
            &[Network::Testnet],
            crate::wallet::initialization::WalletAccountCreationOptions::None,
        )
        .unwrap();

        // Add a standard account to the wallet at index 0
        wallet
            .add_account(
                AccountType::Standard {
                    index: 0,
                    standard_account_type: crate::account::StandardAccountType::BIP44Account,
                },
                Network::Testnet,
                None,
            )
            .unwrap();

        // Create managed wallet info - this will NOT automatically add the wallet's accounts
        let mut managed_info = ManagedWalletInfo::new(wallet.wallet_id);

        // The managed_info should be empty initially
        assert!(managed_info.accounts.is_empty());

        // Now add the account from the wallet to the managed info
        let account_type = AccountType::Standard {
            index: 0,
            standard_account_type: crate::account::StandardAccountType::BIP44Account,
        };

        // Add a managed account
        let result = managed_info.add_managed_account(&wallet, account_type, Network::Testnet);
        assert!(result.is_ok(), "Failed to add managed account: {:?}", result);

        // Verify it was added
        let collection = managed_info.accounts.get(&Network::Testnet).unwrap();
        // Check that the standard BIP44 account at index 0 exists
        assert!(collection.standard_bip44_accounts.contains_key(&0));

        // Try to add the same account again - should fail
        let result = managed_info.add_managed_account(&wallet, account_type, Network::Testnet);
        assert!(result.is_err());

        // Add a different account (index 1) - should succeed
        wallet
            .add_account(
                AccountType::Standard {
                    index: 1,
                    standard_account_type: crate::account::StandardAccountType::BIP44Account,
                },
                Network::Testnet,
                None,
            )
            .unwrap();

        let account_type_2 = AccountType::Standard {
            index: 1,
            standard_account_type: crate::account::StandardAccountType::BIP44Account,
        };

        let result = managed_info.add_managed_account(&wallet, account_type_2, Network::Testnet);
        assert!(result.is_ok(), "Failed to add second managed account: {:?}", result);

        // Verify both accounts exist
        let collection = managed_info.accounts.get(&Network::Testnet).unwrap();
        assert!(collection.standard_bip44_accounts.contains_key(&0));
        assert!(collection.standard_bip44_accounts.contains_key(&1));
    }
}
