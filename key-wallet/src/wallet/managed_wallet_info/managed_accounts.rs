//! Managed account creation methods for ManagedWalletInfo
//!
//! This module contains the implementation of ManagedAccountOperations trait for ManagedWalletInfo.

use super::{managed_account_operations::ManagedAccountOperations, ManagedWalletInfo};
#[cfg(feature = "bls")]
use crate::account::BLSAccount;
#[cfg(feature = "eddsa")]
use crate::account::EdDSAAccount;
use crate::account::{Account, AccountType, ManagedCoreAccount};
use crate::bip32::ExtendedPubKey;
use crate::error::{Error, Result};
use crate::wallet::{Wallet, WalletType};

impl ManagedAccountOperations for ManagedWalletInfo {
    /// Add a new managed account from an existing wallet account
    ///
    /// This creates a ManagedAccount wrapper around an existing Account in the wallet.
    ///
    /// # Arguments
    /// * `wallet` - The wallet containing the account
    /// * `account_type` - The type of account to manage
    ///
    /// # Returns
    /// Ok(()) if the managed account was successfully added
    fn add_managed_account(&mut self, wallet: &Wallet, account_type: AccountType) -> Result<()> {
        // Validate network consistency
        if wallet.network != self.network {
            return Err(Error::InvalidParameter(
                format!(
                    "Network mismatch: wallet network {:?} does not match managed wallet info network {:?}",
                    wallet.network,
                    self.network)
                )
            );
        }
        let account = wallet.accounts.account_of_type(account_type).ok_or_else(|| {
            Error::InvalidParameter(format!(
                "Account type {:?} not found for network {:?}",
                account_type, wallet.network
            ))
        })?;

        // Create the ManagedAccount from the Account
        let managed_account = ManagedCoreAccount::from_account(account);

        // Check if managed account already exists
        if self.accounts.contains_managed_account_type(managed_account.managed_type()) {
            return Err(Error::InvalidParameter(format!(
                "Managed account type {:?} already exists for network {:?}",
                account_type, self.network
            )));
        }

        // Insert into the collection
        self.accounts.insert(managed_account);
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
    /// * `passphrase` - The passphrase to verify
    ///
    /// # Returns
    /// Ok(()) if the managed account was successfully added
    fn add_managed_account_with_passphrase(
        &mut self,
        wallet: &Wallet,
        account_type: AccountType,
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
                self.add_managed_account(wallet, account_type)
            }
            _ => Err(Error::InvalidParameter(
                "add_managed_account_with_passphrase can only be used with wallets created with a passphrase".to_string()
            )),
        }
    }

    fn add_managed_account_from_xpub(
        &mut self,
        account_type: AccountType,
        account_xpub: ExtendedPubKey,
    ) -> Result<()> {
        // Verify network matches
        if account_xpub.network != self.network {
            return Err(Error::InvalidParameter(format!(
                "Network mismatch: expected {:?}, got {:?}",
                self.network, account_xpub.network
            )));
        }

        // Create an Account with no wallet ID (standalone managed account)
        let account = Account::new(None, account_type, account_xpub, self.network)?;

        // Create the ManagedAccount from the Account
        let managed_account = ManagedCoreAccount::from_account(&account);

        // Check if managed account already exists
        if self.accounts.contains_managed_account_type(managed_account.managed_type()) {
            return Err(Error::InvalidParameter(format!(
                "Managed account type {:?} already exists for network {:?}",
                account_type, self.network
            )));
        }

        // Insert into the collection
        self.accounts.insert(managed_account);
        Ok(())
    }

    #[cfg(feature = "bls")]
    fn add_managed_bls_account(
        &mut self,
        wallet: &Wallet,
        account_type: AccountType,
    ) -> Result<()> {
        // Validate network consistency
        if wallet.network != self.network {
            return Err(Error::InvalidParameter(format!(
                "Network mismatch: wallet network {:?} does not match managed wallet info network {:?}",
                wallet.network,
                self.network
            )));
        }

        // Validate account type
        if !matches!(account_type, AccountType::ProviderOperatorKeys) {
            return Err(Error::InvalidParameter(
                "BLS accounts can only be ProviderOperatorKeys".to_string(),
            ));
        }

        let bls_account = wallet.accounts.bls_account_of_type(account_type).ok_or_else(|| {
            Error::InvalidParameter(format!(
                "BLS account type {:?} not found for network {:?}",
                account_type, wallet.network
            ))
        })?;

        // Create the ManagedAccount from the BLS Account
        let managed_account = ManagedCoreAccount::from_bls_account(bls_account);

        // Check if managed account already exists
        if self.accounts.contains_managed_account_type(managed_account.managed_type()) {
            return Err(Error::InvalidParameter(format!(
                "Managed BLS account type {:?} already exists for network {:?}",
                account_type, self.network
            )));
        }

        // Insert into the collection
        self.accounts.insert(managed_account);
        Ok(())
    }

    #[cfg(feature = "bls")]
    fn add_managed_bls_account_with_passphrase(
        &mut self,
        wallet: &Wallet,
        account_type: AccountType,
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
                self.add_managed_bls_account(wallet, account_type)
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
            BLSAccount::from_public_key_bytes(None, account_type, bls_public_key, self.network)?;

        // Create the ManagedAccount from the BLS Account
        let managed_account = ManagedCoreAccount::from_bls_account(&bls_account);

        // Check if managed account already exists
        if self.accounts.contains_managed_account_type(managed_account.managed_type()) {
            return Err(Error::InvalidParameter(format!(
                "Managed BLS account type {:?} already exists for network {:?}",
                account_type, self.network
            )));
        }

        // Insert into the collection
        self.accounts.insert(managed_account);
        Ok(())
    }

    #[cfg(feature = "eddsa")]
    fn add_managed_eddsa_account(
        &mut self,
        wallet: &Wallet,
        account_type: AccountType,
    ) -> Result<()> {
        // Validate network consistency
        if wallet.network != self.network {
            return Err(Error::InvalidParameter(format!(
                "Network mismatch: wallet network {:?} does not match managed wallet info network {:?}",
                wallet.network,
                self.network
            )));
        }

        // Validate account type
        if !matches!(account_type, AccountType::ProviderPlatformKeys) {
            return Err(Error::InvalidParameter(
                "EdDSA accounts can only be ProviderPlatformKeys".to_string(),
            ));
        }

        let eddsa_account =
            wallet.accounts.eddsa_account_of_type(account_type).ok_or_else(|| {
                Error::InvalidParameter(format!(
                    "EdDSA account type {:?} not found for network {:?}",
                    account_type, wallet.network
                ))
            })?;

        // Create the ManagedAccount from the EdDSA Account
        let managed_account = ManagedCoreAccount::from_eddsa_account(eddsa_account);

        // Check if managed account already exists
        if self.accounts.contains_managed_account_type(managed_account.managed_type()) {
            return Err(Error::InvalidParameter(format!(
                "Managed EdDSA account type {:?} already exists for network {:?}",
                account_type, self.network
            )));
        }

        // Insert into the collection
        self.accounts.insert(managed_account);
        Ok(())
    }

    #[cfg(feature = "eddsa")]
    fn add_managed_eddsa_account_with_passphrase(
        &mut self,
        wallet: &Wallet,
        account_type: AccountType,
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
                self.add_managed_eddsa_account(wallet, account_type)
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
        ed25519_public_key: [u8; 32],
    ) -> Result<()> {
        // Validate account type
        if !matches!(account_type, AccountType::ProviderPlatformKeys) {
            return Err(Error::InvalidParameter(
                "EdDSA accounts can only be ProviderPlatformKeys".to_string(),
            ));
        }

        // Create an EdDSA account with no wallet ID (standalone managed account)
        let eddsa_account = EdDSAAccount::from_public_key_bytes(
            None,
            account_type,
            ed25519_public_key,
            self.network,
        )?;

        // Create the ManagedAccount from the EdDSA Account
        let managed_account = ManagedCoreAccount::from_eddsa_account(&eddsa_account);

        // Check if managed account already exists
        if self.accounts.contains_managed_account_type(managed_account.managed_type()) {
            return Err(Error::InvalidParameter(format!(
                "Managed EdDSA account type {:?} already exists for network {:?}",
                account_type, self.network
            )));
        }

        // Insert into the collection
        self.accounts.insert(managed_account);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::Wallet;
    use crate::Network;

    #[test]
    fn test_add_managed_account() {
        // Create a test wallet without BLS accounts to avoid that complexity
        let mut wallet = Wallet::new_random(
            Network::Testnet,
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
                None,
            )
            .unwrap();

        // Create managed wallet info - this will NOT automatically add the wallet's accounts
        let mut managed_info = ManagedWalletInfo::new(Network::Testnet, wallet.wallet_id);

        // The managed_info should be empty initially
        assert!(managed_info.accounts.is_empty());

        // Now add the account from the wallet to the managed info
        let account_type = AccountType::Standard {
            index: 0,
            standard_account_type: crate::account::StandardAccountType::BIP44Account,
        };

        // Add a managed account
        let result = managed_info.add_managed_account(&wallet, account_type);
        assert!(result.is_ok(), "Failed to add managed account: {:?}", result);

        // Verify it was added - direct access to accounts collection
        assert!(managed_info.accounts.standard_bip44_accounts.contains_key(&0));

        // Try to add the same account again - should fail
        let result = managed_info.add_managed_account(&wallet, account_type);
        assert!(result.is_err());

        // Add a different account (index 1) - should succeed
        wallet
            .add_account(
                AccountType::Standard {
                    index: 1,
                    standard_account_type: crate::account::StandardAccountType::BIP44Account,
                },
                None,
            )
            .unwrap();

        let account_type_2 = AccountType::Standard {
            index: 1,
            standard_account_type: crate::account::StandardAccountType::BIP44Account,
        };

        let result = managed_info.add_managed_account(&wallet, account_type_2);
        assert!(result.is_ok(), "Failed to add second managed account: {:?}", result);

        // Verify both accounts exist
        assert!(managed_info.accounts.standard_bip44_accounts.contains_key(&0));
        assert!(managed_info.accounts.standard_bip44_accounts.contains_key(&1));
    }
}
