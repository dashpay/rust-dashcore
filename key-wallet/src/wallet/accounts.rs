//! Account management methods for wallets
//!
//! This module contains methods for creating and managing accounts within wallets.

use super::Wallet;
use crate::account::{Account, AccountType};
use crate::bip32::ExtendedPubKey;
use crate::derivation::HDWallet;
use crate::error::{Error, Result};
use crate::Network;

impl Wallet {
    /// Add a new account to the wallet
    ///
    /// # Arguments
    /// * `account_type` - The type of account to create
    /// * `network` - The network for the account
    /// * `account_xpub` - Optional extended public key for the account. If not provided,
    ///   the account will be derived from the wallet's private key.
    ///   This will fail if the wallet doesn't have a private key
    ///   (watch-only wallets or externally managed wallets where
    ///   the private key is stored securely outside of the SDK).
    ///
    /// # Returns
    /// Ok(()) if the account was successfully added
    pub fn add_account(
        &mut self,
        account_type: AccountType,
        network: Network,
        account_xpub: Option<ExtendedPubKey>,
    ) -> Result<()> {
        // Get a unique wallet ID for this wallet first
        let wallet_id = self.get_wallet_id();

        // Create the account based on whether we have an xpub or need to derive
        let account = if let Some(xpub) = account_xpub {
            // Use the provided extended public key
            Account::new(Some(wallet_id), account_type, xpub, network)?
        } else {
            // Derive from wallet's private key
            let derivation_path = account_type.derivation_path(network)?;

            // This will fail if the wallet doesn't have a private key (watch-only or externally managed)
            let root_key = self.root_extended_priv_key()?;
            let master_key = root_key.to_extended_priv_key(network);
            let hd_wallet = HDWallet::new(master_key);
            let account_xpriv = hd_wallet.derive(&derivation_path)?;

            Account::from_xpriv(Some(wallet_id), account_type, account_xpriv, network)?
        };

        // Now get or create the account collection for this network
        let collection = self.accounts.entry(network).or_default();

        // Check if account already exists
        if collection.contains_account_type(&account_type) {
            return Err(Error::InvalidParameter(format!(
                "Account type {:?} already exists for network {:?}",
                account_type, network
            )));
        }

        // Insert into the collection
        collection.insert(account);

        Ok(())
    }

    /// Add a new account to a wallet that requires a passphrase
    ///
    /// This function only works with wallets created with a passphrase (MnemonicWithPassphrase type).
    /// It will fail if called on other wallet types.
    ///
    /// # Arguments
    /// * `account_type` - The type of account to create
    /// * `network` - The network for the account
    /// * `passphrase` - The passphrase used when creating the wallet
    ///
    /// # Returns
    /// Ok(()) if the account was successfully added
    ///
    /// # Errors
    /// Returns an error if:
    /// - The wallet is not a passphrase wallet
    /// - The account already exists
    /// - The passphrase is incorrect (will fail during derivation)
    pub fn add_account_with_passphrase(
        &mut self,
        account_type: AccountType,
        network: Network,
        passphrase: &str,
    ) -> Result<()> {
        // Check that this is a passphrase wallet
        match &self.wallet_type {
            crate::wallet::WalletType::MnemonicWithPassphrase { mnemonic, .. } => {
                // Get a unique wallet ID for this wallet first
                let wallet_id = self.get_wallet_id();

                // Derive the account using the passphrase
                let derivation_path = account_type.derivation_path(network)?;

                // Generate seed with passphrase
                let seed = mnemonic.to_seed(passphrase);
                let root_key = super::root_extended_keys::RootExtendedPrivKey::new_master(&seed)?;
                let master_key = root_key.to_extended_priv_key(network);
                let hd_wallet = HDWallet::new(master_key);
                let account_xpriv = hd_wallet.derive(&derivation_path)?;

                let account = Account::from_xpriv(Some(wallet_id), account_type, account_xpriv, network)?;

                // Now get or create the account collection for this network
                let collection = self.accounts.entry(network).or_default();

                // Check if account already exists
                if collection.contains_account_type(&account_type) {
                    return Err(Error::InvalidParameter(format!(
                        "Account type {:?} already exists for network {:?}",
                        account_type, network
                    )));
                }

                // Insert into the collection
                collection.insert(account);

                Ok(())
            }
            _ => Err(Error::InvalidParameter(
                "add_account_with_passphrase can only be used with wallets created with a passphrase".to_string()
            )),
        }
    }

    /// Get the wallet ID for this wallet
    fn get_wallet_id(&self) -> [u8; 32] {
        self.wallet_id
    }
}
