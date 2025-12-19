//! Account management methods for wallets
//!
//! This module contains methods for creating and managing accounts within wallets.

use super::Wallet;
#[cfg(feature = "bls")]
use crate::account::BLSAccount;
#[cfg(feature = "eddsa")]
use crate::account::EdDSAAccount;
use crate::account::{Account, AccountType};
use crate::bip32::ExtendedPubKey;
use crate::derivation::HDWallet;
use crate::error::{Error, Result};

impl Wallet {
    /// Add a new account to the wallet
    ///
    /// # Arguments
    /// * `account_type` - The type of account to create
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
        account_xpub: Option<ExtendedPubKey>,
    ) -> Result<()> {
        // Get a unique wallet ID for this wallet first
        let wallet_id = self.get_wallet_id();

        // Create the account based on whether we have an xpub or need to derive
        let account = if let Some(xpub) = account_xpub {
            // Use the provided extended public key
            Account::new(Some(wallet_id), account_type, xpub, self.network)?
        } else {
            // Derive from wallet's private key
            let derivation_path = account_type.derivation_path(self.network)?;

            // This will fail if the wallet doesn't have a private key (watch-only or externally managed)
            let root_key = self.root_extended_priv_key()?;
            let master_key = root_key.to_extended_priv_key(self.network);
            let hd_wallet = HDWallet::new(master_key);
            let account_xpriv = hd_wallet.derive(&derivation_path)?;

            Account::from_xpriv(Some(wallet_id), account_type, account_xpriv, self.network)?
        };

        // Check if account already exists
        if self.accounts.contains_account_type(&account_type) {
            return Err(Error::InvalidParameter(format!(
                "Account type {:?} already exists for network {:?}",
                account_type, self.network
            )));
        }

        // Insert into the collection
        self.accounts.insert(account).map_err(|e| Error::InvalidParameter(e.to_string()))
    }

    /// Add a new account to a wallet that requires a passphrase
    ///
    /// This function only works with wallets created with a passphrase (MnemonicWithPassphrase type).
    /// It will fail if called on other wallet types.
    ///
    /// # Arguments
    /// * `account_type` - The type of account to create
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
        passphrase: &str,
    ) -> Result<()> {
        // Check that this is a passphrase wallet
        match &self.wallet_type {
            crate::wallet::WalletType::MnemonicWithPassphrase { mnemonic, .. } => {
                // Get a unique wallet ID for this wallet first
                let wallet_id = self.get_wallet_id();

                // Derive the account using the passphrase
                let derivation_path = account_type.derivation_path(self.network)?;

                // Generate seed with passphrase
                let seed = mnemonic.to_seed(passphrase);
                let root_key = super::root_extended_keys::RootExtendedPrivKey::new_master(&seed)?;
                let master_key = root_key.to_extended_priv_key(self.network);
                let hd_wallet = HDWallet::new(master_key);
                let account_xpriv = hd_wallet.derive(&derivation_path)?;

                let account = Account::from_xpriv(Some(wallet_id), account_type, account_xpriv, self.network)?;

                // Check if account already exists
                if self.accounts.contains_account_type(&account_type) {
                    return Err(Error::InvalidParameter(format!(
                        "Account type {:?} already exists for network {:?}",
                        account_type, self.network
                    )));
                }

                // Insert into the collection
                self.accounts.insert(account)
                    .map_err(|e| Error::InvalidParameter(e.to_string()))
            }
            _ => Err(Error::InvalidParameter(
                "add_account_with_passphrase can only be used with wallets created with a passphrase".to_string()
            )),
        }
    }

    /// Add a new BLS account to the wallet
    ///
    /// BLS accounts are used for Platform/masternode operations.
    ///
    /// # Arguments
    /// * `account_type` - The type of account (must be ProviderOperatorKeys)
    /// * `bls_seed` - Optional 32-byte seed for BLS key generation. If not provided,
    ///   the account will be derived from the wallet's private key.
    ///
    /// # Returns
    /// Ok(()) if the account was successfully added
    #[cfg(feature = "bls")]
    pub fn add_bls_account(
        &mut self,
        account_type: AccountType,
        bls_seed: Option<[u8; 32]>,
    ) -> Result<()> {
        // Validate account type
        if !matches!(account_type, AccountType::ProviderOperatorKeys) {
            return Err(Error::InvalidParameter(
                "BLS accounts can only be ProviderOperatorKeys".to_string(),
            ));
        }

        // Get a unique wallet ID for this wallet first
        let wallet_id = self.get_wallet_id();

        // Create the BLS account based on whether we have a seed or need to derive
        let bls_account = if let Some(seed) = bls_seed {
            // Use the provided seed
            BLSAccount::from_seed(Some(wallet_id.to_vec()), account_type, seed, self.network)?
        } else {
            // Derive from wallet's private key
            let derivation_path = account_type.derivation_path(self.network)?;

            // This will fail if the wallet doesn't have a private key
            let root_key = self.root_extended_priv_key()?;
            let master_key = root_key.to_extended_priv_key(self.network);
            let hd_wallet = HDWallet::new(master_key);
            let account_xpriv = hd_wallet.derive(&derivation_path)?;

            // Create BLS seed from derived private key
            let seed = account_xpriv.private_key.secret_bytes();
            BLSAccount::from_seed(Some(wallet_id.to_vec()), account_type, seed, self.network)?
        };

        // Check if account already exists
        if self.accounts.contains_account_type(&account_type) {
            return Err(Error::InvalidParameter(format!(
                "Account type {:?} already exists for network {:?}",
                account_type, self.network
            )));
        }

        // Insert into the collection
        self.accounts
            .insert_bls_account(bls_account)
            .map_err(|e| Error::InvalidParameter(e.to_string()))
    }

    /// Add a new BLS account to a wallet that requires a passphrase
    ///
    /// This function only works with wallets created with a passphrase (MnemonicWithPassphrase type).
    ///
    /// # Arguments
    /// * `account_type` - The type of account (must be ProviderOperatorKeys)
    /// * `passphrase` - The passphrase used when creating the wallet
    ///
    /// # Returns
    /// Ok(()) if the account was successfully added
    #[cfg(feature = "bls")]
    pub fn add_bls_account_with_passphrase(
        &mut self,
        account_type: AccountType,
        passphrase: &str,
    ) -> Result<()> {
        // Validate account type
        if !matches!(account_type, AccountType::ProviderOperatorKeys) {
            return Err(Error::InvalidParameter(
                "BLS accounts can only be ProviderOperatorKeys".to_string(),
            ));
        }

        // Check that this is a passphrase wallet
        match &self.wallet_type {
            crate::wallet::WalletType::MnemonicWithPassphrase { mnemonic, .. } => {
                // Get a unique wallet ID for this wallet first
                let wallet_id = self.get_wallet_id();

                // Derive the account using the passphrase
                let derivation_path = account_type.derivation_path(self.network)?;

                // Generate seed with passphrase
                let seed = mnemonic.to_seed(passphrase);
                let root_key = super::root_extended_keys::RootExtendedPrivKey::new_master(&seed)?;
                let master_key = root_key.to_extended_priv_key(self.network);
                let hd_wallet = HDWallet::new(master_key);
                let account_xpriv = hd_wallet.derive(&derivation_path)?;

                // Create BLS seed from derived private key
                let bls_seed = account_xpriv.private_key.secret_bytes();
                let bls_account = BLSAccount::from_seed(Some(wallet_id.to_vec()), account_type, bls_seed, self.network)?;

                // Check if account already exists
                if self.accounts.contains_account_type(&account_type) {
                    return Err(Error::InvalidParameter(format!(
                        "Account type {:?} already exists for network {:?}",
                        account_type, self.network
                    )));
                }

                // Insert into the collection
                self.accounts.insert_bls_account(bls_account)
                    .map_err(|e| Error::InvalidParameter(e.to_string()))
            }
            _ => Err(Error::InvalidParameter(
                "add_bls_account_with_passphrase can only be used with wallets created with a passphrase".to_string()
            )),
        }
    }

    /// Add a new EdDSA account to the wallet
    ///
    /// EdDSA accounts are used for Platform operations.
    ///
    /// # Arguments
    /// * `account_type` - The type of account (must be ProviderPlatformKeys)
    /// * `ed25519_seed` - Optional 32-byte seed for Ed25519 key generation. If not provided,
    ///   the account will be derived from the wallet's private key.
    ///
    /// # Returns
    /// Ok(()) if the account was successfully added
    #[cfg(feature = "eddsa")]
    pub fn add_eddsa_account(
        &mut self,
        account_type: AccountType,
        ed25519_seed: Option<[u8; 32]>,
    ) -> Result<()> {
        // Validate account type
        if !matches!(account_type, AccountType::ProviderPlatformKeys) {
            return Err(Error::InvalidParameter(
                "EdDSA accounts can only be ProviderPlatformKeys".to_string(),
            ));
        }

        // Get a unique wallet ID for this wallet first
        let wallet_id = self.get_wallet_id();

        // Create the EdDSA account based on whether we have a seed or need to derive
        let eddsa_account = if let Some(seed) = ed25519_seed {
            // Use the provided seed
            EdDSAAccount::from_seed(Some(wallet_id.to_vec()), account_type, seed, self.network)?
        } else {
            // Derive from wallet's private key
            let derivation_path = account_type.derivation_path(self.network)?;

            // This will fail if the wallet doesn't have a private key
            let root_key = self.root_extended_priv_key()?;
            let master_key = root_key.to_extended_priv_key(self.network);
            let hd_wallet = HDWallet::new(master_key);
            let account_xpriv = hd_wallet.derive(&derivation_path)?;

            // Create Ed25519 seed from derived private key
            let seed = account_xpriv.private_key.secret_bytes();
            EdDSAAccount::from_seed(Some(wallet_id.to_vec()), account_type, seed, self.network)?
        };

        // Check if account already exists
        if self.accounts.contains_account_type(&account_type) {
            return Err(Error::InvalidParameter(format!(
                "Account type {:?} already exists for network {:?}",
                account_type, self.network
            )));
        }

        // Insert into the collection
        self.accounts
            .insert_eddsa_account(eddsa_account)
            .map_err(|e| Error::InvalidParameter(e.to_string()))
    }

    /// Add a new EdDSA account to a wallet that requires a passphrase
    ///
    /// This function only works with wallets created with a passphrase (MnemonicWithPassphrase type).
    ///
    /// # Arguments
    /// * `account_type` - The type of account (must be ProviderPlatformKeys)
    /// * `passphrase` - The passphrase used when creating the wallet
    ///
    /// # Returns
    /// Ok(()) if the account was successfully added
    #[cfg(feature = "eddsa")]
    pub fn add_eddsa_account_with_passphrase(
        &mut self,
        account_type: AccountType,
        passphrase: &str,
    ) -> Result<()> {
        // Validate account type
        if !matches!(account_type, AccountType::ProviderPlatformKeys) {
            return Err(Error::InvalidParameter(
                "EdDSA accounts can only be ProviderPlatformKeys".to_string(),
            ));
        }

        // Check that this is a passphrase wallet
        match &self.wallet_type {
            crate::wallet::WalletType::MnemonicWithPassphrase { mnemonic, .. } => {
                // Get a unique wallet ID for this wallet first
                let wallet_id = self.get_wallet_id();

                // Derive the account using the passphrase
                let derivation_path = account_type.derivation_path(self.network)?;

                // Generate seed with passphrase
                let seed = mnemonic.to_seed(passphrase);
                let root_key = super::root_extended_keys::RootExtendedPrivKey::new_master(&seed)?;
                let master_key = root_key.to_extended_priv_key(self.network);
                let hd_wallet = HDWallet::new(master_key);
                let account_xpriv = hd_wallet.derive(&derivation_path)?;

                // Create Ed25519 seed from derived private key
                let ed25519_seed = account_xpriv.private_key.secret_bytes();
                let eddsa_account = EdDSAAccount::from_seed(Some(wallet_id.to_vec()), account_type, ed25519_seed, self.network)?;

                // Check if account already exists
                if self.accounts.contains_account_type(&account_type) {
                    return Err(Error::InvalidParameter(format!(
                        "Account type {:?} already exists for network {:?}",
                        account_type, self.network
                    )));
                }

                // Insert into the collection
                self.accounts.insert_eddsa_account(eddsa_account)
                    .map_err(|e| Error::InvalidParameter(e.to_string()))
            }
            _ => Err(Error::InvalidParameter(
                "add_eddsa_account_with_passphrase can only be used with wallets created with a passphrase".to_string()
            )),
        }
    }

    /// Get the wallet ID for this wallet
    fn get_wallet_id(&self) -> [u8; 32] {
        self.wallet_id
    }
}
