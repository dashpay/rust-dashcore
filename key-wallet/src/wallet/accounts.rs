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
use crate::error::{Error, Result};
use secp256k1::Secp256k1;

impl Wallet {
    /// Add a new account to the wallet
    ///
    /// # Arguments
    /// * `account_type` - The type of account to create
    /// * `account_xpub` - Optional extended public key for the account. If not provided,
    ///   the account is derived from the wallet's in-wallet private key.
    ///
    /// # Returns
    /// Ok(()) if the account was successfully added
    ///
    /// # Errors
    /// Returns [`Error::KeylessWalletRequiresAccountKey`] when `account_xpub` is
    /// `None` on a keyless wallet (watch-only / external-signable): such wallets
    /// hold no in-wallet private key, so pass the account's xpub via `Some(..)`.
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

            let root_key = self.root_extended_priv_key().map_err(|_| {
                Error::KeylessWalletRequiresAccountKey {
                    account_type,
                    required_key: "extended public key (xpub)",
                }
            })?;
            let master_key = root_key.to_extended_priv_key(self.network);
            let secp = Secp256k1::new();
            let account_xpriv =
                master_key.derive_priv(&secp, &derivation_path).map_err(Error::Bip32)?;

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

    /// Add a new BLS account to the wallet
    ///
    /// BLS accounts are used for Platform/masternode operations.
    ///
    /// The seed (whether provided or taken from the wallet) is fed directly
    /// into the BLS HD master key and the account's derivation path is applied
    /// in the BLS scheme, matching DashSync/dashbls.
    ///
    /// # Arguments
    /// * `account_type` - The type of account (must be ProviderOperatorKeys)
    /// * `bls_seed` - Optional wallet seed (typically the 64-byte BIP39 seed)
    ///   for BLS key generation. If not provided, the wallet's own seed is used.
    ///
    /// # Returns
    /// Ok(()) if the account was successfully added
    ///
    /// # Errors
    /// Returns [`Error::KeylessWalletRequiresAccountKey`] when `bls_seed` is `None`
    /// on a wallet without a stored seed (watch-only / external-signable /
    /// created from an extended private key): pass the seed via `Some(..)`.
    #[cfg(feature = "bls")]
    pub fn add_bls_account(
        &mut self,
        account_type: AccountType,
        bls_seed: Option<&[u8]>,
    ) -> Result<()> {
        // Validate account type
        if !matches!(account_type, AccountType::ProviderOperatorKeys) {
            return Err(Error::InvalidParameter(
                "BLS accounts can only be ProviderOperatorKeys".to_string(),
            ));
        }

        // Get a unique wallet ID for this wallet first
        let wallet_id = self.get_wallet_id();

        // Use the provided seed, or fall back to the wallet's own seed.
        // BLS provider keys must be derived from the raw seed in the BLS
        // scheme (dashbls ExtendedPrivateKey::FromSeed) — they cannot be
        // derived from a secp256k1 extended private key.
        let bls_account = if let Some(seed) = bls_seed {
            BLSAccount::from_seed(Some(wallet_id.to_vec()), account_type, seed, self.network)?
        } else {
            let seed = self.wallet_seed_bytes().ok_or(Error::KeylessWalletRequiresAccountKey {
                account_type,
                required_key: "wallet seed (e.g. 64-byte BIP39 seed)",
            })?;
            BLSAccount::from_seed(Some(wallet_id.to_vec()), account_type, &seed, self.network)?
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

    /// Add a new EdDSA account to the wallet
    ///
    /// EdDSA accounts are used for Platform operations.
    ///
    /// The seed (whether provided or taken from the wallet) is fed directly
    /// into the SLIP-0010 Ed25519 master key and the account's derivation path
    /// is applied in the Ed25519 scheme, matching DashSync.
    ///
    /// # Arguments
    /// * `account_type` - The type of account (must be ProviderPlatformKeys)
    /// * `ed25519_seed` - Optional wallet seed (typically the 64-byte BIP39
    ///   seed) for Ed25519 key generation. If not provided, the wallet's own
    ///   seed is used.
    ///
    /// # Returns
    /// Ok(()) if the account was successfully added
    ///
    /// # Errors
    /// Returns [`Error::KeylessWalletRequiresAccountKey`] when `ed25519_seed` is `None`
    /// on a wallet without a stored seed (watch-only / external-signable /
    /// created from an extended private key): pass the seed via `Some(..)`.
    #[cfg(feature = "eddsa")]
    pub fn add_eddsa_account(
        &mut self,
        account_type: AccountType,
        ed25519_seed: Option<&[u8]>,
    ) -> Result<()> {
        // Validate account type
        if !matches!(account_type, AccountType::ProviderPlatformKeys) {
            return Err(Error::InvalidParameter(
                "EdDSA accounts can only be ProviderPlatformKeys".to_string(),
            ));
        }

        // Get a unique wallet ID for this wallet first
        let wallet_id = self.get_wallet_id();

        // Use the provided seed, or fall back to the wallet's own seed.
        // Platform node keys must be derived from the raw seed via SLIP-0010 —
        // they cannot be derived from a secp256k1 extended private key.
        let eddsa_account = if let Some(seed) = ed25519_seed {
            EdDSAAccount::from_seed(Some(wallet_id.to_vec()), account_type, seed, self.network)?
        } else {
            let seed = self.wallet_seed_bytes().ok_or(Error::KeylessWalletRequiresAccountKey {
                account_type,
                required_key: "wallet seed (e.g. 64-byte BIP39 seed)",
            })?;
            EdDSAAccount::from_seed(Some(wallet_id.to_vec()), account_type, &seed, self.network)?
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

    /// Get the wallet ID for this wallet
    fn get_wallet_id(&self) -> [u8; 32] {
        self.wallet_id
    }
}
