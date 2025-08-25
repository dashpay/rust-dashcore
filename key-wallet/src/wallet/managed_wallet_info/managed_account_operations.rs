//! Trait for managed account operations
//!
//! This trait defines the interface for adding and managing accounts in ManagedWalletInfo.

use crate::account::AccountType;
use crate::bip32::ExtendedPubKey;
use crate::error::Result;
use crate::wallet::Wallet;
use crate::Network;

/// Trait for managed account operations
pub trait ManagedAccountOperations {
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
    ) -> Result<()>;

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
    ) -> Result<()>;

    /// Create and add a managed account directly with extended public key
    ///
    /// This allows creating a managed account without requiring it to exist in the wallet first.
    /// Useful for watch-only scenarios or external key management.
    ///
    /// # Arguments
    /// * `account_type` - The type of account to create
    /// * `network` - The network for the account
    /// * `account_xpub` - Extended public key for the account
    ///
    /// # Returns
    /// Ok(()) if the managed account was successfully added
    fn add_managed_account_from_xpub(
        &mut self,
        account_type: AccountType,
        network: Network,
        account_xpub: ExtendedPubKey,
    ) -> Result<()>;

    /// Add a new managed BLS account from an existing wallet BLS account
    ///
    /// BLS accounts are used for Platform/masternode operations.
    ///
    /// # Arguments
    /// * `wallet` - The wallet containing the BLS account
    /// * `account_type` - The type of account (must be ProviderOperatorKeys)
    /// * `network` - The network for the account
    ///
    /// # Returns
    /// Ok(()) if the managed BLS account was successfully added
    #[cfg(feature = "bls")]
    fn add_managed_bls_account(
        &mut self,
        wallet: &Wallet,
        account_type: AccountType,
        network: Network,
    ) -> Result<()>;

    /// Add a new managed BLS account with passphrase verification
    ///
    /// This function verifies the passphrase and creates a managed BLS account.
    /// It only works with wallets created with a passphrase.
    ///
    /// # Arguments
    /// * `wallet` - The wallet containing the BLS account (must be MnemonicWithPassphrase type)
    /// * `account_type` - The type of account (must be ProviderOperatorKeys)
    /// * `network` - The network for the account
    /// * `passphrase` - The passphrase to verify
    ///
    /// # Returns
    /// Ok(()) if the managed BLS account was successfully added
    #[cfg(feature = "bls")]
    fn add_managed_bls_account_with_passphrase(
        &mut self,
        wallet: &Wallet,
        account_type: AccountType,
        network: Network,
        passphrase: &str,
    ) -> Result<()>;

    /// Create and add a managed BLS account directly with BLS public key
    ///
    /// This allows creating a managed BLS account without requiring it to exist in the wallet first.
    ///
    /// # Arguments
    /// * `account_type` - The type of account (must be ProviderOperatorKeys)
    /// * `network` - The network for the account
    /// * `bls_public_key` - 48-byte BLS public key
    ///
    /// # Returns
    /// Ok(()) if the managed BLS account was successfully added
    #[cfg(feature = "bls")]
    fn add_managed_bls_account_from_public_key(
        &mut self,
        account_type: AccountType,
        network: Network,
        bls_public_key: [u8; 48],
    ) -> Result<()>;

    /// Add a new managed EdDSA account from an existing wallet EdDSA account
    ///
    /// EdDSA accounts are used for Platform operations.
    ///
    /// # Arguments
    /// * `wallet` - The wallet containing the EdDSA account
    /// * `account_type` - The type of account (must be ProviderPlatformKeys)
    /// * `network` - The network for the account
    ///
    /// # Returns
    /// Ok(()) if the managed EdDSA account was successfully added
    #[cfg(feature = "eddsa")]
    fn add_managed_eddsa_account(
        &mut self,
        wallet: &Wallet,
        account_type: AccountType,
        network: Network,
    ) -> Result<()>;

    /// Add a new managed EdDSA account with passphrase verification
    ///
    /// This function verifies the passphrase and creates a managed EdDSA account.
    /// It only works with wallets created with a passphrase.
    ///
    /// # Arguments
    /// * `wallet` - The wallet containing the EdDSA account (must be MnemonicWithPassphrase type)
    /// * `account_type` - The type of account (must be ProviderPlatformKeys)
    /// * `network` - The network for the account
    /// * `passphrase` - The passphrase to verify
    ///
    /// # Returns
    /// Ok(()) if the managed EdDSA account was successfully added
    #[cfg(feature = "eddsa")]
    fn add_managed_eddsa_account_with_passphrase(
        &mut self,
        wallet: &Wallet,
        account_type: AccountType,
        network: Network,
        passphrase: &str,
    ) -> Result<()>;

    /// Create and add a managed EdDSA account directly with Ed25519 public key
    ///
    /// This allows creating a managed EdDSA account without requiring it to exist in the wallet first.
    ///
    /// # Arguments
    /// * `account_type` - The type of account (must be ProviderPlatformKeys)
    /// * `network` - The network for the account
    /// * `ed25519_public_key` - 32-byte Ed25519 public key
    ///
    /// # Returns
    /// Ok(()) if the managed EdDSA account was successfully added
    #[cfg(feature = "eddsa")]
    fn add_managed_eddsa_account_from_public_key(
        &mut self,
        account_type: AccountType,
        network: Network,
        ed25519_public_key: [u8; 32],
    ) -> Result<()>;
}
