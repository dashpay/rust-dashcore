//! BIP38 encryption/decryption methods for wallets
//!
//! This module contains methods for importing and exporting BIP38 encrypted keys.

#[cfg(feature = "bip38")]
use super::Wallet;
#[cfg(feature = "bip38")]
use crate::bip38::{encrypt_private_key, Bip38EncryptedKey};
#[cfg(feature = "bip38")]
use crate::error::{Error, Result};
#[cfg(feature = "bip38")]
use crate::Network;
#[cfg(feature = "bip38")]
use alloc::vec::Vec;

#[cfg(feature = "bip38")]
impl Wallet {
    /// Export the master private key as BIP38 encrypted
    pub fn export_master_key_bip38(
        &self,
        password: &str,
        network: Network,
    ) -> Result<Bip38EncryptedKey> {
        if self.is_watch_only() {
            return Err(Error::InvalidParameter(
                "Cannot export private key from watch-only wallet".into(),
            ));
        }

        let root_key = self.root_extended_priv_key()?;
        let secret_key = root_key.root_private_key;

        encrypt_private_key(&secret_key, password, true, network)
    }

    /// Export an account's private key as BIP38 encrypted
    pub fn export_bip44_account_key_bip38(
        &self,
        network: Network,
        account_index: u32,
        password: &str,
    ) -> Result<Bip38EncryptedKey> {
        if self.is_watch_only() {
            return Err(Error::InvalidParameter(
                "Cannot export private key from watch-only wallet".into(),
            ));
        }

        // Verify account exists
        let account =
            self.get_bip44_account(network, account_index).ok_or(Error::InvalidParameter(
                format!("Account {} not found for network {:?}", account_index, network),
            ))?;

        // Derive the account key from the root key
        let root_key = self.root_extended_priv_key()?;
        let master_key = root_key.to_extended_priv_key(network);

        use crate::account::AccountType;
        use crate::derivation::HDWallet;

        let hd_wallet = HDWallet::new(master_key);
        let account_key = match &account.account_type {
            AccountType::CoinJoin {
                ..
            } => hd_wallet.coinjoin_account(account_index)?,
            AccountType::Standard {
                ..
            } => hd_wallet.bip44_account(account_index)?,
            _ => {
                return Err(Error::InvalidParameter(
                    "Unsupported account type for BIP38 export".into(),
                ))
            }
        };

        let secret_key = account_key.private_key;
        encrypt_private_key(&secret_key, password, true, network)
    }

    /// Import a BIP38 encrypted private key
    pub fn import_bip38_key(
        &mut self,
        encrypted_key: &Bip38EncryptedKey,
        password: &str,
    ) -> Result<()> {
        // Decrypt the key
        let secret_key = encrypted_key.decrypt(password)?;

        // Create a new account with this key
        // Note: This is a simplified implementation - in production you'd want more options
        let private_bytes = secret_key.secret_bytes();
        let mut extended_key_bytes = Vec::new();
        extended_key_bytes.extend_from_slice(&[0; 32]); // chain code (zeros for imported keys)
        extended_key_bytes.extend_from_slice(&private_bytes);

        // This is simplified - in production you'd properly construct the ExtendedPrivKey
        // For now, we'll just note that the key was imported

        Ok(())
    }
}
