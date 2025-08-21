//! Wallet backup and restore functionality
//!
//! This module provides serialization and deserialization methods for wallets
//! using bincode for efficient binary storage.

use crate::wallet::Wallet;

impl Wallet {
    /// Create a backup of this wallet
    ///
    /// # Returns
    /// A `Vec<u8>` containing the serialized wallet data
    ///
    /// # Example
    /// ```no_run
    /// use key_wallet::wallet::Wallet;
    ///
    /// let wallet = Wallet::new_random(
    ///     Default::default(),
    ///     key_wallet::Network::Testnet,
    ///     key_wallet::wallet::initialization::WalletAccountCreationOptions::Default,
    /// ).unwrap();
    ///
    /// let backup_data = wallet.backup().unwrap();
    /// // Store backup_data securely...
    /// ```
    #[cfg(feature = "bincode")]
    pub fn backup(&self) -> Result<Vec<u8>> {
        bincode::encode_to_vec(self, bincode::config::standard())
            .map_err(|e| Error::Serialization(format!("Failed to backup wallet: {}", e)))
    }

    /// Restore a wallet from a backup
    ///
    /// # Arguments
    /// * `backup_data` - The serialized wallet data
    ///
    /// # Returns
    /// The restored `Wallet`
    ///
    /// # Example
    /// ```no_run
    /// use key_wallet::wallet::Wallet;
    ///
    /// let backup_data: Vec<u8> = vec![]; // Load from storage
    /// let restored_wallet = Wallet::restore(&backup_data).unwrap();
    /// ```
    #[cfg(feature = "bincode")]
    pub fn restore(backup_data: &[u8]) -> Result<Self> {
        bincode::decode_from_slice(backup_data, bincode::config::standard())
            .map(|(wallet, _)| wallet)
            .map_err(|e| Error::Serialization(format!("Failed to restore wallet: {}", e)))
    }
}

#[cfg(all(test, feature = "bincode"))]
mod tests {
    use super::*;
    use crate::mnemonic::{Language, Mnemonic};
    use crate::wallet::{initialization::WalletAccountCreationOptions, WalletConfig};
    use crate::Network;

    #[test]
    fn test_backup_restore() {
        // Create a wallet
        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English,
        ).unwrap();

        let original = Wallet::from_mnemonic(
            mnemonic,
            WalletConfig::default(),
            Network::Testnet,
            WalletAccountCreationOptions::Default,
        )
        .unwrap();

        // Create backup
        let backup_data = original.backup().unwrap();
        assert!(!backup_data.is_empty());

        // Restore from backup
        let restored = Wallet::restore(&backup_data).unwrap();

        // Verify the restored wallet matches the original
        assert_eq!(original.wallet_id, restored.wallet_id);
        assert_eq!(original.accounts.len(), restored.accounts.len());
    }

    #[test]
    fn test_restore_invalid_data() {
        let invalid_data = vec![0xFF, 0xFF, 0xFF, 0xFF];
        let result = Wallet::restore(&invalid_data);
        assert!(result.is_err());
    }
}
