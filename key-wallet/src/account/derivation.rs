use secp256k1::Secp256k1;
use crate::{Account, ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use crate::managed_account::address_pool::AddressPoolType;

impl Account {

    /// Derive an extended private key from a wallet's master private key
    ///
    /// This requires the wallet to have the master private key available.
    /// Returns None for watch-only wallets.
    pub fn derive_xpriv_from_master_xpriv(
        &self,
        master_xpriv: &ExtendedPrivKey,
    ) -> crate::Result<ExtendedPrivKey> {
        if self.is_watch_only {
            return Err(crate::error::Error::WatchOnly);
        }

        let secp = Secp256k1::new();
        let path = self.derivation_path()?;
        master_xpriv.derive_priv(&secp, &path).map_err(crate::error::Error::Bip32)
    }

    /// Derive a child private key at a specific path from the account
    ///
    /// This requires providing the account's extended private key.
    /// The path should be relative to the account (e.g., "0/5" for external address 5)
    pub fn derive_child_xpriv_from_account_xpriv(
        &self,
        account_xpriv: &ExtendedPrivKey,
        child_path: &DerivationPath,
    ) -> crate::Result<ExtendedPrivKey> {
        if self.is_watch_only {
            return Err(crate::error::Error::WatchOnly);
        }

        let secp = Secp256k1::new();
        account_xpriv.derive_priv(&secp, child_path).map_err(crate::error::Error::Bip32)
    }

    /// Derive a child public key at a specific path from the account
    ///
    /// The path should be relative to the account (e.g., "0/5" for external address 5)
    pub fn derive_child_xpub(&self, child_path: &DerivationPath) -> crate::Result<ExtendedPubKey> {
        let secp = Secp256k1::new();
        self.account_xpub.derive_pub(&secp, child_path).map_err(crate::error::Error::Bip32)
    }

    /// Derive an address at a specific chain and index
    ///
    /// # Arguments
    /// * `is_internal` - If true, derives from internal chain (1), otherwise external chain (0)
    /// * `index` - The address index
    ///
    /// # Example
    /// ```ignore
    /// let external_addr = account.derive_address_at(false, 5)?;  // Same as derive_receive_address(5)
    /// let internal_addr = account.derive_address_at(true, 3)?;   // Same as derive_change_address(3)
    /// ```
    pub fn derive_address_at(&self, address_pool_type: AddressPoolType, index: u32, use_hardened_with_priv_key: Option<ExtendedPrivKey>) -> crate::Result<dashcore::Address> {
        match address_pool_type {
            AddressPoolType::External => {
                let derivation_path = DerivationPath::from(vec![
                    ChildNumber::from_idx(1, use_hardened)?, // Internal chain
                    ChildNumber::from_idx(index, use_hardened)?,
                ]);
                let xpub = self.derive_child_xpub(&derivation_path)?;
                Ok(dashcore::Address::p2pkh(&xpub.to_pub(), self.network))
            }
            (AddressPoolType::External, true) => {
                let derivation_path = DerivationPath::from(vec![
                    ChildNumber::from_hardened_idx(1)?, // Internal chain
                    ChildNumber::from_hardened_idx(index)?,
                ]);
                let xpub = self.derive_child_xpub(&derivation_path)?;
                Ok(dashcore::Address::p2pkh(&xpub.to_pub(), self.network))
            }
            AddressPoolType::Internal => {
                self.derive_change_address_impl(index, use_hardened)
            }
            AddressPoolType::Absent => {

            }
        }
    }

    // Internal implementation methods to avoid name conflicts with trait defaults
    fn derive_receive_address_impl(&self, index: u32, use_hardened: bool) -> crate::Result<dashcore::Address> {
        use crate::bip32::ChildNumber;

        // Build path: 0/index (external chain)
        let path = DerivationPath::from(vec![
            ChildNumber::from_normal_idx(0)?, // External chain
            ChildNumber::from_normal_idx(index)?,
        ]);

        let xpub = self.derive_child_xpub(&path)?;
        // Convert secp256k1::PublicKey to dashcore::PublicKey
        let pubkey =
            dashcore::PublicKey::from_slice(&xpub.public_key.serialize()).map_err(|e| {
                crate::error::Error::InvalidParameter(format!("Invalid public key: {}", e))
            })?;
        Ok(dashcore::Address::p2pkh(&pubkey, self.network))
    }

    fn derive_change_address_impl(&self, index: u32) -> crate::Result<dashcore::Address> {
        use crate::bip32::ChildNumber;

        // Build path: 1/index (internal/change chain)
        let path =

        let xpub = self.derive_child_xpub(&path)?;
        // Convert secp256k1::PublicKey to dashcore::PublicKey
        let pubkey =
            dashcore::PublicKey::from_slice(&xpub.public_key.serialize()).map_err(|e| {
                crate::error::Error::InvalidParameter(format!("Invalid public key: {}", e))
            })?;
        Ok(dashcore::Address::p2pkh(&pubkey, self.network))
    }

}

#[cfg(test)]
mod tests {
    use crate::account::AccountTrait;
    use crate::account::tests::test_account;

    #[test]
    fn test_derive_receive_address() {
        let account = test_account();

        // Derive receive address at index 0
        let addr0 = account.derive_receive_address(0).unwrap();
        assert!(!addr0.to_string().is_empty());

        // Derive receive address at index 5
        let addr5 = account.derive_receive_address(5).unwrap();
        assert!(!addr5.to_string().is_empty());

        // Addresses at different indices should be different
        assert_ne!(addr0, addr5);
    }

    #[test]
    fn test_derive_change_address() {
        let account = test_account();

        // Derive change address at index 0
        let addr0 = account.derive_change_address(0).unwrap();
        assert!(!addr0.to_string().is_empty());

        // Derive change address at index 3
        let addr3 = account.derive_change_address(3).unwrap();
        assert!(!addr3.to_string().is_empty());

        // Addresses at different indices should be different
        assert_ne!(addr0, addr3);

        // Change address should be different from receive address at same index
        let receive0 = account.derive_receive_address(0).unwrap();
        assert_ne!(addr0, receive0);
    }

    #[test]
    fn test_derive_multiple_addresses() {
        let account = test_account();

        // Derive 5 receive addresses starting from index 0
        let receive_addrs = account.derive_receive_addresses(0, 5).unwrap();
        assert_eq!(receive_addrs.len(), 5);

        // All addresses should be unique
        let unique: std::collections::HashSet<_> = receive_addrs.iter().collect();
        assert_eq!(unique.len(), 5);

        // Derive 3 change addresses starting from index 2
        let change_addrs = account.derive_change_addresses(2, 3).unwrap();
        assert_eq!(change_addrs.len(), 3);

        // Verify the addresses match individual derivation
        assert_eq!(change_addrs[0], account.derive_change_address(2).unwrap());
        assert_eq!(change_addrs[1], account.derive_change_address(3).unwrap());
        assert_eq!(change_addrs[2], account.derive_change_address(4).unwrap());
    }

    #[test]
    fn test_derive_address_at() {
        let account = test_account();

        // External address at index 5
        let external5 = account.derive_address_at(false, 5).unwrap();
        let receive5 = account.derive_receive_address(5).unwrap();
        assert_eq!(external5, receive5);

        // Internal address at index 3
        let internal3 = account.derive_address_at(true, 3).unwrap();
        let change3 = account.derive_change_address(3).unwrap();
        assert_eq!(internal3, change3);
    }
}