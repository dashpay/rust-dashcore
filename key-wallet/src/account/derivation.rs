use secp256k1::Secp256k1;
use dashcore::{Address, PublicKey};
use crate::{Account, ChildNumber, DerivationPath, Error, ExtendedPrivKey, ExtendedPubKey};
use crate::managed_account::address_pool::AddressPoolType;

/// Derivation helpers available on an account-like type.
///
/// Notes:
/// - External/receive chain = `0`, internal/change chain = `1`.
/// - Hardened indices are in `[0, 2^31 - 1]` and marked `'` conceptually.
/// - Implementors may use private state (e.g., `is_watch_only`, `account_xpub`, `network`)
///   inside their concrete `impl` blocks; this trait only fixes the public API.
pub trait AccountDerivation<EPrivKeyType, EPubKeyType, PubKeyType> {
    /// Derive an extended private key from the wallet’s master xpriv
    /// using the implementor’s account derivation path.
    ///
    /// Returns an error for watch-only accounts.
    fn derive_xpriv_from_master_xpriv(
        &self,
        master_xpriv: &EPrivKeyType,
    ) -> Result<EPrivKeyType, Error>;

    /// Derive a child xpriv at a path **relative to the account** (e.g., `0/5`).
    ///
    /// Returns an error for watch-only accounts.
    fn derive_child_xpriv_from_account_xpriv(
        &self,
        account_xpriv: &EPrivKeyType,
        child_path: &DerivationPath,
    ) -> Result<EPrivKeyType, Error>;

    /// Derive a child xpub at a path **relative to the account** (e.g., `0/5`)
    /// from the account xpub.
    fn derive_child_xpub(&self, child_path: &DerivationPath) -> Result<EPubKeyType, Error>;


    /// Build the (chain, index) tail of a derivation path for the given address pool.
    ///
    /// This helper returns the last two components of a BIP32-style path:
    ///
    /// - **External chain** → `.../0/{index}`
    /// - **Internal (change) chain** → `.../1/{index}`
    /// - **Absent** → `.../{index}` (single component; used when the caller supplies
    ///   the full path prefix elsewhere)
    ///
    /// If `use_hardened` is `true`, both returned child indices are created as
    /// **hardened** (i.e., `index'`); otherwise they are **normal**. Indices must be
    /// in `[0, 2^31 - 1]`.
    ///
    /// # Parameters
    /// - `address_pool_type`: `External` (0), `Internal` (1), or `Absent`
    /// - `index`: address index within the selected chain
    /// - `use_hardened`: whether to create hardened child numbers
    ///
    /// # Returns
    /// A `DerivationPath` consisting of:
    /// - `External` → `[0, index]` (hardened if requested)
    /// - `Internal` → `[1, index]` (hardened if requested)
    /// - `Absent`   → `[index]`    (hardened if requested)
    fn derivation_path_for_index(
        address_pool_type: AddressPoolType,
        index: u32,
        use_hardened: bool,
    ) -> Result<DerivationPath, Error>
    where
        Self: Sized
        {
            Ok(match address_pool_type {
                AddressPoolType::External => {
                    DerivationPath::from(vec![
                        ChildNumber::from_idx(0, use_hardened)?, // External chain
                        ChildNumber::from_idx(index, use_hardened)?,
                    ])
                }
                AddressPoolType::Internal => {
                    DerivationPath::from(vec![
                        ChildNumber::from_idx(1, use_hardened)?, // Internal chain
                        ChildNumber::from_idx(index, use_hardened)?,
                    ])
                }
                AddressPoolType::Absent => {
                    DerivationPath::from(vec![
                        ChildNumber::from_idx(index, use_hardened)?,
                    ])
                }
            })
        }


    /// Derive an address at a specific chain (external/internal/absent) and index.
    ///
    /// If `use_hardened_with_priv_key` is `Some(xpriv)`, derive via xpriv (hardened allowed),
    /// otherwise derive public children from the account xpub (non-hardened).
    fn derive_address_at(
        &self,
        address_pool_type: AddressPoolType,
        index: u32,
        use_hardened_with_priv_key: Option<EPrivKeyType>,
    ) -> Result<Address, Error>;

    /// Derive a public key at a specific chain (external/internal/absent) and index.
    ///
    /// If `use_hardened_with_priv_key` is `Some(xpriv)`, derive via xpriv (hardened allowed),
    /// otherwise derive public children from the account xpub (non-hardened).
    fn derive_public_key_at(
        &self,
        address_pool_type: AddressPoolType,
        index: u32,
        use_hardened_with_priv_key: Option<EPrivKeyType>,
    ) -> Result<PubKeyType, Error>;

    /// Derive an extended public key at a specific chain (external/internal/absent) and index.
    ///
    /// If `use_hardened_with_priv_key` is `Some(xpriv)`, derive via xpriv (hardened allowed),
    /// otherwise derive public children from the account xpub (non-hardened).
    fn derive_extended_public_key_at(&self, address_pool_type: AddressPoolType, index: u32, use_hardened_with_priv_key: Option<EPrivKeyType>) -> Result<EPubKeyType, Error>;
}

#[cfg(test)]
mod tests {
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