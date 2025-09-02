use crate::managed_account::address_pool::AddressPoolType;
use crate::mnemonic::Language;
use crate::{ChildNumber, DerivationPath, Error, Mnemonic};
use dashcore::Address;

/// Derivation helpers available on an account-like type.
///
/// Notes:
/// - External/receive chain = `0`, internal/change chain = `1`.
/// - Hardened indices are in `[0, 2^31 - 1]` and marked `'` conceptually.
/// - Implementors may use private state (e.g., `is_watch_only`, `account_xpub`, `network`)
///   inside their concrete `impl` blocks; this trait only fixes the public API.
pub trait AccountDerivation<EPrivKeyType, EPubKeyType, PubKeyType, PrivKeyType> {
    /// Whether this account's index derivations default to hardened.
    ///
    /// For example, Ed25519 (SLIP-0010) requires hardened-only derivation.
    fn defaults_to_hardened_derivation(&self) -> bool;

    /// Whether this account uses separate internal/external chains.
    ///
    /// If true, the simplified helpers below are not applicable and will return an error,
    /// since callers must specify which chain to use.
    fn has_internal_and_external(&self) -> bool {
        false
    }

    fn has_intermediate_derivation(&self) -> Option<ChildNumber> {
        None
    }

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
        Self: Sized,
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
                DerivationPath::from(vec![ChildNumber::from_idx(index, use_hardened)?])
            }
            AddressPoolType::AbsentHardened => {
                DerivationPath::from(vec![ChildNumber::from_idx(index, use_hardened)?])
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
    fn derive_extended_public_key_at(
        &self,
        address_pool_type: AddressPoolType,
        index: u32,
        use_hardened_with_priv_key: Option<EPrivKeyType>,
    ) -> Result<EPubKeyType, Error>;

    /// Derive an extended private key at the given chain and index
    /// starting from the wallet's master extended private key.
    ///
    /// Default implementation derives the account xpriv from master, then
    /// appends the (chain, index) tail. External/Internal use non-hardened
    /// indices; AbsentHardened uses hardened index.
    fn derive_from_master_xpriv_extended_xpriv_at(
        &self,
        master_xpriv: &EPrivKeyType,
        index: u32,
    ) -> Result<EPrivKeyType, Error>
    where
        Self: Sized,
    {
        // Disallow when account has both internal and external chains
        if self.has_internal_and_external() {
            return Err(Error::InvalidParameter(
                "Account has internal/external chains; chain-agnostic derivation not applicable"
                    .into(),
            ));
        }

        // Derive account-level xpriv first
        let account_xpriv = self.derive_xpriv_from_master_xpriv(master_xpriv)?;
        // Build the child derivation path relative to the account
        let child_path = if let Some(intermediate) = self.has_intermediate_derivation() {
            DerivationPath::from(vec![
                intermediate,
                ChildNumber::from_idx(index, self.defaults_to_hardened_derivation())?,
            ])
        } else {
            DerivationPath::from(vec![ChildNumber::from_idx(
                index,
                self.defaults_to_hardened_derivation(),
            )?])
        };
        // Derive the child extended private key
        self.derive_child_xpriv_from_account_xpriv(&account_xpriv, &child_path)
    }

    /// Derive a raw private key at the given chain and index
    /// starting from the wallet's master extended private key.
    fn derive_from_master_xpriv_private_key_at(
        &self,
        master_xpriv: &EPrivKeyType,
        index: u32,
    ) -> Result<PrivKeyType, Error>;

    /// Derive an extended private key from a raw seed at the given index.
    fn derive_from_seed_extended_xpriv_at(
        &self,
        seed: &[u8],
        index: u32,
    ) -> Result<EPrivKeyType, Error>;

    /// Derive a private key from a raw seed at the given index.
    fn derive_from_seed_private_key_at(
        &self,
        seed: &[u8],
        index: u32,
    ) -> Result<PrivKeyType, Error>;

    /// Derive an extended private key from a BIP39 mnemonic and optional passphrase at the given index.
    fn derive_from_mnemonic_extended_xpriv_at(
        &self,
        mnemonic: &str,
        passphrase: Option<&str>,
        language: Language,
        index: u32,
    ) -> Result<EPrivKeyType, Error> {
        let m = Mnemonic::from_phrase(mnemonic, language)?;
        let seed = m.to_seed(passphrase.unwrap_or(""));
        self.derive_from_seed_extended_xpriv_at(&seed, index)
    }

    /// Derive a private key from a BIP39 mnemonic and optional passphrase at the given index.
    fn derive_from_mnemonic_private_key_at(
        &self,
        mnemonic: &str,
        passphrase: Option<&str>,
        language: Language,
        index: u32,
    ) -> Result<PrivKeyType, Error> {
        let m = Mnemonic::from_phrase(mnemonic, language)?;
        let seed = m.to_seed(passphrase.unwrap_or(""));
        self.derive_from_seed_private_key_at(&seed, index)
    }
}
