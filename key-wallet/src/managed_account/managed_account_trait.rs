//! Trait for managed account functionality
//!
//! Defines the shared interface implemented by every "core" managed account
//! type (funds-bearing or keys-only). All cross-cutting logic that does not
//! depend on funds bookkeeping (balance / UTXOs / spent outpoints) lives here
//! as default-method implementations so it is written exactly once.

use std::collections::BTreeMap;

use crate::account::TransactionRecord;
#[cfg(feature = "bls")]
use crate::derivation_bls_bip32::ExtendedBLSPubKey;
use crate::managed_account::address_pool;
#[cfg(any(feature = "bls", feature = "eddsa"))]
use crate::managed_account::address_pool::PublicKeyType;
use crate::managed_account::managed_account_type::ManagedAccountType;
#[cfg(feature = "eddsa")]
use crate::AddressInfo;
use crate::ExtendedPubKey;
use crate::Network;
use dashcore::{Address, ScriptBuf, Txid};

/// Common trait for "core" managed account types — both funds-bearing
/// (`ManagedCoreFundsAccount`) and keys-only (`ManagedCoreKeysAccount`).
///
/// Implementors only need to provide the small set of primitive accessors
/// listed under "Required" below. Everything else is defaulted in terms of
/// those accessors plus methods on the embedded [`ManagedAccountType`].
pub trait ManagedAccountTrait {
    // ----- Required: primitive accessors -----

    /// Get the managed account type (address pools + variant data)
    fn managed_account_type(&self) -> &ManagedAccountType;

    /// Get mutable managed account type
    fn managed_account_type_mut(&mut self) -> &mut ManagedAccountType;

    /// Get the network
    fn network(&self) -> Network;

    /// Check if this is a watch-only account
    fn is_watch_only(&self) -> bool;

    /// Get transactions
    fn transactions(&self) -> &BTreeMap<Txid, TransactionRecord>;

    /// Get mutable transactions
    fn transactions_mut(&mut self) -> &mut BTreeMap<Txid, TransactionRecord>;

    /// Return the current monitor revision.
    ///
    /// Bumped whenever the monitored address set changes (e.g. new addresses
    /// generated). Used to detect bloom-filter staleness.
    fn monitor_revision(&self) -> u64;

    /// Increment the monitor revision to signal that the monitored address set changed.
    fn bump_monitor_revision(&mut self);

    // ----- Provided: defaults built on the primitives above -----

    /// Get the account index
    fn index(&self) -> Option<u32> {
        self.managed_account_type().index()
    }

    /// Get the account index or 0 if none exists
    fn index_or_default(&self) -> u32 {
        self.managed_account_type().index_or_default()
    }

    /// Get the managed account type (alias for [`Self::managed_account_type`])
    fn managed_type(&self) -> &ManagedAccountType {
        self.managed_account_type()
    }

    /// Get the next unused receive address index for standard accounts
    fn get_next_receive_address_index(&self) -> Option<u32> {
        if let ManagedAccountType::Standard {
            external_addresses,
            ..
        } = self.managed_account_type()
        {
            if let Some(addr) = external_addresses.unused_addresses().first() {
                external_addresses.address_index(addr)
            } else {
                let stats = external_addresses.stats();
                Some(stats.highest_generated.map(|h| h + 1).unwrap_or(0))
            }
        } else {
            None
        }
    }

    /// Get the next unused change address index for standard accounts
    fn get_next_change_address_index(&self) -> Option<u32> {
        if let ManagedAccountType::Standard {
            internal_addresses,
            ..
        } = self.managed_account_type()
        {
            if let Some(addr) = internal_addresses.unused_addresses().first() {
                internal_addresses.address_index(addr)
            } else {
                let stats = internal_addresses.stats();
                Some(stats.highest_generated.map(|h| h + 1).unwrap_or(0))
            }
        } else {
            None
        }
    }

    /// Get the next unused address index for single-pool account types
    fn get_next_address_index(&self) -> Option<u32> {
        match self.managed_account_type() {
            ManagedAccountType::Standard {
                ..
            } => self.get_next_receive_address_index(),
            ManagedAccountType::CoinJoin {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityRegistration {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityTopUp {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityTopUpNotBoundToIdentity {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityInvitation {
                addresses,
                ..
            }
            | ManagedAccountType::AssetLockAddressTopUp {
                addresses,
                ..
            }
            | ManagedAccountType::AssetLockShieldedAddressTopUp {
                addresses,
                ..
            }
            | ManagedAccountType::ProviderVotingKeys {
                addresses,
                ..
            }
            | ManagedAccountType::ProviderOwnerKeys {
                addresses,
                ..
            }
            | ManagedAccountType::ProviderOperatorKeys {
                addresses,
                ..
            }
            | ManagedAccountType::ProviderPlatformKeys {
                addresses,
                ..
            }
            | ManagedAccountType::DashpayReceivingFunds {
                addresses,
                ..
            }
            | ManagedAccountType::DashpayExternalAccount {
                addresses,
                ..
            }
            | ManagedAccountType::PlatformPayment {
                addresses,
                ..
            } => {
                addresses.unused_addresses().first().and_then(|addr| addresses.address_index(addr))
            }
        }
    }

    /// Mark an address as used
    fn mark_address_used(&mut self, address: &Address) -> bool {
        self.managed_account_type_mut().mark_address_used(address)
    }

    /// Get all addresses from all pools
    fn all_addresses(&self) -> Vec<Address> {
        self.managed_account_type().all_addresses()
    }

    /// Check if an address belongs to this account
    fn contains_address(&self, address: &Address) -> bool {
        self.managed_account_type().contains_address(address)
    }

    /// Check if a script pub key belongs to this account
    fn contains_script_pub_key(&self, script_pub_key: &ScriptBuf) -> bool {
        self.managed_account_type().contains_script_pub_key(script_pub_key)
    }

    /// Get address info for a given address
    fn get_address_info(&self, address: &Address) -> Option<address_pool::AddressInfo> {
        self.managed_account_type().get_address_info(address)
    }

    /// Generate the next address for non-standard (single-pool) account types.
    ///
    /// For Standard accounts, use `next_receive_address` / `next_change_address`
    /// on the funds-bearing variant instead.
    fn next_address(
        &mut self,
        account_xpub: Option<&ExtendedPubKey>,
        add_to_state: bool,
    ) -> Result<Address, &'static str> {
        match self.managed_account_type_mut() {
            ManagedAccountType::Standard {
                ..
            } => Err("Standard accounts must use next_receive_address or next_change_address"),
            ManagedAccountType::CoinJoin {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityRegistration {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityTopUp {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityTopUpNotBoundToIdentity {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityInvitation {
                addresses,
                ..
            }
            | ManagedAccountType::AssetLockAddressTopUp {
                addresses,
                ..
            }
            | ManagedAccountType::AssetLockShieldedAddressTopUp {
                addresses,
                ..
            }
            | ManagedAccountType::ProviderVotingKeys {
                addresses,
                ..
            }
            | ManagedAccountType::ProviderOwnerKeys {
                addresses,
                ..
            }
            | ManagedAccountType::ProviderOperatorKeys {
                addresses,
                ..
            }
            | ManagedAccountType::ProviderPlatformKeys {
                addresses,
                ..
            }
            | ManagedAccountType::DashpayReceivingFunds {
                addresses,
                ..
            }
            | ManagedAccountType::DashpayExternalAccount {
                addresses,
                ..
            }
            | ManagedAccountType::PlatformPayment {
                addresses,
                ..
            } => {
                let key_source = match account_xpub {
                    Some(xpub) => address_pool::KeySource::Public(*xpub),
                    None => address_pool::KeySource::NoKeySource,
                };

                addresses.next_unused(&key_source, add_to_state).map_err(|e| match e {
                    crate::error::Error::NoKeySource => {
                        "No unused addresses available and no key source provided"
                    }
                    _ => "Failed to generate address",
                })
            }
        }
    }

    /// Generate the next address with full info for non-standard account types.
    fn next_address_with_info(
        &mut self,
        account_xpub: Option<&ExtendedPubKey>,
        add_to_state: bool,
    ) -> Result<address_pool::AddressInfo, &'static str> {
        match self.managed_account_type_mut() {
            ManagedAccountType::Standard {
                ..
            } => Err(
                "Standard accounts must use next_receive_address_with_info or next_change_address_with_info",
            ),
            ManagedAccountType::CoinJoin {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityRegistration {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityTopUp {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityTopUpNotBoundToIdentity {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityInvitation {
                addresses,
                ..
            }
            | ManagedAccountType::AssetLockAddressTopUp {
                addresses,
                ..
            }
            | ManagedAccountType::AssetLockShieldedAddressTopUp {
                addresses,
                ..
            }
            | ManagedAccountType::ProviderVotingKeys {
                addresses,
                ..
            }
            | ManagedAccountType::ProviderOwnerKeys {
                addresses,
                ..
            }
            | ManagedAccountType::ProviderOperatorKeys {
                addresses,
                ..
            }
            | ManagedAccountType::ProviderPlatformKeys {
                addresses,
                ..
            }
            | ManagedAccountType::DashpayReceivingFunds {
                addresses,
                ..
            }
            | ManagedAccountType::DashpayExternalAccount {
                addresses,
                ..
            }
            | ManagedAccountType::PlatformPayment {
                addresses,
                ..
            } => {
                let key_source = match account_xpub {
                    Some(xpub) => address_pool::KeySource::Public(*xpub),
                    None => address_pool::KeySource::NoKeySource,
                };

                addresses.next_unused_with_info(&key_source, add_to_state).map_err(|e| match e {
                    crate::error::Error::NoKeySource => {
                        "No unused addresses available and no key source provided"
                    }
                    _ => "Failed to generate address with info",
                })
            }
        }
    }

    /// Generate the next BLS operator key (only for ProviderOperatorKeys accounts)
    #[cfg(feature = "bls")]
    fn next_bls_operator_key(
        &mut self,
        account_xpub: Option<ExtendedBLSPubKey>,
        add_to_state: bool,
    ) -> Result<dashcore::blsful::PublicKey<dashcore::blsful::Bls12381G2Impl>, &'static str> {
        match self.managed_account_type_mut() {
            ManagedAccountType::ProviderOperatorKeys {
                addresses,
                ..
            } => {
                let key_source = match account_xpub {
                    Some(xpub) => address_pool::KeySource::BLSPublic(xpub),
                    None => address_pool::KeySource::NoKeySource,
                };

                let info = addresses
                    .next_unused_with_info(&key_source, add_to_state)
                    .map_err(|_| "Failed to get next unused address")?;

                let Some(PublicKeyType::BLS(pub_key_bytes)) = info.public_key else {
                    return Err("Expected BLS public key but got different key type");
                };

                addresses.mark_index_used(info.index);

                use dashcore::blsful::{Bls12381G2Impl, PublicKey, SerializationFormat};
                let public_key = PublicKey::<Bls12381G2Impl>::from_bytes_with_mode(
                    &pub_key_bytes,
                    SerializationFormat::Modern,
                )
                .map_err(|_| "Failed to deserialize BLS public key")?;

                Ok(public_key)
            }
            _ => Err("This method only works for ProviderOperatorKeys accounts"),
        }
    }

    /// Generate the next EdDSA platform key (only for ProviderPlatformKeys accounts)
    #[cfg(feature = "eddsa")]
    fn next_eddsa_platform_key(
        &mut self,
        account_xpriv: crate::derivation_slip10::ExtendedEd25519PrivKey,
        add_to_state: bool,
    ) -> Result<(crate::derivation_slip10::VerifyingKey, AddressInfo), &'static str> {
        match self.managed_account_type_mut() {
            ManagedAccountType::ProviderPlatformKeys {
                addresses,
                ..
            } => {
                let key_source = address_pool::KeySource::EdDSAPrivate(account_xpriv);

                let info = addresses
                    .next_unused_with_info(&key_source, add_to_state)
                    .map_err(|_| "Failed to get next unused address")?;

                let Some(PublicKeyType::EdDSA(pub_key_bytes)) = info.public_key.clone() else {
                    return Err("Expected EdDSA public key but got different key type");
                };

                addresses.mark_index_used(info.index);

                let verifying_key = crate::derivation_slip10::VerifyingKey::from_bytes(
                    &pub_key_bytes.try_into().map_err(|_| "Invalid EdDSA public key length")?,
                )
                .map_err(|_| "Failed to deserialize EdDSA public key")?;

                Ok((verifying_key, info))
            }
            _ => Err("This method only works for ProviderPlatformKeys accounts"),
        }
    }

    /// Consume the next unused address and derive its private key.
    fn next_private_key(
        &mut self,
        root_xpriv: &crate::wallet::root_extended_keys::RootExtendedPrivKey,
        network: Network,
    ) -> Result<[u8; 32], &'static str> {
        if matches!(self.managed_account_type(), ManagedAccountType::Standard { .. }) {
            return Err("Standard accounts must use next_receive_address or next_change_address");
        }

        let mut pools = self.managed_account_type_mut().address_pools_mut();
        let pool = pools.first_mut().ok_or("Account has no address pool")?;

        let info = pool
            .next_unused_with_info(&address_pool::KeySource::NoKeySource, false)
            .map_err(|_| "No unused address available")?;

        pool.mark_index_used(info.index);

        let secp = secp256k1::Secp256k1::new();
        let root_ext_priv = root_xpriv.to_extended_priv_key(network);
        let derived_xpriv =
            root_ext_priv.derive_priv(&secp, &info.path).map_err(|_| "Key derivation failed")?;

        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&derived_xpriv.private_key[..]);
        Ok(private_key)
    }

    /// Peek at the next unused address's path and index without marking the index used.
    fn peek_next_path(&mut self) -> Result<(crate::DerivationPath, u32), &'static str> {
        if matches!(self.managed_account_type(), ManagedAccountType::Standard { .. }) {
            return Err("Standard accounts must use next_receive_address or next_change_address");
        }

        let mut pools = self.managed_account_type_mut().address_pools_mut();
        let pool = pools.first_mut().ok_or("Account has no address pool")?;

        let info = pool
            .next_unused_with_info(&address_pool::KeySource::NoKeySource, false)
            .map_err(|_| "No unused address available")?;

        Ok((info.path, info.index))
    }

    /// Mark an index on the account's first address pool as used.
    fn mark_first_pool_index_used(&mut self, index: u32) -> Result<(), &'static str> {
        if matches!(self.managed_account_type(), ManagedAccountType::Standard { .. }) {
            return Err("Standard accounts must use next_receive_address or next_change_address");
        }

        let mut pools = self.managed_account_type_mut().address_pools_mut();
        let pool = pools.first_mut().ok_or("Account has no address pool")?;
        pool.mark_index_used(index);
        Ok(())
    }

    /// Consume the next unused address and return only its derivation path.
    fn next_path(&mut self) -> Result<crate::DerivationPath, &'static str> {
        let (path, index) = self.peek_next_path()?;
        self.mark_first_pool_index_used(index)?;
        Ok(path)
    }

    /// Get the derivation path for an address if it belongs to this account
    fn address_derivation_path(&self, address: &Address) -> Option<crate::DerivationPath> {
        self.managed_account_type().get_address_derivation_path(address)
    }

    /// Get total address count across all pools
    fn total_address_count(&self) -> usize {
        self.managed_account_type()
            .address_pools()
            .iter()
            .map(|pool| pool.stats().total_generated as usize)
            .sum()
    }

    /// Get used address count across all pools
    fn used_address_count(&self) -> usize {
        self.managed_account_type()
            .address_pools()
            .iter()
            .map(|pool| pool.stats().used_count as usize)
            .sum()
    }

    /// Get the gap limit for non-standard (single-pool) accounts
    fn gap_limit(&self) -> Option<u32> {
        match self.managed_account_type() {
            ManagedAccountType::Standard {
                ..
            } => None,
            ManagedAccountType::CoinJoin {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityRegistration {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityTopUp {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityTopUpNotBoundToIdentity {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityInvitation {
                addresses,
                ..
            }
            | ManagedAccountType::AssetLockAddressTopUp {
                addresses,
                ..
            }
            | ManagedAccountType::AssetLockShieldedAddressTopUp {
                addresses,
                ..
            }
            | ManagedAccountType::ProviderVotingKeys {
                addresses,
                ..
            }
            | ManagedAccountType::ProviderOwnerKeys {
                addresses,
                ..
            }
            | ManagedAccountType::ProviderOperatorKeys {
                addresses,
                ..
            }
            | ManagedAccountType::ProviderPlatformKeys {
                addresses,
                ..
            }
            | ManagedAccountType::DashpayReceivingFunds {
                addresses,
                ..
            }
            | ManagedAccountType::DashpayExternalAccount {
                addresses,
                ..
            }
            | ManagedAccountType::PlatformPayment {
                addresses,
                ..
            } => Some(addresses.gap_limit),
        }
    }
}
