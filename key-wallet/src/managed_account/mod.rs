//! Managed account structure with mutable state
//!
//! This module contains the mutable account state that changes during wallet operation,
//! kept separate from the immutable Account structure.

use crate::account::AccountMetadata;
#[cfg(feature = "bls")]
use crate::account::BLSAccount;
#[cfg(feature = "eddsa")]
use crate::account::EdDSAAccount;
use crate::account::ManagedAccountTrait;
use crate::account::TransactionRecord;
#[cfg(feature = "bls")]
use crate::derivation_bls_bip32::ExtendedBLSPubKey;
#[cfg(any(feature = "bls", feature = "eddsa"))]
use crate::managed_account::address_pool::PublicKeyType;
use crate::utxo::Utxo;
use crate::wallet::balance::WalletCoreBalance;
#[cfg(feature = "eddsa")]
use crate::AddressInfo;
use crate::{ExtendedPubKey, Network};
use alloc::collections::BTreeMap;
use dashcore::blockdata::transaction::OutPoint;
use dashcore::Txid;
use dashcore::{Address, ScriptBuf};
use managed_account_type::ManagedAccountType;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub mod address_pool;
pub mod managed_account_collection;
pub mod managed_account_trait;
pub mod managed_account_type;
pub mod managed_platform_account;
pub mod metadata;
pub mod platform_address;
pub mod transaction_record;

/// Managed account with mutable state
///
/// This struct contains the mutable state of an account including address pools,
/// metadata, and balance information. It is managed separately from
/// the immutable Account structure.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ManagedCoreAccount {
    /// Account type with embedded address pools and index
    pub account_type: ManagedAccountType,
    /// Network this account belongs to
    pub network: Network,
    /// Account metadata
    pub metadata: AccountMetadata,
    /// Whether this is a watch-only account
    pub is_watch_only: bool,
    /// Account balance information
    pub balance: WalletCoreBalance,
    /// Transaction history for this account
    pub transactions: BTreeMap<Txid, TransactionRecord>,
    /// UTXO set for this account
    pub utxos: BTreeMap<OutPoint, Utxo>,
}

impl ManagedCoreAccount {
    /// Create a new managed account
    pub fn new(account_type: ManagedAccountType, network: Network, is_watch_only: bool) -> Self {
        Self {
            account_type,
            network,
            metadata: AccountMetadata::default(),
            is_watch_only,
            balance: WalletCoreBalance::default(),
            transactions: BTreeMap::new(),
            utxos: BTreeMap::new(),
        }
    }

    /// Create a ManagedAccount from an Account
    pub fn from_account(account: &super::Account) -> Self {
        // Use the account's public key as the key source
        let key_source = address_pool::KeySource::Public(account.account_xpub);
        let managed_type = ManagedAccountType::from_account_type(
            account.account_type,
            account.network,
            &key_source,
        )
        .unwrap_or_else(|_| {
            // Fallback: create without pre-generated addresses
            let no_key_source = address_pool::KeySource::NoKeySource;
            ManagedAccountType::from_account_type(
                account.account_type,
                account.network,
                &no_key_source,
            )
            .expect("Should succeed with NoKeySource")
        });

        Self::new(managed_type, account.network, account.is_watch_only)
    }

    /// Create a ManagedAccount from a BLS Account
    #[cfg(feature = "bls")]
    pub fn from_bls_account(account: &BLSAccount) -> Self {
        // Use the BLS public key as the key source
        let key_source = address_pool::KeySource::BLSPublic(account.bls_public_key.clone());
        let managed_type = ManagedAccountType::from_account_type(
            account.account_type,
            account.network,
            &key_source,
        )
        .unwrap_or_else(|_| {
            // Fallback: create without pre-generated addresses
            let no_key_source = address_pool::KeySource::NoKeySource;
            ManagedAccountType::from_account_type(
                account.account_type,
                account.network,
                &no_key_source,
            )
            .expect("Should succeed with NoKeySource")
        });

        Self::new(managed_type, account.network, account.is_watch_only)
    }

    /// Create a ManagedAccount from an EdDSA Account
    #[cfg(feature = "eddsa")]
    pub fn from_eddsa_account(account: &EdDSAAccount) -> Self {
        // EdDSA requires hardened derivation, so we can't generate addresses without private key
        let key_source = address_pool::KeySource::NoKeySource;
        let managed_type = ManagedAccountType::from_account_type(
            account.account_type,
            account.network,
            &key_source,
        )
        .expect("Should succeed with NoKeySource");

        Self::new(managed_type, account.network, account.is_watch_only)
    }

    /// Get the account index
    pub fn index(&self) -> Option<u32> {
        self.account_type.index()
    }

    /// Get the account index or 0 if none exists
    pub fn index_or_default(&self) -> u32 {
        self.account_type.index_or_default()
    }

    /// Get the managed account type
    pub fn managed_type(&self) -> &ManagedAccountType {
        &self.account_type
    }

    /// Get the next unused receive address index for standard accounts
    /// Note: This requires a key source which is not available in ManagedAccount
    /// Address generation should be done through a method that has access to the Account's keys
    pub fn get_next_receive_address_index(&self) -> Option<u32> {
        // Only applicable for standard accounts
        if let ManagedAccountType::Standard {
            external_addresses,
            ..
        } = &self.account_type
        {
            // Get the first unused address or the next index after the last used one
            if let Some(addr) = external_addresses.unused_addresses().first() {
                external_addresses.address_index(addr)
            } else {
                // If no unused addresses, return the next index based on stats
                let stats = external_addresses.stats();
                Some(stats.highest_generated.map(|h| h + 1).unwrap_or(0))
            }
        } else {
            None
        }
    }

    /// Get the next unused change address index for standard accounts
    /// Note: This requires a key source which is not available in ManagedAccount
    /// Address generation should be done through a method that has access to the Account's keys
    pub fn get_next_change_address_index(&self) -> Option<u32> {
        // Only applicable for standard accounts
        if let ManagedAccountType::Standard {
            internal_addresses,
            ..
        } = &self.account_type
        {
            // Get the first unused address or the next index after the last used one
            if let Some(addr) = internal_addresses.unused_addresses().first() {
                internal_addresses.address_index(addr)
            } else {
                // If no unused addresses, return the next index based on stats
                let stats = internal_addresses.stats();
                Some(stats.highest_generated.map(|h| h + 1).unwrap_or(0))
            }
        } else {
            None
        }
    }

    /// Get the next unused address index for single-pool account types
    pub fn get_next_address_index(&self) -> Option<u32> {
        match &self.account_type {
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
    pub fn mark_address_used(&mut self, address: &Address) -> bool {
        // Update metadata timestamp
        self.metadata.last_used = Some(Self::current_timestamp());

        // Use the account type's mark_address_used method
        // The address pools already track gap limits internally
        self.account_type.mark_address_used(address)
    }

    /// Update the account balance
    pub fn update_balance(&mut self, synced_height: u32) {
        let mut spendable = 0;
        let mut unconfirmed = 0;
        let mut immature = 0;
        let mut locked = 0;
        for utxo in self.utxos.values() {
            let value = utxo.txout.value;
            if utxo.is_locked {
                locked += value;
            } else if !utxo.is_mature(synced_height) {
                immature += value;
            } else if utxo.is_spendable(synced_height) {
                spendable += value;
            } else {
                unconfirmed += value;
            }
        }
        self.balance = WalletCoreBalance::new(spendable, unconfirmed, immature, locked);
        self.metadata.last_used = Some(Self::current_timestamp());
    }

    /// Get all addresses from all pools
    pub fn all_addresses(&self) -> Vec<Address> {
        self.account_type.all_addresses()
    }

    /// Check if an address belongs to this account
    pub fn contains_address(&self, address: &Address) -> bool {
        self.account_type.contains_address(address)
    }

    /// Check if a script pub key belongs to this account
    pub fn contains_script_pub_key(&self, script_pub_key: &ScriptBuf) -> bool {
        self.account_type.contains_script_pub_key(script_pub_key)
    }

    /// Get address info for a given address
    pub fn get_address_info(&self, address: &Address) -> Option<address_pool::AddressInfo> {
        self.account_type.get_address_info(address)
    }

    /// Generate the next receive address using the optionally provided extended public key
    /// If no key is provided, can only return pre-generated unused addresses
    /// This method derives a new address from the account's xpub but does not add it to the pool
    /// The address must be added to the pool separately with proper tracking
    pub fn next_receive_address(
        &mut self,
        account_xpub: Option<&ExtendedPubKey>,
        add_to_state: bool,
    ) -> Result<Address, &'static str> {
        // For standard accounts, use the address pool to get the next unused address
        if let ManagedAccountType::Standard {
            external_addresses,
            ..
        } = &mut self.account_type
        {
            // Create appropriate key source based on whether xpub is provided
            let key_source = match account_xpub {
                Some(xpub) => address_pool::KeySource::Public(*xpub),
                None => address_pool::KeySource::NoKeySource,
            };

            external_addresses.next_unused(&key_source, add_to_state).map_err(|e| match e {
                crate::error::Error::NoKeySource => {
                    "No unused addresses available and no key source provided"
                }
                _ => "Failed to generate receive address",
            })
        } else {
            Err("Cannot generate receive address for non-standard account type")
        }
    }

    /// Generate the next change address using the optionally provided extended public key
    /// If no key is provided, can only return pre-generated unused addresses
    /// This method uses the address pool to properly track and generate addresses
    pub fn next_change_address(
        &mut self,
        account_xpub: Option<&ExtendedPubKey>,
        add_to_state: bool,
    ) -> Result<Address, &'static str> {
        // For standard accounts, use the address pool to get the next unused address
        if let ManagedAccountType::Standard {
            internal_addresses,
            ..
        } = &mut self.account_type
        {
            // Create appropriate key source based on whether xpub is provided
            let key_source = match account_xpub {
                Some(xpub) => address_pool::KeySource::Public(*xpub),
                None => address_pool::KeySource::NoKeySource,
            };

            internal_addresses.next_unused(&key_source, add_to_state).map_err(|e| match e {
                crate::error::Error::NoKeySource => {
                    "No unused addresses available and no key source provided"
                }
                _ => "Failed to generate change address",
            })
        } else {
            Err("Cannot generate change address for non-standard account type")
        }
    }

    /// Generate multiple receive addresses at once using the optionally provided extended public key
    ///
    /// Returns the requested number of unused receive addresses, generating new ones if needed.
    /// This is more efficient than calling `next_receive_address` multiple times.
    /// If no key is provided, can only return pre-generated unused addresses.
    pub fn next_receive_addresses(
        &mut self,
        account_xpub: Option<&ExtendedPubKey>,
        count: usize,
        add_to_state: bool,
    ) -> Result<Vec<Address>, String> {
        // For standard accounts, use the address pool to get multiple unused addresses
        if let ManagedAccountType::Standard {
            external_addresses,
            ..
        } = &mut self.account_type
        {
            // Create appropriate key source based on whether xpub is provided
            let key_source = match account_xpub {
                Some(xpub) => address_pool::KeySource::Public(*xpub),
                None => address_pool::KeySource::NoKeySource,
            };

            let addresses =
                external_addresses.next_unused_multiple(count, &key_source, add_to_state);
            if addresses.is_empty() && count > 0 {
                Err("Failed to generate any receive addresses".to_string())
            } else if addresses.len() < count
                && matches!(key_source, address_pool::KeySource::NoKeySource)
            {
                Err(format!(
                    "Could only generate {} out of {} requested addresses (no key source)",
                    addresses.len(),
                    count
                ))
            } else {
                Ok(addresses)
            }
        } else {
            Err("Cannot generate receive addresses for non-standard account type".to_string())
        }
    }

    /// Generate multiple change addresses at once using the optionally provided extended public key
    ///
    /// Returns the requested number of unused change addresses, generating new ones if needed.
    /// This is more efficient than calling `next_change_address` multiple times.
    /// If no key is provided, can only return pre-generated unused addresses.
    pub fn next_change_addresses(
        &mut self,
        account_xpub: Option<&ExtendedPubKey>,
        count: usize,
        add_to_state: bool,
    ) -> Result<Vec<Address>, String> {
        // For standard accounts, use the address pool to get multiple unused addresses
        if let ManagedAccountType::Standard {
            internal_addresses,
            ..
        } = &mut self.account_type
        {
            // Create appropriate key source based on whether xpub is provided
            let key_source = match account_xpub {
                Some(xpub) => address_pool::KeySource::Public(*xpub),
                None => address_pool::KeySource::NoKeySource,
            };

            let addresses =
                internal_addresses.next_unused_multiple(count, &key_source, add_to_state);
            if addresses.is_empty() && count > 0 {
                Err("Failed to generate any change addresses".to_string())
            } else if addresses.len() < count
                && matches!(key_source, address_pool::KeySource::NoKeySource)
            {
                Err(format!(
                    "Could only generate {} out of {} requested addresses (no key source)",
                    addresses.len(),
                    count
                ))
            } else {
                Ok(addresses)
            }
        } else {
            Err("Cannot generate change addresses for non-standard account type".to_string())
        }
    }

    /// Generate the next address for non-standard accounts
    /// This method is for special accounts like Identity, Provider accounts, etc.
    /// Standard accounts (BIP44/BIP32) should use next_receive_address or next_change_address
    pub fn next_address(
        &mut self,
        account_xpub: Option<&ExtendedPubKey>,
        add_to_state: bool,
    ) -> Result<Address, &'static str> {
        match &mut self.account_type {
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
            | ManagedAccountType::IdentityTopUpNotBoundToIdentity {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityInvitation {
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
                // Create appropriate key source based on whether xpub is provided
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
            ManagedAccountType::IdentityTopUp {
                addresses,
                ..
            } => {
                // Identity top-up has an address pool
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

    /// Generate the next address with full info for non-standard accounts
    /// This method is for special accounts like Identity, Provider accounts, etc.
    /// Standard accounts (BIP44/BIP32) should use next_receive_address_with_info or next_change_address_with_info
    pub fn next_address_with_info(
        &mut self,
        account_xpub: Option<&ExtendedPubKey>,
        add_to_state: bool,
    ) -> Result<address_pool::AddressInfo, &'static str> {
        match &mut self.account_type {
            ManagedAccountType::Standard {
                ..
            } => Err("Standard accounts must use next_receive_address_with_info or next_change_address_with_info"),
            ManagedAccountType::CoinJoin {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityRegistration {
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
                // Create appropriate key source based on whether xpub is provided
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
            ManagedAccountType::IdentityTopUp {
                addresses,
                ..
            } => {
                // Identity top-up has an address pool
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
    /// Returns the BLS public key at the next unused index
    #[cfg(feature = "bls")]
    pub fn next_bls_operator_key(
        &mut self,
        account_xpub: Option<ExtendedBLSPubKey>,
        add_to_state: bool,
    ) -> Result<dashcore::blsful::PublicKey<dashcore::blsful::Bls12381G2Impl>, &'static str> {
        match &mut self.account_type {
            ManagedAccountType::ProviderOperatorKeys {
                addresses,
                ..
            } => {
                // Create key source from the optional BLS public key
                let key_source = match account_xpub {
                    Some(xpub) => address_pool::KeySource::BLSPublic(xpub),
                    None => address_pool::KeySource::NoKeySource,
                };

                // Use next_unused_with_info to get the next address (handles caching and derivation)
                let info = addresses
                    .next_unused_with_info(&key_source, add_to_state)
                    .map_err(|_| "Failed to get next unused address")?;

                // Extract the BLS public key from the address info
                let Some(PublicKeyType::BLS(pub_key_bytes)) = info.public_key else {
                    return Err("Expected BLS public key but got different key type");
                };

                // Mark as used
                addresses.mark_index_used(info.index);

                // Convert bytes to BLS public key
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
    /// Returns the Ed25519 public key and address info at the next unused index
    #[cfg(feature = "eddsa")]
    pub fn next_eddsa_platform_key(
        &mut self,
        account_xpriv: crate::derivation_slip10::ExtendedEd25519PrivKey,
        add_to_state: bool,
    ) -> Result<(crate::derivation_slip10::VerifyingKey, AddressInfo), &'static str> {
        match &mut self.account_type {
            ManagedAccountType::ProviderPlatformKeys {
                addresses,
                ..
            } => {
                // Create key source from the EdDSA private key
                let key_source = address_pool::KeySource::EdDSAPrivate(account_xpriv);

                // Use next_unused_with_info to get the next address (handles caching and derivation)
                let info = addresses
                    .next_unused_with_info(&key_source, add_to_state)
                    .map_err(|_| "Failed to get next unused address")?;

                // Extract the EdDSA public key from the address info
                let Some(PublicKeyType::EdDSA(pub_key_bytes)) = info.public_key.clone() else {
                    return Err("Expected EdDSA public key but got different key type");
                };

                // Mark as used
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

    /// Get the derivation path for an address if it belongs to this account
    pub fn address_derivation_path(&self, address: &Address) -> Option<crate::DerivationPath> {
        self.account_type.get_address_derivation_path(address)
    }

    /// Get the current timestamp (for metadata)
    fn current_timestamp() -> u64 {
        #[cfg(feature = "std")]
        {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        }
        #[cfg(not(feature = "std"))]
        {
            0 // In no_std environments, timestamp must be provided externally
        }
    }

    /// Get total address count across all pools
    pub fn total_address_count(&self) -> usize {
        self.account_type
            .address_pools()
            .iter()
            .map(|pool| pool.stats().total_generated as usize)
            .sum()
    }

    /// Get used address count across all pools
    pub fn used_address_count(&self) -> usize {
        self.account_type.address_pools().iter().map(|pool| pool.stats().used_count as usize).sum()
    }

    /// Get the external gap limit for standard accounts
    pub fn external_gap_limit(&self) -> Option<u32> {
        match &self.account_type {
            ManagedAccountType::Standard {
                external_addresses,
                ..
            } => Some(external_addresses.gap_limit),
            _ => None,
        }
    }

    /// Get the internal gap limit for standard accounts
    pub fn internal_gap_limit(&self) -> Option<u32> {
        match &self.account_type {
            ManagedAccountType::Standard {
                internal_addresses,
                ..
            } => Some(internal_addresses.gap_limit),
            _ => None,
        }
    }

    /// Get the gap limit for non-standard (single-pool) accounts
    pub fn gap_limit(&self) -> Option<u32> {
        match &self.account_type {
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

impl ManagedAccountTrait for ManagedCoreAccount {
    fn account_type(&self) -> &ManagedAccountType {
        &self.account_type
    }

    fn account_type_mut(&mut self) -> &mut ManagedAccountType {
        &mut self.account_type
    }

    fn network(&self) -> Network {
        self.network
    }

    fn metadata(&self) -> &AccountMetadata {
        &self.metadata
    }

    fn metadata_mut(&mut self) -> &mut AccountMetadata {
        &mut self.metadata
    }

    fn is_watch_only(&self) -> bool {
        self.is_watch_only
    }

    fn balance(&self) -> &WalletCoreBalance {
        &self.balance
    }

    fn balance_mut(&mut self) -> &mut WalletCoreBalance {
        &mut self.balance
    }

    fn transactions(&self) -> &BTreeMap<Txid, TransactionRecord> {
        &self.transactions
    }

    fn transactions_mut(&mut self) -> &mut BTreeMap<Txid, TransactionRecord> {
        &mut self.transactions
    }

    fn utxos(&self) -> &BTreeMap<OutPoint, Utxo> {
        &self.utxos
    }

    fn utxos_mut(&mut self) -> &mut BTreeMap<OutPoint, Utxo> {
        &mut self.utxos
    }
}
