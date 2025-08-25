//! Managed account structure with mutable state
//!
//! This module contains the mutable account state that changes during wallet operation,
//! kept separate from the immutable Account structure.

use crate::account::AccountMetadata;
use crate::account::TransactionRecord;
use crate::account::{BLSAccount, EdDSAAccount, ManagedAccountTrait};
use crate::derivation_bls_bip32::ExtendedBLSPubKey;
use crate::gap_limit::GapLimitManager;
use crate::managed_account::address_pool::PublicKeyType;
use crate::utxo::Utxo;
use crate::wallet::balance::WalletBalance;
use crate::{ExtendedPubKey, Network};
use alloc::collections::{BTreeMap, BTreeSet};
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
pub mod metadata;
pub mod transaction_record;

/// Managed account with mutable state
///
/// This struct contains the mutable state of an account including address pools,
/// gap limits, metadata, and balance information. It is managed separately from
/// the immutable Account structure.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ManagedAccount {
    /// Account type with embedded address pools and index
    pub account_type: ManagedAccountType,
    /// Network this account belongs to
    pub network: Network,
    /// Gap limit manager
    pub gap_limits: GapLimitManager,
    /// Account metadata
    pub metadata: AccountMetadata,
    /// Whether this is a watch-only account
    pub is_watch_only: bool,
    /// Account balance information
    pub balance: WalletBalance,
    /// Transaction history for this account
    pub transactions: BTreeMap<Txid, TransactionRecord>,
    /// Monitored addresses for transaction detection
    pub monitored_addresses: BTreeSet<Address>,
    /// UTXO set for this account
    pub utxos: BTreeMap<OutPoint, Utxo>,
}

impl ManagedAccount {
    /// Create a new managed account
    pub fn new(
        account_type: ManagedAccountType,
        network: Network,
        gap_limits: GapLimitManager,
        is_watch_only: bool,
    ) -> Self {
        Self {
            account_type,
            network,
            gap_limits,
            metadata: AccountMetadata::default(),
            is_watch_only,
            balance: WalletBalance::default(),
            transactions: BTreeMap::new(),
            monitored_addresses: BTreeSet::new(),
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

        Self::new(managed_type, account.network, GapLimitManager::default(), account.is_watch_only)
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

        Self::new(managed_type, account.network, GapLimitManager::default(), account.is_watch_only)
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

        Self::new(managed_type, account.network, GapLimitManager::default(), account.is_watch_only)
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
        let result = self.account_type.mark_address_used(address);

        // Update gap limits if address was marked as used
        if result {
            match &self.account_type {
                ManagedAccountType::Standard {
                    external_addresses,
                    internal_addresses,
                    ..
                } => {
                    if let Some(index) = external_addresses.address_index(address) {
                        self.gap_limits.external.mark_used(index);
                    } else if let Some(index) = internal_addresses.address_index(address) {
                        self.gap_limits.internal.mark_used(index);
                    }
                }
                _ => {
                    // For single-pool account types, update the external gap limit
                    for pool in self.account_type.address_pools() {
                        if let Some(index) = pool.address_index(address) {
                            self.gap_limits.external.mark_used(index);
                            break;
                        }
                    }
                }
            }
        }

        result
    }

    /// Update the account balance
    pub fn update_balance(
        &mut self,
        confirmed: u64,
        unconfirmed: u64,
        locked: u64,
    ) -> Result<(), crate::wallet::balance::BalanceError> {
        self.balance.update(confirmed, unconfirmed, locked)?;
        self.metadata.last_used = Some(Self::current_timestamp());
        Ok(())
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

            external_addresses.next_unused(&key_source).map_err(|e| match e {
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

            internal_addresses.next_unused(&key_source).map_err(|e| match e {
                crate::error::Error::NoKeySource => {
                    "No unused addresses available and no key source provided"
                }
                _ => "Failed to generate change address",
            })
        } else {
            Err("Cannot generate change address for non-standard account type")
        }
    }

    /// Generate the next address for non-standard accounts
    /// This method is for special accounts like Identity, Provider accounts, etc.
    /// Standard accounts (BIP44/BIP32) should use next_receive_address or next_change_address
    pub fn next_address(
        &mut self,
        account_xpub: Option<&ExtendedPubKey>,
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
            } => {
                // Create appropriate key source based on whether xpub is provided
                let key_source = match account_xpub {
                    Some(xpub) => address_pool::KeySource::Public(*xpub),
                    None => address_pool::KeySource::NoKeySource,
                };

                addresses.next_unused(&key_source).map_err(|e| match e {
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

                addresses.next_unused(&key_source).map_err(|e| match e {
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
            } => {
                // Create appropriate key source based on whether xpub is provided
                let key_source = match account_xpub {
                    Some(xpub) => address_pool::KeySource::Public(*xpub),
                    None => address_pool::KeySource::NoKeySource,
                };

                addresses.next_unused_with_info(&key_source).map_err(|e| match e {
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

                addresses.next_unused_with_info(&key_source).map_err(|e| match e {
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
                    .next_unused_with_info(&key_source)
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
    /// Returns the Ed25519 public key at the next unused index
    #[cfg(feature = "eddsa")]
    pub fn next_eddsa_platform_key(
        &mut self,
        account_xpriv: crate::derivation_slip10::ExtendedEd25519PrivKey,
    ) -> Result<crate::derivation_slip10::VerifyingKey, &'static str> {
        match &mut self.account_type {
            ManagedAccountType::ProviderPlatformKeys {
                addresses,
                ..
            } => {
                // Create key source from the EdDSA private key
                let key_source = address_pool::KeySource::EdDSAPrivate(account_xpriv);

                // Use next_unused_with_info to get the next address (handles caching and derivation)
                let info = addresses
                    .next_unused_with_info(&key_source)
                    .map_err(|_| "Failed to get next unused address")?;

                // Extract the EdDSA public key from the address info
                let Some(PublicKeyType::EdDSA(pub_key_bytes)) = info.public_key else {
                    return Err("Expected EdDSA public key but got different key type");
                };

                // Mark as used
                addresses.mark_index_used(info.index);

                let verifying_key = crate::derivation_slip10::VerifyingKey::from_bytes(
                    &pub_key_bytes.try_into().map_err(|_| "Invalid EdDSA public key length")?,
                )
                .map_err(|_| "Failed to deserialize EdDSA public key")?;

                Ok(verifying_key)
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
}

impl ManagedAccountTrait for ManagedAccount {
    fn account_type(&self) -> &ManagedAccountType {
        &self.account_type
    }

    fn account_type_mut(&mut self) -> &mut ManagedAccountType {
        &mut self.account_type
    }

    fn network(&self) -> Network {
        self.network
    }

    fn gap_limits(&self) -> &GapLimitManager {
        &self.gap_limits
    }

    fn gap_limits_mut(&mut self) -> &mut GapLimitManager {
        &mut self.gap_limits
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

    fn balance(&self) -> &WalletBalance {
        &self.balance
    }

    fn balance_mut(&mut self) -> &mut WalletBalance {
        &mut self.balance
    }

    fn transactions(&self) -> &BTreeMap<Txid, TransactionRecord> {
        &self.transactions
    }

    fn transactions_mut(&mut self) -> &mut BTreeMap<Txid, TransactionRecord> {
        &mut self.transactions
    }

    fn monitored_addresses(&self) -> &BTreeSet<Address> {
        &self.monitored_addresses
    }

    fn monitored_addresses_mut(&mut self) -> &mut BTreeSet<Address> {
        &mut self.monitored_addresses
    }

    fn utxos(&self) -> &BTreeMap<OutPoint, Utxo> {
        &self.utxos
    }

    fn utxos_mut(&mut self) -> &mut BTreeMap<OutPoint, Utxo> {
        &mut self.utxos
    }
}
