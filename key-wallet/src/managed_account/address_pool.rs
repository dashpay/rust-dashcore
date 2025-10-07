//! Address pool management for HD wallets
//!
//! This module provides comprehensive address pool management including
//! generation, usage tracking, and discovery.

use alloc::string::String;
use alloc::vec::Vec;
#[cfg(feature = "bincode")]
use bincode_derive::{Decode, Encode};
use core::fmt;
use secp256k1::Secp256k1;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

use crate::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use crate::error::{Error, Result};
use crate::Network;
use dashcore::{Address, AddressType, ScriptBuf};
use crate::gap_limit::DEFAULT_EXTERNAL_GAP_LIMIT;

/// Types of public keys used in the address pool
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[allow(clippy::upper_case_acronyms)]
pub enum PublicKeyType {
    /// ECDSA public key (standard Bitcoin/Dash addresses) - stored as Vec<u8> for serialization
    ECDSA(Vec<u8>),
    /// EdDSA public key (Ed25519, used in some Platform operations)
    EdDSA(Vec<u8>),
    /// BLS public key (used for masternode operations and Platform)
    BLS(Vec<u8>),
}

/// Type of address pool (external, internal, or absent/single-pool)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub enum AddressPoolType {
    /// External (receive) addresses - used for receiving funds
    External,
    /// Internal (change) addresses - used for transaction change
    Internal,
    /// Absent/single pool - for special account types that don't distinguish
    Absent,
    /// Absent/single pool - uses hardened derivation
    AbsentHardened,
}

#[cfg(feature = "serde")]
impl Serialize for PublicKeyType {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        #[allow(clippy::upper_case_acronyms)]
        enum PublicKeyTypeSer<'a> {
            ECDSA(&'a Vec<u8>),
            EdDSA(&'a Vec<u8>),
            BLS(&'a Vec<u8>),
        }

        match self {
            PublicKeyType::ECDSA(bytes) => PublicKeyTypeSer::ECDSA(bytes).serialize(serializer),
            PublicKeyType::EdDSA(bytes) => PublicKeyTypeSer::EdDSA(bytes).serialize(serializer),
            PublicKeyType::BLS(bytes) => PublicKeyTypeSer::BLS(bytes).serialize(serializer),
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for PublicKeyType {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[allow(clippy::upper_case_acronyms)]
        enum PublicKeyTypeDe {
            ECDSA(Vec<u8>),
            EdDSA(Vec<u8>),
            BLS(Vec<u8>),
        }

        match PublicKeyTypeDe::deserialize(deserializer)? {
            PublicKeyTypeDe::ECDSA(bytes) => Ok(PublicKeyType::ECDSA(bytes)),
            PublicKeyTypeDe::EdDSA(bytes) => Ok(PublicKeyType::EdDSA(bytes)),
            PublicKeyTypeDe::BLS(bytes) => Ok(PublicKeyType::BLS(bytes)),
        }
    }
}

/// Key source for address derivation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub enum KeySource {
    /// ECDSA private key for full wallet
    Private(ExtendedPrivKey),
    /// ECDSA public key for watch-only wallet
    Public(ExtendedPubKey),
    /// BLS private key for HD derivation
    #[cfg(feature = "bls")]
    BLSPrivate(crate::derivation_bls_bip32::ExtendedBLSPrivKey),
    /// BLS public key for HD derivation
    #[cfg(feature = "bls")]
    BLSPublic(crate::derivation_bls_bip32::ExtendedBLSPubKey),
    /// EdDSA private key
    #[cfg(feature = "eddsa")]
    EdDSAPrivate(crate::derivation_slip10::ExtendedEd25519PrivKey),
    /// EdDSA public key
    #[cfg(feature = "eddsa")]
    EdDSAPublic(crate::derivation_slip10::ExtendedEd25519PubKey),
    /// No key source available (can only return pre-generated addresses)
    NoKeySource,
}

/// Result of key derivation that can contain different key types
#[derive(Debug, Clone)]
pub enum DerivedKey {
    /// ECDSA extended public key
    ECDSA(ExtendedPubKey),
    /// BLS public key (48 bytes)
    BLS(Vec<u8>),
    /// EdDSA public key (32 bytes)
    EdDSA(Vec<u8>),
}

impl KeySource {
    /// Derive a child key at the given path
    /// Returns a DerivedKey which can be ECDSA, BLS, or EdDSA
    pub fn derive_at_path(&self, path: &DerivationPath) -> Result<DerivedKey> {
        match self {
            KeySource::Private(xprv) => {
                let secp = Secp256k1::new();
                let child = xprv.derive_priv(&secp, path).map_err(Error::Bip32)?;
                Ok(DerivedKey::ECDSA(ExtendedPubKey::from_priv(&secp, &child)))
            }
            KeySource::Public(xpub) => {
                let secp = Secp256k1::new();
                let derived = xpub.derive_pub(&secp, path).map_err(Error::Bip32)?;
                Ok(DerivedKey::ECDSA(derived))
            }
            #[cfg(feature = "bls")]
            KeySource::BLSPrivate(xprv) => {
                // BLS HD derivation using the proper BIP32-like derivation
                let mut derived = xprv.clone();
                for child_num in path.as_ref() {
                    derived = derived.derive_priv(*child_num).map_err(|e| {
                        Error::InvalidParameter(format!("BLS derivation error: {:?}", e))
                    })?;
                }
                Ok(DerivedKey::BLS(derived.public_key_bytes().to_vec()))
            }
            #[cfg(feature = "bls")]
            KeySource::BLSPublic(xpub) => {
                // BLS public key derivation for non-hardened paths
                let mut derived = xpub.clone();
                for child_num in path.as_ref() {
                    if child_num.is_hardened() {
                        return Err(Error::InvalidParameter(
                            "Cannot derive hardened child from BLS public key".into(),
                        ));
                    }
                    derived = derived.derive_pub(*child_num).map_err(|e| {
                        Error::InvalidParameter(format!("BLS public derivation error: {:?}", e))
                    })?;
                }
                Ok(DerivedKey::BLS(derived.to_bytes().to_vec()))
            }
            #[cfg(feature = "eddsa")]
            KeySource::EdDSAPrivate(xprv) => {
                // EdDSA uses SLIP-0010 hardened-only derivation
                let mut derived = xprv.clone();
                for child_num in path.as_ref() {
                    derived = derived.derive_priv(&[*child_num])?;
                }
                let pubkey = derived.public_key()?;
                Ok(DerivedKey::EdDSA(pubkey.to_bytes().to_vec()))
            }
            #[cfg(feature = "eddsa")]
            KeySource::EdDSAPublic(_xpub) => {
                // EdDSA public key derivation is not supported (hardened-only)
                Err(Error::InvalidParameter(
                    "EdDSA public key derivation not supported (hardened-only)".into(),
                ))
            }
            KeySource::NoKeySource => Err(Error::NoKeySource),
        }
    }

    /// Legacy method for ECDSA-only derivation (for backward compatibility)
    pub fn derive_ecdsa_at_path(&self, path: &DerivationPath) -> Result<ExtendedPubKey> {
        match self.derive_at_path(path)? {
            DerivedKey::ECDSA(xpub) => Ok(xpub),
            _ => Err(Error::InvalidParameter("Key source is not ECDSA".into())),
        }
    }

    /// Check if this is a watch-only key source
    pub fn is_watch_only(&self) -> bool {
        matches!(self, KeySource::Public(_))
    }

    /// Check if key source is available for derivation
    pub fn can_derive(&self) -> bool {
        !matches!(self, KeySource::NoKeySource)
    }
}

/// Information about a single address in the pool
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct AddressInfo {
    /// The address
    pub address: Address,
    /// The script pubkey for this address
    pub script_pubkey: ScriptBuf,
    /// The public key used to derive this address
    pub public_key: Option<PublicKeyType>,
    /// Derivation index
    pub index: u32,
    /// Full derivation path
    pub path: DerivationPath,
    /// Whether this address has been used
    pub used: bool,
    /// When the address was first generated (timestamp)
    pub generated_at: u64,
    /// When the address was first used (timestamp)
    pub used_at: Option<u64>,
    /// Transaction count for this address
    pub tx_count: u32,
    /// Total received amount
    pub total_received: u64,
    /// Total sent amount
    pub total_sent: u64,
    /// Current balance
    pub balance: u64,
    /// Custom label
    pub label: Option<String>,
    /// Custom metadata
    pub metadata: BTreeMap<String, String>,
}

impl AddressInfo {
    /// Create new address info with a public key
    fn new_with_public_key(
        address: Address,
        index: u32,
        path: DerivationPath,
        public_key: PublicKeyType,
    ) -> Self {
        let script_pubkey = address.script_pubkey();
        Self {
            address,
            script_pubkey,
            public_key: Some(public_key),
            index,
            path,
            used: false,
            generated_at: 0, // Should use actual timestamp
            used_at: None,
            tx_count: 0,
            total_received: 0,
            total_sent: 0,
            balance: 0,
            label: None,
            metadata: BTreeMap::new(),
        }
    }

    /// Create new address info from a P2PKH script pubkey
    pub fn new_from_script_pubkey_p2pkh(
        script_pubkey: ScriptBuf,
        index: u32,
        path: DerivationPath,
        network: Network,
    ) -> Result<Self> {
        // Try to extract the address from the P2PKH script
        let address = Address::from_script(&script_pubkey, network)
            .map_err(|_| Error::InvalidAddress("Failed to parse P2PKH script".to_string()))?;

        // Verify it's actually a P2PKH address
        if address.address_type() != Some(AddressType::P2pkh) {
            return Err(Error::InvalidAddress("Script is not P2PKH".to_string()));
        }

        Ok(Self {
            address,
            script_pubkey,
            public_key: None, // Public key not available from script alone
            index,
            path,
            used: false,
            generated_at: 0, // Should use actual timestamp
            used_at: None,
            tx_count: 0,
            total_received: 0,
            total_sent: 0,
            balance: 0,
            label: None,
            metadata: BTreeMap::new(),
        })
    }

    /// Mark this address as used
    fn mark_used(&mut self) {
        if !self.used {
            self.used = true;
            self.used_at = Some(0); // Should use actual timestamp
        }
    }

    /// Update transaction statistics
    pub fn update_stats(&mut self, received: u64, sent: u64) {
        self.total_received += received;
        self.total_sent += sent;
        self.tx_count += 1;
    }
}

/// Address pool for managing HD wallet addresses
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct AddressPool {
    /// Base derivation path for this pool
    pub base_path: DerivationPath,
    /// Type of address pool (external, internal, or absent)
    pub pool_type: AddressPoolType,
    /// Gap limit for this pool
    pub gap_limit: u32,
    /// Network for address generation
    pub network: Network,
    /// All addresses in the pool
    pub addresses: BTreeMap<u32, AddressInfo>,
    /// Reverse lookup: address -> index
    pub address_index: HashMap<Address, u32>,
    /// Reverse lookup: script pubkey -> index
    pub script_pubkey_index: HashMap<ScriptBuf, u32>,
    /// Set of used address indices
    pub used_indices: HashSet<u32>,
    /// Highest generated index (None if no addresses generated yet)
    pub highest_generated: Option<u32>,
    /// Highest used index
    pub highest_used: Option<u32>,
    /// Lookahead window for performance
    pub lookahead_size: u32,
    /// Address type preference
    pub address_type: AddressType,
}

impl AddressPool {
    /// Create a new address pool and generate addresses up to the gap limit
    pub fn new(
        base_path: DerivationPath,
        pool_type: AddressPoolType,
        gap_limit: u32,
        network: Network,
        key_source: &KeySource,
    ) -> Result<Self> {
        let mut pool = Self::new_without_generation(base_path, pool_type, gap_limit, network);

        // Generate addresses up to the gap limit if we have a key source
        if !matches!(key_source, KeySource::NoKeySource) {
            pool.generate_addresses(gap_limit, key_source, true)?;
        }

        Ok(pool)
    }

    /// Create a new address pool without generating any addresses
    pub fn new_without_generation(
        base_path: DerivationPath,
        pool_type: AddressPoolType,
        gap_limit: u32,
        network: Network,
    ) -> Self {
        Self {
            base_path,
            pool_type,
            gap_limit,
            network,
            addresses: BTreeMap::new(),
            address_index: HashMap::new(),
            script_pubkey_index: HashMap::new(),
            used_indices: HashSet::new(),
            highest_generated: None,
            highest_used: None,
            lookahead_size: gap_limit * 2,
            address_type: AddressType::P2pkh,
        }
    }

    /// Set the address type for new addresses
    pub fn set_address_type(&mut self, address_type: AddressType) {
        self.address_type = address_type;
    }

    /// Check if this is an internal (change) address pool
    pub fn is_internal(&self) -> bool {
        self.pool_type == AddressPoolType::Internal
    }

    /// Check if this is an external (receive) address pool
    pub fn is_external(&self) -> bool {
        self.pool_type == AddressPoolType::External
    }

    /// Generate addresses up to the specified count
    pub fn generate_addresses(
        &mut self,
        count: u32,
        key_source: &KeySource,
        add_to_state: bool,
    ) -> Result<Vec<Address>> {
        let mut new_addresses = Vec::new();
        let start_index = self.highest_generated.map(|h| h + 1).unwrap_or(0);
        let end_index = start_index + count;

        for index in start_index..end_index {
            let address = self.generate_address_at_index(index, key_source, add_to_state)?;
            new_addresses.push(address);
        }

        Ok(new_addresses)
    }

    /// Generate a specific address at an index
    pub(crate) fn generate_address_at_index(
        &mut self,
        index: u32,
        key_source: &KeySource,
        add_to_state: bool,
    ) -> Result<Address> {
        // Check if already generated
        if let Some(info) = self.addresses.get(&index) {
            return Ok(info.address.clone());
        }

        // Build the full path for record keeping
        let mut full_path = self.base_path.clone();
        full_path.push(ChildNumber::from_normal_idx(index).map_err(Error::Bip32)?);

        // For derivation, we need the relative path from where the key_source is
        // The key_source xpub is at account level (e.g., m/44'/1'/0')
        // For standard accounts: [0, index] for external or [1, index] for internal
        // For special accounts (Absent): just [index] with no branch distinction
        let relative_path =
            match self.pool_type {
                AddressPoolType::External => DerivationPath::from(vec![
                    ChildNumber::from_normal_idx(0).map_err(Error::Bip32)?,
                    ChildNumber::from_normal_idx(index).map_err(Error::Bip32)?,
                ]),
                AddressPoolType::Internal => DerivationPath::from(vec![
                    ChildNumber::from_normal_idx(1).map_err(Error::Bip32)?,
                    ChildNumber::from_normal_idx(index).map_err(Error::Bip32)?,
                ]),
                AddressPoolType::Absent => DerivationPath::from(vec![
                    ChildNumber::from_normal_idx(index).map_err(Error::Bip32)?,
                ]),
                AddressPoolType::AbsentHardened => DerivationPath::from(vec![
                    ChildNumber::from_hardened_idx(index).map_err(Error::Bip32)?,
                ]),
            };

        // Derive the key using the relative path
        let derived_key = key_source.derive_at_path(&relative_path)?;

        // Generate the address and public key type based on the derived key type
        let (address, public_key_type) = match derived_key {
            DerivedKey::ECDSA(xpub) => {
                // Standard ECDSA address generation
                let dash_pubkey = dashcore::PublicKey::new(xpub.public_key);
                let network = self.network;
                let address = match self.address_type {
                    AddressType::P2pkh => Address::p2pkh(&dash_pubkey, network),
                    AddressType::P2sh => {
                        // For P2SH, we'd need script information
                        // For now, default to P2PKH
                        Address::p2pkh(&dash_pubkey, network)
                    }
                    _ => {
                        // For other address types, default to P2PKH
                        Address::p2pkh(&dash_pubkey, network)
                    }
                };
                let public_key_bytes = dash_pubkey.to_bytes();
                (address, PublicKeyType::ECDSA(public_key_bytes.to_vec()))
            }
            DerivedKey::BLS(public_key_bytes) => {
                // BLS addresses use Hash160 of the public key bytes
                use dashcore::hashes::{hash160, Hash};
                let pubkey_hash = hash160::Hash::hash(&public_key_bytes);

                // Create P2PKH address from the hash
                use dashcore::address::Payload;
                let payload = Payload::PubkeyHash(pubkey_hash.into());
                let address = Address::new(self.network, payload);

                (address, PublicKeyType::BLS(public_key_bytes))
            }
            DerivedKey::EdDSA(public_key_bytes) => {
                // EdDSA addresses use Hash160 of the public key bytes
                use dashcore::hashes::{hash160, Hash};
                let pubkey_hash = hash160::Hash::hash(&public_key_bytes);

                // Create P2PKH address from the hash
                use dashcore::address::Payload;
                let payload = Payload::PubkeyHash(pubkey_hash.into());
                let address = Address::new(self.network, payload);

                (address, PublicKeyType::EdDSA(public_key_bytes))
            }
        };
        let info =
            AddressInfo::new_with_public_key(address.clone(), index, full_path, public_key_type);
        let script_pubkey = info.script_pubkey.clone();
        if add_to_state {
            self.addresses.insert(index, info);
            self.address_index.insert(address.clone(), index);
            self.script_pubkey_index.insert(script_pubkey, index);

            // Update highest generated
            if self.highest_generated.map(|h| index > h).unwrap_or(true) {
                self.highest_generated = Some(index);
            }
        }

        Ok(address)
    }

    /// Get the next unused address
    pub fn next_unused(&mut self, key_source: &KeySource, add_to_state: bool) -> Result<Address> {
        // First, try to find an already generated unused address
        for i in 0..=self.highest_generated.unwrap_or(0) {
            if let Some(info) = self.addresses.get(&i) {
                if !info.used {
                    return Ok(info.address.clone());
                }
            }
        }

        // If NoKeySource, we can't generate new addresses
        if matches!(key_source, KeySource::NoKeySource) {
            return Err(Error::NoKeySource);
        }

        // Generate a new address
        let next_index = self.highest_generated.map(|h| h + 1).unwrap_or(0);
        self.generate_address_at_index(next_index, key_source, add_to_state)
    }

    /// Get the next unused address info
    pub fn next_unused_with_info(
        &mut self,
        key_source: &KeySource,
        add_to_state: bool,
    ) -> Result<AddressInfo> {
        // First, try to find an already generated unused address
        for i in 0..=self.highest_generated.unwrap_or(0) {
            if let Some(info) = self.addresses.get(&i) {
                if !info.used {
                    return Ok(info.clone());
                }
            }
        }

        // If NoKeySource, we can't generate new addresses
        if matches!(key_source, KeySource::NoKeySource) {
            return Err(Error::NoKeySource);
        }

        // Generate a new address
        let next_index = self.highest_generated.map(|h| h + 1).unwrap_or(0);
        self.generate_address_at_index(next_index, key_source, add_to_state)?;

        // Return the AddressInfo we just created
        self.addresses.get(&next_index).cloned().ok_or_else(|| {
            Error::InvalidParameter("Failed to retrieve generated address info".into())
        })
    }

    /// Get multiple unused addresses at once
    ///
    /// Returns the requested number of unused addresses, generating new ones if needed.
    /// This is more efficient than calling `next_unused` multiple times as it minimizes
    /// the search through existing addresses.
    pub fn next_unused_multiple(
        &mut self,
        count: usize,
        key_source: &KeySource,
        add_to_state: bool,
    ) -> Vec<Address> {
        let mut addresses = Vec::with_capacity(count);

        // First, collect existing unused addresses
        let mut collected = 0;
        for i in 0..=self.highest_generated.unwrap_or(0) {
            if collected >= count {
                break;
            }
            if let Some(info) = self.addresses.get(&i) {
                if !info.used {
                    addresses.push(info.address.clone());
                    collected += 1;
                }
            }
        }

        // If we have enough unused addresses, return them
        if addresses.len() >= count {
            addresses.truncate(count);
            return addresses;
        }

        // If NoKeySource and we don't have enough addresses, return what we have
        if matches!(key_source, KeySource::NoKeySource) {
            return addresses;
        }

        // Generate new addresses to fill the remaining count
        let remaining = count - addresses.len();
        let start_index = self.highest_generated.map(|h| h + 1).unwrap_or(0);

        for i in 0..remaining {
            if let Ok(address) =
                self.generate_address_at_index(start_index + i as u32, key_source, add_to_state)
            {
                addresses.push(address);
            } else {
                // If generation fails, return what we have so far
                break;
            }
        }

        addresses
    }

    /// Get multiple unused addresses with their info at once
    ///
    /// Returns the requested number of unused addresses with their full information,
    /// generating new ones if needed. This is more efficient than calling
    /// `next_unused_with_info` multiple times.
    pub fn next_unused_multiple_with_info(
        &mut self,
        count: usize,
        key_source: &KeySource,
        add_to_state: bool,
    ) -> Vec<(Address, AddressInfo)> {
        let mut result = Vec::with_capacity(count);

        // First, collect existing unused addresses with their info
        let mut collected = 0;
        for i in 0..=self.highest_generated.unwrap_or(0) {
            if collected >= count {
                break;
            }
            if let Some(info) = self.addresses.get(&i) {
                if !info.used {
                    result.push((info.address.clone(), info.clone()));
                    collected += 1;
                }
            }
        }

        // If we have enough unused addresses, return them
        if result.len() >= count {
            result.truncate(count);
            return result;
        }

        // If NoKeySource and we don't have enough addresses, return what we have
        if matches!(key_source, KeySource::NoKeySource) {
            return result;
        }

        // Generate new addresses with info to fill the remaining count
        let remaining = count - result.len();
        let start_index = self.highest_generated.map(|h| h + 1).unwrap_or(0);

        for i in 0..remaining {
            let index = start_index + i as u32;
            if self.generate_address_at_index(index, key_source, add_to_state).is_ok() {
                if let Some(info) = self.addresses.get(&index) {
                    result.push((info.address.clone(), info.clone()));
                }
            } else {
                // If generation fails, return what we have so far
                break;
            }
        }

        result
    }

    /// Get multiple unused addresses
    pub fn unused_addresses_count(
        &mut self,
        count: u32,
        key_source: &KeySource,
    ) -> Result<Vec<Address>> {
        let mut unused = Vec::new();
        let mut current_index = 0;

        // Collect existing unused addresses
        while unused.len() < count as usize
            && self.highest_generated.map(|h| current_index <= h).unwrap_or(false)
        {
            if let Some(info) = self.addresses.get(&current_index) {
                if !info.used {
                    unused.push(info.address.clone());
                }
            }
            current_index += 1;
        }

        // Generate more if needed
        while unused.len() < count as usize {
            let next_index = self.highest_generated.map(|h| h + 1).unwrap_or(0);
            let address = self.generate_address_at_index(next_index, key_source, true)?;
            unused.push(address);
        }

        Ok(unused)
    }

    /// Mark an address as used
    pub fn mark_used(&mut self, address: &Address) -> bool {
        if let Some(&index) = self.address_index.get(address) {
            if let Some(info) = self.addresses.get_mut(&index) {
                if !info.used {
                    info.mark_used();
                    self.used_indices.insert(index);

                    // Update highest used
                    self.highest_used = match self.highest_used {
                        None => Some(index),
                        Some(current) => Some(current.max(index)),
                    };

                    return true;
                }
            }
        }
        false
    }

    /// Mark an address at a specific index as used
    pub fn mark_index_used(&mut self, index: u32) -> bool {
        if let Some(info) = self.addresses.get_mut(&index) {
            if !info.used {
                info.mark_used();
                self.used_indices.insert(index);

                // Update highest used
                self.highest_used = match self.highest_used {
                    None => Some(index),
                    Some(current) => Some(current.max(index)),
                };

                return true;
            }
        }
        false
    }

    /// Scan addresses for usage using a check function
    pub fn scan_for_usage<F>(&mut self, check_fn: F) -> Vec<Address>
    where
        F: Fn(&Address) -> bool,
    {
        let mut found = Vec::new();

        for (_, info) in self.addresses.iter_mut() {
            if !info.used && check_fn(&info.address) {
                info.mark_used();
                self.used_indices.insert(info.index);
                found.push(info.address.clone());

                // Update highest used
                self.highest_used = match self.highest_used {
                    None => Some(info.index),
                    Some(current) => Some(current.max(info.index)),
                };
            }
        }

        found
    }

    /// Get all addresses in the pool
    pub fn all_addresses(&self) -> Vec<Address> {
        self.addresses.values().map(|info| info.address.clone()).collect()
    }

    /// Get only used addresses
    pub fn used_addresses(&self) -> Vec<Address> {
        self.addresses.values().filter(|info| info.used).map(|info| info.address.clone()).collect()
    }

    /// Get only unused addresses
    pub fn unused_addresses(&self) -> Vec<Address> {
        self.addresses.values().filter(|info| !info.used).map(|info| info.address.clone()).collect()
    }

    /// Get address at specific index
    pub fn address_at_index(&self, index: u32) -> Option<Address> {
        self.addresses.get(&index).map(|info| info.address.clone())
    }

    /// Get address info by address
    pub fn address_info(&self, address: &Address) -> Option<&AddressInfo> {
        self.address_index.get(address).and_then(|&index| self.addresses.get(&index))
    }

    /// Get mutable address info by address
    pub fn address_info_mut(&mut self, address: &Address) -> Option<&mut AddressInfo> {
        if let Some(&index) = self.address_index.get(address) {
            self.addresses.get_mut(&index)
        } else {
            None
        }
    }

    /// Get address info by index
    pub fn info_at_index(&self, index: u32) -> Option<&AddressInfo> {
        self.addresses.get(&index)
    }

    /// Get the index of an address
    pub fn address_index(&self, address: &Address) -> Option<u32> {
        self.address_index.get(address).copied()
    }

    /// Get the index of an address by its script pubkey
    pub fn script_pubkey_index(&self, script_pubkey: &ScriptBuf) -> Option<u32> {
        self.script_pubkey_index.get(script_pubkey).copied()
    }

    /// Check if an address belongs to this pool
    pub fn contains_address(&self, address: &Address) -> bool {
        self.address_index.contains_key(address)
    }

    /// Check if a script pubkey belongs to this pool
    pub fn contains_script_pubkey(&self, script_pubkey: &ScriptBuf) -> bool {
        self.script_pubkey_index.contains_key(script_pubkey)
    }

    /// Get addresses in the specified range
    ///
    /// Returns addresses from start_index (inclusive) to end_index (exclusive).
    /// If addresses in the range haven't been generated yet, they will be generated.
    pub fn address_range(
        &mut self,
        start_index: u32,
        end_index: u32,
        key_source: &KeySource,
    ) -> Result<Vec<Address>> {
        if end_index <= start_index {
            return Ok(Vec::new());
        }

        // Generate addresses up to end_index if needed
        let current_highest = self.highest_generated.unwrap_or(0);
        if end_index > current_highest + 1 {
            // Generate from current_highest + 1 to end_index - 1
            for index in (current_highest + 1)..end_index {
                self.generate_address_at_index(index, key_source, true)?;
            }
        }

        // Collect addresses in the range
        let mut addresses = Vec::new();
        for index in start_index..end_index {
            if let Some(info) = self.addresses.get(&index) {
                addresses.push(info.address.clone());
            }
        }

        Ok(addresses)
    }

    /// Check if we need to generate more addresses
    pub fn needs_more_addresses(&self) -> bool {
        let unused_count = self.addresses.values().filter(|info| !info.used).count() as u32;

        unused_count < self.gap_limit
    }

    /// Generate addresses to maintain the gap limit
    pub fn maintain_gap_limit(&mut self, key_source: &KeySource) -> Result<Vec<Address>> {
        let target = match self.highest_used {
            None => self.gap_limit,
            Some(highest) => highest + self.gap_limit + 1,
        };

        let mut new_addresses = Vec::new();
        while self.highest_generated.unwrap_or(0) < target {
            let next_index = self.highest_generated.map(|h| h + 1).unwrap_or(0);
            let address = self.generate_address_at_index(next_index, key_source, true)?;
            new_addresses.push(address);
        }

        Ok(new_addresses)
    }

    /// Generate lookahead addresses for performance
    pub fn generate_lookahead(&mut self, key_source: &KeySource) -> Result<Vec<Address>> {
        let target = match self.highest_used {
            None => self.lookahead_size,
            Some(highest) => highest + self.lookahead_size + 1,
        };

        let mut new_addresses = Vec::new();
        while self.highest_generated.unwrap_or(0) < target {
            let next_index = self.highest_generated.map(|h| h + 1).unwrap_or(0);
            let address = self.generate_address_at_index(next_index, key_source, true)?;
            new_addresses.push(address);
        }

        Ok(new_addresses)
    }

    /// Set a custom label for an address
    pub fn set_address_label(&mut self, address: &Address, label: String) -> bool {
        if let Some(info) = self.address_info_mut(address) {
            info.label = Some(label);
            true
        } else {
            false
        }
    }

    /// Add custom metadata to an address
    pub fn add_address_metadata(&mut self, address: &Address, key: String, value: String) -> bool {
        if let Some(info) = self.address_info_mut(address) {
            info.metadata.insert(key, value);
            true
        } else {
            false
        }
    }

    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        let used_count = self.used_indices.len() as u32;
        let unused_count = self.addresses.len() as u32 - used_count;

        PoolStats {
            total_generated: self.addresses.len() as u32,
            used_count,
            unused_count,
            highest_used: self.highest_used,
            highest_generated: self.highest_generated,
            gap_limit: self.gap_limit,
            is_internal: self.is_internal(),
        }
    }

    /// Reset the pool (for rescan)
    pub fn reset_usage(&mut self) {
        for info in self.addresses.values_mut() {
            info.used = false;
            info.used_at = None;
            info.tx_count = 0;
            info.total_received = 0;
            info.total_sent = 0;
            info.balance = 0;
        }
        self.used_indices.clear();
        self.highest_used = None;
    }

    /// Prune unused addresses beyond the gap limit
    pub fn prune_unused(&mut self) -> u32 {
        let keep_until = match self.highest_used {
            None => self.gap_limit - 1, // Keep indices 0 to gap_limit-1
            Some(highest) => highest + self.gap_limit, // Keep up to highest + gap_limit
        };

        let mut pruned = 0;
        let indices_to_remove: Vec<u32> = self
            .addresses
            .keys()
            .filter(|&&idx| idx > keep_until && !self.used_indices.contains(&idx))
            .copied()
            .collect();

        for idx in indices_to_remove {
            if let Some(info) = self.addresses.remove(&idx) {
                self.address_index.remove(&info.address);
                pruned += 1;
            }
        }

        if let Some(&new_highest) = self.addresses.keys().max() {
            self.highest_generated = Some(new_highest);
        }

        pruned
    }
}

/// Pool statistics
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PoolStats {
    /// Total addresses generated
    pub total_generated: u32,
    /// Number of used addresses
    pub used_count: u32,
    /// Number of unused addresses
    pub unused_count: u32,
    /// Highest used index
    pub highest_used: Option<u32>,
    /// Highest generated index (None if no addresses generated)
    pub highest_generated: Option<u32>,
    /// Gap limit
    pub gap_limit: u32,
    /// Whether this is an internal pool
    pub is_internal: bool,
}

impl fmt::Display for PoolStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} pool: {} addresses ({} used, {} unused), gap limit: {}",
            if self.is_internal {
                "Internal"
            } else {
                "External"
            },
            self.total_generated,
            self.used_count,
            self.unused_count,
            self.gap_limit
        )
    }
}

/// Builder for AddressPool
pub struct AddressPoolBuilder {
    base_path: Option<DerivationPath>,
    pool_type: AddressPoolType,
    gap_limit: u32,
    network: Network,
    lookahead_size: u32,
    address_type: AddressType,
    key_source: Option<KeySource>,
}

impl AddressPoolBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            base_path: None,
            pool_type: AddressPoolType::External,
            gap_limit: DEFAULT_EXTERNAL_GAP_LIMIT,
            network: Network::Dash,
            lookahead_size: 40,
            address_type: AddressType::P2pkh,
            key_source: None,
        }
    }

    /// Set the base derivation path
    pub fn base_path(mut self, path: DerivationPath) -> Self {
        self.base_path = Some(path);
        self
    }

    /// Set the pool type (external, internal, or absent)
    pub fn pool_type(mut self, pool_type: AddressPoolType) -> Self {
        self.pool_type = pool_type;
        self
    }

    /// Set whether this is an internal (change) pool (compatibility method)
    pub fn internal(mut self, is_internal: bool) -> Self {
        self.pool_type = if is_internal {
            AddressPoolType::Internal
        } else {
            AddressPoolType::External
        };
        self
    }

    /// Set the gap limit
    pub fn gap_limit(mut self, limit: u32) -> Self {
        self.gap_limit = limit;
        self
    }

    /// Set the network
    pub fn network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    /// Set the lookahead size
    pub fn lookahead(mut self, size: u32) -> Self {
        self.lookahead_size = size;
        self
    }

    /// Set the address type
    pub fn address_type(mut self, addr_type: AddressType) -> Self {
        self.address_type = addr_type;
        self
    }

    /// Set the key source for generating addresses
    pub fn key_source(mut self, key_source: KeySource) -> Self {
        self.key_source = Some(key_source);
        self
    }

    /// Build the address pool
    pub fn build(self) -> Result<AddressPool> {
        let base_path =
            self.base_path.ok_or(Error::InvalidParameter("base_path required".into()))?;

        let mut pool = AddressPool::new_without_generation(
            base_path,
            self.pool_type,
            self.gap_limit,
            self.network,
        );
        pool.lookahead_size = self.lookahead_size;
        pool.address_type = self.address_type;

        // Generate addresses if a key source was provided
        if let Some(key_source) = self.key_source {
            if !matches!(key_source, KeySource::NoKeySource) {
                pool.generate_addresses(self.gap_limit, &key_source, true)?;
            }
        }

        Ok(pool)
    }
}

impl Default for AddressPoolBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mnemonic::{Language, Mnemonic};

    fn test_key_source() -> KeySource {
        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English,
        ).unwrap();
        let seed = mnemonic.to_seed("");
        let master = ExtendedPrivKey::new_master(Network::Testnet, &seed).unwrap();

        let secp = Secp256k1::new();
        let path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(44).unwrap(),
            ChildNumber::from_hardened_idx(1).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
        ]);
        let account_key = master.derive_priv(&secp, &path).unwrap();

        KeySource::Private(account_key)
    }

    #[test]
    fn test_address_pool_generation() {
        let base_path = DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]);
        let mut pool = AddressPool::new_without_generation(
            base_path,
            AddressPoolType::External,
            20,
            Network::Testnet,
        );
        let key_source = test_key_source();

        let addresses = pool.generate_addresses(10, &key_source, true).unwrap();
        assert_eq!(addresses.len(), 10);
        assert_eq!(pool.highest_generated, Some(9));
        assert_eq!(pool.addresses.len(), 10);
    }

    #[test]
    fn test_address_usage() {
        let base_path = DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]);
        let mut pool = AddressPool::new_without_generation(
            base_path,
            AddressPoolType::External,
            5,
            Network::Testnet,
        );
        let key_source = test_key_source();

        let addresses = pool.generate_addresses(5, &key_source, true).unwrap();
        let first_addr = &addresses[0];

        assert!(pool.mark_used(first_addr));
        assert_eq!(pool.used_indices.len(), 1);
        assert_eq!(pool.highest_used, Some(0));

        let used = pool.used_addresses();
        assert_eq!(used.len(), 1);
        assert_eq!(&used[0], first_addr);
    }

    #[test]
    fn test_next_unused() {
        let base_path = DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]);
        let mut pool = AddressPool::new_without_generation(
            base_path,
            AddressPoolType::External,
            5,
            Network::Testnet,
        );
        let key_source = test_key_source();

        let addr1 = pool.next_unused(&key_source, true).unwrap();
        let addr2 = pool.next_unused(&key_source, true).unwrap();
        assert_eq!(addr1, addr2); // Should return same unused address

        pool.mark_used(&addr1);
        let addr3 = pool.next_unused(&key_source, true).unwrap();
        assert_ne!(addr1, addr3); // Should return different address after marking used
    }

    #[test]
    fn test_gap_limit_maintenance() {
        let base_path = DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]);
        let mut pool = AddressPool::new_without_generation(
            base_path,
            AddressPoolType::External,
            5,
            Network::Testnet,
        );
        let key_source = test_key_source();

        // Generate initial addresses
        pool.generate_addresses(3, &key_source, true).unwrap();
        pool.mark_index_used(1);

        // Maintain gap limit
        let _new_addrs = pool.maintain_gap_limit(&key_source).unwrap();
        assert!(pool.highest_generated.unwrap_or(0) >= 6); // Should have at least index 1 + gap limit 5
    }

    #[test]
    fn test_address_pool_builder() {
        let pool = AddressPoolBuilder::new()
            .base_path(DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]))
            .internal(true)
            .gap_limit(10)
            .network(Network::Testnet)
            .lookahead(20)
            .address_type(AddressType::P2pkh)
            .build()
            .unwrap();

        assert!(pool.is_internal());
        assert_eq!(pool.gap_limit, 10);
        assert_eq!(pool.network, Network::Testnet);
        assert_eq!(pool.lookahead_size, 20);
    }

    #[test]
    fn test_scan_for_usage() {
        let base_path = DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]);
        let mut pool = AddressPool::new_without_generation(
            base_path,
            AddressPoolType::External,
            5,
            Network::Testnet,
        );
        let key_source = test_key_source();

        let addresses = pool.generate_addresses(10, &key_source, true).unwrap();

        // Simulate checking for usage - mark addresses at indices 2, 5, 7 as used
        let check_fn = |addr: &Address| {
            addresses[2] == *addr || addresses[5] == *addr || addresses[7] == *addr
        };

        let found = pool.scan_for_usage(check_fn);
        assert_eq!(found.len(), 3);
        assert_eq!(pool.used_indices.len(), 3);
        assert_eq!(pool.highest_used, Some(7));
    }
}
