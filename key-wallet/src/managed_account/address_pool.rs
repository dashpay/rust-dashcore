//! Address pool management for HD wallets
//!
//! This module provides comprehensive address pool management including
//! generation, usage tracking, and discovery.

#[cfg(feature = "bincode")]
use bincode_derive::{Decode, Encode};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

use crate::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use crate::error::{Error, Result};
use crate::Network;
use dashcore::address::Payload;
#[cfg(feature = "eddsa")]
use dashcore::eddsa::{EddsaPkBytes, EddsaPkHash};
use dashcore::hashes::hash160;
use dashcore::{Address, AddressType, ScriptBuf};

/// Types of public keys used in the address pool
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[allow(clippy::upper_case_acronyms)]
pub enum PublicKeyType {
    /// ECDSA public key (standard Bitcoin/Dash addresses) - stored as `Vec<u8>` for serialization
    ECDSA(Vec<u8>),
    /// EdDSA public key (Ed25519, used in some Platform operations)
    EdDSA(Vec<u8>),
    /// BLS public key (used for masternode operations and Platform)
    BLS(Vec<u8>),
}

/// Type of address pool (external, internal, or absent/single-pool)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
    #[cfg(feature = "eddsa")]
    EdDSA(Vec<u8>),
}

impl KeySource {
    /// Derive a child key at the given path
    /// Returns a DerivedKey which can be ECDSA, BLS, or EdDSA
    fn derive_at_path(&self, path: &DerivationPath) -> Result<DerivedKey> {
        match self {
            KeySource::Private(xprv) => {
                let child = xprv.derive_priv(path).map_err(Error::Bip32)?;
                Ok(DerivedKey::ECDSA(ExtendedPubKey::from_priv(&child)))
            }
            KeySource::Public(xpub) => {
                let derived = xpub.derive_pub(path).map_err(Error::Bip32)?;
                Ok(DerivedKey::ECDSA(derived))
            }
            #[cfg(feature = "bls")]
            KeySource::BLSPrivate(xprv) => {
                // BLS HD derivation using the proper BIP32-like derivation
                // Legacy mode: BLS pools exist only for provider operator keys,
                // which dashbls/DashSync derive with fLegacy = true.
                let mut derived = xprv.clone();
                for child_num in path.as_ref() {
                    derived = derived.derive_priv_legacy(*child_num).map_err(|e| {
                        Error::InvalidParameter(format!("BLS derivation error: {:?}", e))
                    })?;
                }
                let public_key_bytes = derived.public_key_bytes().map_err(|e| {
                    Error::InvalidParameter(format!("BLS derivation error: {:?}", e))
                })?;
                Ok(DerivedKey::BLS(public_key_bytes.to_vec()))
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
                    derived = derived.derive_pub_legacy(*child_num).map_err(|e| {
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

    /// Check if this is a watch-only key source
    pub fn is_watch_only(&self) -> bool {
        matches!(self, KeySource::Public(_))
    }

    /// Check if key source is available for derivation
    pub fn can_derive(&self) -> bool {
        !matches!(self, KeySource::NoKeySource)
    }
}

/// Lifecycle state of an address in the pool.
///
/// The three states are mutually exclusive by construction, so the invariant
/// "a used address is never reserved" holds structurally rather than being
/// maintained by hand. The reservation timestamp is caller-supplied (seconds),
/// and `0` means the caller had no clock available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub enum AddressState {
    /// Free to hand out: neither reserved nor used.
    #[default]
    Available,
    /// Handed out but not yet funded. `at` is when it was reserved.
    Reserved {
        /// Reservation timestamp.
        at: u64,
    },
    /// Funds have been seen at this address.
    Used,
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
    /// Lifecycle state: available, reserved, or used
    pub state: AddressState,
}

impl AddressInfo {
    fn new(
        address: Address,
        index: u32,
        path: DerivationPath,
        public_key: Option<PublicKeyType>,
    ) -> Self {
        let script_pubkey = address.script_pubkey();
        Self {
            address,
            script_pubkey,
            public_key,
            index,
            path,
            state: AddressState::Available,
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

        Ok(Self::new(address, index, path, None))
    }

    /// Mark this address as used.
    ///
    /// Transitions to [`AddressState::Used`], which structurally drops any
    /// reservation so the invariant "a used address is never reserved" holds
    /// even when a reserved address is promoted directly to used.
    fn mark_used(&mut self) {
        self.state = AddressState::Used;
    }

    /// Whether this address is available to be handed out: neither used nor
    /// reserved.
    pub fn is_available(&self) -> bool {
        matches!(self.state, AddressState::Available)
    }

    /// Whether this address is currently reserved (handed out but not yet used).
    fn is_reserved(&self) -> bool {
        matches!(self.state, AddressState::Reserved { .. })
    }

    /// Whether this address has been used.
    pub fn is_used(&self) -> bool {
        matches!(self.state, AddressState::Used)
    }

    /// Timestamp the address was reserved, or `None` if not reserved.
    pub fn reserved_at(&self) -> Option<u64> {
        match self.state {
            AddressState::Reserved {
                at,
            } => Some(at),
            _ => None,
        }
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
        if key_source.can_derive() {
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
        }
    }

    /// Check if this is an internal (change) address pool
    pub fn is_internal(&self) -> bool {
        self.pool_type == AddressPoolType::Internal
    }

    /// Check if this is an external (receive) address pool
    pub fn is_external(&self) -> bool {
        self.pool_type == AddressPoolType::External
    }

    /// Returns the index of the first available address, or the next index to derive when none is.
    fn next_unused_index(&self) -> u32 {
        self.addresses
            .iter()
            .find(|(_, info)| info.is_available())
            .map_or_else(|| self.next_index_to_derive(), |(index, _)| *index)
    }

    /// Returns the highest derived index, or `None` for an empty pool.
    pub fn highest_generated(&self) -> Option<u32> {
        self.addresses.keys().next_back().copied()
    }

    /// Returns the highest used index, or `None` when no address is used.
    pub fn highest_used(&self) -> Option<u32> {
        self.addresses.values().rev().find(|info| info.is_used()).map(|info| info.index)
    }

    fn next_index_to_derive(&self) -> u32 {
        self.highest_generated().map_or(0, |highest| highest + 1)
    }

    /// Generate addresses up to the specified count
    pub fn generate_addresses(
        &mut self,
        count: u32,
        key_source: &KeySource,
        add_to_state: bool,
    ) -> Result<Vec<AddressInfo>> {
        let start_index = self.next_index_to_derive();
        (start_index..start_index + count)
            .map(|index| self.generate_address_at_index(index, key_source, add_to_state))
            .collect()
    }

    /// Generate every address up to and including `index`
    pub(crate) fn generate_up_to(
        &mut self,
        index: u32,
        key_source: &KeySource,
    ) -> Result<Vec<AddressInfo>> {
        let next = self.next_index_to_derive();
        self.generate_addresses((index + 1).saturating_sub(next), key_source, true)
    }

    /// Generate a specific address at an index
    pub(crate) fn generate_address_at_index(
        &mut self,
        index: u32,
        key_source: &KeySource,
        add_to_state: bool,
    ) -> Result<AddressInfo> {
        // Check if already generated
        if let Some(info) = self.addresses.get(&index) {
            return Ok(info.clone());
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
                // Generate P2PKH address (Platform addresses use the same underlying
                // hash but with different encoding handled by the Platform repo)
                let address = Address::p2pkh(&dash_pubkey, network);
                let public_key_bytes = dash_pubkey.to_bytes();
                (address, PublicKeyType::ECDSA(public_key_bytes.to_vec()))
            }
            DerivedKey::BLS(public_key_bytes) => {
                // BLS addresses use Hash160 of the public key bytes
                let pubkey_hash = hash160::Hash::hash(&public_key_bytes);

                // Create P2PKH address from the hash
                let payload = Payload::PubkeyHash(pubkey_hash.into());
                let address = Address::new(self.network, payload);

                (address, PublicKeyType::BLS(public_key_bytes))
            }
            #[cfg(feature = "eddsa")]
            DerivedKey::EdDSA(public_key_bytes) => {
                // EdDSA pool entries key on the Tenderdash node ID
                // (SHA256(pubkey)[0..20]) — the value ProRegTx carries as
                // `platform_node_id` — wrapped in a P2PKH-style payload so it
                // can live in the pool's address index. NOT hash160: a
                // hash160-keyed entry can never match an on-chain evonode
                // registration.
                let pubkey_arr: &[u8; 32] =
                    public_key_bytes.as_slice().try_into().map_err(|_| {
                        Error::InvalidParameter(format!(
                            "EdDSA public key must be 32 bytes, got {}",
                            public_key_bytes.len()
                        ))
                    })?;
                let node_id =
                    EddsaPkHash::from(EddsaPkBytes::from_bytes(*pubkey_arr)).to_canonical_bytes();
                let payload = Payload::PubkeyHash(dashcore::PubkeyHash::from_byte_array(node_id));
                let address = Address::new(self.network, payload);

                (address, PublicKeyType::EdDSA(public_key_bytes))
            }
        };
        let info = AddressInfo::new(address.clone(), index, full_path, Some(public_key_type));
        if add_to_state {
            self.addresses.insert(index, info.clone());
            self.address_index.insert(address, index);
            self.script_pubkey_index.insert(info.script_pubkey.clone(), index);
        }

        Ok(info)
    }

    /// Get the next unused address
    pub fn next_unused(&mut self, key_source: &KeySource, add_to_state: bool) -> Result<Address> {
        self.next_unused_with_info(key_source, add_to_state).map(|info| info.address)
    }

    /// Get the next unused address info
    pub(crate) fn next_unused_with_info(
        &mut self,
        key_source: &KeySource,
        add_to_state: bool,
    ) -> Result<AddressInfo> {
        // First, try to find an already generated unused address
        if let Some(info) = self.addresses.get(&self.next_unused_index()) {
            return Ok(info.clone());
        }

        self.generate_addresses(1, key_source, add_to_state)?
            .pop()
            .ok_or_else(|| Error::InvalidState("generate_addresses(1) returned nothing".into()))
    }

    /// Reserve and return the next available address.
    ///
    /// Scans for the first available index (neither used nor reserved), marks it
    /// reserved with `now`, and returns its address. Because the scan and the
    /// reserve happen under a single exclusive `&mut self` borrow, two
    /// sequential hand-outs cannot both observe the same index as available: the
    /// first reserves it before the second runs. When no generated address is
    /// available a fresh one is derived and always materialized into the pool,
    /// since the reservation is stored on the address entry.
    ///
    /// `now` is a caller-supplied timestamp (seconds) that stamps the
    /// reservation and is what [`AddressPool::sweep_expired_reservations`] later
    /// compares against. The pool keeps no clock of its own.
    ///
    /// This path derives a fresh address whenever every existing address is
    /// used or reserved, with no upper bound. Outstanding reservations are
    /// reclaimed only by [`AddressPool::release_reservation`] and
    /// [`AddressPool::sweep_expired_reservations`], so callers are assumed
    /// trusted. Gate or cap this before exposing it to untrusted input.
    pub(crate) fn next_unused_and_reserve(
        &mut self,
        key_source: &KeySource,
        now: u64,
    ) -> Result<Address> {
        let index = self.next_unused_with_info(key_source, true)?.index;
        // A lookup miss would hand out an unreserved address, so fail instead.
        let info = self.addresses.get_mut(&index).ok_or_else(|| {
            Error::InvalidState(format!("next_unused_and_reserve: index {} not stored", index))
        })?;
        info.state = AddressState::Reserved {
            at: now,
        };
        Ok(info.address.clone())
    }

    /// Release a reservation, returning the address to the available pool.
    ///
    /// Idempotent: returns `false` when the index is not currently reserved
    /// (never reserved, already released, already used, or unknown index), and
    /// `true` when a reservation was actually cleared.
    pub fn release_reservation(&mut self, index: u32) -> bool {
        if let Some(info) = self.addresses.get_mut(&index) {
            if info.is_reserved() {
                info.state = AddressState::Available;
                return true;
            }
        }
        false
    }

    /// Reclaim reservations older than `ttl`, returning their addresses to the
    /// available pool.
    ///
    /// A reservation is expired when `now - reserved_at >= ttl`. Returns how
    /// many reservations were reclaimed. `now` and `ttl` are caller-supplied
    /// (seconds). The pool keeps no clock. This is the backstop against a
    /// hand-out that is reserved but never paid and never explicitly released,
    /// which would otherwise pin gap-limit headroom across restarts forever.
    ///
    /// A `now` of 0 means the caller has no clock available, so the sweep
    /// declines to judge staleness and reclaims nothing. A `ttl` of 0 means no
    /// expiry window, so nothing is reclaimed either. A reservation stamped with
    /// `at == 0` (its caller had no clock) is likewise never aged out.
    pub(crate) fn sweep_expired_reservations(&mut self, now: u64, ttl: u64) -> usize {
        if now == 0 || ttl == 0 {
            return 0;
        }
        let mut reclaimed = 0;
        for info in self.addresses.values_mut() {
            if let AddressState::Reserved {
                at,
            } = info.state
            {
                // A clockless stamp cannot be judged stale against a real clock.
                if at == 0 {
                    continue;
                }
                if now.saturating_sub(at) >= ttl {
                    info.state = AddressState::Available;
                    reclaimed += 1;
                }
            }
        }
        reclaimed
    }

    /// Mark an address as used
    pub fn mark_used(&mut self, address: &Address) -> bool {
        let Some(&index) = self.address_index.get(address) else {
            return false;
        };

        let Some(info) = self.addresses.get_mut(&index) else {
            return false;
        };

        if info.is_used() {
            return false;
        }

        info.mark_used();

        true
    }

    /// Get all addresses in the pool
    pub fn all_addresses(&self) -> Vec<Address> {
        self.addresses.values().map(|info| info.address.clone()).collect()
    }

    /// Get cached scriptPubKeys for every address in the pool.
    pub(crate) fn all_script_pubkeys(&self) -> Vec<ScriptBuf> {
        self.addresses.values().map(|info| info.script_pubkey.clone()).collect()
    }

    /// Get only available addresses (neither used nor reserved)
    pub fn unused_addresses(&self) -> Vec<Address> {
        self.addresses
            .values()
            .filter(|info| info.is_available())
            .map(|info| info.address.clone())
            .collect()
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
        self.address_index.get(address).and_then(|index| self.addresses.get_mut(index))
    }

    /// Get the index of an address
    pub fn address_index(&self, address: &Address) -> Option<u32> {
        self.address_index.get(address).copied()
    }

    /// Check if an address belongs to this pool
    pub fn contains_address(&self, address: &Address) -> bool {
        self.address_index.contains_key(address)
    }

    /// Check if a script pubkey belongs to this pool
    pub(crate) fn contains_script_pubkey(&self, script_pubkey: &ScriptBuf) -> bool {
        self.script_pubkey_index.contains_key(script_pubkey)
    }

    /// Raise the gap limit and generate the addresses the wider limit now requires.
    ///
    /// The new limit is capped at [`crate::gap_limit::MAX_GAP_LIMIT`]. Returns the freshly
    /// generated [`AddressInfo`] entries
    pub fn set_gap_limit(
        &mut self,
        gap_limit: u32,
        key_source: &KeySource,
    ) -> Result<Vec<AddressInfo>> {
        self.gap_limit = gap_limit.clamp(1, crate::gap_limit::MAX_GAP_LIMIT);
        self.maintain_gap_limit(key_source)
    }

    /// Generate addresses to maintain the gap limit.
    ///
    /// Returns the freshly generated [`AddressInfo`] entries (in derivation
    /// order). Returning the rich [`AddressInfo`] rather than just
    /// [`Address`] lets callers — in particular the wallet-manager event
    /// emission seam — surface the full derivation context (index, path,
    /// public key) for downstream persisters without re-deriving it.
    pub fn maintain_gap_limit(&mut self, key_source: &KeySource) -> Result<Vec<AddressInfo>> {
        let target = match self.highest_used() {
            None => self.gap_limit - 1,
            Some(highest) => highest + self.gap_limit,
        };
        self.generate_up_to(target, key_source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mnemonic::Mnemonic;

    fn test_key_source() -> KeySource {
        let mnemonic = Mnemonic::from_phrase("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let seed = mnemonic.to_seed("");
        let master = ExtendedPrivKey::new_master(Network::Testnet, &seed[..]).unwrap();

        let path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(44).unwrap(),
            ChildNumber::from_hardened_idx(1).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
        ]);
        let account_key = master.derive_priv(&path).unwrap();

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
        assert_eq!(pool.highest_generated(), Some(9));
        assert_eq!(pool.addresses.len(), 10);
    }

    #[test]
    fn test_generate_up_to() {
        let base_path = DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]);
        let key_source = test_key_source();
        let mut pool = AddressPool::new(
            base_path,
            AddressPoolType::External,
            5,
            Network::Testnet,
            &key_source,
        )
        .unwrap();

        assert_eq!(pool.generate_up_to(29, &key_source).unwrap().len(), 25);
        assert_eq!(pool.highest_generated(), Some(29));
        assert_eq!(pool.addresses.len(), 30);

        assert!(pool.generate_up_to(10, &key_source).unwrap().is_empty());
        assert_eq!(pool.highest_generated(), Some(29));
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
        let first_addr = &addresses[0].address;

        assert!(pool.mark_used(first_addr));
        assert_eq!(pool.highest_used(), Some(0));

        assert!(pool.address_info(first_addr).unwrap().is_used());
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
    fn test_set_gap_limit_widens_and_generates() {
        let base_path = DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]);
        let key_source = test_key_source();

        // Start with a small gap limit (5 pre-generated addresses).
        let mut pool = AddressPool::new(
            base_path,
            AddressPoolType::External,
            5,
            Network::Testnet,
            &key_source,
        )
        .unwrap();
        assert_eq!(pool.gap_limit, 5);
        assert_eq!(pool.addresses.len(), 5);

        // Widening generates the extra addresses up front and returns them.
        let new = pool.set_gap_limit(20, &key_source).unwrap();
        assert_eq!(pool.gap_limit, 20);
        assert_eq!(new.len(), 15);
        assert_eq!(pool.addresses.len(), 20);
        assert_eq!(pool.highest_generated(), Some(19));

        // The new limit is capped at MAX_GAP_LIMIT.
        pool.set_gap_limit(crate::gap_limit::MAX_GAP_LIMIT + 500, &key_source).unwrap();
        assert_eq!(pool.gap_limit, crate::gap_limit::MAX_GAP_LIMIT);
        assert_eq!(pool.addresses.len(), crate::gap_limit::MAX_GAP_LIMIT as usize);
    }

    #[test]
    fn test_reserve_returns_distinct_addresses() {
        let base_path = DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]);
        let mut pool = AddressPool::new_without_generation(
            base_path,
            AddressPoolType::External,
            5,
            Network::Testnet,
        );
        let key_source = test_key_source();

        // Without reserving, two hand-outs return the same address (the race).
        let peek1 = pool.next_unused(&key_source, true).unwrap();
        let peek2 = pool.next_unused(&key_source, true).unwrap();
        assert_eq!(peek1, peek2);

        // Reserving on hand-out makes two sequential calls return distinct
        // addresses: the first is no longer available to the second.
        let addr1 = pool.next_unused_and_reserve(&key_source, 100).unwrap();
        let addr2 = pool.next_unused_and_reserve(&key_source, 100).unwrap();
        assert_ne!(addr1, addr2);

        // A plain peek must skip the reserved addresses too.
        let peek3 = pool.next_unused(&key_source, true).unwrap();
        assert_ne!(peek3, addr1);
        assert_ne!(peek3, addr2);
    }

    #[test]
    fn test_release_returns_address_to_pool() {
        let base_path = DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]);
        let mut pool = AddressPool::new_without_generation(
            base_path,
            AddressPoolType::External,
            5,
            Network::Testnet,
        );
        let key_source = test_key_source();

        let addr = pool.next_unused_and_reserve(&key_source, 100).unwrap();
        let index = pool.address_index(&addr).unwrap();

        // A reserved address is excluded from the available set.
        assert!(!pool.unused_addresses().contains(&addr));

        // After releasing, the same address becomes available again.
        assert!(pool.release_reservation(index));
        assert!(pool.unused_addresses().contains(&addr));
        let reissued = pool.next_unused_and_reserve(&key_source, 200).unwrap();
        assert_eq!(addr, reissued);
    }

    #[test]
    fn test_release_is_idempotent() {
        let base_path = DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]);
        let mut pool = AddressPool::new_without_generation(
            base_path,
            AddressPoolType::External,
            5,
            Network::Testnet,
        );
        let key_source = test_key_source();

        let addr = pool.next_unused_and_reserve(&key_source, 100).unwrap();
        let index = pool.address_index(&addr).unwrap();

        // First release clears the reservation, a second is a no-op.
        assert!(pool.release_reservation(index));
        assert!(!pool.release_reservation(index));
        // Releasing a never-reserved index is a no-op too.
        let other = pool.next_unused(&key_source, true).unwrap();
        let other_index = pool.address_index(&other).unwrap();
        assert!(!pool.release_reservation(other_index));
        // Unknown index is a no-op.
        assert!(!pool.release_reservation(9_999));
    }

    #[test]
    fn test_reserved_promoted_to_used_clears_reservation() {
        let base_path = DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]);
        let mut pool = AddressPool::new_without_generation(
            base_path,
            AddressPoolType::External,
            5,
            Network::Testnet,
        );
        let key_source = test_key_source();

        let addr = pool.next_unused_and_reserve(&key_source, 100).unwrap();
        let index = pool.address_index(&addr).unwrap();
        assert!(pool.addresses.get(&index).unwrap().is_reserved());

        // Funds arriving mark the reserved address used, so the reservation is
        // structurally dropped (a used address is never reserved).
        assert!(pool.mark_used(&addr));
        let info = pool.addresses.get(&index).unwrap();
        assert!(info.is_used());
        assert!(!info.is_reserved());
        assert!(info.reserved_at().is_none());
        // Releasing a now-used index is a no-op.
        assert!(!pool.release_reservation(index));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_reservation_survives_serde_round_trip() {
        let base_path = DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]);
        let mut pool = AddressPool::new_without_generation(
            base_path,
            AddressPoolType::External,
            5,
            Network::Testnet,
        );
        let key_source = test_key_source();

        let reserved = pool.next_unused_and_reserve(&key_source, 12_345).unwrap();
        let index = pool.address_index(&reserved).unwrap();

        // Unlike an ephemeral reservation, the reserved state must survive a
        // round trip so a handed-out address is not re-issued after a restart.
        let json = serde_json::to_string(&pool).unwrap();
        let mut restored: AddressPool = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.addresses.get(&index).unwrap().reserved_at(), Some(12_345));
        assert!(restored.addresses.get(&index).unwrap().is_reserved());

        // A fresh hand-out on the restored pool skips the still-reserved address.
        let next = restored.next_unused_and_reserve(&key_source, 12_346).unwrap();
        assert_ne!(next, reserved);
    }

    #[cfg(feature = "bincode")]
    #[test]
    fn test_reservation_survives_bincode_round_trip() {
        let base_path = DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]);
        let mut pool = AddressPool::new_without_generation(
            base_path,
            AddressPoolType::External,
            5,
            Network::Testnet,
        );
        let key_source = test_key_source();

        let reserved = pool.next_unused_and_reserve(&key_source, 12_345).unwrap();
        let index = pool.address_index(&reserved).unwrap();

        // The reserved state must survive a bincode round trip so a handed-out
        // address is not re-issued after a restart.
        let bytes = bincode::encode_to_vec(&pool, bincode::config::standard()).unwrap();
        let (mut restored, _): (AddressPool, usize) =
            bincode::decode_from_slice(&bytes, bincode::config::standard()).unwrap();

        assert_eq!(restored.addresses.get(&index).unwrap().reserved_at(), Some(12_345));
        assert!(restored.addresses.get(&index).unwrap().is_reserved());

        // A fresh hand-out on the restored pool skips the still-reserved address.
        let next = restored.next_unused_and_reserve(&key_source, 12_346).unwrap();
        assert_ne!(next, reserved);
    }

    #[test]
    fn test_sweep_expired_reservations() {
        let base_path = DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]);
        let mut pool = AddressPool::new_without_generation(
            base_path,
            AddressPoolType::External,
            5,
            Network::Testnet,
        );
        let key_source = test_key_source();

        let old = pool.next_unused_and_reserve(&key_source, 100).unwrap();
        let recent = pool.next_unused_and_reserve(&key_source, 200).unwrap();
        let clockless = pool.next_unused_and_reserve(&key_source, 0).unwrap();
        let old_index = pool.address_index(&old).unwrap();
        let recent_index = pool.address_index(&recent).unwrap();
        let clockless_index = pool.address_index(&clockless).unwrap();

        // now == 0 means no clock: nothing is reclaimed.
        assert_eq!(pool.sweep_expired_reservations(0, 100), 0);
        assert!(pool.addresses.get(&old_index).unwrap().is_reserved());

        // ttl == 0 means no expiry window: live reservations are left intact.
        assert_eq!(pool.sweep_expired_reservations(250, 0), 0);
        assert!(pool.addresses.get(&old_index).unwrap().is_reserved());
        assert!(pool.addresses.get(&recent_index).unwrap().is_reserved());

        // At now=250 with ttl=100: old (age 150) expires, recent (age 50) stays.
        // A clockless reservation (reserved_at == 0) is never aged out.
        assert_eq!(pool.sweep_expired_reservations(250, 100), 1);
        assert!(!pool.addresses.get(&old_index).unwrap().is_reserved());
        assert!(pool.addresses.get(&recent_index).unwrap().is_reserved());
        assert!(pool.addresses.get(&clockless_index).unwrap().is_reserved());

        // The reclaimed address is available for hand-out again.
        let reissued = pool.next_unused_and_reserve(&key_source, 300).unwrap();
        assert_eq!(old, reissued);
    }

    #[test]
    fn test_gap_limit_maintenance() {
        let base_path = DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]);
        let key_source = test_key_source();
        let gap_limit = 5;

        // Create pool with gap_limit addresses already generated
        let mut pool = AddressPool::new(
            base_path,
            AddressPoolType::External,
            gap_limit,
            Network::Testnet,
            &key_source,
        )
        .unwrap();

        // Verify gap_limit addresses generated, none used
        assert_eq!(pool.highest_generated(), Some(gap_limit - 1));
        assert_eq!(pool.highest_used(), None);
        assert_eq!(pool.addresses.len(), gap_limit as usize);

        // Calling maintain_gap_limit should not generate any new addresses when none are used
        let new_addresses = pool.maintain_gap_limit(&key_source).unwrap();
        assert_eq!(new_addresses.len(), 0);
        assert_eq!(pool.highest_generated(), Some(gap_limit - 1));
        assert_eq!(pool.addresses.len(), gap_limit as usize);

        // Mark address at index 0 as used
        pool.mark_used(&pool.address_at_index(0).unwrap());
        assert_eq!(pool.highest_used(), Some(0));

        // Should generate exactly 1 address to maintain gap_limit unused after index 0
        let new_addresses = pool.maintain_gap_limit(&key_source).unwrap();
        assert_eq!(new_addresses.len(), 1);
        assert_eq!(new_addresses[0].index, gap_limit);
        assert_eq!(pool.highest_generated(), Some(gap_limit));
        assert_eq!(pool.addresses.len(), gap_limit as usize + 1);

        // Mark address at index 1 and 2 as used
        pool.mark_used(&pool.address_at_index(1).unwrap());
        pool.mark_used(&pool.address_at_index(2).unwrap());

        // Should generate exactly 2 more addresses
        let new_addresses = pool.maintain_gap_limit(&key_source).unwrap();
        assert_eq!(new_addresses.len(), 2);
        assert_eq!(new_addresses[0].index, gap_limit + 1);
        assert_eq!(new_addresses[1].index, gap_limit + 2);
        assert_eq!(pool.highest_generated(), Some(gap_limit + 2));
        assert_eq!(pool.addresses.len(), gap_limit as usize + 3);
    }
}
