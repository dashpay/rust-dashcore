//! Managed Platform Account for DIP-17 Platform Payment addresses
//!
//! This module provides the `ManagedPlatformAccount` type which is a simplified
//! account structure for Platform Payment accounts. Unlike `ManagedCoreAccount`,
//! this type:
//! - Uses a simple `u64` balance instead of `WalletCoreBalance`
//! - Tracks per-address balances directly
//! - Does NOT track transactions or UTXOs (Platform handles these)
//!
//! The derivation path follows DIP-17: `m/9'/coin_type'/17'/account'/key_class'/index`

use super::address_pool::{AddressPool, KeySource};
use super::metadata::AccountMetadata;
use super::platform_address::PlatformP2PKHAddress;
use crate::error::{Error, Result};
use crate::Network;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use dashcore::Address;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Managed Platform Account for DIP-17 Platform Payment addresses
///
/// This is a simplified account structure designed specifically for Platform
/// Payment accounts (DIP-17). It differs from `ManagedCoreAccount` in that:
///
/// - **Balance**: Simple `u64` credit balance (1000 credits = 1 duff)
/// - **Address Balances**: Direct mapping of addresses to their credit balances
/// - **No Transactions**: Platform handles transaction tracking
/// - **No UTXOs**: Platform uses a different model for funds
///
/// The address pool is kept for key derivation and address generation following
/// the DIP-17 derivation path: `m/9'/coin_type'/17'/account'/key_class'/index`
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ManagedPlatformAccount {
    /// Account index (hardened) - DIP-17 `account'` level
    pub account: u32,
    /// Key class (hardened) - DIP-17 `key_class'` level
    /// 0' is default, 1' is reserved for change-like segregation
    pub key_class: u32,
    /// Network this account belongs to
    pub network: Network,
    /// Total balance in credits (1000 credits = 1 duff)
    pub credit_balance: u64,
    /// Per-address balances: PlatformP2PKHAddress -> balance in credits
    pub address_balances: BTreeMap<PlatformP2PKHAddress, u64>,
    /// Address pool for key derivation and address generation
    pub addresses: AddressPool,
    /// Account metadata
    pub metadata: AccountMetadata,
    /// Whether this is a watch-only account
    pub is_watch_only: bool,
}

impl ManagedPlatformAccount {
    /// Create a new managed platform account
    ///
    /// The network is derived from the AddressPool to ensure consistency.
    pub fn new(account: u32, key_class: u32, addresses: AddressPool, is_watch_only: bool) -> Self {
        let network = addresses.network;
        Self {
            account,
            key_class,
            network,
            credit_balance: 0,
            address_balances: BTreeMap::new(),
            addresses,
            metadata: AccountMetadata::default(),
            is_watch_only,
        }
    }

    /// Get the total credit balance across all addresses
    pub fn total_credit_balance(&self) -> u64 {
        self.credit_balance
    }

    /// Get the total balance in duffs (credit_balance / 1000)
    pub fn duff_balance(&self) -> u64 {
        self.credit_balance / 1000
    }

    /// Set the total credit balance
    pub fn set_credit_balance(&mut self, credit_balance: u64) {
        self.credit_balance = credit_balance;
        self.metadata.last_used = Some(Self::current_timestamp());
    }

    /// Get the credit balance for a specific address
    pub fn address_credit_balance(&self, address: &PlatformP2PKHAddress) -> u64 {
        self.address_balances.get(address).copied().unwrap_or(0)
    }

    /// Set the credit balance for a specific address
    ///
    /// This also updates the total balance by applying the delta.
    /// If the address was previously unfunded (balance 0) and becomes funded,
    /// and a `KeySource` is provided, the address will be marked as used
    /// and the gap limit will be maintained.
    pub fn set_address_credit_balance(
        &mut self,
        address: PlatformP2PKHAddress,
        credit_balance: u64,
        key_source: Option<&KeySource>,
    ) {
        let old_balance = self.address_balances.get(&address).copied().unwrap_or(0);
        let was_unfunded = old_balance == 0;
        let is_now_funded = credit_balance > 0;

        self.address_balances.insert(address, credit_balance);
        // Apply delta to total: subtract old, add new
        self.credit_balance =
            self.credit_balance.saturating_sub(old_balance).saturating_add(credit_balance);
        self.metadata.last_used = Some(Self::current_timestamp());

        // If address became funded and we have a key source, update address pool
        if was_unfunded && is_now_funded {
            if let Some(ks) = key_source {
                self.mark_and_maintain_gap_limit(&address, ks);
            }
        }
    }

    /// Add credits to a specific address balance
    ///
    /// Returns the new credit balance for the address.
    /// If the address was previously unfunded (balance 0) and becomes funded,
    /// and a `KeySource` is provided, the address will be marked as used
    /// and the gap limit will be maintained.
    pub fn add_address_credit_balance(
        &mut self,
        address: PlatformP2PKHAddress,
        amount: u64,
        key_source: Option<&KeySource>,
    ) -> u64 {
        let current = self.address_balances.get(&address).copied().unwrap_or(0);
        let was_unfunded = current == 0;
        let new_balance = current.saturating_add(amount);
        let is_now_funded = new_balance > 0;

        self.address_balances.insert(address, new_balance);
        // Add the amount to the total (saturating to handle overflow)
        self.credit_balance = self.credit_balance.saturating_add(amount);
        self.metadata.last_used = Some(Self::current_timestamp());

        // If address became funded and we have a key source, update address pool
        if was_unfunded && is_now_funded {
            if let Some(ks) = key_source {
                self.mark_and_maintain_gap_limit(&address, ks);
            }
        }

        new_balance
    }

    /// Remove credits from a specific address balance
    ///
    /// Uses saturating subtraction - balance will not go below zero.
    /// Returns the new credit balance for the address.
    pub fn remove_address_credit_balance(
        &mut self,
        address: PlatformP2PKHAddress,
        amount: u64,
    ) -> u64 {
        let current = self.address_balances.get(&address).copied().unwrap_or(0);
        // Only subtract what was actually removed (may be less due to saturating)
        let actual_removed = current.min(amount);
        let new_balance = current.saturating_sub(amount);
        self.address_balances.insert(address, new_balance);
        // Subtract only what was actually removed from the total
        self.credit_balance = self.credit_balance.saturating_sub(actual_removed);
        self.metadata.last_used = Some(Self::current_timestamp());
        new_balance
    }

    /// Recalculate total credit balance from address balances
    pub fn recalculate_credit_balance(&mut self) {
        self.credit_balance = self.address_balances.values().sum();
    }

    /// Clear all address balances and reset total balance
    pub fn clear_balances(&mut self) {
        self.address_balances.clear();
        self.credit_balance = 0;
    }

    /// Get all addresses with non-zero balances
    pub fn funded_addresses(&self) -> Vec<&PlatformP2PKHAddress> {
        self.address_balances
            .iter()
            .filter(|(_, &balance)| balance > 0)
            .map(|(addr, _)| addr)
            .collect()
    }

    /// Get the number of addresses with funds
    pub fn funded_address_count(&self) -> usize {
        self.address_balances.values().filter(|&&b| b > 0).count()
    }

    /// Check if an address belongs to this account
    pub fn contains_address(&self, address: &Address) -> bool {
        self.addresses.contains_address(address)
    }

    /// Check if a platform address belongs to this account
    pub fn contains_platform_address(&self, address: &PlatformP2PKHAddress) -> bool {
        // Check if we have it in address_balances
        if self.address_balances.contains_key(address) {
            return true;
        }

        // Check if the equivalent dashcore::Address is in the pool
        let dashcore_addr = address.to_address(self.network);
        self.addresses.contains_address(&dashcore_addr)
    }

    /// Get all addresses in the pool as PlatformP2PKHAddress
    pub fn all_platform_addresses(&self) -> Vec<PlatformP2PKHAddress> {
        self.addresses
            .all_addresses()
            .iter()
            .filter_map(|addr| PlatformP2PKHAddress::from_address(addr).ok())
            .collect()
    }

    /// Get all addresses in the pool
    pub fn all_addresses(&self) -> Vec<Address> {
        self.addresses.all_addresses()
    }

    /// Get the next unused address from the pool
    pub fn next_unused_address(
        &mut self,
        key_source: &super::address_pool::KeySource,
        add_to_state: bool,
    ) -> Result<Address> {
        self.addresses
            .next_unused(key_source, add_to_state)
            .map_err(|e| Error::InvalidParameter(format!("Failed to get next address: {}", e)))
    }

    /// Get the next unused platform address
    pub fn next_unused_platform_address(
        &mut self,
        key_source: &super::address_pool::KeySource,
        add_to_state: bool,
    ) -> Result<PlatformP2PKHAddress> {
        let addr = self.next_unused_address(key_source, add_to_state)?;
        PlatformP2PKHAddress::from_address(&addr)
    }

    /// Mark an address as used
    pub fn mark_address_used(&mut self, address: &Address) -> bool {
        let result = self.addresses.mark_used(address);
        if result {
            self.metadata.last_used = Some(Self::current_timestamp());
        }
        result
    }

    /// Mark a platform address as used
    pub fn mark_platform_address_used(&mut self, address: &PlatformP2PKHAddress) -> bool {
        let dashcore_addr = address.to_address(self.network);
        self.mark_address_used(&dashcore_addr)
    }

    /// Mark a platform address as used and maintain the gap limit
    ///
    /// This is called internally when an address receives funds for the first time.
    /// It marks the address as used in the address pool and generates new addresses
    /// if needed to maintain the gap limit.
    fn mark_and_maintain_gap_limit(
        &mut self,
        address: &PlatformP2PKHAddress,
        key_source: &KeySource,
    ) {
        // Mark the address as used
        self.mark_platform_address_used(address);

        // Maintain gap limit - generate new addresses if needed
        // We ignore errors here since this is a best-effort operation
        let _ = self.addresses.maintain_gap_limit(key_source);
    }

    /// Maintain the gap limit for the address pool
    ///
    /// This generates new addresses if needed to maintain the gap limit.
    /// Returns the newly generated addresses.
    pub fn maintain_gap_limit(&mut self, key_source: &KeySource) -> Result<Vec<Address>> {
        self.addresses
            .maintain_gap_limit(key_source)
            .map_err(|e| Error::InvalidParameter(format!("Failed to maintain gap limit: {}", e)))
    }

    /// Get address info for a given address
    pub fn get_address_info(&self, address: &Address) -> Option<super::address_pool::AddressInfo> {
        self.addresses.address_info(address).cloned()
    }

    /// Get the current timestamp
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

    /// Get pool statistics
    pub fn address_pool_stats(&self) -> super::address_pool::PoolStats {
        self.addresses.stats()
    }

    /// Get total address count in the pool
    pub fn total_address_count(&self) -> usize {
        self.addresses.stats().total_generated as usize
    }

    /// Get used address count in the pool
    pub fn used_address_count(&self) -> usize {
        self.addresses.stats().used_count as usize
    }

    /// Get the gap limit for the address pool
    pub fn gap_limit(&self) -> u32 {
        self.addresses.gap_limit
    }
}

#[cfg(feature = "bincode")]
impl bincode::Encode for ManagedPlatformAccount {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> core::result::Result<(), bincode::error::EncodeError> {
        // Encode each field
        bincode::Encode::encode(&self.account, encoder)?;
        bincode::Encode::encode(&self.key_class, encoder)?;
        bincode::Encode::encode(&self.network, encoder)?;
        bincode::Encode::encode(&self.credit_balance, encoder)?;

        // Encode address_balances as a vec of tuples
        let address_balances_vec: Vec<(PlatformP2PKHAddress, u64)> =
            self.address_balances.iter().map(|(k, v)| (*k, *v)).collect();
        bincode::Encode::encode(&address_balances_vec, encoder)?;

        bincode::Encode::encode(&self.addresses, encoder)?;
        bincode::Encode::encode(&self.metadata, encoder)?;
        bincode::Encode::encode(&self.is_watch_only, encoder)?;
        Ok(())
    }
}

#[cfg(feature = "bincode")]
impl<Context> bincode::Decode<Context> for ManagedPlatformAccount {
    fn decode<D: bincode::de::Decoder<Context = Context>>(
        decoder: &mut D,
    ) -> core::result::Result<Self, bincode::error::DecodeError> {
        let account = bincode::Decode::decode(decoder)?;
        let key_class = bincode::Decode::decode(decoder)?;
        let network = bincode::Decode::decode(decoder)?;
        let credit_balance = bincode::Decode::decode(decoder)?;

        // Decode address_balances from vec of tuples
        let address_balances_vec: Vec<(PlatformP2PKHAddress, u64)> =
            bincode::Decode::decode(decoder)?;
        let address_balances: BTreeMap<PlatformP2PKHAddress, u64> =
            address_balances_vec.into_iter().collect();

        let addresses = bincode::Decode::decode(decoder)?;
        let metadata = bincode::Decode::decode(decoder)?;
        let is_watch_only = bincode::Decode::decode(decoder)?;

        Ok(Self {
            account,
            key_class,
            network,
            credit_balance,
            address_balances,
            addresses,
            metadata,
            is_watch_only,
        })
    }
}

#[cfg(feature = "bincode")]
impl<'de, Context> bincode::BorrowDecode<'de, Context> for ManagedPlatformAccount {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = Context>>(
        decoder: &mut D,
    ) -> core::result::Result<Self, bincode::error::DecodeError> {
        // Use the regular decode implementation
        <Self as bincode::Decode<Context>>::decode(decoder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip32::{ChildNumber, DerivationPath};
    use crate::managed_account::address_pool::{AddressPool, AddressPoolType};

    fn create_test_pool() -> AddressPool {
        let base_path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(9).unwrap(),
            ChildNumber::from_hardened_idx(1).unwrap(),
            ChildNumber::from_hardened_idx(17).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
        ]);
        AddressPool::new_without_generation(
            base_path,
            AddressPoolType::Absent,
            10,
            Network::Testnet,
        )
    }

    #[test]
    fn test_new_account() {
        let pool = create_test_pool();
        let account = ManagedPlatformAccount::new(0, 0, pool, false);

        assert_eq!(account.account, 0);
        assert_eq!(account.key_class, 0);
        assert_eq!(account.network, Network::Testnet);
        assert_eq!(account.credit_balance, 0);
        assert!(account.address_balances.is_empty());
        assert!(!account.is_watch_only);
    }

    #[test]
    fn test_balance_operations() {
        let pool = create_test_pool();
        let mut account = ManagedPlatformAccount::new(0, 0, pool, false);

        // Set address credit balance (this also updates total)
        let addr = PlatformP2PKHAddress::new([0x11; 20]);
        account.set_address_credit_balance(addr, 500, None);
        assert_eq!(account.address_credit_balance(&addr), 500);
        assert_eq!(account.total_credit_balance(), 500);
        assert_eq!(account.duff_balance(), 0); // 500 credits = 0 duffs (integer division)

        // Add to address credit balance
        let new_balance = account.add_address_credit_balance(addr, 500, None);
        assert_eq!(new_balance, 1000);
        assert_eq!(account.total_credit_balance(), 1000);
        assert_eq!(account.duff_balance(), 1); // 1000 credits = 1 duff

        // Add more
        let new_balance = account.add_address_credit_balance(addr, 200, None);
        assert_eq!(new_balance, 1200);
        assert_eq!(account.total_credit_balance(), 1200);

        // Remove from address credit balance
        let new_balance = account.remove_address_credit_balance(addr, 100);
        assert_eq!(new_balance, 1100);
        assert_eq!(account.total_credit_balance(), 1100);

        // Update address balance directly (replacing existing)
        account.set_address_credit_balance(addr, 600, None);
        assert_eq!(account.address_credit_balance(&addr), 600);
        assert_eq!(account.total_credit_balance(), 600);
    }

    #[test]
    fn test_set_credit_balance_directly() {
        let pool = create_test_pool();
        let mut account = ManagedPlatformAccount::new(0, 0, pool, false);

        // set_credit_balance is for direct manipulation (e.g., deserialization)
        // When used alone (no address balances), it just sets the total
        account.set_credit_balance(1000);
        assert_eq!(account.total_credit_balance(), 1000);
        assert_eq!(account.duff_balance(), 1);

        account.set_credit_balance(2500);
        assert_eq!(account.total_credit_balance(), 2500);
        assert_eq!(account.duff_balance(), 2);
    }

    #[test]
    fn test_duff_balance_conversion() {
        let pool = create_test_pool();
        let mut account = ManagedPlatformAccount::new(0, 0, pool, false);

        // Test various credit to duff conversions
        account.set_credit_balance(0);
        assert_eq!(account.duff_balance(), 0);

        account.set_credit_balance(999);
        assert_eq!(account.duff_balance(), 0); // 999 credits = 0 duffs (integer division)

        account.set_credit_balance(1000);
        assert_eq!(account.duff_balance(), 1); // 1000 credits = 1 duff

        account.set_credit_balance(1500);
        assert_eq!(account.duff_balance(), 1); // 1500 credits = 1 duff

        account.set_credit_balance(5000);
        assert_eq!(account.duff_balance(), 5); // 5000 credits = 5 duffs

        account.set_credit_balance(1_000_000);
        assert_eq!(account.duff_balance(), 1000); // 1M credits = 1000 duffs
    }

    #[test]
    fn test_multiple_address_balances() {
        let pool = create_test_pool();
        let mut account = ManagedPlatformAccount::new(0, 0, pool, false);

        let addr1 = PlatformP2PKHAddress::new([0x11; 20]);
        let addr2 = PlatformP2PKHAddress::new([0x22; 20]);
        let addr3 = PlatformP2PKHAddress::new([0x33; 20]);

        account.set_address_credit_balance(addr1, 100, None);
        account.set_address_credit_balance(addr2, 200, None);
        account.set_address_credit_balance(addr3, 300, None);

        assert_eq!(account.total_credit_balance(), 600);
        assert_eq!(account.funded_address_count(), 3);

        // Set one to zero
        account.set_address_credit_balance(addr2, 0, None);
        assert_eq!(account.total_credit_balance(), 400);
        assert_eq!(account.funded_address_count(), 2);
    }

    #[test]
    fn test_clear_balances() {
        let pool = create_test_pool();
        let mut account = ManagedPlatformAccount::new(0, 0, pool, false);

        let addr = PlatformP2PKHAddress::new([0x11; 20]);
        account.set_address_credit_balance(addr, 1000, None);

        account.clear_balances();
        assert_eq!(account.total_credit_balance(), 0);
        assert!(account.address_balances.is_empty());
    }

    #[test]
    fn test_funded_addresses() {
        let pool = create_test_pool();
        let mut account = ManagedPlatformAccount::new(0, 0, pool, false);

        let addr1 = PlatformP2PKHAddress::new([0x11; 20]);
        let addr2 = PlatformP2PKHAddress::new([0x22; 20]);
        let addr3 = PlatformP2PKHAddress::new([0x33; 20]);

        account.set_address_credit_balance(addr1, 100, None);
        account.set_address_credit_balance(addr2, 0, None); // Zero balance
        account.set_address_credit_balance(addr3, 300, None);

        let funded = account.funded_addresses();
        assert_eq!(funded.len(), 2);
        assert!(funded.contains(&&addr1));
        assert!(funded.contains(&&addr3));
        assert!(!funded.contains(&&addr2));
    }

    #[test]
    fn test_contains_platform_address() {
        let pool = create_test_pool();
        let mut account = ManagedPlatformAccount::new(0, 0, pool, false);

        let addr = PlatformP2PKHAddress::new([0x11; 20]);

        // Initially not in balances
        assert!(!account.address_balances.contains_key(&addr));

        // Add to balances
        account.set_address_credit_balance(addr, 100, None);
        assert!(account.contains_platform_address(&addr));
    }
}
