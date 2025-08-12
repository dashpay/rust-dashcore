//! Managed account structure with mutable state
//!
//! This module contains the mutable account state that changes during wallet operation,
//! kept separate from the immutable Account structure.

use super::address_pool::AddressPool;
use super::balance::AccountBalance;
use super::coinjoin::CoinJoinPools;
use super::metadata::AccountMetadata;
use super::types::AccountType;
use crate::gap_limit::GapLimitManager;
use crate::Network;
use dashcore::Address;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Managed account with mutable state
///
/// This struct contains the mutable state of an account including address pools,
/// gap limits, metadata, and balance information. It is managed separately from
/// the immutable Account structure.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ManagedAccount {
    /// Account index (BIP44 account level)
    pub index: u32,
    /// Account type
    pub account_type: AccountType,
    /// Network this account belongs to
    pub network: Network,
    /// External (receive) address pool
    pub external_addresses: AddressPool,
    /// Internal (change) address pool
    pub internal_addresses: AddressPool,
    /// CoinJoin address pools (if enabled)
    pub coinjoin_addresses: Option<CoinJoinPools>,
    /// Gap limit manager
    pub gap_limits: GapLimitManager,
    /// Account metadata
    pub metadata: AccountMetadata,
    /// Whether this is a watch-only account
    pub is_watch_only: bool,
    /// Account balance information
    pub balance: AccountBalance,
}

impl ManagedAccount {
    /// Create a new managed account
    pub fn new(
        index: u32,
        account_type: AccountType,
        network: Network,
        external_addresses: AddressPool,
        internal_addresses: AddressPool,
        gap_limits: GapLimitManager,
        is_watch_only: bool,
    ) -> Self {
        Self {
            index,
            account_type,
            network,
            external_addresses,
            internal_addresses,
            coinjoin_addresses: None,
            gap_limits,
            metadata: AccountMetadata::default(),
            is_watch_only,
            balance: AccountBalance::default(),
        }
    }

    /// Enable CoinJoin for this account
    pub fn enable_coinjoin(&mut self, coinjoin_pools: CoinJoinPools) {
        self.coinjoin_addresses = Some(coinjoin_pools);
    }

    /// Disable CoinJoin for this account
    pub fn disable_coinjoin(&mut self) {
        self.coinjoin_addresses = None;
    }

    /// Get the next unused receive address
    /// Note: This requires a key source which is not available in ManagedAccount
    /// Address generation should be done through a method that has access to the Account's keys
    pub fn get_next_receive_address_index(&self) -> Option<u32> {
        // Return the next unused index (would need key source to generate actual address)
        self.external_addresses
            .get_unused_addresses()
            .first()
            .and_then(|addr| self.external_addresses.get_address_index(addr))
    }

    /// Get the next unused change address
    /// Note: This requires a key source which is not available in ManagedAccount
    /// Address generation should be done through a method that has access to the Account's keys
    pub fn get_next_change_address_index(&self) -> Option<u32> {
        // Return the next unused index (would need key source to generate actual address)
        self.internal_addresses
            .get_unused_addresses()
            .first()
            .and_then(|addr| self.internal_addresses.get_address_index(addr))
    }

    /// Get the next unused CoinJoin receive address
    /// Note: This requires a key source which is not available in ManagedAccount
    /// Address generation should be done through a method that has access to the Account's keys
    pub fn get_next_coinjoin_receive_address_index(&self) -> Option<u32> {
        self.coinjoin_addresses.as_ref().and_then(|cj| {
            cj.external
                .get_unused_addresses()
                .first()
                .and_then(|addr| cj.external.get_address_index(addr))
        })
    }

    /// Get the next unused CoinJoin change address
    /// Note: This requires a key source which is not available in ManagedAccount
    /// Address generation should be done through a method that has access to the Account's keys
    pub fn get_next_coinjoin_change_address_index(&self) -> Option<u32> {
        self.coinjoin_addresses.as_ref().and_then(|cj| {
            cj.internal
                .get_unused_addresses()
                .first()
                .and_then(|addr| cj.internal.get_address_index(addr))
        })
    }

    /// Mark an address as used
    pub fn mark_address_used(&mut self, address: &Address) -> bool {
        // Update metadata timestamp
        self.metadata.last_used = Some(Self::current_timestamp());

        // Try external addresses first
        if self.external_addresses.mark_used(address) {
            if let Some(index) = self.external_addresses.get_address_index(address) {
                self.gap_limits.external.mark_used(index);
            }
            return true;
        }

        // Try internal addresses
        if self.internal_addresses.mark_used(address) {
            if let Some(index) = self.internal_addresses.get_address_index(address) {
                self.gap_limits.internal.mark_used(index);
            }
            return true;
        }

        // Try CoinJoin addresses if enabled
        if let Some(ref mut cj) = self.coinjoin_addresses {
            if cj.external.mark_used(address) {
                if let Some(index) = cj.external.get_address_index(address) {
                    if let Some(ref mut cj_gap) = self.gap_limits.coinjoin {
                        cj_gap.mark_used(index);
                    }
                }
                return true;
            }
            if cj.internal.mark_used(address) {
                if let Some(index) = cj.internal.get_address_index(address) {
                    if let Some(ref mut cj_gap) = self.gap_limits.coinjoin {
                        cj_gap.mark_used(index);
                    }
                }
                return true;
            }
        }

        false
    }

    /// Update the account balance
    pub fn update_balance(&mut self, confirmed: u64, unconfirmed: u64, immature: u64) {
        self.balance.confirmed = confirmed;
        self.balance.unconfirmed = unconfirmed;
        self.balance.immature = immature;
        self.balance.total = confirmed + unconfirmed;
        self.metadata.last_used = Some(Self::current_timestamp());
    }

    /// Get all addresses from all pools
    pub fn get_all_addresses(&self) -> alloc::vec::Vec<Address> {
        let mut addresses = self.external_addresses.get_all_addresses();
        addresses.extend(self.internal_addresses.get_all_addresses());

        if let Some(ref cj) = self.coinjoin_addresses {
            addresses.extend(cj.external.get_all_addresses());
            addresses.extend(cj.internal.get_all_addresses());
        }

        addresses
    }

    /// Check if an address belongs to this account
    pub fn contains_address(&self, address: &Address) -> bool {
        self.external_addresses.contains_address(address)
            || self.internal_addresses.contains_address(address)
            || self
                .coinjoin_addresses
                .as_ref()
                .map(|cj| {
                    cj.external.contains_address(address) || cj.internal.contains_address(address)
                })
                .unwrap_or(false)
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
        let external_stats = self.external_addresses.stats();
        let internal_stats = self.internal_addresses.stats();
        let mut total =
            external_stats.total_generated as usize + internal_stats.total_generated as usize;

        if let Some(ref cj) = self.coinjoin_addresses {
            let cj_external_stats = cj.external.stats();
            let cj_internal_stats = cj.internal.stats();
            total += cj_external_stats.total_generated as usize
                + cj_internal_stats.total_generated as usize;
        }

        total
    }

    /// Get used address count across all pools
    pub fn used_address_count(&self) -> usize {
        let external_stats = self.external_addresses.stats();
        let internal_stats = self.internal_addresses.stats();
        let mut total = external_stats.used_count as usize + internal_stats.used_count as usize;

        if let Some(ref cj) = self.coinjoin_addresses {
            let cj_external_stats = cj.external.stats();
            let cj_internal_stats = cj.internal.stats();
            total += cj_external_stats.used_count as usize + cj_internal_stats.used_count as usize;
        }

        total
    }
}
