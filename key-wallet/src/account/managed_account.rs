//! Managed account structure with mutable state
//!
//! This module contains the mutable account state that changes during wallet operation,
//! kept separate from the immutable Account structure.

use super::metadata::AccountMetadata;
use super::transaction_record::TransactionRecord;
use super::types::ManagedAccountType;
use crate::gap_limit::GapLimitManager;
use crate::wallet::balance::WalletBalance;
use crate::Network;
use alloc::collections::{BTreeMap, BTreeSet};
use dashcore::Address;
use dashcore::blockdata::transaction::OutPoint;
use dashcore::blockdata::transaction::txout::TxOut;
use dashcore::Txid;
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

/// Simple UTXO representation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Utxo {
    /// The outpoint
    pub outpoint: OutPoint,
    /// The output
    pub txout: TxOut,
    /// The address this UTXO belongs to
    pub address: Address,
    /// Confirmation height
    pub height: Option<u32>,
    /// Whether this UTXO is locked/reserved
    pub is_locked: bool,
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

    /// Get the account index
    pub fn index(&self) -> Option<u32> {
        self.account_type.index()
    }
    
    /// Get the account index or 0 if none exists
    pub fn index_or_default(&self) -> u32 {
        self.account_type.index_or_default()
    }

    /// Get the next unused receive address index for standard accounts
    /// Note: This requires a key source which is not available in ManagedAccount
    /// Address generation should be done through a method that has access to the Account's keys
    pub fn get_next_receive_address_index(&self) -> Option<u32> {
        // Only applicable for standard accounts
        if let ManagedAccountType::Standard { external_addresses, .. } = &self.account_type {
            external_addresses
                .get_unused_addresses()
                .first()
                .and_then(|addr| external_addresses.get_address_index(addr))
        } else {
            None
        }
    }

    /// Get the next unused change address index for standard accounts
    /// Note: This requires a key source which is not available in ManagedAccount
    /// Address generation should be done through a method that has access to the Account's keys
    pub fn get_next_change_address_index(&self) -> Option<u32> {
        // Only applicable for standard accounts
        if let ManagedAccountType::Standard { internal_addresses, .. } = &self.account_type {
            internal_addresses
                .get_unused_addresses()
                .first()
                .and_then(|addr| internal_addresses.get_address_index(addr))
        } else {
            None
        }
    }

    /// Get the next unused address index for single-pool account types
    pub fn get_next_address_index(&self) -> Option<u32> {
        match &self.account_type {
            ManagedAccountType::Standard { .. } => self.get_next_receive_address_index(),
            ManagedAccountType::CoinJoin { addresses, .. } |
            ManagedAccountType::IdentityRegistration { addresses, .. } |
            ManagedAccountType::IdentityTopUp { addresses, .. } |
            ManagedAccountType::IdentityTopUpNotBoundToIdentity { addresses, .. } |
            ManagedAccountType::IdentityInvitation { addresses, .. } |
            ManagedAccountType::ProviderVotingKeys { addresses, .. } |
            ManagedAccountType::ProviderOwnerKeys { addresses, .. } |
            ManagedAccountType::ProviderOperatorKeys { addresses, .. } |
            ManagedAccountType::ProviderPlatformKeys { addresses, .. } => {
                addresses
                    .get_unused_addresses()
                    .first()
                    .and_then(|addr| addresses.get_address_index(addr))
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
                ManagedAccountType::Standard { external_addresses, internal_addresses, .. } => {
                    if let Some(index) = external_addresses.get_address_index(address) {
                        self.gap_limits.external.mark_used(index);
                    } else if let Some(index) = internal_addresses.get_address_index(address) {
                        self.gap_limits.internal.mark_used(index);
                    }
                }
                _ => {
                    // For single-pool account types, update the external gap limit
                    for pool in self.account_type.get_address_pools() {
                        if let Some(index) = pool.get_address_index(address) {
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
    pub fn update_balance(&mut self, confirmed: u64, unconfirmed: u64, locked: u64) -> Result<(), crate::wallet::balance::BalanceError> {
        self.balance.update(confirmed, unconfirmed, locked)?;
        self.metadata.last_used = Some(Self::current_timestamp());
        Ok(())
    }

    /// Get all addresses from all pools
    pub fn get_all_addresses(&self) -> alloc::vec::Vec<Address> {
        self.account_type.get_all_addresses()
    }

    /// Check if an address belongs to this account
    pub fn contains_address(&self, address: &Address) -> bool {
        self.account_type.contains_address(address)
    }

    /// Get the derivation path for an address if it belongs to this account
    pub fn get_address_derivation_path(&self, address: &Address) -> Option<crate::DerivationPath> {
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
            .get_address_pools()
            .iter()
            .map(|pool| pool.stats().total_generated as usize)
            .sum()
    }

    /// Get used address count across all pools
    pub fn used_address_count(&self) -> usize {
        self.account_type
            .get_address_pools()
            .iter()
            .map(|pool| pool.stats().used_count as usize)
            .sum()
    }
}
