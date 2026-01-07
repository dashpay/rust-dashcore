//! UTXO management for wallet operations
//!
//! This module provides UTXO tracking and management functionality
//! that works with dashcore transaction types.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::Address;
use dashcore::blockdata::transaction::txout::TxOut;
use dashcore::blockdata::transaction::OutPoint;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Unspent Transaction Output
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Utxo {
    /// The outpoint (txid + vout)
    pub outpoint: OutPoint,
    /// The transaction output
    pub txout: TxOut,
    /// The address this UTXO belongs to
    pub address: Address,
    /// Block height where this UTXO was created
    pub height: u32,
    /// Whether this is from a coinbase transaction
    pub is_coinbase: bool,
    /// Whether this UTXO is confirmed
    pub is_confirmed: bool,
    /// Whether this UTXO has an InstantLock
    pub is_instantlocked: bool,
    /// Whether this UTXO is locked (not available for spending)
    pub is_locked: bool,
}

impl Utxo {
    /// Create a new UTXO
    pub fn new(
        outpoint: OutPoint,
        txout: TxOut,
        address: Address,
        height: u32,
        is_coinbase: bool,
    ) -> Self {
        Self {
            outpoint,
            txout,
            address,
            height,
            is_coinbase,
            is_confirmed: false,
            is_instantlocked: false,
            is_locked: false,
        }
    }

    /// Get the value of this UTXO in satoshis
    pub fn value(&self) -> u64 {
        self.txout.value
    }

    /// Check if this UTXO can be spent at the given height
    pub fn is_spendable(&self, current_height: u32) -> bool {
        if self.is_locked {
            return false;
        }

        if !self.is_coinbase {
            // Regular UTXOs need to be confirmed or InstantLocked
            self.is_confirmed || self.is_instantlocked
        } else {
            // Coinbase outputs require 100 confirmations
            current_height >= self.height + 100
        }
    }

    /// Check if this UTXO is mature enough for spending
    pub fn is_mature(&self, current_height: u32) -> bool {
        if self.is_coinbase {
            current_height >= self.height + 100
        } else {
            true
        }
    }

    /// Lock this UTXO to prevent it from being selected
    pub fn lock(&mut self) {
        self.is_locked = true;
    }

    /// Unlock this UTXO to allow it to be selected
    pub fn unlock(&mut self) {
        self.is_locked = false;
    }
}

impl Ord for Utxo {
    fn cmp(&self, other: &Self) -> Ordering {
        // Order by value (ascending)
        self.outpoint.cmp(&other.outpoint)
    }
}

impl PartialOrd for Utxo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// UTXO set management
#[derive(Debug, Clone)]
pub struct UtxoSet {
    /// UTXOs indexed by outpoint
    utxos: BTreeMap<OutPoint, Utxo>,
    /// Total balance
    total_balance: u64,
    /// Confirmed balance
    confirmed_balance: u64,
    /// Unconfirmed balance
    unconfirmed_balance: u64,
    /// Locked balance
    locked_balance: u64,
}

impl UtxoSet {
    /// Create a new empty UTXO set
    pub fn new() -> Self {
        Self {
            utxos: BTreeMap::new(),
            total_balance: 0,
            confirmed_balance: 0,
            unconfirmed_balance: 0,
            locked_balance: 0,
        }
    }

    /// Add a UTXO to the set
    pub fn add(&mut self, utxo: Utxo) {
        let value = utxo.value();

        // Update balances
        self.total_balance += value;

        if utxo.is_confirmed || utxo.is_instantlocked {
            self.confirmed_balance += value;
        } else {
            self.unconfirmed_balance += value;
        }

        if utxo.is_locked {
            self.locked_balance += value;
        }

        self.utxos.insert(utxo.outpoint, utxo);
    }

    /// Remove a UTXO from the set
    pub fn remove(&mut self, outpoint: &OutPoint) -> Option<Utxo> {
        if let Some(utxo) = self.utxos.remove(outpoint) {
            let value = utxo.value();

            // Update balances
            self.total_balance = self.total_balance.saturating_sub(value);

            if utxo.is_confirmed || utxo.is_instantlocked {
                self.confirmed_balance = self.confirmed_balance.saturating_sub(value);
            } else {
                self.unconfirmed_balance = self.unconfirmed_balance.saturating_sub(value);
            }

            if utxo.is_locked {
                self.locked_balance = self.locked_balance.saturating_sub(value);
            }

            Some(utxo)
        } else {
            None
        }
    }

    /// Get a UTXO by outpoint
    pub fn get(&self, outpoint: &OutPoint) -> Option<&Utxo> {
        self.utxos.get(outpoint)
    }

    /// Get a mutable UTXO by outpoint
    pub fn get_mut(&mut self, outpoint: &OutPoint) -> Option<&mut Utxo> {
        self.utxos.get_mut(outpoint)
    }

    /// Check if a UTXO exists
    pub fn contains(&self, outpoint: &OutPoint) -> bool {
        self.utxos.contains_key(outpoint)
    }

    /// Get all UTXOs
    pub fn all(&self) -> Vec<&Utxo> {
        self.utxos.values().collect()
    }

    /// Get all spendable UTXOs
    pub fn spendable(&self, current_height: u32) -> Vec<&Utxo> {
        self.utxos.values().filter(|utxo| utxo.is_spendable(current_height)).collect()
    }

    /// Get all UTXOs for a specific address
    pub fn for_address(&self, address: &Address) -> Vec<&Utxo> {
        self.utxos.values().filter(|utxo| &utxo.address == address).collect()
    }

    /// Get total balance
    pub fn total_balance(&self) -> u64 {
        self.total_balance
    }

    /// Get confirmed balance
    pub fn confirmed_balance(&self) -> u64 {
        self.confirmed_balance
    }

    /// Get unconfirmed balance
    pub fn unconfirmed_balance(&self) -> u64 {
        self.unconfirmed_balance
    }

    /// Get locked balance
    pub fn locked_balance(&self) -> u64 {
        self.locked_balance
    }

    /// Get spendable balance
    pub fn spendable_balance(&self, current_height: u32) -> u64 {
        self.spendable(current_height).iter().map(|utxo| utxo.value()).sum()
    }

    /// Clear all UTXOs
    pub fn clear(&mut self) {
        self.utxos.clear();
        self.total_balance = 0;
        self.confirmed_balance = 0;
        self.unconfirmed_balance = 0;
        self.locked_balance = 0;
    }

    /// Get the number of UTXOs
    pub fn len(&self) -> usize {
        self.utxos.len()
    }

    /// Check if the set is empty
    pub fn is_empty(&self) -> bool {
        self.utxos.is_empty()
    }

    /// Update confirmation status for a UTXO
    pub fn update_confirmation(&mut self, outpoint: &OutPoint, confirmed: bool) {
        if let Some(utxo) = self.utxos.get_mut(outpoint) {
            let value = utxo.value();

            if utxo.is_confirmed != confirmed {
                if confirmed {
                    self.confirmed_balance += value;
                    self.unconfirmed_balance = self.unconfirmed_balance.saturating_sub(value);
                } else {
                    self.unconfirmed_balance += value;
                    self.confirmed_balance = self.confirmed_balance.saturating_sub(value);
                }
                utxo.is_confirmed = confirmed;
            }
        }
    }

    /// Lock a UTXO
    pub fn lock_utxo(&mut self, outpoint: &OutPoint) -> bool {
        if let Some(utxo) = self.utxos.get_mut(outpoint) {
            if !utxo.is_locked {
                utxo.lock();
                self.locked_balance += utxo.value();
                return true;
            }
        }
        false
    }

    /// Unlock a UTXO
    pub fn unlock_utxo(&mut self, outpoint: &OutPoint) -> bool {
        if let Some(utxo) = self.utxos.get_mut(outpoint) {
            if utxo.is_locked {
                utxo.unlock();
                self.locked_balance = self.locked_balance.saturating_sub(utxo.value());
                return true;
            }
        }
        false
    }
}

impl Default for UtxoSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utxo_spendability() {
        let mut utxo = Utxo::dummy(0, 100000, 100, false, false);

        // Unconfirmed UTXO should not be spendable
        assert!(!utxo.is_spendable(200));

        // Confirmed UTXO should be spendable
        utxo.is_confirmed = true;
        assert!(utxo.is_spendable(200));

        // Locked UTXO should not be spendable
        utxo.lock();
        assert!(!utxo.is_spendable(200));
    }

    #[test]
    fn test_utxo_set_operations() {
        let mut set = UtxoSet::new();

        let utxo1 = Utxo::dummy(0, 100000, 100, false, false);
        let utxo2 = Utxo::dummy(1, 200000, 150, false, false);

        set.add(utxo1.clone());
        set.add(utxo2.clone());

        assert_eq!(set.len(), 2);
        assert_eq!(set.total_balance(), 300000);
        assert_eq!(set.unconfirmed_balance(), 300000);
        assert_eq!(set.confirmed_balance(), 0);

        // Update confirmation
        set.update_confirmation(&utxo1.outpoint, true);
        assert_eq!(set.confirmed_balance(), 100000);
        assert_eq!(set.unconfirmed_balance(), 200000);

        // Remove UTXO
        let removed = set.remove(&utxo1.outpoint);
        assert!(removed.is_some());
        assert_eq!(set.len(), 1);
        assert_eq!(set.total_balance(), 200000);
    }
}
