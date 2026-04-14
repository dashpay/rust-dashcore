//! UTXO management for wallet operations
//!
//! This module provides UTXO tracking and management functionality
//! that works with dashcore transaction types.

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

    /// Check if this UTXO can be spent at the given height.
    ///
    /// A UTXO is spendable unless it is locked or (for coinbase)
    /// immature. Mempool 0-conf outputs are spendable — callers that
    /// want to restrict to confirmed/InstantLocked UTXOs (e.g. the
    /// "spendable" balance bucket or conservative coin selection)
    /// should check `is_confirmed || is_instantlocked` themselves.
    pub fn is_spendable(&self, current_height: u32) -> bool {
        if self.is_locked {
            return false;
        }
        self.is_mature(current_height)
    }

    /// Check if this UTXO is mature enough for spending
    pub fn is_mature(&self, current_height: u32) -> bool {
        if self.is_coinbase {
            current_height >= self.height + 100
        } else {
            true
        }
    }

    /// Get the number of confirmations for this UTXO
    pub fn confirmations(&self, current_height: u32) -> u32 {
        if self.is_confirmed && current_height >= self.height {
            current_height - self.height + 1
        } else {
            0
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

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test]
    fn test_utxo_spendability() {
        let mut utxo = Utxo::dummy(0, 100000, 100, false, false);

        // Non-coinbase UTXOs are spendable even at 0 confs
        assert!(utxo.is_spendable(200));

        // Setting is_confirmed does not affect spendability
        utxo.is_confirmed = true;
        assert!(utxo.is_spendable(200));

        // Locked UTXO should not be spendable
        utxo.lock();
        assert!(!utxo.is_spendable(200));
        utxo.unlock();

        // Coinbase still requires 100 confirmations
        let mut cb = Utxo::dummy(0, 100000, 100, true, false);
        assert!(!cb.is_spendable(150));
        assert!(cb.is_spendable(200));
        cb.lock();
        assert!(!cb.is_spendable(200));
    }

    #[test_case(false, 0, 500, 0 ; "unconfirmed utxo has 0 confirmations")]
    #[test_case(true, 0, 500, 501 ; "confirmed utxo at genesis height has 501 confirmations")]
    #[test_case(true, 1000, 500, 0 ; "utxo height greater than current height has 0 confirmations")]
    #[test_case(true, 500, 500, 1 ; "utxo at current height has 1 confirmation")]
    #[test_case(true, 100, 500, 401 ; "normal case has current_height minus utxo_height plus 1 confirmations")]
    fn test_confirmations(
        is_confirmed: bool,
        utxo_height: u32,
        current_height: u32,
        expected: u32,
    ) {
        let utxo = Utxo::dummy(0, 100000, utxo_height, false, is_confirmed);
        assert_eq!(utxo.confirmations(current_height), expected);
    }
}
