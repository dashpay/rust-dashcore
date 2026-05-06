//! Wallet balance
//!
//! This module provides a wallet balance structure containing all available balances.

use core::fmt::{Display, Formatter};
use core::ops::AddAssign;
use dashcore::Amount;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Wallet balance breakdown.
///
/// Both `confirmed` and `unconfirmed` funds are spendable — the
/// split exists purely so callers can surface the distinction to
/// users. `spendable()` returns their sum.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WalletCoreBalance {
    /// Mature UTXOs that are confirmed in a block or InstantSend-locked.
    confirmed: u64,
    /// Mature UTXOs that are seen in the mempool but not yet confirmed
    /// or InstantSend-locked. Still spendable — just not settled.
    unconfirmed: u64,
    /// Immature balance (UTXOs without enough confirmations for maturity, e.g. 100 for coinbase).
    immature: u64,
    /// Locked balance (UTXOs reserved for specific purposes like CoinJoin).
    locked: u64,
}

impl WalletCoreBalance {
    /// Create a new wallet balance.
    pub fn new(confirmed: u64, unconfirmed: u64, immature: u64, locked: u64) -> Self {
        Self {
            confirmed,
            unconfirmed,
            immature,
            locked,
        }
    }

    /// Get the confirmed balance: mature UTXOs that are in a block or InstantSend-locked.
    pub fn confirmed(&self) -> u64 {
        self.confirmed
    }

    /// Get the unconfirmed balance: mature mempool UTXOs that are not yet
    /// confirmed or InstantSend-locked. Also spendable.
    pub fn unconfirmed(&self) -> u64 {
        self.unconfirmed
    }

    /// Get the total spendable balance (confirmed + unconfirmed).
    pub fn spendable(&self) -> u64 {
        self.confirmed + self.unconfirmed
    }

    /// Get the immature balance.
    pub fn immature(&self) -> u64 {
        self.immature
    }

    /// Get the locked balance.
    pub fn locked(&self) -> u64 {
        self.locked
    }

    /// Get the total balance.
    pub fn total(&self) -> u64 {
        self.confirmed + self.unconfirmed + self.immature + self.locked
    }
}

impl Display for WalletCoreBalance {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Confirmed: {}, Unconfirmed: {}, Immature: {}, Locked: {}, Total: {}",
            Amount::from_sat(self.confirmed),
            Amount::from_sat(self.unconfirmed),
            Amount::from_sat(self.immature),
            Amount::from_sat(self.locked),
            Amount::from_sat(self.total())
        )
    }
}

impl AddAssign for WalletCoreBalance {
    fn add_assign(&mut self, other: Self) {
        self.confirmed += other.confirmed;
        self.unconfirmed += other.unconfirmed;
        self.immature += other.immature;
        self.locked += other.locked;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_balance_creation_and_getters() {
        let balance = WalletCoreBalance::new(1000, 500, 100, 200);
        assert_eq!(balance.confirmed(), 1000);
        assert_eq!(balance.unconfirmed(), 500);
        assert_eq!(balance.spendable(), 1500);
        assert_eq!(balance.immature(), 100);
        assert_eq!(balance.locked(), 200);
        assert_eq!(balance.total(), 1800);
    }

    #[test]
    #[should_panic(expected = "attempt to add with overflow")]
    fn test_balance_overflow() {
        let balance = WalletCoreBalance::new(u64::MAX, u64::MAX, u64::MAX, u64::MAX);
        balance.total();
    }

    #[test]
    fn test_balance_display() {
        let zero = WalletCoreBalance::default();
        assert_eq!(
            zero.to_string(),
            "Confirmed: 0 DASH, Unconfirmed: 0 DASH, Immature: 0 DASH, Locked: 0 DASH, Total: 0 DASH"
        );

        let balance = WalletCoreBalance::new(100_000_000, 50_000_000, 10_000_000, 20_000_000);
        let display = balance.to_string();
        assert_eq!(
            display,
            "Confirmed: 1 DASH, Unconfirmed: 0.5 DASH, Immature: 0.1 DASH, Locked: 0.2 DASH, Total: 1.8 DASH"
        );
    }

    #[test]
    fn test_balance_add_assign() {
        let mut balance = WalletCoreBalance::new(1000, 500, 50, 200);
        let balance_add = WalletCoreBalance::new(300, 100, 100, 50);
        // Test adding actual balances
        balance += balance_add;
        assert_eq!(balance.confirmed(), 1300);
        assert_eq!(balance.unconfirmed(), 600);
        assert_eq!(balance.immature(), 150);
        assert_eq!(balance.locked(), 250);
        assert_eq!(balance.total(), 2300);
        // Test adding zero balances
        let balance_before = balance;
        balance += WalletCoreBalance::default();
        assert_eq!(balance_before, balance);
    }
}
