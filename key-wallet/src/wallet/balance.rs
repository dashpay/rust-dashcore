//! Wallet balance
//!
//! This module provides a wallet balance structure containing all available balances.

use crate::changeset::BalanceChangeSet;
use core::fmt::{Display, Formatter};
use core::ops::AddAssign;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Wallet balance breakdown
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WalletCoreBalance {
    /// Confirmed and mature balance (UTXOs with enough confirmations to be spendable)
    spendable: u64,
    /// Unconfirmed balance (UTXOs without confirmations)
    unconfirmed: u64,
    /// Immature balance (UTXOs without enough confirmations for maturity. e.g., 100 for coinbase.)
    immature: u64,
    /// Locked balance (UTXOs reserved for specific purposes like CoinJoin)
    locked: u64,
}

impl WalletCoreBalance {
    /// Create a new wallet balance
    pub fn new(spendable: u64, unconfirmed: u64, immature: u64, locked: u64) -> Self {
        Self {
            spendable,
            unconfirmed,
            immature,
            locked,
        }
    }

    /// Get the spendable balance.
    pub fn spendable(&self) -> u64 {
        self.spendable
    }

    /// Get the unconfirmed balance.
    pub fn unconfirmed(&self) -> u64 {
        self.unconfirmed
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
        self.spendable + self.unconfirmed + self.immature + self.locked
    }

    /// Apply a [`BalanceChangeSet`] (signed deltas) to this balance.
    ///
    /// Each field is adjusted by adding the corresponding delta. Negative deltas
    /// that would underflow are clamped to zero.
    pub fn apply_delta(&mut self, delta: &BalanceChangeSet) {
        self.spendable = apply_signed_delta(self.spendable, delta.spendable_delta);
        self.unconfirmed = apply_signed_delta(self.unconfirmed, delta.unconfirmed_delta);
        self.immature = apply_signed_delta(self.immature, delta.immature_delta);
        self.locked = apply_signed_delta(self.locked, delta.locked_delta);
    }
}

/// Apply a signed delta to an unsigned value, clamping at zero on underflow.
fn apply_signed_delta(value: u64, delta: i64) -> u64 {
    if delta >= 0 {
        value.saturating_add(delta as u64)
    } else {
        value.saturating_sub(delta.unsigned_abs())
    }
}

impl Display for WalletCoreBalance {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Spendable: {}, Unconfirmed: {}, Immature: {}, Locked: {}, Total: {}",
            self.spendable,
            self.unconfirmed,
            self.immature,
            self.locked,
            self.total()
        )
    }
}

impl AddAssign for WalletCoreBalance {
    fn add_assign(&mut self, other: Self) {
        self.spendable += other.spendable;
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
        assert_eq!(balance.spendable(), 1000);
        assert_eq!(balance.unconfirmed(), 500);
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
            "Spendable: 0, Unconfirmed: 0, Immature: 0, Locked: 0, Total: 0"
        );

        let balance = WalletCoreBalance::new(1000, 500, 100, 200);
        let display = balance.to_string();
        assert_eq!(
            display,
            "Spendable: 1000, Unconfirmed: 500, Immature: 100, Locked: 200, Total: 1800"
        );
    }

    #[test]
    fn test_balance_add_assign() {
        let mut balance = WalletCoreBalance::new(1000, 500, 50, 200);
        let balance_add = WalletCoreBalance::new(300, 100, 100, 50);
        // Test adding actual balances
        balance += balance_add;
        assert_eq!(balance.spendable(), 1300);
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
