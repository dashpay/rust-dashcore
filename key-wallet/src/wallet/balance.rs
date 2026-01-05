//! Wallet balance
//!
//! This module provides a wallet balance structure containing all available balances.

use core::fmt::{Display, Formatter};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Wallet balance breakdown
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WalletBalance {
    /// Confirmed and mature balance (UTXOs with enough confirmations to be spendable)
    spendable: u64,
    /// Unconfirmed balance (UTXOs without confirmations)
    unconfirmed: u64,
    /// Locked balance (UTXOs reserved for specific purposes like CoinJoin)
    locked: u64,
}

impl WalletBalance {
    /// Create a new wallet balance
    pub fn new(spendable: u64, unconfirmed: u64, locked: u64) -> Self {
        Self {
            spendable,
            unconfirmed,
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

    /// Get the locked balance.
    pub fn locked(&self) -> u64 {
        self.locked
    }

    /// Get the total balance.
    pub fn total(&self) -> u64 {
        self.spendable + self.unconfirmed + self.locked
    }
}

impl Display for WalletBalance {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Spendable: {}, Unconfirmed: {}, Locked: {}, Total: {}",
            self.spendable,
            self.unconfirmed,
            self.locked,
            self.total()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_balance_creation_and_getters() {
        let balance = WalletBalance::new(1000, 500, 200);
        assert_eq!(balance.spendable(), 1000);
        assert_eq!(balance.unconfirmed(), 500);
        assert_eq!(balance.locked(), 200);
        assert_eq!(balance.total(), 1700);
    }

    #[test]
    #[should_panic(expected = "attempt to add with overflow")]
    fn test_balance_overflow() {
        let balance = WalletBalance::new(u64::MAX, u64::MAX, u64::MAX);
        balance.total();
    }

    #[test]
    fn test_balance_display() {
        let zero = WalletBalance::default();
        assert_eq!(zero.to_string(), "Spendable: 0, Unconfirmed: 0, Locked: 0, Total: 0");

        let balance = WalletBalance::new(1000, 500, 200);
        let display = balance.to_string();
        assert_eq!(display, "Spendable: 1000, Unconfirmed: 500, Locked: 200, Total: 1700");
    }
}
