//! Wallet balance management
//!
//! This module provides wallet balance tracking and state transition functionality
//! for managing confirmed, unconfirmed, and locked balances.

use alloc::string::String;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Wallet balance breakdown
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WalletBalance {
    /// Confirmed balance (UTXOs with confirmations)
    pub confirmed: u64,
    /// Unconfirmed balance (UTXOs without confirmations)
    pub unconfirmed: u64,
    /// Locked balance (UTXOs reserved for specific purposes like CoinJoin)
    pub locked: u64,
    /// Total balance (sum of all balances)
    pub total: u64,
}

impl WalletBalance {
    /// Create a new wallet balance
    pub fn new(confirmed: u64, unconfirmed: u64, locked: u64) -> Result<Self, BalanceError> {
        let total = confirmed
            .checked_add(unconfirmed)
            .and_then(|sum| sum.checked_add(locked))
            .ok_or(BalanceError::Overflow)?;

        Ok(Self {
            confirmed,
            unconfirmed,
            locked,
            total,
        })
    }

    /// Create an empty balance
    pub fn zero() -> Self {
        Self::default()
    }

    /// Get spendable balance (confirmed only, excluding locked)
    pub fn spendable(&self) -> u64 {
        self.confirmed
    }

    /// Get pending balance (unconfirmed)
    pub fn pending(&self) -> u64 {
        self.unconfirmed
    }

    /// Get available balance (confirmed + unconfirmed, excluding locked)
    pub fn available(&self) -> u64 {
        self.confirmed + self.unconfirmed
    }

    /// Mature locked balance by moving an amount from locked to confirmed
    /// This happens when locked funds (e.g., from CoinJoin) become available
    pub fn mature(&mut self, amount: u64) -> Result<(), BalanceError> {
        if amount > self.locked {
            return Err(BalanceError::InsufficientLockedBalance {
                requested: amount,
                available: self.locked,
            });
        }

        self.locked = self.locked.checked_sub(amount).ok_or(BalanceError::Underflow)?;
        self.confirmed = self.confirmed.checked_add(amount).ok_or(BalanceError::Overflow)?;
        // Total remains the same
        Ok(())
    }

    /// Confirm unconfirmed balance by moving an amount from unconfirmed to confirmed
    /// This happens when transactions get confirmed in blocks
    pub fn confirm(&mut self, amount: u64) -> Result<(), BalanceError> {
        if amount > self.unconfirmed {
            return Err(BalanceError::InsufficientUnconfirmedBalance {
                requested: amount,
                available: self.unconfirmed,
            });
        }

        self.unconfirmed = self.unconfirmed.checked_sub(amount).ok_or(BalanceError::Underflow)?;
        self.confirmed = self.confirmed.checked_add(amount).ok_or(BalanceError::Overflow)?;
        // Total remains the same
        Ok(())
    }

    /// Lock confirmed balance by moving an amount from confirmed to locked
    /// This happens when funds are reserved for specific purposes
    pub fn lock(&mut self, amount: u64) -> Result<(), BalanceError> {
        if amount > self.confirmed {
            return Err(BalanceError::InsufficientConfirmedBalance {
                requested: amount,
                available: self.confirmed,
            });
        }

        self.confirmed = self.confirmed.checked_sub(amount).ok_or(BalanceError::Underflow)?;
        self.locked = self.locked.checked_add(amount).ok_or(BalanceError::Overflow)?;
        // Total remains the same
        Ok(())
    }

    /// Add incoming unconfirmed balance
    pub fn add_unconfirmed(&mut self, amount: u64) -> Result<(), BalanceError> {
        self.unconfirmed = self.unconfirmed.checked_add(amount).ok_or(BalanceError::Overflow)?;
        self.total = self.total.checked_add(amount).ok_or(BalanceError::Overflow)?;
        Ok(())
    }

    /// Add incoming confirmed balance
    pub fn add_confirmed(&mut self, amount: u64) -> Result<(), BalanceError> {
        self.confirmed = self.confirmed.checked_add(amount).ok_or(BalanceError::Overflow)?;
        self.total = self.total.checked_add(amount).ok_or(BalanceError::Overflow)?;
        Ok(())
    }

    /// Remove spent confirmed balance
    pub fn spend_confirmed(&mut self, amount: u64) -> Result<(), BalanceError> {
        if amount > self.confirmed {
            return Err(BalanceError::InsufficientConfirmedBalance {
                requested: amount,
                available: self.confirmed,
            });
        }

        self.confirmed = self.confirmed.checked_sub(amount).ok_or(BalanceError::Underflow)?;
        self.total = self.total.checked_sub(amount).ok_or(BalanceError::Underflow)?;
        Ok(())
    }

    /// Remove spent unconfirmed balance (e.g., double-spend or replacement)
    pub fn remove_unconfirmed(&mut self, amount: u64) -> Result<(), BalanceError> {
        if amount > self.unconfirmed {
            return Err(BalanceError::InsufficientUnconfirmedBalance {
                requested: amount,
                available: self.unconfirmed,
            });
        }

        self.unconfirmed = self.unconfirmed.checked_sub(amount).ok_or(BalanceError::Underflow)?;
        self.total = self.total.checked_sub(amount).ok_or(BalanceError::Underflow)?;
        Ok(())
    }

    /// Update all balance components at once
    pub fn update(
        &mut self,
        confirmed: u64,
        unconfirmed: u64,
        locked: u64,
    ) -> Result<(), BalanceError> {
        let total = confirmed
            .checked_add(unconfirmed)
            .and_then(|sum| sum.checked_add(locked))
            .ok_or(BalanceError::Overflow)?;

        self.confirmed = confirmed;
        self.unconfirmed = unconfirmed;
        self.locked = locked;
        self.total = total;
        Ok(())
    }

    /// Check if balance is empty
    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// Format balance as a human-readable string
    pub fn format_display(&self) -> String {
        use alloc::format;
        format!(
            "Confirmed: {}, Unconfirmed: {}, Locked: {}, Total: {}",
            self.confirmed, self.unconfirmed, self.locked, self.total
        )
    }
}

/// Balance operation errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BalanceError {
    /// Insufficient confirmed balance for operation
    InsufficientConfirmedBalance {
        requested: u64,
        available: u64,
    },
    /// Insufficient unconfirmed balance for operation
    InsufficientUnconfirmedBalance {
        requested: u64,
        available: u64,
    },
    /// Insufficient locked balance for operation
    InsufficientLockedBalance {
        requested: u64,
        available: u64,
    },
    /// Arithmetic overflow occurred
    Overflow,
    /// Arithmetic underflow occurred
    Underflow,
}

impl core::fmt::Display for BalanceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BalanceError::InsufficientConfirmedBalance {
                requested,
                available,
            } => {
                write!(
                    f,
                    "Insufficient confirmed balance: requested {} but only {} available",
                    requested, available
                )
            }
            BalanceError::InsufficientUnconfirmedBalance {
                requested,
                available,
            } => {
                write!(
                    f,
                    "Insufficient unconfirmed balance: requested {} but only {} available",
                    requested, available
                )
            }
            BalanceError::InsufficientLockedBalance {
                requested,
                available,
            } => {
                write!(
                    f,
                    "Insufficient locked balance: requested {} but only {} available",
                    requested, available
                )
            }
            BalanceError::Overflow => {
                write!(f, "Arithmetic overflow in balance calculation")
            }
            BalanceError::Underflow => {
                write!(f, "Arithmetic underflow in balance calculation")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BalanceError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_balance_creation() {
        let balance = WalletBalance::new(1000, 500, 200).unwrap();
        assert_eq!(balance.confirmed, 1000);
        assert_eq!(balance.unconfirmed, 500);
        assert_eq!(balance.locked, 200);
        assert_eq!(balance.total, 1700);
    }

    #[test]
    fn test_balance_creation_overflow() {
        let result = WalletBalance::new(u64::MAX, 1, 0);
        assert_eq!(result, Err(BalanceError::Overflow));
    }

    #[test]
    fn test_balance_mature() {
        let mut balance = WalletBalance::new(1000, 500, 200).unwrap();

        // Mature 100 from locked to confirmed
        assert!(balance.mature(100).is_ok());
        assert_eq!(balance.confirmed, 1100);
        assert_eq!(balance.locked, 100);
        assert_eq!(balance.total, 1700); // Total unchanged

        // Try to mature more than available
        assert!(balance.mature(200).is_err());
    }

    #[test]
    fn test_balance_confirm() {
        let mut balance = WalletBalance::new(1000, 500, 200).unwrap();

        // Confirm 300 from unconfirmed to confirmed
        assert!(balance.confirm(300).is_ok());
        assert_eq!(balance.confirmed, 1300);
        assert_eq!(balance.unconfirmed, 200);
        assert_eq!(balance.total, 1700); // Total unchanged

        // Try to confirm more than available
        assert!(balance.confirm(300).is_err());
    }

    #[test]
    fn test_balance_lock() {
        let mut balance = WalletBalance::new(1000, 500, 200).unwrap();

        // Lock 400 from confirmed
        assert!(balance.lock(400).is_ok());
        assert_eq!(balance.confirmed, 600);
        assert_eq!(balance.locked, 600);
        assert_eq!(balance.total, 1700); // Total unchanged

        // Try to lock more than available
        assert!(balance.lock(700).is_err());
    }

    #[test]
    fn test_balance_spend() {
        let mut balance = WalletBalance::new(1000, 500, 200).unwrap();

        // Spend 400 confirmed
        assert!(balance.spend_confirmed(400).is_ok());
        assert_eq!(balance.confirmed, 600);
        assert_eq!(balance.total, 1300); // Total reduced

        // Try to spend more than available
        assert!(balance.spend_confirmed(700).is_err());
    }

    #[test]
    fn test_balance_add_remove() {
        let mut balance = WalletBalance::new(1000, 0, 0).unwrap();

        // Add unconfirmed
        assert!(balance.add_unconfirmed(500).is_ok());
        assert_eq!(balance.unconfirmed, 500);
        assert_eq!(balance.total, 1500);

        // Add confirmed
        assert!(balance.add_confirmed(300).is_ok());
        assert_eq!(balance.confirmed, 1300);
        assert_eq!(balance.total, 1800);

        // Remove unconfirmed
        assert!(balance.remove_unconfirmed(200).is_ok());
        assert_eq!(balance.unconfirmed, 300);
        assert_eq!(balance.total, 1600);
    }

    #[test]
    fn test_balance_helpers() {
        let balance = WalletBalance::new(1000, 500, 200).unwrap();

        assert_eq!(balance.spendable(), 1000);
        assert_eq!(balance.pending(), 500);
        assert_eq!(balance.available(), 1500);
        assert!(!balance.is_empty());

        let empty = WalletBalance::zero();
        assert!(empty.is_empty());
    }

    #[test]
    fn test_balance_update() {
        let mut balance = WalletBalance::new(1000, 500, 200).unwrap();

        assert!(balance.update(2000, 1000, 500).is_ok());
        assert_eq!(balance.confirmed, 2000);
        assert_eq!(balance.unconfirmed, 1000);
        assert_eq!(balance.locked, 500);
        assert_eq!(balance.total, 3500);
    }

    #[test]
    fn test_overflow_protection() {
        let mut balance = WalletBalance::new(u64::MAX - 100, 0, 0).unwrap();

        // Test overflow in add_confirmed
        assert_eq!(balance.add_confirmed(200), Err(BalanceError::Overflow));

        // Test overflow in confirm
        balance.unconfirmed = 200;
        balance.confirmed = u64::MAX - 100;
        assert_eq!(balance.confirm(200), Err(BalanceError::Overflow));
    }

    #[test]
    fn test_balance_error_display() {
        let err = BalanceError::InsufficientConfirmedBalance {
            requested: 1000,
            available: 500,
        };
        let err_str = err.to_string();
        assert!(err_str.contains("Insufficient confirmed balance"));
        assert!(err_str.contains("1000"));
        assert!(err_str.contains("500"));
    }
}
