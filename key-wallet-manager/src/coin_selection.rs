//! Coin selection algorithms for transaction building
//!
//! This module provides various strategies for selecting UTXOs
//! when building transactions.

use alloc::vec::Vec;
use core::cmp::Reverse;

use crate::fee::FeeRate;
use key_wallet::Utxo;

/// UTXO selection strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionStrategy {
    /// Select smallest UTXOs first (minimize UTXO set)
    SmallestFirst,
    /// Select largest UTXOs first (minimize fees)
    LargestFirst,
    /// Branch and bound optimization (find exact match if possible)
    BranchAndBound,
    /// Random selection for privacy
    Random,
    /// Manual selection (user specifies exact UTXOs)
    Manual,
}

/// Result of UTXO selection
#[derive(Debug, Clone)]
pub struct SelectionResult {
    /// Selected UTXOs
    pub selected: Vec<Utxo>,
    /// Total value of selected UTXOs
    pub total_value: u64,
    /// Target amount (excluding fees)
    pub target_amount: u64,
    /// Change amount (if any)
    pub change_amount: u64,
    /// Estimated transaction size in bytes
    pub estimated_size: usize,
    /// Estimated fee
    pub estimated_fee: u64,
    /// Whether an exact match was found (no change needed)
    pub exact_match: bool,
}

/// Coin selector for choosing UTXOs
pub struct CoinSelector {
    strategy: SelectionStrategy,
    min_confirmations: u32,
    include_unconfirmed: bool,
    dust_threshold: u64,
}

impl CoinSelector {
    /// Create a new coin selector
    pub fn new(strategy: SelectionStrategy) -> Self {
        Self {
            strategy,
            min_confirmations: 1,
            include_unconfirmed: false,
            dust_threshold: 546, // Standard dust threshold
        }
    }

    /// Set minimum confirmations required
    pub fn with_min_confirmations(mut self, confirmations: u32) -> Self {
        self.min_confirmations = confirmations;
        self
    }

    /// Include unconfirmed UTXOs
    pub fn include_unconfirmed(mut self) -> Self {
        self.include_unconfirmed = true;
        self
    }

    /// Set dust threshold
    pub fn with_dust_threshold(mut self, threshold: u64) -> Self {
        self.dust_threshold = threshold;
        self
    }

    /// Select UTXOs for a target amount
    pub fn select_coins(
        &self,
        utxos: &[Utxo],
        target_amount: u64,
        fee_rate: FeeRate,
        current_height: u32,
    ) -> Result<SelectionResult, SelectionError> {
        // Filter spendable UTXOs
        let mut available: Vec<Utxo> = utxos
            .iter()
            .filter(|u| {
                u.is_spendable(current_height)
                    && (self.include_unconfirmed || u.is_confirmed || u.is_instantlocked)
                    && (current_height.saturating_sub(u.height) >= self.min_confirmations
                        || u.height == 0)
            })
            .cloned()
            .collect();

        if available.is_empty() {
            return Err(SelectionError::NoUtxosAvailable);
        }

        // Check if we have enough funds
        let total_available: u64 = available.iter().map(|u| u.value()).sum();
        if total_available < target_amount {
            return Err(SelectionError::InsufficientFunds {
                available: total_available,
                required: target_amount,
            });
        }

        // Apply selection strategy
        match self.strategy {
            SelectionStrategy::SmallestFirst => {
                available.sort_by_key(|u| u.value());
                self.accumulate_coins(&available, target_amount, fee_rate)
            }
            SelectionStrategy::LargestFirst => {
                available.sort_by_key(|u| Reverse(u.value()));
                self.accumulate_coins(&available, target_amount, fee_rate)
            }
            SelectionStrategy::BranchAndBound => {
                self.branch_and_bound(&available, target_amount, fee_rate)
            }
            SelectionStrategy::Random => {
                // TODO: Implement random shuffling
                // For now, just use as-is
                self.accumulate_coins(&available, target_amount, fee_rate)
            }
            SelectionStrategy::Manual => Err(SelectionError::ManualSelectionRequired),
        }
    }

    /// Simple accumulation strategy
    fn accumulate_coins(
        &self,
        utxos: &[Utxo],
        target_amount: u64,
        fee_rate: FeeRate,
    ) -> Result<SelectionResult, SelectionError> {
        let mut selected = Vec::new();
        let mut total_value = 0u64;

        // Estimate initial size (rough approximation)
        // 10 bytes for version, locktime, counts
        // 34 bytes per P2PKH output (assume 2: target + change)
        let base_size = 10 + (34 * 2);
        let input_size = 148; // Approximate size per P2PKH input

        for utxo in utxos {
            selected.push(utxo.clone());
            total_value += utxo.value();

            // Calculate size with current inputs
            let estimated_size = base_size + (input_size * selected.len());
            let estimated_fee = fee_rate.calculate_fee(estimated_size);
            let required_amount = target_amount + estimated_fee;

            if total_value >= required_amount {
                let change_amount = total_value - required_amount;

                // Check if change is dust
                let (final_change, exact_match) = if change_amount < self.dust_threshold {
                    // Add dust to fee
                    (0, change_amount == 0)
                } else {
                    (change_amount, false)
                };

                return Ok(SelectionResult {
                    selected,
                    total_value,
                    target_amount,
                    change_amount: final_change,
                    estimated_size,
                    estimated_fee: if final_change == 0 {
                        total_value - target_amount
                    } else {
                        estimated_fee
                    },
                    exact_match,
                });
            }
        }

        Err(SelectionError::InsufficientFunds {
            available: total_value,
            required: target_amount,
        })
    }

    /// Branch and bound coin selection (finds exact match if possible)
    fn branch_and_bound(
        &self,
        utxos: &[Utxo],
        target_amount: u64,
        fee_rate: FeeRate,
    ) -> Result<SelectionResult, SelectionError> {
        // Sort UTXOs by value (descending) for better pruning
        let mut sorted: Vec<Utxo> = utxos.to_vec();
        sorted.sort_by_key(|u| Reverse(u.value()));

        // Try to find an exact match first
        let base_size = 10 + (34 * 1); // No change output needed for exact match
        let input_size = 148;

        // Use a simple recursive approach with memoization
        let result = self.find_exact_match(
            &sorted,
            target_amount,
            fee_rate,
            base_size,
            input_size,
            0,
            Vec::new(),
            0,
        );

        if let Some((selected, total)) = result {
            let estimated_size = base_size + (input_size * selected.len());
            let estimated_fee = fee_rate.calculate_fee(estimated_size);

            return Ok(SelectionResult {
                selected,
                total_value: total,
                target_amount,
                change_amount: 0,
                estimated_size,
                estimated_fee,
                exact_match: true,
            });
        }

        // Fall back to accumulation if no exact match found
        self.accumulate_coins(&sorted, target_amount, fee_rate)
    }

    /// Recursive helper for finding exact match
    fn find_exact_match(
        &self,
        utxos: &[Utxo],
        target: u64,
        fee_rate: FeeRate,
        base_size: usize,
        input_size: usize,
        index: usize,
        mut current: Vec<Utxo>,
        current_total: u64,
    ) -> Option<(Vec<Utxo>, u64)> {
        // Calculate required amount including fee
        let estimated_size = base_size + (input_size * (current.len() + 1));
        let estimated_fee = fee_rate.calculate_fee(estimated_size);
        let required = target + estimated_fee;

        // Check if we've found an exact match
        if current_total == required {
            return Some((current, current_total));
        }

        // Prune if we've exceeded the target
        if current_total > required + self.dust_threshold {
            return None;
        }

        // Try remaining UTXOs
        for i in index..utxos.len() {
            let new_total = current_total + utxos[i].value();

            // Skip if this would exceed our target by too much
            if new_total > required + self.dust_threshold * 10 {
                continue;
            }

            current.push(utxos[i].clone());

            if let Some(result) = self.find_exact_match(
                utxos,
                target,
                fee_rate,
                base_size,
                input_size,
                i + 1,
                current.clone(),
                new_total,
            ) {
                return Some(result);
            }

            current.pop();
        }

        None
    }
}

/// Errors that can occur during coin selection
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectionError {
    /// No UTXOs available for selection
    NoUtxosAvailable,
    /// Insufficient funds
    InsufficientFunds {
        available: u64,
        required: u64,
    },
    /// Manual selection required
    ManualSelectionRequired,
    /// Selection failed
    SelectionFailed(String),
}

impl core::fmt::Display for SelectionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoUtxosAvailable => write!(f, "No UTXOs available for selection"),
            Self::InsufficientFunds {
                available,
                required,
            } => {
                write!(f, "Insufficient funds: available {}, required {}", available, required)
            }
            Self::ManualSelectionRequired => write!(f, "Manual UTXO selection required"),
            Self::SelectionFailed(msg) => write!(f, "Selection failed: {}", msg),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SelectionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::blockdata::script::ScriptBuf;
    use dashcore::{OutPoint, TxOut, Txid};
    use dashcore_hashes::{sha256d, Hash};
    use key_wallet::Utxo;
    use key_wallet::{Address, Network};

    fn test_utxo(value: u64, confirmed: bool) -> Utxo {
        let outpoint = OutPoint {
            txid: Txid::from_raw_hash(sha256d::Hash::from_slice(&[1u8; 32]).unwrap()),
            vout: 0,
        };

        let txout = TxOut {
            value,
            script_pubkey: ScriptBuf::new(),
        };

        let address = Address::p2pkh(
            &dashcore::PublicKey::from_slice(&[
                0x02, 0x50, 0x86, 0x3a, 0xd6, 0x4a, 0x87, 0xae, 0x8a, 0x2f, 0xe8, 0x3c, 0x1a, 0xf1,
                0xa8, 0x40, 0x3c, 0xb5, 0x3f, 0x53, 0xe4, 0x86, 0xd8, 0x51, 0x1d, 0xad, 0x8a, 0x04,
                0x88, 0x7e, 0x5b, 0x23, 0x52,
            ])
            .unwrap(),
            Network::Testnet,
        );

        let mut utxo = Utxo::new(outpoint, txout, address, 100, false);
        utxo.is_confirmed = confirmed;
        utxo
    }

    #[test]
    fn test_smallest_first_selection() {
        let utxos = vec![
            test_utxo(10000, true),
            test_utxo(20000, true),
            test_utxo(30000, true),
            test_utxo(40000, true),
        ];

        let selector = CoinSelector::new(SelectionStrategy::SmallestFirst);
        let result = selector.select_coins(&utxos, 25000, FeeRate::new(1000), 200).unwrap();

        // The algorithm should select the smallest UTXOs first: 10k + 20k = 30k which covers 25k target
        assert_eq!(result.selected.len(), 2); // Should select 10k + 20k
        assert_eq!(result.total_value, 30000);
        assert!(result.change_amount > 0);
    }

    #[test]
    fn test_largest_first_selection() {
        let utxos = vec![
            test_utxo(10000, true),
            test_utxo(20000, true),
            test_utxo(30000, true),
            test_utxo(40000, true),
        ];

        let selector = CoinSelector::new(SelectionStrategy::LargestFirst);
        let result = selector.select_coins(&utxos, 25000, FeeRate::new(1000), 200).unwrap();

        assert_eq!(result.selected.len(), 1); // Should select just 40k
        assert_eq!(result.total_value, 40000);
        assert!(result.change_amount > 0);
    }

    #[test]
    fn test_insufficient_funds() {
        let utxos = vec![test_utxo(10000, true), test_utxo(20000, true)];

        let selector = CoinSelector::new(SelectionStrategy::LargestFirst);
        let result = selector.select_coins(&utxos, 50000, FeeRate::new(1000), 200);

        assert!(matches!(result, Err(SelectionError::InsufficientFunds { .. })));
    }
}
