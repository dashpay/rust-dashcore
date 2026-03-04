//! Coin selection algorithms for transaction building
//!
//! This module provides various strategies for selecting UTXOs
//! when building transactions.

use crate::Utxo;
use alloc::vec::Vec;
use core::cmp::Reverse;
use rand::seq::SliceRandom;
use rand::thread_rng;

/// Errors that can occur during coin selection
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectionError {
    /// Insufficient funds
    InsufficientFunds {
        available: u64,
        required: u64,
    },
}

impl core::fmt::Display for SelectionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InsufficientFunds {
                available,
                required,
            } => {
                write!(f, "Insufficient funds: available {}, required {}", available, required)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SelectionError {}

#[derive(Clone, Copy)]
pub enum UtxoSelectorStrategy {
    /// Select smallest UTXOs first (minimize UTXO set)
    SmallestFirst,
    /// Select largest UTXOs first (minimize fees)
    LargestFirst,
    /// Select smallest UTXOs first until count, then largest (This minimizes UTXO set without
    /// creating massive transactions)
    SmallestFirstTill(u16),
    /// Branch and bound optimization - exhaustively searches for the optimal combination of UTXOs
    /// that minimizes waste (excess value that would go to fees or change). Uses a depth-first
    /// search with pruning to find exact matches or near-exact matches efficiently.
    ///
    /// Best for: Regular transactions where minimizing fees is the priority. This strategy
    /// works well when you have many UTXOs of varying sizes and want to find the most
    /// efficient combination. It prioritizes larger UTXOs first to minimize the number
    /// of inputs needed.
    BranchAndBound,
    /// Optimal consolidation - tries to find exact match or minimal change while consolidating UTXOs
    ///
    /// Best for: Wallets with many small UTXOs that need consolidation. This strategy
    /// prioritizes using smaller UTXOs first to reduce wallet fragmentation over time.
    /// It searches for exact matches (no change output needed) using smaller denominations,
    /// which helps clean up dust and small UTXOs while making payments. If no exact match
    /// exists, it tries to minimize change while still preferring smaller inputs.
    OptimalConsolidation,
    /// Random selection for privacy
    Random,
}

impl UtxoSelectorStrategy {
    fn apply<'a>(
        &self,
        target: u64,
        mut utxos: Vec<&'a Utxo>,
    ) -> Result<Vec<&'a Utxo>, SelectionError> {
        match self {
            UtxoSelectorStrategy::SmallestFirst => {
                utxos.sort_by_key(|&u| u.value());
                let iter = utxos.into_iter();

                select_utxo_from_iterator(iter, target)
            }
            UtxoSelectorStrategy::LargestFirst => {
                utxos.sort_by_key(|&u| Reverse(u.value()));
                let iter = utxos.into_iter();

                select_utxo_from_iterator(iter, target)
            }
            UtxoSelectorStrategy::SmallestFirstTill(v) => {
                utxos.sort_by_key(|&u| u.value());
                let (utxos, _) = utxos.split_at(*v as usize);
                let iter = utxos.to_vec().into_iter();

                select_utxo_from_iterator(iter, target)
            }
            UtxoSelectorStrategy::BranchAndBound => branch_and_bound_impl(utxos, target),
            UtxoSelectorStrategy::OptimalConsolidation => optimal_consolidation_impl(utxos, target),
            UtxoSelectorStrategy::Random => {
                utxos.shuffle(&mut thread_rng());
                let iter = utxos.into_iter();

                select_utxo_from_iterator(iter, target)
            }
        }
    }
}

pub struct UtxoSelector {
    strategy: UtxoSelectorStrategy,
}

impl UtxoSelector {
    pub fn new(strategy: UtxoSelectorStrategy) -> Self {
        Self {
            strategy,
        }
    }

    pub fn select<'a, I>(
        &self,
        target: u64,
        utxos: I,
        current_height: u32,
    ) -> Result<Vec<&'a Utxo>, SelectionError>
    where
        I: IntoIterator<Item = &'a Utxo>,
    {
        let utxos: Vec<&Utxo> =
            utxos.into_iter().filter(|&u| u.is_spendable(current_height)).collect();

        self.strategy.apply(target, utxos)
    }
}

fn select_utxo_from_iterator<'a>(
    iter: impl Iterator<Item = &'a Utxo>,
    target: u64,
) -> Result<Vec<&'a Utxo>, SelectionError> {
    let mut current_value = 0;
    let mut utxos = vec![];

    for utxo in iter {
        if current_value >= target {
            break;
        }

        current_value += utxo.value();
        utxos.push(utxo);
    }

    if current_value < target {
        return Err(SelectionError::InsufficientFunds {
            available: current_value,
            required: target,
        });
    }

    Ok(utxos)
}

/// Optimal consolidation strategy implementation
/// Tries to find combinations that either:
/// 1. Match exactly (no change needed)
/// 2. Create minimal change while using smaller UTXOs
///
/// This algorithm:
/// - Sorts UTXOs by value ascending (smallest first)
/// - Prioritizes exact matches using smaller denominations
/// - Falls back to minimal change if no exact match exists
/// - Helps reduce UTXO set size over time
///
/// Trade-offs vs BranchAndBound:
/// - Pros: Reduces wallet fragmentation by consuming small UTXOs
/// - Pros: More likely to find exact matches with smaller denominations
/// - Pros: Better for long-term wallet health and UTXO management
/// - Cons: May result in higher fees due to more inputs
/// - Cons: Transactions may be larger due to using more UTXOs
///
/// When to use this over BranchAndBound:
/// - When wallet has accumulated many small UTXOs (dust)
/// - During low-fee periods when consolidation is cheaper
/// - For wallets that receive many small payments
/// - When exact change is preferred to minimize privacy leaks
fn optimal_consolidation_impl<'a>(
    mut utxos: Vec<&'a Utxo>,
    target: u64,
) -> Result<Vec<&'a Utxo>, SelectionError> {
    // First, try to find an exact match using smaller UTXOs
    // Sort by value ascending to prioritize using smaller UTXOs
    utxos.sort_by_key(|&u| u.value());

    // Try combinations of up to 10 UTXOs for exact match

    // Try to find exact match with smaller UTXOs first
    for max_inputs in 1..=10.min(utxos.len()) {
        for num_inputs in 1..=max_inputs.min(utxos.len()) {
            // Try combinations of this size
            if let Some(combo) =
                find_combination_recursive(&utxos, target, num_inputs, 0, Vec::new(), 0)
            {
                return Ok(combo);
            }
        }
    }

    // If no exact match, try to minimize change while consolidating small UTXOs
    // Use a combination of smallest UTXOs that slightly exceeds the target
    let mut best_selection: Option<Vec<&Utxo>> = None;
    let mut best_change = u64::MAX;

    for i in 1..=utxos.len().min(10) {
        let mut current = Vec::new();
        let mut current_total = 0u64;

        for &utxo in &utxos[..i] {
            current.push(utxo);
            current_total += utxo.value();
        }

        if current_total >= target {
            let change = current_total - target;
            if change < best_change {
                best_selection = Some(current);
                best_change = change;
            }
        }
    }

    return if let Some(selected) = best_selection {
        Ok(selected)
    } else {
        select_utxo_from_iterator(utxos.into_iter(), target)
    };

    /// Recursive helper to find exact combination
    fn find_combination_recursive<'a>(
        utxos: &[&'a Utxo],
        target: u64,
        remaining_picks: usize,
        index: usize,
        current: Vec<&'a Utxo>,
        current_total: u64,
    ) -> Option<Vec<&'a Utxo>> {
        if remaining_picks == 0 {
            return None;
        }

        // Check if we've found an exact match
        if current_total == target {
            return Some(current);
        }

        // Prune if we've exceeded the target
        if current_total > target {
            return None;
        }

        for i in index..=utxos.len().saturating_sub(remaining_picks) {
            let mut new_current = current.clone();
            new_current.push(utxos[i]);
            let new_total = current_total + utxos[i].value();

            if let Some(result) = find_combination_recursive(
                utxos,
                target,
                remaining_picks - 1,
                i + 1,
                new_current,
                new_total,
            ) {
                return Some(result);
            }
        }

        None
    }
}

/// Branch and bound coin selection with custom sizes (finds exact match if possible)
///
/// This algorithm:
/// - Sorts UTXOs by value descending (largest first)
/// - Recursively explores combinations looking for exact matches
/// - Prunes branches that exceed the target by too much
/// - Falls back to simple accumulation if no exact match found
///
/// Trade-offs vs OptimalConsolidation:
/// - Pros: Minimizes transaction fees by using fewer, larger UTXOs
/// - Pros: Faster to find solutions due to aggressive pruning
/// - Cons: May leave small UTXOs unconsolidated, leading to wallet fragmentation
/// - Cons: Less likely to find exact matches with larger denominations
fn branch_and_bound_impl<'a>(
    mut utxos: Vec<&'a Utxo>,
    target: u64,
) -> Result<Vec<&'a Utxo>, SelectionError> {
    utxos.sort_by_key(|&u| Reverse(u.value()));

    // Try to find an exact match first

    // Use a simple recursive approach with memoization
    let result = find_exact_match(&utxos, target, 0, Vec::new(), 0);

    if let Some(selected) = result {
        return Ok(selected);
    }

    // Fall back to accumulation if no exact match found
    // For fallback, assume change output is needed
    return select_utxo_from_iterator(utxos.into_iter(), target);

    fn find_exact_match<'a>(
        utxos: &[&'a Utxo],
        target: u64,
        index: usize,
        mut current: Vec<&'a Utxo>,
        current_total: u64,
    ) -> Option<Vec<&'a Utxo>> {
        // Check if we've found an exact match
        if current_total == target {
            return Some(current);
        }

        // Prune if we've exceeded the target
        if current_total > target {
            return None;
        }

        // Try remaining UTXOs
        for i in index..utxos.len() {
            let new_total = current_total + utxos[i].value();

            // Skip if this would exceed our target by too much
            if new_total > target {
                continue;
            }

            current.push(utxos[i]);

            if let Some(result) = find_exact_match(utxos, target, i + 1, current.clone(), new_total)
            {
                return Some(result);
            }

            current.pop();
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smallest_first_selection() {
        let utxos = vec![
            Utxo::dummy(0, 10000, 100, false, true),
            Utxo::dummy(0, 20000, 100, false, true),
            Utxo::dummy(0, 30000, 100, false, true),
            Utxo::dummy(0, 40000, 100, false, true),
        ];

        let selector = UtxoSelector::new(UtxoSelectorStrategy::SmallestFirst);
        let selected = selector.select(25000, &utxos, 200).unwrap();

        // The algorithm should select the smallest UTXOs first: 10k + 20k = 30k which covers 25k target
        assert_eq!(selected.len(), 2); // Should select 10k + 20k
    }

    #[test]
    fn test_largest_first_selection() {
        let utxos = vec![
            Utxo::dummy(0, 10000, 100, false, true),
            Utxo::dummy(0, 20000, 100, false, true),
            Utxo::dummy(0, 30000, 100, false, true),
            Utxo::dummy(0, 40000, 100, false, true),
        ];

        let selector = UtxoSelector::new(UtxoSelectorStrategy::LargestFirst);
        let selected = selector.select(25000, &utxos, 200).unwrap();

        assert_eq!(selected.len(), 1); // Should select just 40k
    }

    #[test]
    fn test_insufficient_funds() {
        let utxos =
            vec![Utxo::dummy(0, 10000, 100, false, true), Utxo::dummy(0, 20000, 100, false, true)];

        let selector = UtxoSelector::new(UtxoSelectorStrategy::LargestFirst);
        let result = selector.select(50000, &utxos, 200);

        assert!(matches!(result, Err(SelectionError::InsufficientFunds { .. })));
    }

    #[test]
    fn test_optimal_consolidation_strategy() {
        // Test that OptimalConsolidation strategy works correctly
        let utxos = vec![
            Utxo::dummy(0, 100, 100, false, true),
            Utxo::dummy(0, 200, 100, false, true),
            Utxo::dummy(0, 300, 100, false, true),
            Utxo::dummy(0, 500, 100, false, true),
            Utxo::dummy(0, 1000, 100, false, true),
            Utxo::dummy(0, 2000, 100, false, true),
        ];

        let selector = UtxoSelector::new(UtxoSelectorStrategy::OptimalConsolidation);
        let selected = selector.select(1500, &utxos, 200).unwrap();

        // OptimalConsolidation should work and produce a valid selection
        assert!(!selected.is_empty());

        // The strategy should prefer smaller UTXOs, so it should include
        // some of the smaller values
        let selected_values: Vec<u64> = selected.iter().map(|&u| u.value()).collect();
        let has_small_utxos = selected_values.iter().any(|&v| v <= 500);
        assert!(has_small_utxos, "Should include at least one small UTXO for consolidation");
    }
}
