//! Coin selection algorithms for transaction building
//!
//! This module provides various strategies for selecting UTXOs
//! when building transactions.

use crate::wallet::managed_wallet_info::fee::FeeRate;
use crate::Utxo;
use alloc::vec::Vec;
use core::cmp::Reverse;

/// UTXO selection strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionStrategy {
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
///
/// # Strategy Selection Guide
///
/// ## For Fee Optimization:
/// - **BranchAndBound**: Best when fees are high and you want to minimize transaction cost
/// - **LargestFirst**: Simple strategy that also minimizes fees but may not find optimal solutions
///
/// ## For UTXO Management:
/// - **OptimalConsolidation**: Best for wallets with many small UTXOs that need cleaning up
/// - **SmallestFirst**: Aggressively consolidates but may create expensive transactions
/// - **SmallestFirstTill(n)**: Balanced approach - consolidates up to n small UTXOs then switches to large
///
/// ## Special Cases:
/// - **Random**: For privacy-conscious users (currently not fully implemented)
///
/// ## Recommended Defaults:
/// - Normal payments: **BranchAndBound** (minimizes fees)
/// - Wallet maintenance: **OptimalConsolidation** (during low fee periods)
/// - High-frequency receivers: **SmallestFirstTill(10)** (balanced approach)
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

    /// Select UTXOs for a target amount with default transaction size assumptions
    pub fn select_coins<'a, I>(
        &self,
        utxos: I,
        target_amount: u64,
        fee_rate: FeeRate,
        current_height: u32,
    ) -> Result<SelectionResult, SelectionError>
    where
        I: IntoIterator<Item = &'a Utxo>,
    {
        // Default base size assumes 2 outputs (target + change)
        let default_base_size = 10 + (34 * 2);
        let input_size = 148;
        self.select_coins_with_size(
            utxos,
            target_amount,
            fee_rate,
            current_height,
            default_base_size,
            input_size,
        )
    }

    /// Select UTXOs for a target amount with custom transaction size parameters
    pub fn select_coins_with_size<'a, I>(
        &self,
        utxos: I,
        target_amount: u64,
        fee_rate: FeeRate,
        current_height: u32,
        base_size: usize,
        input_size: usize,
    ) -> Result<SelectionResult, SelectionError>
    where
        I: IntoIterator<Item = &'a Utxo>,
    {
        // For strategies that need sorting, we must collect
        // For others, we can work with iterators directly
        match self.strategy {
            SelectionStrategy::SmallestFirst
            | SelectionStrategy::LargestFirst
            | SelectionStrategy::SmallestFirstTill(_)
            | SelectionStrategy::BranchAndBound
            | SelectionStrategy::OptimalConsolidation => {
                // These strategies need all UTXOs to sort/analyze
                let mut available: Vec<&'a Utxo> = utxos
                    .into_iter()
                    .filter(|u| {
                        u.is_spendable(current_height)
                            && (self.include_unconfirmed || u.is_confirmed || u.is_instantlocked)
                            && (current_height.saturating_sub(u.height) >= self.min_confirmations
                                || u.height == 0)
                    })
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

                match self.strategy {
                    SelectionStrategy::SmallestFirst => {
                        available.sort_by_key(|u| u.value());
                        self.accumulate_coins_with_size(
                            available,
                            target_amount,
                            fee_rate,
                            base_size,
                            input_size,
                        )
                    }
                    SelectionStrategy::LargestFirst => {
                        available.sort_by_key(|u| Reverse(u.value()));
                        self.accumulate_coins_with_size(
                            available,
                            target_amount,
                            fee_rate,
                            base_size,
                            input_size,
                        )
                    }
                    SelectionStrategy::SmallestFirstTill(threshold) => {
                        // Sort by value ascending (smallest first)
                        available.sort_by_key(|u| u.value());

                        // Take the first 'threshold' smallest, then sort the rest by largest
                        let threshold = threshold as usize;
                        if available.len() <= threshold {
                            // If we have fewer UTXOs than threshold, just use smallest first
                            self.accumulate_coins_with_size(
                                available,
                                target_amount,
                                fee_rate,
                                base_size,
                                input_size,
                            )
                        } else {
                            // Split at threshold
                            let (smallest, rest) = available.split_at(threshold);

                            // Sort the rest by largest first
                            let mut rest_vec = rest.to_vec();
                            rest_vec.sort_by_key(|u| Reverse(u.value()));

                            // Chain smallest first, then largest of the rest
                            let combined = smallest.iter().copied().chain(rest_vec);
                            self.accumulate_coins_with_size(
                                combined,
                                target_amount,
                                fee_rate,
                                base_size,
                                input_size,
                            )
                        }
                    }
                    SelectionStrategy::BranchAndBound => {
                        // Sort by value descending for better pruning in branch and bound
                        available.sort_by_key(|u| Reverse(u.value()));
                        self.branch_and_bound_with_size(
                            available,
                            target_amount,
                            fee_rate,
                            base_size,
                            input_size,
                        )
                    }
                    SelectionStrategy::OptimalConsolidation => self
                        .optimal_consolidation_with_size(
                            &available,
                            target_amount,
                            fee_rate,
                            base_size,
                            input_size,
                        ),
                    _ => unreachable!(),
                }
            }
            SelectionStrategy::Random => {
                // Random can work with iterators directly
                let filtered = utxos.into_iter().filter(|u| {
                    u.is_spendable(current_height)
                        && (self.include_unconfirmed || u.is_confirmed || u.is_instantlocked)
                        && (current_height.saturating_sub(u.height) >= self.min_confirmations
                            || u.height == 0)
                });

                // For Random (currently just uses accumulate as-is)
                // TODO: Implement proper random selection for privacy
                self.accumulate_coins_with_size(
                    filtered,
                    target_amount,
                    fee_rate,
                    base_size,
                    input_size,
                )
            }
        }
    }

    /// Simple accumulation strategy with custom transaction size parameters
    fn accumulate_coins_with_size<'a, I>(
        &self,
        utxos: I,
        target_amount: u64,
        fee_rate: FeeRate,
        base_size: usize,
        input_size: usize,
    ) -> Result<SelectionResult, SelectionError>
    where
        I: IntoIterator<Item = &'a Utxo>,
    {
        let mut selected = Vec::new();
        let mut total_value = 0u64;

        for utxo in utxos {
            total_value += utxo.value();
            selected.push(utxo.clone());

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
    fn branch_and_bound_with_size<'a, I>(
        &self,
        utxos: I,
        target_amount: u64,
        fee_rate: FeeRate,
        base_size: usize,
        input_size: usize,
    ) -> Result<SelectionResult, SelectionError>
    where
        I: IntoIterator<Item = &'a Utxo>,
    {
        // Collect the UTXOs - they should already be in the right order if needed
        let sorted_refs: Vec<&'a Utxo> = utxos.into_iter().collect();

        // Try to find an exact match first

        // Use a simple recursive approach with memoization
        let result = self.find_exact_match(
            &sorted_refs,
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
        // For fallback, assume change output is needed
        let base_size_with_change = base_size + 34;
        self.accumulate_coins_with_size(
            sorted_refs,
            target_amount,
            fee_rate,
            base_size_with_change,
            input_size,
        )
    }

    /// Optimal consolidation strategy with custom sizes
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
    fn optimal_consolidation_with_size<'a>(
        &self,
        utxos: &[&'a Utxo],
        target_amount: u64,
        fee_rate: FeeRate,
        base_size: usize,
        input_size: usize,
    ) -> Result<SelectionResult, SelectionError> {
        // First, try to find an exact match using smaller UTXOs
        // Sort by value ascending to prioritize using smaller UTXOs
        let mut sorted_asc: Vec<&'a Utxo> = utxos.to_vec();
        sorted_asc.sort_by_key(|u| u.value());

        // Try combinations of up to 10 UTXOs for exact match

        // Try to find exact match with smaller UTXOs first
        for max_inputs in 1..=10.min(sorted_asc.len()) {
            if let Some(combination) = self.find_exact_combination(
                &sorted_asc, // Check all UTXOs
                target_amount,
                fee_rate,
                base_size,
                input_size,
                max_inputs,
            ) {
                let estimated_size = base_size + (input_size * combination.len());
                let estimated_fee = fee_rate.calculate_fee(estimated_size);

                return Ok(SelectionResult {
                    selected: combination.clone(),
                    total_value: combination.iter().map(|u| u.value()).sum(),
                    target_amount,
                    change_amount: 0,
                    estimated_size,
                    estimated_fee,
                    exact_match: true,
                });
            }
        }

        // If no exact match, try to minimize change while consolidating small UTXOs
        // Use a combination of smallest UTXOs that slightly exceeds the target
        let base_size_with_change = base_size + 34; // Add change output to base size
        let mut best_selection: Option<Vec<Utxo>> = None;
        let mut best_change = u64::MAX;

        for i in 1..=sorted_asc.len().min(10) {
            let mut current = Vec::new();
            let mut current_total = 0u64;

            for utxo in &sorted_asc[..i] {
                current.push((*utxo).clone());
                current_total += utxo.value();
            }

            let estimated_size = base_size_with_change + (input_size * current.len());
            let estimated_fee = fee_rate.calculate_fee(estimated_size);
            let required = target_amount + estimated_fee;

            if current_total >= required {
                let change = current_total - required;
                if change < best_change && change >= self.dust_threshold {
                    best_selection = Some(current);
                    best_change = change;
                }
            }
        }

        if let Some(selected) = best_selection {
            let estimated_size = base_size_with_change + (input_size * selected.len());
            let estimated_fee = fee_rate.calculate_fee(estimated_size);
            let total_value: u64 = selected.iter().map(|u| u.value()).sum();

            return Ok(SelectionResult {
                selected,
                total_value,
                target_amount,
                change_amount: best_change,
                estimated_size,
                estimated_fee,
                exact_match: false,
            });
        }

        // Fall back to accumulate if we couldn't find a good solution
        // For fallback, assume change output is needed
        let base_size_with_change = base_size + 34;
        self.accumulate_coins_with_size(
            sorted_asc,
            target_amount,
            fee_rate,
            base_size_with_change,
            input_size,
        )
    }

    /// Find exact combination of UTXOs
    fn find_exact_combination(
        &self,
        utxos: &[&Utxo],
        target: u64,
        fee_rate: FeeRate,
        base_size: usize,
        input_size: usize,
        max_inputs: usize,
    ) -> Option<Vec<Utxo>> {
        // Simple subset sum solver for exact matches
        // This is a simplified version - could be optimized with dynamic programming

        for num_inputs in 1..=max_inputs.min(utxos.len()) {
            let estimated_size = base_size + (input_size * num_inputs);
            let estimated_fee = fee_rate.calculate_fee(estimated_size);
            let required = target + estimated_fee;

            // Try combinations of this size
            if let Some(combo) =
                Self::find_combination_recursive(utxos, required, num_inputs, 0, Vec::new(), 0)
            {
                return Some(combo);
            }
        }

        None
    }

    /// Recursive helper to find exact combination
    fn find_combination_recursive(
        utxos: &[&Utxo],
        target: u64,
        remaining_picks: usize,
        start_index: usize,
        current: Vec<Utxo>,
        current_sum: u64,
    ) -> Option<Vec<Utxo>> {
        if remaining_picks == 0 {
            return if current_sum == target {
                Some(current)
            } else {
                None
            };
        }

        if start_index >= utxos.len() || current_sum > target {
            return None;
        }

        for i in start_index..=utxos.len().saturating_sub(remaining_picks) {
            let mut new_current = current.clone();
            new_current.push(utxos[i].clone());
            let new_sum = current_sum + utxos[i].value();

            if let Some(result) = Self::find_combination_recursive(
                utxos,
                target,
                remaining_picks - 1,
                i + 1,
                new_current,
                new_sum,
            ) {
                return Some(result);
            }
        }

        None
    }

    /// Recursive helper for finding exact match
    #[allow(clippy::too_many_arguments)]
    fn find_exact_match(
        &self,
        utxos: &[&Utxo],
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
            Self::SelectionFailed(msg) => write!(f, "Selection failed: {}", msg),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SelectionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smallest_first_selection() {
        let utxos = vec![
            Utxo::new_test(0, 10000, 100, false, true),
            Utxo::new_test(0, 20000, 100, false, true),
            Utxo::new_test(0, 30000, 100, false, true),
            Utxo::new_test(0, 40000, 100, false, true),
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
            Utxo::new_test(0, 10000, 100, false, true),
            Utxo::new_test(0, 20000, 100, false, true),
            Utxo::new_test(0, 30000, 100, false, true),
            Utxo::new_test(0, 40000, 100, false, true),
        ];

        let selector = CoinSelector::new(SelectionStrategy::LargestFirst);
        let result = selector.select_coins(&utxos, 25000, FeeRate::new(1000), 200).unwrap();

        assert_eq!(result.selected.len(), 1); // Should select just 40k
        assert_eq!(result.total_value, 40000);
        assert!(result.change_amount > 0);
    }

    #[test]
    fn test_insufficient_funds() {
        let utxos = vec![
            Utxo::new_test(0, 10000, 100, false, true),
            Utxo::new_test(0, 20000, 100, false, true),
        ];

        let selector = CoinSelector::new(SelectionStrategy::LargestFirst);
        let result = selector.select_coins(&utxos, 50000, FeeRate::new(1000), 200);

        assert!(matches!(result, Err(SelectionError::InsufficientFunds { .. })));
    }

    #[test]
    fn test_optimal_consolidation_strategy() {
        // Test that OptimalConsolidation strategy works correctly
        let utxos = vec![
            Utxo::new_test(0, 100, 100, false, true),
            Utxo::new_test(0, 200, 100, false, true),
            Utxo::new_test(0, 300, 100, false, true),
            Utxo::new_test(0, 500, 100, false, true),
            Utxo::new_test(0, 1000, 100, false, true),
            Utxo::new_test(0, 2000, 100, false, true),
        ];

        let selector = CoinSelector::new(SelectionStrategy::OptimalConsolidation);
        let fee_rate = FeeRate::new(100); // Simpler fee rate
        let result = selector.select_coins(&utxos, 1500, fee_rate, 200).unwrap();

        // OptimalConsolidation should work and produce a valid selection
        assert!(!result.selected.is_empty());
        assert!(result.total_value >= 1500 + result.estimated_fee);
        assert_eq!(result.target_amount, 1500);

        // The strategy should prefer smaller UTXOs, so it should include
        // some of the smaller values
        let selected_values: Vec<u64> = result.selected.iter().map(|u| u.value()).collect();
        let has_small_utxos = selected_values.iter().any(|&v| v <= 500);
        assert!(has_small_utxos, "Should include at least one small UTXO for consolidation");
    }
}
