//! Coin selection algorithms for transaction building
//!
//! This module provides various strategies for selecting UTXOs
//! when building transactions.

use crate::wallet::managed_wallet_info::fee::FeeRate;
use crate::Utxo;
use core::cmp::Reverse;

pub(crate) const TX_OUTPUT_SIZE: usize = 34;
pub(crate) const TX_INPUT_SIZE: usize = 148;
pub(crate) const CHANGE_OUTPUT_SIZE: usize = TX_OUTPUT_SIZE;

/// Nodes the search may visit before giving up and falling back to accumulation.
/// Caps the worst case so no input set can stall a build. Same figure as Bitcoin Core.
const BNB_NODE_BUDGET: u32 = 100_000;

#[derive(Clone, Copy)]
struct BnbCandidate {
    /// Position in the caller's slice, so the winner can be mapped back.
    index: usize,
    /// Value net of the fee to spend it.
    effective_value: u64,
}

/// Depth-first search over subsets for one that funds the target with no change
/// output, burning as little surplus as possible.
///
/// Two bounds, because one alone is not enough: abandon a branch that has overshot,
/// *and* one that cannot reach the target even taking every UTXO left (#918).
struct BnbSearch<'a> {
    /// Descending effective value, so the bounds bite early.
    candidates: &'a [BnbCandidate],
    /// `suffix[i]`: effective value still available from `i` onwards.
    suffix: &'a [u64],
    target: u64,
    /// How far above `target` is still acceptable.
    window: u64,
    budget: u32,
    /// Lowest-surplus selection so far, as candidate indices.
    best: Option<(Vec<usize>, u64)>,
}

impl BnbSearch<'_> {
    fn run(&mut self, index: usize, chosen: &mut Vec<usize>, sum: u64) {
        if self.budget == 0 {
            return;
        }
        self.budget -= 1;

        if sum >= self.target {
            // Adding more to a funded selection only burns more; this branch ends here.
            let surplus = sum - self.target;
            if surplus <= self.window && self.best.as_ref().is_none_or(|(_, b)| surplus < *b) {
                self.best = Some((chosen.clone(), surplus));
            }
            return;
        }

        // Even taking everything left falls short.
        if sum.saturating_add(self.suffix[index]) < self.target {
            return;
        }

        for i in index..self.candidates.len() {
            let next = sum.saturating_add(self.candidates[i].effective_value);
            // Overshoots on its own; later candidates are smaller, so skip, don't break.
            if next > self.target.saturating_add(self.window) {
                continue;
            }

            chosen.push(i);
            self.run(i + 1, chosen, next);
            chosen.pop();

            // Nothing wasted cannot be improved on.
            if self.best.as_ref().is_some_and(|(_, surplus)| *surplus == 0) {
                return;
            }
        }
    }
}

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
    /// Select EVERY spendable UTXO (drain / sweep an account empty). There is no change: the
    /// single deliverable output is worth the total minus the fee to spend them all
    All,
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
    dust_threshold: u64,
}

impl CoinSelector {
    pub fn new(strategy: SelectionStrategy) -> Self {
        Self {
            strategy,
            dust_threshold: 546, // Standard dust threshold
        }
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
        // Default base size assumes 2 outputs: the target output and one change output.
        let default_base_size = 10 + TX_OUTPUT_SIZE + CHANGE_OUTPUT_SIZE;
        self.select_coins_with_size(
            utxos,
            target_amount,
            fee_rate,
            current_height,
            default_base_size,
            CHANGE_OUTPUT_SIZE,
        )
    }

    /// Select UTXOs for a target amount with custom transaction size parameters.
    ///
    /// `base_size` includes the change output; `change_output_size` is its byte count (`0` when
    /// there is no change address), letting the accumulator drop it to size a no-change fee.
    /// Input size is always `TX_INPUT_SIZE`.
    pub fn select_coins_with_size<'a, I>(
        &self,
        utxos: I,
        target_amount: u64,
        fee_rate: FeeRate,
        current_height: u32,
        base_size: usize,
        change_output_size: usize,
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
                let mut available: Vec<&'a Utxo> =
                    utxos.into_iter().filter(|u| u.is_spendable(current_height)).collect();

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
                            change_output_size,
                        )
                    }
                    SelectionStrategy::LargestFirst => {
                        available.sort_by_key(|u| Reverse(u.value()));
                        self.accumulate_coins_with_size(
                            available,
                            target_amount,
                            fee_rate,
                            base_size,
                            change_output_size,
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
                                change_output_size,
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
                                change_output_size,
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
                            change_output_size,
                        )
                    }
                    SelectionStrategy::OptimalConsolidation => self
                        .optimal_consolidation_with_size(
                            &available,
                            target_amount,
                            fee_rate,
                            base_size,
                            change_output_size,
                        ),
                    _ => unreachable!(),
                }
            }
            SelectionStrategy::Random => {
                // Random can work with iterators directly
                let filtered = utxos.into_iter().filter(|u| u.is_spendable(current_height));

                // For Random (currently just uses accumulate as-is)
                // TODO: Implement proper random selection for privacy
                self.accumulate_coins_with_size(
                    filtered,
                    target_amount,
                    fee_rate,
                    base_size,
                    change_output_size,
                )
            }
            SelectionStrategy::All => {
                let selected: Vec<Utxo> =
                    utxos.into_iter().filter(|u| u.is_spendable(current_height)).cloned().collect();

                if selected.is_empty() {
                    return Err(SelectionError::NoUtxosAvailable);
                }

                let total_value: u64 = selected.iter().map(|u| u.value()).sum();
                let estimated_size = base_size + selected.len() * TX_INPUT_SIZE;
                let estimated_fee = fee_rate.calculate_fee(estimated_size);

                // The caller's `target_amount` is ignored: a drain spends everything, there is no
                // target to satisfy
                let deliverable = total_value
                    .checked_sub(estimated_fee)
                    .filter(|d| *d > self.dust_threshold)
                    .ok_or(SelectionError::InsufficientFunds {
                        available: total_value,
                        required: estimated_fee + self.dust_threshold + 1,
                    })?;

                Ok(SelectionResult {
                    selected,
                    total_value,
                    target_amount: deliverable,
                    change_amount: 0,
                    estimated_size,
                    estimated_fee,
                    exact_match: true,
                })
            }
        }
    }

    /// Accumulate UTXOs. `change_output_size` = the change output's bytes within `base_size`
    /// (`0` if none is budgeted), shaved off to size the no-change fee.
    fn accumulate_coins_with_size<'a, I>(
        &self,
        utxos: I,
        target_amount: u64,
        fee_rate: FeeRate,
        base_size: usize,
        change_output_size: usize,
    ) -> Result<SelectionResult, SelectionError>
    where
        I: IntoIterator<Item = &'a Utxo>,
    {
        let mut selected = Vec::new();
        let mut total_value = 0u64;
        // Reported on shortfall so `available < required`, not the fee-excluded `target_amount`
        // that looked like `available > required` (#911).
        let mut required_no_change = target_amount;

        for utxo in utxos {
            total_value += utxo.value();
            selected.push(utxo.clone());

            // `base_size` budgets a change output; a no-change send omits it and pays less.
            let estimated_size = base_size + (TX_INPUT_SIZE * selected.len());
            let estimated_fee = fee_rate.calculate_fee(estimated_size);
            let size_no_change = estimated_size.saturating_sub(change_output_size);
            let fee_no_change = fee_rate.calculate_fee(size_no_change);
            required_no_change = target_amount + fee_no_change;

            if total_value < required_no_change {
                continue;
            }

            // Keep change only if one is budgeted and it clears dust (`>`, like the builder).
            let required_with_change = target_amount + estimated_fee;
            if change_output_size > 0
                && total_value >= required_with_change
                && total_value - required_with_change > self.dust_threshold
            {
                return Ok(SelectionResult {
                    selected,
                    total_value,
                    target_amount,
                    change_amount: total_value - required_with_change,
                    estimated_size,
                    estimated_fee,
                    exact_match: false,
                });
            }

            // No change output budgeted but a real remainder: surface it as change so the builder
            // adds one or errors, instead of burning a large surplus into the fee.
            let remainder = total_value - required_no_change;
            if change_output_size == 0 && remainder > self.dust_threshold {
                return Ok(SelectionResult {
                    selected,
                    total_value,
                    target_amount,
                    change_amount: remainder,
                    estimated_size: size_no_change,
                    estimated_fee: fee_no_change,
                    exact_match: false,
                });
            }

            // Otherwise the remainder is dust: drop the change output, fold it into the fee (#911).
            return Ok(SelectionResult {
                selected,
                total_value,
                target_amount,
                change_amount: 0,
                estimated_size: size_no_change,
                estimated_fee: total_value - target_amount,
                exact_match: total_value == required_no_change,
            });
        }

        Err(SelectionError::InsufficientFunds {
            available: total_value,
            required: required_no_change,
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
        change_output_size: usize,
    ) -> Result<SelectionResult, SelectionError>
    where
        I: IntoIterator<Item = &'a Utxo>,
    {
        let sorted_refs: Vec<&'a Utxo> = utxos.into_iter().collect();

        // `base_size` budgets a change output, which a change-free send does not pay for.
        let base_size_no_change = base_size.saturating_sub(change_output_size);

        if let Some(selected) =
            self.branch_and_bound(&sorted_refs, target_amount, fee_rate, base_size_no_change)
        {
            let total_value: u64 = selected.iter().map(|u| u.value()).sum();
            let estimated_size = base_size_no_change + TX_INPUT_SIZE * selected.len();

            return Ok(SelectionResult {
                selected,
                total_value,
                target_amount,
                // The surplus is smaller than a change output would cost (#911).
                change_amount: 0,
                estimated_size,
                estimated_fee: total_value - target_amount,
                exact_match: true,
            });
        }

        // Nothing change-free found: accumulate.
        self.accumulate_coins_with_size(
            sorted_refs,
            target_amount,
            fee_rate,
            base_size,
            change_output_size,
        )
    }

    /// Choose UTXOs that fund `target_amount` with **no change output**.
    ///
    /// `base_size_no_change` is the transaction with no inputs and no change output —
    /// the shape being aimed for. Input and change sizes come from [`TX_INPUT_SIZE`]
    /// and [`CHANGE_OUTPUT_SIZE`].
    ///
    /// `None` when nothing lands close enough, or the node budget runs out.
    fn branch_and_bound(
        &self,
        utxos: &[&Utxo],
        target_amount: u64,
        fee_rate: FeeRate,
        base_size_no_change: usize,
    ) -> Option<Vec<Utxo>> {
        // Effective values — value net of the fee to spend it — make the acceptance
        // test independent of how many inputs are chosen. Sizing the fee from a
        // guessed input count is what produced the old off-by-one.
        let input_fee = fee_rate.calculate_fee(TX_INPUT_SIZE);
        let mut candidates: Vec<BnbCandidate> = utxos
            .iter()
            .enumerate()
            .filter_map(|(index, utxo)| {
                // Worth no more than its own input costs: never helps.
                utxo.value().checked_sub(input_fee).filter(|ev| *ev > 0).map(|effective_value| {
                    BnbCandidate {
                        index,
                        effective_value,
                    }
                })
            })
            .collect();
        candidates.sort_by_key(|c| Reverse(c.effective_value));

        // What the effective values must cover.
        let target = target_amount.saturating_add(fee_rate.calculate_fee(base_size_no_change));
        let window = self.cost_of_change(fee_rate);

        // Lets the search abandon a branch that can no longer reach the target.
        let mut suffix = vec![0u64; candidates.len() + 1];
        for i in (0..candidates.len()).rev() {
            suffix[i] = suffix[i + 1].saturating_add(candidates[i].effective_value);
        }

        let mut search = BnbSearch {
            candidates: &candidates,
            suffix: &suffix,
            target,
            window,
            budget: BNB_NODE_BUDGET,
            best: None,
        };
        search.run(0, &mut Vec::new(), 0);

        let (chosen, _) = search.best?;
        let selected: Vec<Utxo> =
            chosen.iter().map(|&c| utxos[candidates[c].index].clone()).collect();

        // Effective values round each input's fee up on its own; the real transaction
        // rounds once over its whole size. Re-check against the real fee.
        let total_value: u64 = selected.iter().map(|u| u.value()).sum();
        let size = base_size_no_change + TX_INPUT_SIZE * selected.len();
        let required = target_amount.saturating_add(fee_rate.calculate_fee(size));
        (total_value >= required && total_value - required <= window).then_some(selected)
    }

    /// What a change output costs: creating it now plus spending it later. A surplus
    /// smaller than this is cheaper given to the miner than returned, which is what
    /// makes a near-exact match as good as an exact one.
    ///
    /// Floored at the dust threshold: below that it could not be change anyway (#911).
    fn cost_of_change(&self, fee_rate: FeeRate) -> u64 {
        let create = fee_rate.calculate_fee(CHANGE_OUTPUT_SIZE);
        let spend_later = fee_rate.calculate_fee(TX_INPUT_SIZE);
        create.saturating_add(spend_later).max(self.dust_threshold)
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
        change_output_size: usize,
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
                max_inputs,
            ) {
                let estimated_size = base_size + (TX_INPUT_SIZE * combination.len());
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

        // Minimize change while consolidating small UTXOs. `base_size` already budgets the
        // change output.
        let mut best_selection: Option<Vec<Utxo>> = None;
        let mut best_change = u64::MAX;

        for i in 1..=sorted_asc.len().min(10) {
            let mut current = Vec::new();
            let mut current_total = 0u64;

            for utxo in &sorted_asc[..i] {
                current.push((*utxo).clone());
                current_total += utxo.value();
            }

            let estimated_size = base_size + (TX_INPUT_SIZE * current.len());
            let estimated_fee = fee_rate.calculate_fee(estimated_size);
            let required = target_amount + estimated_fee;

            if current_total >= required {
                let change = current_total - required;
                if change < best_change && change > self.dust_threshold {
                    best_selection = Some(current);
                    best_change = change;
                }
            }
        }

        if let Some(selected) = best_selection {
            let estimated_size = base_size + (TX_INPUT_SIZE * selected.len());
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

        // Fall back to accumulate; `base_size` already budgets the change output.
        self.accumulate_coins_with_size(
            sorted_asc,
            target_amount,
            fee_rate,
            base_size,
            change_output_size,
        )
    }

    /// Find exact combination of UTXOs
    fn find_exact_combination(
        &self,
        utxos: &[&Utxo],
        target: u64,
        fee_rate: FeeRate,
        base_size: usize,
        max_inputs: usize,
    ) -> Option<Vec<Utxo>> {
        // Simple subset sum solver for exact matches
        // This is a simplified version - could be optimized with dynamic programming

        for num_inputs in 1..=max_inputs.min(utxos.len()) {
            let estimated_size = base_size + (TX_INPUT_SIZE * num_inputs);
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

impl std::error::Error for SelectionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test]
    fn test_select_all_drains_everything() {
        let utxos = vec![
            Utxo::dummy(0, 10000, 100, false, true),
            Utxo::dummy(0, 20000, 100, false, true),
            Utxo::dummy(0, 30000, 100, false, true),
        ];
        let selector = CoinSelector::new(SelectionStrategy::All);
        // Pass a non-zero target to prove it is IGNORED: a drain takes everything regardless.
        let result = selector.select_coins(&utxos, 12_345, FeeRate::new(1000), 200).unwrap();

        assert_eq!(result.selected.len(), 3, "All selects every spendable UTXO");
        assert_eq!(result.total_value, 60000);
        assert!(result.estimated_fee > 0);
        assert_eq!(result.target_amount, 60000 - result.estimated_fee, "deliverable = total - fee");
        assert_eq!(result.change_amount, 0, "a drain leaves no change");
        assert!(result.exact_match, "no change output for a drain");
    }

    #[test]
    fn test_select_all_empty_is_error() {
        let selector = CoinSelector::new(SelectionStrategy::All);
        let result = selector.select_coins(&[], 0, FeeRate::new(1000), 200);
        assert!(matches!(result, Err(SelectionError::NoUtxosAvailable)));
    }

    #[test]
    fn test_smallest_first_selection() {
        let utxos = vec![
            Utxo::dummy(0, 10000, 100, false, true),
            Utxo::dummy(0, 20000, 100, false, true),
            Utxo::dummy(0, 30000, 100, false, true),
            Utxo::dummy(0, 40000, 100, false, true),
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
            Utxo::dummy(0, 10000, 100, false, true),
            Utxo::dummy(0, 20000, 100, false, true),
            Utxo::dummy(0, 30000, 100, false, true),
            Utxo::dummy(0, 40000, 100, false, true),
        ];

        let selector = CoinSelector::new(SelectionStrategy::LargestFirst);
        let result = selector.select_coins(&utxos, 25000, FeeRate::new(1000), 200).unwrap();

        assert_eq!(result.selected.len(), 1); // Should select just 40k
        assert_eq!(result.total_value, 40000);
        assert!(result.change_amount > 0);
    }

    #[test]
    fn test_insufficient_funds() {
        let utxos =
            vec![Utxo::dummy(0, 10000, 100, false, true), Utxo::dummy(0, 20000, 100, false, true)];

        let selector = CoinSelector::new(SelectionStrategy::LargestFirst);
        let result = selector.select_coins(&utxos, 50000, FeeRate::new(1000), 200);

        assert!(matches!(result, Err(SelectionError::InsufficientFunds { .. })));
    }

    /// #911: a no-change send is wrongly rejected with a misleading `InsufficientFunds`
    /// (available > required) because the fee is sized for a change output that won't exist.
    /// UTXO 150_200, send 150_000 (fee 200, no change) — must succeed for every strategy.
    #[test_case(SelectionStrategy::SmallestFirst      ; "smallest_first")]
    #[test_case(SelectionStrategy::LargestFirst       ; "largest_first")]
    #[test_case(SelectionStrategy::SmallestFirstTill(2) ; "smallest_first_till")]
    #[test_case(SelectionStrategy::BranchAndBound     ; "branch_and_bound")]
    #[test_case(SelectionStrategy::OptimalConsolidation ; "optimal_consolidation")]
    #[test_case(SelectionStrategy::Random             ; "random")]
    fn test_zero_or_dust_change_send_not_rejected_issue_911(strategy: SelectionStrategy) {
        let utxos = vec![Utxo::dummy(0, 150_200, 100, false, true)];
        let target = 150_000;

        let result =
            CoinSelector::new(strategy).select_coins(&utxos, target, FeeRate::normal(), 200);

        // The bug's tell-tale: InsufficientFunds with available > required.
        if let Err(SelectionError::InsufficientFunds {
            available,
            required,
        }) = &result
        {
            assert!(
                available < required,
                "{strategy:?}: misleading InsufficientFunds — available {available} > required \
                 {required}; a no-change tx (fee {}) fits, so this send must not be rejected",
                available - target
            );
        }

        let selection =
            result.unwrap_or_else(|e| panic!("{strategy:?}: valid no-change send rejected: {e:?}"));
        assert_eq!(
            selection.change_amount, 0,
            "{strategy:?}: send-everything-minus-fee has no change"
        );
        assert_eq!(selection.total_value, 150_200, "{strategy:?}");
        assert_eq!(selection.estimated_fee, 200, "{strategy:?}: whole remainder becomes the fee");
    }

    /// #911 with its exact figures, through the fallback path: `BranchAndBound` (the builder
    /// default) and `OptimalConsolidation` used to hand the accumulator a `base_size` inflated by
    /// a phantom change output. UTXO 10_000_000, send 9_999_780 (fee 220, no change) — must hold
    /// for every strategy, not just those that skip the fallback.
    #[test_case(SelectionStrategy::SmallestFirst        ; "smallest_first")]
    #[test_case(SelectionStrategy::LargestFirst         ; "largest_first")]
    #[test_case(SelectionStrategy::SmallestFirstTill(2) ; "smallest_first_till")]
    #[test_case(SelectionStrategy::BranchAndBound       ; "branch_and_bound_default")]
    #[test_case(SelectionStrategy::OptimalConsolidation ; "optimal_consolidation")]
    #[test_case(SelectionStrategy::Random               ; "random")]
    fn test_issue_911_exact_figures_no_phantom_change(strategy: SelectionStrategy) {
        let utxos = vec![Utxo::dummy(0, 10_000_000, 100, false, true)];
        let target = 9_999_780;

        let result =
            CoinSelector::new(strategy).select_coins(&utxos, target, FeeRate::normal(), 200);

        let selection = result.unwrap_or_else(|e| {
            panic!("{strategy:?}: #911 send rejected (phantom change output in fallback?): {e:?}")
        });
        assert_eq!(selection.change_amount, 0, "{strategy:?}: no change on a send-everything");
        assert_eq!(
            selection.estimated_fee, 220,
            "{strategy:?}: the whole 220-duff remainder is the fee (no change output budgeted)"
        );
    }

    /// #911 gap 2: with no change address, `base_size` has no change output and
    /// `change_output_size` is 0 — the accumulator must NOT shave a phantom 34 bytes off the fee.
    /// Sending everything but a 158-duff remainder underpays the real 192-byte fee and must be
    /// rejected, not silently accepted below the min-relay fee.
    #[test_case(SelectionStrategy::SmallestFirst        ; "smallest_first")]
    #[test_case(SelectionStrategy::LargestFirst         ; "largest_first")]
    #[test_case(SelectionStrategy::SmallestFirstTill(2) ; "smallest_first_till")]
    #[test_case(SelectionStrategy::BranchAndBound       ; "branch_and_bound")]
    #[test_case(SelectionStrategy::OptimalConsolidation ; "optimal_consolidation")]
    #[test_case(SelectionStrategy::Random               ; "random")]
    fn test_no_change_address_does_not_underpay_issue_911_gap2(strategy: SelectionStrategy) {
        let utxos = vec![Utxo::dummy(0, 10_000_000, 100, false, true)];
        let target = 10_000_000 - 158; // only affordable if the fee were under-sized to 158
        let base_size = 10 + 34; // overhead + target output, NO change output
        let result = CoinSelector::new(strategy).select_coins_with_size(
            &utxos,
            target,
            FeeRate::normal(),
            200,
            base_size,
            0, // no change address => no change output to drop
        );
        assert!(
            matches!(result, Err(SelectionError::InsufficientFunds { .. })),
            "{strategy:?}: accepted an underpaid (158 < 192) no-change tx: {result:?}"
        );
    }

    /// Review finding: with no change address (`change_output_size == 0`) and a remainder well
    /// above dust, the leftover must be reported as change (so the builder can add a change output
    /// or error), NOT silently folded into the fee. Sending 100_000 out of a 10_000_000 UTXO leaves
    /// ~9.9M that must not become fee.
    #[test_case(SelectionStrategy::SmallestFirst        ; "smallest_first")]
    #[test_case(SelectionStrategy::LargestFirst         ; "largest_first")]
    #[test_case(SelectionStrategy::SmallestFirstTill(2) ; "smallest_first_till")]
    #[test_case(SelectionStrategy::BranchAndBound       ; "branch_and_bound")]
    #[test_case(SelectionStrategy::OptimalConsolidation ; "optimal_consolidation")]
    #[test_case(SelectionStrategy::Random               ; "random")]
    fn test_no_change_address_surplus_not_burned_as_fee(strategy: SelectionStrategy) {
        let utxos = vec![Utxo::dummy(0, 10_000_000, 100, false, true)];
        let target = 100_000;
        let base_size = 10 + 34; // one (target) output, no change output budgeted
        let selection = CoinSelector::new(strategy)
            .select_coins_with_size(&utxos, target, FeeRate::normal(), 200, base_size, 0)
            .unwrap_or_else(|e| panic!("{strategy:?}: {e:?}"));

        // No-change fee is 192 (44 + 148); the ~9.9M remainder is change, not fee.
        assert_eq!(
            selection.estimated_fee, 192,
            "{strategy:?}: only the no-change fee is charged, not the whole surplus"
        );
        assert_eq!(
            selection.change_amount,
            10_000_000 - target - 192,
            "{strategy:?}: the surplus is surfaced as change, not burned"
        );
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

    /// Size of a no-change transaction with `n` inputs.
    fn no_change_size(n: usize) -> usize {
        (10 + TX_OUTPUT_SIZE + CHANGE_OUTPUT_SIZE) - CHANGE_OUTPUT_SIZE + TX_INPUT_SIZE * n
    }

    /// The point of the strategy: fund the payment with no change output at all.
    #[test]
    fn test_branch_and_bound_finds_an_exact_match() {
        let selector = CoinSelector::new(SelectionStrategy::BranchAndBound);
        let fee_rate = FeeRate::new(1000);
        let utxos = vec![
            Utxo::dummy(0, 40_000, 100, false, true),
            Utxo::dummy(0, 30_000, 100, false, true),
            Utxo::dummy(0, 10_000, 100, false, true),
        ];

        // Sized from the inputs actually chosen. Before the rewrite this needed the
        // fee for *three* inputs, because the search sized it as `current.len() + 1`.
        let fee = fee_rate.calculate_fee(no_change_size(2));
        let target = 50_000 - fee;

        let result = selector.select_coins(&utxos, target, fee_rate, 200).unwrap();

        assert!(result.exact_match);
        assert_eq!(result.change_amount, 0, "an exact match needs no change output");
        assert_eq!(result.total_value, 50_000);
        assert_eq!(result.selected.len(), 2);
        assert_eq!(result.estimated_fee, fee, "nothing is burned beyond the real fee");
    }

    /// A surplus smaller than a change output would cost is taken anyway, folded into
    /// the fee. Demanding the exact satoshi would reject it for a costlier transaction.
    #[test]
    fn test_branch_and_bound_prefers_a_near_exact_match_over_change() {
        let selector = CoinSelector::new(SelectionStrategy::BranchAndBound);
        let fee_rate = FeeRate::new(1000);
        let utxos = vec![
            Utxo::dummy(0, 40_000, 100, false, true),
            Utxo::dummy(0, 30_000, 100, false, true),
            Utxo::dummy(0, 10_000, 100, false, true),
        ];

        let fee = fee_rate.calculate_fee(no_change_size(2));
        let surplus = 300; // under the dust threshold, so it could never be change
        let target = 50_000 - fee - surplus;

        let result = selector.select_coins(&utxos, target, fee_rate, 200).unwrap();

        assert_eq!(result.total_value, 50_000);
        assert_eq!(result.change_amount, 0, "the surplus is not worth a change output");
        assert_eq!(result.estimated_fee, fee + surplus, "the surplus goes to the fee, not lost");
    }

    /// The mirror image: a surplus worth keeping must come back, not be burned.
    #[test]
    fn test_branch_and_bound_returns_change_when_the_surplus_is_worth_keeping() {
        let selector = CoinSelector::new(SelectionStrategy::BranchAndBound);
        let utxos = vec![Utxo::dummy(0, 60_000, 100, false, true)];

        let result = selector.select_coins(&utxos, 50_000, FeeRate::new(1000), 200).unwrap();

        assert!(result.change_amount > 0, "a large surplus must come back as change");
        assert!(!result.exact_match);
    }

    /// A UTXO worth no more than the fee to spend it contributes nothing.
    #[test]
    fn test_branch_and_bound_skips_uneconomic_utxos() {
        let selector = CoinSelector::new(SelectionStrategy::BranchAndBound);
        let fee_rate = FeeRate::new(1000);
        // An input costs 148 sat at this rate, so 120 is uneconomic.
        let utxos = vec![
            Utxo::dummy(0, 40_000, 100, false, true),
            Utxo::dummy(0, 10_000, 100, false, true),
            Utxo::dummy(0, 120, 100, false, true),
        ];
        let target = 50_000 - fee_rate.calculate_fee(no_change_size(2));

        let result = selector.select_coins(&utxos, target, fee_rate, 200).unwrap();

        assert!(
            !result.selected.iter().any(|u| u.value() == 120),
            "an input that costs more than it brings must not be selected"
        );
    }

    /// Issue #918: a near-total target defeated the only bound the search had
    /// (overshoot) — ~3s at 22 UTXOs, non-terminating past 32.
    #[test]
    fn test_branch_and_bound_near_total_balance_is_bounded() {
        let selector = CoinSelector::new(SelectionStrategy::BranchAndBound);

        for n in [24usize, 32, 48, 64] {
            let utxos: Vec<Utxo> = (0..n)
                .map(|i| Utxo::dummy(0, 100_000 + (i as u64) * 7_919, 100, false, true))
                .collect();
            let total: u64 = utxos.iter().map(|u| u.value()).sum();

            let started = std::time::Instant::now();
            let result = selector
                .select_coins(&utxos, total - 50_000, FeeRate::new(1000), 200)
                .expect("a near-total target is still fundable");
            let elapsed = started.elapsed();

            assert!(result.total_value >= total - 50_000);
            // Generous on purpose: this only has to catch a return to unbounded
            // search, not police runner speed. The node-count test below is what
            // actually pins the bound.
            assert!(
                elapsed < std::time::Duration::from_secs(30),
                "selection over {} UTXOs took {:?}; the search is unbounded again",
                n,
                elapsed
            );
        }
    }

    /// A low target leaves a huge feasible space; the node budget bounds it.
    #[test]
    fn test_branch_and_bound_mid_range_target_is_bounded() {
        let selector = CoinSelector::new(SelectionStrategy::BranchAndBound);
        let utxos: Vec<Utxo> = (0..64)
            .map(|i| Utxo::dummy(0, 100_000 + (i as u64) * 7_919, 100, false, true))
            .collect();
        let total: u64 = utxos.iter().map(|u| u.value()).sum();

        let started = std::time::Instant::now();
        let result = selector.select_coins(&utxos, total / 3, FeeRate::new(1000), 200).unwrap();
        let elapsed = started.elapsed();

        assert!(result.total_value >= total / 3);
        assert!(
            elapsed < std::time::Duration::from_secs(30),
            "selection took {:?}; the node budget is not bounding the search",
            elapsed
        );
    }

    /// What actually fixes #918 is the feasibility bound, not the node budget: with
    /// a near-total target the search settles in a handful of nodes instead of
    /// walking 2^N. Asserted on nodes visited, so it does not depend on machine speed.
    #[test]
    fn test_feasibility_bound_settles_a_near_total_target_in_few_nodes() {
        let fee_rate = FeeRate::new(1000);
        let values: Vec<u64> = (0..32u64).map(|i| 100_000 + i * 7_919).collect();
        let total: u64 = values.iter().sum();

        let (candidates, suffix) = bnb_setup(&values, fee_rate);
        let visited = run_bnb(&candidates, &suffix, total - 50_000);
        assert!(
            visited < 1_000,
            "a near-total target should be bounded in a few nodes, visited {}",
            visited
        );
    }

    /// Candidates and suffix sums as `branch_and_bound` builds them, so a test can
    /// drive the search directly and count what it costs.
    fn bnb_setup(values: &[u64], fee_rate: FeeRate) -> (Vec<BnbCandidate>, Vec<u64>) {
        let input_fee = fee_rate.calculate_fee(TX_INPUT_SIZE);
        let mut candidates: Vec<BnbCandidate> = values
            .iter()
            .enumerate()
            .map(|(index, v)| BnbCandidate {
                index,
                effective_value: v - input_fee,
            })
            .collect();
        candidates.sort_by_key(|c| Reverse(c.effective_value));

        let mut suffix = vec![0u64; candidates.len() + 1];
        for i in (0..candidates.len()).rev() {
            suffix[i] = suffix[i + 1] + candidates[i].effective_value;
        }
        (candidates, suffix)
    }

    /// Run the search over a full budget and report the nodes it visited.
    fn run_bnb(candidates: &[BnbCandidate], suffix: &[u64], target: u64) -> u32 {
        let mut search = BnbSearch {
            candidates,
            suffix,
            target,
            window: 546,
            budget: BNB_NODE_BUDGET,
            best: None,
        };
        search.run(0, &mut Vec::new(), 0);
        BNB_NODE_BUDGET - search.budget
    }

    /// The mirror of the near-total case: a low target leaves a huge feasible space
    /// with no exact match in it, so the bounds cannot settle it and the *budget* is
    /// what has to stop the search. Asserted on nodes visited rather than the clock.
    #[test]
    fn test_node_budget_stops_a_mid_range_search() {
        let fee_rate = FeeRate::new(1000);
        let values: Vec<u64> = (0..64u64).map(|i| 100_000 + i * 7_919).collect();
        let total: u64 = values.iter().sum();

        let (candidates, suffix) = bnb_setup(&values, fee_rate);
        let visited = run_bnb(&candidates, &suffix, total / 3);

        assert_eq!(
            visited, BNB_NODE_BUDGET,
            "the budget should be the binding constraint here; if the bounds now settle \
             this case in {visited} nodes the budget may be sized wrong"
        );
    }
}
