//! Tests for CoinJoin transaction handling

use super::helpers::*;
use crate::transaction_checking::transaction_router::{
    AccountTypeToCheck, TransactionRouter, TransactionType,
};

#[test]
fn test_coinjoin_mixing_round() {
    // Standard CoinJoin mixing round
    let tx = create_test_transaction(
        6, // Multiple participants
        vec![
            10_000_000, // 0.1 DASH denomination
            10_000_000, // 0.1 DASH denomination
            10_000_000, // 0.1 DASH denomination
            10_000_000, // 0.1 DASH denomination
            10_000_000, // 0.1 DASH denomination
            10_000_000, // 0.1 DASH denomination
        ],
    );

    let tx_type = TransactionRouter::classify_transaction(&tx);
    assert_eq!(tx_type, TransactionType::CoinJoin);

    let accounts = TransactionRouter::get_relevant_account_types(&tx_type);
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0], AccountTypeToCheck::CoinJoin);
}

#[test]
fn test_coinjoin_with_multiple_denominations() {
    // CoinJoin with mixed denominations
    let tx = create_test_transaction(
        8,
        vec![
            100_000_000, // 1 DASH
            100_000_000, // 1 DASH
            10_000_000,  // 0.1 DASH
            10_000_000,  // 0.1 DASH
            1_000_000,   // 0.01 DASH
            1_000_000,   // 0.01 DASH
            100_000,     // 0.001 DASH
            100_000,     // 0.001 DASH
        ],
    );

    let tx_type = TransactionRouter::classify_transaction(&tx);
    assert_eq!(tx_type, TransactionType::CoinJoin);

    let accounts = TransactionRouter::get_relevant_account_types(&tx_type);
    assert_eq!(accounts[0], AccountTypeToCheck::CoinJoin);
}

#[test]
fn test_coinjoin_threshold_exactly_half_denominations() {
    // Edge case: exactly half outputs are denominations
    let tx = create_test_transaction(
        4,
        vec![
            100_000_000, // Denomination
            100_000_000, // Denomination
            50_000_000,  // Non-denomination
            50_000_000,  // Non-denomination
        ],
    );

    let tx_type = TransactionRouter::classify_transaction(&tx);
    // Should be classified as CoinJoin (>= 50% denominations)
    assert_eq!(tx_type, TransactionType::CoinJoin);
}

#[test]
fn test_not_coinjoin_just_under_threshold() {
    // Just under 50% denominations
    let tx = create_test_transaction(
        3,
        vec![
            100_000_000, // Denomination
            50_000_000,  // Non-denomination
            75_000_000,  // Non-denomination
            25_000_000,  // Non-denomination
        ],
    );

    let tx_type = TransactionRouter::classify_transaction(&tx);
    // Should NOT be classified as CoinJoin (< 50% denominations)
    assert_eq!(tx_type, TransactionType::Standard);
}
