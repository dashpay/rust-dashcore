//! Tests for CoinJoin transaction handling

use super::helpers::*;
use crate::transaction_checking::transaction_router::{
    AccountTypeToCheck, TransactionRouter, TransactionType,
};
use dashcore::blockdata::transaction::Transaction;

#[test]
fn test_coinjoin_mixing_round() {
    // Standard CoinJoin mixing round
    let addr = test_addr();
    let tx = Transaction::dummy(
        &addr,
        0..6, // Multiple participants
        &[
            10_000_100, // 0.1 DASH denomination (+ fee)
            10_000_100, // 0.1 DASH denomination (+ fee)
            10_000_100, // 0.1 DASH denomination (+ fee)
            10_000_100, // 0.1 DASH denomination (+ fee)
            10_000_100, // 0.1 DASH denomination (+ fee)
            10_000_100, // 0.1 DASH denomination (+ fee)
        ],
    );

    let tx_type = TransactionRouter::classify_transaction(&tx);
    assert_eq!(tx_type, TransactionType::CoinJoin);

    // The CoinJoin label does not narrow discovery: ownership is membership-based, so a CoinJoin
    // tx checks every fund-bearing account (it commonly touches standard funds for collateral,
    // funding, and change too).
    let accounts = TransactionRouter::get_relevant_account_types(&tx_type);
    assert!(accounts.contains(&AccountTypeToCheck::CoinJoin));
    assert!(accounts.contains(&AccountTypeToCheck::StandardBIP44));
    assert!(accounts.contains(&AccountTypeToCheck::StandardBIP32));
    assert!(accounts.contains(&AccountTypeToCheck::DashpayReceivingFunds));
    assert!(accounts.contains(&AccountTypeToCheck::DashpayExternalAccount));
}

#[test]
fn test_coinjoin_with_multiple_denominations() {
    // CoinJoin with mixed denominations
    let addr = test_addr();
    let tx = Transaction::dummy(
        &addr,
        0..8,
        &[
            100_001_000, // 1 DASH (+ fee)
            100_001_000, // 1 DASH (+ fee)
            10_000_100,  // 0.1 DASH (+ fee)
            10_000_100,  // 0.1 DASH (+ fee)
            1_000_010,   // 0.01 DASH (+ fee)
            1_000_010,   // 0.01 DASH (+ fee)
            100_001,     // 0.001 DASH (+ fee)
            100_001,     // 0.001 DASH (+ fee)
        ],
    );

    let tx_type = TransactionRouter::classify_transaction(&tx);
    assert_eq!(tx_type, TransactionType::CoinJoin);

    let accounts = TransactionRouter::get_relevant_account_types(&tx_type);
    assert!(accounts.contains(&AccountTypeToCheck::CoinJoin));
    assert!(accounts.contains(&AccountTypeToCheck::StandardBIP44));
}

#[test]
fn test_coinjoin_threshold_exactly_half_denominations() {
    // Edge case: exactly half outputs are denominations
    let addr = test_addr();
    let tx = Transaction::dummy(
        &addr,
        0..4,
        &[
            100_001_000, // Denomination
            100_001_000, // Denomination
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
    let addr = test_addr();
    let tx = Transaction::dummy(
        &addr,
        0..3,
        &[
            100_001_000, // Denomination
            50_000_000,  // Non-denomination
            75_000_000,  // Non-denomination
            25_000_000,  // Non-denomination
        ],
    );

    let tx_type = TransactionRouter::classify_transaction(&tx);
    // Should NOT be classified as CoinJoin (< 50% denominations)
    assert_eq!(tx_type, TransactionType::Standard);
}
