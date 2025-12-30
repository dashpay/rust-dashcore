//! Tests for standard transaction patterns

use super::helpers::*;
use crate::transaction_checking::transaction_router::{
    AccountTypeToCheck, TransactionRouter, TransactionType,
};

#[test]
fn test_single_input_two_outputs_payment() {
    // Typical payment: 1 input -> payment + change
    let tx = create_test_transaction(
        1,
        vec![
            25_000_000, // Payment amount
            74_900_000, // Change (minus fee)
        ],
    );

    let tx_type = TransactionRouter::classify_transaction(&tx);
    assert_eq!(tx_type, TransactionType::Standard);

    let accounts = TransactionRouter::get_relevant_account_types(&tx_type);
    assert!(accounts.contains(&AccountTypeToCheck::StandardBIP44));
    assert!(accounts.contains(&AccountTypeToCheck::StandardBIP32));
}

#[test]
fn test_multiple_inputs_single_output_consolidation() {
    // Consolidation: multiple inputs -> single output
    let tx = create_test_transaction(
        5,
        vec![
            499_900_000, // Consolidated amount minus fee
        ],
    );

    let tx_type = TransactionRouter::classify_transaction(&tx);
    assert_eq!(tx_type, TransactionType::Standard);

    let accounts = TransactionRouter::get_relevant_account_types(&tx_type);
    // Standard transaction should check both BIP44 and BIP32 accounts
    assert!(accounts.contains(&AccountTypeToCheck::StandardBIP44));
    assert!(accounts.contains(&AccountTypeToCheck::StandardBIP32));
}

#[test]
fn test_many_inputs_same_account() {
    // Spending many small UTXOs from same account
    // 10 small inputs -> payment + change
    let tx = create_test_transaction(
        10,
        vec![
            75_000_000, // Payment
            24_950_000, // Change
        ],
    );

    let tx_type = TransactionRouter::classify_transaction(&tx);
    assert_eq!(tx_type, TransactionType::Standard);

    // Should still be routed to standard accounts
    let accounts = TransactionRouter::get_relevant_account_types(&tx_type);
    assert!(accounts.contains(&AccountTypeToCheck::StandardBIP44));
    assert!(accounts.contains(&AccountTypeToCheck::StandardBIP32));
}

#[test]
fn test_payment_to_multiple_recipients() {
    // Batch payment: 1 input -> multiple recipients + change
    let tx = create_test_transaction(
        1,
        vec![
            10_000_000, // Recipient 1
            15_000_000, // Recipient 2
            20_000_000, // Recipient 3
            5_000_000,  // Recipient 4
            49_900_000, // Change
        ],
    );

    let tx_type = TransactionRouter::classify_transaction(&tx);
    assert_eq!(tx_type, TransactionType::Standard);

    let accounts = TransactionRouter::get_relevant_account_types(&tx_type);
    assert!(accounts.contains(&AccountTypeToCheck::StandardBIP44));
    assert!(accounts.contains(&AccountTypeToCheck::StandardBIP32));
}
