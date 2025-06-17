use dashcore::{Address, Amount, Network};
use std::collections::HashMap;
use std::str::FromStr;

/// Test for the specific transaction calculation bug described in:
/// Transaction 62364518eeb41d01f71f7aff9d1046f188dd6c1b311e84908298b2f82c0b7a1b
///
/// This transaction shows wrong net amount calculation where:
/// - Expected: -0.00020527 BTC (fee + small transfer)  
/// - Actual log showed: +13.88979473 BTC (incorrect)
///
/// The bug appears to be in the balance change calculation logic where
/// the code may be only processing the first input or incorrectly handling
/// multiple inputs from the same address.
#[test]
fn test_transaction_62364518_net_amount_calculation() {
    // Transaction data based on the raw transaction and explorer:
    // Transaction: 62364518eeb41d01f71f7aff9d1046f188dd6c1b311e84908298b2f82c0b7a1b

    let watched_address = Address::from_str("XjbaGWaGnvEtuQAUoBgDxJWe8ZNv45upG2")
        .unwrap()
        .require_network(Network::Dash)
        .unwrap();

    // Input values (all from the same watched address):
    let input1_value = 1389000000i64; // 13.89 BTC
    let input2_value = 42631789513i64; // 426.31789513 BTC
    let input3_value = 89378917i64; // 0.89378917 BTC
    let total_inputs = input1_value + input2_value + input3_value; // 44122168430 satoshis

    // Output values:
    let output_to_other = 20008i64; // 0.00020008 BTC to different address
    let output_to_watched = 44110147903i64; // 441.10147903 BTC back to watched address (change)

    // Simulate the balance change calculation as done in block_processor.rs
    let mut balance_changes: HashMap<Address, i64> = HashMap::new();

    // Process inputs (subtract from balance - spending UTXOs)
    *balance_changes.entry(watched_address.clone()).or_insert(0) -= input1_value;
    *balance_changes.entry(watched_address.clone()).or_insert(0) -= input2_value;
    *balance_changes.entry(watched_address.clone()).or_insert(0) -= input3_value;

    // Process outputs (add to balance - receiving UTXOs)
    // Note: output_to_other goes to different address, so not tracked here
    *balance_changes.entry(watched_address.clone()).or_insert(0) += output_to_watched;

    let actual_net_change = balance_changes.get(&watched_address).unwrap_or(&0);

    // Calculate expected values
    let expected_net_change = output_to_watched - total_inputs; // Should be -20527 (negative)

    println!("\n=== Transaction 62364518 Balance Calculation ===");
    println!(
        "Input 1 (XjbaGWaGnvEtuQAUoBgDxJWe8ZNv45upG2): {} sat ({} BTC)",
        input1_value,
        Amount::from_sat(input1_value as u64)
    );
    println!(
        "Input 2 (XjbaGWaGnvEtuQAUoBgDxJWe8ZNv45upG2): {} sat ({} BTC)",
        input2_value,
        Amount::from_sat(input2_value as u64)
    );
    println!(
        "Input 3 (XjbaGWaGnvEtuQAUoBgDxJWe8ZNv45upG2): {} sat ({} BTC)",
        input3_value,
        Amount::from_sat(input3_value as u64)
    );
    println!(
        "Total inputs from watched address: {} sat ({} BTC)",
        total_inputs,
        Amount::from_sat(total_inputs as u64)
    );
    println!();
    println!(
        "Output to other address: {} sat ({} BTC)",
        output_to_other,
        Amount::from_sat(output_to_other as u64)
    );
    println!(
        "Output back to watched address: {} sat ({} BTC)",
        output_to_watched,
        Amount::from_sat(output_to_watched as u64)
    );
    println!();
    println!(
        "Expected net change: {} sat ({} BTC)",
        expected_net_change,
        Amount::from_sat(expected_net_change.abs() as u64)
    );
    println!(
        "Actual net change: {} sat ({} BTC)",
        actual_net_change,
        Amount::from_sat(actual_net_change.abs() as u64)
    );

    // The key assertion: net change should be negative (fee + amount sent to other address)
    assert_eq!(
        *actual_net_change, expected_net_change,
        "Net amount calculation is incorrect. Expected {} sat, got {} sat",
        expected_net_change, actual_net_change
    );

    // Additional verification: the net change should represent fee + transfer amount
    let transaction_fee = expected_net_change.abs() - output_to_other;
    println!(
        "Transaction fee: {} sat ({} BTC)",
        transaction_fee,
        Amount::from_sat(transaction_fee as u64)
    );

    // Verify the transaction makes sense
    assert!(*actual_net_change < 0, "Net change should be negative for spending transaction");
    assert_eq!(*actual_net_change, -20527i64, "Expected exactly -20527 sat net change");
    assert!(transaction_fee > 0, "Transaction fee should be positive");
    assert_eq!(transaction_fee, 519i64, "Expected exactly 519 sat transaction fee");
}

/// Test the bug scenario: what if only the first input is processed?
/// This reproduces the suspected bug where only the first input is considered.
#[test]
fn test_suspected_bug_only_first_input() {
    let watched_address = Address::from_str("XjbaGWaGnvEtuQAUoBgDxJWe8ZNv45upG2")
        .unwrap()
        .require_network(Network::Dash)
        .unwrap();

    // Same transaction data
    let input1_value = 1389000000i64; // 13.89 BTC (first input)
    let output_to_watched = 44110147903i64; // 441.10147903 BTC back to watched address

    // Simulate the BUGGY calculation (only processing first input)
    let mut balance_changes: HashMap<Address, i64> = HashMap::new();

    // BUG: Only process the first input instead of all three
    *balance_changes.entry(watched_address.clone()).or_insert(0) -= input1_value;

    // Still process the output correctly
    *balance_changes.entry(watched_address.clone()).or_insert(0) += output_to_watched;

    let buggy_net_change = balance_changes.get(&watched_address).unwrap_or(&0);
    let buggy_result = output_to_watched - input1_value; // 42721147903 sat = 427.21147903 BTC

    println!("\n=== Suspected Bug: Only First Input Processed ===");
    println!(
        "Only first input processed: {} sat ({} BTC)",
        input1_value,
        Amount::from_sat(input1_value as u64)
    );
    println!(
        "Output to watched address: {} sat ({} BTC)",
        output_to_watched,
        Amount::from_sat(output_to_watched as u64)
    );
    println!(
        "Buggy net change: {} sat ({} BTC)",
        buggy_net_change,
        Amount::from_sat(*buggy_net_change as u64)
    );

    assert_eq!(*buggy_net_change, buggy_result);
    assert!(*buggy_net_change > 0, "Buggy calculation would show positive balance increase");

    // The reported bug was +13.88979473 BTC, which is close to the first input amount
    // This suggests the bug might be more complex than just "only first input"
    // Let's check if it could be a different calculation error
    let reported_bug_amount = 1388979473i64; // 13.88979473 BTC in satoshis

    // This is very close to input1_value (1389000000) minus a small amount
    let difference = input1_value - reported_bug_amount;
    println!("Difference between first input and reported bug: {} sat", difference);

    // The difference is 20527 sat, which equals the correct net change magnitude!
    // This suggests the bug might be: output - (input1 - correct_net_change)
    assert_eq!(difference, 20527i64, "Suspicious: difference equals correct net change magnitude");
}

/// Test for edge case: multiple inputs, single output to watched address
#[test]
fn test_multiple_inputs_single_output() {
    let watched_address = Address::from_str("XjbaGWaGnvEtuQAUoBgDxJWe8ZNv45upG2")
        .unwrap()
        .require_network(Network::Dash)
        .unwrap();

    // Simpler test case: consolidation transaction
    let input1 = 50000000i64; // 0.5 BTC
    let input2 = 30000000i64; // 0.3 BTC
    let input3 = 20000000i64; // 0.2 BTC
    let total_inputs = input1 + input2 + input3; // 1.0 BTC

    let output = 99000000i64; // 0.99 BTC (0.01 BTC fee)

    let mut balance_changes: HashMap<Address, i64> = HashMap::new();

    // Process all inputs
    *balance_changes.entry(watched_address.clone()).or_insert(0) -= input1;
    *balance_changes.entry(watched_address.clone()).or_insert(0) -= input2;
    *balance_changes.entry(watched_address.clone()).or_insert(0) -= input3;

    // Process output
    *balance_changes.entry(watched_address.clone()).or_insert(0) += output;

    let net_change = balance_changes.get(&watched_address).unwrap();
    let expected = output - total_inputs; // Should be -1000000 (0.01 BTC fee)

    assert_eq!(*net_change, expected);
    assert_eq!(*net_change, -1000000i64, "Should lose exactly 0.01 BTC in fees");
}

/// Test for a simple receive-only transaction
#[test]
fn test_receive_only_transaction() {
    let receiver_address = Address::from_str("XjbaGWaGnvEtuQAUoBgDxJWe8ZNv45upG2")
        .unwrap()
        .require_network(Network::Dash)
        .unwrap();

    let mut balance_changes: HashMap<Address, i64> = HashMap::new();

    // Simulate receiving payment (no inputs from this address)
    let received_amount = 50000000i64; // 0.5 BTC
    *balance_changes.entry(receiver_address.clone()).or_insert(0) += received_amount;

    let net_change = balance_changes.get(&receiver_address).unwrap();

    assert_eq!(*net_change, received_amount);
    assert!(*net_change > 0, "Receive-only transaction should have positive net change");
}

/// Test for a spend-only transaction (no change back)
#[test]
fn test_spend_only_transaction() {
    let sender_address = Address::from_str("XjbaGWaGnvEtuQAUoBgDxJWe8ZNv45upG2")
        .unwrap()
        .require_network(Network::Dash)
        .unwrap();

    let mut balance_changes: HashMap<Address, i64> = HashMap::new();

    // Simulate spending all UTXOs with no change (only fee paid)
    let spent_amount = 100000000i64; // 1 BTC
    *balance_changes.entry(sender_address.clone()).or_insert(0) -= spent_amount;

    let net_change = balance_changes.get(&sender_address).unwrap();

    assert_eq!(*net_change, -spent_amount);
    assert!(*net_change < 0, "Spend-only transaction should have negative net change");
}
