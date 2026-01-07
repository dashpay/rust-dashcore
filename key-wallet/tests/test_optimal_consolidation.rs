use key_wallet::Utxo;

// Test for OptimalConsolidation coin selection strategy
#[test]
fn test_optimal_consolidation_strategy() {
    use key_wallet::wallet::managed_wallet_info::coin_selection::*;
    use key_wallet::wallet::managed_wallet_info::fee::FeeRate;

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

    println!("Selected {} UTXOs with total value {}", result.selected.len(), result.total_value);
    println!("Selected values: {:?}", selected_values);
}
