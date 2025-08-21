// Test for OptimalConsolidation coin selection strategy
#[test]
fn test_optimal_consolidation_strategy() {
    use dashcore::blockdata::script::ScriptBuf;
    use dashcore::{Address, Network, OutPoint, TxOut, Txid};
    use dashcore_hashes::{sha256d, Hash};
    use key_wallet::utxo::Utxo;
    use key_wallet::wallet::managed_wallet_info::coin_selection::*;
    use key_wallet::wallet::managed_wallet_info::fee::FeeRate;

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

    // Test that OptimalConsolidation strategy works correctly
    let utxos = vec![
        test_utxo(100, true),
        test_utxo(200, true),
        test_utxo(300, true),
        test_utxo(500, true),
        test_utxo(1000, true),
        test_utxo(2000, true),
    ];

    let selector = CoinSelector::new(SelectionStrategy::OptimalConsolidation);
    let fee_rate = FeeRate::new(100); // Simpler fee rate
    let result = selector.select_coins(&utxos, 1500, fee_rate, 200).unwrap();

    // OptimalConsolidation should work and produce a valid selection
    assert!(result.selected.len() > 0);
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
