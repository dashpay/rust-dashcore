//! Comprehensive unit tests for UTXO management
//!
//! This module tests UTXO creation, state management, serialization,
//! and spending detection functionality.

#[cfg(test)]
mod tests {
    use super::super::utxo::*;
    use dashcore::{Address, Amount, Network, OutPoint, PubkeyHash, ScriptBuf, TxOut, Txid};
    use dashcore_hashes::Hash;
    use std::str::FromStr;

    // Helper functions

    fn create_test_address(seed: u8) -> Address {
        let pubkey_hash = PubkeyHash::from_slice(&[seed; 20])
            .expect("Valid 20-byte slice for pubkey hash");
        let script = ScriptBuf::new_p2pkh(&pubkey_hash);
        Address::from_script(&script, Network::Testnet)
            .expect("Valid P2PKH script should produce valid address")
    }

    fn create_test_outpoint(tx_num: u8, vout: u32) -> OutPoint {
        OutPoint {
            txid: Txid::from_slice(&[tx_num; 32]).expect("Valid test txid"),
            vout,
        }
    }

    fn create_test_utxo(value: u64, height: u32, is_coinbase: bool) -> Utxo {
        let outpoint = create_test_outpoint(1, 0);
        let txout = TxOut {
            value,
            script_pubkey: ScriptBuf::new(),
        };
        let address = create_test_address(1);
        Utxo::new(outpoint, txout, address, height, is_coinbase)
    }

    // Basic UTXO creation and property tests

    #[test]
    fn test_utxo_new() {
        let outpoint = create_test_outpoint(1, 0);
        let txout = TxOut {
            value: 100000,
            script_pubkey: ScriptBuf::new(),
        };
        let address = create_test_address(1);
        
        let utxo = Utxo::new(outpoint, txout.clone(), address.clone(), 100, false);
        
        assert_eq!(utxo.outpoint, outpoint);
        assert_eq!(utxo.txout, txout);
        assert_eq!(utxo.address, address);
        assert_eq!(utxo.height, 100);
        assert!(!utxo.is_coinbase);
        assert!(!utxo.is_confirmed);
        assert!(!utxo.is_instantlocked);
    }

    #[test]
    fn test_utxo_value() {
        let utxo = create_test_utxo(123456789, 100, false);
        assert_eq!(utxo.value(), Amount::from_sat(123456789));
    }

    #[test]
    fn test_utxo_script_pubkey() {
        let script = ScriptBuf::from_hex("76a914000000000000000000000000000000000000000088ac")
            .expect("Valid hex script");
        let txout = TxOut {
            value: 100000,
            script_pubkey: script.clone(),
        };
        let utxo = Utxo::new(
            create_test_outpoint(1, 0),
            txout,
            create_test_address(1),
            100,
            false,
        );
        
        assert_eq!(utxo.script_pubkey(), &script);
    }

    // State management tests

    #[test]
    fn test_utxo_set_confirmed() {
        let mut utxo = create_test_utxo(100000, 100, false);
        
        assert!(!utxo.is_confirmed);
        utxo.set_confirmed(true);
        assert!(utxo.is_confirmed);
        utxo.set_confirmed(false);
        assert!(!utxo.is_confirmed);
    }

    #[test]
    fn test_utxo_set_instantlocked() {
        let mut utxo = create_test_utxo(100000, 100, false);
        
        assert!(!utxo.is_instantlocked);
        utxo.set_instantlocked(true);
        assert!(utxo.is_instantlocked);
        utxo.set_instantlocked(false);
        assert!(!utxo.is_instantlocked);
    }

    #[test]
    fn test_utxo_multiple_state_changes() {
        let mut utxo = create_test_utxo(100000, 100, false);
        
        // Set multiple states
        utxo.set_confirmed(true);
        utxo.set_instantlocked(true);
        
        assert!(utxo.is_confirmed);
        assert!(utxo.is_instantlocked);
        
        // Unset one state
        utxo.set_confirmed(false);
        assert!(!utxo.is_confirmed);
        assert!(utxo.is_instantlocked);
    }

    // Spendability tests

    #[test]
    fn test_regular_utxo_always_spendable() {
        let utxo = create_test_utxo(100000, 100, false);
        
        // Regular UTXOs are always spendable regardless of height
        assert!(utxo.is_spendable(0));
        assert!(utxo.is_spendable(100));
        assert!(utxo.is_spendable(200));
        assert!(utxo.is_spendable(u32::MAX));
    }

    #[test]
    fn test_coinbase_utxo_maturity() {
        let coinbase_utxo = create_test_utxo(5000000000, 100, true);
        
        // Coinbase needs 100 confirmations
        assert!(!coinbase_utxo.is_spendable(100)); // 0 confirmations
        assert!(!coinbase_utxo.is_spendable(101)); // 1 confirmation
        assert!(!coinbase_utxo.is_spendable(199)); // 99 confirmations
        assert!(coinbase_utxo.is_spendable(200)); // 100 confirmations
        assert!(coinbase_utxo.is_spendable(300)); // >100 confirmations
    }

    #[test]
    fn test_coinbase_utxo_edge_cases() {
        // Test coinbase at height 0
        let coinbase_utxo = create_test_utxo(5000000000, 0, true);
        assert!(!coinbase_utxo.is_spendable(0));
        assert!(!coinbase_utxo.is_spendable(99));
        assert!(coinbase_utxo.is_spendable(100));
        
        // Test with overflow protection
        let high_height_utxo = create_test_utxo(5000000000, u32::MAX - 50, true);
        assert!(!high_height_utxo.is_spendable(u32::MAX - 50));
        assert!(!high_height_utxo.is_spendable(u32::MAX));
    }

    // Serialization tests

    #[test]
    fn test_utxo_json_serialization() {
        let mut utxo = create_test_utxo(123456, 999, false);
        utxo.set_confirmed(true);
        utxo.set_instantlocked(true);
        
        let json = serde_json::to_string(&utxo)
            .expect("Should serialize UTXO to JSON");
        let deserialized: Utxo = serde_json::from_str(&json)
            .expect("Should deserialize UTXO from JSON");
        
        assert_eq!(utxo, deserialized);
        assert_eq!(deserialized.is_confirmed, true);
        assert_eq!(deserialized.is_instantlocked, true);
    }

    #[test]
    fn test_utxo_bincode_serialization() {
        let utxo = create_test_utxo(987654321, 12345, true);
        
        let encoded = bincode::serialize(&utxo)
            .expect("Should serialize UTXO with bincode");
        let decoded: Utxo = bincode::deserialize(&encoded)
            .expect("Should deserialize UTXO with bincode");
        
        assert_eq!(utxo, decoded);
    }

    #[test]
    fn test_utxo_serialization_preserves_all_fields() {
        let outpoint = OutPoint {
            txid: Txid::from_str(
                "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            ).expect("Valid test txid"),
            vout: 42,
        };
        
        let txout = TxOut {
            value: 999999999,
            script_pubkey: ScriptBuf::from_hex("76a914abcdef88ac").expect("Valid hex script"),
        };
        
        let address = create_test_address(99);
        
        let mut utxo = Utxo::new(outpoint, txout, address, 654321, true);
        utxo.set_confirmed(true);
        utxo.set_instantlocked(false);
        
        // Test JSON roundtrip
        let json = serde_json::to_string(&utxo).expect("Should serialize to JSON");
        let from_json: Utxo = serde_json::from_str(&json).expect("Should deserialize from JSON");
        
        assert_eq!(utxo.outpoint, from_json.outpoint);
        assert_eq!(utxo.txout, from_json.txout);
        assert_eq!(utxo.address, from_json.address);
        assert_eq!(utxo.height, from_json.height);
        assert_eq!(utxo.is_coinbase, from_json.is_coinbase);
        assert_eq!(utxo.is_confirmed, from_json.is_confirmed);
        assert_eq!(utxo.is_instantlocked, from_json.is_instantlocked);
    }

    // Equality tests

    #[test]
    fn test_utxo_equality() {
        let utxo1 = create_test_utxo(100000, 100, false);
        let utxo2 = create_test_utxo(100000, 100, false);
        let utxo3 = create_test_utxo(200000, 100, false); // Different value
        
        assert_eq!(utxo1, utxo2);
        assert_ne!(utxo1, utxo3);
    }

    #[test]
    fn test_utxo_equality_with_states() {
        let mut utxo1 = create_test_utxo(100000, 100, false);
        let mut utxo2 = create_test_utxo(100000, 100, false);
        
        utxo1.set_confirmed(true);
        assert_ne!(utxo1, utxo2);
        
        utxo2.set_confirmed(true);
        assert_eq!(utxo1, utxo2);
        
        utxo1.set_instantlocked(true);
        assert_ne!(utxo1, utxo2);
    }

    // Clone tests

    #[test]
    fn test_utxo_clone() {
        let mut original = create_test_utxo(100000, 100, true);
        original.set_confirmed(true);
        original.set_instantlocked(true);
        
        let cloned = original.clone();
        
        assert_eq!(original, cloned);
        assert_eq!(cloned.is_confirmed, true);
        assert_eq!(cloned.is_instantlocked, true);
        assert_eq!(cloned.is_coinbase, true);
    }

    // Debug trait tests

    #[test]
    fn test_utxo_debug() {
        let utxo = create_test_utxo(100000, 100, false);
        let debug_str = format!("{:?}", utxo);
        
        // Should contain key information
        assert!(debug_str.contains("Utxo"));
        assert!(debug_str.contains("outpoint"));
        assert!(debug_str.contains("txout"));
        assert!(debug_str.contains("address"));
        assert!(debug_str.contains("height"));
    }

    // Edge case tests

    #[test]
    fn test_utxo_zero_value() {
        let utxo = create_test_utxo(0, 100, false);
        assert_eq!(utxo.value(), Amount::ZERO);
        assert!(utxo.is_spendable(200));
    }

    #[test]
    fn test_utxo_max_value() {
        let max_value = 21_000_000 * 100_000_000; // 21 million DASH in satoshis
        let utxo = create_test_utxo(max_value, 100, false);
        assert_eq!(utxo.value(), Amount::from_sat(max_value));
    }

    #[test]
    fn test_utxo_different_address_types() {
        // Test with P2PKH address
        let p2pkh_address = create_test_address(1);
        let utxo_p2pkh = Utxo::new(
            create_test_outpoint(1, 0),
            TxOut {
                value: 100000,
                script_pubkey: p2pkh_address.script_pubkey(),
            },
            p2pkh_address.clone(),
            100,
            false,
        );
        assert_eq!(utxo_p2pkh.address, p2pkh_address);
        
        // Test with P2SH address
        use dashcore::{ScriptHash};
        let script_hash = ScriptHash::from_slice(&[2u8; 20])
            .expect("Valid 20-byte slice for script hash");
        let p2sh_script = ScriptBuf::new_p2sh(&script_hash);
        let p2sh_address = Address::from_script(&p2sh_script, Network::Testnet)
            .expect("Valid P2SH script should produce valid address");
        
        let utxo_p2sh = Utxo::new(
            create_test_outpoint(2, 0),
            TxOut {
                value: 200000,
                script_pubkey: p2sh_address.script_pubkey(),
            },
            p2sh_address.clone(),
            200,
            false,
        );
        assert_eq!(utxo_p2sh.address, p2sh_address);
    }

    // Serialization error handling tests

    #[test]
    fn test_utxo_deserialization_with_invalid_address() {
        let json = r#"{
            "outpoint": {
                "txid": "0000000000000000000000000000000000000000000000000000000000000001",
                "vout": 0
            },
            "txout": {
                "value": 100000,
                "script_pubkey": ""
            },
            "address": "invalid_address",
            "height": 100,
            "is_coinbase": false,
            "is_confirmed": false,
            "is_instantlocked": false
        }"#;
        
        let result: Result<Utxo, _> = serde_json::from_str(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid address"));
    }

    #[test]
    fn test_utxo_deserialization_with_missing_fields() {
        let json = r#"{
            "outpoint": {
                "txid": "0000000000000000000000000000000000000000000000000000000000000001",
                "vout": 0
            }
        }"#;
        
        let result: Result<Utxo, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // Real-world scenario tests

    #[test]
    fn test_utxo_consolidation_scenario() {
        // Simulate consolidating multiple small UTXOs
        let small_utxos: Vec<Utxo> = (0..10)
            .map(|i| create_test_utxo(10000 * (i + 1) as u64, 100 + i, false))
            .collect();
        
        let total_value: u64 = small_utxos.iter().map(|u| u.txout.value).sum();
        assert_eq!(total_value, 550000); // 10k + 20k + ... + 100k
        
        // All should be spendable
        assert!(small_utxos.iter().all(|u| u.is_spendable(200)));
    }

    #[test]
    fn test_utxo_dust_detection() {
        // Very small UTXO that might be considered dust
        let dust_utxo = create_test_utxo(546, 100, false); // Common dust limit
        assert_eq!(dust_utxo.value(), Amount::from_sat(546));
        assert!(dust_utxo.is_spendable(200));
    }
}