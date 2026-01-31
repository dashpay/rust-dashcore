//! Comprehensive tests for transaction checking and management
//!
//! Tests various transaction types and checking mechanisms.

// Note: Many transaction checking tests need ManagedAccount and proper
// address pool integration. Simplified for now until the API stabilizes.

use dashcore::hashes::Hash;
use dashcore::{Address, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid};

/// Helper to create a simple P2PKH transaction
fn create_p2pkh_transaction(address: &Address) -> Transaction {
    let script_pubkey = address.script_pubkey();

    Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([1u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
        }],
        output: vec![TxOut {
            value: 100000,
            script_pubkey,
        }],
        special_transaction_payload: None,
    }
}

/// Helper to create a coinbase transaction
fn create_coinbase_transaction(address: &Address, height: u32) -> Transaction {
    let script_pubkey = address.script_pubkey();

    // Create coinbase input with height in scriptSig
    let mut script_sig = Vec::new();
    script_sig.push(0x03); // Push 3 bytes
    script_sig.extend_from_slice(&height.to_le_bytes()[0..3]); // Height as little-endian

    Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint::null(), // Coinbase has null outpoint
            script_sig: ScriptBuf::from(script_sig),
            sequence: 0xffffffff,
        }],
        output: vec![TxOut {
            value: 5000000000, // 50 DASH block reward
            script_pubkey,
        }],
        special_transaction_payload: None,
    }
}

#[test]
fn test_coinbase_detection() {
    use crate::Network;

    // Create a test address
    let address =
        Address::p2pkh(&dashcore::PublicKey::from_slice(&[0x02; 33]).unwrap(), Network::Testnet);

    // Create a coinbase transaction
    let tx = create_coinbase_transaction(&address, 100000);

    // Verify it's recognized as coinbase
    assert!(tx.is_coin_base());

    // Create a normal transaction
    let normal_tx = create_p2pkh_transaction(&address);
    assert!(!normal_tx.is_coin_base());
}

#[test]
fn test_transaction_with_multiple_outputs() {
    // Create test script pubkeys directly without needing valid public keys
    let script1 = ScriptBuf::from(vec![
        0x76, 0xa9, 0x14, // OP_DUP OP_HASH160 PUSH(20)
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, // 20 bytes of hash
        0x88, 0xac, // OP_EQUALVERIFY OP_CHECKSIG
    ]);

    let script2 = ScriptBuf::from(vec![
        0x76, 0xa9, 0x14, // OP_DUP OP_HASH160 PUSH(20)
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x22, 0x22, 0x22, // 20 bytes of hash
        0x88, 0xac, // OP_EQUALVERIFY OP_CHECKSIG
    ]);

    // Create a transaction with multiple outputs
    let tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([1u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
        }],
        output: vec![
            TxOut {
                value: 100000,
                script_pubkey: script1,
            },
            TxOut {
                value: 200000,
                script_pubkey: script2,
            },
        ],
        special_transaction_payload: None,
    };

    assert_eq!(tx.output.len(), 2);
    assert_eq!(tx.output[0].value, 100000);
    assert_eq!(tx.output[1].value, 200000);
}

// Additional transaction checking tests would require ManagedAccount integration
// which needs the full address pool and account management system to be functional
