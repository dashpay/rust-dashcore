//! Helper functions for transaction router tests

use dashcore::blockdata::script::ScriptBuf;
use dashcore::blockdata::transaction::special_transaction::asset_lock::AssetLockPayload;
use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::blockdata::transaction::{OutPoint, Transaction};
use dashcore::hashes::Hash;
use dashcore::{TxIn, TxOut, Txid};

/// Helper function to create a test transaction with specified inputs and outputs
pub fn create_test_transaction(num_inputs: usize, outputs: Vec<u64>) -> Transaction {
    let inputs = (0..num_inputs)
        .map(|i| TxIn {
            previous_output: OutPoint {
                txid: Txid::from_slice(&[i as u8; 32]).unwrap(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
        })
        .collect();

    let outputs = outputs
        .into_iter()
        .map(|value| TxOut {
            value,
            script_pubkey: ScriptBuf::new(),
        })
        .collect();

    Transaction {
        version: 2,
        lock_time: 0,
        input: inputs,
        output: outputs,
        special_transaction_payload: None,
    }
}

/// Helper to create an asset lock transaction (used for identity operations)
pub fn create_asset_lock_transaction(inputs: usize, output_value: u64) -> Transaction {
    let mut tx = create_test_transaction(inputs, vec![output_value]);
    // Create a simple asset lock payload with one credit output
    let credit_output = TxOut {
        value: output_value,
        script_pubkey: ScriptBuf::new(),
    };
    let payload = AssetLockPayload {
        version: 1,
        credit_outputs: vec![credit_output],
    };
    tx.special_transaction_payload = Some(TransactionPayload::AssetLockPayloadType(payload));
    tx
}
