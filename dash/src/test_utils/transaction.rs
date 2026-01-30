use std::ops::Range;

use crate::{Address, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid};

impl Transaction {
    pub fn dummy(
        address: &Address,
        inputs_ids_range: Range<u8>,
        outputs_values: &[u64],
    ) -> Transaction {
        let inputs = inputs_ids_range
            .enumerate()
            .map(|(i, id)| {
                let mut txid_bytes = [id; 32];
                txid_bytes[0] = 1; // This ensures that the txid is not all zeros

                TxIn {
                    previous_output: OutPoint::new(Txid::from(txid_bytes), i as u32),
                    script_sig: address.script_pubkey(),
                    sequence: 0xffffffff,
                }
            })
            .collect();

        let outputs = outputs_values
            .iter()
            .map(|&value| TxOut {
                value,
                script_pubkey: address.script_pubkey(),
            })
            .collect();

        Transaction {
            version: 1,
            lock_time: 0,
            input: inputs,
            output: outputs,
            special_transaction_payload: None,
        }
    }

    pub fn dummy_coinbase(address: &Address, value: u64) -> Transaction {
        let inputs = vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
        }];

        let outputs = vec![TxOut {
            value,
            script_pubkey: address.script_pubkey(),
        }];

        Transaction {
            version: 1,
            lock_time: 0,
            input: inputs,
            output: outputs,
            special_transaction_payload: None,
        }
    }
}
