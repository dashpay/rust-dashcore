use hashes::sha256d;

use crate::{Address, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid, Witness};

impl Transaction {
    pub fn dummy(inputs: Vec<sha256d::Hash>, value: u64) -> Transaction {
        let tx_ins = inputs
            .into_iter()
            .enumerate()
            .map(|(i, txid)| TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_raw_hash(txid),
                    vout: i as u32,
                },
                script_sig: ScriptBuf::new(),
                sequence: 0xffffffff,
                witness: Witness::new(),
            })
            .collect();

        let tx_outs = vec![TxOut {
            value,
            script_pubkey: ScriptBuf::new(),
        }];

        Transaction {
            version: 1,
            lock_time: 0,
            input: tx_ins,
            output: tx_outs,
            special_transaction_payload: None,
        }
    }

    pub fn dummy_with_address(address: Address, inputs: Vec<OutPoint>) -> Transaction {
        let mut tx_outputs = vec![];
        tx_outputs.push(TxOut {
            value: 50000,
            script_pubkey: address.script_pubkey(),
        });

        let mut tx_inputs = vec![];
        for outpoint in inputs {
            tx_inputs.push(TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: 0xffffffff,
                witness: Witness::new(),
            });
        }

        Transaction {
            version: 1,
            lock_time: 0,
            input: tx_inputs,
            output: tx_outputs,
            special_transaction_payload: None,
        }
    }
}
