use hashes::sha256d;

use crate::{OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid, Witness};

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
            version: 2,
            lock_time: 0,
            input: tx_ins,
            output: tx_outs,
            special_transaction_payload: None,
        }
    }
}
