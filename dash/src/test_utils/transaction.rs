use std::ops::Range;

use hashes::Hash;

use crate::hash_types::{MerkleRootMasternodeList, MerkleRootQuorums};
use crate::transaction::special_transaction::coinbase::CoinbasePayload;
use crate::{Address, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid, Witness};

/// A special transaction type no Dash Core version assigns
pub const UNASSIGNED_SPECIAL_TX_TYPE: u16 = 0xffff;

impl Transaction {
    /// Creates a transaction with no inputs or outputs.
    pub fn dummy_empty() -> Transaction {
        Transaction {
            version: 1,
            lock_time: 0,
            input: Vec::new(),
            output: Vec::new(),
            special_transaction_payload: None,
        }
    }

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
                    witness: Witness::new(),
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
            witness: Witness::new(),
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

impl CoinbasePayload {
    /// A current version payload at `height` committing to empty lists.
    pub fn dummy(height: u32) -> Self {
        CoinbasePayload {
            version: CoinbasePayload::CURRENT_VERSION,
            height,
            merkle_root_masternode_list: MerkleRootMasternodeList::all_zeros(),
            merkle_root_quorums: MerkleRootQuorums::all_zeros(),
            best_cl_height: None,
            best_cl_signature: None,
            asset_locked_amount: None,
            merkle_root_asset_unlocks: None,
        }
    }
}
