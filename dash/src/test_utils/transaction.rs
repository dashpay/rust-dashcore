use std::ops::Range;

use crate::consensus::serialize;
use crate::hash_types::MerkleRootAssetUnlocks;
use crate::transaction::special_transaction::coinbase::CoinbasePayload;
use crate::transaction::special_transaction::{TransactionPayload, TransactionType};
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

    /// This coinbase with its version 3 payload written as a version this crate does not decode,
    /// the way a later Dash Core release that appends fields would write it: the version 4
    /// fields under version 5, then 8 bytes of a field of its own. The transaction decoder keeps
    /// such a payload raw.
    pub fn with_newer_coinbase_payload(&self) -> Transaction {
        let Some(TransactionPayload::CoinbasePayloadType(payload)) =
            &self.special_transaction_payload
        else {
            panic!("a coinbase payload");
        };
        assert_eq!(payload.version, 3, "a version 3 coinbase payload");
        let mut bytes = serialize(&CoinbasePayload {
            version: 4,
            merkle_root_asset_unlocks: Some(MerkleRootAssetUnlocks::all_zeros()),
            ..payload.clone()
        });
        bytes[..2].copy_from_slice(&5u16.to_le_bytes());
        bytes.extend([0xA5; 8]);
        Transaction {
            special_transaction_payload: Some(TransactionPayload::RawPayloadType(
                TransactionType::Coinbase.to_u16(),
                bytes,
            )),
            ..self.clone()
        }
    }
}
