//! Asset-lock transaction fixtures.

use dashcore::blockdata::transaction::special_transaction::asset_lock::AssetLockPayload;
use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::{OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid, Witness};

/// An asset lock spending a placeholder input of `seed` whose credit outputs pay `credits`, with
/// the burn output of their sum.
pub(crate) fn asset_lock_to(seed: u8, credits: &[(ScriptBuf, u64)]) -> Transaction {
    let credit_outputs: Vec<TxOut> = credits
        .iter()
        .map(|(script, value)| TxOut {
            value: *value,
            script_pubkey: script.clone(),
        })
        .collect();
    let burnt = credit_outputs.iter().map(|output| output.value).sum();
    Transaction {
        version: 3,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([seed; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: burnt,
            script_pubkey: ScriptBuf::new_op_return(&[]),
        }],
        special_transaction_payload: Some(TransactionPayload::AssetLockPayloadType(
            AssetLockPayload {
                version: 1,
                credit_outputs,
            },
        )),
    }
}
