//! Helper functions for transaction router tests

use dashcore::blockdata::transaction::special_transaction::asset_lock::AssetLockPayload;
use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::blockdata::transaction::Transaction;
use dashcore::{Address, Network, TxOut};

/// Returns a deterministic test address for creating dummy transactions.
pub fn test_addr() -> Address {
    Address::dummy(Network::Regtest, 0)
}

/// Helper to create an asset lock transaction (used for identity operations)
pub fn create_asset_lock_transaction(inputs: usize, output_value: u64) -> Transaction {
    let addr = test_addr();
    let mut tx = Transaction::dummy(&addr, 0..inputs as u8, &[output_value]);
    let credit_output = TxOut {
        value: output_value,
        script_pubkey: addr.script_pubkey(),
    };
    let payload = AssetLockPayload {
        version: 1,
        credit_outputs: vec![credit_output],
    };
    tx.special_transaction_payload = Some(TransactionPayload::AssetLockPayloadType(payload));
    tx
}
