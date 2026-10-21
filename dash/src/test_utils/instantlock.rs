use std::ops::Range;

use crate::{
    Address, BlockHash, InstantLock, Transaction, bls_sig_utils::BLSSignature,
    constants::COIN_VALUE,
};

impl InstantLock {
    pub fn dummy(transaction_input_ids: Range<u8>) -> InstantLock {
        let address = Address::dummy(crate::Network::Testnet, 0);
        let tx = Transaction::dummy(&address, transaction_input_ids, &[COIN_VALUE]);
        let inputs = tx.input.iter().map(|input| input.previous_output).collect();

        InstantLock {
            version: 1,
            inputs,
            txid: tx.txid(),
            signature: BLSSignature::from([1; 96]),
            cyclehash: BlockHash::dummy(0),
        }
    }
}
