use hashes::{Hash, sha256d};

use crate::{
    BlockHash, InstantLock, Transaction, bls_sig_utils::BLSSignature, constants::COIN_VALUE,
};

impl InstantLock {
    pub fn dummy() -> InstantLock {
        Self::dummy_with_inputs(vec![
            sha256d::Hash::hash(&[1, 2, 3]),
            sha256d::Hash::hash(&[4, 5, 6]),
            sha256d::Hash::hash(&[7, 8, 9]),
        ])
    }

    pub fn dummy_with_inputs(inputs: Vec<sha256d::Hash>) -> InstantLock {
        let tx = Transaction::dummy(inputs, COIN_VALUE);
        let inputs = tx.input.iter().map(|input| input.previous_output).collect();

        InstantLock {
            version: 1,
            inputs,
            txid: tx.txid(),
            signature: BLSSignature::from([1; 96]),
            cyclehash: BlockHash::from_byte_array([0; 32]),
        }
    }
}
