use std::ops::Range;

use dashcore::{OutPoint, ScriptBuf, TxOut, Txid};

use crate::{test_utils::test_address, Utxo};

impl Utxo {
    pub fn new_test(id: u8, value: u64, height: u32, confirmed: bool) -> Self {
        Self::new_test_batch(id..id + 1, value, height, confirmed).remove(0)
    }

    pub fn new_test_batch(
        ids_range: Range<u8>,
        value: u64,
        height: u32,
        confirmed: bool,
    ) -> Vec<Self> {
        ids_range
            .enumerate()
            .map(|(i, id)| {
                let outpoint = OutPoint::new(Txid::from([id; 32]), i as u32);

                let txout = TxOut {
                    value,
                    script_pubkey: ScriptBuf::new(),
                };

                let mut utxo = Utxo::new(outpoint, txout, test_address(), height, false);
                utxo.is_confirmed = confirmed;
                utxo
            })
            .collect()
    }
}
