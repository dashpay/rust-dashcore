use std::ops::Range;

use dashcore::{Address, OutPoint, ScriptBuf, TxOut, Txid};

use crate::Utxo;

impl Utxo {
    pub fn new_test(id: u8, value: u64, height: u32, coinbase: bool, confirmed: bool) -> Self {
        Self::new_test_batch(id..id + 1, value, height, coinbase, confirmed).remove(0)
    }

    pub fn new_test_batch(
        ids_range: Range<u8>,
        value: u64,
        height: u32,
        coinbase: bool,
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

                let mut utxo =
                    Utxo::new(outpoint, txout, Address::test_address(), height, coinbase);
                utxo.is_confirmed = confirmed;
                utxo
            })
            .collect()
    }
}
