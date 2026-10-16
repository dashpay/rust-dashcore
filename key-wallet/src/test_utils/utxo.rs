use std::ops::Range;

use dashcore::{Address, Network, OutPoint, TxOut, Txid};

use crate::Utxo;

impl Utxo {
    pub fn dummy(id: u8, value: u64, height: u32, coinbase: bool, confirmed: bool) -> Self {
        Self::dummy_batch(id..id + 1, value, height, coinbase, confirmed).remove(0)
    }

    pub fn dummy_batch(
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

                let address = Address::dummy(Network::Testnet, id as usize);
                // The script the address pays to, so a dummy is a real P2PKH
                // output (asset-lock builds refuse anything else).
                let txout = TxOut {
                    value,
                    script_pubkey: address.script_pubkey(),
                };

                let mut utxo = Utxo::new(outpoint, txout, address, height, coinbase);
                utxo.is_confirmed = confirmed;
                utxo
            })
            .collect()
    }
}
