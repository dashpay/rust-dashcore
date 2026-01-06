use dashcore::{OutPoint, ScriptBuf, TxOut, Txid};
use dashcore_hashes::{sha256d, Hash};

use crate::{test_utils::test_address, Utxo};

pub fn test_utxo(value: u64) -> Utxo {
    test_utxo_full(value, 100, 0, true)
}

pub fn test_utxo2(value: u64, confirmed: bool) -> Utxo {
    let outpoint = OutPoint {
        txid: Txid::from_raw_hash(sha256d::Hash::from_slice(&[1u8; 32]).unwrap()),
        vout: 0,
    };

    let txout = TxOut {
        value,
        script_pubkey: ScriptBuf::new(),
    };

    let mut utxo = Utxo::new(outpoint, txout, test_address(), 100, false);
    utxo.is_confirmed = confirmed;
    utxo
}

pub fn test_utxo_full(value: u64, height: u32, vout: u32, confirmed: bool) -> Utxo {
    let outpoint = OutPoint {
        txid: Txid::from_raw_hash(sha256d::Hash::from_slice(&[1u8; 32]).unwrap()),
        vout,
    };

    let txout = TxOut {
        value,
        script_pubkey: ScriptBuf::new(),
    };

    let mut utxo = Utxo::new(outpoint, txout, test_address(), height, false);
    utxo.is_confirmed = confirmed;
    utxo
}
