use std::ops::Range;

use dashcore::{Address, Network, OutPoint, ScriptBuf, TxOut, Txid};
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

pub fn test_utxo_range(range: Range<u64>) -> Vec<Utxo> {
    range
        .enumerate()
        .map(|(i, value)| {
            let outpoint = OutPoint {
                txid: Txid::from([value as u8; 32]),
                vout: i as u32,
            };
            let txout = TxOut {
                value: 10000,
                script_pubkey: ScriptBuf::from(vec![]),
            };
            // Create a dummy P2PKH address
            let dummy_pubkey_hash = dashcore::PubkeyHash::from([0u8; 20]);
            let script = ScriptBuf::new_p2pkh(&dummy_pubkey_hash);
            let address = Address::from_script(&script, Network::Testnet).unwrap();
            Utxo::new(outpoint, txout, address, 100, false)
        })
        .collect()
}

pub fn test_utxo_range_with_value(range: Range<u64>, value: u64, height: u32) -> Vec<Utxo> {
    range
        .map(|i| {
            let outpoint = OutPoint {
                txid: Txid::from([i as u8; 32]),
                vout: i as u32,
            };
            let txout = TxOut {
                value,
                script_pubkey: ScriptBuf::from(vec![]),
            };
            // Create a dummy P2PKH address
            let dummy_pubkey_hash = dashcore::PubkeyHash::from([0u8; 20]);
            let script = ScriptBuf::new_p2pkh(&dummy_pubkey_hash);
            let address = Address::from_script(&script, Network::Testnet).unwrap();
            Utxo::new(outpoint, txout, address, height, false)
        })
        .collect()
}
