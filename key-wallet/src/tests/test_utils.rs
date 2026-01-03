//! Test utilities for key-wallet tests

use crate::utxo::Utxo;
use crate::Network;
use dashcore::blockdata::transaction::txout::TxOut;
use dashcore::blockdata::transaction::OutPoint;
use dashcore::hashes::Hash;
use dashcore::{Address, ScriptBuf, Txid};
use dashcore_hashes::sha256d;

const TEST_PUBKEY_BYTES: [u8; 33] = [
    0x02, 0x50, 0x86, 0x3a, 0xd6, 0x4a, 0x87, 0xae, 0x8a, 0x2f, 0xe8, 0x3c, 0x1a, 0xf1, 0xa8, 0x40,
    0x3c, 0xb5, 0x3f, 0x53, 0xe4, 0x86, 0xd8, 0x51, 0x1d, 0xad, 0x8a, 0x04, 0x88, 0x7e, 0x5b, 0x23,
    0x52,
];

pub fn test_address() -> Address {
    Address::p2pkh(&dashcore::PublicKey::from_slice(&TEST_PUBKEY_BYTES).unwrap(), Network::Testnet)
}

pub fn test_utxo(value: u64) -> Utxo {
    test_utxo_full(value, 100, 0, true)
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
