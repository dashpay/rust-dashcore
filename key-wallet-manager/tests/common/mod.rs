//! Shared helpers for the observed-spent-outpoint guard integration tests
//! (dashpay/rust-dashcore#649).
//!
//! Each test binary pulls this in via `mod common;` and uses a subset of the
//! helpers, so unused-item warnings are expected per binary and silenced here.
#![allow(dead_code)]

use dashcore::blockdata::block::Block;
use dashcore::blockdata::transaction::OutPoint;
use dashcore::{Address, ScriptBuf, Transaction, TxIn, TxOut, Witness};
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::{WalletId, WalletInterface, WalletManager};
use std::collections::BTreeSet;

/// Deliver `block` at `height` to the given `wallets`.
pub async fn process_block_for(
    manager: &mut WalletManager<ManagedWalletInfo>,
    block: &Block,
    height: u32,
    wallets: &BTreeSet<WalletId>,
) {
    manager.process_block_for_wallets(block, block.block_hash(), height, wallets).await;
}

/// Deliver `block` at `height` to every wallet the manager holds.
pub async fn process_block_all_wallets(
    manager: &mut WalletManager<ManagedWalletInfo>,
    block: &Block,
    height: u32,
) {
    let wallet_ids: BTreeSet<WalletId> = manager.list_wallets().into_iter().copied().collect();
    process_block_for(manager, block, height, &wallet_ids).await;
}

/// A transaction paying `value` to `address` from one synthetic, unrelated
/// input (`input_seed` makes its txid deterministic and distinct). Only the
/// transaction's own txid/vout matter to the tests, as the coin later spent.
pub fn funding_tx(address: &Address, value: u64, input_seed: u8) -> Transaction {
    Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint::new(dashcore::Txid::from([input_seed; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value,
            script_pubkey: address.script_pubkey(),
        }],
        special_transaction_payload: None,
    }
}

/// A transaction spending `outpoint` and paying `value` to an unrelated
/// external payee (`ext_id` selects a distinct script).
///
/// The payee script is built directly (a P2PKH shape seeded by `ext_id`) rather
/// than via `Address::dummy`, so the helper needs no `Network`: the
/// observed-spend logic keys on the input outpoint, never on the payee, so the
/// payee's network is irrelevant to every scenario here. `Transaction::dummy`
/// does not fit this helper — it derives its inputs from an id range and cannot
/// spend a caller-specified `outpoint`, which is the whole point of a spend.
pub fn spend_tx(outpoint: OutPoint, value: u64, ext_id: usize) -> Transaction {
    // OP_DUP OP_HASH160 <20-byte push> OP_EQUALVERIFY OP_CHECKSIG — a well-formed
    // P2PKH scriptPubKey whose hash160 is seeded by `ext_id` so each payee is
    // distinct and never collides with a wallet-owned script.
    let mut payee = vec![0x76, 0xa9, 0x14];
    payee.extend_from_slice(&[ext_id as u8; 20]);
    payee.extend_from_slice(&[0x88, 0xac]);
    Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value,
            script_pubkey: ScriptBuf::from_bytes(payee),
        }],
        special_transaction_payload: None,
    }
}
