//! Tests for the forward-scan query pruning of spent single-use (CoinJoin)
//! addresses (dashpay/rust-dashcore#948).
//!
//! `scan_script_pubkeys` must drop CoinJoin addresses that are used and hold
//! no unspent output, while keeping unused (gap-window) CoinJoin addresses,
//! used CoinJoin addresses that still hold a UTXO, and every address of every
//! other account type — used or not.

use crate::account::ManagedAccountTrait;
use crate::wallet::initialization::WalletAccountCreationOptions;
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::wallet::{ManagedWalletInfo, Wallet};
use crate::{Network, Utxo};
use dashcore::blockdata::transaction::txout::TxOut;
use dashcore::hashes::Hash;
use dashcore::{Address, OutPoint, ScriptBuf, Txid};

/// Known test mnemonic for deterministic testing
const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn setup_wallet_info() -> ManagedWalletInfo {
    let mnemonic = crate::mnemonic::Mnemonic::from_phrase(TEST_MNEMONIC).unwrap();
    let wallet =
        Wallet::from_mnemonic(mnemonic, Network::Testnet, WalletAccountCreationOptions::Default)
            .unwrap();
    ManagedWalletInfo::from_wallet(&wallet, 0)
}

fn dummy_utxo_for(address: &Address, salt: u8) -> Utxo {
    Utxo::new(
        OutPoint::new(Txid::from_byte_array([salt; 32]), 0),
        TxOut {
            value: 100_000,
            script_pubkey: address.script_pubkey(),
        },
        address.clone(),
        100,
        false,
    )
}

#[test]
fn test_scan_set_prunes_spent_and_empty_coinjoin_addresses() {
    let mut info = setup_wallet_info();

    let coinjoin = info.accounts.coinjoin_accounts.get_mut(&0).expect("CoinJoin account 0");
    let addresses = coinjoin.all_addresses();
    assert!(addresses.len() >= 2, "CoinJoin pools should pre-generate addresses");

    // Address 0: used, all outputs spent (no UTXO left) — must be pruned.
    let spent_addr = addresses[0].clone();
    // Address 1: used, but still holds an unspent output — must be kept.
    let funded_addr = addresses[1].clone();

    assert!(coinjoin.mark_address_used(&spent_addr));
    assert!(coinjoin.mark_address_used(&funded_addr));
    let utxo = dummy_utxo_for(&funded_addr, 0xaa);
    coinjoin.utxos.insert(utxo.outpoint, utxo);

    let monitored = info.monitored_script_pubkeys();
    let scan = info.scan_script_pubkeys();

    let spent_script = spent_addr.script_pubkey();
    let funded_script = funded_addr.script_pubkey();

    assert!(monitored.contains(&spent_script), "monitored set keeps the spent address");
    assert!(!scan.contains(&spent_script), "scan set drops the spent-and-empty address");
    assert!(scan.contains(&funded_script), "scan set keeps the address still holding a UTXO");

    // Exactly one script was pruned; every unused gap-window address stays.
    assert_eq!(scan.len(), monitored.len() - 1);
}

#[test]
fn test_scan_set_keeps_used_and_empty_standard_addresses() {
    let mut info = setup_wallet_info();

    let standard =
        info.accounts.standard_bip44_accounts.get_mut(&0).expect("standard BIP44 account 0");
    let addr = standard.all_addresses().first().cloned().expect("pre-generated address");
    // Used with no remaining UTXO: a standard address can always be paid
    // again, so the scan set must keep watching it.
    assert!(standard.mark_address_used(&addr));

    let scan = info.scan_script_pubkeys();
    assert!(
        scan.contains(&addr.script_pubkey()),
        "used-and-empty standard addresses stay in the scan set"
    );
    assert_eq!(scan.len(), info.monitored_script_pubkeys().len());
}

#[test]
fn test_unspent_or_unused_script_pubkeys_on_funds_account() {
    let mut info = setup_wallet_info();
    let coinjoin = info.accounts.coinjoin_accounts.get_mut(&0).expect("CoinJoin account 0");

    let all: Vec<ScriptBuf> = coinjoin.all_script_pubkeys();
    // Untouched account: nothing is used, so nothing is pruned.
    assert_eq!(coinjoin.unspent_or_unused_script_pubkeys().len(), all.len());

    // Mark one address used without a UTXO: it drops out.
    let addr = coinjoin.all_addresses()[0].clone();
    assert!(coinjoin.mark_address_used(&addr));
    let pruned = coinjoin.unspent_or_unused_script_pubkeys();
    assert_eq!(pruned.len(), all.len() - 1);
    assert!(!pruned.contains(&addr.script_pubkey()));

    // Give it back an unspent output: it returns to the scan set.
    let utxo = dummy_utxo_for(&addr, 0xbb);
    coinjoin.utxos.insert(utxo.outpoint, utxo);
    let restored = coinjoin.unspent_or_unused_script_pubkeys();
    assert_eq!(restored.len(), all.len());
    assert!(restored.contains(&addr.script_pubkey()));
}
