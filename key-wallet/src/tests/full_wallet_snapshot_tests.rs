//! Full-wallet snapshots preserve spend state through restart and continued sync.

use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::transaction_checking::{BlockInfo, TransactionContext, WalletTransactionChecker};
use crate::wallet::initialization::WalletAccountCreationOptions;
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::wallet::ManagedWalletInfo;
use crate::Wallet;
use dashcore::hashes::Hash;
use dashcore::{
    Address, BlockHash, ChainLock, InstantLock, Network, OutPoint, Transaction, TxIn, TxOut,
};

fn wallet() -> (Wallet, ManagedWalletInfo, Address) {
    let wallet =
        Wallet::from_seed_bytes([42; 64], Network::Testnet, WalletAccountCreationOptions::Default)
            .unwrap();
    let mut info = ManagedWalletInfo::from_wallet(&wallet, 0);
    let xpub = wallet.accounts.standard_bip44_accounts.get(&0).unwrap().account_xpub;
    let address = info
        .first_bip44_managed_account_mut()
        .unwrap()
        .next_receive_address(Some(&xpub), true)
        .unwrap();
    (wallet, info, address)
}

fn restart(info: &ManagedWalletInfo) -> ManagedWalletInfo {
    let bytes = bincode::serde::encode_to_vec(info, bincode::config::standard()).unwrap();
    let (restored, consumed) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(consumed, bytes.len());
    restored
}

fn block(height: u32) -> TransactionContext {
    TransactionContext::InBlock(BlockInfo::new(height, BlockHash::from_byte_array([7; 32]), 1000))
}

fn chain_lock() -> ChainLock {
    ChainLock {
        block_height: 200,
        block_hash: BlockHash::from_byte_array([8; 32]),
        signature: [0; 96].into(),
    }
}

fn spend(parent: OutPoint) -> Transaction {
    Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: parent,
            ..Default::default()
        }],
        output: vec![TxOut {
            value: 99_000,
            script_pubkey: Default::default(),
        }],
        special_transaction_payload: None,
    }
}

#[test_case::test_case(false, false; "pending")]
#[test_case::test_case(true, false; "mined")]
#[test_case::test_case(true, true; "chainlocked_and_pruned")]
#[tokio::test]
async fn full_snapshot_keeps_spent_funding_unavailable(mined: bool, finalized: bool) {
    let (mut wallet, mut info, address) = wallet();
    let funding = Transaction::dummy(&address, 0..1, &[100_000]);
    let parent = OutPoint::new(funding.txid(), 0);
    let spending = spend(parent);
    info.check_core_transaction(&funding, block(120), &mut wallet, true, true).await;
    assert!(info.first_bip44_managed_account().unwrap().utxos.contains_key(&parent));
    let context = if mined {
        block(150)
    } else {
        TransactionContext::Mempool
    };
    info.check_core_transaction(&spending, context, &mut wallet, true, true).await;
    if finalized {
        info.apply_chain_lock(chain_lock());
        info.update_synced_height(200);
    }
    assert!(info.first_bip44_managed_account().unwrap().utxos.is_empty());
    let mut restored = restart(&info);
    assert_eq!(restored.balance, info.balance);
    for context in [TransactionContext::Mempool, block(120)] {
        restored.check_core_transaction(&funding, context, &mut wallet, true, true).await;
        assert!(restored.first_bip44_managed_account().unwrap().utxos.is_empty());
        assert_eq!(restored.balance, info.balance);
    }
    if !mined {
        restored.abandon_transaction(spending.txid());
        restored.check_core_transaction(&funding, block(120), &mut wallet, true, true).await;
        assert!(restored.first_bip44_managed_account().unwrap().utxos.contains_key(&parent));
    }
}

#[test_case::test_case(false; "mined")]
#[test_case::test_case(true; "chainlocked")]
#[tokio::test]
async fn full_snapshot_keeps_spend_before_funding_evidence(finalized: bool) {
    let (mut wallet, mut info, address) = wallet();
    let funding = Transaction::dummy(&address, 0..1, &[100_000]);
    let parent = OutPoint::new(funding.txid(), 0);
    let spending = spend(parent);
    info.check_core_transaction(&spending, block(150), &mut wallet, true, true).await;
    info.update_synced_height(100);
    if finalized {
        info.apply_chain_lock(chain_lock());
    }
    let mut restored = restart(&info);
    assert_eq!(restored.observed_spent_outpoints().get(&parent), Some(&150));
    restored.check_core_transaction(&funding, block(120), &mut wallet, true, true).await;
    restored.apply_chain_lock(chain_lock());
    restored.update_synced_height(200);
    restored = restart(&restored);
    restored.check_core_transaction(&funding, block(120), &mut wallet, true, true).await;
    assert!(restored.first_bip44_managed_account().unwrap().utxos.is_empty());
    assert_eq!(restored.balance, info.balance);
}

#[tokio::test]
async fn full_snapshot_preserves_instant_send_until_block_confirmation() {
    let (mut wallet, mut info, address) = wallet();
    let funding = Transaction::dummy(&address, 0..1, &[100_000]);
    let parent = OutPoint::new(funding.txid(), 0);
    let mut spending = spend(parent);
    spending.output[0].script_pubkey = address.script_pubkey();
    info.check_core_transaction(&funding, block(120), &mut wallet, true, true).await;
    let lock = InstantLock {
        txid: spending.txid(),
        ..Default::default()
    };
    info.check_core_transaction(
        &spending,
        TransactionContext::InstantSend(lock.clone()),
        &mut wallet,
        true,
        true,
    )
    .await;
    let mut restored = restart(&info);
    assert_eq!(restored.balance.confirmed(), 99_000);
    assert_eq!(
        restored.first_bip44_managed_account().unwrap().transactions()[&spending.txid()].context,
        TransactionContext::InstantSend(lock)
    );
    restored.check_core_transaction(&spending, block(150), &mut wallet, true, true).await;
    restored.apply_chain_lock(chain_lock());
    restored.update_synced_height(200);
    restored = restart(&restored);
    restored.check_core_transaction(&funding, block(120), &mut wallet, true, true).await;
    assert_eq!(restored.balance.confirmed(), 99_000);
    assert!(!restored.first_bip44_managed_account().unwrap().utxos.contains_key(&parent));
}

#[tokio::test]
async fn full_snapshot_preserves_pending_conflict_cleanup() {
    let (mut wallet, mut info, address) = wallet();
    let funding = Transaction::dummy(&address, 0..1, &[100_000]);
    let parent = OutPoint::new(funding.txid(), 0);
    let mut pending = spend(parent);
    pending.output[0].script_pubkey = address.script_pubkey();
    info.check_core_transaction(&funding, block(120), &mut wallet, true, true).await;
    info.check_core_transaction(&pending, TransactionContext::Mempool, &mut wallet, true, true)
        .await;
    let mut restored = restart(&info);
    assert_eq!(restored.balance.spendable(), 99_000);
    restored.check_core_transaction(&spend(parent), block(150), &mut wallet, true, true).await;
    let account = restored.first_bip44_managed_account().unwrap();
    assert!(!account.transactions().contains_key(&pending.txid()));
    assert!(account.utxos.is_empty());
    assert_eq!(restored.balance.spendable(), 0);
    restored = restart(&restored);
    restored.check_core_transaction(&funding, block(120), &mut wallet, true, true).await;
    assert!(restored.first_bip44_managed_account().unwrap().utxos.is_empty());
    assert_eq!(restored.balance.spendable(), 0);
}
