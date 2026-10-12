//! `WalletInfoInterface::truncate_above`: what a fork drops from the wallet and
//! what it gives back.

use dashcore::blockdata::script::ScriptBuf;
use dashcore::ephemerealdata::chain_lock::ChainLock;
use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::hashes::Hash;
use dashcore::{BlockHash, OutPoint, Transaction, TxIn, TxOut};
use test_case::test_case;

use crate::account::ManagedAccountTrait;
use crate::test_utils::TestWalletContext;
use crate::transaction_checking::{BlockInfo, TransactionContext};
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::Error;

const FUNDING_VALUE: u64 = 1_000_000;

fn in_block(height: u32) -> BlockInfo {
    BlockInfo::new(height, BlockHash::from_byte_array([height as u8; 32]), 1_650_000_000 + height)
}

fn spend_to_external(funding: &Transaction) -> Transaction {
    let external = dashcore::Address::p2pkh(
        &dashcore::PublicKey::from_slice(&[0x02; 33]).expect("pubkey"),
        dashcore::Network::Testnet,
    );
    Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint::new(funding.txid(), 0),
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: dashcore::Witness::new(),
        }],
        output: vec![TxOut {
            value: FUNDING_VALUE - 1_000,
            script_pubkey: external.script_pubkey(),
        }],
        special_transaction_payload: None,
    }
}

/// Funds the wallet at `fund_ctx` and spends the coin in a block at 101.
async fn fund_and_spend(
    fund_ctx: TransactionContext,
) -> (TestWalletContext, Transaction, Transaction) {
    let mut ctx = TestWalletContext::new_random();
    let funding = Transaction::dummy(&ctx.receive_address, 0..1, &[FUNDING_VALUE]);
    let spend = spend_to_external(&funding);
    assert!(ctx.check_transaction(&funding, fund_ctx).await.is_relevant);
    assert!(
        ctx.check_transaction(&spend, TransactionContext::InBlock(in_block(101))).await.is_relevant
    );
    assert_eq!(ctx.managed_wallet.balance.total(), 0);
    (ctx, funding, spend)
}

#[tokio::test]
async fn truncate_above_restores_a_coin_from_a_chainlocked_funding() {
    let (mut ctx, funding, _spend) =
        fund_and_spend(TransactionContext::InChainLockedBlock(in_block(100))).await;

    let truncation = ctx.managed_wallet.truncate_above(100).expect("truncates");

    assert_eq!(truncation.restored_outpoints, vec![OutPoint::new(funding.txid(), 0)]);
    assert_eq!(ctx.managed_wallet.balance.confirmed(), FUNDING_VALUE);
}

#[tokio::test]
async fn truncate_above_restores_nothing_the_fork_drops_too() {
    let (mut ctx, funding, spend) =
        fund_and_spend(TransactionContext::InBlock(in_block(100))).await;

    let truncation = ctx.managed_wallet.truncate_above(99).expect("truncates");

    assert_eq!(truncation.txids.len(), 2);
    assert!(truncation.txids.contains(&funding.txid()));
    assert!(truncation.txids.contains(&spend.txid()));
    assert!(truncation.restored_outpoints.is_empty());
    assert!(ctx.bip44_account().utxos.is_empty());
    assert_eq!(ctx.managed_wallet.balance.total(), 0);
}

#[test_case(99, false; "below the ChainLock")]
#[test_case(100, true; "at the ChainLock")]
#[tokio::test]
async fn truncate_above_never_drops_a_chain_locked_block(height: u32, truncates: bool) {
    let (mut ctx, _funding, spend) =
        fund_and_spend(TransactionContext::InBlock(in_block(100))).await;
    ctx.managed_wallet.update_synced_height(101);
    ctx.managed_wallet.metadata.last_applied_chain_lock = Some(ChainLock::dummy(100));

    let result = ctx.managed_wallet.truncate_above(height);

    if truncates {
        assert_eq!(result.expect("truncates").txids, vec![spend.txid()]);
        assert_eq!(ctx.managed_wallet.synced_height(), height);
    } else {
        assert_eq!(
            result.expect_err("refuses"),
            Error::TruncateBelowChainLock {
                height,
                chain_locked: 100,
            }
        );
        assert_eq!(ctx.bip44_account().transactions().len(), 2, "nothing is dropped");
        assert_eq!(ctx.managed_wallet.synced_height(), 101);
    }
}

/// A spend that reaches a chainlocked block after the mempool is final, so
/// nothing is kept to give its coins back.
#[tokio::test]
async fn a_mempool_spend_mined_in_a_chain_locked_block_is_settled() {
    let mut ctx = TestWalletContext::new_random();
    let funding = Transaction::dummy(&ctx.receive_address, 0..1, &[FUNDING_VALUE]);
    let spend = spend_to_external(&funding);
    assert!(
        ctx.check_transaction(&funding, TransactionContext::InBlock(in_block(100)))
            .await
            .is_relevant
    );
    assert!(ctx.check_transaction(&spend, TransactionContext::Mempool).await.is_relevant);
    assert!(ctx.bip44_account().unsettled_spends().contains_key(&spend.txid()));

    ctx.check_transaction(&spend, TransactionContext::InChainLockedBlock(in_block(101))).await;

    assert!(ctx.bip44_account().unsettled_spends().is_empty());
}

/// An InstantSend-locked spend is final for its txid and the network mines it
/// again, so a fork dropping its block keeps it as unconfirmed: the coin it
/// spent is not handed back for coin selection, and its change stays.
#[test_case(true; "InstantSend-locked")]
#[test_case(false; "not locked")]
#[tokio::test]
async fn truncate_above_keeps_an_instant_locked_spend_unconfirmed(instant_locked: bool) {
    const CHANGE_VALUE: u64 = 400_000;
    let mut ctx = TestWalletContext::new_random();
    let funding = Transaction::dummy(&ctx.receive_address, 0..1, &[FUNDING_VALUE]);
    let mut spend = spend_to_external(&funding);
    spend.output[0].value -= CHANGE_VALUE;
    spend.output.push(TxOut {
        value: CHANGE_VALUE,
        script_pubkey: ctx.receive_address.script_pubkey(),
    });
    let funding_outpoint = OutPoint::new(funding.txid(), 0);
    let change_outpoint = OutPoint::new(spend.txid(), 1);
    assert!(
        ctx.check_transaction(&funding, TransactionContext::InBlock(in_block(100)))
            .await
            .is_relevant
    );
    if instant_locked {
        let lock = InstantLock {
            txid: spend.txid(),
            ..InstantLock::dummy(0..1)
        };
        ctx.check_transaction(&spend, TransactionContext::InstantSend(lock)).await;
    }
    ctx.check_transaction(&spend, TransactionContext::InBlock(in_block(101))).await;

    let truncation = ctx.managed_wallet.truncate_above(100).expect("truncates");

    let account = ctx.bip44_account();
    if instant_locked {
        assert!(truncation.txids.is_empty());
        assert_eq!(truncation.unconfirmed_txids, vec![spend.txid()]);
        assert!(truncation.restored_outpoints.is_empty());
        assert!(!account.utxos.contains_key(&funding_outpoint), "the spent coin stays spent");
        let record = &account.transactions()[&spend.txid()];
        assert!(matches!(record.context, TransactionContext::Mempool));
        let change = &account.utxos[&change_outpoint];
        assert!(change.is_instantlocked && !change.is_confirmed);

        // Mined again on the new branch, it confirms as any mempool transaction.
        ctx.check_transaction(&spend, TransactionContext::InBlock(in_block(102))).await;
        let account = ctx.bip44_account();
        assert_eq!(account.transactions()[&spend.txid()].height(), Some(102));
        assert!(account.utxos[&change_outpoint].is_confirmed);
    } else {
        assert_eq!(truncation.txids, vec![spend.txid()]);
        assert!(truncation.unconfirmed_txids.is_empty());
        assert_eq!(truncation.restored_outpoints, vec![funding_outpoint]);
        assert!(!account.utxos.contains_key(&change_outpoint));
    }
}
