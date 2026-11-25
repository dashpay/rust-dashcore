//! A conflict sweep credits again a coin only the removed loser spent, as it
//! was, and once; a coin the winner spends, or another recorded spend
//! still takes, stays spent.

use dashcore::blockdata::script::ScriptBuf;
use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::{Address, BlockHash, OutPoint, Transaction, TxIn, TxOut};

use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::test_utils::TestWalletContext;
use crate::transaction_checking::{BlockInfo, TransactionContext};
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;

const A: u64 = 500_000;
const B: u64 = 400_000;

fn block_info(height: u32) -> BlockInfo {
    BlockInfo::new(height, BlockHash::from_byte_array([height as u8; 32]), 1_650_000_000 + height)
}

fn elsewhere() -> ScriptBuf {
    Address::p2pkh(
        &dashcore::PublicKey::from_slice(&[0x02; 33]).expect("pubkey"),
        dashcore::Network::Testnet,
    )
    .script_pubkey()
}

fn spend(inputs: &[OutPoint], value: u64) -> Transaction {
    Transaction {
        version: 2,
        lock_time: value as u32,
        input: inputs
            .iter()
            .map(|previous_output| TxIn {
                previous_output: *previous_output,
                ..Default::default()
            })
            .collect(),
        output: vec![TxOut {
            value,
            script_pubkey: elsewhere(),
        }],
        special_transaction_payload: None,
    }
}

/// A wallet whose receive address a mined funding transaction pays twice,
/// A and B, and that funding.
async fn funded() -> (TestWalletContext, Transaction, OutPoint, OutPoint) {
    let mut ctx = TestWalletContext::new_random();
    let funding = Transaction::dummy(&ctx.receive_address, 0..2, &[A, B]);
    ctx.check_transaction(&funding, TransactionContext::InBlock(block_info(100))).await;
    assert_eq!(ctx.managed_wallet.balance.confirmed(), A + B);
    let (a, b) = (OutPoint::new(funding.txid(), 0), OutPoint::new(funding.txid(), 1));
    (ctx, funding, a, b)
}

#[tokio::test]
async fn a_locked_loser_beaten_by_a_chain_locked_winner_gives_back_only_its_other_coin() {
    let (mut ctx, funding, a, b) = funded().await;
    let loser = spend(&[a, b], A + B - 1_000);
    let lock = InstantLock {
        txid: loser.txid(),
        inputs: vec![a, b],
        ..InstantLock::default()
    };
    ctx.check_transaction(&loser, TransactionContext::InstantSend(lock)).await;
    assert_eq!(ctx.managed_wallet.balance.total(), 0);

    let winner = spend(&[a], A - 1_000);
    let result = ctx
        .check_transaction(&winner, TransactionContext::InChainLockedBlock(block_info(101)))
        .await;
    assert_eq!(result.swept_transactions, vec![loser.txid()]);
    assert_eq!(result.released_outpoints, vec![b]);
    let account = ctx.bip44_account();
    assert!(!account.utxos.contains_key(&a), "the winner spends A");
    let restored = account.utxos.get(&b).expect("only the loser spent B");
    assert!(restored.is_confirmed);
    assert_eq!(restored.txout.value, B);
    assert_eq!(ctx.managed_wallet.balance.total(), B);

    ctx.check_transaction(&funding, TransactionContext::InBlock(block_info(100))).await;
    assert!(!ctx.bip44_account().utxos.contains_key(&a), "a rescan does not bring A back");
    assert_eq!(ctx.managed_wallet.balance.total(), B, "B is counted once");
}

#[tokio::test]
async fn a_coin_another_recorded_spend_takes_stays_spent_when_a_loser_is_swept() {
    let (mut ctx, funding, a, b) = funded().await;
    let loser = ctx.signed(spend(&[a, b], A + B - 1_000), &[&funding]).await;
    ctx.check_transaction(&loser, TransactionContext::Mempool).await;
    let change = change_address(&mut ctx);
    let mut other = spend(&[b], 100_000);
    other.output.push(TxOut {
        value: B - 101_000,
        script_pubkey: change.script_pubkey(),
    });
    let other = ctx.signed(other, &[&funding]).await;
    ctx.check_transaction(&other, TransactionContext::Mempool).await;
    assert!(ctx.bip44_account().transactions().contains_key(&other.txid()));

    let winner = spend(&[a], A - 1_000);
    let result = ctx.check_transaction(&winner, TransactionContext::InBlock(block_info(101))).await;
    assert_eq!(result.swept_transactions, vec![loser.txid()]);
    assert!(result.released_outpoints.is_empty(), "the other spend still takes B");
    let account = ctx.bip44_account();
    assert!(account.transactions().contains_key(&other.txid()));
    assert!(!account.utxos.contains_key(&a));
    assert!(!account.utxos.contains_key(&b), "the other spend takes B");
    assert_eq!(ctx.managed_wallet.balance.total(), B - 101_000, "the other spend's change");
}

fn change_address(ctx: &mut TestWalletContext) -> Address {
    let xpub = ctx.xpub;
    ctx.managed_wallet
        .first_bip44_managed_account_mut()
        .expect("account")
        .next_change_address(Some(&xpub))
        .expect("change address")
}

/// L0, in the standard account, and L2, in the CoinJoin account, lose to
/// W. L2 spends F:0, which F, a spend of L0's change, paid the CoinJoin
/// account: F dies with L0, so F:0 never existed and is not credited.
#[tokio::test]
async fn a_coin_whose_funding_the_same_sweep_removed_is_not_credited() {
    let (mut ctx, funding, a, b) = funded().await;
    let coinjoin_xpub =
        ctx.wallet.accounts.coinjoin_accounts.get(&0).expect("CoinJoin").account_xpub;
    let coinjoin_address = ctx
        .managed_wallet
        .first_coinjoin_managed_account_mut()
        .expect("managed CoinJoin")
        .next_address(Some(&coinjoin_xpub))
        .expect("CoinJoin address");
    let change = change_address(&mut ctx);

    let mut first = spend(&[a], 100_000);
    first.output.push(TxOut {
        value: A - 101_000,
        script_pubkey: change.script_pubkey(),
    });
    let first = ctx.signed(first, &[&funding]).await;
    ctx.check_transaction(&first, TransactionContext::Mempool).await;
    let pass_on = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint::new(first.txid(), 1),
            ..Default::default()
        }],
        output: vec![TxOut {
            value: A - 102_000,
            script_pubkey: coinjoin_address.script_pubkey(),
        }],
        special_transaction_payload: None,
    };
    let pass_on = ctx.signed(pass_on, &[&first]).await;
    ctx.check_transaction(&pass_on, TransactionContext::Mempool).await;
    let passed = OutPoint::new(pass_on.txid(), 0);
    assert!(ctx
        .managed_wallet
        .first_coinjoin_managed_account()
        .unwrap()
        .utxos
        .contains_key(&passed));
    let second = ctx.signed(spend(&[passed, b], A + B - 200_000), &[&pass_on, &funding]).await;
    ctx.check_transaction(&second, TransactionContext::Mempool).await;

    let winner = spend(&[a, b], A + B - 1_000);
    let result = ctx.check_transaction(&winner, TransactionContext::InBlock(block_info(101))).await;
    for loser in [first.txid(), pass_on.txid(), second.txid()] {
        assert!(result.swept_transactions.contains(&loser));
    }
    assert!(!result.released_outpoints.contains(&passed), "F:0 never existed");
    let coinjoin = ctx.managed_wallet.first_coinjoin_managed_account().unwrap();
    assert!(!coinjoin.utxos.contains_key(&passed), "F:0 never existed");
    assert_eq!(ctx.managed_wallet.balance.total(), 0);
}

/// F is in a block no ChainLock covers, and a pending L spends F:0 and
/// another coin Z. A fork drops F's block; W then beats L on Z. F:0 is
/// gone with F, so it is not credited.
#[tokio::test]
async fn a_coin_whose_funding_a_fork_dropped_is_not_credited_when_its_spend_loses() {
    let mut ctx = TestWalletContext::new_random();
    let other_funding = Transaction::dummy(&ctx.receive_address, 2..3, &[B]);
    ctx.check_transaction(&other_funding, TransactionContext::InBlock(block_info(90))).await;
    let funding = Transaction::dummy(&ctx.receive_address, 0..1, &[A]);
    ctx.check_transaction(&funding, TransactionContext::InBlock(block_info(100))).await;
    let (coin, z) = (OutPoint::new(funding.txid(), 0), OutPoint::new(other_funding.txid(), 0));
    let loser = ctx.signed(spend(&[coin, z], A + B - 1_000), &[&funding, &other_funding]).await;
    ctx.check_transaction(&loser, TransactionContext::Mempool).await;

    ctx.managed_wallet.truncate_above(99).expect("no ChainLock");
    assert!(!ctx.bip44_account().transactions().contains_key(&funding.txid()));

    let winner = spend(&[z], B - 1_000);
    let lock = InstantLock {
        txid: winner.txid(),
        inputs: vec![z],
        ..InstantLock::default()
    };
    let result = ctx.check_transaction(&winner, TransactionContext::InstantSend(lock)).await;
    assert_eq!(result.swept_transactions, vec![loser.txid()]);
    assert!(!ctx.bip44_account().utxos.contains_key(&coin), "F is gone");
    assert_eq!(ctx.managed_wallet.balance.total(), 0);
}

/// L, abandoned, spends A and B, and another device's E spends B. L comes back locked, beating E,
/// then a ChainLocked W beats L on A: B is reported released although E spends it, until E is
/// mined. A known gap.
#[tokio::test]
async fn known_gap_a_coin_another_device_spent_shows_again_when_the_abandoned_payment_loses() {
    let (mut ctx, funding, a, b) = funded().await;
    let loser = ctx.signed(spend(&[a, b], A + B - 1_000), &[&funding]).await;
    ctx.check_transaction(&loser, TransactionContext::Mempool).await;
    ctx.managed_wallet.abandon_transaction(loser.txid());
    ctx.check_transaction(&funding, TransactionContext::InBlock(block_info(100))).await;
    assert_eq!(ctx.managed_wallet.balance.total(), A + B, "the abandon frees A and B");
    let other_device = ctx.signed(spend(&[b], B - 1_000), &[&funding]).await;
    ctx.check_transaction(&other_device, TransactionContext::Mempool).await;
    assert!(!ctx.bip44_account().utxos.contains_key(&b), "E spends B");

    let lock = InstantLock {
        txid: loser.txid(),
        inputs: vec![a, b],
        ..InstantLock::default()
    };
    ctx.check_transaction(&loser, TransactionContext::InstantSend(lock)).await;
    assert!(!ctx.bip44_account().transactions().contains_key(&other_device.txid()));
    let winner = spend(&[a], A - 1_000);
    let result = ctx
        .check_transaction(&winner, TransactionContext::InChainLockedBlock(block_info(101)))
        .await;
    assert_eq!(result.swept_transactions, vec![loser.txid()]);
    assert_eq!(result.released_outpoints, vec![b], "known gap: B is handed back while E spends it");
    assert!(
        !ctx.bip44_account().utxos.contains_key(&b),
        "L took B as no coin, so none is credited"
    );

    ctx.check_transaction(&other_device, TransactionContext::InBlock(block_info(102))).await;
    assert!(!ctx.bip44_account().utxos.contains_key(&b), "E is in a block");
    assert_eq!(ctx.managed_wallet.balance.total(), 0);
}

/// F's lock arrives after L took F:1. When W beats L, F:1 is credited as locked, as F is now.
#[tokio::test]
async fn a_coin_given_back_takes_its_fundings_lock_as_it_is_now() {
    let mut ctx = TestWalletContext::new_random();
    let funding = Transaction::dummy(&ctx.receive_address, 0..2, &[A, B]);
    ctx.check_transaction(&funding, TransactionContext::Mempool).await;
    let (a, b) = (OutPoint::new(funding.txid(), 0), OutPoint::new(funding.txid(), 1));
    let loser = ctx.signed(spend(&[a, b], A + B - 1_000), &[&funding]).await;
    ctx.check_transaction(&loser, TransactionContext::Mempool).await;
    let funding_lock = InstantLock {
        txid: funding.txid(),
        inputs: funding.input.iter().map(|input| input.previous_output).collect(),
        ..InstantLock::default()
    };
    ctx.check_transaction(&funding, TransactionContext::InstantSend(funding_lock)).await;

    let winner = spend(&[a], A - 1_000);
    let winner_lock = InstantLock {
        txid: winner.txid(),
        inputs: vec![a],
        ..InstantLock::default()
    };
    let result = ctx.check_transaction(&winner, TransactionContext::InstantSend(winner_lock)).await;
    assert_eq!(result.swept_transactions, vec![loser.txid()]);
    let restored = ctx.bip44_account().utxos.get(&b).expect("only the loser spent B");
    assert!(restored.is_instantlocked, "F is locked now");
    assert!(!restored.is_confirmed);
}
