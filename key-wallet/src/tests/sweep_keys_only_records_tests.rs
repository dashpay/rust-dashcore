//! A conflict sweep must take a loser out of every account that recorded it.
//!
//! An asset-lock funding transaction is recorded twice: in the funds account
//! that pays for it and in the identity keys account it funds. These tests
//! drive both sweep entry points — `check_core_transaction` with a final
//! context, and `mark_instant_send_utxos` — over such a transaction and check
//! that the keys-only record goes with the funds one.

use dashcore::blockdata::transaction::special_transaction::asset_lock::AssetLockPayload;
use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::hashes::Hash;
use dashcore::{Address, BlockHash, OutPoint, Transaction, TxIn, TxOut, Txid};

use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::test_utils::TestWalletContext;
use crate::transaction_checking::{BlockInfo, TransactionContext};
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::AccountType;

fn in_block(height: u32) -> TransactionContext {
    TransactionContext::InBlock(BlockInfo::new(
        height,
        BlockHash::from_slice(&[height as u8; 32]).expect("hash"),
        1_700_000_000 + height,
    ))
}

fn instant_lock_for(tx: &Transaction) -> InstantLock {
    InstantLock {
        txid: tx.txid(),
        ..InstantLock::default()
    }
}

fn spend(inputs: &[OutPoint], outputs: &[(&Address, u64)]) -> Transaction {
    Transaction {
        version: 2,
        lock_time: 0,
        input: inputs
            .iter()
            .map(|previous_output| TxIn {
                previous_output: *previous_output,
                ..Default::default()
            })
            .collect(),
        output: outputs
            .iter()
            .map(|(address, value)| TxOut {
                value: *value,
                script_pubkey: address.script_pubkey(),
            })
            .collect(),
        special_transaction_payload: None,
    }
}

/// An asset lock whose credit output funds `identity_address`.
fn new_asset_lock(
    inputs: &[OutPoint],
    outputs: &[(&Address, u64)],
    identity_address: &Address,
) -> Transaction {
    let mut tx = spend(inputs, outputs);
    tx.version = 3;
    tx.special_transaction_payload =
        Some(TransactionPayload::AssetLockPayloadType(AssetLockPayload {
            version: 1,
            credit_outputs: vec![TxOut {
                value: 100_000,
                script_pubkey: identity_address.script_pubkey(),
            }],
        }));
    tx
}

fn identity_address(ctx: &mut TestWalletContext) -> Address {
    let xpub = ctx
        .wallet
        .accounts
        .identity_registration
        .as_ref()
        .expect("identity registration account")
        .account_xpub;
    ctx.managed_wallet
        .identity_registration_managed_account_mut()
        .expect("managed identity registration account")
        .next_address(Some(&xpub), true)
        .expect("identity address")
}

fn change_address(ctx: &mut TestWalletContext) -> Address {
    let xpub = ctx.xpub;
    ctx.managed_wallet
        .first_bip44_managed_account_mut()
        .expect("BIP44 account")
        .next_change_address(Some(&xpub), true)
        .expect("change address")
}

/// Every account, funds or keys-only, holding a record of `txid`.
fn accounts_holding(ctx: &TestWalletContext, txid: &Txid) -> Vec<AccountType> {
    ctx.managed_wallet
        .accounts
        .all_accounts()
        .into_iter()
        .filter(|account| account.transactions().contains_key(txid))
        .map(|account| account.managed_account_type().to_account_type())
        .collect()
}

/// A wallet with two confirmed coins and an unconfirmed asset lock spending
/// both, recorded in the BIP44 account and in the identity account.
struct PendingAssetLock {
    ctx: TestWalletContext,
    funding: Transaction,
    coin_a: OutPoint,
    coin_b: OutPoint,
    asset_lock: Transaction,
}

impl PendingAssetLock {
    async fn new() -> Self {
        let mut ctx = TestWalletContext::new_random();
        let funding = Transaction::dummy(&ctx.receive_address, 0..2, &[500_000, 400_000]);
        ctx.check_transaction(&funding, in_block(100)).await;
        let coin_a = OutPoint::new(funding.txid(), 0);
        let coin_b = OutPoint::new(funding.txid(), 1);

        let identity = identity_address(&mut ctx);
        let change = change_address(&mut ctx);
        let asset_lock = new_asset_lock(&[coin_a, coin_b], &[(&change, 799_000)], &identity);
        ctx.check_transaction(&asset_lock, TransactionContext::Mempool).await;
        assert_eq!(
            accounts_holding(&ctx, &asset_lock.txid()).len(),
            2,
            "the asset lock is recorded in its funding account and in the identity account"
        );

        Self {
            ctx,
            funding,
            coin_a,
            coin_b,
            asset_lock,
        }
    }

    /// A transaction conflicting with the asset lock over `coin_a` alone.
    fn winner(&mut self) -> Transaction {
        let change = change_address(&mut self.ctx);
        spend(&[self.coin_a], &[(&change, 499_000)])
    }
}

#[tokio::test]
async fn a_block_winner_sweeps_an_asset_lock_from_every_account() {
    let mut fixture = PendingAssetLock::new().await;
    let winner = fixture.winner();

    let result = fixture.ctx.check_transaction(&winner, in_block(101)).await;

    assert_eq!(result.swept_transactions, vec![fixture.asset_lock.txid()]);
    assert_eq!(
        accounts_holding(&fixture.ctx, &fixture.asset_lock.txid()),
        Vec::new(),
        "a swept transaction must not stay recorded anywhere in the wallet"
    );
    assert_eq!(
        result.released_outpoints,
        vec![fixture.coin_b],
        "the coin only the swept asset lock spent came free and must be named"
    );
    assert_eq!(fixture.ctx.managed_wallet.balance.confirmed(), 499_000, "the winner's change");
}

#[tokio::test]
async fn an_instant_send_winner_sweeps_an_asset_lock_from_every_account() {
    let mut fixture = PendingAssetLock::new().await;
    let winner = fixture.winner();

    let context = TransactionContext::InstantSend(instant_lock_for(&winner));
    let result = fixture.ctx.check_transaction(&winner, context).await;

    assert_eq!(result.swept_transactions, vec![fixture.asset_lock.txid()]);
    assert_eq!(
        accounts_holding(&fixture.ctx, &fixture.asset_lock.txid()),
        Vec::new(),
        "a swept transaction must not stay recorded anywhere in the wallet"
    );
    assert_eq!(result.released_outpoints, vec![fixture.coin_b]);
}

/// The lock arrives for a winner the wallet already tracks, which is the
/// `mark_instant_send_utxos` path rather than `check_core_transaction`.
#[tokio::test]
async fn a_late_instant_lock_sweeps_an_asset_lock_from_every_account() {
    let mut fixture = PendingAssetLock::new().await;
    let winner = fixture.winner();
    fixture.ctx.check_transaction(&winner, TransactionContext::Mempool).await;
    assert_eq!(
        accounts_holding(&fixture.ctx, &fixture.asset_lock.txid()).len(),
        2,
        "nothing is swept while neither transaction is final"
    );

    let changed = fixture
        .ctx
        .managed_wallet
        .mark_instant_send_utxos(&winner.txid(), &instant_lock_for(&winner));

    assert!(changed);
    assert_eq!(
        accounts_holding(&fixture.ctx, &fixture.asset_lock.txid()),
        Vec::new(),
        "a swept transaction must not stay recorded anywhere in the wallet"
    );
}

/// The asset lock is not the loser itself: it spends the loser's change and
/// is swept as its descendant.
#[tokio::test]
async fn a_descendant_asset_lock_is_swept_from_every_account() {
    let mut ctx = TestWalletContext::new_random();
    let funding = Transaction::dummy(&ctx.receive_address, 0..1, &[500_000]);
    ctx.check_transaction(&funding, in_block(100)).await;
    let coin = OutPoint::new(funding.txid(), 0);

    let loser_change = change_address(&mut ctx);
    let loser = spend(&[coin], &[(&loser_change, 499_000)]);
    ctx.check_transaction(&loser, TransactionContext::Mempool).await;

    let identity = identity_address(&mut ctx);
    let descendant = new_asset_lock(&[OutPoint::new(loser.txid(), 0)], &[], &identity);
    ctx.check_transaction(&descendant, TransactionContext::Mempool).await;
    assert_eq!(accounts_holding(&ctx, &descendant.txid()).len(), 2);

    let winner_change = change_address(&mut ctx);
    let winner = spend(&[coin], &[(&winner_change, 498_000)]);
    let result = ctx.check_transaction(&winner, in_block(101)).await;

    let mut expected = vec![loser.txid(), descendant.txid()];
    expected.sort_unstable();
    assert_eq!(result.swept_transactions, expected);
    assert_eq!(accounts_holding(&ctx, &loser.txid()), Vec::new());
    assert_eq!(
        accounts_holding(&ctx, &descendant.txid()),
        Vec::new(),
        "a descendant swept with its parent must not stay recorded anywhere in the wallet"
    );
}

/// A swept transaction the wallet sees again is a transaction it does not
/// hold, so it is handled like any loser arriving after its winner: every
/// account it touches records the attempt, and nothing it created is credited.
#[tokio::test]
async fn a_swept_asset_lock_seen_again_is_recorded_as_new() {
    let mut fixture = PendingAssetLock::new().await;
    let winner = fixture.winner();
    fixture.ctx.check_transaction(&winner, in_block(101)).await;
    // A rescan re-delivers the funding block and restores the released coin.
    fixture.ctx.check_transaction(&fixture.funding, in_block(100)).await;
    assert_eq!(fixture.ctx.managed_wallet.balance.confirmed(), 899_000);

    let result =
        fixture.ctx.check_transaction(&fixture.asset_lock, TransactionContext::Mempool).await;

    assert!(result.is_new_transaction, "nothing in the wallet holds the swept transaction");
    assert_eq!(
        accounts_holding(&fixture.ctx, &fixture.asset_lock.txid()).len(),
        2,
        "the funding account must record the transaction again, not only the identity account"
    );
    assert!(
        fixture.ctx.bip44_account().utxos.contains_key(&fixture.coin_b),
        "a transaction a block already beat must not consume the restored coin"
    );
    assert_eq!(
        fixture.ctx.managed_wallet.balance.total(),
        899_000,
        "the winner's change and the restored coin, and nothing the asset lock created"
    );
}

/// The sweep removes what it swept and nothing else: a keys-only record of a
/// transaction the winner does not conflict with stays.
#[tokio::test]
async fn the_sweep_leaves_an_unrelated_keys_only_record_alone() {
    let mut fixture = PendingAssetLock::new().await;
    let identity = identity_address(&mut fixture.ctx);
    let foreign_coin = OutPoint::new(Txid::from([0x77; 32]), 0);
    let bystander = new_asset_lock(&[foreign_coin], &[], &identity);
    fixture.ctx.check_transaction(&bystander, TransactionContext::Mempool).await;
    let winner = fixture.winner();

    let result = fixture.ctx.check_transaction(&winner, in_block(101)).await;

    assert_eq!(result.swept_transactions, vec![fixture.asset_lock.txid()]);
    assert_eq!(
        accounts_holding(&fixture.ctx, &bystander.txid()),
        vec![AccountType::IdentityRegistration]
    );
}
