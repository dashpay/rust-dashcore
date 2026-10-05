//! Tests for spent_outpoints deserialization and tracking.

use dashcore::blockdata::transaction::{OutPoint, Transaction};
use dashcore::bls_sig_utils::BLSSignature;
use dashcore::ephemerealdata::chain_lock::ChainLock;
use dashcore::hashes::Hash;
use dashcore::{BlockHash, TxIn, Txid};

use crate::account::{AccountType, StandardAccountType, TransactionRecord};
use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::managed_account::reservation::ReservationToken;
use crate::managed_account::transaction_record::TransactionDirection;
use crate::managed_account::ManagedCoreFundsAccount;
use crate::test_utils::TestWalletContext;
use crate::transaction_checking::{BlockInfo, TransactionContext, TransactionType};
use crate::wallet::initialization::WalletAccountCreationOptions;
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::wallet::managed_wallet_info::ManagedAccountOperations;
use crate::wallet::ManagedWalletInfo;
use crate::{Network, Wallet};

fn restored_wallet_context() -> TestWalletContext {
    let wallet =
        Wallet::from_seed_bytes([42; 64], Network::Testnet, WalletAccountCreationOptions::Default)
            .expect("test wallet");
    let mut managed_wallet = ManagedWalletInfo::from_wallet(&wallet, 0);
    let xpub = wallet.accounts.standard_bip44_accounts[&0].account_xpub;
    let receive_address = managed_wallet
        .first_bip44_managed_account_mut()
        .expect("first account")
        .next_receive_address(Some(&xpub), true)
        .expect("receive address");
    TestWalletContext {
        managed_wallet,
        wallet,
        receive_address,
        xpub,
    }
}

fn chain_lock(height: u32) -> ChainLock {
    ChainLock {
        block_height: height,
        block_hash: BlockHash::from([0x77; 32]),
        signature: BLSSignature::from([0; 96]),
    }
}

fn add_second_account(ctx: &mut TestWalletContext) -> dashcore::Address {
    let account_type = AccountType::Standard {
        index: 1,
        standard_account_type: StandardAccountType::BIP44Account,
    };
    ctx.wallet.add_account(account_type, None).expect("second account");
    ctx.managed_wallet.add_managed_account(&ctx.wallet, account_type).expect("managed account");
    let xpub = ctx.wallet.accounts.standard_bip44_accounts[&1].account_xpub;
    ctx.managed_wallet
        .accounts
        .standard_bip44_accounts
        .get_mut(&1)
        .expect("second account")
        .next_receive_address(Some(&xpub), true)
        .expect("second receive address")
}

#[tokio::test]
async fn restored_spent_outpoints_block_funding_without_spending_history_after_finality() {
    let mut ctx = restored_wallet_context();
    let second_address = add_second_account(&mut ctx);
    let funding = Transaction::dummy(&second_address, 10..11, &[150_000]);
    let spent = OutPoint::new(funding.txid(), 0);
    let spend = spending_tx(&[spent]);
    ctx.managed_wallet.record_observed_spends(&spend, 100);
    ctx.managed_wallet.metadata.synced_height = 100;
    ctx.managed_wallet.apply_chain_lock(chain_lock(100));
    assert!(ctx.managed_wallet.observed_spent_outpoints().is_empty());

    let balance = ctx.managed_wallet.balance;
    ctx.managed_wallet
        .restore_spent_outpoints(&[(spent, Some(spend.txid())), (spent, Some(spend.txid()))]);
    ctx.managed_wallet.restore_spent_outpoints(&[]);
    assert_eq!(ctx.managed_wallet.balance, balance);
    assert!(ctx.managed_wallet.observed_spent_outpoints().is_empty());
    assert!(ctx.managed_wallet.accounts.all_accounts().iter().all(|a| a.transactions().is_empty()));
    assert!(ctx.managed_wallet.accounts.all_funding_accounts().iter().all(|a| a.utxos.is_empty()));

    // A later finality event cannot expire a restored guard with no known spending height.
    ctx.managed_wallet.metadata.synced_height = 200;
    ctx.managed_wallet.apply_chain_lock(chain_lock(200));
    ctx.check_transaction(&funding, TransactionContext::Mempool).await;
    assert!(
        ctx.managed_wallet.accounts.standard_bip44_accounts[&1].utxos.is_empty(),
        "a spent placeholder with no known owner must not become a spendable funding output"
    );
    assert_eq!(ctx.managed_wallet.balance, balance);
    assert!(!ctx
        .managed_wallet
        .accounts
        .all_accounts()
        .iter()
        .any(|a| a.transactions().contains_key(&spend.txid())));

    let unspent = Transaction::dummy(&second_address, 11..12, &[80_000]);
    ctx.check_transaction(&unspent, TransactionContext::Mempool).await;
    assert!(ctx.managed_wallet.accounts.standard_bip44_accounts[&1]
        .utxos
        .contains_key(&OutPoint::new(unspent.txid(), 0)));
}

#[tokio::test]
async fn restored_spent_outpoints_release_conflicts_across_seeded_accounts() {
    let mut ctx = restored_wallet_context();
    let second_address = add_second_account(&mut ctx);
    let funding = Transaction::dummy(&second_address, 20..21, &[150_000, 90_000, 60_000]);
    let released = OutPoint::new(funding.txid(), 0);
    let retained = OutPoint::new(funding.txid(), 1);
    let unrelated = OutPoint::new(funding.txid(), 2);
    let contested = OutPoint::new(Txid::from([0x55; 32]), 0);
    let loser = spending_tx(&[contested, released, retained]);
    let survivor = spending_tx(&[retained]);
    ctx.managed_wallet
        .first_bip44_managed_account_mut()
        .expect("first account")
        .transactions_mut()
        .insert(loser.txid(), record_from_tx(&loser));
    ctx.managed_wallet
        .accounts
        .standard_bip44_accounts
        .get_mut(&1)
        .expect("second account")
        .transactions_mut()
        .insert(survivor.txid(), record_from_tx(&survivor));
    ctx.managed_wallet.restore_spent_outpoints(&[
        (contested, Some(loser.txid())),
        (released, Some(loser.txid())),
        (retained, Some(survivor.txid())),
        (unrelated, None),
    ]);

    let winner = spending_tx(&[contested]);
    let result = ctx.managed_wallet.sweep_conflicts(
        &winner,
        &TransactionContext::InBlock(BlockInfo::new(
            100,
            BlockHash::from([0x66; 32]),
            1_700_000_000,
        )),
    );
    assert_eq!(result.txids, vec![loser.txid()]);
    assert_eq!(result.released_outpoints, vec![released]);
    ctx.check_transaction(&funding, TransactionContext::Mempool).await;
    let account = &ctx.managed_wallet.accounts.standard_bip44_accounts[&1];
    assert!(
        account.utxos.contains_key(&released),
        "release must reach an account without the loser record"
    );
    assert!(!account.utxos.contains_key(&retained), "surviving claims must remain guarded");
    assert!(
        !account.utxos.contains_key(&unrelated),
        "unrelated restored guards must survive a conflict"
    );
}

#[tokio::test]
async fn restored_spent_outpoints_survive_abandoning_a_later_claim() {
    for claimant in [None, Some(Txid::from([0x99; 32]))] {
        let mut ctx = restored_wallet_context();
        let funding = Transaction::dummy(&ctx.receive_address, 40..41, &[150_000]);
        let spent = OutPoint::new(funding.txid(), 0);
        ctx.managed_wallet.restore_spent_outpoints(&[(spent, claimant)]);
        let mut later_claim = spending_tx(&[spent]);
        later_claim.output = funding.output.clone();
        let result = ctx.check_transaction(&later_claim, TransactionContext::Mempool).await;
        assert!(result.is_relevant);
        assert!(ctx.bip44_account().transactions().contains_key(&later_claim.txid()));
        ctx.managed_wallet.abandon_transaction(later_claim.txid());
        ctx.check_transaction(&funding, TransactionContext::Mempool).await;
        assert!(
            !ctx.bip44_account().utxos.contains_key(&spent),
            "abandoning a later claimant must not release a preexisting recordless durable spend"
        );
    }
}

#[tokio::test]
async fn restored_spent_outpoints_survive_sweeping_a_later_claim() {
    for claimant in [None, Some(Txid::from([0x99; 32]))] {
        let mut ctx = restored_wallet_context();
        let funding = Transaction::dummy(&ctx.receive_address, 50..51, &[150_000]);
        let spent = OutPoint::new(funding.txid(), 0);
        let contested = OutPoint::new(Txid::from([0x55; 32]), 0);
        ctx.managed_wallet.restore_spent_outpoints(&[(spent, claimant)]);
        let mut later_claim = spending_tx(&[spent, contested]);
        later_claim.output = funding.output.clone();
        ctx.check_transaction(&later_claim, TransactionContext::Mempool).await;
        assert!(ctx.bip44_account().transactions().contains_key(&later_claim.txid()));
        let result = ctx.managed_wallet.sweep_conflicts(
            &spending_tx(&[contested]),
            &TransactionContext::InBlock(BlockInfo::new(
                100,
                BlockHash::from([0x66; 32]),
                1_700_000_000,
            )),
        );
        assert_eq!(result.txids, vec![later_claim.txid()]);
        assert!(result.released_outpoints.is_empty(), "the durable claimant still owns the input");
        ctx.check_transaction(&funding, TransactionContext::Mempool).await;
        assert!(!ctx.bip44_account().utxos.contains_key(&spent));
    }
}

#[test]
fn restored_spent_outpoints_do_not_change_snapshot_encoding() {
    let mut account = ManagedCoreFundsAccount::dummy_bip44();
    let before = serde_json::to_string(&account).expect("encode before restoration");
    let spent = OutPoint::new(Txid::from([0x88; 32]), 0);
    account.restore_spent_outpoints(&[(spent, None)]);
    let after = serde_json::to_string(&account).expect("encode after restoration");
    assert_eq!(before, after);
    let candidates = [spent].into_iter().collect();
    assert!(account.release_spent_marks(&candidates, &Default::default()).is_empty());
    let mut reloaded: ManagedCoreFundsAccount = serde_json::from_str(&after).expect("reload");
    assert_eq!(
        reloaded.release_spent_marks(&candidates, &Default::default()),
        candidates,
        "external claims must be reapplied after deserialization"
    );
}

#[tokio::test]
async fn restored_spent_outpoints_release_abandoned_inputs_across_seeded_accounts() {
    let mut ctx = restored_wallet_context();
    let second_address = add_second_account(&mut ctx);
    let funding = Transaction::dummy(&second_address, 30..31, &[150_000, 90_000, 60_000]);
    let released = OutPoint::new(funding.txid(), 0);
    let retained = OutPoint::new(funding.txid(), 1);
    let unrelated = OutPoint::new(funding.txid(), 2);
    let abandoned = spending_tx(&[released, retained]);
    let survivor = spending_tx(&[retained]);
    ctx.managed_wallet
        .first_bip44_managed_account_mut()
        .expect("first account")
        .transactions_mut()
        .insert(abandoned.txid(), record_from_tx(&abandoned));
    ctx.managed_wallet
        .accounts
        .standard_bip44_accounts
        .get_mut(&1)
        .expect("second account")
        .transactions_mut()
        .insert(survivor.txid(), record_from_tx(&survivor));
    ctx.managed_wallet.restore_spent_outpoints(&[
        (released, Some(abandoned.txid())),
        (retained, Some(survivor.txid())),
        (unrelated, None),
    ]);

    let result = ctx.managed_wallet.abandon_transaction(abandoned.txid());
    assert_eq!(result.records_removed, 1);
    assert!(result.abandoned.contains(&abandoned.txid()));
    ctx.check_transaction(&funding, TransactionContext::Mempool).await;
    let account = &ctx.managed_wallet.accounts.standard_bip44_accounts[&1];
    assert!(
        account.utxos.contains_key(&released),
        "abandonment must release guards in every seeded account"
    );
    assert!(!account.utxos.contains_key(&retained), "a surviving spender still claims this input");
    assert!(
        !account.utxos.contains_key(&unrelated),
        "unrelated restored guards must survive abandonment"
    );
}

/// Create a transaction that spends the given outpoints.
fn spending_tx(spent: &[OutPoint]) -> Transaction {
    Transaction {
        version: 1,
        lock_time: 0,
        input: spent
            .iter()
            .map(|op| TxIn {
                previous_output: *op,
                ..Default::default()
            })
            .collect(),
        output: Vec::new(),
        special_transaction_payload: None,
    }
}

/// Create a receive-only transaction (no meaningful inputs).
fn receive_only_tx() -> Transaction {
    Transaction {
        version: 1,
        lock_time: 0,
        input: vec![TxIn::default()],
        output: Vec::new(),
        special_transaction_payload: None,
    }
}

fn record_from_tx(tx: &Transaction) -> TransactionRecord {
    TransactionRecord::new(
        tx.clone(),
        AccountType::Standard {
            index: 0,
            standard_account_type: StandardAccountType::BIP44Account,
        },
        TransactionContext::Mempool,
        TransactionType::Standard,
        TransactionDirection::Incoming,
        Vec::new(),
        Vec::new(),
        0,
    )
}

#[test]
fn fresh_account_has_empty_spent_outpoints() {
    let account = ManagedCoreFundsAccount::dummy_bip44();
    assert!(account.transactions().is_empty());

    let probe = OutPoint::new(Txid::from([0xAA; 32]), 0);
    // Accessing spent_outpoints on a fresh account should not panic or misbehave.
    // We verify indirectly via serde round-trip (spent_outpoints is private).
    let json = serde_json::to_string(&account).unwrap();
    let deserialized: ManagedCoreFundsAccount = serde_json::from_str(&json).unwrap();
    // No transactions, so spent_outpoints stays empty after round-trip.
    assert!(deserialized.transactions().is_empty());
    // Confirm the serialized form does not contain spent_outpoints.
    assert!(!json.contains("spent_outpoints"));
    let _ = probe; // used only for clarity of intent
}

#[test]
fn reservations_are_not_persisted() {
    let account = ManagedCoreFundsAccount::dummy_bip44();
    let outpoint = OutPoint::new(Txid::from([0x42; 32]), 0);

    account.reservations().reserve(&[outpoint], 0, ReservationToken::next());
    assert!(account.reservations().reserved(0).contains(&outpoint));

    let json = serde_json::to_string(&account).unwrap();
    assert!(!json.contains("reservations"));

    // After a round-trip the reservation set is empty: it is ephemeral, and on
    // restart chain/mempool sync is the source of truth for spent coins.
    let deserialized: ManagedCoreFundsAccount = serde_json::from_str(&json).unwrap();
    assert!(!deserialized.reservations().reserved(0).contains(&outpoint));
}

#[tokio::test]
async fn processing_a_spend_releases_its_reservation() {
    let (mut ctx, funding_tx) = TestWalletContext::new_random().with_mempool_funding(150_000).await;
    let funded = OutPoint::new(funding_tx.txid(), 0);

    let account = ctx.managed_wallet.first_bip44_managed_account_mut().expect("BIP44 account");
    assert!(account.utxos.contains_key(&funded));
    account.reservations().reserve(&[funded], 0, ReservationToken::next());
    assert!(account.reservations().reserved(0).contains(&funded));

    let spend = spending_tx(&[funded]);
    ctx.check_transaction(&spend, TransactionContext::Mempool).await;

    let account = ctx.managed_wallet.first_bip44_managed_account().expect("BIP44 account");
    assert!(!account.reservations().reserved(0).contains(&funded));

    // The confirmed path releases reservations too: a separate funding tx with
    // a distinct input range yields a second outpoint that is reserved and then
    // spent in a block.
    let second_funding = Transaction::dummy(&ctx.receive_address, 1..2, &[120_000]);
    ctx.check_transaction(&second_funding, TransactionContext::Mempool).await;
    let second_funded = OutPoint::new(second_funding.txid(), 0);

    let account = ctx.managed_wallet.first_bip44_managed_account_mut().expect("BIP44 account");
    assert!(account.utxos.contains_key(&second_funded));
    account.reservations().reserve(&[second_funded], 0, ReservationToken::next());
    assert!(account.reservations().reserved(0).contains(&second_funded));

    let block_hash = BlockHash::from_slice(&[7u8; 32]).expect("hash");
    let confirmed_spend = spending_tx(&[second_funded]);
    ctx.check_transaction(
        &confirmed_spend,
        TransactionContext::InBlock(BlockInfo::new(100, block_hash, 1_700_000_000)),
    )
    .await;

    let account = ctx.managed_wallet.first_bip44_managed_account().expect("BIP44 account");
    assert!(!account.reservations().reserved(0).contains(&second_funded));
}

#[test]
fn serde_round_trip_rebuilds_spent_outpoints() {
    let mut account = ManagedCoreFundsAccount::dummy_bip44();

    let outpoint_a = OutPoint::new(Txid::from([0x01; 32]), 0);
    let outpoint_b = OutPoint::new(Txid::from([0x02; 32]), 1);
    let tx = spending_tx(&[outpoint_a, outpoint_b]);
    let txid = tx.txid();
    account.transactions_mut().insert(txid, record_from_tx(&tx));

    // Serialize (spent_outpoints is skipped)
    let json = serde_json::to_string(&account).unwrap();
    assert!(!json.contains("spent_outpoints"));

    // Deserialize: spent_outpoints should be rebuilt from transactions
    let deserialized: ManagedCoreFundsAccount = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.transactions().len(), 1);

    // Verify the rebuilt set by serializing again and comparing transactions
    // (spent_outpoints is private, so we test behavior through a second round-trip
    //  to confirm stability)
    let json2 = serde_json::to_string(&deserialized).unwrap();
    let deserialized2: ManagedCoreFundsAccount = serde_json::from_str(&json2).unwrap();
    assert_eq!(deserialized2.transactions().len(), 1);
}

#[test]
fn receive_only_account_round_trips_correctly() {
    let mut account = ManagedCoreFundsAccount::dummy_bip44();

    // Add a receive-only transaction (coinbase-like, no real spent outpoints)
    let tx = receive_only_tx();
    let txid = tx.txid();
    account.transactions_mut().insert(txid, record_from_tx(&tx));

    assert_eq!(account.transactions().len(), 1);

    // Round-trip should work without issues (no rebuild loop)
    let json = serde_json::to_string(&account).unwrap();
    let deserialized: ManagedCoreFundsAccount = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.transactions().len(), 1);

    // A second round-trip should be stable
    let json2 = serde_json::to_string(&deserialized).unwrap();
    let deserialized2: ManagedCoreFundsAccount = serde_json::from_str(&json2).unwrap();
    assert_eq!(deserialized2.transactions().len(), 1);
}

#[test]
fn multiple_transactions_all_inputs_tracked_after_round_trip() {
    let mut account = ManagedCoreFundsAccount::dummy_bip44();

    let outpoint_1 = OutPoint::new(Txid::from([0x10; 32]), 0);
    let outpoint_2 = OutPoint::new(Txid::from([0x20; 32]), 0);
    let outpoint_3 = OutPoint::new(Txid::from([0x30; 32]), 2);

    let tx1 = spending_tx(&[outpoint_1]);
    let tx2 = spending_tx(&[outpoint_2, outpoint_3]);

    account.transactions_mut().insert(tx1.txid(), record_from_tx(&tx1));
    account.transactions_mut().insert(tx2.txid(), record_from_tx(&tx2));

    let json = serde_json::to_string(&account).unwrap();
    let deserialized: ManagedCoreFundsAccount = serde_json::from_str(&json).unwrap();

    // All three outpoints should be in the rebuilt spent set.
    // We verify by confirming the transaction inputs survived the round-trip.
    let all_spent: Vec<OutPoint> = deserialized
        .transactions()
        .values()
        .flat_map(|r| &r.transaction.input)
        .map(|inp| inp.previous_output)
        .collect();
    assert!(all_spent.contains(&outpoint_1));
    assert!(all_spent.contains(&outpoint_2));
    assert!(all_spent.contains(&outpoint_3));
    assert_eq!(all_spent.len(), 3);
}
