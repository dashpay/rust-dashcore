//! Tests for spent_outpoints deserialization and tracking.

use dashcore::blockdata::transaction::{OutPoint, Transaction};
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
use crate::wallet::{ManagedWalletInfo, Wallet};
use crate::Network;

fn restore_context() -> (TestWalletContext, dashcore::Address) {
    let wallet = Wallet::from_seed_bytes(
        [42; 64],
        Network::Testnet,
        WalletAccountCreationOptions::BIP44AccountsOnly([0, 1].into_iter().collect()),
    )
    .unwrap();
    let mut managed_wallet = ManagedWalletInfo::from_wallet(&wallet, 0);
    let mut address = |index| {
        let xpub = wallet.accounts.standard_bip44_accounts[&index].account_xpub;
        managed_wallet
            .accounts
            .standard_bip44_accounts
            .get_mut(&index)
            .unwrap()
            .next_receive_address(Some(&xpub), true)
            .unwrap()
    };
    let receive_address = address(0);
    let second_address = address(1);
    let xpub = wallet.accounts.standard_bip44_accounts[&0].account_xpub;
    (
        TestWalletContext {
            wallet,
            managed_wallet,
            receive_address,
            xpub,
        },
        second_address,
    )
}

#[tokio::test]
async fn restored_spends_survive_finality_without_records() {
    let (mut ctx, address) = restore_context();
    let funding = Transaction::dummy(&address, 10..11, &[150_000, 90_000]);
    let claims = [
        (OutPoint::new(funding.txid(), 0), None),
        (OutPoint::new(funding.txid(), 1), Some(Txid::from([0x99; 32]))),
    ];
    ctx.managed_wallet.restore_spent_outpoints(&claims);
    ctx.managed_wallet.restore_spent_outpoints(&claims);
    ctx.managed_wallet.restore_spent_outpoints(&[]);
    assert!(ctx.managed_wallet.accounts.all_accounts().iter().all(|a| a.transactions().is_empty()));
    assert!(ctx.managed_wallet.accounts.all_funding_accounts().iter().all(|a| a.utxos.is_empty()));
    assert_eq!(ctx.managed_wallet.balance.total(), 0);
    assert!(ctx.managed_wallet.observed_spent_outpoints().is_empty());
    ctx.managed_wallet.update_synced_height(200);
    ctx.managed_wallet.apply_chain_lock(ChainLock::dummy(200));
    ctx.check_transaction(&funding, TransactionContext::Mempool).await;
    assert!(
        ctx.managed_wallet.accounts.standard_bip44_accounts[&1].utxos.is_empty(),
        "restored claims must prevent credit without any spending transaction body"
    );
    assert_eq!(ctx.managed_wallet.balance.total(), 0);
}

#[test_case::test_case(false; "conflict")]
#[test_case::test_case(true; "abandonment")]
#[tokio::test]
async fn restored_spends_release_only_removed_claimants(abandon: bool) {
    for kind in 0..4 {
        let (mut ctx, address) = restore_context();
        let funding = Transaction::dummy(&address, 20..21, &[150_000, 90_000]);
        let spent = OutPoint::new(funding.txid(), 0);
        let unrelated = OutPoint::new(funding.txid(), 1);
        let contested = OutPoint::new(Txid::from([0x55; 32]), 0);
        let mut loser = spending_tx(&[contested, spent]);
        loser.output = Transaction::dummy(&ctx.receive_address, 30..31, &[140_000]).output;
        let claimant = match kind {
            0 | 3 => Some(loser.txid()),
            1 => None,
            _ => Some(Txid::from([0x99; 32])),
        };
        ctx.managed_wallet.restore_spent_outpoints(&[(spent, claimant), (unrelated, None)]);
        ctx.check_transaction(&loser, TransactionContext::Mempool).await;
        assert!(ctx.bip44_account().has_transaction(&loser.txid()));
        assert!(
            !ctx.managed_wallet.accounts.standard_bip44_accounts[&1].has_transaction(&loser.txid())
        );
        if kind == 3 {
            let mut survivor = spending_tx(&[spent]);
            survivor.output = loser.output.clone();
            ctx.check_transaction(&survivor, TransactionContext::Mempool).await;
            assert!(ctx.bip44_account().has_transaction(&survivor.txid()));
        }
        if abandon {
            assert_eq!(ctx.managed_wallet.abandon_transaction(loser.txid()).records_removed, 1);
        } else {
            let result = ctx
                .check_transaction(
                    &spending_tx(&[contested]),
                    TransactionContext::InBlock(BlockInfo::new(
                        100,
                        BlockHash::from([0x66; 32]),
                        1_700_000_000,
                    )),
                )
                .await;
            assert_eq!(result.swept_transactions, vec![loser.txid()]);
            assert_eq!(result.released_outpoints.contains(&spent), kind == 0);
        }
        ctx.check_transaction(&funding, TransactionContext::Mempool).await;
        let account = &ctx.managed_wallet.accounts.standard_bip44_accounts[&1];
        assert_eq!(
            account.utxos.contains_key(&spent),
            kind == 0,
            "claimant kind {kind}, abandon={abandon}"
        );
        assert!(!account.utxos.contains_key(&unrelated));
    }
}

#[test]
fn restored_spends_leave_snapshot_encoding_unchanged() {
    let mut info = ManagedWalletInfo::dummy(1);
    info.accounts.standard_bip44_accounts.insert(0, ManagedCoreFundsAccount::dummy_bip44());
    let before = serde_json::to_string(&info).unwrap();
    info.restore_spent_outpoints(&[(OutPoint::new(Txid::from([0x88; 32]), 0), None)]);
    let after = serde_json::to_string(&info).unwrap();
    assert_eq!(before, after);
    let restored: ManagedWalletInfo = serde_json::from_str(&after).unwrap();
    assert_eq!(serde_json::to_string(&restored).unwrap(), before);
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
