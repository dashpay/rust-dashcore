//! A wallet locks the coins it owns that back a registered masternode, so
//! ordinary sends never spend them, and anything else locked by hand. See
//! [`ManagedWalletInfo::locked_outpoints`](crate::wallet::ManagedWalletInfo::locked_outpoints).

use std::str::FromStr;

use dashcore::address::NetworkUnchecked;
use dashcore::blockdata::transaction::special_transaction::provider_registration::{
    ProviderMasternodeType, ProviderRegistrationPayload,
};
use dashcore::blockdata::transaction::special_transaction::provider_update_revocation::ProviderUpdateRevocationPayload;
use dashcore::blockdata::transaction::special_transaction::provider_update_service::ProviderUpdateServicePayload;
use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::bls_sig_utils::{BLSPublicKey, BLSSignature};
use dashcore::hash_types::InputsHash;
use dashcore::hashes::Hash;
use dashcore::{
    Address, BlockHash, OutPoint, PubkeyHash, ScriptBuf, Transaction, TxIn, TxOut, Txid,
};
use test_case::test_case;

use crate::test_utils::TestWalletContext;
use crate::transaction_checking::{BlockInfo, TransactionContext, WalletTransactionChecker};
use crate::wallet::managed_wallet_info::asset_lock_builder::{
    AssetLockError, AssetLockFundingType, CreditOutputFunding,
};
use crate::wallet::managed_wallet_info::coin_selection::{SelectionError, SelectionStrategy};
use crate::wallet::managed_wallet_info::fee::FeeRate;
use crate::wallet::managed_wallet_info::transaction_builder::{BuilderError, TransactionBuilder};
use crate::wallet::managed_wallet_info::transaction_building::AccountTypePreference;
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::Utxo;

const DASH: u64 = 100_000_000;
const COLLATERAL: u64 = 1_000 * DASH;
const SPARE: u64 = 5 * DASH;
const TIP: u32 = 200;

fn block(height: u32) -> TransactionContext {
    TransactionContext::InBlock(BlockInfo::new(
        height,
        BlockHash::from_byte_array([height as u8; 32]),
        1_700_000_000 + height,
    ))
}

/// An address that is not the wallet's.
fn elsewhere() -> Address<NetworkUnchecked> {
    Address::from_str("yTb47qEBpNmgXvYYsHEN4nh8yJwa5iC4Cs").expect("testnet address")
}

/// A ProRegTx registering `collateral`, paying `outputs`. Everything else,
/// its fee input and keys included, belongs to no one this wallet knows, so
/// the collateral is its only link to the wallet. `seed` varies the txid.
fn registration(collateral: OutPoint, outputs: Vec<TxOut>, seed: u8) -> Transaction {
    let key_hash = PubkeyHash::from_byte_array([0x70; 20]);
    Transaction {
        version: 3,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([seed; 32]), 0),
            ..Default::default()
        }],
        output: outputs,
        special_transaction_payload: Some(TransactionPayload::ProviderRegistrationPayloadType(
            ProviderRegistrationPayload {
                version: 1,
                masternode_type: ProviderMasternodeType::Regular,
                masternode_mode: 0,
                collateral_outpoint: collateral,
                service_address: "127.0.0.1:19999".parse().expect("socket address"),
                owner_key_hash: key_hash,
                operator_public_key: BLSPublicKey::from([0x11; 48]),
                voting_key_hash: key_hash,
                operator_reward: 0,
                script_payout: ScriptBuf::new(),
                inputs_hash: InputsHash::all_zeros(),
                signature: vec![0x33; 65],
                platform_node_id: None,
                platform_p2p_port: None,
                platform_http_port: None,
            },
        )),
    }
}

/// Pay `value` to the wallet in a block at `height`; `seed` varies the txid.
async fn receive(ctx: &mut TestWalletContext, value: u64, seed: u8, height: u32) -> OutPoint {
    let tx = Transaction::dummy(&ctx.receive_address, seed..seed + 1, &[value]);
    assert!(ctx.check_transaction(&tx, block(height)).await.is_relevant);
    OutPoint::new(tx.txid(), 0)
}

/// A wallet holding a 1,000 DASH coin registered as masternode collateral by
/// a ProRegTx it has seen, and a spare coin of `spare` duffs, if any.
async fn registered_wallet(spare: Option<u64>) -> (TestWalletContext, OutPoint, Option<OutPoint>) {
    let mut ctx = TestWalletContext::new_random();
    let collateral = receive(&mut ctx, COLLATERAL, 0x01, 100).await;
    let spare = match spare {
        Some(value) => Some(receive(&mut ctx, value, 0x02, 100).await),
        None => None,
    };
    let registration = registration(collateral, vec![], 0xEE);
    let registered = ctx.check_transaction(&registration, block(101)).await;
    assert_eq!(registered.locked_outpoints, vec![collateral]);
    ctx.managed_wallet.update_last_processed_height(TIP);
    (ctx, collateral, spare)
}

/// Build a send of `amount` from BIP44 account 0 without signing it. The
/// build's reservation is handed back, so the next build sees every coin.
fn send(
    ctx: &mut TestWalletContext,
    amount: u64,
    strategy: SelectionStrategy,
) -> Result<Transaction, BuilderError> {
    let (tx, _fee) = ctx.managed_wallet.build_unsigned_transaction(
        &ctx.wallet,
        &[AccountTypePreference::BIP44],
        0,
        vec![(elsewhere(), amount)],
        FeeRate::normal(),
        strategy,
    )?;
    ctx.bip44_account().release_reservation(&tx);
    Ok(tx)
}

fn spent(tx: &Transaction) -> Vec<OutPoint> {
    tx.input.iter().map(|input| input.previous_output).collect()
}

fn is_out_of_coins(result: Result<Transaction, BuilderError>) -> bool {
    matches!(
        result,
        Err(BuilderError::CoinSelection(
            SelectionError::NoUtxosAvailable
                | SelectionError::InsufficientFunds {
                    available: 0,
                    ..
                }
        ))
    )
}

#[test_case(SelectionStrategy::SmallestFirst ; "smallest first")]
#[test_case(SelectionStrategy::LargestFirst ; "largest first")]
#[test_case(SelectionStrategy::SmallestFirstTill(1) ; "smallest first till one")]
#[test_case(SelectionStrategy::BranchAndBound ; "branch and bound")]
#[test_case(SelectionStrategy::OptimalConsolidation ; "optimal consolidation")]
#[test_case(SelectionStrategy::Random ; "random")]
#[test_case(SelectionStrategy::All ; "drain")]
#[tokio::test]
async fn a_send_spends_the_spare_coin_and_never_the_collateral(strategy: SelectionStrategy) {
    let (mut ctx, _collateral, spare) = registered_wallet(Some(SPARE)).await;

    let tx = send(&mut ctx, DASH, strategy).expect("the spare 5 DASH covers a 1 DASH send");

    // A drain takes every spendable coin: still only the spare one.
    assert_eq!(spent(&tx), vec![spare.expect("spare coin")]);
}

#[test_case(SelectionStrategy::SmallestFirst ; "smallest first")]
#[test_case(SelectionStrategy::LargestFirst ; "largest first")]
#[test_case(SelectionStrategy::SmallestFirstTill(1) ; "smallest first till one")]
#[test_case(SelectionStrategy::BranchAndBound ; "branch and bound")]
#[test_case(SelectionStrategy::OptimalConsolidation ; "optimal consolidation")]
#[test_case(SelectionStrategy::Random ; "random")]
#[test_case(SelectionStrategy::All ; "drain")]
#[tokio::test]
async fn a_wallet_holding_only_its_collateral_has_nothing_to_send(strategy: SelectionStrategy) {
    let (mut ctx, _collateral, _) = registered_wallet(None).await;

    assert!(is_out_of_coins(send(&mut ctx, DASH, strategy)));
    assert!(ctx.managed_wallet.get_spendable_utxos().is_empty());
    let balance = ctx.managed_wallet.balance();
    assert_eq!(balance.spendable(), 0, "the collateral is not spendable balance");
    assert_eq!(balance.locked(), COLLATERAL);
    assert_eq!(balance.total(), COLLATERAL, "the collateral still counts toward the total");
}

/// The lock comes from the registration, not the amount: the same 1,000 DASH
/// coin is an ordinary coin until a ProRegTx names it.
#[tokio::test]
async fn a_collateral_sized_coin_nobody_registered_is_spendable() {
    let mut ctx = TestWalletContext::new_random();
    let big = receive(&mut ctx, COLLATERAL, 0x01, 100).await;
    receive(&mut ctx, SPARE, 0x02, 100).await;
    ctx.managed_wallet.update_last_processed_height(TIP);

    let tx = send(&mut ctx, DASH, SelectionStrategy::LargestFirst).expect("funded");

    assert_eq!(spent(&tx), vec![big]);
    assert!(ctx.managed_wallet.locked_outpoints().is_empty());
}

#[test_case(true ; "collateral first")]
#[test_case(false ; "registration first")]
#[tokio::test]
async fn a_registration_locks_its_external_collateral_whichever_arrives_first(
    collateral_first: bool,
) {
    let mut ctx = TestWalletContext::new_random();
    let collateral_tx = Transaction::dummy(&ctx.receive_address, 0x01..0x02, &[COLLATERAL]);
    let collateral = OutPoint::new(collateral_tx.txid(), 0);
    let registration = registration(collateral, vec![], 0xEE);

    let registered = if collateral_first {
        ctx.check_transaction(&collateral_tx, block(100)).await;
        ctx.check_transaction(&registration, block(101)).await
    } else {
        // A rescan can hand over the later block first.
        let registered = ctx.check_transaction(&registration, block(101)).await;
        assert!(ctx.managed_wallet.is_outpoint_locked(&collateral), "locked before it arrives");
        ctx.check_transaction(&collateral_tx, block(100)).await;
        registered
    };

    // No separate balance refresh: the checks leave the balance right.
    assert!(!registered.is_relevant, "nothing but the collateral ties it to this wallet");
    assert_eq!(registered.locked_outpoints, vec![collateral]);
    assert!(registered.state_modified, "the lock set is persisted state");
    assert!(ctx.bip44_account().utxos[&collateral].is_locked);
    assert_eq!(ctx.managed_wallet.balance().locked(), COLLATERAL);
    assert!(is_out_of_coins(send(&mut ctx, DASH, SelectionStrategy::LargestFirst)));
}

#[test_case(&[TransactionContext::Mempool, block(101)] ; "seen in the mempool, then mined")]
#[test_case(&[block(101)] ; "first seen mined")]
#[tokio::test]
async fn a_registration_locks_the_collateral_it_creates(sightings: &[TransactionContext]) {
    let mut ctx = TestWalletContext::new_random();
    let to_wallet = TxOut {
        value: COLLATERAL,
        script_pubkey: ctx.receive_address.script_pubkey(),
    };
    let to_elsewhere = TxOut {
        value: DASH,
        script_pubkey: elsewhere().assume_checked().script_pubkey(),
    };
    // A null collateral txid: the collateral is this ProRegTx's output 1.
    let registration =
        registration(OutPoint::new(Txid::all_zeros(), 1), vec![to_elsewhere, to_wallet], 0xEE);
    let collateral = OutPoint::new(registration.txid(), 1);

    let mut reported = Vec::new();
    for context in sightings {
        let result = ctx.check_transaction(&registration, context.clone()).await;
        assert!(result.is_relevant, "the collateral pays this wallet");
        reported.extend(result.locked_outpoints);
        assert!(
            ctx.bip44_account().utxos[&collateral].is_locked,
            "the coin is locked from its first sighting, in {context}"
        );
    }
    ctx.managed_wallet.update_last_processed_height(TIP);

    assert_eq!(reported, vec![collateral], "reported once, when first locked");
    assert_eq!(ctx.managed_wallet.balance().locked(), COLLATERAL);
    assert!(is_out_of_coins(send(&mut ctx, DASH, SelectionStrategy::LargestFirst)));
}

#[tokio::test]
async fn unlocking_lets_a_send_spend_the_collateral_and_relocking_stops_it_again() {
    let (mut ctx, collateral, _) = registered_wallet(None).await;
    assert!(is_out_of_coins(send(&mut ctx, DASH, SelectionStrategy::LargestFirst)));

    assert!(ctx.managed_wallet.unlock_outpoint(&collateral));
    assert!(!ctx.managed_wallet.unlock_outpoint(&collateral), "already unlocked");
    assert_eq!(ctx.managed_wallet.balance().spendable(), COLLATERAL);
    assert_eq!(ctx.managed_wallet.balance().locked(), 0);
    let tx = send(&mut ctx, DASH, SelectionStrategy::LargestFirst).expect("unlocked");
    assert_eq!(spent(&tx), vec![collateral]);

    assert!(ctx.managed_wallet.lock_outpoint(collateral));
    assert!(!ctx.managed_wallet.lock_outpoint(collateral), "already locked");
    assert_eq!(ctx.managed_wallet.balance().locked(), COLLATERAL);
    assert!(is_out_of_coins(send(&mut ctx, DASH, SelectionStrategy::LargestFirst)));
}

/// Core ties the lock to the masternode list, which only spending the
/// collateral leaves: a revocation keeps the masternode registered, and a new
/// ProRegTx naming the same collateral replaces the registration.
#[tokio::test]
async fn a_revocation_or_a_replacing_registration_keeps_the_collateral_locked() {
    let (mut ctx, collateral, spare) = registered_wallet(Some(SPARE)).await;
    let original = registration(collateral, vec![], 0xEE);

    let revocation = Transaction {
        version: 3,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([0xEF; 32]), 0),
            ..Default::default()
        }],
        output: Vec::new(),
        special_transaction_payload: Some(TransactionPayload::ProviderUpdateRevocationPayloadType(
            ProviderUpdateRevocationPayload {
                version: 1,
                pro_tx_hash: original.txid(),
                reason: 0,
                inputs_hash: InputsHash::all_zeros(),
                payload_sig: BLSSignature::from([0; 96]),
            },
        )),
    };
    assert!(ctx.check_transaction(&revocation, block(102)).await.locked_outpoints.is_empty());
    assert!(ctx.managed_wallet.is_outpoint_locked(&collateral));

    let replacement = registration(collateral, vec![], 0xF0);
    let replaced = ctx.check_transaction(&replacement, block(103)).await;
    assert!(replaced.locked_outpoints.is_empty(), "already locked, nothing new to report");
    assert!(ctx.managed_wallet.is_outpoint_locked(&collateral));

    ctx.managed_wallet.update_last_processed_height(TIP);
    let tx = send(&mut ctx, DASH, SelectionStrategy::LargestFirst).expect("the spare coin");
    assert_eq!(spent(&tx), vec![spare.expect("spare coin")]);
}

/// Only spending the collateral ends a registration. The coin leaves; its
/// entry stays and has nothing to act on, so a spend that is reorged out or
/// swept brings the coin back locked.
#[tokio::test]
async fn spending_the_collateral_removes_the_coin_but_not_its_lock() {
    let (mut ctx, collateral, _) = registered_wallet(None).await;
    let spend = Transaction {
        version: 1,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: collateral,
            ..Default::default()
        }],
        output: vec![TxOut {
            value: COLLATERAL - 1_000,
            script_pubkey: elsewhere().assume_checked().script_pubkey(),
        }],
        special_transaction_payload: None,
    };

    assert!(ctx.check_transaction(&spend, block(150)).await.is_relevant);

    assert!(!ctx.bip44_account().utxos.contains_key(&collateral));
    assert!(ctx.managed_wallet.is_outpoint_locked(&collateral));
    assert_eq!(ctx.managed_wallet.balance().total(), 0);
}

#[tokio::test]
async fn a_preview_check_locks_nothing() {
    let mut ctx = TestWalletContext::new_random();
    let collateral = receive(&mut ctx, COLLATERAL, 0x01, 100).await;

    let preview = ctx
        .managed_wallet
        .check_core_transaction(
            &registration(collateral, vec![], 0xEE),
            block(101),
            &mut ctx.wallet,
            false,
            false,
        )
        .await;

    assert!(preview.locked_outpoints.is_empty());
    assert!(!ctx.managed_wallet.is_outpoint_locked(&collateral));
    assert!(!ctx.bip44_account().utxos[&collateral].is_locked);
}

/// Block processing checks each transaction with `update_balance = false` and
/// refreshes the balance once per block. The coin must be locked in between,
/// not only after that refresh.
#[tokio::test]
async fn a_collateral_is_locked_even_before_the_next_balance_refresh() {
    let mut ctx = TestWalletContext::new_random();
    let collateral = receive(&mut ctx, COLLATERAL, 0x01, 100).await;

    let result = ctx
        .managed_wallet
        .check_core_transaction(
            &registration(collateral, vec![], 0xEE),
            block(101),
            &mut ctx.wallet,
            true,
            false,
        )
        .await;

    assert_eq!(result.locked_outpoints, vec![collateral]);
    assert!(ctx.bip44_account().utxos[&collateral].is_locked);
    assert!(ctx.managed_wallet.get_spendable_utxos().is_empty());
}

/// The lock set is the source of truth: a flag written on a held coin by hand
/// is set back from the set on the next balance refresh.
#[tokio::test]
async fn a_held_coins_lock_flag_follows_the_lock_set() {
    let (mut ctx, collateral, spare) = registered_wallet(Some(SPARE)).await;
    let spare = spare.expect("spare coin");
    let account = ctx.managed_wallet.first_bip44_managed_account_mut().expect("BIP44 account");
    account.utxos.get_mut(&collateral).expect("collateral").is_locked = false;
    account.utxos.get_mut(&spare).expect("spare").is_locked = true;

    ctx.managed_wallet.update_balance();

    assert!(ctx.bip44_account().utxos[&collateral].is_locked);
    assert!(!ctx.bip44_account().utxos[&spare].is_locked);
    assert_eq!(ctx.managed_wallet.balance().locked(), COLLATERAL);
    assert_eq!(ctx.managed_wallet.balance().spendable(), SPARE);
}

#[test_case(false ; "a set amount")]
#[test_case(true ; "a drain")]
#[tokio::test]
async fn the_asset_lock_builder_skips_the_collateral(drain: bool) {
    let (mut ctx, _collateral, spare) = registered_wallet(Some(SPARE)).await;
    let credit = CreditOutputFunding {
        output: TxOut {
            value: DASH,
            script_pubkey: elsewhere().assume_checked().script_pubkey(),
        },
        funding_type: AssetLockFundingType::AssetLockAddressTopUp,
        identity_index: 0,
    };

    let built = ctx
        .managed_wallet
        .build_asset_lock(
            &ctx.wallet,
            &[AccountTypePreference::BIP44],
            0,
            vec![credit],
            1000,
            drain,
        )
        .await
        .expect("the spare coin funds the asset lock");

    assert_eq!(spent(&built.transaction), vec![spare.expect("spare coin")]);
}

#[tokio::test]
async fn the_asset_lock_builder_has_nothing_to_lock_from_the_collateral_alone() {
    let (mut ctx, _collateral, _) = registered_wallet(None).await;
    let credit = CreditOutputFunding {
        output: TxOut {
            value: DASH,
            script_pubkey: elsewhere().assume_checked().script_pubkey(),
        },
        funding_type: AssetLockFundingType::AssetLockAddressTopUp,
        identity_index: 0,
    };

    let built = ctx
        .managed_wallet
        .build_asset_lock(&ctx.wallet, &[AccountTypePreference::BIP44], 0, vec![credit], 1000, true)
        .await;

    assert!(
        matches!(
            built,
            Err(AssetLockError::Builder(BuilderError::CoinSelection(
                SelectionError::NoUtxosAvailable
            )))
        ),
        "only the collateral is left, and it is locked"
    );
}

/// A ProUpServTx placeholder: special transactions such as provider updates
/// fund their fee through `add_funding`.
fn provider_update_service() -> TransactionPayload {
    TransactionPayload::ProviderUpdateServicePayloadType(ProviderUpdateServicePayload::new(
        Some(0),
        Txid::all_zeros(),
        0x00000000000000000000ffff7f000001, // 127.0.0.1 mapped
        19999,
        ScriptBuf::new(),
        InputsHash::all_zeros(),
        None,
        None,
        None,
        BLSSignature::from([0; 96]),
    ))
}

/// A copy of the collateral cloned before it was locked, or built by the
/// caller, still carries an unlocked flag.
fn stale_copy(ctx: &TestWalletContext, collateral: OutPoint) -> Utxo {
    let mut stale = ctx.bip44_account().utxos[&collateral].clone();
    stale.is_locked = false;
    stale
}

#[tokio::test]
async fn special_transaction_funding_skips_the_collateral_even_when_seeded() {
    let (mut ctx, collateral, spare) = registered_wallet(Some(SPARE)).await;
    let stale = stale_copy(&ctx, collateral);
    let account = ctx.wallet.accounts.standard_bip44_accounts.get(&0).expect("BIP44").clone();
    let funds = ctx.managed_wallet.accounts.standard_bip44_accounts.get_mut(&0).expect("BIP44");

    let (tx, _fee, _reservation) = TransactionBuilder::new()
        .set_current_height(TIP)
        .set_fee_rate(FeeRate::normal())
        .add_inputs([stale])
        .add_funding(funds, &account)
        .set_special_payload(provider_update_service())
        .build_unsigned_reserved()
        .expect("the spare coin pays the fee");

    assert_eq!(spent(&tx), vec![spare.expect("spare coin")]);
}

/// The chunked drain path offers only what the caller seeds; a seeded copy of
/// a coin the account holds locked is dropped all the same.
#[tokio::test]
async fn reservation_only_funding_drops_a_seeded_collateral() {
    let (mut ctx, collateral, _) = registered_wallet(None).await;
    let stale = stale_copy(&ctx, collateral);
    let account = ctx.wallet.accounts.standard_bip44_accounts.get(&0).expect("BIP44").clone();
    let funds = ctx.managed_wallet.accounts.standard_bip44_accounts.get_mut(&0).expect("BIP44");

    let result = TransactionBuilder::new()
        .set_current_height(TIP)
        .set_selection_strategy(SelectionStrategy::All)
        .add_inputs([stale])
        .add_funding_reservation_only(funds, &account)
        .add_output(&elsewhere().assume_checked(), DASH)
        .build_unsigned_reserved();

    assert!(matches!(result, Err(BuilderError::CoinSelection(SelectionError::NoUtxosAvailable))));
}

#[cfg(feature = "serde")]
#[test]
fn locks_survive_a_serialization_round_trip() {
    use crate::managed_account::ManagedCoreFundsAccount;
    use crate::wallet::ManagedWalletInfo;

    let mut info = ManagedWalletInfo::dummy(1);
    let mut account = ManagedCoreFundsAccount::dummy_bip44();
    let collateral = Utxo::dummy(1, COLLATERAL, 100, false, true);
    let spare = Utxo::dummy(2, SPARE, 100, false, true);
    account.utxos.insert(collateral.outpoint, collateral.clone());
    account.utxos.insert(spare.outpoint, spare.clone());
    info.accounts.insert(account).expect("account");
    // Locked before the coin arrives, as when a registration is seen first.
    let arriving = Utxo::dummy(3, COLLATERAL, 100, false, true);
    info.lock_outpoint(collateral.outpoint);
    info.lock_outpoint(arriving.outpoint);

    let json = serde_json::to_string(&info).expect("serialize");
    let mut restored: ManagedWalletInfo = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(restored.locked_outpoints(), info.locked_outpoints());
    restored.update_last_processed_height(TIP);
    let spendable: Vec<OutPoint> =
        restored.get_spendable_utxos().into_iter().map(|utxo| utxo.outpoint).collect();
    assert_eq!(spendable, vec![spare.outpoint]);
    assert_eq!(restored.balance().locked(), COLLATERAL);

    // The lock taken before the coin arrived still applies after the reload.
    let account = restored.first_bip44_managed_account_mut().expect("BIP44 account");
    account.utxos.insert(arriving.outpoint, arriving.clone());
    restored.update_balance();
    assert_eq!(restored.balance().locked(), 2 * COLLATERAL);
    assert_eq!(restored.balance().spendable(), SPARE);
}

/// A snapshot written before the lock set existed loads with no locks.
#[cfg(feature = "serde")]
#[test]
fn a_snapshot_without_locks_loads_with_none() {
    use crate::wallet::ManagedWalletInfo;

    let mut info = ManagedWalletInfo::dummy(2);
    info.lock_outpoint(OutPoint::new(Txid::from_byte_array([0x42; 32]), 0));
    let mut json = serde_json::to_value(&info).expect("serialize");
    json.as_object_mut().expect("object").remove("locked_outpoints").expect("the field");

    let restored: ManagedWalletInfo = serde_json::from_value(json).expect("deserialize");

    assert!(restored.locked_outpoints().is_empty());
}
