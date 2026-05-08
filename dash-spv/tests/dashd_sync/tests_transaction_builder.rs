//! End-to-end tests for the in-wallet `TransactionBuilder` against a real
//! dashd regtest node.
//!
//! These tests exercise the path that recently landed in `key-wallet`:
//! `ManagedWalletInfo::build_and_sign_transaction` (which builds via
//! `TransactionBuilder` and signs through the wallet's root extended private
//! key). The transaction is broadcast through the SPV client, so dashd
//! receives the bytes our builder produced and validates them like any other
//! peer-relayed transaction.
//!
//! The two scenarios target balance that the wallet *believes* it can spend
//! but that the coin selector may filter out:
//!
//! 1. **Mempool change**: after we send funds to an external address, the
//!    change UTXO returns to the wallet flagged as `is_trusted` (mirrors
//!    Bitcoin Core's `IsTrusted`). `update_balance` credits it to the
//!    confirmed bucket, so callers reading `spendable()` see it as
//!    available — but the next build can fail because coin selection
//!    skips anything that is not literally `is_confirmed || is_instantlocked`.
//!
//! 2. **Unconfirmed incoming**: a payment that arrives via the mempool to
//!    one of our addresses without us having any input in the funding tx.
//!    Such a UTXO is *not* trusted; spending it without confirmation /
//!    InstantLock is a deliberate policy choice the test pins.
//!
//! Both tests run against a wallet built from a *fresh* mnemonic so that
//! the SPV side has no preexisting confirmed UTXOs from the regtest test
//! chain — that's important because the dashd "default" wallet shares its
//! mnemonic with the standard test fixture, and reusing it would leave the
//! wallet with plenty of confirmed funds the coin selector could fall back
//! on, masking the very behavior these tests need to inspect.

use std::sync::Arc;
use std::time::Duration;

use dash_spv::Network;
use dashcore::address::NetworkUnchecked;
use dashcore::{Address, Amount, Network as DashNetwork};
use key_wallet::account::ManagedAccountTrait;
use key_wallet::managed_account::managed_account_type::ManagedAccountType;
use key_wallet::wallet::managed_wallet_info::fee::FeeRate;
use key_wallet::wallet::managed_wallet_info::transaction_builder::BuilderError;
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::{WalletId, WalletManager};
use tokio::sync::RwLock;

use super::helpers::{
    wait_for_mempool_tx, wait_for_sync, wait_for_wallet_synced, EMPTY_MNEMONIC, SECONDARY_MNEMONIC,
};
use super::setup::{create_and_start_client, create_test_wallet, ClientHandle, TestContext};
use dash_spv::test_utils::TestChain;

const MEMPOOL_TIMEOUT: Duration = Duration::from_secs(30);

/// Derive a fresh BIP44 external receive address for `mnemonic` without
/// touching the live wallet manager. Mirrors the helper in
/// `tests_multi_wallet.rs` so we can reserve a funding address before the
/// SPV client is even running.
async fn reserve_first_address(mnemonic: &str) -> Address {
    let (temp_mgr, temp_id) = create_test_wallet(mnemonic, Network::Regtest);
    let reader = temp_mgr.read().await;
    let info = reader.get_wallet_info(&temp_id).expect("temp wallet info");
    let account =
        info.accounts().standard_bip44_accounts.get(&0).expect("temp wallet BIP44 account 0");
    let ManagedAccountType::Standard {
        external_addresses,
        ..
    } = &account.managed_account_type()
    else {
        panic!("temp wallet account 0 is not a Standard account type");
    };
    external_addresses
        .unused_addresses()
        .into_iter()
        .next()
        .expect("temp wallet receive address available")
}

/// Build and sign a transaction using the SPV wallet's `TransactionBuilder`
/// (via `ManagedWalletInfo::build_and_sign_transaction`).
///
/// Acquires the wallet manager write lock for the duration of the build+sign
/// so the immutable `Wallet` and mutable `ManagedWalletInfo` borrows stay
/// coherent across the async signing step.
async fn build_and_sign(
    wallet: &Arc<RwLock<WalletManager<ManagedWalletInfo>>>,
    wallet_id: &WalletId,
    destination: &Address,
    amount: u64,
) -> Result<(dashcore::Transaction, u64), BuilderError> {
    let dest_unchecked: Address<NetworkUnchecked> =
        destination.to_string().parse().expect("destination address parses");

    let mut wallet_lock = wallet.write().await;
    let (w, info) =
        wallet_lock.get_wallet_and_info_mut(wallet_id).expect("wallet present in manager");

    info.build_and_sign_transaction(w, 0, vec![(dest_unchecked, amount)], FeeRate::normal()).await
}

/// Spendable balance reported to UI surfaces: includes trusted mempool
/// change in the confirmed bucket. "What the user thinks they can spend."
async fn reported_spendable(
    wallet: &Arc<RwLock<WalletManager<ManagedWalletInfo>>>,
    wallet_id: &WalletId,
) -> u64 {
    let reader = wallet.read().await;
    reader.get_wallet_balance(wallet_id).expect("balance lookup").spendable()
}

/// Spawn an SPV client backed by a fresh wallet (different mnemonic from
/// the dashd default), so the SPV side starts with zero confirmed UTXOs.
/// Returns the manager, the wallet id, and the running client handle.
async fn spawn_fresh_wallet_client(
    ctx: &TestContext,
    mnemonic: &str,
) -> (Arc<RwLock<WalletManager<ManagedWalletInfo>>>, WalletId, ClientHandle) {
    let (wallet, wallet_id) = create_test_wallet(mnemonic, Network::Regtest);
    let handle = create_and_start_client(&ctx.client_config, Arc::clone(&wallet)).await;
    (wallet, wallet_id, handle)
}

/// Verify that a confirmed UTXO can be spent through the wallet's
/// `TransactionBuilder`, and that the resulting change UTXO (which lands in
/// the mempool flagged `is_trusted`) is then itself spendable for a follow-up
/// transaction.
///
/// This is the regression case for the bug where a wallet shows a non-zero
/// `spendable()` balance — because `update_balance` credits trusted mempool
/// change to the confirmed bucket — but the coin selector refuses to use
/// that UTXO because it filters on `is_confirmed || is_instantlocked` only,
/// not `is_trusted`. A user in that state sees their funds in the UI but
/// `build_and_sign_transaction` returns `InsufficientFunds` / a coin
/// selection error.
#[tokio::test]
async fn test_spend_unconfirmed_change_balance() {
    let Some(ctx) = TestContext::new(TestChain::Minimal).await else {
        return;
    };
    if !ctx.dashd.supports_mining {
        eprintln!("Skipping test (dashd RPC miner not available)");
        return;
    }

    let (wallet, wallet_id, mut client_handle) =
        spawn_fresh_wallet_client(&ctx, EMPTY_MNEMONIC).await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.initial_height).await;
    assert_eq!(
        reported_spendable(&wallet, &wallet_id).await,
        0,
        "fresh-mnemonic wallet should start with zero spendable balance"
    );

    // Step 1: fund the SPV wallet with a confirmed UTXO from dashd's
    // default wallet (an external sender, since it uses a different
    // mnemonic).
    let receive_address = reserve_first_address(EMPTY_MNEMONIC).await;
    let funding_amount = Amount::from_sat(500_000_000);
    let funding_txid = ctx.dashd.node.send_to_address(&receive_address, funding_amount);
    tracing::info!("Funded fresh SPV wallet with {}, txid: {}", funding_amount, funding_txid);

    let miner_address = ctx.dashd.node.get_new_address_from_wallet("default");
    ctx.dashd.node.generate_blocks(1, &miner_address);
    let funded_height = ctx.dashd.initial_height + 1;
    wait_for_sync(&mut client_handle.progress_receiver, funded_height).await;
    wait_for_wallet_synced(&wallet, &wallet_id, funded_height).await;

    let initial_spendable = reported_spendable(&wallet, &wallet_id).await;
    assert_eq!(
        initial_spendable,
        funding_amount.to_sat(),
        "wallet should report exactly the funding amount as spendable"
    );

    // Step 2: build + sign + broadcast a tx that sends part of the funding
    // UTXO to an external (dummy) address. The remainder lands as a mempool
    // change UTXO on a freshly-derived internal address.
    let external_dest_a = Address::dummy(DashNetwork::Regtest, 1);
    let send_amount = 100_000_000u64;
    let (signed_tx_a, fee_a) = build_and_sign(&wallet, &wallet_id, &external_dest_a, send_amount)
        .await
        .expect("first build_and_sign should succeed against a confirmed UTXO");
    tracing::info!(
        "Built and signed first tx: txid={}, fee={}, inputs={}, outputs={}",
        signed_tx_a.txid(),
        fee_a,
        signed_tx_a.input.len(),
        signed_tx_a.output.len()
    );

    // Sanity: change must come back to one of our internal addresses.
    let external_script = external_dest_a.script_pubkey();
    let change_output = signed_tx_a
        .output
        .iter()
        .find(|o| o.script_pubkey != external_script)
        .expect("first tx must have a change output (otherwise nothing to spend in step 4)");
    let expected_change_value = change_output.value;
    tracing::info!("Expected mempool change value: {}", expected_change_value);

    client_handle.client.broadcast_transaction(&signed_tx_a).await.expect("broadcast first tx");

    // Wait for the wallet to actually ingest the broadcast tx (dispatch_local
    // hands it to the mempool manager, which routes through the wallet
    // checker). Until this fires, the change UTXO isn't in `info.utxos()`.
    let detected_a = wait_for_mempool_tx(&mut client_handle.wallet_event_receiver, MEMPOOL_TIMEOUT)
        .await
        .expect("SPV wallet should detect its own broadcast tx via the mempool path");
    assert_eq!(detected_a, signed_tx_a.txid(), "detected txid must match what we broadcast");

    // The original funding UTXO is now spent; the change UTXO is in the
    // mempool. From the user's perspective the balance is essentially the
    // same (funding − send − fee), and `spendable()` should reflect that
    // because `is_trusted` change goes into the confirmed bucket.
    let spendable_after_first = reported_spendable(&wallet, &wallet_id).await;
    assert!(
        spendable_after_first >= expected_change_value,
        "wallet should still report the change as spendable (got {}, expected >= {})",
        spendable_after_first,
        expected_change_value
    );

    // Step 3: try to spend that mempool change UTXO. The amount is small
    // enough to come out of just the change UTXO (we no longer have any
    // other balance), and large enough to clearly require it.
    let external_dest_b = Address::dummy(DashNetwork::Regtest, 2);
    let second_send = expected_change_value / 2;
    let result_b = build_and_sign(&wallet, &wallet_id, &external_dest_b, second_send).await;

    match result_b {
        Ok((signed_tx_b, fee_b)) => {
            tracing::info!(
                "Second build_and_sign succeeded: txid={}, fee={}",
                signed_tx_b.txid(),
                fee_b
            );

            // The second tx must be spending the mempool change UTXO from
            // the first tx — that's the only output the wallet has left.
            let prior_txid = signed_tx_a.txid();
            assert!(
                signed_tx_b.input.iter().any(|i| i.previous_output.txid == prior_txid),
                "second tx must spend the mempool change UTXO produced by the first tx"
            );

            client_handle
                .client
                .broadcast_transaction(&signed_tx_b)
                .await
                .expect("broadcast second tx");

            let detected_b =
                wait_for_mempool_tx(&mut client_handle.wallet_event_receiver, MEMPOOL_TIMEOUT)
                    .await
                    .expect("SPV wallet should detect the chained spend via mempool");
            assert_eq!(detected_b, signed_tx_b.txid());
        }
        Err(e) => {
            // This is the bug we want this test to surface. The wallet
            // reported the change as spendable, but coin selection refused
            // to actually use it. Fail loudly with the diagnostic context
            // that will help track down whether the regression is in
            // `is_trusted` propagation or in the coin selector filter.
            panic!(
                "spending mempool change failed despite wallet reporting it as spendable. \
                 reported_spendable={}, expected_change_value={}, error={}",
                spendable_after_first, expected_change_value, e
            );
        }
    }

    client_handle.stop().await;
}

/// Verify the wallet's behavior when asked to spend balance from an
/// **incoming, unconfirmed** transaction (a mempool tx where we own the
/// receiving output but none of the inputs).
///
/// In regtest dashd issues InstantSend locks on standard transactions, so
/// the receiving output arrives flagged `is_instantlocked`. By wallet rules
/// IS-locked UTXOs *are* spendable: `update_balance` credits them to the
/// confirmed bucket and the coin selector includes them. The user's
/// expectation matches that: an incoming, not-yet-mined tx whose finality
/// we trust (here via the IS-lock) should be usable as input for a
/// follow-up transaction.
///
/// The test asserts:
///   1. After the incoming arrives the wallet reports it as spendable.
///   2. `build_and_sign_transaction` succeeds against just that UTXO.
///   3. The follow-up tx, when broadcast, references the unconfirmed
///      incoming txid as its sole input — proving the build actually used
///      the mempool/IS-locked UTXO rather than some hidden fallback.
#[tokio::test]
async fn test_spend_unconfirmed_incoming_balance() {
    let Some(ctx) = TestContext::new(TestChain::Minimal).await else {
        return;
    };
    if !ctx.dashd.supports_mining {
        eprintln!("Skipping test (dashd RPC miner not available)");
        return;
    }

    let (wallet, wallet_id, mut client_handle) =
        spawn_fresh_wallet_client(&ctx, SECONDARY_MNEMONIC).await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.initial_height).await;
    assert_eq!(
        reported_spendable(&wallet, &wallet_id).await,
        0,
        "fresh-mnemonic wallet should start with zero spendable balance"
    );

    // Send a payment to the SPV wallet but do NOT mine it. The funding tx
    // sits in dashd's mempool and propagates to the SPV mempool manager.
    let receive_address = reserve_first_address(SECONDARY_MNEMONIC).await;
    let incoming_amount = Amount::from_sat(300_000_000);
    let incoming_txid = ctx.dashd.node.send_to_address(&receive_address, incoming_amount);
    tracing::info!("Sent incoming tx (NOT mined): {}", incoming_txid);

    let detected = wait_for_mempool_tx(&mut client_handle.wallet_event_receiver, MEMPOOL_TIMEOUT)
        .await
        .expect("SPV should detect the incoming mempool tx");
    assert_eq!(detected, incoming_txid);

    let spendable_after = reported_spendable(&wallet, &wallet_id).await;
    let total_after = {
        let reader = wallet.read().await;
        reader.get_wallet_balance(&wallet_id).expect("balance lookup").total()
    };
    tracing::info!(
        "After unconfirmed incoming: spendable_reported={}, total_reported={}, incoming_amount={}",
        spendable_after,
        total_after,
        incoming_amount.to_sat()
    );
    assert_eq!(
        total_after,
        incoming_amount.to_sat(),
        "incoming UTXO should be visible in total balance"
    );
    assert_eq!(
        spendable_after,
        incoming_amount.to_sat(),
        "incoming IS-locked / mempool UTXO should be reported as spendable in regtest"
    );

    // Try to spend half of the incoming amount through the builder. The
    // wallet's only UTXO is the unconfirmed incoming one, so a successful
    // build proves the coin selector used it.
    let dest = Address::dummy(DashNetwork::Regtest, 3);
    let attempt_amount = incoming_amount.to_sat() / 2;
    let (signed_tx, fee) = build_and_sign(&wallet, &wallet_id, &dest, attempt_amount).await.expect(
        "build_and_sign must succeed against an unconfirmed incoming UTXO whose balance \
             the wallet itself reports as spendable",
    );
    tracing::info!(
        "Spent unconfirmed incoming: txid={}, fee={}, inputs={}",
        signed_tx.txid(),
        fee,
        signed_tx.input.len()
    );

    // The chained spend must reference the unconfirmed incoming tx as a
    // parent — anything else means coin selection picked a different UTXO
    // (and there should be no other UTXOs in this fresh wallet).
    assert!(
        signed_tx.input.iter().any(|i| i.previous_output.txid == incoming_txid),
        "spend must reference the unconfirmed incoming txid {} as a parent",
        incoming_txid
    );

    // Broadcast and verify the network accepts the chained spend.
    client_handle
        .client
        .broadcast_transaction(&signed_tx)
        .await
        .expect("broadcast chained spend of unconfirmed incoming");

    let detected_spend =
        wait_for_mempool_tx(&mut client_handle.wallet_event_receiver, MEMPOOL_TIMEOUT)
            .await
            .expect("SPV should detect the chained spend via mempool");
    assert_eq!(detected_spend, signed_tx.txid());

    client_handle.stop().await;
}
