//! A UTXO that `key-wallet` marked `is_confirmed = true` stays reported as
//! spendable/selectable after the real Dash testnet network has genuinely
//! spent it — surfaced through the wallet's own public balance/UTXO-query
//! API, the same surface `platform-wallet`'s asset-lock builder consumes.
//!
//! Defect site: `key-wallet/src/managed_account/managed_core_funds_account.rs`
//! (`update_utxos`'s spent-outpoint removal loop — `self.utxos.remove(&input
//! .previous_output)` only runs for transactions this account's block/event
//! pipeline actually processes). That function's own long-standing comment
//! already acknowledges the risk class: "Check if this outpoint was already
//! spent by a transaction we've seen. This handles out-of-order block
//! processing during rescan... TODO: This is mostly needed for wallet rescan
//! from storage — there is a timing issue with event processing which might
//! lead to invalid UTXO set / balances."
//! No upstream issue filed yet — see dash-evo-tool's
//! `docs/ai-design/2026-07-07-asset-lock-finality-retest/retest-findings.md`
//! (§16-18) for the full investigation this repro is drawn from.
//!
//! ## Real-world background
//!
//! dash-evo-tool's asset-lock identity registration
//! (`platform-wallet`'s `create_funded_asset_lock_proof`, built on
//! `key-wallet`'s `TransactionBuilder::require_final_inputs`) repeatedly
//! failed with a 300s `FinalityTimeout` against this exact wallet, even
//! immediately after a full, uninterrupted, from-genesis rescan and a fresh
//! real deposit. Tracing the failing asset-lock transaction's funding input
//! on the public testnet block explorer
//! (<https://insight.testnet.networks.dash.org/insight-api>) showed the
//! selected UTXO `5c43cd895754b925234950f5e94a7cdfd73b315a6d2eef9eee1b44de03d58de7:1`
//! was confirmed for real at block 1474688, but its output was *already
//! spent* at block 1474746 by txid
//! `f9ca52d513f2801a2aec9d222f3d958748254ffb7a4532c6c44b22a111b638c7` —
//! roughly 35,400+ confirmations before the failing attempt reused it.
//! `require_final_inputs` accepts this UTXO because its `is_confirmed` flag
//! was correctly `true` when it was created and was never invalidated by the
//! later spend.
//!
//! ## Why this test is live-network rather than synthetic
//!
//! Unlike this branch's other crate-level repros (deterministic, no
//! network), this defect is specifically about a rescan losing track of a
//! *real* historical spend — reproducing it synthetically would require
//! faithfully replaying two independent real block-processing passes across
//! genuine chain reorgs/timing, which is exactly what's in question. This
//! test instead restores the actual affected wallet and syncs it against
//! real Dash testnet, observing the result purely through `key-wallet` +
//! `dash-spv`'s public API — no internal fields or private methods (no
//! direct `update_utxos` call, no reaching into `ManagedCoreFundsAccount`
//! internals) — the same surface a downstream consumer like
//! `platform-wallet` uses:
//! `WalletManager::create_wallet_from_mnemonic`, a real `DashSpvClient`,
//! `ManagedCoreFundsAccount::spendable_utxos` (the coin-selector's own
//! candidate-set query), and `ManagedWalletInfo::build_asset_lock` (the
//! same asset-lock entry point `platform-wallet` calls into).
//!
//! ## Test lifecycle
//!
//! RED today: the known-dead outpoint above is still reported spendable, and
//! a real `build_asset_lock` call selects it as funding. GREEN once
//! `update_utxos` (or whatever upstream layer feeds it) reliably observes
//! and removes a real spend of a previously-tracked UTXO, regardless of
//! rescan timing.
//!
//! ## Running this test
//!
//! Requires the real, already-funded testnet mnemonic this bug was observed
//! against, via `ASSET_LOCK_REPRO_MNEMONIC` (not hardcoded — testnet-only
//! wallet, holds no value beyond dust test coins, but kept out of the
//! committed diff regardless). Takes a few minutes: rescans the real
//! testnet chain across the ~750-block window spanning the UTXO's creation
//! and its real spend.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use dash_spv::network::PeerNetworkManager;
use dash_spv::storage::DiskStorageManager;
use dash_spv::{ClientConfig, DashSpvClient};
use dashcore::{Network, OutPoint, ScriptBuf, TxOut, Txid};
use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::wallet::managed_wallet_info::asset_lock_builder::{
    AssetLockFundingType, CreditOutputFunding,
};
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::WalletManager;
use tempfile::TempDir;
use tokio::sync::RwLock;

/// One block before the funding UTXO's own creation height (1474688), so the
/// rescan naturally replays both its insertion and its later real spend
/// (1474746) without needing to replay the full ~1.5M-block testnet history.
const BIRTH_HEIGHT: u32 = 1_474_000;

/// Per Insight, confirmed at block 1474688, spent for real at block 1474746
/// by txid f9ca52d513f2801a2aec9d222f3d958748254ffb7a4532c6c44b22a111b638c7.
const STALE_FUNDING_TXID: &str = "5c43cd895754b925234950f5e94a7cdfd73b315a6d2eef9eee1b44de03d58de7";
const STALE_FUNDING_VOUT: u32 = 1;
const REAL_SPEND_HEIGHT: u32 = 1_474_746;

/// One credit-output funding spec, matching the shape used by
/// `key-wallet/tests/asset_lock_builder_failed_build.rs` — the minimum to
/// drive `build_asset_lock` into real coin selection.
fn one_credit_output(amount: u64) -> Vec<CreditOutputFunding> {
    vec![CreditOutputFunding {
        output: TxOut {
            value: amount,
            script_pubkey: ScriptBuf::from(vec![
                0x76, 0xa9, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x88, 0xac,
            ]),
        },
        funding_type: AssetLockFundingType::AssetLockAddressTopUp,
        identity_index: 0,
    }]
}

#[tokio::test]
async fn stale_spent_utxo_still_reported_selectable() {
    let mnemonic = std::env::var("ASSET_LOCK_REPRO_MNEMONIC").expect(
        "set ASSET_LOCK_REPRO_MNEMONIC to the real testnet mnemonic this bug was observed \
         against (see module docs) — not hardcoded here on purpose",
    );

    let storage_dir = TempDir::new().expect("failed to create temp storage dir");
    let config = ClientConfig::testnet()
        .with_storage_path(storage_dir.path())
        .with_start_height(BIRTH_HEIGHT)
        .without_masternodes();

    let mut wallet_manager = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);
    let wallet_id = wallet_manager
        .create_wallet_from_mnemonic(&mnemonic, BIRTH_HEIGHT, WalletAccountCreationOptions::Default)
        .expect("failed to restore framework wallet from mnemonic");
    let wallet = Arc::new(RwLock::new(wallet_manager));

    let network_manager =
        PeerNetworkManager::new(&config).await.expect("failed to create network manager");
    let storage_manager =
        DiskStorageManager::new(&config).await.expect("failed to create storage manager");

    let client =
        DashSpvClient::new(config, network_manager, storage_manager, wallet.clone(), vec![])
            .await
            .expect("failed to create SPV client");

    let run_client = client.clone();
    let run_handle = tokio::spawn(async move { run_client.run().await });

    // Poll the real testnet chain tip until the rescan has passed the real
    // spend height, or time out.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(600);
    loop {
        let height = client.tip_height().await;
        if height >= REAL_SPEND_HEIGHT {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "rescan did not reach the real spend height {REAL_SPEND_HEIGHT} within 600s \
             (stuck at {height}) — cannot evaluate the assertions below"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    // Let the wallet finish processing the last few matched blocks/filters
    // after the header/filter tip itself has advanced far enough.
    tokio::time::sleep(Duration::from_secs(10)).await;

    let target_outpoint = OutPoint {
        txid: Txid::from_str(STALE_FUNDING_TXID).expect("valid txid hex"),
        vout: STALE_FUNDING_VOUT,
    };
    let current_height = client.tip_height().await;

    // Primary assertion: the wallet's own public "what can I spend right
    // now" query (`spendable_utxos` — the coin-selector's own candidate-set
    // method, not an internal implementation detail) must not still offer a
    // real-network-dead outpoint.
    let still_selectable = {
        let mut wm = wallet.write().await;
        let (_, info) =
            wm.get_wallet_and_info_mut(&wallet_id).expect("wallet + info must be registered");
        let account = info
            .accounts
            .standard_bip44_accounts
            .get(&0)
            .expect("BIP-44 account 0 must exist on a Default-options wallet");
        account.spendable_utxos(current_height).iter().any(|u| u.outpoint == target_outpoint)
    };

    assert!(
        !still_selectable,
        "BUG: outpoint {target_outpoint} is genuinely spent on real Dash testnet \
         (block {REAL_SPEND_HEIGHT}, txid f9ca52d513f2801a2aec9d222f3d958748254ffb7a4532c6c44b22a111b638c7) \
         but ManagedCoreFundsAccount::spendable_utxos still reports it selectable for \
         BIP-44 account 0 after a rescan spanning both its creation and its real spend. \
         This is the root cause of dash-evo-tool's AssetLockFinalityTimeout: the \
         asset-lock builder's require_final_inputs filter (is_confirmed || \
         is_instantlocked) accepts this UTXO because its is_confirmed flag was \
         correctly set to true at creation and was never invalidated by the later \
         real spend."
    );

    // Secondary, consumer-facing demonstration: a real build_asset_lock call
    // (the same public entry point platform-wallet's create_funded_asset_lock_proof
    // ultimately calls into) large enough to require reaching for the stale
    // UTXO must not select it as funding.
    let build_result = {
        let mut wm = wallet.write().await;
        let (raw_wallet, info) =
            wm.get_wallet_and_info_mut(&wallet_id).expect("wallet + info must be registered");
        info.build_asset_lock(raw_wallet, 0, one_credit_output(100_000_000), 1_000).await
    };

    client.stop().await.ok();
    run_handle.abort();

    if let Ok(result) = build_result {
        let spent_the_dead_utxo =
            result.transaction.input.iter().any(|txin| txin.previous_output == target_outpoint);
        assert!(
            !spent_the_dead_utxo,
            "BUG: build_asset_lock produced a transaction funded by the real-network-dead \
             outpoint {target_outpoint} — the exact failure mode behind dash-evo-tool's \
             AssetLockFinalityTimeout: the built transaction double-spends an output the \
             real network already consumed and can never receive an InstantSend or \
             ChainLock proof."
        );
    }
    // An Err(_) here (e.g. no other funds available) does not invalidate the
    // primary assertion above, which is the deterministic pin for this bug.
}
