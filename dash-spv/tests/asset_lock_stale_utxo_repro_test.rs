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
//! (§16-19) for the full investigation this repro is drawn from.
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
//! ## Why this test is two-phase, not a single continuous sync
//!
//! A first version of this repro (a single, uninterrupted `DashSpvClient`
//! syncing straight from `BIRTH_HEIGHT` through past the real spend height in
//! one pass) does **not** reproduce the defect — the stale outpoint is
//! correctly absent, i.e. GREEN, when run this way. Re-reading the
//! `update_utxos` TODO closely, it names a specific trigger: *"wallet rescan
//! from storage — a timing issue with event processing."* That is
//! specifically about reloading already-persisted prior wallet state from
//! disk and resuming, not a clean single-pass sync from a birth height — the
//! real DET defect lives in a workdir resumed across many sessions over
//! weeks, i.e. repeated persisted-state reloads, which a single continuous
//! sync never exercises.
//!
//! This version instead splits the same window into two phases against the
//! **same on-disk storage directory** (headers/filters persist across the
//! split — nothing is re-downloaded), with a genuine reload of the wallet's
//! own persisted state in between, mimicking an app restart mid-history:
//!
//! - **Phase 1**: sync from `BIRTH_HEIGHT` (1,474,000) to `PHASE1_STOP_HEIGHT`
//!   (1,474,700) — past the UTXO's creation (1,474,688) but short of its real
//!   spend (1,474,746). Stop that client, serialize the wallet's
//!   `ManagedWalletInfo` (its accounts/UTXOs/transactions — the actual
//!   persisted state a real app would save), and drop the in-memory
//!   `WalletManager` entirely.
//! - **Phase 2**: deserialize that `ManagedWalletInfo` into a **brand-new**
//!   `WalletManager`, construct a **brand-new** `DashSpvClient` over the same
//!   storage directory, and resume syncing forward past the real spend
//!   height. This is a genuine reload from persisted state, not a
//!   continuation of the same in-memory instance.
//!
//! If the stale outpoint is still reported selectable after phase 2, that
//! pins the TODO's named trigger precisely. If it is correctly absent even
//! with this structure, that is equally important and reported as such —
//! the real bug would then need a different triggering condition than
//! theorized here.
//!
//! ## Black-box constraint
//!
//! Both phases interact with `key-wallet`/`dash-spv` only through public API
//! — no internal fields, no direct `update_utxos` call. Phase transition uses
//! `ManagedWalletInfo`'s own public `serde` round-trip (the same shape a real
//! persistence layer would serialize), `WalletManager::insert_wallet`, and a
//! fresh `DashSpvClient`/`PeerNetworkManager`/`DiskStorageManager` — the same
//! surface a downstream consumer like `platform-wallet` uses.
//!
//! ## Running this test
//!
//! Requires the real, already-funded testnet mnemonic this bug was observed
//! against, via `ASSET_LOCK_REPRO_MNEMONIC` (not hardcoded — testnet-only
//! wallet, holds no value beyond dust test coins, but kept out of the
//! committed diff regardless). Takes a few minutes: rescans the real
//! testnet chain across the ~750-block window spanning the UTXO's creation
//! and its real spend, split across two client instances.

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

/// One block before the funding UTXO's own creation height (1474688), so
/// phase 1's rescan naturally replays its insertion.
const BIRTH_HEIGHT: u32 = 1_474_000;

/// Past the UTXO's creation (1474688), short of its real spend (1474746).
/// Phase 1 stops here; phase 2 resumes from here after a genuine reload.
const PHASE1_STOP_HEIGHT: u32 = 1_474_700;

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

async fn make_client(
    storage_path: &std::path::Path,
    wallet: Arc<RwLock<WalletManager<ManagedWalletInfo>>>,
) -> DashSpvClient<WalletManager<ManagedWalletInfo>, PeerNetworkManager, DiskStorageManager> {
    let config = ClientConfig::testnet()
        .with_storage_path(storage_path)
        .with_start_height(BIRTH_HEIGHT)
        .without_masternodes();
    let network_manager =
        PeerNetworkManager::new(&config).await.expect("failed to create network manager");
    let storage_manager =
        DiskStorageManager::new(&config).await.expect("failed to create storage manager");
    DashSpvClient::new(config, network_manager, storage_manager, wallet, vec![])
        .await
        .expect("failed to create SPV client")
}

/// Poll `client`'s real testnet chain tip until it reaches `target_height`,
/// or time out.
async fn wait_for_height(
    client: &DashSpvClient<
        WalletManager<ManagedWalletInfo>,
        PeerNetworkManager,
        DiskStorageManager,
    >,
    target_height: u32,
    timeout: Duration,
) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let height = client.tip_height().await;
        if height >= target_height {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "did not reach height {target_height} within {timeout:?} (stuck at {height})"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

#[tokio::test]
async fn stale_spent_utxo_still_reported_selectable_after_persisted_reload() {
    let mnemonic = std::env::var("ASSET_LOCK_REPRO_MNEMONIC").expect(
        "set ASSET_LOCK_REPRO_MNEMONIC to the real testnet mnemonic this bug was observed \
         against (see module docs) — not hardcoded here on purpose",
    );

    // Kept alive for the whole test — both phases share this directory so
    // headers/filters persist across the reload rather than being
    // re-downloaded, and phase 2 genuinely reloads phase 1's on-disk state.
    let storage_dir = TempDir::new().expect("failed to create temp storage dir");

    // ---- Phase 1: sync from BIRTH_HEIGHT to PHASE1_STOP_HEIGHT ----
    let (wallet_id, raw_wallet, info_bytes) = {
        let mut wallet_manager = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);
        let wallet_id = wallet_manager
            .create_wallet_from_mnemonic(
                &mnemonic,
                BIRTH_HEIGHT,
                WalletAccountCreationOptions::Default,
            )
            .expect("failed to restore framework wallet from mnemonic");
        let wallet = Arc::new(RwLock::new(wallet_manager));

        let client = make_client(storage_dir.path(), wallet.clone()).await;
        let run_client = client.clone();
        let run_handle = tokio::spawn(async move { run_client.run().await });

        wait_for_height(&client, PHASE1_STOP_HEIGHT, Duration::from_secs(300)).await;
        // Let the wallet finish processing the last few matched blocks/filters.
        tokio::time::sleep(Duration::from_secs(10)).await;

        client.stop().await.expect("phase 1 client stop");
        run_handle.await.expect("phase 1 run task panicked").expect("phase 1 run task errored");

        // Extract what a real app would persist: the signable Wallet (key
        // material) and the ManagedWalletInfo (accounts/UTXOs/transactions —
        // the actual sync-derived state) — via public accessors and serde,
        // no internal fields touched.
        let wm = wallet.read().await;
        let raw_wallet = wm.get_wallet(&wallet_id).expect("wallet registered").clone();
        let info = wm.get_wallet_info(&wallet_id).expect("wallet info registered");
        // bincode's serde-compat shim, not serde_json: ManagedWalletInfo's
        // internal maps are keyed by non-string types (e.g. OutPoint), which
        // JSON's object-key model cannot represent (verified: serde_json
        // fails with "key must be a string" on this exact type).
        let info_bytes = bincode::serde::encode_to_vec(info, bincode::config::standard())
            .expect("serialize ManagedWalletInfo");
        (wallet_id, raw_wallet, info_bytes)
        // wallet_manager (and its client) drop here — nothing carries over
        // in-memory into phase 2 except these three plain values.
    };

    // ---- Phase 2: genuine reload into a brand-new WalletManager + client ----
    let (restored_info, _): (ManagedWalletInfo, usize) =
        bincode::serde::decode_from_slice(&info_bytes, bincode::config::standard())
            .expect("deserialize ManagedWalletInfo");

    let mut wallet_manager2 = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);
    let reloaded_wallet_id = wallet_manager2
        .insert_wallet(raw_wallet, restored_info)
        .expect("insert reloaded wallet into brand-new WalletManager");
    assert_eq!(
        reloaded_wallet_id, wallet_id,
        "reloaded wallet id must match phase 1's — same signable Wallet, same root key"
    );
    let wallet2 = Arc::new(RwLock::new(wallet_manager2));

    let client2 = make_client(storage_dir.path(), wallet2.clone()).await;
    let run_client2 = client2.clone();
    let run_handle2 = tokio::spawn(async move { run_client2.run().await });

    wait_for_height(&client2, REAL_SPEND_HEIGHT, Duration::from_secs(300)).await;
    tokio::time::sleep(Duration::from_secs(10)).await;

    let target_outpoint = OutPoint {
        txid: Txid::from_str(STALE_FUNDING_TXID).expect("valid txid hex"),
        vout: STALE_FUNDING_VOUT,
    };
    let current_height = client2.tip_height().await;

    let still_selectable = {
        let mut wm = wallet2.write().await;
        let (_, info) = wm
            .get_wallet_and_info_mut(&reloaded_wallet_id)
            .expect("wallet + info must be registered");
        let account = info
            .accounts
            .standard_bip44_accounts
            .get(&0)
            .expect("BIP-44 account 0 must exist on a Default-options wallet");
        account.spendable_utxos(current_height).iter().any(|u| u.outpoint == target_outpoint)
    };

    let build_result = {
        let mut wm = wallet2.write().await;
        let (raw_wallet, info) = wm
            .get_wallet_and_info_mut(&reloaded_wallet_id)
            .expect("wallet + info must be registered");
        info.build_asset_lock(raw_wallet, 0, one_credit_output(100_000_000), 1_000).await
    };

    client2.stop().await.ok();
    run_handle2.abort();

    assert!(
        !still_selectable,
        "BUG: outpoint {target_outpoint} is genuinely spent on real Dash testnet \
         (block {REAL_SPEND_HEIGHT}, txid f9ca52d513f2801a2aec9d222f3d958748254ffb7a4532c6c44b22a111b638c7) \
         but ManagedCoreFundsAccount::spendable_utxos still reports it selectable for \
         BIP-44 account 0 after phase 1 synced through {PHASE1_STOP_HEIGHT}, a genuine \
         reload of the persisted ManagedWalletInfo into a brand-new WalletManager, and \
         phase 2 resuming sync through the real spend height {REAL_SPEND_HEIGHT}. This \
         is the root cause of dash-evo-tool's AssetLockFinalityTimeout: the asset-lock \
         builder's require_final_inputs filter (is_confirmed || is_instantlocked) \
         accepts this UTXO because its is_confirmed flag was correctly set to true at \
         creation and was never invalidated by the later real spend, once that spend \
         had to be observed across a persisted-state reload rather than a single \
         continuous in-memory sync."
    );

    if let Ok(result) = build_result {
        let spent_the_dead_utxo =
            result.transaction.input.iter().any(|txin| txin.previous_output == target_outpoint);
        assert!(
            !spent_the_dead_utxo,
            "BUG: build_asset_lock produced a transaction funded by the real-network-dead \
             outpoint {target_outpoint} after the persisted-state reload — the exact \
             failure mode behind dash-evo-tool's AssetLockFinalityTimeout."
        );
    }
    // An Err(_) here (e.g. no other funds available) does not invalidate the
    // primary assertion above, which is the deterministic pin for this bug.
}
