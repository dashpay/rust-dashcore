//! Found-022 — `AssetLockBuilder::build` performs change-address derivation
//! work before the build can fail, bumping `monitor_revision` on the
//! BIP-44-account-0 funds account even though no transaction is produced.
//!
//! Defect site: `TransactionBuilder::set_funding`
//! (`key-wallet/src/wallet/managed_wallet_info/transaction_builder.rs`) calls
//! `funds_acc.next_change_address(..., add_to_state = true)` BEFORE
//! `build_signed` runs coin selection; `next_change_address` unconditionally
//! invokes `bump_monitor_revision()`
//! (`key-wallet/src/managed_account/managed_core_funds_account.rs`).
//! Tracking issue: https://github.com/dashpay/rust-dashcore/issues/764
//!
//! `build_asset_lock`'s doc-comment promises: "The transaction is built
//! first, and keys are only derived after a successful build — so no
//! addresses are consumed if the build fails." The eager `set_funding` call
//! violates that contract.
//!
//! ## Why `monitor_revision` is the pin
//!
//! With `WalletAccountCreationOptions::Default` the internal pool is
//! pre-populated with a full gap-limit window, so the eager
//! `next_change_address` short-circuits to an existing unused entry without
//! growing the pool: `addresses`, `highest_generated`, and `highest_used`
//! are all unchanged in both bug-present and bug-fixed states. The single
//! deterministic, observable footprint of the eager call on a fresh wallet
//! is the unconditional `bump_monitor_revision()` — load-bearing for any
//! consumer that watches `monitor_revision` for "did the account change?"
//! signaling. Snapshot-and-compare absorbs incidental bumps from setup.
//!
//! Test lifecycle: RED today (revision bumps 0 -> 1 across a failed build).
//! GREEN once `next_change_address` is deferred past `build_signed` (or
//! `set_funding` learns to peek without mutating).

use key_wallet::account::ManagedAccountTrait;
use key_wallet::dashcore::{ScriptBuf, TxOut};
use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::wallet::managed_wallet_info::asset_lock_builder::{
    AssetLockFundingType, CreditOutputFunding,
};
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet::{Network, Wallet};

/// One credit-output funding spec — the minimum to drive `build_asset_lock`
/// past the empty-outputs guard and into coin selection.
fn one_credit_output(amount: u64) -> Vec<CreditOutputFunding> {
    vec![CreditOutputFunding {
        output: TxOut {
            value: amount,
            // Minimal P2PKH-shaped script; the builder only reads `value`.
            script_pubkey: ScriptBuf::from(vec![
                0x76, 0xa9, 0x14, // OP_DUP OP_HASH160 PUSH20
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x88, 0xac, // OP_EQUALVERIFY OP_CHECKSIG
            ]),
        },
        funding_type: AssetLockFundingType::AssetLockAddressTopUp,
        identity_index: 0,
    }]
}

/// `monitor_revision` of the BIP-44-account-0 funds account — bumped by
/// every funds-mutating call, including the eager `next_change_address`.
fn bip44_account_0_monitor_revision(info: &ManagedWalletInfo) -> u64 {
    info.accounts
        .standard_bip44_accounts
        .get(&0)
        .expect("BIP-44 account 0 must exist on a default-options wallet")
        .monitor_revision()
}

#[tokio::test]
async fn found_022_asset_lock_builder_consumes_change_index_on_failure() {
    // Fresh wallet with default accounts and an EMPTY UTXO set, so the build
    // must fail at coin selection — after set_funding already ran.
    let wallet = Wallet::new_random(Network::Testnet, WalletAccountCreationOptions::Default)
        .expect("wallet creation must succeed");
    let mut info = ManagedWalletInfo::from_wallet(&wallet, 0);

    let revision_before = bip44_account_0_monitor_revision(&info);

    let result = info
        .build_asset_lock(
            &wallet,
            0, // BIP-44 account 0
            one_credit_output(100_000),
            1_000, // fee_per_kb (duffs)
        )
        .await;

    assert!(result.is_err(), "pre-condition: build must fail on an empty UTXO set; got Ok(_)");

    // (RED-by-design): set_funding eagerly reserves a change address before
    // build_signed can fail, so monitor_revision advances across a FAILED
    // build (rust-dashcore#764).
    let revision_after = bip44_account_0_monitor_revision(&info);
    assert_eq!(
        revision_after, revision_before,
        "BIP-44-account-0 monitor_revision advanced from {revision_before} to \
         {revision_after} across a failed build_asset_lock — the funds account was \
         mutated even though no transaction was produced, violating the documented \
         contract that no addresses are consumed on a failed build. \
         TransactionBuilder::set_funding calls next_change_address(..., \
         add_to_state=true) BEFORE build_signed runs coin selection, and that call \
         unconditionally bumps the monitor revision. Fix: defer next_change_address \
         past build_signed, or make set_funding peek without mutating. \
         See https://github.com/dashpay/rust-dashcore/issues/764"
    );
}
