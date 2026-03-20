use std::collections::HashSet;
use std::sync::atomic::Ordering;

use dash_spv::test_utils::{DashdTestContext, TestChain};

use super::context::FFITestContext;

#[test]
fn test_wallet_sync_via_ffi() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let Some(dashd) = rt.block_on(DashdTestContext::new(TestChain::Full)) else {
        eprintln!("Skipping test (dashd context unavailable)");
        return;
    };

    unsafe {
        let ctx = FFITestContext::new(dashd.addr);

        let wallet_id = ctx.add_wallet(&dashd.wallet.mnemonic);
        tracing::info!("Added wallet, ID: {}", hex::encode(&wallet_id));

        ctx.run_with_sync_callbacks();
        tracing::info!("FFI client running");

        ctx.wait_for_sync(dashd.initial_height);

        ctx.tracker().assert_no_errors();

        // Validate sync heights
        let final_header = ctx.tracker().last_header_tip.load(Ordering::SeqCst);
        let final_filter = ctx.tracker().last_filter_tip.load(Ordering::SeqCst);

        assert_eq!(final_header, dashd.initial_height, "Header height mismatch");
        assert_eq!(final_filter, dashd.initial_height, "Filter header height mismatch");
        assert_eq!(
            ctx.tracker().last_sync_cycle.load(Ordering::SeqCst),
            0,
            "Initial sync should be cycle 0"
        );
        tracing::info!("Heights match: headers={}, filters={}", final_header, final_filter);

        // Validate wallet balance
        let (confirmed, _unconfirmed) = ctx.get_wallet_balance(&wallet_id);
        let expected_balance = (dashd.wallet.balance * 100_000_000.0).round() as u64;
        tracing::info!(
            "Balance: confirmed={} satoshis, expected={} satoshis",
            confirmed,
            expected_balance
        );

        assert_eq!(confirmed, expected_balance, "Balance mismatch");

        // Validate transaction set against dashd baseline
        let spv_txids = ctx.wallet_txids(&wallet_id);
        let expected_txids: HashSet<String> = dashd
            .wallet
            .transactions
            .iter()
            .filter_map(|tx| tx.get("txid").and_then(|v| v.as_str()).map(String::from))
            .collect();

        let missing: Vec<_> = expected_txids.difference(&spv_txids).collect();
        let extra: Vec<_> = spv_txids.difference(&expected_txids).collect();

        assert!(
            missing.is_empty(),
            "SPV wallet is missing {} transactions: {:?}",
            missing.len(),
            missing
        );
        assert!(
            extra.is_empty(),
            "SPV wallet has {} unexpected transactions: {:?}",
            extra.len(),
            extra
        );
        tracing::info!("Transaction set validated: {} transactions match", spv_txids.len());
    }
}
