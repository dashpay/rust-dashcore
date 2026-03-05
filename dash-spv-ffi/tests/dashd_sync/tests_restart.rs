use std::sync::atomic::Ordering;

use dash_spv::test_utils::DashdTestContext;

use super::context::FFITestContext;

/// Verify FFI client restart preserves consistent state across stop/recreate cycles.
#[test]
fn test_ffi_restart_consistency() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let Some(dashd) = rt.block_on(DashdTestContext::new()) else {
        eprintln!("Skipping test (dashd context unavailable)");
        return;
    };

    unsafe {
        // First sync
        tracing::info!("First FFI sync");
        let ctx = FFITestContext::new(dashd.addr);
        let wallet_id = ctx.add_wallet(&dashd.wallet.mnemonic);

        ctx.run_with_sync_callbacks();
        ctx.wait_for_sync(dashd.initial_height);

        let (first_balance, _) = ctx.get_wallet_balance(&wallet_id);
        let first_header = ctx.tracker().last_header_tip.load(Ordering::SeqCst);

        ctx.tracker().assert_no_errors();
        assert_eq!(
            ctx.tracker().last_sync_cycle.load(Ordering::SeqCst),
            0,
            "First sync should be cycle 0"
        );

        tracing::info!("First sync: balance={}, header_tip={}", first_balance, first_header);

        // Restart with same storage
        tracing::info!("Restarting FFI client");
        let ctx = ctx.restart();
        let wallet_id = ctx.add_wallet(&dashd.wallet.mnemonic);

        ctx.run_with_sync_callbacks();
        ctx.wait_for_sync(dashd.initial_height);

        let (second_balance, _) = ctx.get_wallet_balance(&wallet_id);
        let second_header = ctx.tracker().last_header_tip.load(Ordering::SeqCst);

        ctx.tracker().assert_no_errors();
        assert_eq!(
            ctx.tracker().last_sync_cycle.load(Ordering::SeqCst),
            0,
            "Restart sync should be cycle 0 (fresh client)"
        );

        tracing::info!("Second sync: balance={}, header_tip={}", second_balance, second_header);

        // Verify state is identical
        assert_eq!(first_balance, second_balance, "Balance mismatch after restart");
        assert_eq!(first_header, second_header, "Header tip mismatch after restart");
    }
}
