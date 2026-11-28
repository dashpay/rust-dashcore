//! Moving `synced_height` down bumps the account generation, so a filter scan taken before
//! the rewind cannot certify the heights the rewind reopened.

use test_case::test_case;

use crate::test_utils::TestWalletContext;
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;

#[test_case(0, true; "rewind")]
#[test_case(100, false; "same height")]
#[test_case(200, false; "advance")]
fn update_synced_height_bumps_the_generation_only_when_it_rewinds(height: u32, bumps: bool) {
    let mut ctx = TestWalletContext::new_random();
    ctx.managed_wallet.update_synced_height(100);
    let before = ctx.managed_wallet.account_generation();

    ctx.managed_wallet.update_synced_height(height);

    assert_eq!(ctx.managed_wallet.synced_height(), height);
    assert_eq!(ctx.managed_wallet.account_generation(), before + u64::from(bumps));
}

#[test_case(50, 50, true; "below the checkpoint")]
#[test_case(150, 100, false; "above the checkpoint")]
fn truncate_above_bumps_the_generation_only_when_it_lowers_the_checkpoint(
    height: u32,
    synced: u32,
    bumps: bool,
) {
    let mut ctx = TestWalletContext::new_random();
    ctx.managed_wallet.update_synced_height(100);
    let before = ctx.managed_wallet.account_generation();

    ctx.managed_wallet.truncate_above(height).expect("truncates");

    assert_eq!(ctx.managed_wallet.synced_height(), synced);
    assert_eq!(ctx.managed_wallet.account_generation(), before + u64::from(bumps));
}
