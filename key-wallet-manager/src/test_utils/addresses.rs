use crate::{WalletId, WalletManager};
use dashcore::Address;
use key_wallet::account::{AccountType, ManagedAccountTrait};
use key_wallet::managed_account::address_pool::{AddressPool, AddressPoolType, KeySource};
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;

/// Returns the first `count` External addresses of the wallet's `account_type` account.
/// They come from a standalone pool over the account xpub, so they can lie beyond
/// the wallet's watch window without changing its state.
pub fn external_addresses(
    manager: &WalletManager<ManagedWalletInfo>,
    wallet_id: &WalletId,
    account_type: AccountType,
    count: u32,
) -> Vec<Address> {
    let wallet = manager.get_wallet(wallet_id).expect("wallet present");
    let xpub = wallet
        .accounts
        .account_of_type(account_type)
        .unwrap_or_else(|| panic!("{account_type} account"))
        .account_xpub;
    let info = manager.get_wallet_info(wallet_id).expect("wallet info present");
    let account = info
        .accounts
        .funds_account(&account_type)
        .unwrap_or_else(|| panic!("managed {account_type} account"));
    let pools = account.managed_account_type().address_pools();
    let live = pools
        .iter()
        .find(|p| p.pool_type == AddressPoolType::External)
        .unwrap_or_else(|| panic!("{account_type} External pool"));
    let pool = AddressPool::new(
        live.base_path.clone(),
        AddressPoolType::External,
        count,
        wallet.network,
        &KeySource::Public(xpub),
    )
    .expect("derive standalone External pool");
    (0..count).map(|i| pool.address_at_index(i).expect("address generated")).collect()
}

/// Returns the first `count` External addresses of the wallet's CoinJoin account 0,
/// as [`external_addresses`] does.
pub fn coinjoin_external_addresses(
    manager: &WalletManager<ManagedWalletInfo>,
    wallet_id: &WalletId,
    count: u32,
) -> Vec<Address> {
    external_addresses(
        manager,
        wallet_id,
        AccountType::CoinJoin {
            index: 0,
        },
        count,
    )
}
