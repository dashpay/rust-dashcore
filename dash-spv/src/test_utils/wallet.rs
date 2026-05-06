//! Shared wallet/logging helpers for integration tests.

use std::collections::BTreeSet;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use key_wallet::managed_account::managed_account_trait::ManagedAccountTrait;
use key_wallet::managed_account::managed_account_type::ManagedAccountType;
use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::{WalletId, WalletManager};
use tokio::sync::RwLock;
use tracing::level_filters::LevelFilter;

use crate::logging::{init_logging, LogFileConfig, LoggingConfig, LoggingGuard};
use crate::Network;

/// Account creation options for tests: a single standard BIP44 account 0.
pub fn default_test_account_options() -> WalletAccountCreationOptions {
    WalletAccountCreationOptions::SpecificAccounts(
        BTreeSet::from([0]),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        None,
    )
}

/// Create a test wallet from a BIP39 mnemonic.
pub fn create_test_wallet(
    mnemonic: &str,
    network: Network,
) -> (Arc<RwLock<WalletManager<ManagedWalletInfo>>>, WalletId) {
    let mut wallet_manager = WalletManager::<ManagedWalletInfo>::new(network);
    let wallet_id = wallet_manager
        .create_wallet_from_mnemonic(mnemonic, 0, default_test_account_options())
        .expect("Failed to create wallet from mnemonic");
    (Arc::new(RwLock::new(wallet_manager)), wallet_id)
}

/// Return the next unused BIP44 account-0 external address from the wallet.
pub async fn next_unused_receive_address(
    wallet: &Arc<RwLock<WalletManager<ManagedWalletInfo>>>,
    wallet_id: &WalletId,
) -> dashcore::Address {
    let wallet_read = wallet.read().await;
    let wallet_info = wallet_read.get_wallet_info(wallet_id).expect("Wallet info not found");
    let account =
        wallet_info.accounts().standard_bip44_accounts.get(&0).expect("BIP44 account 0 not found");
    let ManagedAccountType::Standard {
        external_addresses,
        ..
    } = account.managed_account_type()
    else {
        panic!("Account 0 is not a Standard account type");
    };
    external_addresses
        .unused_addresses()
        .into_iter()
        .next()
        .expect("No unused receive address available")
}

/// Initialize per-test thread-local logging into the given directory.
///
/// Honors `DASHD_TEST_LOG` to additionally enable console output.
pub fn init_test_logging(log_dir: PathBuf) -> LoggingGuard {
    init_logging(LoggingConfig {
        level: Some(LevelFilter::DEBUG),
        console: env::var("DASHD_TEST_LOG").is_ok(),
        file: Some(LogFileConfig {
            log_dir,
            max_files: 1,
        }),
        thread_local: true,
    })
    .expect("Failed to initialize test logging")
}
