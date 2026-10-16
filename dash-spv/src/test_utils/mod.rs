mod chain_tip;
mod chain_work;
mod checkpoint;
mod context;
mod event_handler;
mod filter;
mod fs_helpers;
mod header_storage;
pub(crate) mod masternode_network;
mod network;
mod node;
mod types;
mod wallet;

use std::time::Duration;

/// Default timeout for sync operations in integration tests.
pub const SYNC_TIMEOUT: Duration = Duration::from_secs(180);

pub use context::DashdTestContext;
pub use event_handler::TestEventHandler;
pub use fs_helpers::retain_test_dir;
pub use header_storage::MockHeaderStorage;
pub use masternode_network::MasternodeTestContext;
pub use network::{test_socket_address, MockNetworkManager};
pub use node::{DashCoreNode, TestChain, WalletFile};
pub use wallet::{
    create_test_wallet, default_test_account_options, init_test_logging,
    next_unused_receive_address,
};

pub(crate) use node::DashCoreConfig;

pub use crate::sml_engine::{MasternodeListEngine, WORK_DIFF_DEPTH};

/// The client's masternode list engine, for tests that inspect its state.
pub fn masternode_list_engine<W, N, S>(
    client: &crate::client::DashSpvClient<W, N, S>,
) -> crate::error::Result<
    std::sync::Arc<
        tokio::sync::RwLock<MasternodeListEngine<crate::storage::PersistentBlockHeaderStorage>>,
    >,
>
where
    W: key_wallet_manager::WalletInterface,
    N: crate::network::NetworkManager,
    S: crate::storage::StorageManager,
{
    client.masternode_list_engine()
}
