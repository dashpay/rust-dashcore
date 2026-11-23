mod chain_tip;
mod chain_work;
mod checkpoint;
mod event_handler;
mod filter;
mod header_storage;
mod metadata_storage;
mod network;
mod types;
mod wallet;

use std::time::Duration;

/// Default timeout for sync operations in integration tests.
pub const SYNC_TIMEOUT: Duration = Duration::from_secs(180);

pub use dashcore_rpc::test_utils::{
    retain_test_dir, ControllerInfo, DashCoreNode, DashdTestContext, MasternodeInfo,
    MasternodeTestContext, NetworkMetadata, TestChain, WalletFile,
};
pub use event_handler::TestEventHandler;
pub use header_storage::MockHeaderStorage;
pub use metadata_storage::FailingMetadataStorage;
pub use network::{test_socket_address, MockNetworkManager};
pub use wallet::{
    create_test_wallet, default_test_account_options, init_test_logging,
    next_unused_receive_address,
};

pub use crate::sml_engine::{FeedError, MasternodeListEngine, WORK_DIFF_DEPTH};

/// Storage types for tests and benches that open the client's storage directly.
pub use crate::storage::{
    BlockHeaderStorage, BlockStorage, DiskStorageManager, FilterHeaderStorage, FilterStorage,
    MasternodeStorage, MetadataStorage, PersistentBlockHeaderStorage, PersistentBlockStorage,
    PersistentFilterHeaderStorage, PersistentFilterStorage, PersistentMasternodeStorage,
    PersistentMetadataStorage, PersistentStorage, StorageManager,
};

/// The client's masternode list engine, for tests that inspect its state.
pub fn masternode_list_engine<W, N>(
    client: &crate::client::DashSpvClient<W, N>,
) -> crate::error::Result<
    std::sync::Arc<
        tokio::sync::RwLock<MasternodeListEngine<crate::storage::PersistentBlockHeaderStorage>>,
    >,
>
where
    W: key_wallet_manager::WalletInterface,
    N: crate::network::NetworkManager,
{
    client.masternode_list_engine()
}
