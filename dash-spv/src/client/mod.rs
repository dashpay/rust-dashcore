//! High-level client API for the Dash SPV client.
//!
//! Provides `DashSpvClient`, the main entry point for SPV operations including
//! sync orchestration, mempool tracking, peer/masternode queries, and transaction
//! broadcasting.
//!
//! ## Module Structure
//!
//! - `config.rs` - Client configuration
//! - `core.rs` - Core `DashSpvClient` struct definition and simple accessors
//! - `lifecycle.rs` - Client lifecycle (new, start, stop, shutdown)
//! - `events.rs` - Event emission and progress tracking receivers
//! - `queries.rs` - Peer, masternode, and balance queries
//! - `transactions.rs` - Transaction operations (e.g., broadcast)
//! - `sync_coordinator.rs` - Sync orchestration and network monitoring

pub mod config;
pub mod devnet;
pub mod event_handler;

mod core;
mod events;
mod lifecycle;
mod queries;
mod sync_coordinator;
mod transactions;

// Re-export public types from extracted modules
pub use config::ClientConfig;
pub use devnet::DevnetConfig;
pub use event_handler::EventHandler;

// Re-export the main client struct
pub use core::DashSpvClient;

#[cfg(test)]
mod config_test;

#[cfg(test)]
mod tests {
    use super::{ClientConfig, DashSpvClient, EventHandler};
    use crate::client::config::MempoolStrategy;
    use crate::storage::DiskStorageManager;
    use crate::test_utils::MockNetworkManager;
    use crate::Network;
    use key_wallet::wallet::initialization::WalletAccountCreationOptions;
    use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
    use key_wallet_manager::WalletManager;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::sync::RwLock;

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    const SECOND_MNEMONIC: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";

    /// Construct a mainnet client seeded with a single wallet at `birth_height` and an
    /// optional explicit `start_from_height`. Returns the client, its shared wallet manager,
    /// and the storage `TempDir` guard, which the caller must keep alive for the client's
    /// storage to remain valid.
    async fn build_test_client(
        birth_height: u32,
        start_from_height: Option<u32>,
    ) -> (
        DashSpvClient<WalletManager<ManagedWalletInfo>, MockNetworkManager, DiskStorageManager>,
        Arc<RwLock<WalletManager<ManagedWalletInfo>>>,
        TempDir,
    ) {
        build_test_client_with_handlers(birth_height, start_from_height, vec![Arc::new(())]).await
    }

    /// Like [`build_test_client`] but installs the given event handlers, so a test can observe
    /// the client's push notifications.
    async fn build_test_client_with_handlers(
        birth_height: u32,
        start_from_height: Option<u32>,
        event_handlers: Vec<Arc<dyn EventHandler>>,
    ) -> (
        DashSpvClient<WalletManager<ManagedWalletInfo>, MockNetworkManager, DiskStorageManager>,
        Arc<RwLock<WalletManager<ManagedWalletInfo>>>,
        TempDir,
    ) {
        let mut wallet_manager = WalletManager::<ManagedWalletInfo>::new(Network::Mainnet);
        wallet_manager
            .create_wallet_from_mnemonic(
                TEST_MNEMONIC,
                birth_height,
                WalletAccountCreationOptions::Default,
            )
            .expect("wallet creation must succeed");
        let wallet = Arc::new(RwLock::new(wallet_manager));

        let temp_dir = TempDir::new().unwrap();
        let mut config = ClientConfig::mainnet()
            .without_filters()
            .without_masternodes()
            .with_storage_path(temp_dir.path());
        config.start_from_height = start_from_height;

        let storage = DiskStorageManager::new(&config).await.expect("Failed to create storage");
        let client = DashSpvClient::new(
            config,
            MockNetworkManager::new(),
            storage,
            wallet.clone(),
            event_handlers,
        )
        .await
        .expect("client construction must succeed");
        (client, wallet, temp_dir)
    }

    /// Return the height and hash a client's chain is anchored at for the given wallet birth
    /// height and optional explicit `start_from_height`.
    async fn anchored_tip(
        birth_height: u32,
        start_from_height: Option<u32>,
    ) -> (u32, Option<dashcore::BlockHash>) {
        let (client, _wallet, _temp_dir) = build_test_client(birth_height, start_from_height).await;
        (client.tip_height().await, client.tip_hash().await)
    }

    #[tokio::test]
    async fn birth_height_anchors_chain_to_nearest_checkpoint() {
        // A wallet birth height below mainnet's HD/BIP39 activation floor is clamped up to
        // the floor, which anchors at the nearest checkpoint at or before it: the 200_000
        // checkpoint. The stored tip carries the trusted checkpoint hash (what the next
        // header's `prev_blockhash` is validated against), not a hash recomputed from a header.
        // 120_000 is below mainnet's HD/BIP39 sync floor, so it is clamped up.
        let (height, hash) = anchored_tip(120_000, None).await;
        assert_eq!(height, 200_000);
        let expected: dashcore::BlockHash =
            "000000000004d0615ff622ec78457ca211dc63fc9c62cca9d9d9af7206be721b".parse().unwrap();
        assert_eq!(hash, Some(expected));

        // Birth height 0 no longer drags mainnet sync to genesis; it floors at HD activation.
        assert_eq!(anchored_tip(0, None).await.0, 200_000);

        // A birth height above the floor is unaffected and anchors at the nearest
        // checkpoint at or below it.
        assert_eq!(anchored_tip(560_000, None).await.0, 550_000);

        // Explicit `start_from_height` wins over the wallet birth height and is honored
        // even below the floor.
        assert_eq!(anchored_tip(120_000, Some(60_000)).await.0, 50_000);
    }

    #[tokio::test]
    async fn force_resync_reanchors_to_lower_birth_wallet() {
        // A client whose only wallet is born at 620_000 anchors at the 600_000 checkpoint.
        // Both wallets here sit well above mainnet's HD/BIP39 sync floor, so the anchor is
        // genuinely wallet-derived rather than clamped to the floor.
        let (client, wallet, _temp_dir) = build_test_client(620_000, None).await;

        assert_eq!(client.tip_height().await, 600_000);
        assert!(!client.resync_needed().await);

        // Add a wallet born below the current anchor. Nothing re-anchors on its own, so the
        // stored chain still starts at 600_000 and a resync is now required.
        wallet
            .write()
            .await
            .create_wallet_from_mnemonic(
                SECOND_MNEMONIC,
                520_000,
                WalletAccountCreationOptions::Default,
            )
            .expect("second wallet creation must succeed");
        assert!(client.resync_needed().await);
        assert_eq!(client.tip_height().await, 600_000);

        // Forcing a resync wipes the old anchor and re-anchors at the 500_000 checkpoint, the
        // nearest at or below the new minimum birth height.
        client.force_resync().await.expect("force resync must succeed");
        assert_eq!(client.tip_height().await, 500_000);
        assert!(!client.resync_needed().await);
    }

    #[tokio::test]
    async fn resync_if_needed_runs_only_when_needed() {
        // Only wallet born at 620_000, anchored at the 600_000 checkpoint: no resync is
        // needed, so `resync_if_needed` is a no-op that reports it did nothing and leaves the
        // anchor. Both birth heights used here are above mainnet's HD/BIP39 sync floor, so the
        // anchor tracks the wallets rather than the floor.
        let (client, wallet, _temp_dir) = build_test_client(620_000, None).await;
        assert_eq!(client.tip_height().await, 600_000);
        assert!(!client.resync_if_needed().await.expect("resync_if_needed must succeed"));
        assert_eq!(client.tip_height().await, 600_000);

        // A wallet added below the anchor makes a resync necessary, so now it re-anchors and
        // reports that it ran.
        wallet
            .write()
            .await
            .create_wallet_from_mnemonic(
                SECOND_MNEMONIC,
                520_000,
                WalletAccountCreationOptions::Default,
            )
            .expect("second wallet creation must succeed");
        assert!(client.resync_if_needed().await.expect("resync_if_needed must succeed"));
        assert_eq!(client.tip_height().await, 500_000);

        // Once re-anchored the condition is cleared, so a second call is again a no-op.
        assert!(!client.resync_if_needed().await.expect("resync_if_needed must succeed"));
        assert_eq!(client.tip_height().await, 500_000);

        // A wallet born below mainnet's HD/BIP39 sync floor anchors at the floor's checkpoint,
        // which sits above its birth height. Re-anchoring could never reach that birth height,
        // so the resync condition must read as false rather than wiping and refetching the
        // whole chain on every call.
        let (floored, _wallet, _temp_dir) = build_test_client(60_000, None).await;
        assert_eq!(floored.tip_height().await, 200_000);
        assert!(!floored.resync_needed().await);
        assert!(!floored.resync_if_needed().await.expect("resync_if_needed must succeed"));
        assert_eq!(floored.tip_height().await, 200_000);
    }

    #[tokio::test]
    async fn run_loop_signals_resync_needed_on_wallet_add_below_anchor() {
        // Records how many times the client pushed `on_resync_needed`.
        struct ResyncRecorder {
            count: Arc<AtomicUsize>,
        }
        impl EventHandler for ResyncRecorder {
            fn on_resync_needed(&self) {
                self.count.fetch_add(1, Ordering::SeqCst);
            }
        }

        let count = Arc::new(AtomicUsize::new(0));
        let (client, wallet, _temp_dir) = build_test_client_with_handlers(
            620_000,
            None,
            vec![Arc::new(ResyncRecorder {
                count: count.clone(),
            })],
        )
        .await;
        let client = Arc::new(client);

        // Drive the run loop so its periodic resync check runs. The mock network connects
        // without a real peer, so sync just idles.
        let run_client = Arc::clone(&client);
        let run_handle = tokio::spawn(async move { run_client.run().await });

        // Let the loop start and seed its baseline (resync not yet needed) before we change
        // the wallet set, so adding the wallet is observed as a rising edge.
        while !client.is_running() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(count.load(Ordering::SeqCst), 0);

        // Add a wallet below the anchor: the next periodic check must see the rising edge and
        // fire the notification exactly once. 520_000 is still above mainnet's HD/BIP39 sync
        // floor, so it lands below the 600_000 anchor on its own merit rather than being
        // clamped up to the floor.
        wallet
            .write()
            .await
            .create_wallet_from_mnemonic(
                SECOND_MNEMONIC,
                520_000,
                WalletAccountCreationOptions::Default,
            )
            .expect("second wallet creation must succeed");

        let mut waited = Duration::ZERO;
        while count.load(Ordering::SeqCst) == 0 && waited < Duration::from_secs(5) {
            tokio::time::sleep(Duration::from_millis(50)).await;
            waited += Duration::from_millis(50);
        }
        assert_eq!(count.load(Ordering::SeqCst), 1, "resync-needed must fire once on the edge");

        // The condition stays true but must not re-fire on later checks.
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert_eq!(count.load(Ordering::SeqCst), 1, "resync-needed must not repeat");

        client.stop().await.expect("stop must succeed");
        let _ = run_handle.await;
    }

    #[tokio::test]
    async fn client_exposes_shared_wallet_manager() {
        let config = ClientConfig::mainnet()
            .without_filters()
            .without_masternodes()
            .with_mempool_tracking(MempoolStrategy::FetchAll)
            .with_storage_path(TempDir::new().unwrap().path());

        let network_manager = MockNetworkManager::new();
        let storage =
            DiskStorageManager::with_temp_dir().await.expect("Failed to create tmp storage");
        let wallet = Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new(config.network)));

        let client =
            DashSpvClient::new(config, network_manager, storage, wallet, vec![Arc::new(())])
                .await
                .expect("client construction must succeed");

        // Verify the wallet is accessible
        let wallet_ref = client.wallet();
        let _wallet_guard = wallet_ref.read().await;
    }
}
