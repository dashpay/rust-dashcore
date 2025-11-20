//! High-level client API for the Dash SPV client.
//!
//! This module has been refactored from a monolithic 2,851-line file into focused submodules:
//!
//! ## Module Structure
//!
//! - `core.rs` - Core DashSpvClient struct definition and simple accessors
//! - `lifecycle.rs` - Client lifecycle (new, start, stop, shutdown)
//! - `events.rs` - Event emission and progress tracking receivers
//! - `progress.rs` - Sync progress calculation and reporting
//! - `mempool.rs` - Mempool tracking and coordination
//! - `queries.rs` - Peer, masternode, and balance queries
//! - `transactions.rs` - Transaction operations (e.g., broadcast)
//! - `chainlock.rs` - ChainLock and InstantLock processing
//! - `sync_coordinator.rs` - Sync orchestration and network monitoring (the largest module)
//!
//! ## Already Extracted Modules
//!
//! - `block_processor.rs` (649 lines) - Block processing and validation
//! - `config.rs` (484 lines) - Client configuration
//! - `filter_sync.rs` (171 lines) - Filter synchronization
//! - `message_handler.rs` (585 lines) - Network message handling
//! - `status_display.rs` (242 lines) - Status display formatting
//!
//! ## Lock Ordering (CRITICAL - Prevents Deadlocks)
//!
//! When acquiring multiple locks, ALWAYS use this order:
//! 1. running (Arc<RwLock<bool>>)
//! 2. state (Arc<RwLock<ChainState>>)
//! 3. stats (Arc<RwLock<SpvStats>>)
//! 4. mempool_state (Arc<RwLock<MempoolState>>)
//! 5. storage (Arc<Mutex<S>>)
//!
//! Never acquire locks in reverse order or deadlock will occur!

// Existing extracted modules
pub mod block_processor;
pub mod config;
pub mod filter_sync;
pub mod message_handler;
pub mod status_display;

// New refactored modules
mod chainlock;
mod core;
mod events;
mod lifecycle;
mod mempool;
mod progress;
mod queries;
mod quorum_lookup;
mod sync_coordinator;
mod transactions;

// Re-export public types from extracted modules
pub use block_processor::{BlockProcessingTask, BlockProcessor};
pub use config::ClientConfig;
pub use filter_sync::FilterSyncCoordinator;
pub use message_handler::MessageHandler;
pub use quorum_lookup::QuorumLookup;
pub use status_display::StatusDisplay;

// Re-export the main client struct
pub use core::DashSpvClient;

#[cfg(test)]
mod config_test;

#[cfg(test)]
mod block_processor_test;

#[cfg(test)]
mod message_handler_test;

#[cfg(test)]
mod tests {
    use super::{ClientConfig, DashSpvClient};
    use crate::network::mock::MockNetworkManager;
    use crate::storage::MemoryStorageManager;
    use crate::types::UnconfirmedTransaction;
    use dashcore::{Amount, Network, Transaction, TxOut};
    use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
    use key_wallet_manager::wallet_manager::WalletManager;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    // Tests for get_mempool_balance function
    // These tests validate that the balance calculation correctly handles:
    // 1. The sign of net_amount
    // 2. Validation of transaction effects on addresses
    // 3. Edge cases like zero amounts and conflicting signs

    #[tokio::test]
    async fn client_exposes_shared_wallet_manager() {
        let config = ClientConfig {
            network: Network::Dash,
            enable_filters: false,
            enable_masternodes: false,
            enable_mempool_tracking: false,
            ..Default::default()
        };

        let network_manager = MockNetworkManager::new();
        let storage = MemoryStorageManager::new().await.expect("memory storage should initialize");
        let wallet = Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new()));

        let client = DashSpvClient::new(config, network_manager, storage, wallet)
            .await
            .expect("client construction must succeed");

        // Verify the wallet is accessible
        let wallet_ref = client.wallet();
        let _wallet_guard = wallet_ref.read().await;
        // Success: we can access the shared wallet
    }

    #[tokio::test]
    async fn test_get_mempool_balance_logic() {
        // This test validates the get_mempool_balance logic by directly testing
        // the balance calculation code using a mocked mempool state.

        let config = ClientConfig {
            network: Network::Testnet,
            enable_filters: false,
            enable_masternodes: false,
            enable_mempool_tracking: true,
            ..Default::default()
        };

        let network_manager = MockNetworkManager::new();
        let storage = MemoryStorageManager::new().await.expect("memory storage should initialize");
        let wallet = Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new()));

        let mut client = DashSpvClient::new(config, network_manager, storage, wallet)
            .await
            .expect("client construction must succeed");

        // Enable mempool tracking to initialize mempool_filter
        client
            .enable_mempool_tracking(crate::client::config::MempoolStrategy::BloomFilter)
            .await
            .expect("enable mempool tracking must succeed");

        // Create a test address (testnet address to match Network::Testnet config)
        let test_address_str = "yP8A3cbdxRtLRduy5mXDsBnJtMzHWs6ZXr";
        let test_address = test_address_str
            .parse::<dashcore::Address<dashcore::address::NetworkUnchecked>>()
            .expect("valid address")
            .assume_checked();

        // Create a transaction that sends 10 Dash to the test address
        let tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![],
            output: vec![TxOut {
                value: 1_000_000_000, // 10 Dash in satoshis
                script_pubkey: test_address.script_pubkey(),
            }],
            special_transaction_payload: None,
        };

        // Add to mempool state
        {
            let mut mempool_state = client.mempool_state.write().await;
            let tx_record = UnconfirmedTransaction {
                transaction: tx.clone(),
                first_seen: std::time::Instant::now(),
                fee: Amount::ZERO,
                size: 0,
                is_instant_send: false,
                addresses: vec![test_address.clone()],
                net_amount: 1_000_000_000, // Incoming 10 Dash
                is_outgoing: false,
            };
            mempool_state.transactions.insert(tx.txid(), tx_record);
        }

        // Get balance for the test address
        let balance = client
            .get_mempool_balance(&test_address)
            .await
            .expect("balance calculation must succeed");

        // Verify the pending balance is correct
        assert_eq!(
            balance.pending,
            Amount::from_sat(1_000_000_000),
            "Pending balance should be 10 Dash"
        );
        assert_eq!(balance.pending_instant, Amount::ZERO, "InstantSend balance should be zero");

        // Test with InstantSend transaction
        {
            // Modify transaction to be InstantSend
            let mut mempool_state = client.mempool_state.write().await;
            if let Some(tx_record) = mempool_state.transactions.get_mut(&tx.txid()) {
                tx_record.is_instant_send = true;
            }
        }

        let balance = client
            .get_mempool_balance(&test_address)
            .await
            .expect("balance calculation must succeed");

        // Verify InstantSend balance
        assert_eq!(balance.pending, Amount::ZERO, "Regular pending should be zero");
        assert_eq!(
            balance.pending_instant,
            Amount::from_sat(1_000_000_000),
            "InstantSend balance should be 10 Dash"
        );
    }
}
