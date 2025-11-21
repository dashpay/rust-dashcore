//! Query methods for peers, masternodes, and balances.
//!
//! This module contains:
//! - Peer queries (count, info, disconnect)
//! - Masternode queries (engine, list, quorums)
//! - Balance queries
//! - Filter availability checks

use crate::error::{Result, SpvError};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::types::AddressBalance;
use dashcore::sml::masternode_list::MasternodeList;
use dashcore::sml::masternode_list_engine::MasternodeListEngine;
use dashcore::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use key_wallet_manager::wallet_interface::WalletInterface;

use super::DashSpvClient;

impl<
        W: WalletInterface + Send + Sync + 'static,
        N: NetworkManager + Send + Sync + 'static,
        S: StorageManager + Send + Sync + 'static,
    > DashSpvClient<W, N, S>
{
    // ============ Peer Queries ============

    /// Get the number of connected peers.
    pub fn peer_count(&self) -> usize {
        self.network.peer_count()
    }

    /// Get information about connected peers.
    pub fn peer_info(&self) -> Vec<crate::types::PeerInfo> {
        self.network.peer_info()
    }

    /// Get the number of connected peers (async version).
    pub async fn get_peer_count(&self) -> usize {
        self.network.peer_count()
    }

    /// Disconnect a specific peer.
    pub async fn disconnect_peer(&self, addr: &std::net::SocketAddr, reason: &str) -> Result<()> {
        // Cast network manager to PeerNetworkManager to access disconnect_peer
        let network = self
            .network
            .as_any()
            .downcast_ref::<crate::network::manager::PeerNetworkManager>()
            .ok_or_else(|| {
                SpvError::Config("Network manager does not support peer disconnection".to_string())
            })?;

        network.disconnect_peer(addr, reason).await
    }

    // ============ Masternode Queries ============

    /// Get a reference to the masternode list engine.
    /// Returns None if masternode sync is not enabled in config.
    pub fn masternode_list_engine(&self) -> Option<&MasternodeListEngine> {
        self.sync_manager.masternode_list_engine()
    }

    /// Get the masternode list at a specific block height.
    /// Returns None if the masternode list for that height is not available.
    pub fn get_masternode_list_at_height(&self, height: u32) -> Option<&MasternodeList> {
        self.masternode_list_engine().and_then(|engine| engine.masternode_lists.get(&height))
    }

    /// Get a quorum entry by type and hash at a specific block height.
    /// Returns None if the quorum is not found.
    ///
    /// # Deprecated
    ///
    /// This method is now a synchronous wrapper that blocks on the async QuorumLookup.
    /// For better performance and to avoid blocking, prefer using the async version:
    ///
    /// ```rust,no_run
    /// # use dash_spv::client::DashSpvClient;
    /// # async fn example(client: &DashSpvClient<
    /// #     key_wallet_manager::wallet_manager::WalletManager<key_wallet::wallet::managed_wallet_info::ManagedWalletInfo>,
    /// #     dash_spv::network::manager::PeerNetworkManager,
    /// #     dash_spv::storage::DiskStorageManager
    /// # >) {
    /// let quorum_lookup = client.quorum_lookup();
    /// let quorum_hash = [0u8; 32]; // Placeholder - use actual hash
    /// if let Some(quorum) = quorum_lookup.get_quorum_at_height(100000, 1, &quorum_hash).await {
    ///     println!("Found quorum!");
    /// }
    /// # }
    /// ```
    pub fn get_quorum_at_height(
        &self,
        height: u32,
        quorum_type: u8,
        quorum_hash: &[u8; 32],
    ) -> Option<QualifiedQuorumEntry> {
        // Delegate to the QuorumLookup component
        // This requires blocking on the async call
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.quorum_lookup.get_quorum_at_height(height, quorum_type, quorum_hash).await
            })
        })
    }

    // ============ Balance Queries ============

    /// Get balance for a specific address.
    ///
    /// This method is deprecated - use the wallet's balance query methods instead.
    pub async fn get_address_balance(
        &self,
        _address: &dashcore::Address,
    ) -> Result<AddressBalance> {
        // This method requires wallet-specific functionality not in WalletInterface
        // The wallet should expose balance info through its own interface
        Err(SpvError::Config(
            "Address balance queries should be made directly to the wallet implementation"
                .to_string(),
        ))
    }

    /// Get balances for all watched addresses.
    ///
    /// This method is deprecated - use the wallet's balance query methods instead.
    pub async fn get_all_balances(
        &self,
    ) -> Result<std::collections::HashMap<dashcore::Address, AddressBalance>> {
        // TODO: Get balances from wallet instead of tracking separately
        // Will be implemented when wallet integration is complete
        Ok(std::collections::HashMap::new())
    }

    // ============ Filter Queries ============

    /// Check if filter sync is available (any peer supports compact filters).
    pub async fn is_filter_sync_available(&self) -> bool {
        self.network
            .has_peer_with_service(dashcore::network::constants::ServiceFlags::COMPACT_FILTERS)
            .await
    }
}
