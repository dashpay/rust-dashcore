//! Network message handling for the Dash SPV client.

use crate::client::ClientConfig;
use crate::error::{Result, SpvError};
use crate::mempool_filter::MempoolFilter;
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::sync::legacy::SyncManager;
use crate::types::{MempoolState, SpvEvent};
// Removed local ad-hoc compact filter construction in favor of always processing full blocks
use key_wallet_manager::wallet_interface::WalletInterface;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Network message handler for processing incoming Dash protocol messages.
pub struct MessageHandler<'a, S: StorageManager, N: NetworkManager, W: WalletInterface> {
    sync_manager: &'a mut SyncManager<S, N, W>,
    storage: &'a mut S,
    network: &'a mut N,
    config: &'a ClientConfig,
    mempool_filter: &'a Option<Arc<MempoolFilter>>,
    mempool_state: &'a Arc<RwLock<MempoolState>>,
    event_tx: &'a tokio::sync::mpsc::UnboundedSender<SpvEvent>,
}

impl<'a, S: StorageManager, N: NetworkManager, W: WalletInterface> MessageHandler<'a, S, N, W> {
    /// Create a new message handler.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sync_manager: &'a mut SyncManager<S, N, W>,
        storage: &'a mut S,
        network: &'a mut N,
        config: &'a ClientConfig,
        mempool_filter: &'a Option<Arc<MempoolFilter>>,
        mempool_state: &'a Arc<RwLock<MempoolState>>,
        event_tx: &'a tokio::sync::mpsc::UnboundedSender<SpvEvent>,
    ) -> Self {
        Self {
            sync_manager,
            storage,
            network,
            config,
            mempool_filter,
            mempool_state,
            event_tx,
        }
    }

    /// Handle incoming network messages during monitoring.
    pub async fn handle_network_message(
        &mut self,
        message: &dashcore::network::message::NetworkMessage,
    ) -> Result<()> {
        use dashcore::network::message::NetworkMessage;

        tracing::debug!("Client handling network message: {:?}", std::mem::discriminant(message));

        // First check if this is a message that ONLY the sync manager handles
        // These messages can be moved to the sync manager without cloning
        match message {
            NetworkMessage::Headers2(ref headers2) => {
                tracing::info!(
                    "📋 Received Headers2 message with {} compressed headers",
                    headers2.headers.len()
                );

                // Move to sync manager without cloning
                return self
                    .sync_manager
                    .handle_message(message, &mut *self.network, &mut *self.storage)
                    .await
                    .map_err(|e| {
                        tracing::error!("Sequential sync manager error handling message: {}", e);
                        SpvError::Sync(e)
                    });
            }
            NetworkMessage::MnListDiff(ref diff) => {
                tracing::info!("📨 Received MnListDiff message: {} new masternodes, {} deleted masternodes, {} quorums",
                              diff.new_masternodes.len(), diff.deleted_masternodes.len(), diff.new_quorums.len());
                // Move to sync manager without cloning
                return self
                    .sync_manager
                    .handle_message(message, &mut *self.network, &mut *self.storage)
                    .await
                    .map_err(|e| {
                        tracing::error!("Sequential sync manager error handling message: {}", e);
                        SpvError::Sync(e)
                    });
            }
            NetworkMessage::CFHeaders(ref cf_headers) => {
                // Try to include the peer address for better diagnostics
                let peer_addr = self.network.get_last_message_peer_addr().await;
                match peer_addr {
                    Some(addr) => {
                        tracing::info!(
                            "📨 Client received CFHeaders message with {} filter headers from {}",
                            cf_headers.filter_hashes.len(),
                            addr
                        );
                    }
                    None => {
                        tracing::info!(
                            "📨 Client received CFHeaders message with {} filter headers (peer unknown)",
                            cf_headers.filter_hashes.len()
                        );
                    }
                }
                // Move to sync manager without cloning
                return self
                    .sync_manager
                    .handle_message(message, &mut *self.network, &mut *self.storage)
                    .await
                    .map_err(|e| {
                        tracing::error!("Sequential sync manager error handling message: {}", e);
                        SpvError::Sync(e)
                    });
            }
            NetworkMessage::QRInfo(ref qr_info) => {
                tracing::info!(
                    "📨 Received QRInfo message with {} diffs and {} snapshots",
                    qr_info.mn_list_diff_list.len(),
                    qr_info.quorum_snapshot_list.len()
                );
                // Move to sync manager without cloning
                return self
                    .sync_manager
                    .handle_message(message, &mut *self.network, &mut *self.storage)
                    .await
                    .map_err(|e| {
                        tracing::error!("Sequential sync manager error handling QRInfo: {}", e);
                        SpvError::Sync(e)
                    });
            }
            NetworkMessage::Headers(_) | NetworkMessage::CFilter(_) => {
                // Headers and CFilters are relatively small, cloning is acceptable
                if let Err(e) = self
                    .sync_manager
                    .handle_message(message, &mut *self.network, &mut *self.storage)
                    .await
                {
                    tracing::error!("Sequential sync manager error handling message: {}", e);
                }
            }
            NetworkMessage::Block(_) => {
                if self.sync_manager.is_in_downloading_blocks_phase() {
                    if let Err(e) = self
                        .sync_manager
                        .handle_message(message, &mut *self.network, &mut *self.storage)
                        .await
                    {
                        tracing::error!(
                            "Sequential sync manager error handling block message: {}",
                            e
                        );
                    }
                } else {
                    // Sync manager will just log and return, no need to send it
                    tracing::debug!("Block received outside of DownloadingBlocks phase - skipping sync manager processing");
                }
            }
            _ => {
                // Other messages don't need sync manager processing in this context
            }
        }

        // Then handle client-specific message processing
        match message {
            NetworkMessage::Headers(headers) => {
                // For post-sync headers, we need special handling
                if self.sync_manager.is_synced() && !headers.is_empty() {
                    let peer_addr = self.network.get_last_message_peer_addr().await;
                    if let Some(addr) = peer_addr {
                        tracing::info!(
                            "📋 Post-sync headers received from {} ({} headers), additional processing may be needed",
                            addr,
                            headers.len()
                        );
                    } else {
                        tracing::info!(
                            "📋 Post-sync headers received ({} headers), additional processing may be needed",
                            headers.len()
                        );
                    }
                }
            }
            NetworkMessage::Block(block) => {
                let block_hash = block.header.block_hash();
                tracing::info!("Received new block: {}", block_hash);
                tracing::debug!(
                    "📋 Block {} contains {} transactions",
                    block_hash,
                    block.txdata.len()
                );

                // 1) Ensure header processing and chain tip update for this block
                //    Route the header through the sequential sync manager as a Headers message
                let headers_msg = NetworkMessage::Headers(vec![block.header]);
                if let Err(e) = self
                    .sync_manager
                    .handle_message(&headers_msg, &mut *self.network, &mut *self.storage)
                    .await
                {
                    tracing::error!(
                        "❌ Failed to process header for block {} via sync manager: {}",
                        block_hash,
                        e
                    );
                    return Err(SpvError::Sync(e));
                }
            }
            NetworkMessage::Inv(inv) => {
                tracing::debug!("Received inventory message with {} items", inv.len());
                // Handle inventory messages (new blocks, transactions, etc.)
                self.handle_inventory(inv.clone()).await?;
            }
            NetworkMessage::Tx(tx) => {
                tracing::info!("📨 Received transaction: {}", tx.txid());

                // Only process if mempool tracking is enabled
                if let Some(filter) = self.mempool_filter {
                    // Check if we should process this transaction
                    if let Some(unconfirmed_tx) = filter.process_transaction(tx.clone()).await {
                        let txid = unconfirmed_tx.txid();
                        let amount = unconfirmed_tx.net_amount;
                        let is_instant_send = unconfirmed_tx.is_instant_send;
                        let addresses: Vec<String> =
                            unconfirmed_tx.addresses.iter().map(|a| a.to_string()).collect();

                        // Store in mempool
                        let mut state = self.mempool_state.write().await;
                        state.add_transaction(unconfirmed_tx.clone());
                        drop(state);

                        // Store in storage if persistence is enabled
                        if self.config.persist_mempool {
                            if let Err(e) =
                                self.storage.store_mempool_transaction(&txid, &unconfirmed_tx).await
                            {
                                tracing::error!("Failed to persist mempool transaction: {}", e);
                            }
                        }

                        // Emit event
                        let event = SpvEvent::MempoolTransactionAdded {
                            txid,
                            transaction: Box::new(tx.clone()),
                            amount,
                            addresses,
                            is_instant_send,
                        };
                        let _ = self.event_tx.send(event);

                        tracing::info!(
                            "💸 Added mempool transaction {} (amount: {})",
                            txid,
                            amount
                        );
                    } else {
                        tracing::debug!(
                            "Transaction {} not relevant or at capacity, ignoring",
                            tx.txid()
                        );
                    }
                } else {
                    tracing::warn!("⚠️ Received transaction {} but mempool tracking is disabled (enable_mempool_tracking=false)", tx.txid());
                }
            }
            NetworkMessage::CLSig(chain_lock) => {
                tracing::info!("Received ChainLock for block {}", chain_lock.block_hash);
                // ChainLock processing would need access to state and validation
                // This might need to be handled at the client level
                tracing::debug!("ChainLock processing not yet implemented in message handler");
            }
            NetworkMessage::ISLock(instant_lock) => {
                tracing::info!("Received InstantSendLock for tx {}", instant_lock.txid);
                // InstantLock processing would need access to validation
                // This might need to be handled at the client level
                tracing::debug!("InstantLock processing not yet implemented in message handler");
            }
            NetworkMessage::Ping(nonce) => {
                tracing::debug!("Received ping with nonce {}", nonce);
            }
            NetworkMessage::Pong(nonce) => {
                tracing::debug!("Received pong with nonce {}", nonce);
            }
            NetworkMessage::CFilter(cfilter) => {
                tracing::debug!("Received CFilter for block {}", cfilter.block_hash);
            }
            NetworkMessage::SendDsq(wants_dsq) => {
                tracing::info!("Received SendDsq message - peer wants DSQ messages: {}", wants_dsq);

                // Send our own SendDsq(false) in response - we're an SPV client and don't want DSQ messages
                tracing::info!("Sending SendDsq(false) to indicate we don't want DSQ messages");
                if let Err(e) = self.network.send_message(NetworkMessage::SendDsq(false)).await {
                    tracing::error!("Failed to send SendDsq response: {}", e);
                }
            }
            _ => {
                // Ignore other message types for now
                tracing::debug!("Received network message: {:?}", std::mem::discriminant(message));
            }
        }

        Ok(())
    }

    /// Handle inventory messages - auto-request ChainLocks and other important data.
    async fn handle_inventory(
        &mut self,
        inv: Vec<dashcore::network::message_blockdata::Inventory>,
    ) -> Result<()> {
        use dashcore::network::message::NetworkMessage;
        use dashcore::network::message_blockdata::Inventory;

        let mut chainlocks_to_request = Vec::new();
        let mut blocks_to_request = Vec::new();
        let mut islocks_to_request = Vec::new();

        for item in inv {
            match item {
                Inventory::Block(block_hash) => {
                    tracing::info!("🆕 Inventory: New block announcement {}", block_hash);
                    blocks_to_request.push(item);
                }
                Inventory::ChainLock(chainlock_hash) => {
                    tracing::info!("🔒 Inventory: New ChainLock {}", chainlock_hash);
                    chainlocks_to_request.push(item);
                }
                Inventory::InstantSendLock(islock_hash) => {
                    // Only fetch InstantSendLocks when we're fully synced and have masternode data
                    if self.sync_manager.is_synced()
                        && self.sync_manager.get_masternode_engine().is_some()
                    {
                        tracing::info!("⚡ Inventory: New InstantSendLock {}", islock_hash);
                        islocks_to_request.push(item);
                    } else {
                        tracing::debug!(
                            "Skipping InstantSendLock {} fetch - not fully synced or masternode engine unavailable",
                            islock_hash
                        );
                    }
                }
                Inventory::Transaction(txid) => {
                    tracing::debug!("💸 Inventory: New transaction {}", txid);

                    // Check if we should fetch this transaction
                    if let Some(filter) = self.mempool_filter {
                        if self.config.fetch_mempool_transactions
                            && filter.should_fetch_transaction(&txid).await
                        {
                            tracing::info!("📥 Requesting transaction {}", txid);
                            // Request the transaction
                            let getdata = NetworkMessage::GetData(vec![item]);
                            if let Err(e) = self.network.send_message(getdata).await {
                                tracing::error!("Failed to request transaction {}: {}", txid, e);
                            }
                        } else {
                            tracing::debug!("Not fetching transaction {} (fetch_mempool_transactions={}, should_fetch={})",
                                txid,
                                self.config.fetch_mempool_transactions,
                                filter.should_fetch_transaction(&txid).await
                            );
                        }
                    } else {
                        tracing::warn!("⚠️ Transaction {} announced but mempool tracking is disabled (enable_mempool_tracking=false)", txid);
                    }
                }
                _ => {
                    tracing::debug!("❓ Inventory: Other item type");
                }
            }
        }

        // Auto-request ChainLocks (highest priority for validation)
        if !chainlocks_to_request.is_empty() {
            tracing::info!("Requesting {} ChainLocks", chainlocks_to_request.len());
            let getdata = NetworkMessage::GetData(chainlocks_to_request);
            self.network.send_message(getdata).await.map_err(SpvError::Network)?;
        }

        // Auto-request InstantLocks (only when synced and masternodes available; gated above)
        if !islocks_to_request.is_empty() {
            tracing::info!("Requesting {} InstantLocks", islocks_to_request.len());
            let getdata = NetworkMessage::GetData(islocks_to_request);
            self.network.send_message(getdata).await.map_err(SpvError::Network)?;
        }

        // For blocks announced via inventory during tip sync, request full blocks for privacy
        if !blocks_to_request.is_empty() {
            tracing::info!(
                "📥 Requesting {} new blocks announced via inventory",
                blocks_to_request.len()
            );

            let getdata = NetworkMessage::GetData(blocks_to_request);
            if let Err(e) = self.network.send_message(getdata).await {
                tracing::error!("Failed to request announced blocks: {}", e);
            }
        }

        Ok(())
    }

    /// Handle new headers received after the initial sync is complete.
    /// The sequential sync manager will handle requesting filter headers internally.
    pub async fn handle_post_sync_headers(
        &mut self,
        headers: &[dashcore::block::Header],
    ) -> Result<()> {
        if !self.config.enable_filters {
            tracing::debug!(
                "Filters not enabled, skipping post-sync filter requests for {} headers",
                headers.len()
            );
            return Ok(());
        }

        tracing::info!(
            "Handling {} post-sync headers - sequential sync will manage filter requests",
            headers.len()
        );

        // The sequential sync manager's handle_new_headers method will automatically
        // request filter headers and filters as needed
        self.sync_manager
            .handle_new_headers(headers, &mut *self.network, &mut *self.storage)
            .await
            .map_err(SpvError::Sync)?;

        Ok(())
    }
}
