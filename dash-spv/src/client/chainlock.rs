//! ChainLock processing and validation.
//!
//! This module contains:
//! - ChainLock processing
//! - InstantSendLock processing
//! - ChainLock validation updates
//! - Pending ChainLock validation

use crate::error::{Result, SpvError};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::types::SpvEvent;
use key_wallet_manager::wallet_interface::WalletInterface;
use std::net::SocketAddr;

use super::DashSpvClient;

impl<W: WalletInterface, N: NetworkManager, S: StorageManager> DashSpvClient<W, N, S> {
    /// Process and validate a ChainLock.
    pub async fn process_chainlock(
        &mut self,
        peer_address: SocketAddr,
        chainlock: dashcore::ephemerealdata::chain_lock::ChainLock,
    ) -> Result<()> {
        tracing::info!(
            "Processing ChainLock for block {} at height {}",
            chainlock.block_hash,
            chainlock.block_height
        );

        // First perform basic validation and storage through ChainLockManager
        let chain_state = self.state.read().await;
        {
            let mut storage = self.storage.lock().await;
            if let Err(e) = self
                .chainlock_manager
                .process_chain_lock(chainlock.clone(), &chain_state, &mut *storage)
                .await
            {
                // Penalize the peer that relayed the invalid ChainLock
                let reason = format!("Invalid ChainLock: {}", e);
                self.network.penalize_peer_invalid_chainlock(peer_address, &reason).await;
                return Err(SpvError::Validation(e));
            }
        }
        drop(chain_state);

        // Sequential sync handles masternode validation internally
        tracing::info!(
            "ChainLock stored, sequential sync will handle masternode validation internally"
        );

        // Update chain state with the new ChainLock
        let mut state = self.state.write().await;
        if let Some(current_chainlock_height) = state.last_chainlock_height {
            if chainlock.block_height <= current_chainlock_height {
                tracing::debug!(
                    "ChainLock for height {} does not supersede current ChainLock at height {}",
                    chainlock.block_height,
                    current_chainlock_height
                );
                return Ok(());
            }
        }

        // Update our confirmed chain tip
        state.last_chainlock_height = Some(chainlock.block_height);
        state.last_chainlock_hash = Some(chainlock.block_hash);

        tracing::info!(
            "🔒 Updated confirmed chain tip to ChainLock at height {} ({})",
            chainlock.block_height,
            chainlock.block_hash
        );

        // Emit ChainLock event
        self.emit_event(SpvEvent::ChainLockReceived {
            height: chainlock.block_height,
            hash: chainlock.block_hash,
        });

        // No need for additional storage - ChainLockManager already handles it
        Ok(())
    }

    /// Validate all pending ChainLocks after masternode engine is available.
    /// This requires mutable access to self for storage access.
    pub async fn validate_pending_chainlocks(&mut self) -> Result<()> {
        let chain_state = self.state.read().await;

        let mut storage = self.storage.lock().await;
        match self.chainlock_manager.validate_pending_chainlocks(&chain_state, &mut *storage).await
        {
            Ok(_) => {
                tracing::info!("Successfully validated pending ChainLocks");
                Ok(())
            }
            Err(e) => {
                tracing::error!("Failed to validate pending ChainLocks: {}", e);
                Err(SpvError::Validation(e))
            }
        }
    }
}
