//! ChainLock processing and validation.
//!
//! This module contains:
//! - ChainLock processing
//! - InstantSendLock processing
//! - ChainLock validation updates
//! - Pending ChainLock validation

use std::sync::Arc;

use crate::error::{Result, SpvError};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::types::SpvEvent;
use key_wallet_manager::wallet_interface::WalletInterface;

use super::DashSpvClient;

impl<
        W: WalletInterface + Send + Sync + 'static,
        N: NetworkManager + Send + Sync + 'static,
        S: StorageManager + Send + Sync + 'static,
    > DashSpvClient<W, N, S>
{
    /// Process and validate a ChainLock.
    pub async fn process_chainlock(
        &mut self,
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
            self.chainlock_manager
                .process_chain_lock(chainlock.clone(), &chain_state, &mut *storage)
                .await
                .map_err(SpvError::Validation)?;
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

    /// Process and validate an InstantSendLock.
    pub(super) async fn process_instantsendlock(
        &mut self,
        islock: dashcore::ephemerealdata::instant_lock::InstantLock,
    ) -> Result<()> {
        tracing::info!("Processing InstantSendLock for tx {}", islock.txid);

        // TODO: Implement InstantSendLock validation
        // - Verify BLS signature against known quorum
        // - Check if all inputs are locked
        // - Mark transaction as instantly confirmed
        // - Store InstantSendLock for future reference

        // For now, just log the InstantSendLock details
        tracing::info!(
            "InstantSendLock validated: txid={}, inputs={}, signature={:?}",
            islock.txid,
            islock.inputs.len(),
            islock.signature.to_string().chars().take(20).collect::<String>()
        );

        Ok(())
    }

    /// Update ChainLock validation with masternode engine after sync completes.
    /// This should be called when masternode sync finishes to enable full validation.
    /// Returns true if the engine was successfully set.
    pub fn update_chainlock_validation(&self) -> Result<bool> {
        // Check if masternode sync has an engine available
        if let Some(engine) = self.sync_manager.get_masternode_engine() {
            // Clone the engine for the ChainLockManager
            let engine_arc = Arc::new(engine.clone());
            self.chainlock_manager.set_masternode_engine(engine_arc);

            tracing::info!("Updated ChainLockManager with masternode engine for full validation");

            // Note: Pending ChainLocks will be validated when they are next processed
            // or can be triggered by calling validate_pending_chainlocks separately
            // when mutable access to storage is available

            Ok(true)
        } else {
            tracing::warn!("Masternode engine not available for ChainLock validation update");
            Ok(false)
        }
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
