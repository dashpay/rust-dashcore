//! Event handling and emission.
//!
//! This module contains:
//! - Event receiver management
//! - Event emission

use tokio::sync::mpsc;

use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::types::{DetailedSyncProgress, SpvEvent};
use key_wallet_manager::wallet_interface::WalletInterface;

use super::DashSpvClient;

impl<
        W: WalletInterface + Send + Sync + 'static,
        N: NetworkManager + Send + Sync + 'static,
        S: StorageManager + Send + Sync + 'static,
    > DashSpvClient<W, N, S>
{
    /// Take the event receiver for external consumption.
    pub fn take_event_receiver(&mut self) -> Option<mpsc::UnboundedReceiver<SpvEvent>> {
        self.event_rx.take()
    }

    /// Emit an event.
    pub(crate) fn emit_event(&self, event: SpvEvent) {
        tracing::debug!("Emitting event: {:?}", event);
        let _ = self.event_tx.send(event);
    }

    /// Take the progress receiver for external consumption.
    pub fn take_progress_receiver(
        &mut self,
    ) -> Option<mpsc::UnboundedReceiver<DetailedSyncProgress>> {
        self.progress_receiver.take()
    }

    /// Emit a progress update.
    pub(super) fn emit_progress(&self, progress: DetailedSyncProgress) {
        if let Some(ref sender) = self.progress_sender {
            let _ = sender.send(progress);
        }
    }
}
