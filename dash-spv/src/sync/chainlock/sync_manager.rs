use crate::error::SyncResult;
use crate::network::{Message, MessageType, RequestSender};
use crate::storage::{BlockHeaderStorage, MetadataStorage};
use crate::sync::{
    ChainLockManager, ManagerIdentifier, SyncEvent, SyncManager, SyncManagerProgress, SyncState,
};
use async_trait::async_trait;
use dashcore::network::message::NetworkMessage;
use dashcore::network::message_blockdata::Inventory;

#[async_trait]
impl<H: BlockHeaderStorage, M: MetadataStorage> SyncManager for ChainLockManager<H, M> {
    fn identifier(&self) -> ManagerIdentifier {
        ManagerIdentifier::ChainLock
    }

    fn state(&self) -> SyncState {
        self.progress.state()
    }

    fn set_state(&mut self, state: SyncState) {
        self.progress.set_state(state);
    }

    fn wanted_message_types(&self) -> &'static [MessageType] {
        &[MessageType::CLSig, MessageType::Inv]
    }

    fn on_disconnect(&mut self) {
        self.requested_chainlocks.clear();
        self.masternode_ready = false;
    }

    async fn handle_message(
        &mut self,
        msg: Message,
        requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>> {
        match msg.inner() {
            NetworkMessage::CLSig(chainlock) => self.process_chainlock(chainlock).await,
            NetworkMessage::Inv(inv) => {
                // Check for ChainLock inventory items, filtering out already-requested ones
                let chainlocks_to_request: Vec<Inventory> = inv
                    .iter()
                    .filter(|item| {
                        if let Inventory::ChainLock(hash) = item {
                            // Only request if we haven't already requested this ChainLock
                            !self.requested_chainlocks.contains(hash)
                        } else {
                            false
                        }
                    })
                    .cloned()
                    .collect();

                if !chainlocks_to_request.is_empty() {
                    tracing::info!(
                        "Received {} ChainLock announcements, requesting via getdata",
                        chainlocks_to_request.len()
                    );
                    requests
                        .request_inventory(chainlocks_to_request.clone(), msg.peer_address())?;

                    for item in &chainlocks_to_request {
                        if let Inventory::ChainLock(hash) = item {
                            self.requested_chainlocks.insert(*hash);
                        }
                    }
                }
                Ok(vec![])
            }
            _ => Ok(vec![]),
        }
    }

    async fn handle_sync_event(
        &mut self,
        event: &SyncEvent,
        _requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>> {
        // `MasternodeStateUpdated` fires on every MnListDiff / QRInfo
        // update; the work below is strictly one-shot startup work, so
        // gate the entire branch on the not-ready transition. Also drop
        // buffered events that arrive between `stop_sync` and the next
        // `start_sync`, otherwise the one-shot would force `Synced` while
        // peerless. `MasternodeStateUpdated` re-fires once `MasternodesManager`
        // completes a sync cycle after reconnect.
        if !matches!(event, SyncEvent::MasternodeStateUpdated { .. })
            || self.masternode_ready
            || self.state() == SyncState::WaitingForConnections
        {
            return Ok(vec![]);
        }

        let chainlock = self.on_masternode_ready().await;
        self.set_state(SyncState::Synced);
        tracing::info!("ChainLock manager synced (masternode data available)");

        // Re-broadcast the best chainlock we know about so downstream
        // consumers (e.g. the wallet manager's record promotion) learn
        // pre-ready state without waiting for a fresh CLSig from the
        // network. Covers both the persisted-from-disk case and a
        // chainlock that arrived during initial sync but couldn't be
        // validated until now.
        if let Some(chain_lock) = chainlock {
            return Ok(vec![SyncEvent::ChainLockReceived {
                chain_lock,
                validated: true,
            }]);
        }

        Ok(vec![])
    }

    async fn tick(&mut self, _requests: &RequestSender) -> SyncResult<Vec<SyncEvent>> {
        // No periodic work needed
        Ok(vec![])
    }

    fn progress(&self) -> SyncManagerProgress {
        SyncManagerProgress::ChainLock(self.progress.clone())
    }
}
