use crate::error::SyncResult;
use crate::network::{Message, MessageType, RequestSender};
use crate::storage::BlockHeaderStorage;
use crate::sync::{
    ChainLockManager, ManagerIdentifier, SyncEvent, SyncManager, SyncManagerProgress, SyncState,
};
use async_trait::async_trait;
use dashcore::network::message::NetworkMessage;
use dashcore::network::message_blockdata::Inventory;

#[async_trait]
impl<H: BlockHeaderStorage> SyncManager for ChainLockManager<H> {
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
                    // Mark these as requested
                    for item in &chainlocks_to_request {
                        if let Inventory::ChainLock(hash) = item {
                            self.requested_chainlocks.insert(*hash);
                        }
                    }

                    tracing::info!(
                        "Received {} ChainLock announcements, requesting via getdata",
                        chainlocks_to_request.len()
                    );
                    requests.request_inventory(chainlocks_to_request)?;
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
        // Enable ChainLock validation when masternode state is available
        if let SyncEvent::MasternodeStateUpdated {
            ..
        } = event
        {
            self.set_masternode_ready();
            if matches!(self.state(), SyncState::Syncing | SyncState::WaitForEvents) {
                self.set_state(SyncState::Synced);
                tracing::info!("ChainLock manager synced (masternode data available)");
            }
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
