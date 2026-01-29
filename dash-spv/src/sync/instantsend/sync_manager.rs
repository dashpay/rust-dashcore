use crate::error::SyncResult;
use crate::network::{Message, MessageType, RequestSender};
use crate::sync::{
    InstantSendManager, ManagerIdentifier, SyncEvent, SyncManager, SyncManagerProgress, SyncState,
};
use async_trait::async_trait;
use dashcore::network::message::NetworkMessage;
use dashcore::network::message_blockdata::Inventory;

#[async_trait]
impl SyncManager for InstantSendManager {
    fn identifier(&self) -> ManagerIdentifier {
        ManagerIdentifier::InstantSend
    }

    fn state(&self) -> SyncState {
        self.progress.state()
    }

    fn set_state(&mut self, state: SyncState) {
        self.progress.set_state(state);
    }

    fn wanted_message_types(&self) -> &'static [MessageType] {
        &[MessageType::ISLock, MessageType::Inv]
    }

    async fn handle_message(
        &mut self,
        msg: Message,
        requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>> {
        match msg.inner() {
            NetworkMessage::ISLock(instantlock) => self.process_instantlock(instantlock).await,
            NetworkMessage::Inv(inv) => {
                // Check for InstantSendLock inventory items
                let islocks_to_request: Vec<Inventory> = inv
                    .iter()
                    .filter(|item| matches!(item, Inventory::InstantSendLock(_)))
                    .cloned()
                    .collect();

                if !islocks_to_request.is_empty() {
                    tracing::info!(
                        "Received {} InstantSendLock announcements, requesting via getdata",
                        islocks_to_request.len()
                    );
                    requests.request_inventory(islocks_to_request)?;
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
        // Validate pending InstantLocks when masternode state is updated
        if let SyncEvent::MasternodeStateUpdated {
            ..
        } = event
        {
            let pending = self.pending_count();
            let events = if pending > 0 {
                tracing::info!(
                    "Masternode state updated, validating {} pending InstantLocks",
                    pending
                );
                self.validate_pending().await?
            } else {
                vec![]
            };

            // Transition to Synced when no pending validations after masternode sync
            if self.pending_count() == 0
                && matches!(self.state(), SyncState::Syncing | SyncState::WaitForEvents)
            {
                self.set_state(SyncState::Synced);
                tracing::info!("InstantSend manager synced (no pending validations)");
            }

            return Ok(events);
        }

        Ok(vec![])
    }

    async fn tick(&mut self, _requests: &RequestSender) -> SyncResult<Vec<SyncEvent>> {
        // Prune old entries periodically
        self.prune_old_entries();
        Ok(vec![])
    }

    fn progress(&self) -> SyncManagerProgress {
        SyncManagerProgress::InstantSend(self.progress.clone())
    }
}
