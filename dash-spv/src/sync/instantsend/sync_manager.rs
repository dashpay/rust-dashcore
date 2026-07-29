use crate::error::SyncResult;
use crate::network::{MessageType, NetworkManager};
use crate::sync::{
    InstantSendManager, ManagerIdentifier, SyncEvent, SyncManager, SyncManagerProgress, SyncState,
};
use async_trait::async_trait;
use dashcore::network::message::NetworkMessage;
use dashcore::network::message_blockdata::Inventory;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

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
        &[MessageType::IsDLock, MessageType::Inv]
    }

    fn on_disconnect(&mut self) {
        // Clear the queue *and* drop unvalidated cache entries. Leaving the
        // latter behind would make `process_instantlock` treat a lock
        // re-announced after reconnect as a duplicate, so it would never be
        // re-queued or re-validated.
        self.clear_unvalidated_on_disconnect();
        // Nothing is queued anymore, so the height at which we last validated is
        // meaningless; reset it so re-validation runs again after reconnect.
        self.last_validated_engine_height = None;
    }

    async fn handle_message(
        &mut self,
        peer: SocketAddr,
        msg: NetworkMessage,
        network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<Vec<SyncEvent>> {
        match &msg {
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
                    network.send_to(peer, NetworkMessage::GetData(islocks_to_request)).await;
                }
                Ok(vec![])
            }
            _ => Ok(vec![]),
        }
    }

    async fn handle_sync_event(
        &mut self,
        event: &SyncEvent,
        _network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<Vec<SyncEvent>> {
        // Drop buffered events that arrive between `stop_sync` and the next
        // `start_sync`. `pending_instantlocks` is cleared on disconnect, and
        // `MasternodesManager` re-emits `MasternodeStateUpdated` once it
        // completes a sync cycle after reconnect.
        if self.state() == SyncState::WaitingForConnections {
            return Ok(vec![]);
        }

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
                self.validate_pending(Instant::now()).await?
            } else {
                vec![]
            };

            // Transition to Synced when no pending validations after masternode sync.
            self.transition_synced_if_idle();

            return Ok(events);
        }

        Ok(vec![])
    }

    async fn tick(&mut self, network: &Arc<dyn NetworkManager>) -> SyncResult<Vec<SyncEvent>> {
        self.tick_at(Instant::now(), network).await
    }

    fn progress(&self) -> SyncManagerProgress {
        SyncManagerProgress::InstantSend(self.progress.clone())
    }
}

impl InstantSendManager {
    /// `tick` with the current time injected, so tests can drive TTL expiry with
    /// a future instant instead of back-dating `first_seen` (an `Instant` cannot
    /// portably be back-dated by subtraction — `PendingInstantLock::is_expired`
    /// explains why). The trait `tick` passes `Instant::now()`.
    pub(super) async fn tick_at(
        &mut self,
        now: Instant,
        _network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<Vec<SyncEvent>> {
        // Prune old entries periodically
        self.prune_old_entries();

        // Whether there was work to resolve at the start of this tick. Guards the
        // synced-state transition below so a freshly created manager sitting idle
        // in `WaitForEvents` isn't marked `Synced` without ever having done work.
        let had_pending = !self.pending_instantlocks.is_empty();

        // Expire pending locks that have outlived their TTL. This runs on every
        // tick, independent of engine advancement — otherwise, with a static
        // engine height, `validate_pending` (the only other place expiry runs)
        // would never be reached and a lock could stay pending forever.
        self.expire_pending(now);

        // Re-validate queued InstantLocks once the masternode engine has advanced
        // past the height at which they were last checked. A lock received before
        // quorum sync completed (e.g. right after a fresh SPV start, for a
        // transaction the wallet just broadcast) is then verified as soon as the
        // needed quorum data lands, rather than waiting for the next
        // `MasternodeStateUpdated` event — which, for a just-broadcast
        // transaction, may not arrive until the block that mines it.
        let mut events = Vec::new();
        if !self.pending_instantlocks.is_empty() {
            let engine_height = self.engine_height().await;
            let advanced = match (engine_height, self.last_validated_engine_height) {
                (Some(current), Some(last)) => current > last,
                (Some(_), None) => true,
                (None, _) => false,
            };
            if advanced {
                events = self.validate_pending(now).await?;
            }
        }

        // If this tick started with pending work that has now fully drained (via
        // expiry or validation), mirror `handle_sync_event` and resolve the
        // manager's state — otherwise a final lock resolved by tick rather than a
        // `MasternodeStateUpdated` event would leave it stuck in `Syncing`.
        if had_pending {
            self.transition_synced_if_idle();
        }

        Ok(events)
    }
}
