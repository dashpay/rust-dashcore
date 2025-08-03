//! Sync engine that owns the SPV client and handles all mutations
//!
//! This separates the mutable sync operations from read-only status queries.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

use crate::client::DashSpvClient;
use crate::error::{Result as SpvResult, SpvError, SyncError};
use crate::types::{NetworkEvent, SyncProgress};
use dashcore::sml::llmq_type::LLMQType;
use dashcore::QuorumHash;
use dashcore_hashes::Hash;

use super::sync_state::{SyncState, SyncStateReader, SyncStateWriter};

/// Sync engine that owns the SPV client and manages synchronization
pub struct SyncEngine {
    /// The SPV client (owned, not shared)
    client: Option<DashSpvClient>,

    /// Shared sync state
    sync_state: Arc<RwLock<SyncState>>,

    /// State writer
    state_writer: SyncStateWriter,

    /// Background sync task handle
    sync_task: Option<JoinHandle<SpvResult<()>>>,

    /// Control channel for sync commands
    control_tx: tokio::sync::mpsc::Sender<SyncCommand>,
    control_rx: Option<tokio::sync::mpsc::Receiver<SyncCommand>>,
}

/// Commands that can be sent to the sync engine
#[derive(Debug)]
enum SyncCommand {
    /// Start synchronization
    StartSync,

    /// Stop synchronization
    StopSync,

    /// Get a quorum public key
    GetQuorumKey {
        quorum_type: u8,
        quorum_hash: [u8; 32],
        response: tokio::sync::oneshot::Sender<Option<[u8; 48]>>,
    },

    /// Shutdown the engine
    Shutdown,
}

impl SyncEngine {
    /// Create a new sync engine with the given client
    pub fn new(client: DashSpvClient) -> Self {
        let sync_state = Arc::new(RwLock::new(SyncState::default()));
        let state_writer = SyncStateWriter::new(sync_state.clone());

        let (control_tx, control_rx) = tokio::sync::mpsc::channel(10);

        Self {
            client: Some(client),
            sync_state,
            state_writer,
            sync_task: None,
            control_tx,
            control_rx: Some(control_rx),
        }
    }

    /// Get a reader for the sync state
    pub fn state_reader(&self) -> SyncStateReader {
        SyncStateReader::new(self.sync_state.clone())
    }

    /// Start the sync engine
    pub async fn start(&mut self) -> SpvResult<()> {
        if self.sync_task.is_some() {
            return Err(SpvError::Sync(SyncError::InvalidState(
                "Sync engine already running".to_string(),
            )));
        }

        // Take ownership of the client and control receiver
        let mut client = self.client.take().ok_or_else(|| {
            SpvError::Sync(SyncError::InvalidState("Client already taken".to_string()))
        })?;

        let mut control_rx = self.control_rx.take().ok_or_else(|| {
            SpvError::Sync(SyncError::InvalidState("Control receiver already taken".to_string()))
        })?;

        let state_writer = self.state_writer.clone();
        let control_tx = self.control_tx.clone();

        // Start the client
        client.start().await?;

        // Wait for peers to connect before initiating sync
        let start = tokio::time::Instant::now();
        while client.peer_count() == 0 && start.elapsed() < tokio::time::Duration::from_secs(5) {
            tracing::info!("Waiting for peers to connect...");
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }

        if client.peer_count() == 0 {
            tracing::warn!("No peers connected after 5 seconds, proceeding anyway");
        } else {
            tracing::info!("Connected to {} peers", client.peer_count());
        }

        // Call sync_to_tip to prepare the client state
        if let Err(e) = client.sync_to_tip().await {
            tracing::error!("Failed to prepare sync state: {:?}", e);
        }

        // Spawn the sync task
        let handle = tokio::spawn(async move {
            Self::sync_loop(client, control_rx, control_tx, state_writer).await
        });

        self.sync_task = Some(handle);

        // Trigger initial sync
        self.control_tx.send(SyncCommand::StartSync).await.map_err(|_| {
            SpvError::Sync(SyncError::InvalidState("Failed to send start sync command".to_string()))
        })?;

        Ok(())
    }

    /// Stop the sync engine
    pub async fn stop(&mut self) -> SpvResult<()> {
        // Send shutdown command
        let _ = self.control_tx.send(SyncCommand::Shutdown).await;

        // Wait for the sync task to complete
        if let Some(handle) = self.sync_task.take() {
            let _ = handle.await;
        }

        Ok(())
    }

    /// The main sync loop that runs in a background task
    async fn sync_loop(
        mut client: DashSpvClient,
        mut control_rx: tokio::sync::mpsc::Receiver<SyncCommand>,
        control_tx: tokio::sync::mpsc::Sender<SyncCommand>,
        state_writer: SyncStateWriter,
    ) -> SpvResult<()> {
        let mut sync_active = false;
        let mut sync_triggered = false;

        loop {
            tokio::select! {
                // Handle control commands with priority
                biased;

                Some(command) = control_rx.recv() => {
                    match command {
                        SyncCommand::StartSync => {
                            if !sync_active {
                                tracing::info!("Starting synchronization");
                                sync_active = true;

                                // Get peer best height first
                                let best_peer_height = client.get_best_peer_height().await.unwrap_or(0);

                                // Update state
                                state_writer.update(|state| {
                                    state.phase = super::sync_state::SyncPhase::Connecting;
                                    state.sync_start_time = Some(std::time::Instant::now());
                                    // Set target height from peers
                                    if best_peer_height > state.target_height {
                                        state.target_height = best_peer_height;
                                    }
                                }).await;

                                // First call sync_to_tip if not done yet
                                if !sync_triggered {
                                    if let Err(e) = client.sync_to_tip().await {
                                        tracing::error!("Failed to prepare sync: {}", e);
                                    }
                                }

                                // Trigger sync
                                match client.trigger_sync_start().await {
                                    Ok(started) => {
                                        sync_triggered = true;
                                        if started {
                                            tracing::info!("📊 Sync started - client is behind peers");
                                            
                                            // Get current heights
                                            let current_height = client.chain_height().await.unwrap_or(0);
                                            let target = state_writer.get_target_height().await;
                                            
                                            state_writer.update(|state| {
                                                state.current_height = current_height;
                                                state.update_headers_progress(current_height, target);
                                            }).await;
                                        } else {
                                            tracing::info!("✅ Already synced to peer height");
                                            sync_active = false;
                                            state_writer.update(|state| {
                                                state.phase = super::sync_state::SyncPhase::Synced;
                                                state.headers_synced = true;
                                            }).await;
                                        }
                                    }
                                    Err(e) => {
                                        tracing::error!("Failed to start sync: {}", e);
                                        sync_active = false;

                                        state_writer.update(|state| {
                                            state.phase = super::sync_state::SyncPhase::Error(e.to_string());
                                        }).await;
                                    }
                                }
                            }
                        }

                        SyncCommand::StopSync => {
                            if sync_active {
                                tracing::info!("Stopping synchronization");
                                sync_active = false;

                                state_writer.update(|state| {
                                    state.phase = super::sync_state::SyncPhase::Idle;
                                }).await;
                            }
                        }

                        SyncCommand::GetQuorumKey { quorum_type, quorum_hash, response } => {
                            let result = Self::get_quorum_key_from_client(&client, quorum_type, &quorum_hash);
                            let _ = response.send(result);
                        }

                        SyncCommand::Shutdown => {
                            tracing::info!("Shutting down sync engine");
                            let _ = client.stop().await;
                            break;
                        }
                    }
                }

                // Process network messages and events
                _ = async {
                    if sync_active {
                        // Process network messages
                        if let Err(e) = client.process_network_messages(Duration::from_millis(100)).await {
                            tracing::error!("Error processing network messages: {}", e);
                        }

                        // Check for events and update state
                        match client.next_event_timeout(Duration::from_millis(50)).await {
                            Ok(Some(event)) => {
                                let should_trigger_sync = Self::handle_event(event, &state_writer).await;

                                // If event handler says we should trigger sync, send the command
                                if should_trigger_sync && !sync_active {
                                    if let Err(e) = control_tx.send(SyncCommand::StartSync).await {
                                        tracing::error!("Failed to send StartSync command: {}", e);
                                    }
                                }
                            }
                            Ok(None) => {
                                // No events available
                            }
                            Err(e) => {
                                tracing::error!("Error getting event: {}", e);
                            }
                        }

                        // Periodically update sync progress from client
                        if let Ok(progress) = client.sync_progress().await {
                            let current_height = progress.header_height;
                            let headers_synced = progress.headers_synced;

                            // Get the best height from connected peers
                            let best_peer_height = client.get_best_peer_height().await.unwrap_or(0);

                            state_writer.update(|state| {
                                state.current_height = progress.header_height;
                                state.headers_synced = progress.headers_synced;
                                state.filter_headers_synced = progress.filter_headers_synced;
                                state.phase_info = progress.current_phase;

                                // Update target height if we have a better one from peers
                                if best_peer_height > state.target_height {
                                    state.target_height = best_peer_height;
                                }

                                // Update phase based on progress
                                if progress.headers_synced && progress.filter_headers_synced {
                                    state.phase = super::sync_state::SyncPhase::Synced;
                                    sync_active = false;
                                } else if !progress.headers_synced {
                                    // Still syncing headers
                                    if state.target_height > 0 {
                                        state.phase = super::sync_state::SyncPhase::Headers {
                                            start_height: 0,
                                            current_height: progress.header_height,
                                            target_height: state.target_height,
                                        };
                                    }
                                }
                            }).await;

                            // Check if sync appears stuck at a checkpoint
                            if sync_active && !headers_synced && current_height == 1900000 {
                                tracing::warn!(
                                    "Sync appears stuck at checkpoint height 1900000. Current state: sync_active={}, headers_synced={}",
                                    sync_active,
                                    headers_synced
                                );

                                // Try to trigger sync continuation
                                match client.trigger_sync_start().await {
                                    Ok(started) => {
                                        if started {
                                            tracing::info!("Manually triggered sync continuation from height {}", current_height);
                                        } else {
                                            tracing::info!("Sync trigger returned false - client thinks it's synced");
                                        }
                                    }
                                    Err(e) => {
                                        tracing::error!("Failed to trigger sync continuation: {}", e);
                                    }
                                }
                            }
                        }
                    } else {
                        // Not syncing, just sleep
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                } => {}
            }
        }

        Ok(())
    }

    /// Handle network events and update sync state
    /// Returns true if sync should be triggered
    async fn handle_event(event: NetworkEvent, state_writer: &SyncStateWriter) -> bool {
        let mut should_trigger_sync = false;

        match event {
            NetworkEvent::SyncStarted {
                starting_height,
                target_height,
            } => {
                tracing::info!("Sync started from {} to {:?}", starting_height, target_height);

                state_writer
                    .update(|state| {
                        state.current_height = starting_height;
                        if let Some(target) = target_height {
                            state.target_height = target;
                        }
                        
                        // Update the phase info with proper details
                        state.update_headers_progress(starting_height, target_height.unwrap_or(state.target_height));
                    })
                    .await;
            }

            NetworkEvent::HeadersReceived {
                count,
                tip_height,
                progress_percent,
            } => {
                tracing::debug!(
                    "Headers received: {} (tip: {}, progress: {:.1}%)",
                    count,
                    tip_height,
                    progress_percent
                );

                state_writer
                    .update(|state| {
                        // Update current height
                        state.current_height = tip_height;
                        
                        // Recalculate progress with proper target
                        let actual_progress = if state.target_height > 0 {
                            (tip_height as f64 / state.target_height as f64 * 100.0)
                        } else {
                            progress_percent
                        };
                        
                        state.update_headers_progress(tip_height, state.target_height);

                        if actual_progress >= 100.0 || progress_percent >= 100.0 {
                            state.mark_headers_synced(tip_height);
                        }
                    })
                    .await;
            }

            NetworkEvent::SyncCompleted {
                final_height,
            } => {
                tracing::info!("Sync completed at height {}", final_height);

                state_writer
                    .update(|state| {
                        state.current_height = final_height;
                        state.target_height = final_height;
                        state.headers_synced = true;
                        state.phase = super::sync_state::SyncPhase::Synced;
                    })
                    .await;
            }

            NetworkEvent::PeerConnected {
                address,
                height,
                ..
            } => {
                tracing::info!("Peer connected: {} with height {:?}", address, height);

                if let Some(peer_height) = height {
                    let mut trigger_sync = false;

                    state_writer
                        .update(|state| {
                            // Update target height if peer has higher height
                            if peer_height > state.target_height {
                                state.target_height = peer_height;
                            }

                            // Check if we should trigger sync
                            trigger_sync = !state.headers_synced
                                && state.current_height < peer_height
                                && matches!(
                                    state.phase,
                                    super::sync_state::SyncPhase::Idle
                                        | super::sync_state::SyncPhase::Connecting
                                );

                            if trigger_sync {
                                tracing::info!(
                                    "First peer connected with height {}, need to trigger sync",
                                    peer_height
                                );
                            }
                        })
                        .await;

                    should_trigger_sync = trigger_sync;
                }
            }

            _ => {
                // Other events don't affect sync state
            }
        }

        should_trigger_sync
    }

    /// Get current sync progress (convenience method)
    pub async fn sync_progress(&self) -> SpvResult<SyncProgress> {
        let reader = self.state_reader();
        Ok(reader.get_progress().await)
    }

    /// Get a quorum public key
    pub async fn get_quorum_public_key(
        &self,
        quorum_type: u8,
        quorum_hash: &[u8; 32],
    ) -> SpvResult<Option<[u8; 48]>> {
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();

        self.control_tx
            .send(SyncCommand::GetQuorumKey {
                quorum_type,
                quorum_hash: *quorum_hash,
                response: response_tx,
            })
            .await
            .map_err(|_| {
                SpvError::Sync(SyncError::InvalidState(
                    "Failed to send GetQuorumKey command".to_string(),
                ))
            })?;

        response_rx.await.map_err(|_| {
            SpvError::Sync(SyncError::InvalidState(
                "Failed to receive GetQuorumKey response".to_string(),
            ))
        })
    }

    /// Get quorum key directly from the client's MasternodeListEngine
    fn get_quorum_key_from_client(
        client: &DashSpvClient,
        quorum_type: u8,
        quorum_hash: &[u8; 32],
    ) -> Option<[u8; 48]> {
        let mn_list_engine = client.masternode_list_engine()?;
        let llmq_type = LLMQType::from(quorum_type);

        // Try both reversed and unreversed hash
        let mut reversed_hash = *quorum_hash;
        reversed_hash.reverse();
        let quorum_hash_typed = QuorumHash::from_slice(&reversed_hash).map_err(|_| ()).ok()?;

        // Search through masternode lists
        for (_height, mn_list) in &mn_list_engine.masternode_lists {
            if let Some(quorums) = mn_list.quorums.get(&llmq_type) {
                // Query with reversed hash
                if let Some(entry) = quorums.get(&quorum_hash_typed) {
                    let public_key_bytes: &[u8] = entry.quorum_entry.quorum_public_key.as_ref();
                    if public_key_bytes.len() == 48 {
                        let mut key_array = [0u8; 48];
                        key_array.copy_from_slice(public_key_bytes);
                        return Some(key_array);
                    }
                }
            }
        }

        None
    }
}
