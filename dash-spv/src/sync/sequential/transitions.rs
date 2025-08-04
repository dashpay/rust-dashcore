//! Phase transition logic for sequential sync

use crate::client::ClientConfig;
use crate::error::{SyncError, SyncResult};
use crate::storage::StorageManager;

use super::phases::{PhaseTransition, SyncPhase};
use std::time::Instant;

/// Manages phase transitions and validation
pub struct TransitionManager {
    config: ClientConfig,
}

impl TransitionManager {
    /// Create a new transition manager
    pub fn new(config: &ClientConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    /// Check if we can transition from current phase to target phase
    pub async fn can_transition_to(
        &self,
        current_phase: &SyncPhase,
        target_phase: &SyncPhase,
        storage: &dyn StorageManager,
    ) -> SyncResult<bool> {
        // Can't transition to the same phase
        if std::mem::discriminant(current_phase) == std::mem::discriminant(target_phase) {
            return Ok(false);
        }

        // Check specific transition rules
        match (current_phase, target_phase) {
            // From Idle, can only go to DownloadingHeaders
            (
                SyncPhase::Idle,
                SyncPhase::DownloadingHeaders {
                    ..
                },
            ) => Ok(true),

            // From DownloadingHeaders, check completion
            (
                SyncPhase::DownloadingHeaders {
                    ..
                },
                next_phase,
            ) => {
                // Headers must be complete
                if !self.are_headers_complete(current_phase, storage).await? {
                    return Ok(false);
                }

                // Can go to MnList if enabled, or skip to CFHeaders
                match next_phase {
                    SyncPhase::DownloadingMnList {
                        ..
                    } => Ok(self.config.enable_masternodes),
                    SyncPhase::DownloadingCFHeaders {
                        ..
                    } => Ok(!self.config.enable_masternodes && self.config.enable_filters),
                    SyncPhase::FullySynced {
                        ..
                    } => Ok(!self.config.enable_masternodes && !self.config.enable_filters),
                    _ => Ok(false),
                }
            }

            // From DownloadingMnList
            (
                SyncPhase::DownloadingMnList {
                    ..
                },
                next_phase,
            ) => {
                // MnList must be complete
                if !self.are_masternodes_complete(current_phase, storage).await? {
                    return Ok(false);
                }

                match next_phase {
                    SyncPhase::DownloadingCFHeaders {
                        ..
                    } => Ok(self.config.enable_filters),
                    SyncPhase::FullySynced {
                        ..
                    } => Ok(!self.config.enable_filters),
                    _ => Ok(false),
                }
            }

            // From DownloadingCFHeaders
            (
                SyncPhase::DownloadingCFHeaders {
                    ..
                },
                next_phase,
            ) => {
                // Check if we actually downloaded any filter headers
                let filter_tip = storage
                    .get_filter_tip_height()
                    .await
                    .map_err(|e| SyncError::Storage(format!("Failed to get filter tip: {}", e)))?;

                match next_phase {
                    SyncPhase::DownloadingFilters {
                        ..
                    } => {
                        // Can only go to filters if we actually downloaded cfheaders
                        Ok(filter_tip.is_some() && filter_tip != Some(0))
                    }
                    SyncPhase::FullySynced {
                        ..
                    } => {
                        // Can go to synced if no filter headers were downloaded (no peer support)
                        Ok(filter_tip.is_none() || filter_tip == Some(0))
                    }
                    _ => Ok(false),
                }
            }

            // From DownloadingFilters
            (
                SyncPhase::DownloadingFilters {
                    ..
                },
                next_phase,
            ) => {
                // Filters must be complete or no blocks needed
                if !self.are_filters_complete(current_phase) {
                    return Ok(false);
                }

                match next_phase {
                    SyncPhase::DownloadingBlocks {
                        ..
                    } => {
                        // Check if we have blocks to download
                        Ok(self.has_blocks_to_download(current_phase))
                    }
                    SyncPhase::FullySynced {
                        ..
                    } => {
                        // Can go to synced if no blocks to download
                        Ok(!self.has_blocks_to_download(current_phase))
                    }
                    _ => Ok(false),
                }
            }

            // From DownloadingBlocks
            (
                SyncPhase::DownloadingBlocks {
                    ..
                },
                SyncPhase::FullySynced {
                    ..
                },
            ) => {
                // All blocks must be downloaded
                Ok(self.are_blocks_complete(current_phase))
            }

            // All other transitions are invalid
            _ => Ok(false),
        }
    }

    /// Get the next phase based on current phase and configuration
    pub async fn get_next_phase(
        &self,
        current_phase: &SyncPhase,
        storage: &dyn StorageManager,
    ) -> SyncResult<Option<SyncPhase>> {
        match current_phase {
            SyncPhase::Idle => {
                // Always start with headers
                let storage_height = storage
                    .get_tip_height()
                    .await
                    .map_err(|e| SyncError::Storage(format!("Failed to get tip height: {}", e)))?
                    .unwrap_or(0);

                // For checkpoint sync, we need to get the actual blockchain height
                // This accounts for the sync base height from checkpoints
                let blockchain_height =
                    if let Ok(Some(metadata)) = storage.load_metadata("sync_base_height").await {
                        if metadata.len() >= 4 {
                            let sync_base = u32::from_le_bytes([
                                metadata[0],
                                metadata[1],
                                metadata[2],
                                metadata[3],
                            ]);
                            sync_base + storage_height
                        } else {
                            storage_height
                        }
                    } else {
                        storage_height
                    };

                // For progress calculation, start_height should be 0 to show overall progress
                // current_height is the actual blockchain height we're at
                Ok(Some(SyncPhase::DownloadingHeaders {
                    start_time: Instant::now(),
                    start_height: 0, // Start from 0 for accurate progress calculation
                    current_height: blockchain_height,
                    target_height: None,
                    last_progress: Instant::now(),
                    headers_downloaded: 0,
                    headers_per_second: 0.0,
                    received_empty_response: false,
                }))
            }

            SyncPhase::DownloadingHeaders {
                ..
            } => {
                tracing::info!(
                    "🔍 [DEBUG] Determining next phase after headers. Config: enable_masternodes={}, enable_filters={}",
                    self.config.enable_masternodes,
                    self.config.enable_filters
                );

                if self.config.enable_masternodes {
                    let header_tip = storage
                        .get_tip_height()
                        .await
                        .map_err(|e| {
                            SyncError::Storage(format!("Failed to get header tip: {}", e))
                        })?
                        .unwrap_or(0);

                    let mn_state = storage.load_masternode_state().await;
                    let mn_height = match &mn_state {
                        Ok(Some(state)) => state.last_height,
                        _ => 0,
                    };

                    tracing::info!(
                        "🔍 [DEBUG] Creating MnList phase: header_tip={}, mn_height={}, mn_state={:?}",
                        header_tip,
                        mn_height,
                        mn_state.is_ok()
                    );

                    Ok(Some(SyncPhase::DownloadingMnList {
                        start_time: Instant::now(),
                        start_height: mn_height,
                        current_height: mn_height,
                        target_height: header_tip,
                        last_progress: Instant::now(),
                        diffs_processed: 0,
                    }))
                } else if self.config.enable_filters {
                    self.create_cfheaders_phase(storage).await
                } else {
                    self.create_fully_synced_phase(storage).await
                }
            }

            SyncPhase::DownloadingMnList {
                ..
            } => {
                if self.config.enable_filters {
                    self.create_cfheaders_phase(storage).await
                } else {
                    self.create_fully_synced_phase(storage).await
                }
            }

            SyncPhase::DownloadingCFHeaders {
                ..
            } => {
                // Check if we actually downloaded any filter headers
                let filter_tip = storage
                    .get_filter_tip_height()
                    .await
                    .map_err(|e| SyncError::Storage(format!("Failed to get filter tip: {}", e)))?;

                if filter_tip.is_none() || filter_tip == Some(0) {
                    // No filter headers were downloaded (no peer support)
                    // Skip directly to fully synced
                    tracing::info!("No filter headers downloaded, skipping to fully synced");
                    self.create_fully_synced_phase(storage).await
                } else {
                    // After CFHeaders, we need to determine what filters to download
                    // For now, we'll create a filters phase that will be populated later
                    Ok(Some(SyncPhase::DownloadingFilters {
                        start_time: Instant::now(),
                        requested_ranges: std::collections::HashMap::new(),
                        completed_heights: std::collections::HashSet::new(),
                        total_filters: 0, // Will be determined based on watch items
                        last_progress: Instant::now(),
                        batches_processed: 0,
                    }))
                }
            }

            SyncPhase::DownloadingFilters {
                ..
            } => {
                // Check if we have blocks to download
                if self.has_blocks_to_download(current_phase) {
                    if let SyncPhase::DownloadingFilters {
                        ..
                    } = current_phase
                    {
                        Ok(Some(SyncPhase::DownloadingBlocks {
                            start_time: Instant::now(),
                            pending_blocks: Vec::new(), // Will be populated from filter matches
                            downloading: std::collections::HashMap::new(),
                            completed: Vec::new(),
                            last_progress: Instant::now(),
                            total_blocks: 0, // Will be set when we populate pending_blocks
                        }))
                    } else {
                        Ok(None)
                    }
                } else {
                    self.create_fully_synced_phase(storage).await
                }
            }

            SyncPhase::DownloadingBlocks {
                ..
            } => self.create_fully_synced_phase(storage).await,

            SyncPhase::FullySynced {
                ..
            } => Ok(None), // Already synced
        }
    }

    /// Create a phase transition record
    pub fn create_transition(
        &self,
        from_phase: &SyncPhase,
        to_phase: &SyncPhase,
        reason: String,
    ) -> PhaseTransition {
        PhaseTransition {
            from_phase: from_phase.name().to_string(),
            to_phase: to_phase.name().to_string(),
            timestamp: Instant::now(),
            reason,
            final_progress: if from_phase.is_syncing() {
                Some(from_phase.progress())
            } else {
                None
            },
        }
    }

    // Helper methods for checking phase completion

    async fn are_headers_complete(
        &self,
        phase: &SyncPhase,
        _storage: &dyn StorageManager,
    ) -> SyncResult<bool> {
        if let SyncPhase::DownloadingHeaders {
            received_empty_response,
            current_height,
            target_height,
            ..
        } = phase
        {
            tracing::info!(
                "🔍 [DEBUG] Checking headers complete: received_empty_response={}, current_height={}, target_height={:?}",
                received_empty_response,
                current_height,
                target_height
            );

            // Headers are complete when we receive an empty response
            Ok(*received_empty_response)
        } else {
            Ok(false)
        }
    }

    async fn are_masternodes_complete(
        &self,
        phase: &SyncPhase,
        storage: &dyn StorageManager,
    ) -> SyncResult<bool> {
        if let SyncPhase::DownloadingMnList {
            current_height,
            target_height,
            ..
        } = phase
        {
            // Check if we've reached the target
            if current_height >= target_height {
                return Ok(true);
            }

            // Also check storage to be sure
            if let Ok(Some(state)) = storage.load_masternode_state().await {
                Ok(state.last_height >= *target_height)
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    async fn are_cfheaders_complete(
        &self,
        phase: &SyncPhase,
        _storage: &dyn StorageManager,
    ) -> SyncResult<bool> {
        if let SyncPhase::DownloadingCFHeaders {
            current_height,
            target_height,
            ..
        } = phase
        {
            Ok(current_height >= target_height)
        } else {
            Ok(false)
        }
    }

    fn are_filters_complete(&self, phase: &SyncPhase) -> bool {
        if let SyncPhase::DownloadingFilters {
            completed_heights,
            total_filters,
            ..
        } = phase
        {
            completed_heights.len() as u32 >= *total_filters
        } else {
            false
        }
    }

    fn are_blocks_complete(&self, phase: &SyncPhase) -> bool {
        if let SyncPhase::DownloadingBlocks {
            pending_blocks,
            downloading,
            ..
        } = phase
        {
            pending_blocks.is_empty() && downloading.is_empty()
        } else {
            false
        }
    }

    fn has_blocks_to_download(&self, _phase: &SyncPhase) -> bool {
        // This will be determined by filter matches
        // For now, return false (no blocks to download)
        false
    }

    async fn create_cfheaders_phase(
        &self,
        storage: &dyn StorageManager,
    ) -> SyncResult<Option<SyncPhase>> {
        let header_tip = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get header tip: {}", e)))?
            .unwrap_or(0);

        let filter_tip = storage
            .get_filter_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get filter tip: {}", e)))?
            .unwrap_or(0);

        Ok(Some(SyncPhase::DownloadingCFHeaders {
            start_time: Instant::now(),
            start_height: filter_tip,
            current_height: filter_tip,
            target_height: header_tip,
            last_progress: Instant::now(),
            cfheaders_downloaded: 0,
            cfheaders_per_second: 0.0,
        }))
    }

    async fn create_fully_synced_phase(
        &self,
        _storage: &dyn StorageManager,
    ) -> SyncResult<Option<SyncPhase>> {
        Ok(Some(SyncPhase::FullySynced {
            sync_completed_at: Instant::now(),
            total_sync_time: Duration::from_secs(0), // Will be calculated from phase history
            headers_synced: 0,                       // Will be calculated from phase history
            filters_synced: 0,                       // Will be calculated from phase history
            blocks_downloaded: 0,                    // Will be calculated from phase history
        }))
    }
}

use std::time::Duration;
