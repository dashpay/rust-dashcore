//! Shared sync state for concurrent access
//!
//! This module provides a thread-safe sync state that can be read
//! concurrently while the sync engine updates it.

use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

use crate::types::{SyncPhaseInfo, SyncProgress};

/// Shared synchronization state that can be read concurrently
#[derive(Debug, Clone)]
pub struct SyncState {
    /// Current blockchain height
    pub current_height: u32,

    /// Target blockchain height (from peers)
    pub target_height: u32,

    /// Current sync phase
    pub phase: SyncPhase,

    /// Headers synced to tip
    pub headers_synced: bool,

    /// Filter headers synced
    pub filter_headers_synced: bool,

    /// Number of headers synced in current session
    pub headers_synced_count: u32,

    /// Number of filter headers synced
    pub filter_headers_synced_count: u32,

    /// Last update timestamp
    pub last_update: Instant,

    /// Detailed phase information
    pub phase_info: Option<SyncPhaseInfo>,

    /// Sync start time
    pub sync_start_time: Option<Instant>,

    /// Estimated time remaining
    pub estimated_time_remaining: Option<std::time::Duration>,
}

/// Current synchronization phase
#[derive(Debug, Clone, PartialEq)]
pub enum SyncPhase {
    /// Not syncing
    Idle,

    /// Connecting to peers
    Connecting,

    /// Syncing blockchain headers
    Headers {
        start_height: u32,
        current_height: u32,
        target_height: u32,
    },

    /// Syncing masternode list
    MasternodeList {
        current_height: u32,
        target_height: u32,
    },

    /// Syncing filter headers
    FilterHeaders {
        current_height: u32,
        target_height: u32,
    },

    /// Syncing filters
    Filters {
        current_count: u32,
        total_count: u32,
    },

    /// Fully synced
    Synced,

    /// Error state
    Error(String),
}

impl Default for SyncState {
    fn default() -> Self {
        Self {
            current_height: 0,
            target_height: 0,
            phase: SyncPhase::Idle,
            headers_synced: false,
            filter_headers_synced: false,
            headers_synced_count: 0,
            filter_headers_synced_count: 0,
            last_update: Instant::now(),
            phase_info: None,
            sync_start_time: None,
            estimated_time_remaining: None,
        }
    }
}

impl SyncState {
    /// Convert to SyncProgress for API compatibility
    pub fn to_sync_progress(&self) -> SyncProgress {
        SyncProgress {
            header_height: self.current_height,
            filter_header_height: self.filter_headers_synced_count,
            headers_synced: self.headers_synced,
            filter_headers_synced: self.filter_headers_synced,
            current_phase: self.phase_info.clone(),
            ..Default::default()
        }
    }

    /// Update progress for headers phase
    pub fn update_headers_progress(&mut self, current: u32, target: u32) {
        self.current_height = current;
        self.target_height = target;
        self.phase = SyncPhase::Headers {
            start_height: 0, // Could track this separately
            current_height: current,
            target_height: target,
        };
        self.last_update = Instant::now();

        // Update phase info
        self.phase_info = Some(SyncPhaseInfo {
            phase_name: "Downloading Headers".to_string(),
            progress_percentage: if target > 0 {
                (current as f64 / target as f64 * 100.0)
            } else {
                0.0
            },
            items_completed: current,
            items_total: Some(target),
            rate: self.sync_rate(),
            eta_seconds: self.estimated_time_remaining.map(|d| d.as_secs()),
            elapsed_seconds: self.sync_start_time.map(|t| t.elapsed().as_secs()).unwrap_or(0),
            details: Some(format!("Syncing headers from height {} to {}", current, target)),
            current_position: Some(current),
            target_position: Some(target),
            rate_units: Some("headers/sec".to_string()),
        });
    }

    /// Mark headers as synced
    pub fn mark_headers_synced(&mut self, height: u32) {
        self.headers_synced = true;
        self.current_height = height;
        self.headers_synced_count = height;
        self.last_update = Instant::now();
    }

    /// Calculate sync rate (items per second)
    pub fn sync_rate(&self) -> f64 {
        if let Some(start_time) = self.sync_start_time {
            let elapsed = start_time.elapsed().as_secs_f64();
            if elapsed > 0.0 {
                return self.current_height as f64 / elapsed;
            }
        }
        0.0
    }
}

/// Thread-safe sync state reader
#[derive(Clone)]
pub struct SyncStateReader {
    state: Arc<RwLock<SyncState>>,
}

impl SyncStateReader {
    /// Create a new sync state reader
    pub fn new(state: Arc<RwLock<SyncState>>) -> Self {
        Self {
            state,
        }
    }

    /// Get current sync progress
    pub async fn get_progress(&self) -> SyncProgress {
        let state = self.state.read().await;
        state.to_sync_progress()
    }

    /// Get detailed sync state
    pub async fn get_state(&self) -> SyncState {
        let state = self.state.read().await;
        state.clone()
    }

    /// Check if syncing
    pub async fn is_syncing(&self) -> bool {
        let state = self.state.read().await;
        !matches!(state.phase, SyncPhase::Idle | SyncPhase::Synced)
    }

    /// Get current height
    pub async fn current_height(&self) -> u32 {
        let state = self.state.read().await;
        state.current_height
    }

    /// Get target height (blockchain tip from peers)
    pub async fn target_height(&self) -> u32 {
        let state = self.state.read().await;
        state.target_height
    }
}

/// Thread-safe sync state writer (for the sync engine)
#[derive(Clone)]
pub struct SyncStateWriter {
    state: Arc<RwLock<SyncState>>,
}

impl SyncStateWriter {
    /// Create a new sync state writer
    pub fn new(state: Arc<RwLock<SyncState>>) -> Self {
        Self {
            state,
        }
    }

    /// Update the sync state
    pub async fn update<F>(&self, updater: F)
    where
        F: FnOnce(&mut SyncState),
    {
        let mut state = self.state.write().await;
        updater(&mut state);
    }

    /// Get a reader for this state
    pub fn reader(&self) -> SyncStateReader {
        SyncStateReader::new(self.state.clone())
    }

    /// Get the target height
    pub async fn get_target_height(&self) -> u32 {
        let state = self.state.read().await;
        state.target_height
    }
}
