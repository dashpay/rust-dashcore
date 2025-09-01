//! Sync state management.

use crate::sync::SyncComponent;
use std::collections::HashSet;
use std::time::SystemTime;

/// Manages the state of synchronization processes.
#[derive(Debug, Clone)]
pub struct SyncState {
    /// Components currently syncing.
    syncing: HashSet<SyncComponent>,

    /// Last sync times for each component.
    last_sync: std::collections::HashMap<SyncComponent, SystemTime>,

    /// Sync start time.
    sync_start: Option<SystemTime>,
}

impl Default for SyncState {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncState {
    /// Create a new sync state.
    pub fn new() -> Self {
        Self {
            syncing: HashSet::new(),
            last_sync: std::collections::HashMap::new(),
            sync_start: None,
        }
    }

    /// Start sync for a component.
    pub fn start_sync(&mut self, component: SyncComponent) {
        self.syncing.insert(component);
        if self.sync_start.is_none() {
            self.sync_start = Some(SystemTime::now());
        }
    }

    /// Finish sync for a component.
    pub fn finish_sync(&mut self, component: SyncComponent) {
        self.syncing.remove(&component);
        self.last_sync.insert(component, SystemTime::now());

        if self.syncing.is_empty() {
            self.sync_start = None;
        }
    }

    /// Check if a component is syncing.
    pub fn is_syncing(&self, component: SyncComponent) -> bool {
        self.syncing.contains(&component)
    }

    /// Check if any component is syncing.
    pub fn is_any_syncing(&self) -> bool {
        !self.syncing.is_empty()
    }

    /// Get all syncing components.
    pub fn syncing_components(&self) -> Vec<SyncComponent> {
        self.syncing.iter().copied().collect()
    }

    /// Get last sync time for a component.
    pub fn last_sync_time(&self, component: SyncComponent) -> Option<SystemTime> {
        self.last_sync.get(&component).copied()
    }

    /// Get sync start time.
    pub fn sync_start_time(&self) -> Option<SystemTime> {
        self.sync_start
    }

    /// Reset all sync state.
    pub fn reset(&mut self) {
        self.syncing.clear();
        self.last_sync.clear();
        self.sync_start = None;
    }
}
