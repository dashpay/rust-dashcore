//! Statistics and progress tracking for filter synchronization.

use super::types::*;
use crate::network::NetworkManager;
use crate::storage::StorageManager;

impl<S: StorageManager, N: NetworkManager> super::manager::FilterSyncManager<S, N> {
    /// Get state (pending count, active count).
    pub fn get_filter_sync_state(&self) -> (usize, usize) {
        (self.pending_filter_requests.len(), self.active_filter_requests.len())
    }

    /// Get number of available request slots.
    pub fn get_available_request_slots(&self) -> usize {
        MAX_CONCURRENT_FILTER_REQUESTS.saturating_sub(self.active_filter_requests.len())
    }

    /// Get the total number of filters received.
    pub fn get_received_filter_count(&self) -> u32 {
        match self.received_filter_heights.try_lock() {
            Ok(heights) => heights.len() as u32,
            Err(_) => 0,
        }
    }
}
