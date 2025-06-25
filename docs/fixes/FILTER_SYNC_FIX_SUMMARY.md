# Filter Sync Stalling Fix Summary

## Problem
Filter sync was stalling at 1400/10000 filters (14%) and never recovering. The retry mechanism would trigger but wouldn't actually resume downloading.

## Root Cause
1. **State Not Cleared on Retry**: When filter sync timed out and attempted to retry, the old request tracking state (`requested_filter_ranges`, `active_filter_requests`) was not cleared.
2. **Incorrect Flag Management**: The `syncing_filters` flag was prematurely set to false, preventing restart attempts.
3. **No Proper Recovery**: The sequential sync manager didn't properly handle the stalled state by clearing and restarting the filter sync.

## Solution Implemented

### 1. Added State Clearing Method (`clear_filter_sync_state`)
```rust
fn clear_filter_sync_state(&mut self) {
    // Clear request tracking
    self.requested_filter_ranges.clear();
    self.active_filter_requests.clear();
    self.pending_filter_requests.clear();
    
    // Clear retry counts for fresh start
    self.filter_retry_counts.clear();
    
    // Note: We don't clear received_filter_heights as those are actually received
}
```

### 2. Updated `sync_filters_with_flow_control` to Clear State
```rust
pub async fn sync_filters_with_flow_control(...) {
    // ...
    
    // Clear any stale state from previous attempts
    self.clear_filter_sync_state();
    
    // Build the queue of filter requests
    self.build_filter_request_queue(storage, start_height, count).await?;
    
    // Don't set syncing_filters to false here - it should remain true during download
}
```

### 3. Enhanced Sequential Sync Recovery
```rust
// In SequentialSyncManager::check_timeout
SyncPhase::DownloadingFilters { .. } => {
    // First check for timed out filter requests
    self.filter_sync.check_filter_request_timeouts(network, storage).await?;
    
    if /* timeout detected */ {
        // Check if we received some filters but not all
        let received_count = self.filter_sync.get_received_filter_count();
        if received_count > 0 && received_count < *total_filters {
            // Clear the filter sync state and restart
            self.filter_sync.reset();
            self.filter_sync.syncing_filters = false; // Allow restart
            
            // Re-execute the phase
            self.execute_current_phase(network, storage).await?;
        }
    }
}
```

## Key Changes

1. **State Management**:
   - Properly clear all tracking state before retry
   - Preserve actually received filters
   - Allow sync to restart cleanly

2. **Timeout Handling**:
   - Check for timed out requests periodically
   - Detect partial progress (e.g., 1400/10000)
   - Trigger proper recovery with state reset

3. **Flag Management**:
   - Keep `syncing_filters` true during download
   - Only clear when explicitly resetting
   - Made `syncing_filters` public for sequential sync manager

## Testing

Created test script `test_filter_sync_fix.sh` to verify:
- Filter sync completes without stalling
- Retry mechanism properly resumes downloading
- No permanent stalls after retry attempts

## Result

Filter sync now properly recovers from stalls:
1. Detects when sync is stuck (no active/pending requests)
2. Clears all tracking state 
3. Restarts filter download from where it left off
4. Continues until all filters are received

The fix ensures reliable filter synchronization even when network issues cause temporary stalls.