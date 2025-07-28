# SPV Sync Phase Tracking Guide

This guide explains how to track detailed synchronization phases in dash-spv for UI applications like Dash Evo Tool.

## Overview

The dash-spv library now exposes detailed synchronization phase information through the `SyncProgress` struct. This allows UI applications to show users exactly what stage of synchronization the SPV client is in.

## Sync Phases

The SPV client progresses through these phases sequentially:

1. **Idle** - Not syncing
2. **Downloading Headers** - Syncing blockchain headers
3. **Downloading Masternode Lists** - Syncing masternode information
4. **Downloading Filter Headers** - Syncing compact filter headers
5. **Downloading Filters** - Downloading compact filters
6. **Downloading Blocks** - Downloading full blocks (when filters match)
7. **Fully Synced** - Synchronization complete

## Using Phase Information

### Getting Sync Progress

```rust
// Get current sync progress from the client
let progress = client.sync_progress().await?;

// Check if phase information is available
if let Some(phase_info) = &progress.current_phase {
    println!("Current phase: {}", phase_info.phase_name);
    println!("Progress: {:.1}%", phase_info.progress_percentage);
    println!("Items: {}/{:?}", phase_info.items_completed, phase_info.items_total);
    println!("Rate: {:.1} items/sec", phase_info.rate);
    
    if let Some(eta) = phase_info.eta_seconds {
        println!("ETA: {} seconds", eta);
    }
    
    if let Some(details) = &phase_info.details {
        println!("Details: {}", details);
    }
}
```

### SyncPhaseInfo Structure

```rust
pub struct SyncPhaseInfo {
    /// Name of the current phase
    pub phase_name: String,
    
    /// Progress percentage (0-100)
    pub progress_percentage: f64,
    
    /// Items completed in this phase
    pub items_completed: u32,
    
    /// Total items expected (if known)
    pub items_total: Option<u32>,
    
    /// Processing rate (items per second)
    pub rate: f64,
    
    /// Estimated time remaining (seconds)
    pub eta_seconds: Option<u64>,
    
    /// Time elapsed in this phase (seconds)
    pub elapsed_seconds: u64,
    
    /// Additional phase-specific details
    pub details: Option<String>,
}
```

## Example UI Integration

Here's how you might display this in a UI:

```rust
// Example UI update function
fn update_sync_ui(phase_info: &SyncPhaseInfo) {
    // Update phase label
    ui.set_phase_label(&phase_info.phase_name);
    
    // Update progress bar
    ui.set_progress(phase_info.progress_percentage);
    
    // Update status text
    let status = format!(
        "{}/{} items @ {:.1}/sec",
        phase_info.items_completed,
        phase_info.items_total.unwrap_or(0),
        phase_info.rate
    );
    ui.set_status_text(&status);
    
    // Update ETA
    if let Some(eta) = phase_info.eta_seconds {
        let eta_text = format_duration(eta);
        ui.set_eta_text(&eta_text);
    }
    
    // Update details
    if let Some(details) = &phase_info.details {
        ui.set_details_text(details);
    }
}
```

## Phase-Specific Details

Each phase provides relevant details:

- **Downloading Headers**: Shows current height and target height
- **Downloading Masternode Lists**: Shows masternode list sync progress
- **Downloading Filter Headers**: Shows filter header sync range
- **Downloading Filters**: Shows number of filters downloaded
- **Downloading Blocks**: Shows blocks being downloaded
- **Fully Synced**: Shows total items synced

## Example Output

```
🔄 Phase Change: Downloading Headers
Downloading Headers: [████████████░░░░░░░░] 60.5% (121000/200000) @ 2500.3 items/sec - ETA: 31s - Syncing headers from 121000 to 200000

🔄 Phase Change: Downloading Masternode Lists  
Downloading Masternode Lists: [██████░░░░░░░░░░░░░░] 30.0% (60/200) @ 10.5 items/sec - ETA: 13s - Syncing masternode lists from 60 to 200

🔄 Phase Change: Downloading Filter Headers
Downloading Filter Headers: [████████████████░░░░] 80.0% (160000/200000) @ 1500.0 items/sec - ETA: 26s - Syncing filter headers from 160000 to 200000

🔄 Phase Change: Downloading Filters
Downloading Filters: [██████████░░░░░░░░░░] 50.0% (5000/10000) @ 250.0 items/sec - ETA: 20s - 5000 of 10000 filters downloaded

🔄 Phase Change: Fully Synced
Fully Synced: [████████████████████] 100.0% - Sync complete: 200000 headers, 10000 filters, 0 blocks
```

## Integration with Dash Evo Tool

To integrate this with Dash Evo Tool:

1. Poll `sync_progress()` periodically (e.g., every second)
2. Extract the `current_phase` field
3. Update your UI components based on the phase information
4. Use the `phase_name` to show which sync stage is active
5. Use `progress_percentage` for progress bars
6. Display `rate` and `eta_seconds` for user feedback
7. Show `details` for additional context

## Performance Considerations

- The `sync_progress()` method uses internal caching to avoid excessive storage queries
- Polling once per second is recommended for responsive UI updates
- Phase transitions are tracked internally and don't require additional queries

## Error Handling

Always check if `current_phase` is `Some` before accessing:

```rust
if let Some(phase_info) = progress.current_phase {
    // Safe to use phase_info
} else {
    // Sync hasn't started yet or phase info not available
}
```