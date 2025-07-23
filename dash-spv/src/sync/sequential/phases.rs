//! Phase definitions for sequential sync

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use dashcore::BlockHash;

/// Hybrid sync strategy tracking
#[derive(Debug, Clone, PartialEq)]
pub enum HybridSyncStrategy {
    /// Engine-driven discovery with both QRInfo and MnListDiff
    EngineDiscovery {
        qr_info_requests: u32,
        mn_diff_requests: u32,
        qr_info_completed: u32,
        mn_diff_completed: u32,
    },
}

/// Represents the current synchronization phase
#[derive(Debug, Clone, PartialEq)]
pub enum SyncPhase {
    /// Not currently syncing
    Idle,

    /// Phase 1: Downloading block headers
    DownloadingHeaders {
        /// When this phase started
        start_time: Instant,
        /// Height when sync started
        start_height: u32,
        /// Current synchronized height
        current_height: u32,
        /// Target height (if known from peer announcements)
        target_height: Option<u32>,
        /// Last time we made progress
        last_progress: Instant,
        /// Headers downloaded in this phase
        headers_downloaded: u32,
        /// Average headers per second
        headers_per_second: f64,
        /// Whether we've received an empty headers response (indicating completion)
        received_empty_response: bool,
    },

    /// Phase 2: Downloading masternode lists
    DownloadingMnList {
        /// When this phase started
        start_time: Instant,
        /// Starting height for masternode sync
        start_height: u32,
        /// Current masternode list height
        current_height: u32,
        /// Target height (should match header tip)
        target_height: u32,
        /// Last time we made progress
        last_progress: Instant,
        /// Number of masternode list diffs processed
        diffs_processed: u32,
        /// Hybrid sync strategy tracking
        sync_strategy: Option<HybridSyncStrategy>,
        /// Total requests (QRInfo + MnListDiff)
        requests_total: u32,
        /// Completed requests
        requests_completed: u32,
    },

    /// Phase 3: Downloading compact filter headers
    DownloadingCFHeaders {
        /// When this phase started
        start_time: Instant,
        /// Starting height
        start_height: u32,
        /// Current filter header height
        current_height: u32,
        /// Target height (should match header tip)
        target_height: u32,
        /// Last time we made progress
        last_progress: Instant,
        /// Filter headers downloaded in this phase
        cfheaders_downloaded: u32,
        /// Average filter headers per second
        cfheaders_per_second: f64,
    },

    /// Phase 4: Downloading compact filters
    DownloadingFilters {
        /// When this phase started
        start_time: Instant,
        /// Filter ranges that have been requested: (start, end) -> request time
        requested_ranges: HashMap<(u32, u32), Instant>,
        /// Heights for which filters have been downloaded
        completed_heights: HashSet<u32>,
        /// Total number of filters to download
        total_filters: u32,
        /// Last time we made progress
        last_progress: Instant,
        /// Number of filter batches processed
        batches_processed: u32,
    },

    /// Phase 5: Downloading full blocks
    DownloadingBlocks {
        /// When this phase started
        start_time: Instant,
        /// Blocks pending download: (hash, height)
        pending_blocks: Vec<(BlockHash, u32)>,
        /// Currently downloading blocks: hash -> request time
        downloading: HashMap<BlockHash, Instant>,
        /// Successfully downloaded blocks
        completed: Vec<BlockHash>,
        /// Last time we made progress
        last_progress: Instant,
        /// Total blocks to download
        total_blocks: usize,
    },

    /// Fully synchronized with the network
    FullySynced {
        /// When sync completed
        sync_completed_at: Instant,
        /// Total time taken to sync
        total_sync_time: Duration,
        /// Number of headers synced
        headers_synced: u32,
        /// Number of filters synced
        filters_synced: u32,
        /// Number of blocks downloaded
        blocks_downloaded: u32,
    },
}

impl SyncPhase {
    /// Get a human-readable name for the phase
    pub fn name(&self) -> &'static str {
        match self {
            SyncPhase::Idle => "Idle",
            SyncPhase::DownloadingHeaders {
                ..
            } => "Downloading Headers",
            SyncPhase::DownloadingMnList {
                sync_strategy,
                ..
            } => {
                match sync_strategy {
                    Some(HybridSyncStrategy::EngineDiscovery { .. }) => "Downloading Masternode Lists (Hybrid)",
                    None => "Downloading Masternode Lists",
                }
            }
            SyncPhase::DownloadingCFHeaders {
                ..
            } => "Downloading Filter Headers",
            SyncPhase::DownloadingFilters {
                ..
            } => "Downloading Filters",
            SyncPhase::DownloadingBlocks {
                ..
            } => "Downloading Blocks",
            SyncPhase::FullySynced {
                ..
            } => "Fully Synced",
        }
    }

    /// Check if this phase is actively syncing
    pub fn is_syncing(&self) -> bool {
        !matches!(self, SyncPhase::Idle | SyncPhase::FullySynced { .. })
    }

    /// Get the last progress time for timeout detection
    pub fn last_progress_time(&self) -> Option<Instant> {
        match self {
            SyncPhase::DownloadingHeaders {
                last_progress,
                ..
            } => Some(*last_progress),
            SyncPhase::DownloadingMnList {
                last_progress,
                ..
            } => Some(*last_progress),
            SyncPhase::DownloadingCFHeaders {
                last_progress,
                ..
            } => Some(*last_progress),
            SyncPhase::DownloadingFilters {
                last_progress,
                ..
            } => Some(*last_progress),
            SyncPhase::DownloadingBlocks {
                last_progress,
                ..
            } => Some(*last_progress),
            _ => None,
        }
    }

    /// Update the last progress time
    pub fn update_progress(&mut self) {
        let now = Instant::now();
        match self {
            SyncPhase::DownloadingHeaders {
                last_progress,
                ..
            } => *last_progress = now,
            SyncPhase::DownloadingMnList {
                last_progress,
                ..
            } => *last_progress = now,
            SyncPhase::DownloadingCFHeaders {
                last_progress,
                ..
            } => *last_progress = now,
            SyncPhase::DownloadingFilters {
                last_progress,
                ..
            } => *last_progress = now,
            SyncPhase::DownloadingBlocks {
                last_progress,
                ..
            } => *last_progress = now,
            _ => {}
        }
    }

    /// Get phase elapsed time
    pub fn elapsed_time(&self) -> Option<Duration> {
        match self {
            SyncPhase::DownloadingHeaders {
                start_time,
                ..
            } => Some(start_time.elapsed()),
            SyncPhase::DownloadingMnList {
                start_time,
                ..
            } => Some(start_time.elapsed()),
            SyncPhase::DownloadingCFHeaders {
                start_time,
                ..
            } => Some(start_time.elapsed()),
            SyncPhase::DownloadingFilters {
                start_time,
                ..
            } => Some(start_time.elapsed()),
            SyncPhase::DownloadingBlocks {
                start_time,
                ..
            } => Some(start_time.elapsed()),
            SyncPhase::FullySynced {
                total_sync_time,
                ..
            } => Some(*total_sync_time),
            SyncPhase::Idle => None,
        }
    }
}

/// Progress information for a sync phase
#[derive(Debug, Clone)]
pub struct PhaseProgress {
    /// Name of the phase
    pub phase_name: &'static str,
    /// Number of items completed
    pub items_completed: u32,
    /// Total items expected (if known)
    pub items_total: Option<u32>,
    /// Completion percentage (0-100)
    pub percentage: f64,
    /// Processing rate (items per second)
    pub rate: f64,
    /// Estimated time remaining
    pub eta: Option<Duration>,
    /// Time elapsed in this phase
    pub elapsed: Duration,
}

impl SyncPhase {
    /// Calculate progress for the current phase
    pub fn progress(&self) -> PhaseProgress {
        match self {
            SyncPhase::DownloadingHeaders {
                start_height,
                current_height,
                target_height,
                headers_per_second,
                start_time,
                ..
            } => {
                let items_completed = current_height.saturating_sub(*start_height);
                let items_total = target_height.map(|t| t.saturating_sub(*start_height));
                let percentage = if let Some(total) = items_total {
                    if total > 0 {
                        (items_completed as f64 / total as f64) * 100.0
                    } else {
                        100.0
                    }
                } else {
                    0.0
                };

                let eta = if *headers_per_second > 0.0 {
                    items_total.map(|total| {
                        let remaining = total.saturating_sub(items_completed);
                        Duration::from_secs_f64(remaining as f64 / headers_per_second)
                    })
                } else {
                    None
                };

                PhaseProgress {
                    phase_name: self.name(),
                    items_completed,
                    items_total,
                    percentage,
                    rate: *headers_per_second,
                    eta,
                    elapsed: start_time.elapsed(),
                }
            }

            SyncPhase::DownloadingMnList {
                sync_strategy,
                requests_completed,
                requests_total,
                start_time,
                current_height,
                start_height,
                target_height,
                ..
            } => {
                let (method_description, efficiency_note) = match sync_strategy {
                    Some(HybridSyncStrategy::EngineDiscovery { 
                        qr_info_requests, 
                        mn_diff_requests, 
                        qr_info_completed,
                        mn_diff_completed,
                    }) => {
                        let total_requests = qr_info_requests + mn_diff_requests;
                        let qr_info_ratio = if total_requests > 0 {
                            (*qr_info_requests as f64 / total_requests as f64) * 100.0
                        } else { 
                            0.0 
                        };
                        
                        let efficiency = if qr_info_ratio > 70.0 { 
                            "High Efficiency" 
                        } else if qr_info_ratio > 30.0 {
                            "Standard Efficiency"
                        } else {
                            "Targeted Sync"
                        };
                        
                        (
                            format!(
                                "Hybrid ({:.0}% QRInfo, {:.0}% MnListDiff) - {} of {} QRInfo, {} of {} MnListDiff",
                                qr_info_ratio, 
                                100.0 - qr_info_ratio,
                                qr_info_completed,
                                qr_info_requests,
                                mn_diff_completed,
                                mn_diff_requests
                            ),
                            efficiency.to_string()
                        )
                    }
                    None => ("Standard".to_string(), "Legacy Mode".to_string()),
                };
                
                let percentage = if *requests_total > 0 {
                    (*requests_completed as f64 / *requests_total as f64) * 100.0
                } else if *target_height > *start_height {
                    let height_progress = current_height.saturating_sub(*start_height) as f64;
                    let height_total = target_height.saturating_sub(*start_height) as f64;
                    (height_progress / height_total) * 100.0
                } else {
                    0.0
                };
                
                let elapsed = start_time.elapsed();
                let rate = if elapsed.as_secs() > 0 && *requests_completed > 0 {
                    *requests_completed as f64 / elapsed.as_secs() as f64
                } else {
                    0.0
                };
                
                let eta = if rate > 0.0 && *requests_completed < *requests_total {
                    let remaining = requests_total.saturating_sub(*requests_completed);
                    Some(Duration::from_secs((remaining as f64 / rate) as u64))
                } else {
                    None
                };
                
                PhaseProgress {
                    phase_name: self.name(),
                    items_completed: *requests_completed,
                    items_total: Some(*requests_total),
                    percentage,
                    rate,
                    eta,
                    elapsed,
                }
            }

            SyncPhase::DownloadingCFHeaders {
                start_height,
                current_height,
                target_height,
                cfheaders_per_second,
                start_time,
                ..
            } => {
                let items_completed = current_height.saturating_sub(*start_height);
                let items_total = target_height.saturating_sub(*start_height);
                let percentage = if items_total > 0 {
                    (items_completed as f64 / items_total as f64) * 100.0
                } else {
                    100.0
                };

                let eta = if *cfheaders_per_second > 0.0 {
                    let remaining = items_total.saturating_sub(items_completed);
                    Some(Duration::from_secs_f64(remaining as f64 / cfheaders_per_second))
                } else {
                    None
                };

                PhaseProgress {
                    phase_name: self.name(),
                    items_completed,
                    items_total: Some(items_total),
                    percentage,
                    rate: *cfheaders_per_second,
                    eta,
                    elapsed: start_time.elapsed(),
                }
            }

            SyncPhase::DownloadingFilters {
                completed_heights,
                total_filters,
                start_time,
                ..
            } => {
                let items_completed = completed_heights.len() as u32;
                let percentage = if *total_filters > 0 {
                    (items_completed as f64 / *total_filters as f64) * 100.0
                } else {
                    0.0
                };

                let elapsed = start_time.elapsed();
                let rate = if elapsed.as_secs() > 0 {
                    items_completed as f64 / elapsed.as_secs_f64()
                } else {
                    0.0
                };

                let eta = if rate > 0.0 {
                    let remaining = total_filters.saturating_sub(items_completed);
                    Some(Duration::from_secs_f64(remaining as f64 / rate))
                } else {
                    None
                };

                PhaseProgress {
                    phase_name: self.name(),
                    items_completed,
                    items_total: Some(*total_filters),
                    percentage,
                    rate,
                    eta,
                    elapsed,
                }
            }

            SyncPhase::DownloadingBlocks {
                completed,
                total_blocks,
                start_time,
                ..
            } => {
                let items_completed = completed.len() as u32;
                let items_total = *total_blocks as u32;
                let percentage = if items_total > 0 {
                    (items_completed as f64 / items_total as f64) * 100.0
                } else {
                    100.0
                };

                let elapsed = start_time.elapsed();
                let rate = if elapsed.as_secs() > 0 {
                    items_completed as f64 / elapsed.as_secs_f64()
                } else {
                    0.0
                };

                let eta = if rate > 0.0 {
                    let remaining = items_total.saturating_sub(items_completed);
                    Some(Duration::from_secs_f64(remaining as f64 / rate))
                } else {
                    None
                };

                PhaseProgress {
                    phase_name: self.name(),
                    items_completed,
                    items_total: Some(items_total),
                    percentage,
                    rate,
                    eta,
                    elapsed,
                }
            }

            _ => PhaseProgress {
                phase_name: self.name(),
                items_completed: 0,
                items_total: None,
                percentage: 0.0,
                rate: 0.0,
                eta: None,
                elapsed: Duration::from_secs(0),
            },
        }
    }
    
    /// Update hybrid sync strategy for masternode phase
    pub fn set_masternode_sync_plan(&mut self, qr_info_count: u32, mn_diff_count: u32) {
        if let SyncPhase::DownloadingMnList {
            sync_strategy,
            requests_total,
            ..
        } = self {
            *sync_strategy = Some(HybridSyncStrategy::EngineDiscovery {
                qr_info_requests: qr_info_count,
                mn_diff_requests: mn_diff_count,
                qr_info_completed: 0,
                mn_diff_completed: 0,
            });
            *requests_total = qr_info_count + mn_diff_count;
        }
    }
    
    /// Mark a QRInfo request as completed
    pub fn complete_qr_info_request(&mut self) {
        if let SyncPhase::DownloadingMnList {
            sync_strategy: Some(HybridSyncStrategy::EngineDiscovery { 
                qr_info_completed, 
                .. 
            }),
            requests_completed,
            last_progress,
            ..
        } = self {
            *qr_info_completed += 1;
            *requests_completed += 1;
            *last_progress = Instant::now();
        }
    }
    
    /// Mark a MnListDiff request as completed
    pub fn complete_mn_diff_request(&mut self) {
        if let SyncPhase::DownloadingMnList {
            sync_strategy: Some(HybridSyncStrategy::EngineDiscovery { 
                mn_diff_completed, 
                .. 
            }),
            requests_completed,
            diffs_processed,
            last_progress,
            ..
        } = self {
            *mn_diff_completed += 1;
            *requests_completed += 1;
            *diffs_processed += 1; // Backward compatibility
            *last_progress = Instant::now();
        }
    }
    
    /// Update masternode sync height
    pub fn update_masternode_height(&mut self, height: u32) {
        if let SyncPhase::DownloadingMnList {
            current_height,
            last_progress,
            ..
        } = self {
            *current_height = height;
            *last_progress = Instant::now();
        }
    }
}

/// Represents a phase transition in the sync process
#[derive(Debug, Clone)]
pub struct PhaseTransition {
    /// The phase we're transitioning from
    pub from_phase: String,
    /// The phase we're transitioning to
    pub to_phase: String,
    /// When the transition occurred
    pub timestamp: Instant,
    /// Reason for the transition
    pub reason: String,
    /// Progress info at transition time
    pub final_progress: Option<PhaseProgress>,
}
