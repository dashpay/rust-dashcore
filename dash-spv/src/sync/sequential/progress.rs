//! Progress tracking for sequential sync

use std::time::Duration;

use super::phases::{PhaseProgress, PhaseTransition, SyncPhase};

/// Overall sync progress across all phases
#[derive(Debug, Clone)]
pub struct OverallSyncProgress {
    /// Current phase name
    pub current_phase: String,
    
    /// Progress within current phase
    pub phase_progress: PhaseProgress,
    
    /// List of completed phases
    pub phases_completed: Vec<String>,
    
    /// List of remaining phases
    pub phases_remaining: Vec<String>,
    
    /// Total elapsed time since sync started
    pub total_elapsed: Duration,
    
    /// Estimated total time for complete sync
    pub estimated_total_time: Option<Duration>,
    
    /// Overall completion percentage (0-100)
    pub overall_percentage: f64,
    
    /// Human-readable status message
    pub status_message: String,
}

/// Tracks and calculates sync progress
pub struct ProgressTracker {
    /// Start time of sync
    sync_start: Option<std::time::Instant>,
    
    /// Phase weights for overall percentage calculation
    phase_weights: std::collections::HashMap<String, f64>,
}

impl ProgressTracker {
    /// Create a new progress tracker
    pub fn new() -> Self {
        let mut phase_weights = std::collections::HashMap::new();
        
        // Assign weights based on typical time/importance
        phase_weights.insert("Downloading Headers".to_string(), 0.4);
        phase_weights.insert("Downloading Masternode Lists".to_string(), 0.1);
        phase_weights.insert("Downloading Filter Headers".to_string(), 0.2);
        phase_weights.insert("Downloading Filters".to_string(), 0.2);
        phase_weights.insert("Downloading Blocks".to_string(), 0.1);
        
        Self {
            sync_start: None,
            phase_weights,
        }
    }
    
    /// Mark sync as started
    pub fn start_sync(&mut self) {
        self.sync_start = Some(std::time::Instant::now());
    }
    
    /// Calculate overall sync progress
    pub fn calculate_overall_progress(
        &self,
        current_phase: &SyncPhase,
        phase_history: &[PhaseTransition],
        enabled_features: EnabledFeatures,
    ) -> OverallSyncProgress {
        let phase_progress = current_phase.progress();
        let phases_completed = self.get_completed_phases(phase_history);
        let phases_remaining = self.get_remaining_phases(current_phase, &enabled_features);
        
        let total_elapsed = self.sync_start
            .map(|start| start.elapsed())
            .unwrap_or_default();
        
        let overall_percentage = self.calculate_overall_percentage(
            current_phase,
            &phases_completed,
            &phases_remaining,
            &phase_progress,
        );
        
        let estimated_total_time = self.estimate_total_time(
            &phase_progress,
            &phases_completed,
            &phases_remaining,
            total_elapsed,
        );
        
        let status_message = self.generate_status_message(
            current_phase,
            &phase_progress,
            overall_percentage,
        );
        
        OverallSyncProgress {
            current_phase: current_phase.name().to_string(),
            phase_progress,
            phases_completed,
            phases_remaining,
            total_elapsed,
            estimated_total_time,
            overall_percentage,
            status_message,
        }
    }
    
    /// Get list of completed phases from history
    fn get_completed_phases(&self, history: &[PhaseTransition]) -> Vec<String> {
        history.iter()
            .map(|t| t.from_phase.clone())
            .filter(|phase| phase != "Idle")
            .collect()
    }
    
    /// Get list of remaining phases
    fn get_remaining_phases(
        &self,
        current_phase: &SyncPhase,
        features: &EnabledFeatures,
    ) -> Vec<String> {
        let mut remaining = Vec::new();
        
        match current_phase {
            SyncPhase::Idle => {
                remaining.push("Downloading Headers".to_string());
                if features.masternodes {
                    remaining.push("Downloading Masternode Lists".to_string());
                }
                if features.filters {
                    remaining.push("Downloading Filter Headers".to_string());
                    remaining.push("Downloading Filters".to_string());
                }
                // Blocks phase is dynamic based on filter matches
            }
            
            SyncPhase::DownloadingHeaders { .. } => {
                if features.masternodes {
                    remaining.push("Downloading Masternode Lists".to_string());
                }
                if features.filters {
                    remaining.push("Downloading Filter Headers".to_string());
                    remaining.push("Downloading Filters".to_string());
                }
            }
            
            SyncPhase::DownloadingMnList { .. } => {
                if features.filters {
                    remaining.push("Downloading Filter Headers".to_string());
                    remaining.push("Downloading Filters".to_string());
                }
            }
            
            SyncPhase::DownloadingCFHeaders { .. } => {
                remaining.push("Downloading Filters".to_string());
            }
            
            SyncPhase::DownloadingFilters { .. } => {
                // Blocks phase is dynamic
            }
            
            _ => {}
        }
        
        remaining
    }
    
    /// Calculate overall completion percentage
    fn calculate_overall_percentage(
        &self,
        current_phase: &SyncPhase,
        completed: &[String],
        remaining: &[String],
        phase_progress: &PhaseProgress,
    ) -> f64 {
        // Calculate total weight
        let mut total_weight = 0.0;
        let mut completed_weight = 0.0;
        
        // Add completed phases
        for phase in completed {
            if let Some(weight) = self.phase_weights.get(phase) {
                total_weight += weight;
                completed_weight += weight;
            }
        }
        
        // Add current phase
        let current_phase_name = current_phase.name();
        if let Some(weight) = self.phase_weights.get(current_phase_name) {
            total_weight += weight;
            completed_weight += weight * (phase_progress.percentage / 100.0);
        }
        
        // Add remaining phases
        for phase in remaining {
            if let Some(weight) = self.phase_weights.get(phase) {
                total_weight += weight;
            }
        }
        
        if total_weight > 0.0 {
            (completed_weight / total_weight) * 100.0
        } else {
            0.0
        }
    }
    
    /// Estimate total sync time
    fn estimate_total_time(
        &self,
        current_progress: &PhaseProgress,
        completed: &[String],
        remaining: &[String],
        elapsed: Duration,
    ) -> Option<Duration> {
        // Simple estimation based on current progress
        if elapsed.as_secs() == 0 {
            return None;
        }
        
        let completed_count = completed.len() as f64;
        let total_phases = completed_count + 1.0 + remaining.len() as f64;
        
        // Weight current phase progress
        let effective_completed = completed_count + (current_progress.percentage / 100.0);
        
        if effective_completed > 0.0 {
            let estimated_total_secs = (elapsed.as_secs_f64() / effective_completed) * total_phases;
            Some(Duration::from_secs_f64(estimated_total_secs))
        } else {
            None
        }
    }
    
    /// Generate human-readable status message
    fn generate_status_message(
        &self,
        phase: &SyncPhase,
        progress: &PhaseProgress,
        overall_percentage: f64,
    ) -> String {
        match phase {
            SyncPhase::Idle => "Preparing to sync".to_string(),
            
            SyncPhase::DownloadingHeaders { .. } => {
                format!(
                    "Downloading headers: {} at {:.1} headers/sec",
                    progress.items_completed,
                    progress.rate
                )
            }
            
            SyncPhase::DownloadingMnList { .. } => {
                format!(
                    "Syncing masternode lists: {} processed",
                    progress.items_completed
                )
            }
            
            SyncPhase::DownloadingCFHeaders { .. } => {
                format!(
                    "Downloading filter headers: {:.1}% at {:.1} headers/sec",
                    progress.percentage,
                    progress.rate
                )
            }
            
            SyncPhase::DownloadingFilters { .. } => {
                format!(
                    "Downloading filters: {} of {}",
                    progress.items_completed,
                    progress.items_total.unwrap_or(0)
                )
            }
            
            SyncPhase::DownloadingBlocks { .. } => {
                format!(
                    "Downloading blocks: {} of {} ({:.1}%)",
                    progress.items_completed,
                    progress.items_total.unwrap_or(0),
                    progress.percentage
                )
            }
            
            SyncPhase::FullySynced { .. } => {
                format!("Fully synchronized ({:.1}% complete)", overall_percentage)
            }
        }
    }
}

/// Features enabled for sync
#[derive(Debug, Clone)]
pub struct EnabledFeatures {
    pub masternodes: bool,
    pub filters: bool,
}

impl Default for ProgressTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Format duration in human-readable format
pub fn format_duration(duration: Duration) -> String {
    let total_secs = duration.as_secs();
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;
    
    if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    }
}

/// Format ETA in human-readable format
pub fn format_eta(eta: Option<Duration>) -> String {
    match eta {
        Some(duration) => format!("ETA: {}", format_duration(duration)),
        None => "ETA: calculating...".to_string(),
    }
}