use dash_spv::client::config::MempoolStrategy;
use dash_spv::types::{DetailedSyncProgress, MempoolRemovalReason, SyncStage};
use dash_spv::SyncProgress;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

/// Opaque handle to the wallet manager owned by the SPV client.
///
/// This is intentionally zero-sized so it can be used purely as an FFI handle
/// while still allowing Rust to cast to the underlying key-wallet manager
/// implementation when necessary.
#[repr(C)]
pub struct FFIWalletManager {
    _private: [u8; 0],
}

#[repr(C)]
pub struct FFIString {
    pub ptr: *mut c_char,
    pub length: usize,
}

impl FFIString {
    pub fn new(s: &str) -> Self {
        let c_string = CString::new(s).unwrap_or_else(|_| CString::new("").unwrap());
        // Compute length from the finalized CString to avoid mismatches when input contains NULs
        let length = c_string.as_bytes().len();
        FFIString {
            ptr: c_string.into_raw(),
            length,
        }
    }

    /// # Safety
    /// - `ptr` must be either null or point to a valid, NUL-terminated C string.
    /// - The pointer must remain valid for the duration of this call.
    pub unsafe fn from_ptr(ptr: *const c_char) -> Result<String, String> {
        if ptr.is_null() {
            return Err("Null pointer".to_string());
        }
        CStr::from_ptr(ptr).to_str().map(|s| s.to_string()).map_err(|e| e.to_string())
    }
}

#[repr(C)]
pub struct FFISyncProgress {
    pub header_height: u32,
    pub filter_header_height: u32,
    pub masternode_height: u32,
    pub peer_count: u32,
    pub filter_sync_available: bool,
    pub filters_downloaded: u32,
    pub last_synced_filter_height: u32,
}

impl From<SyncProgress> for FFISyncProgress {
    fn from(progress: SyncProgress) -> Self {
        FFISyncProgress {
            header_height: progress.header_height,
            filter_header_height: progress.filter_header_height,
            masternode_height: progress.masternode_height,
            peer_count: progress.peer_count,
            filter_sync_available: progress.filter_sync_available,
            filters_downloaded: progress.filters_downloaded as u32,
            last_synced_filter_height: progress.last_synced_filter_height.unwrap_or(0),
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum FFISyncStage {
    Connecting = 0,
    QueryingHeight = 1,
    Downloading = 2,
    Validating = 3,
    Storing = 4,
    DownloadingFilterHeaders = 5,
    DownloadingFilters = 6,
    DownloadingBlocks = 7,
    Complete = 8,
    Failed = 9,
}

impl From<SyncStage> for FFISyncStage {
    fn from(stage: SyncStage) -> Self {
        match stage {
            SyncStage::Connecting => FFISyncStage::Connecting,
            SyncStage::QueryingPeerHeight => FFISyncStage::QueryingHeight,
            SyncStage::DownloadingHeaders {
                ..
            } => FFISyncStage::Downloading,
            SyncStage::ValidatingHeaders {
                ..
            } => FFISyncStage::Validating,
            SyncStage::StoringHeaders {
                ..
            } => FFISyncStage::Storing,
            SyncStage::DownloadingFilterHeaders {
                ..
            } => FFISyncStage::DownloadingFilterHeaders,
            SyncStage::DownloadingFilters {
                ..
            } => FFISyncStage::DownloadingFilters,
            SyncStage::DownloadingBlocks {
                ..
            } => FFISyncStage::DownloadingBlocks,
            SyncStage::Complete => FFISyncStage::Complete,
            SyncStage::Failed(_) => FFISyncStage::Failed,
        }
    }
}

#[repr(C)]
pub struct FFIDetailedSyncProgress {
    pub total_height: u32,
    pub percentage: f64,
    pub headers_per_second: f64,
    pub estimated_seconds_remaining: i64, // -1 if unknown
    pub stage: FFISyncStage,
    pub stage_message: FFIString,
    pub overview: FFISyncProgress,
    pub total_headers: u64,
    pub sync_start_timestamp: i64,
}

impl From<DetailedSyncProgress> for FFIDetailedSyncProgress {
    fn from(progress: DetailedSyncProgress) -> Self {
        use std::time::UNIX_EPOCH;

        let stage_message = match &progress.sync_stage {
            SyncStage::Connecting => "Connecting to peers".to_string(),
            SyncStage::QueryingPeerHeight => "Querying blockchain height".to_string(),
            SyncStage::DownloadingHeaders {
                start,
                end,
            } => format!("Downloading headers {} to {}", start, end),
            SyncStage::ValidatingHeaders {
                batch_size,
            } => format!("Validating {} headers", batch_size),
            SyncStage::StoringHeaders {
                batch_size,
            } => format!("Storing {} headers", batch_size),
            SyncStage::DownloadingFilterHeaders {
                current,
                target,
            } => format!("Downloading filter headers {} / {}", current, target),
            SyncStage::DownloadingFilters {
                completed,
                total,
            } => format!("Downloading filters {} / {}", completed, total),
            SyncStage::DownloadingBlocks {
                pending,
            } => format!("Downloading blocks ({} pending)", pending),
            SyncStage::Complete => "Synchronization complete".to_string(),
            SyncStage::Failed(err) => err.clone(),
        };

        let overview = FFISyncProgress::from(progress.sync_progress.clone());

        FFIDetailedSyncProgress {
            total_height: progress.peer_best_height,
            percentage: progress.percentage,
            headers_per_second: progress.headers_per_second,
            estimated_seconds_remaining: progress
                .estimated_time_remaining
                .map(|d| d.as_secs() as i64)
                .unwrap_or(-1),
            stage: progress.sync_stage.into(),
            stage_message: FFIString::new(&stage_message),
            overview,
            total_headers: progress.total_headers_processed,
            sync_start_timestamp: progress
                .sync_start_time
                .duration_since(UNIX_EPOCH)
                .unwrap_or(std::time::Duration::from_secs(0))
                .as_secs() as i64,
        }
    }
}

/// # Safety
/// - `s.ptr` must be a pointer previously returned by `FFIString::new` or compatible.
/// - It must not be used after this call.
pub unsafe fn dash_spv_ffi_string_destroy(s: FFIString) {
    if !s.ptr.is_null() {
        let _ = CString::from_raw(s.ptr);
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FFIMempoolStrategy {
    FetchAll = 0,
    BloomFilter = 1,
}

impl From<MempoolStrategy> for FFIMempoolStrategy {
    fn from(strategy: MempoolStrategy) -> Self {
        match strategy {
            MempoolStrategy::FetchAll => FFIMempoolStrategy::FetchAll,
            MempoolStrategy::BloomFilter => FFIMempoolStrategy::BloomFilter,
        }
    }
}

impl From<FFIMempoolStrategy> for MempoolStrategy {
    fn from(strategy: FFIMempoolStrategy) -> Self {
        match strategy {
            FFIMempoolStrategy::FetchAll => MempoolStrategy::FetchAll,
            FFIMempoolStrategy::BloomFilter => MempoolStrategy::BloomFilter,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FFIMempoolRemovalReason {
    Expired = 0,
    Replaced = 1,
    DoubleSpent = 2,
    Confirmed = 3,
    Manual = 4,
}

impl From<MempoolRemovalReason> for FFIMempoolRemovalReason {
    fn from(reason: MempoolRemovalReason) -> Self {
        match reason {
            MempoolRemovalReason::Expired => FFIMempoolRemovalReason::Expired,
            MempoolRemovalReason::Replaced {
                ..
            } => FFIMempoolRemovalReason::Replaced,
            MempoolRemovalReason::DoubleSpent {
                ..
            } => FFIMempoolRemovalReason::DoubleSpent,
            MempoolRemovalReason::Confirmed => FFIMempoolRemovalReason::Confirmed,
            MempoolRemovalReason::Manual => FFIMempoolRemovalReason::Manual,
        }
    }
}
