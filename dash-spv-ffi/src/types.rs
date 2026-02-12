use dash_spv::client::config::MempoolStrategy;
use dash_spv::sync::{
    BlockHeadersProgress, BlocksProgress, ChainLockProgress, FilterHeadersProgress,
    FiltersProgress, InstantSendProgress, MasternodesProgress, ProgressPercentage, SyncProgress,
    SyncState,
};
use dash_spv::types::MempoolRemovalReason;
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

/// SyncState exposed by the FFI as FFISyncState.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FFISyncState {
    #[default]
    Initializing = 0,
    WaitingForConnections = 1,
    WaitForEvents = 2,
    Syncing = 3,
    Synced = 4,
    Error = 5,
}

impl From<SyncState> for FFISyncState {
    fn from(state: SyncState) -> Self {
        match state {
            SyncState::Initializing => FFISyncState::Initializing,
            SyncState::WaitingForConnections => FFISyncState::WaitingForConnections,
            SyncState::WaitForEvents => FFISyncState::WaitForEvents,
            SyncState::Syncing => FFISyncState::Syncing,
            SyncState::Synced => FFISyncState::Synced,
            SyncState::Error => FFISyncState::Error,
        }
    }
}

/// Progress for block headers synchronization.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct FFIBlockHeadersProgress {
    pub state: FFISyncState,
    pub tip_height: u32,
    pub target_height: u32,
    pub processed: u32,
    pub buffered: u32,
    pub percentage: f64,
    pub last_activity: u64,
}

impl From<&BlockHeadersProgress> for FFIBlockHeadersProgress {
    fn from(progress: &BlockHeadersProgress) -> Self {
        FFIBlockHeadersProgress {
            state: progress.state().into(),
            tip_height: progress.tip_height(),
            target_height: progress.target_height(),
            processed: progress.processed(),
            buffered: progress.buffered(),
            percentage: progress.percentage(),
            last_activity: progress.last_activity().elapsed().as_secs(),
        }
    }
}

/// Progress for filter headers synchronization.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct FFIFilterHeadersProgress {
    pub state: FFISyncState,
    pub current_height: u32,
    pub target_height: u32,
    pub block_header_tip_height: u32,
    pub processed: u32,
    pub percentage: f64,
    pub last_activity: u64,
}

impl From<&FilterHeadersProgress> for FFIFilterHeadersProgress {
    fn from(progress: &FilterHeadersProgress) -> Self {
        FFIFilterHeadersProgress {
            state: progress.state().into(),
            current_height: progress.current_height(),
            target_height: progress.target_height(),
            block_header_tip_height: progress.block_header_tip_height(),
            processed: progress.processed(),
            percentage: progress.percentage(),
            last_activity: progress.last_activity().elapsed().as_secs(),
        }
    }
}

/// Progress for compact block filters synchronization.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct FFIFiltersProgress {
    pub state: FFISyncState,
    pub current_height: u32,
    pub target_height: u32,
    pub filter_header_tip_height: u32,
    pub downloaded: u32,
    pub processed: u32,
    pub matched: u32,
    pub percentage: f64,
    pub last_activity: u64,
}

impl From<&FiltersProgress> for FFIFiltersProgress {
    fn from(progress: &FiltersProgress) -> Self {
        FFIFiltersProgress {
            state: progress.state().into(),
            current_height: progress.current_height(),
            target_height: progress.target_height(),
            filter_header_tip_height: progress.filter_header_tip_height(),
            downloaded: progress.downloaded(),
            processed: progress.processed(),
            matched: progress.matched(),
            percentage: progress.percentage(),
            last_activity: progress.last_activity().elapsed().as_secs(),
        }
    }
}

/// Progress for full block synchronization.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct FFIBlocksProgress {
    pub state: FFISyncState,
    pub last_processed: u32,
    pub requested: u32,
    pub from_storage: u32,
    pub downloaded: u32,
    pub processed: u32,
    pub relevant: u32,
    pub transactions: u32,
    pub last_activity: u64,
}

impl From<&BlocksProgress> for FFIBlocksProgress {
    fn from(progress: &BlocksProgress) -> Self {
        FFIBlocksProgress {
            state: progress.state().into(),
            last_processed: progress.last_processed(),
            requested: progress.requested(),
            from_storage: progress.from_storage(),
            downloaded: progress.downloaded(),
            processed: progress.processed(),
            relevant: progress.relevant(),
            transactions: progress.transactions(),
            last_activity: progress.last_activity().elapsed().as_secs(),
        }
    }
}

/// Progress for masternode list synchronization.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct FFIMasternodesProgress {
    pub state: FFISyncState,
    pub current_height: u32,
    pub target_height: u32,
    pub block_header_tip_height: u32,
    pub diffs_processed: u32,
    pub last_activity: u64,
}

impl From<&MasternodesProgress> for FFIMasternodesProgress {
    fn from(progress: &MasternodesProgress) -> Self {
        FFIMasternodesProgress {
            state: progress.state().into(),
            current_height: progress.current_height(),
            target_height: progress.target_height(),
            block_header_tip_height: progress.block_header_tip_height(),
            diffs_processed: progress.diffs_processed(),
            last_activity: progress.last_activity().elapsed().as_secs(),
        }
    }
}

/// Progress for ChainLock synchronization.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct FFIChainLockProgress {
    pub state: FFISyncState,
    pub best_validated_height: u32,
    pub valid: u32,
    pub invalid: u32,
    pub last_activity: u64,
}

impl From<&ChainLockProgress> for FFIChainLockProgress {
    fn from(progress: &ChainLockProgress) -> Self {
        FFIChainLockProgress {
            state: progress.state().into(),
            best_validated_height: progress.best_validated_height(),
            valid: progress.valid(),
            invalid: progress.invalid(),
            last_activity: progress.last_activity().elapsed().as_secs(),
        }
    }
}

/// Progress for InstantSend synchronization.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct FFIInstantSendProgress {
    pub state: FFISyncState,
    pub pending: u32,
    pub valid: u32,
    pub invalid: u32,
    pub last_activity: u64,
}

impl From<&InstantSendProgress> for FFIInstantSendProgress {
    fn from(progress: &InstantSendProgress) -> Self {
        FFIInstantSendProgress {
            state: progress.state().into(),
            pending: progress.pending() as u32,
            valid: progress.valid(),
            invalid: progress.invalid(),
            last_activity: progress.last_activity().elapsed().as_secs(),
        }
    }
}

/// Aggregate progress for all sync managers.
/// Provides a complete view of the parallel sync system's state.
#[repr(C)]
pub struct FFISyncProgress {
    pub state: FFISyncState,
    pub percentage: f64,
    pub is_synced: bool,
    /// Per-manager progress (null if manager not started).
    pub headers: *mut FFIBlockHeadersProgress,
    pub filter_headers: *mut FFIFilterHeadersProgress,
    pub filters: *mut FFIFiltersProgress,
    pub blocks: *mut FFIBlocksProgress,
    pub masternodes: *mut FFIMasternodesProgress,
    pub chainlocks: *mut FFIChainLockProgress,
    pub instantsend: *mut FFIInstantSendProgress,
}

impl From<SyncProgress> for FFISyncProgress {
    fn from(progress: SyncProgress) -> Self {
        let headers = progress
            .headers()
            .ok()
            .map(|p| Box::into_raw(Box::new(FFIBlockHeadersProgress::from(p))))
            .unwrap_or(std::ptr::null_mut());

        let filter_headers = progress
            .filter_headers()
            .ok()
            .map(|p| Box::into_raw(Box::new(FFIFilterHeadersProgress::from(p))))
            .unwrap_or(std::ptr::null_mut());

        let filters = progress
            .filters()
            .ok()
            .map(|p| Box::into_raw(Box::new(FFIFiltersProgress::from(p))))
            .unwrap_or(std::ptr::null_mut());

        let blocks = progress
            .blocks()
            .ok()
            .map(|p| Box::into_raw(Box::new(FFIBlocksProgress::from(p))))
            .unwrap_or(std::ptr::null_mut());

        let masternodes = progress
            .masternodes()
            .ok()
            .map(|p| Box::into_raw(Box::new(FFIMasternodesProgress::from(p))))
            .unwrap_or(std::ptr::null_mut());

        let chainlocks = progress
            .chainlocks()
            .ok()
            .map(|p| Box::into_raw(Box::new(FFIChainLockProgress::from(p))))
            .unwrap_or(std::ptr::null_mut());

        let instantsend = progress
            .instantsend()
            .ok()
            .map(|p| Box::into_raw(Box::new(FFIInstantSendProgress::from(p))))
            .unwrap_or(std::ptr::null_mut());

        Self {
            state: progress.state().into(),
            percentage: progress.percentage(),
            is_synced: progress.is_synced(),
            headers,
            filter_headers,
            filters,
            blocks,
            masternodes,
            chainlocks,
            instantsend,
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

// ============================================================================
// Destroy functions for new manager progress types
// ============================================================================

/// Destroy an `FFIBlockHeadersProgress` object.
///
/// # Safety
/// - `progress` must be a pointer returned from this crate, or null.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_block_headers_progress_destroy(
    progress: *mut FFIBlockHeadersProgress,
) {
    if !progress.is_null() {
        let _ = Box::from_raw(progress);
    }
}

/// Destroy an `FFIFilterHeadersProgress` object.
///
/// # Safety
/// - `progress` must be a pointer returned from this crate, or null.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_filter_headers_progress_destroy(
    progress: *mut FFIFilterHeadersProgress,
) {
    if !progress.is_null() {
        let _ = Box::from_raw(progress);
    }
}

/// Destroy an `FFIFiltersProgress` object.
///
/// # Safety
/// - `progress` must be a pointer returned from this crate, or null.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_filters_progress_destroy(progress: *mut FFIFiltersProgress) {
    if !progress.is_null() {
        let _ = Box::from_raw(progress);
    }
}

/// Destroy an `FFIBlocksProgress` object.
///
/// # Safety
/// - `progress` must be a pointer returned from this crate, or null.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_blocks_progress_destroy(progress: *mut FFIBlocksProgress) {
    if !progress.is_null() {
        let _ = Box::from_raw(progress);
    }
}

/// Destroy an `FFIMasternodesProgress` object.
///
/// # Safety
/// - `progress` must be a pointer returned from this crate, or null.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_masternode_progress_destroy(
    progress: *mut FFIMasternodesProgress,
) {
    if !progress.is_null() {
        let _ = Box::from_raw(progress);
    }
}

/// Destroy an `FFIChainLockProgress` object.
///
/// # Safety
/// - `progress` must be a pointer returned from this crate, or null.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_chainlock_progress_destroy(
    progress: *mut FFIChainLockProgress,
) {
    if !progress.is_null() {
        let _ = Box::from_raw(progress);
    }
}

/// Destroy an `FFIInstantSendProgress` object.
///
/// # Safety
/// - `progress` must be a pointer returned from this crate, or null.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_instantsend_progress_destroy(
    progress: *mut FFIInstantSendProgress,
) {
    if !progress.is_null() {
        let _ = Box::from_raw(progress);
    }
}

/// Destroy an `FFISyncProgress` object and all its nested pointers.
///
/// # Safety
/// - `progress` must be a pointer returned from this crate, or null.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_manager_sync_progress_destroy(
    progress: *mut FFISyncProgress,
) {
    if !progress.is_null() {
        let p = Box::from_raw(progress);

        // Free all nested progress pointers
        if !p.headers.is_null() {
            dash_spv_ffi_block_headers_progress_destroy(p.headers);
        }
        if !p.filter_headers.is_null() {
            dash_spv_ffi_filter_headers_progress_destroy(p.filter_headers);
        }
        if !p.filters.is_null() {
            dash_spv_ffi_filters_progress_destroy(p.filters);
        }
        if !p.blocks.is_null() {
            dash_spv_ffi_blocks_progress_destroy(p.blocks);
        }
        if !p.masternodes.is_null() {
            dash_spv_ffi_masternode_progress_destroy(p.masternodes);
        }
        if !p.chainlocks.is_null() {
            dash_spv_ffi_chainlock_progress_destroy(p.chainlocks);
        }
        if !p.instantsend.is_null() {
            dash_spv_ffi_instantsend_progress_destroy(p.instantsend);
        }
    }
}
