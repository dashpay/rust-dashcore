use dash_spv::client::config::MempoolStrategy;
use dash_spv::sync::{
    BlockHeadersProgress, BlocksProgress, ChainLockProgress, FilterHeadersProgress,
    FiltersProgress, InstantSendProgress, MasternodesProgress, SyncProgress, SyncState,
};
use dash_spv::types::{DetailedSyncProgress, MempoolRemovalReason, SyncStage};
use dash_spv::{ChainState, SyncProgress as LegacySyncProgress};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};

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
pub struct FFILegacySyncProgress {
    pub header_height: u32,
    pub filter_header_height: u32,
    pub masternode_height: u32,
    pub peer_count: u32,
    pub filter_sync_available: bool,
    pub filters_downloaded: u32,
    pub last_synced_filter_height: u32,
}

impl From<LegacySyncProgress> for FFILegacySyncProgress {
    fn from(progress: LegacySyncProgress) -> Self {
        FFILegacySyncProgress {
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

/// SyncState exposed by the FFI as FFISyncState.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FFISyncState {
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
#[derive(Debug, Clone)]
pub struct FFIBlockHeadersProgress {
    pub state: FFISyncState,
    pub current_height: u32,
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
            current_height: progress.current_height(),
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
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
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

#[repr(C)]
pub struct FFIDetailedSyncProgress {
    pub total_height: u32,
    pub percentage: f64,
    pub headers_per_second: f64,
    pub estimated_seconds_remaining: i64, // -1 if unknown
    pub stage: FFISyncStage,
    pub stage_message: FFIString,
    pub overview: FFILegacySyncProgress,
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

        let overview = FFILegacySyncProgress::from(progress.sync_progress.clone());

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

#[repr(C)]
pub struct FFIChainState {
    pub masternode_height: u32,
    pub last_chainlock_height: u32,
    pub last_chainlock_hash: FFIString,
    pub current_filter_tip: u32,
}

impl From<ChainState> for FFIChainState {
    fn from(state: ChainState) -> Self {
        FFIChainState {
            masternode_height: state.last_masternode_diff_height.unwrap_or(0),
            last_chainlock_height: state.last_chainlock_height.unwrap_or(0),
            last_chainlock_hash: FFIString::new(
                &state.last_chainlock_hash.map(|h| h.to_string()).unwrap_or_default(),
            ),
            current_filter_tip: 0, // FilterHeader not directly convertible to u32
        }
    }
}

/// FFI-safe array that transfers ownership of memory to the C caller.
///
/// # Safety
///
/// This struct represents memory that has been allocated by Rust but ownership
/// has been transferred to the C caller. The caller is responsible for:
/// - Not accessing the memory after it has been freed
/// - Calling `dash_spv_ffi_array_destroy` to properly deallocate the memory
/// - Ensuring the data, len, and capacity fields remain consistent
#[repr(C)]
pub struct FFIArray {
    pub data: *mut c_void,
    pub len: usize,
    pub capacity: usize,
    pub elem_size: usize,
    pub elem_align: usize,
}

impl FFIArray {
    /// Creates a new FFIArray from a Vec, transferring ownership of the memory to the caller.
    ///
    /// # Safety
    ///
    /// This function uses `std::mem::forget` to prevent Rust from deallocating the Vec's memory.
    /// The caller becomes responsible for freeing this memory by calling `dash_spv_ffi_array_destroy`.
    /// Failure to call the destroy function will result in a memory leak.
    pub fn new<T>(vec: Vec<T>) -> Self {
        let mut vec = vec;
        let data = vec.as_mut_ptr() as *mut c_void;
        let len = vec.len();
        let capacity = vec.capacity();
        std::mem::forget(vec);

        FFIArray {
            data,
            len,
            capacity,
            elem_size: std::mem::size_of::<T>(),
            elem_align: std::mem::align_of::<T>(),
        }
    }

    /// # Safety
    /// - The `data` pointer must be valid for reads of `len * size_of::<T>()` bytes.
    /// - The memory must not be mutated for the duration of the returned slice borrow.
    /// - Caller must ensure the `elem_size`/`elem_align` match `T` when interpreting the data.
    pub unsafe fn as_slice<T>(&self) -> &[T] {
        if self.data.is_null() || self.len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(self.data as *const T, self.len)
        }
    }
}

#[no_mangle]
/// # Safety
/// - `s.ptr` must be a pointer previously returned by `FFIString::new` or compatible.
/// - It must not be used after this call.
pub unsafe extern "C" fn dash_spv_ffi_string_destroy(s: FFIString) {
    if !s.ptr.is_null() {
        let _ = CString::from_raw(s.ptr);
    }
}

#[no_mangle]
/// # Safety
/// - `arr` must be either null or a valid pointer to an `FFIArray` previously constructed in Rust.
/// - The memory referenced by `arr.data` must not be used after this call.
pub unsafe extern "C" fn dash_spv_ffi_array_destroy(arr: *mut FFIArray) {
    if !arr.is_null() {
        // Only deallocate the vector buffer recorded in the struct; do not free the struct itself.
        // This makes it safe to pass pointers to stack-allocated FFIArray values returned by-value.
        if !(*arr).data.is_null() && (*arr).capacity > 0 {
            // Deallocate the vector buffer using the original layout
            use std::alloc::{dealloc, Layout};
            let size = (*arr).elem_size.saturating_mul((*arr).capacity);
            if size > 0 && (*arr).elem_align.is_power_of_two() && (*arr).elem_align > 0 {
                // Safety: elem_size/elem_align were recorded from the original Vec<T>
                let layout = Layout::from_size_align_unchecked(size, (*arr).elem_align);
                unsafe { dealloc((*arr).data as *mut u8, layout) };
            }
        }
    }
}

/// Destroy an array of FFIString pointers (Vec<*mut FFIString>) and their contents.
///
/// This function:
/// - Iterates the array elements as pointers to FFIString and destroys each via dash_spv_ffi_string_destroy
/// - Frees the underlying vector buffer stored in FFIArray
/// - Does not free the FFIArray struct itself (safe for both stack- and heap-allocated structs)
#[no_mangle]
/// # Safety
/// - `arr` must be either null or a valid pointer to an `FFIArray` whose elements are `*mut FFIString`.
/// - Each element pointer must be valid or null; non-null entries are freed.
/// - The memory referenced by `arr.data` must not be used after this call.
pub unsafe extern "C" fn dash_spv_ffi_string_array_destroy(arr: *mut FFIArray) {
    if arr.is_null() {
        return;
    }

    // Destroy each FFIString pointed to by the array elements
    if !(*arr).data.is_null() && (*arr).len > 0 {
        let slice = std::slice::from_raw_parts((*arr).data as *const *mut FFIString, (*arr).len);
        for &ffi_string_ptr in slice.iter() {
            if !ffi_string_ptr.is_null() {
                // Take ownership and destroy
                let boxed = Box::from_raw(ffi_string_ptr);
                dash_spv_ffi_string_destroy(*boxed);
            }
        }
    }

    // Free the vector buffer itself
    dash_spv_ffi_array_destroy(arr);
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

/// FFI-safe representation of an unconfirmed transaction
///
/// # Safety
///
/// This struct contains raw pointers that must be properly managed:
///
/// - `raw_tx`: A pointer to the raw transaction bytes. The caller is responsible for:
///   - Allocating this memory before passing it to Rust
///   - Ensuring the pointer remains valid for the lifetime of this struct
///   - Freeing the memory after use with `dash_spv_ffi_unconfirmed_transaction_destroy_raw_tx`
///
/// - `addresses`: A pointer to an array of FFIString objects. The caller is responsible for:
///   - Allocating this array before passing it to Rust
///   - Ensuring the pointer remains valid for the lifetime of this struct
///   - Freeing each FFIString in the array with `dash_spv_ffi_string_destroy`
///   - Freeing the array itself after use with `dash_spv_ffi_unconfirmed_transaction_destroy_addresses`
///
/// Use `dash_spv_ffi_unconfirmed_transaction_destroy` to safely clean up all resources
/// associated with this struct.
#[repr(C)]
pub struct FFIUnconfirmedTransaction {
    pub txid: FFIString,
    pub raw_tx: *mut u8,
    pub raw_tx_len: usize,
    pub amount: i64,
    pub fee: u64,
    pub is_instant_send: bool,
    pub is_outgoing: bool,
    pub addresses: *mut FFIString,
    pub addresses_len: usize,
}

/// Destroys the raw transaction bytes allocated for an FFIUnconfirmedTransaction
///
/// # Safety
///
/// - `raw_tx` must be a valid pointer to memory allocated by the caller
/// - `raw_tx_len` must be the correct length of the allocated memory
/// - The pointer must not be used after this function is called
/// - This function should only be called once per allocation
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_unconfirmed_transaction_destroy_raw_tx(
    raw_tx: *mut u8,
    raw_tx_len: usize,
) {
    if !raw_tx.is_null() && raw_tx_len > 0 {
        // Reconstruct the Vec to properly deallocate the memory
        let _ = Vec::from_raw_parts(raw_tx, raw_tx_len, raw_tx_len);
    }
}

/// Destroys the addresses array allocated for an FFIUnconfirmedTransaction
///
/// # Safety
///
/// - `addresses` must be a valid pointer to an array of FFIString objects
/// - `addresses_len` must be the correct length of the array
/// - Each FFIString in the array must be destroyed separately using `dash_spv_ffi_string_destroy`
/// - The pointer must not be used after this function is called
/// - This function should only be called once per allocation
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_unconfirmed_transaction_destroy_addresses(
    addresses: *mut FFIString,
    addresses_len: usize,
) {
    if !addresses.is_null() && addresses_len > 0 {
        // Reconstruct the Vec to properly deallocate the memory
        let _ = Vec::from_raw_parts(addresses, addresses_len, addresses_len);
    }
}

/// Destroys an FFIUnconfirmedTransaction and all its associated resources
///
/// # Safety
///
/// - `tx` must be a valid pointer to an FFIUnconfirmedTransaction
/// - All resources (raw_tx, addresses array, and individual FFIStrings) will be freed
/// - The pointer must not be used after this function is called
/// - This function should only be called once per FFIUnconfirmedTransaction
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_unconfirmed_transaction_destroy(
    tx: *mut FFIUnconfirmedTransaction,
) {
    if !tx.is_null() {
        let tx = Box::from_raw(tx);

        // Destroy the txid FFIString
        dash_spv_ffi_string_destroy(tx.txid);

        // Destroy the raw_tx bytes
        if !tx.raw_tx.is_null() && tx.raw_tx_len > 0 {
            dash_spv_ffi_unconfirmed_transaction_destroy_raw_tx(tx.raw_tx, tx.raw_tx_len);
        }

        // Destroy each FFIString in the addresses array
        if !tx.addresses.is_null() && tx.addresses_len > 0 {
            // We need to read the addresses and destroy them one by one
            for i in 0..tx.addresses_len {
                let address_ptr = tx.addresses.add(i);
                let address = std::ptr::read(address_ptr);
                dash_spv_ffi_string_destroy(address);
            }
            // Destroy the addresses array itself
            dash_spv_ffi_unconfirmed_transaction_destroy_addresses(tx.addresses, tx.addresses_len);
        }

        // The Box will be dropped here, freeing the FFIUnconfirmedTransaction itself
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
