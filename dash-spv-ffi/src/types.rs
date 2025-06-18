use dash_spv::{ChainState, PeerInfo, SpvStats, SyncProgress};
use dashcore::Network;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};

#[repr(C)]
pub struct FFIString {
    pub ptr: *mut c_char,
}

impl FFIString {
    pub fn new(s: &str) -> Self {
        let c_string = CString::new(s).unwrap_or_else(|_| CString::new("").unwrap());
        FFIString {
            ptr: c_string.into_raw(),
        }
    }

    pub unsafe fn from_ptr(ptr: *const c_char) -> Result<String, String> {
        if ptr.is_null() {
            return Err("Null pointer".to_string());
        }
        CStr::from_ptr(ptr).to_str().map(|s| s.to_string()).map_err(|e| e.to_string())
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FFINetwork {
    Dash = 0,
    Testnet = 1,
    Regtest = 2,
    Devnet = 3,
}

impl From<FFINetwork> for Network {
    fn from(net: FFINetwork) -> Self {
        match net {
            FFINetwork::Dash => Network::Dash,
            FFINetwork::Testnet => Network::Testnet,
            FFINetwork::Regtest => Network::Regtest,
            FFINetwork::Devnet => Network::Devnet,
        }
    }
}

impl From<Network> for FFINetwork {
    fn from(net: Network) -> Self {
        match net {
            Network::Dash => FFINetwork::Dash,
            Network::Testnet => FFINetwork::Testnet,
            Network::Regtest => FFINetwork::Regtest,
            Network::Devnet => FFINetwork::Devnet,
            _ => FFINetwork::Dash,
        }
    }
}

#[repr(C)]
pub struct FFISyncProgress {
    pub header_height: u32,
    pub filter_header_height: u32,
    pub masternode_height: u32,
    pub peer_count: u32,
    pub headers_synced: bool,
    pub filter_headers_synced: bool,
    pub masternodes_synced: bool,
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
            headers_synced: progress.headers_synced,
            filter_headers_synced: progress.filter_headers_synced,
            masternodes_synced: progress.masternodes_synced,
            filters_downloaded: progress.filters_downloaded as u32,
            last_synced_filter_height: progress.last_synced_filter_height.unwrap_or(0),
        }
    }
}

#[repr(C)]
pub struct FFIChainState {
    pub header_height: u32,
    pub filter_header_height: u32,
    pub masternode_height: u32,
    pub last_chainlock_height: u32,
    pub last_chainlock_hash: FFIString,
    pub current_filter_tip: u32,
}

impl From<ChainState> for FFIChainState {
    fn from(state: ChainState) -> Self {
        FFIChainState {
            header_height: state.headers.len() as u32,
            filter_header_height: state.filter_headers.len() as u32,
            masternode_height: state.last_masternode_diff_height.unwrap_or(0),
            last_chainlock_height: state.last_chainlock_height.unwrap_or(0),
            last_chainlock_hash: FFIString::new(
                &state.last_chainlock_hash.map(|h| h.to_string()).unwrap_or_default(),
            ),
            current_filter_tip: 0, // FilterHeader not directly convertible to u32
        }
    }
}

#[repr(C)]
pub struct FFISpvStats {
    pub headers_downloaded: u64,
    pub filter_headers_downloaded: u64,
    pub filters_downloaded: u64,
    pub filters_matched: u64,
    pub blocks_processed: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub uptime: u64,
}

impl From<SpvStats> for FFISpvStats {
    fn from(stats: SpvStats) -> Self {
        FFISpvStats {
            headers_downloaded: stats.headers_downloaded,
            filter_headers_downloaded: stats.filter_headers_downloaded,
            filters_downloaded: stats.filters_downloaded,
            filters_matched: stats.filters_matched,
            blocks_processed: stats.blocks_processed,
            bytes_received: stats.bytes_received,
            bytes_sent: stats.bytes_sent,
            uptime: stats.uptime.as_secs(),
        }
    }
}

#[repr(C)]
pub struct FFIPeerInfo {
    pub address: FFIString,
    pub connected: u64,
    pub last_seen: u64,
    pub version: u32,
    pub services: u64,
    pub user_agent: FFIString,
    pub best_height: u32,
}

impl From<PeerInfo> for FFIPeerInfo {
    fn from(info: PeerInfo) -> Self {
        FFIPeerInfo {
            address: FFIString::new(&info.address.to_string()),
            connected: if info.connected {
                1
            } else {
                0
            },
            last_seen: info.last_seen.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            version: info.version.unwrap_or(0),
            services: info.services.unwrap_or(0),
            user_agent: FFIString::new(&info.user_agent.as_deref().unwrap_or("")),
            best_height: info.best_height.unwrap_or(0) as u32,
        }
    }
}

#[repr(C)]
pub struct FFIArray {
    pub data: *mut c_void,
    pub len: usize,
    pub capacity: usize,
}

impl FFIArray {
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
        }
    }

    pub unsafe fn as_slice<T>(&self) -> &[T] {
        if self.data.is_null() || self.len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(self.data as *const T, self.len)
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_string_destroy(s: FFIString) {
    if !s.ptr.is_null() {
        let _ = CString::from_raw(s.ptr);
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_array_destroy(arr: *mut FFIArray) {
    if !arr.is_null() {
        let arr = Box::from_raw(arr);
        if !arr.data.is_null() && arr.capacity > 0 {
            Vec::from_raw_parts(arr.data as *mut u8, arr.len, arr.capacity);
        }
    }
}

#[repr(C)]
pub struct FFITransaction {
    pub txid: FFIString,
    pub version: i32,
    pub locktime: u32,
    pub size: u32,
    pub weight: u32,
}
