use crate::{null_check, set_last_error, FFIErrorCode, FFIMempoolStrategy, FFIString};
use dash_spv::{ClientConfig, ValidationMode};
use key_wallet_ffi::FFINetwork;
use std::ffi::CStr;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::os::raw::c_char;

#[repr(C)]
pub enum FFIValidationMode {
    None = 0,
    Basic = 1,
    Full = 2,
}

impl From<FFIValidationMode> for ValidationMode {
    fn from(mode: FFIValidationMode) -> Self {
        match mode {
            FFIValidationMode::None => ValidationMode::None,
            FFIValidationMode::Basic => ValidationMode::Basic,
            FFIValidationMode::Full => ValidationMode::Full,
        }
    }
}

#[repr(C)]
pub struct FFIClientConfig {
    // Opaque pointer to avoid exposing internal ClientConfig in generated C headers
    inner: *mut std::ffi::c_void,
    // Tokio runtime worker thread count (0 = auto)
    pub worker_threads: u32,
}

#[no_mangle]
pub extern "C" fn dash_spv_ffi_config_new(network: FFINetwork) -> *mut FFIClientConfig {
    let config = ClientConfig::new(network.into());
    let inner = Box::into_raw(Box::new(config)) as *mut std::ffi::c_void;
    Box::into_raw(Box::new(FFIClientConfig {
        inner,
        worker_threads: 0,
    }))
}

#[no_mangle]
pub extern "C" fn dash_spv_ffi_config_mainnet() -> *mut FFIClientConfig {
    let config = ClientConfig::mainnet();
    let inner = Box::into_raw(Box::new(config)) as *mut std::ffi::c_void;
    Box::into_raw(Box::new(FFIClientConfig {
        inner,
        worker_threads: 0,
    }))
}

#[no_mangle]
pub extern "C" fn dash_spv_ffi_config_testnet() -> *mut FFIClientConfig {
    let config = ClientConfig::testnet();
    let inner = Box::into_raw(Box::new(config)) as *mut std::ffi::c_void;
    Box::into_raw(Box::new(FFIClientConfig {
        inner,
        worker_threads: 0,
    }))
}

/// Sets the data directory for storing blockchain data
///
/// # Safety
/// - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
/// - `path` must be a valid null-terminated C string
/// - The caller must ensure the config pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_set_data_dir(
    config: *mut FFIClientConfig,
    path: *const c_char,
) -> i32 {
    null_check!(config);
    null_check!(path);

    let config = unsafe { &mut *((*config).inner as *mut ClientConfig) };
    match CStr::from_ptr(path).to_str() {
        Ok(path_str) => {
            config.storage_path = Some(path_str.into());
            FFIErrorCode::Success as i32
        }
        Err(e) => {
            set_last_error(&format!("Invalid UTF-8 in path: {}", e));
            FFIErrorCode::InvalidArgument as i32
        }
    }
}

/// Sets the validation mode for the SPV client
///
/// # Safety
/// - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
/// - The caller must ensure the config pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_set_validation_mode(
    config: *mut FFIClientConfig,
    mode: FFIValidationMode,
) -> i32 {
    null_check!(config);

    let config = unsafe { &mut *((*config).inner as *mut ClientConfig) };
    config.validation_mode = mode.into();
    FFIErrorCode::Success as i32
}

/// Sets the maximum number of peers to connect to
///
/// # Safety
/// - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
/// - The caller must ensure the config pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_set_max_peers(
    config: *mut FFIClientConfig,
    max_peers: u32,
) -> i32 {
    null_check!(config);

    let config = unsafe { &mut *((*config).inner as *mut ClientConfig) };
    config.max_peers = max_peers;
    FFIErrorCode::Success as i32
}

// Note: dash-spv doesn't have min_peers, only max_peers

/// Adds a peer address to the configuration
///
/// Accepts either a full socket address (e.g., "192.168.1.1:9999" or "[::1]:19999")
/// or an IP-only string (e.g., "127.0.0.1" or "2001:db8::1"). When an IP-only
/// string is given, the default P2P port for the configured network is used.
///
/// # Safety
/// - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
/// - `addr` must be a valid null-terminated C string containing a socket address or IP-only string
/// - The caller must ensure both pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_add_peer(
    config: *mut FFIClientConfig,
    addr: *const c_char,
) -> i32 {
    null_check!(config);
    null_check!(addr);

    let cfg = unsafe { &mut *((*config).inner as *mut ClientConfig) };
    let default_port = match cfg.network {
        dashcore::Network::Dash => 9999,
        dashcore::Network::Testnet => 19999,
        dashcore::Network::Regtest => 19899,
        dashcore::Network::Devnet => 29999,
        _ => 9999,
    };

    let addr_str = match CStr::from_ptr(addr).to_str() {
        Ok(s) => s.trim(),
        Err(e) => {
            set_last_error(&format!("Invalid UTF-8 in address: {}", e));
            return FFIErrorCode::InvalidArgument as i32;
        }
    };

    // 1) Try parsing as full SocketAddr first (handles IPv6 [::1]:port forms)
    if let Ok(sock) = addr_str.parse::<SocketAddr>() {
        cfg.peers.push(sock);
        return FFIErrorCode::Success as i32;
    }

    // 2) If that fails, try parsing as bare IP address and apply default port
    if let Ok(ip) = addr_str.parse::<IpAddr>() {
        let sock = SocketAddr::new(ip, default_port);
        cfg.peers.push(sock);
        return FFIErrorCode::Success as i32;
    }

    // 3) Optionally attempt DNS name with explicit port only; if no port, reject
    if !addr_str.contains(':') {
        set_last_error("Missing port for hostname; supply 'host:port' or IP only");
        return FFIErrorCode::InvalidArgument as i32;
    }

    match addr_str.to_socket_addrs() {
        Ok(mut iter) => match iter.next() {
            Some(sock) => {
                cfg.peers.push(sock);
                FFIErrorCode::Success as i32
            }
            None => {
                set_last_error(&format!("Failed to resolve address: {}", addr_str));
                FFIErrorCode::InvalidArgument as i32
            }
        },
        Err(e) => {
            set_last_error(&format!("Invalid address {} ({})", addr_str, e));
            FFIErrorCode::InvalidArgument as i32
        }
    }
}

/// Sets the user agent string to advertise in the P2P handshake
///
/// # Safety
/// - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
/// - `user_agent` must be a valid null-terminated C string
/// - The caller must ensure both pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_set_user_agent(
    config: *mut FFIClientConfig,
    user_agent: *const c_char,
) -> i32 {
    null_check!(config);
    null_check!(user_agent);

    // Validate the user_agent string
    match CStr::from_ptr(user_agent).to_str() {
        Ok(agent_str) => {
            // Store as-is; normalization/length capping is applied at handshake build time
            let cfg = unsafe { &mut *((*config).inner as *mut ClientConfig) };
            cfg.user_agent = Some(agent_str.to_string());
            FFIErrorCode::Success as i32
        }
        Err(e) => {
            set_last_error(&format!("Invalid UTF-8 in user agent: {}", e));
            FFIErrorCode::InvalidArgument as i32
        }
    }
}

/// Sets whether to relay transactions (currently a no-op)
///
/// # Safety
/// - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
/// - The caller must ensure the config pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_set_relay_transactions(
    config: *mut FFIClientConfig,
    _relay: bool,
) -> i32 {
    null_check!(config);

    let _config = unsafe { &mut *((*config).inner as *mut ClientConfig) };
    // relay_transactions not directly settable in current ClientConfig
    FFIErrorCode::Success as i32
}

/// Sets whether to load bloom filters
///
/// # Safety
/// - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
/// - The caller must ensure the config pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_set_filter_load(
    config: *mut FFIClientConfig,
    load_filters: bool,
) -> i32 {
    null_check!(config);

    let config = unsafe { &mut *((*config).inner as *mut ClientConfig) };
    config.enable_filters = load_filters;
    FFIErrorCode::Success as i32
}

/// Restrict connections strictly to configured peers (disable DNS discovery and peer store)
///
/// # Safety
/// - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_set_restrict_to_configured_peers(
    config: *mut FFIClientConfig,
    restrict_peers: bool,
) -> i32 {
    null_check!(config);

    let config = unsafe { &mut *((*config).inner as *mut ClientConfig) };
    config.restrict_to_configured_peers = restrict_peers;
    FFIErrorCode::Success as i32
}

/// Enables or disables masternode synchronization
///
/// # Safety
/// - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
/// - The caller must ensure the config pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_set_masternode_sync_enabled(
    config: *mut FFIClientConfig,
    enable: bool,
) -> i32 {
    null_check!(config);

    let config = unsafe { &mut *((*config).inner as *mut ClientConfig) };
    config.enable_masternodes = enable;
    FFIErrorCode::Success as i32
}

/// Gets the network type from the configuration
///
/// # Safety
/// - `config` must be a valid pointer to an FFIClientConfig or null
/// - If null, returns FFINetwork::Dash as default
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_get_network(
    config: *const FFIClientConfig,
) -> FFINetwork {
    if config.is_null() {
        return FFINetwork::Dash;
    }

    let config = unsafe { &*((*config).inner as *const ClientConfig) };
    config.network.into()
}

/// Gets the data directory path from the configuration
///
/// # Safety
/// - `config` must be a valid pointer to an FFIClientConfig or null
/// - If null or no data directory is set, returns an FFIString with null pointer
/// - The returned FFIString must be freed by the caller using `dash_spv_ffi_string_destroy`
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_get_data_dir(
    config: *const FFIClientConfig,
) -> FFIString {
    if config.is_null() {
        return FFIString {
            ptr: std::ptr::null_mut(),
            length: 0,
        };
    }

    let config = unsafe { &*((*config).inner as *const ClientConfig) };
    match &config.storage_path {
        Some(dir) => FFIString::new(&dir.to_string_lossy()),
        None => FFIString {
            ptr: std::ptr::null_mut(),
            length: 0,
        },
    }
}

/// Destroys an FFIClientConfig and frees its memory
///
/// # Safety
/// - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet, or null
/// - After calling this function, the config pointer becomes invalid and must not be used
/// - This function should only be called once per config instance
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_destroy(config: *mut FFIClientConfig) {
    if !config.is_null() {
        // Reclaim outer struct
        let cfg = Box::from_raw(config);
        // Free inner ClientConfig if present
        if !cfg.inner.is_null() {
            let _ = Box::from_raw(cfg.inner as *mut ClientConfig);
        }
    }
}

impl FFIClientConfig {
    pub fn get_inner(&self) -> &ClientConfig {
        unsafe { &*(self.inner as *const ClientConfig) }
    }

    pub fn clone_inner(&self) -> ClientConfig {
        unsafe { (*(self.inner as *const ClientConfig)).clone() }
    }
}

/// Sets the number of Tokio worker threads for the FFI runtime (0 = auto)
///
/// # Safety
/// - `config` must be a valid pointer to an FFIClientConfig
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_set_worker_threads(
    config: *mut FFIClientConfig,
    threads: u32,
) -> i32 {
    null_check!(config);
    let cfg = &mut *config;
    cfg.worker_threads = threads;
    FFIErrorCode::Success as i32
}

// Mempool configuration functions

/// Enables or disables mempool tracking
///
/// # Safety
/// - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
/// - The caller must ensure the config pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_set_mempool_tracking(
    config: *mut FFIClientConfig,
    enable: bool,
) -> i32 {
    null_check!(config);

    let config = unsafe { &mut *((*config).inner as *mut ClientConfig) };
    config.enable_mempool_tracking = enable;
    FFIErrorCode::Success as i32
}

/// Sets the mempool synchronization strategy
///
/// # Safety
/// - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
/// - The caller must ensure the config pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_set_mempool_strategy(
    config: *mut FFIClientConfig,
    strategy: FFIMempoolStrategy,
) -> i32 {
    null_check!(config);

    let config = unsafe { &mut *((*config).inner as *mut ClientConfig) };
    config.mempool_strategy = strategy.into();
    FFIErrorCode::Success as i32
}

/// Sets the maximum number of mempool transactions to track
///
/// # Safety
/// - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
/// - The caller must ensure the config pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_set_max_mempool_transactions(
    config: *mut FFIClientConfig,
    max_transactions: u32,
) -> i32 {
    null_check!(config);

    let config = unsafe { &mut *((*config).inner as *mut ClientConfig) };
    config.max_mempool_transactions = max_transactions as usize;
    FFIErrorCode::Success as i32
}

/// Sets the mempool transaction timeout in seconds
///
/// # Safety
/// - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
/// - The caller must ensure the config pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_set_mempool_timeout(
    config: *mut FFIClientConfig,
    timeout_secs: u64,
) -> i32 {
    null_check!(config);

    let config = unsafe { &mut *((*config).inner as *mut ClientConfig) };
    config.mempool_timeout_secs = timeout_secs;
    FFIErrorCode::Success as i32
}

/// Sets whether to fetch full mempool transaction data
///
/// # Safety
/// - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
/// - The caller must ensure the config pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_set_fetch_mempool_transactions(
    config: *mut FFIClientConfig,
    fetch: bool,
) -> i32 {
    null_check!(config);

    let config = unsafe { &mut *((*config).inner as *mut ClientConfig) };
    config.fetch_mempool_transactions = fetch;
    FFIErrorCode::Success as i32
}

/// Sets whether to persist mempool state to disk
///
/// # Safety
/// - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
/// - The caller must ensure the config pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_set_persist_mempool(
    config: *mut FFIClientConfig,
    persist: bool,
) -> i32 {
    null_check!(config);

    let config = unsafe { &mut *((*config).inner as *mut ClientConfig) };
    config.persist_mempool = persist;
    FFIErrorCode::Success as i32
}

/// Gets whether mempool tracking is enabled
///
/// # Safety
/// - `config` must be a valid pointer to an FFIClientConfig or null
/// - If null, returns false as default
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_get_mempool_tracking(
    config: *const FFIClientConfig,
) -> bool {
    if config.is_null() {
        return false;
    }

    let config = unsafe { &*((*config).inner as *const ClientConfig) };
    config.enable_mempool_tracking
}

/// Gets the mempool synchronization strategy
///
/// # Safety
/// - `config` must be a valid pointer to an FFIClientConfig or null
/// - If null, returns FFIMempoolStrategy::FetchAll as default
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_get_mempool_strategy(
    config: *const FFIClientConfig,
) -> FFIMempoolStrategy {
    if config.is_null() {
        return FFIMempoolStrategy::FetchAll;
    }

    let config = unsafe { &*((*config).inner as *const ClientConfig) };
    config.mempool_strategy.into()
}

// Checkpoint sync configuration functions

/// Sets the starting block height for synchronization
///
/// # Safety
/// - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
/// - The caller must ensure the config pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_set_start_from_height(
    config: *mut FFIClientConfig,
    height: u32,
) -> i32 {
    null_check!(config);

    let config = unsafe { &mut *((*config).inner as *mut ClientConfig) };
    config.start_from_height = Some(height);
    FFIErrorCode::Success as i32
}

/// Sets the wallet creation timestamp for synchronization optimization
///
/// # Safety
/// - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
/// - The caller must ensure the config pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_set_wallet_creation_time(
    config: *mut FFIClientConfig,
    timestamp: u32,
) -> i32 {
    null_check!(config);

    let config = unsafe { &mut *((*config).inner as *mut ClientConfig) };
    config.wallet_creation_time = Some(timestamp);
    FFIErrorCode::Success as i32
}
