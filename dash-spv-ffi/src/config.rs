use crate::{null_check, set_last_error, FFIErrorCode, FFIMempoolStrategy, FFIString};
use dash_spv::{ClientConfig, ValidationMode};
use key_wallet_ffi::FFINetwork;
use std::ffi::CStr;
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

#[repr(transparent)]
pub struct FFIClientConfig {
    inner: ClientConfig,
}

#[no_mangle]
pub extern "C" fn dash_spv_ffi_config_new(network: FFINetwork) -> *mut FFIClientConfig {
    let config = ClientConfig::new(network.into());
    Box::into_raw(Box::new(FFIClientConfig {
        inner: config,
    }))
}

#[no_mangle]
pub extern "C" fn dash_spv_ffi_config_mainnet() -> *mut FFIClientConfig {
    let config = ClientConfig::mainnet();
    Box::into_raw(Box::new(FFIClientConfig {
        inner: config,
    }))
}

#[no_mangle]
pub extern "C" fn dash_spv_ffi_config_testnet() -> *mut FFIClientConfig {
    let config = ClientConfig::testnet();
    Box::into_raw(Box::new(FFIClientConfig {
        inner: config,
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

    let config = &mut (*config).inner;
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

    let config = &mut (*config).inner;
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

    let config = &mut (*config).inner;
    config.max_peers = max_peers;
    FFIErrorCode::Success as i32
}

// Note: dash-spv doesn't have min_peers, only max_peers

/// Adds a peer address to the configuration
///
/// # Safety
/// - `config` must be a valid pointer to an FFIClientConfig created by dash_spv_ffi_config_new/mainnet/testnet
/// - `addr` must be a valid null-terminated C string containing a socket address (e.g., "192.168.1.1:9999")
/// - The caller must ensure both pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_add_peer(
    config: *mut FFIClientConfig,
    addr: *const c_char,
) -> i32 {
    null_check!(config);
    null_check!(addr);

    let config = &mut (*config).inner;
    match CStr::from_ptr(addr).to_str() {
        Ok(addr_str) => match addr_str.parse() {
            Ok(socket_addr) => {
                config.peers.push(socket_addr);
                FFIErrorCode::Success as i32
            }
            Err(e) => {
                set_last_error(&format!("Invalid socket address: {}", e));
                FFIErrorCode::InvalidArgument as i32
            }
        },
        Err(e) => {
            set_last_error(&format!("Invalid UTF-8 in address: {}", e));
            FFIErrorCode::InvalidArgument as i32
        }
    }
}

/// Sets the user agent string (currently not supported)
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
        Ok(_agent_str) => {
            // user_agent is not directly settable in current ClientConfig
            set_last_error("Setting user agent is not supported in current implementation");
            FFIErrorCode::ConfigError as i32
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

    let _config = &mut (*config).inner;
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

    let config = &mut (*config).inner;
    config.enable_filters = load_filters;
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

    let config = &mut (*config).inner;
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

    let config = &(*config).inner;
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

    let config = &(*config).inner;
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
        let _ = Box::from_raw(config);
    }
}

impl FFIClientConfig {
    pub fn get_inner(&self) -> &ClientConfig {
        &self.inner
    }

    pub fn clone_inner(&self) -> ClientConfig {
        self.inner.clone()
    }
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

    let config = &mut (*config).inner;
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

    let config = &mut (*config).inner;
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

    let config = &mut (*config).inner;
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

    let config = &mut (*config).inner;
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

    let config = &mut (*config).inner;
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

    let config = &mut (*config).inner;
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

    let config = &(*config).inner;
    config.enable_mempool_tracking
}

/// Gets the mempool synchronization strategy
///
/// # Safety
/// - `config` must be a valid pointer to an FFIClientConfig or null
/// - If null, returns FFIMempoolStrategy::Selective as default
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_get_mempool_strategy(
    config: *const FFIClientConfig,
) -> FFIMempoolStrategy {
    if config.is_null() {
        return FFIMempoolStrategy::Selective;
    }

    let config = &(*config).inner;
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

    let config = &mut (*config).inner;
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

    let config = &mut (*config).inner;
    config.wallet_creation_time = Some(timestamp);
    FFIErrorCode::Success as i32
}
