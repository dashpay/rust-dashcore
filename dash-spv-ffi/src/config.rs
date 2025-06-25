use crate::{null_check, set_last_error, FFIErrorCode, FFIMempoolStrategy, FFINetwork, FFIString};
use dash_spv::{ClientConfig, ValidationMode};
use dash_spv::client::config::MempoolStrategy;
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

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_get_data_dir(
    config: *const FFIClientConfig,
) -> FFIString {
    if config.is_null() {
        return FFIString {
            ptr: std::ptr::null_mut(),
        };
    }

    let config = &(*config).inner;
    match &config.storage_path {
        Some(dir) => FFIString::new(&dir.to_string_lossy()),
        None => FFIString {
            ptr: std::ptr::null_mut(),
        },
    }
}

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
