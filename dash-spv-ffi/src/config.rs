use crate::{null_check, set_last_error, FFIErrorCode, FFIMempoolStrategy, FFIString};
use dash_spv::{Config, ConfigBuilder, ValidationMode};
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
pub struct FFIConfig {
    // Opaque pointer to avoid exposing internal ClientConfig in generated C headers
    inner: *mut std::ffi::c_void,
    // Tokio runtime worker thread count (0 = auto)
    pub worker_threads: u32,
}

impl From<Config> for FFIConfig {
    fn from(config: Config) -> Self {
        let inner = Box::into_raw(Box::new(config)) as *mut std::ffi::c_void;
        Self {
            inner,
            worker_threads: 0,
        }
    }
}

#[repr(C)]
pub struct FFIConfigBuilder {
    // Opaque pointer to avoid exposing internal ClientConfigBuilder in generated C headers
    inner: *mut std::ffi::c_void,
    // Tokio runtime worker thread count (0 = auto)
    pub worker_threads: u32,
}

impl From<ConfigBuilder> for FFIConfigBuilder {
    fn from(builder: ConfigBuilder) -> Self {
        let inner = Box::into_raw(Box::new(builder)) as *mut std::ffi::c_void;
        Self {
            inner,
            worker_threads: 0,
        }
    }
}

#[no_mangle]
pub extern "C" fn dash_spv_ffi_config_builder_mainnet() -> *mut FFIConfigBuilder {
    Box::into_raw(Box::new(ConfigBuilder::mainnet().into()))
}

#[no_mangle]
pub extern "C" fn dash_spv_ffi_config_builder_testnet() -> *mut FFIConfigBuilder {
    Box::into_raw(Box::new(ConfigBuilder::testnet().into()))
}

#[no_mangle]
pub extern "C" fn dash_spv_ffi_config_builder_devnet() -> *mut FFIConfigBuilder {
    Box::into_raw(Box::new(ConfigBuilder::devnet().into()))
}

#[no_mangle]
pub extern "C" fn dash_spv_ffi_config_builder_regtest() -> *mut FFIConfigBuilder {
    Box::into_raw(Box::new(ConfigBuilder::regtest().into()))
}

/// Sets the data directory for storing blockchain data
///
/// # Safety
/// - `builder` must be a valid pointer to an FFIConfigBuilder
/// - `path` must be a valid null-terminated C string
/// - The caller must ensure the config pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_builder_set_storage_path(
    builder: *mut FFIConfigBuilder,
    path: *const c_char,
) -> i32 {
    null_check!(builder);
    null_check!(path);

    let builder = unsafe { &mut *((*builder).inner as *mut ConfigBuilder) };
    match CStr::from_ptr(path).to_str() {
        Ok(path_str) => {
            builder.storage_path(path_str);
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
/// - `builder` must be a valid pointer to an FFIConfigBuilder
/// - The caller must ensure the config pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_builder_set_validation_mode(
    builder: *mut FFIConfigBuilder,
    mode: FFIValidationMode,
) -> i32 {
    null_check!(builder);

    let config = unsafe { &mut *((*builder).inner as *mut ConfigBuilder) };
    config.validation_mode(mode.into());
    FFIErrorCode::Success as i32
}

/// Sets the maximum number of peers to connect to
///
/// # Safety
/// - `builder` must be a valid pointer to an FFIConfigBuilder
/// - The caller must ensure the config pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_builder_set_max_peers(
    builder: *mut FFIConfigBuilder,
    max_peers: u32,
) -> i32 {
    null_check!(builder);

    let builder = unsafe { &mut *((*builder).inner as *mut ConfigBuilder) };
    builder.max_peers(max_peers);
    FFIErrorCode::Success as i32
}

/// Sets the user agent string to advertise in the P2P handshake
///
/// # Safety
/// - `builder` must be a valid pointer to an FFIConfigBuilder
/// - `user_agent` must be a valid null-terminated C string
/// - The caller must ensure both pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_builder_set_user_agent(
    builder: *mut FFIConfigBuilder,
    user_agent: *const c_char,
) -> i32 {
    null_check!(builder);
    null_check!(user_agent);

    // Validate the user_agent string
    match CStr::from_ptr(user_agent).to_str() {
        Ok(agent_str) => {
            // Store as-is; normalization/length capping is applied at handshake build time
            let cfg = unsafe { &mut *((*builder).inner as *mut ConfigBuilder) };
            cfg.user_agent(agent_str.to_string());
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
/// - `builder` must be a valid pointer to an FFIConfigBuilder
/// - The caller must ensure the config pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_builder_set_relay_transactions(
    builder: *mut FFIConfigBuilder,
    _relay: bool,
) -> i32 {
    null_check!(builder);

    let _builder = unsafe { &mut *((*builder).inner as *mut ConfigBuilder) };
    // relay_transactions not directly settable in current ClientConfig
    FFIErrorCode::Success as i32
}

/// Sets whether to load bloom filters
///
/// # Safety
/// - `builder` must be a valid pointer to an FFIConfigBuilder
/// - The caller must ensure the config pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_builder_set_filter_load(
    builder: *mut FFIConfigBuilder,
    load_filters: bool,
) -> i32 {
    null_check!(builder);

    let builder = unsafe { &mut *((*builder).inner as *mut ConfigBuilder) };
    builder.enable_filters(load_filters);
    FFIErrorCode::Success as i32
}

/// Restrict connections strictly to configured peers (disable DNS discovery and peer store)
///
/// # Safety
/// - `builder` must be a valid pointer to an FFIConfigBuilder
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_builder_set_restrict_to_configured_peers(
    builder: *mut FFIConfigBuilder,
    restrict_peers: bool,
) -> i32 {
    null_check!(builder);

    let builder = unsafe { &mut *((*builder).inner as *mut ConfigBuilder) };
    builder.restrict_to_configured_peers(restrict_peers);
    FFIErrorCode::Success as i32
}

/// Enables or disables masternode synchronization
///
/// # Safety
/// - `builder` must be a valid pointer to an FFIConfigBuilder
/// - The caller must ensure the config pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_builder_set_masternode_sync_enabled(
    builder: *mut FFIConfigBuilder,
    enable: bool,
) -> i32 {
    null_check!(builder);

    let builder = unsafe { &mut *((*builder).inner as *mut ConfigBuilder) };
    builder.enable_masternodes(enable);
    FFIErrorCode::Success as i32
}

/// Sets the number of Tokio worker threads for the FFI runtime (0 = auto)
///
/// # Safety
/// - `config` must be a valid pointer to an FFIConfig
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_builder_set_worker_threads(
    builder: *mut FFIConfigBuilder,
    threads: u32,
) -> i32 {
    null_check!(builder);
    let cfg = &mut *builder;
    cfg.worker_threads = threads;
    FFIErrorCode::Success as i32
}

/// Enables or disables mempool tracking
///
/// # Safety
/// - `builder` must be a valid pointer to an FFIConfigBuilder
/// - The caller must ensure the config pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_builder_set_mempool_tracking(
    builder: *mut FFIConfigBuilder,
    enable: bool,
) -> i32 {
    null_check!(builder);

    let builder = unsafe { &mut *((*builder).inner as *mut ConfigBuilder) };
    builder.enable_mempool_tracking(enable);
    FFIErrorCode::Success as i32
}

/// Sets the mempool synchronization strategy
///
/// # Safety
/// - `builder` must be a valid pointer to an FFIConfigBuilder
/// - The caller must ensure the config pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_builder_set_mempool_strategy(
    builder: *mut FFIConfigBuilder,
    strategy: FFIMempoolStrategy,
) -> i32 {
    null_check!(builder);

    let builder = unsafe { &mut *((*builder).inner as *mut ConfigBuilder) };
    builder.mempool_strategy(strategy.into());
    FFIErrorCode::Success as i32
}

/// Sets the maximum number of mempool transactions to track
///
/// # Safety
/// - `builder` must be a valid pointer to an FFIConfigBuilder
/// - The caller must ensure the config pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_builder_set_max_mempool_transactions(
    builder: *mut FFIConfigBuilder,
    max_transactions: u32,
) -> i32 {
    null_check!(builder);

    let builder = unsafe { &mut *((*builder).inner as *mut ConfigBuilder) };
    builder.max_mempool_transactions(max_transactions as usize);
    FFIErrorCode::Success as i32
}

/// Sets whether to fetch full mempool transaction data
///
/// # Safety
/// - `builder` must be a valid pointer to an FFIConfigBuilder
/// - The caller must ensure the config pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_builder_set_fetch_mempool_transactions(
    builder: *mut FFIConfigBuilder,
    fetch: bool,
) -> i32 {
    null_check!(builder);

    let builder = unsafe { &mut *((*builder).inner as *mut ConfigBuilder) };
    builder.fetch_mempool_transactions(fetch);
    FFIErrorCode::Success as i32
}

/// Sets whether to persist mempool state to disk
///
/// # Safety
/// - `builder` must be a valid pointer to an FFIConfigBuilder
/// - The caller must ensure the config pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_builder_set_persist_mempool(
    builder: *mut FFIConfigBuilder,
    persist: bool,
) -> i32 {
    null_check!(builder);

    let builder = unsafe { &mut *((*builder).inner as *mut ConfigBuilder) };
    builder.persist_mempool(persist);
    FFIErrorCode::Success as i32
}

/// Sets the starting block height for synchronization
///
/// # Safety
/// - `builder` must be a valid pointer to an FFIConfigBuilder
/// - The caller must ensure the config pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_builder_set_start_from_height(
    builder: *mut FFIConfigBuilder,
    height: u32,
) -> i32 {
    null_check!(builder);

    let builder = unsafe { &mut *((*builder).inner as *mut ConfigBuilder) };
    builder.start_from_height(height);
    FFIErrorCode::Success as i32
}

/// Gets ownership of the builder and returns the built configuration destroying the builder in the process
///
/// # Safety
/// - `builder` must be a valid pointer to an FFIConfigBuilder or null
/// - If null, returns default configuration
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_builder_build(
    builder: *mut FFIConfigBuilder,
) -> *mut FFIConfig {
    if builder.is_null() {
        return Box::into_raw(Box::new(Config::default().into()));
    }

    let ffi_builder = Box::from_raw(builder);
    let builder = Box::from_raw(ffi_builder.inner as *mut ConfigBuilder);

    match builder.build() {
        Ok(config) => Box::into_raw(Box::new(config.into())),
        Err(err) => {
            set_last_error(&format!("Failed to build config: {}", err));
            std::ptr::null_mut()
        }
    }
}

/// Destroys an FFIConfigBuilder and frees its memory
///
/// # Safety
/// - `builder` must be a valid pointer to an FFIConfigBuilder, or null
/// - After calling this function, the config pointer becomes invalid and must not be used
/// - This function should only be called once per config builder instance if `built()` was not called
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_builder_destroy(builder: *mut FFIConfigBuilder) {
    if !builder.is_null() {
        let builder = Box::from_raw(builder);
        if !builder.inner.is_null() {
            let _ = Box::from_raw(builder.inner as *mut ConfigBuilder);
        }
    }
}

/// Adds a peer address to the configuration
///
/// Accepts socket addresses with or without port. When no port is specified,
/// the default P2P port for the configured network is used.
///
/// Supported formats:
/// - IP with port: `192.168.1.1:9999`, `[::1]:19999`
/// - IP without port: `127.0.0.1`, `2001:db8::1`
/// - Hostname with port: `node.example.com:9999`
/// - Hostname without port: `node.example.com`
///
/// # Safety
/// - `config` must be a valid pointer to an FFIConfig
/// - `addr` must be a valid null-terminated C string containing a socket address or IP-only string
/// - The caller must ensure both pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_add_peer(
    config: *mut FFIConfig,
    addr: *const c_char,
) -> i32 {
    null_check!(config);
    null_check!(addr);

    let cfg = unsafe { &mut *((*config).inner as *mut Config) };
    let default_port = match cfg.network() {
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

    // Try parsing as bare IP address and apply default port
    if let Ok(ip) = addr_str.parse::<IpAddr>() {
        let sock = SocketAddr::new(ip, default_port);
        cfg.add_peer(sock);
        return FFIErrorCode::Success as i32;
    }

    // If not, must be a hostname - reject empty or missing hostname
    if addr_str.is_empty() || addr_str.starts_with(':') {
        set_last_error("Empty or missing hostname");
        return FFIErrorCode::InvalidArgument as i32;
    }

    let addr_with_port = if addr_str.contains(':') {
        addr_str.to_string()
    } else {
        format!("{}:{}", addr_str, default_port)
    };

    match addr_with_port.to_socket_addrs() {
        Ok(mut iter) => match iter.next() {
            Some(sock) => {
                cfg.add_peer(sock);
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

/// Gets the network type from the configuration
///
/// # Safety
/// - `config` must be a valid pointer to an FFIConfig or null
/// - If null, returns FFINetwork::Dash as default
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_get_network(config: *const FFIConfig) -> FFINetwork {
    if config.is_null() {
        return FFINetwork::Dash;
    }

    let config = unsafe { &*((*config).inner as *const Config) };
    config.network().into()
}

/// Gets the data directory path from the configuration
///
/// # Safety
/// - `config` must be a valid pointer to an FFIConfig or null
/// - If null or no data directory is set, returns an FFIString with null pointer
/// - The returned FFIString must be freed by the caller using `dash_spv_ffi_string_destroy`
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_get_storage_path(
    config: *const FFIConfig,
) -> FFIString {
    if config.is_null() {
        return FFIString {
            ptr: std::ptr::null_mut(),
            length: 0,
        };
    }

    let config = unsafe { &*((*config).inner as *const Config) };
    FFIString::new(&config.storage_path().to_string_lossy())
}

/// Gets whether mempool tracking is enabled
///
/// # Safety
/// - `config` must be a valid pointer to an FFIConfig or null
/// - If null, returns false as default
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_get_mempool_tracking(
    config: *const FFIConfig,
) -> bool {
    if config.is_null() {
        return false;
    }

    let config = unsafe { &*((*config).inner as *const Config) };
    config.enable_mempool_tracking()
}

/// Gets the mempool synchronization strategy
///
/// # Safety
/// - `config` must be a valid pointer to an FFIConfig or null
/// - If null, returns FFIMempoolStrategy::FetchAll as default
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_get_mempool_strategy(
    config: *const FFIConfig,
) -> FFIMempoolStrategy {
    if config.is_null() {
        return FFIMempoolStrategy::FetchAll;
    }

    let config = unsafe { &*((*config).inner as *const Config) };
    config.mempool_strategy().into()
}

/// Destroys an FFIConfig and frees its memory
///
/// # Safety
/// - `builder` must be a valid pointer to an FFIConfigBuilder, or null
/// - After calling this function, the config pointer becomes invalid and must not be used
/// - This function should only be called once per config instance
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_config_destroy(config: *mut FFIConfig) {
    if !config.is_null() {
        // Reclaim outer struct
        let cfg = Box::from_raw(config);
        // Free inner ClientConfig if present
        if !cfg.inner.is_null() {
            let _ = Box::from_raw(cfg.inner as *mut Config);
        }
    }
}

impl FFIConfig {
    pub fn get_inner(&self) -> &Config {
        unsafe { &*(self.inner as *const Config) }
    }

    pub fn clone_inner(&self) -> Config {
        unsafe { (*(self.inner as *const Config)).clone() }
    }
}
