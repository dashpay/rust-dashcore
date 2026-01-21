use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::PathBuf;
use std::sync::OnceLock;

use crate::{set_last_error, SpvFFIErrorCode};
use dash_spv::{LogFileConfig, LoggingConfig};

/// Static storage for the logging guard to keep it alive for the FFI lifetime.
/// The guard must remain alive for log flushing to work correctly.
static LOGGING_GUARD: OnceLock<dash_spv::LoggingGuard> = OnceLock::new();

/// Initialize logging for the SPV library.
///
/// # Arguments
/// - `level`: Log level string (null uses RUST_LOG env var or defaults to INFO).
///   Valid values: "error", "warn", "info", "debug", "trace"
/// - `enable_console`: Whether to output logs to console (stderr)
/// - `log_dir`: Directory for log files (null to disable file logging)
/// - `max_files`: Maximum archived log files to retain (ignored if log_dir is null)
///
/// # Safety
/// - `level` and `log_dir` may be null or point to valid, NUL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_init_logging(
    level: *const c_char,
    enable_console: bool,
    log_dir: *const c_char,
    max_files: usize,
) -> i32 {
    let level_filter = if level.is_null() {
        None
    } else {
        match CStr::from_ptr(level).to_str() {
            Ok(s) => match s.parse() {
                Ok(lf) => Some(lf),
                Err(_) => {
                    set_last_error(&format!(
                        "Invalid log level '{}'. Valid: error, warn, info, debug, trace",
                        s
                    ));
                    return SpvFFIErrorCode::InvalidArgument as i32;
                }
            },
            Err(e) => {
                set_last_error(&format!("Invalid UTF-8 in log level: {}", e));
                return SpvFFIErrorCode::InvalidArgument as i32;
            }
        }
    };

    let file_config = if log_dir.is_null() {
        None
    } else {
        match CStr::from_ptr(log_dir).to_str() {
            Ok(s) => Some(LogFileConfig {
                log_dir: PathBuf::from(s),
                max_files,
            }),
            Err(e) => {
                set_last_error(&format!("Invalid UTF-8 in log directory: {}", e));
                return SpvFFIErrorCode::InvalidArgument as i32;
            }
        }
    };

    let config = LoggingConfig {
        level: level_filter,
        console: enable_console,
        file: file_config,
    };

    match dash_spv::init_logging(config) {
        Ok(guard) => {
            // Store guard in static to keep it alive for log flushing.
            // OnceLock::set returns Err if already set (first init wins).
            if LOGGING_GUARD.set(guard).is_err() {
                tracing::warn!("Logging already initialized, ignoring subsequent init");
            }
            SpvFFIErrorCode::Success as i32
        }
        Err(e) => {
            set_last_error(&format!("Failed to initialize logging: {}", e));
            SpvFFIErrorCode::RuntimeError as i32
        }
    }
}

#[no_mangle]
pub extern "C" fn dash_spv_ffi_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn dash_spv_ffi_enable_test_mode() {
    std::env::set_var("DASH_SPV_TEST_MODE", "1");
}
