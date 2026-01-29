//! Logging configuration and file rotation for the Dash SPV client.
//!
//! This module provides configurable logging with optional file output and automatic rotation.

use std::fs::{self, File};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Local};
use tracing::level_filters::LevelFilter;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::error::{LoggingError, LoggingResult};

/// Prefix for archived log files.
const LOG_FILE_PREFIX: &str = "dash-spv.";
/// Name of the active log file.
const ACTIVE_LOG_NAME: &str = "run.log";

/// Guard that must be kept alive to ensure log flushing on shutdown.
/// When this guard is dropped, all buffered log entries will be flushed.
#[derive(Debug)]
pub struct LoggingGuard {
    _worker_guard: Option<WorkerGuard>,
}

/// Configuration for logging output.
#[derive(Debug, Clone)]
pub struct LoggingConfig {
    /// Log level filter. If None, falls back to INFO.
    pub level: Option<LevelFilter>,
    /// Whether to output logs to console (stderr).
    pub console: bool,
    /// Optional file logging configuration.
    pub file: Option<LogFileConfig>,
}

/// Configuration for log file output.
#[derive(Debug, Clone)]
pub struct LogFileConfig {
    /// Directory where log files will be stored.
    pub log_dir: PathBuf,
    /// Maximum number of archived log files to keep.
    pub max_files: usize,
}

/// Initialize console-only logging with the given level.
///
/// This is a convenience function for simple use cases.
/// For file logging, use [`init_logging`] with a [`LoggingConfig`].
pub fn init_console_logging(level: LevelFilter) -> LoggingResult<LoggingGuard> {
    init_logging(LoggingConfig {
        level: Some(level),
        console: true,
        file: None,
    })
}

/// Initialize logging with the given configuration.
///
/// Returns a `LoggingGuard` that must be kept alive for the duration of the application.
/// When the guard is dropped, all buffered log entries will be flushed to disk.
///
/// # Arguments
///
/// * `config` - Logging configuration specifying level, console, and file output options.
///
/// # Errors
///
/// Returns an error if:
/// - The log directory cannot be created
/// - The tracing subscriber cannot be initialized
///
/// Note: If neither console nor file output is enabled, logging is disabled
/// (tracing macros become no-ops) and Ok is returned.
///
/// # Examples
///
/// ```no_run
/// use dash_spv::logging::{init_logging, LoggingConfig, LogFileConfig};
/// use dash_spv::LevelFilter;
/// use std::path::PathBuf;
///
/// // Console-only logging
/// let _guard = init_logging(LoggingConfig {
///     level: Some(LevelFilter::INFO),
///     console: true,
///     file: None,
/// }).unwrap();
///
/// // File logging only (CLI default)
/// let _guard = init_logging(LoggingConfig {
///     level: Some(LevelFilter::INFO),
///     console: false,
///     file: Some(LogFileConfig {
///         log_dir: PathBuf::from("/path/to/data/logs"),
///         max_files: 20,
///     }),
/// }).unwrap();
/// ```
pub fn init_logging(config: LoggingConfig) -> LoggingResult<LoggingGuard> {
    // No output configured - tracing macros become no-ops
    if !config.console && config.file.is_none() {
        return Ok(LoggingGuard {
            _worker_guard: None,
        });
    }

    // Build env filter from explicit level or RUST_LOG
    let env_filter = match config.level {
        Some(level) => EnvFilter::new(level.to_string()),
        None => EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(LevelFilter::INFO.to_string())),
    };

    // Set up file layer if requested
    let (file_layer, guard) = if let Some(ref file_config) = config.file {
        let (non_blocking, guard) = setup_file_logging(file_config)?;
        let layer = fmt::layer()
            .with_target(true)
            .with_thread_ids(false)
            .with_ansi(false)
            .with_writer(non_blocking);
        (Some(layer), Some(guard))
    } else {
        (None, None)
    };

    // Set up console layer if requested
    let console_layer =
        config.console.then(|| fmt::layer().with_target(true).with_thread_ids(false));

    // Combine layers and initialize
    tracing_subscriber::registry()
        .with(env_filter)
        .with(file_layer)
        .with(console_layer)
        .try_init()
        .map_err(|e| LoggingError::SubscriberInit(e.to_string()))?;

    Ok(LoggingGuard {
        _worker_guard: guard,
    })
}

/// Set up file logging: create directory, rotate old log, cleanup, and create writer.
fn setup_file_logging(config: &LogFileConfig) -> LoggingResult<(NonBlocking, WorkerGuard)> {
    // Create logs directory if needed
    fs::create_dir_all(&config.log_dir)?;

    // Rotate previous run.log to archived name
    rotate_previous_log(&config.log_dir)?;

    // Clean up old archived log files
    cleanup_old_logs(&config.log_dir, config.max_files)?;

    // Create file appender for run.log
    let log_path = config.log_dir.join(ACTIVE_LOG_NAME);
    let file = File::create(&log_path)?;

    // Wrap in non-blocking writer
    Ok(tracing_appender::non_blocking(file))
}

/// Rotate the previous run.log to an archived name.
///
/// If run.log exists, renames it to `dash-spv.YYYY-MM-DD.HHMMSS.log` based on
/// the file modification time.
fn rotate_previous_log(log_dir: &Path) -> LoggingResult<()> {
    let run_log_path = log_dir.join(ACTIVE_LOG_NAME);

    if !run_log_path.exists() {
        return Ok(());
    }

    // Get timestamp from file modification time
    let timestamp = get_file_modification_time(&run_log_path).unwrap_or_else(Local::now);

    // Format: dash-spv.2025-01-15.143025.log
    let archive_name = format!("{}{}.log", LOG_FILE_PREFIX, timestamp.format("%Y-%m-%d.%H%M%S"));
    let archive_path = log_dir.join(&archive_name);

    // Handle collision: if archive already exists, add a suffix
    let final_path = if archive_path.exists() {
        (1..=999)
            .map(|i| {
                log_dir.join(format!(
                    "{}{}-{}.log",
                    LOG_FILE_PREFIX,
                    timestamp.format("%Y-%m-%d.%H%M%S"),
                    i
                ))
            })
            .find(|p| !p.exists())
            .ok_or_else(|| {
                LoggingError::RotationFailed("too many log files with same timestamp".to_string())
            })?
    } else {
        archive_path
    };

    fs::rename(&run_log_path, &final_path).map_err(|e| LoggingError::RotationFailed(e.to_string()))
}

/// Get file modification time as DateTime.
fn get_file_modification_time(path: &Path) -> Option<DateTime<Local>> {
    let metadata = fs::metadata(path).ok()?;
    let modified = metadata.modified().ok()?;
    Some(DateTime::from(modified))
}

/// Delete oldest archived log files if count exceeds max_files.
///
/// Only deletes files matching the pattern `dash-spv.*.log`. The active `run.log`
/// is never deleted.
fn cleanup_old_logs(log_dir: &Path, max_files: usize) -> LoggingResult<()> {
    let mut archived_logs: Vec<_> = fs::read_dir(log_dir)
        .map_err(|e| LoggingError::RotationFailed(format!("failed to read log dir: {}", e)))?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .map(|name| name.starts_with(LOG_FILE_PREFIX) && name.ends_with(".log"))
                .unwrap_or(false)
        })
        .collect();

    if archived_logs.len() <= max_files {
        return Ok(());
    }

    // Sort by modification time (oldest first)
    archived_logs.sort_by(|a, b| {
        let a_time = a.metadata().and_then(|m| m.modified()).ok();
        let b_time = b.metadata().and_then(|m| m.modified()).ok();
        a_time.cmp(&b_time)
    });

    // Remove oldest files to get down to max_files
    let to_remove = archived_logs.len() - max_files;
    for entry in archived_logs.into_iter().take(to_remove) {
        if let Err(e) = fs::remove_file(entry.path()) {
            tracing::warn!("Failed to remove old log file {:?}: {}", entry.path(), e);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_rotate_previous_log_no_file() {
        let temp_dir = TempDir::new().unwrap();
        let log_dir = temp_dir.path();

        // Should succeed when no run.log exists
        rotate_previous_log(log_dir).unwrap();

        // Verify no files were created
        let files: Vec<_> = fs::read_dir(log_dir).unwrap().collect();
        assert!(files.is_empty());
    }

    #[test]
    fn test_rotate_previous_log_renames_file() {
        let temp_dir = TempDir::new().unwrap();
        let log_dir = temp_dir.path();

        // Create a run.log with some content
        let run_log = log_dir.join(ACTIVE_LOG_NAME);
        let mut file = File::create(&run_log).unwrap();
        writeln!(file, "INFO test message").unwrap();
        drop(file);

        // Rotate
        rotate_previous_log(log_dir).unwrap();

        // Verify run.log is gone
        assert!(!run_log.exists());

        // Verify archived file exists with correct name pattern
        let files: Vec<_> = fs::read_dir(log_dir).unwrap().filter_map(|e| e.ok()).collect();
        assert_eq!(files.len(), 1);

        let archived_name = files[0].file_name().to_string_lossy().to_string();
        assert!(archived_name.starts_with("dash-spv."));
        assert!(archived_name.ends_with(".log"));
    }

    #[test]
    fn test_cleanup_old_logs_under_limit() {
        let temp_dir = TempDir::new().unwrap();
        let log_dir = temp_dir.path();

        // Create 3 archived log files
        for i in 1..=3 {
            let name = format!("dash-spv.2025-01-{:02}.120000.log", i);
            File::create(log_dir.join(&name)).unwrap();
        }

        // Cleanup with limit of 7
        cleanup_old_logs(log_dir, 7).unwrap();

        // All 3 files should remain
        let files: Vec<_> = fs::read_dir(log_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(LOG_FILE_PREFIX))
            .collect();
        assert_eq!(files.len(), 3);
    }

    #[test]
    fn test_cleanup_old_logs_over_limit() {
        let temp_dir = TempDir::new().unwrap();
        let log_dir = temp_dir.path();

        // Create 10 archived log files with different mtimes
        for i in 1..=10 {
            let name = format!("dash-spv.2025-01-{:02}.120000.log", i);
            let path = log_dir.join(&name);
            let mut file = File::create(&path).unwrap();
            writeln!(file, "log {}", i).unwrap();
            drop(file);
            // Add small delay to ensure different mtimes
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        // Cleanup with limit of 3
        cleanup_old_logs(log_dir, 3).unwrap();

        // Only 3 files should remain
        let files: Vec<_> = fs::read_dir(log_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(LOG_FILE_PREFIX))
            .collect();
        assert_eq!(files.len(), 3);
    }

    #[test]
    fn test_cleanup_old_logs_ignores_run_log() {
        let temp_dir = TempDir::new().unwrap();
        let log_dir = temp_dir.path();

        // Create run.log (should not be deleted)
        File::create(log_dir.join(ACTIVE_LOG_NAME)).unwrap();

        // Create 5 archived log files
        for i in 1..=5 {
            let name = format!("dash-spv.2025-01-{:02}.120000.log", i);
            File::create(log_dir.join(&name)).unwrap();
        }

        // Cleanup with limit of 2
        cleanup_old_logs(log_dir, 2).unwrap();

        // run.log should still exist
        assert!(log_dir.join(ACTIVE_LOG_NAME).exists());

        // Only 2 archived files should remain
        let archived: Vec<_> = fs::read_dir(log_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(LOG_FILE_PREFIX))
            .collect();
        assert_eq!(archived.len(), 2);
    }

    #[test]
    fn test_cleanup_old_logs_boundary_conditions() {
        // Test max_files = 0 removes all archived logs
        {
            let temp_dir = TempDir::new().unwrap();
            let log_dir = temp_dir.path();

            for i in 1..=3 {
                let name = format!("dash-spv.2025-01-{:02}.120000.log", i);
                let path = log_dir.join(&name);
                let mut file = File::create(&path).unwrap();
                writeln!(file, "log {}", i).unwrap();
                drop(file);
                std::thread::sleep(std::time::Duration::from_millis(10));
            }

            cleanup_old_logs(log_dir, 0).unwrap();

            let archived: Vec<_> = fs::read_dir(log_dir)
                .unwrap()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().starts_with(LOG_FILE_PREFIX))
                .collect();
            assert_eq!(archived.len(), 0);
        }

        // Test max_files = 1 keeps only newest
        {
            let temp_dir = TempDir::new().unwrap();
            let log_dir = temp_dir.path();

            for i in 1..=5 {
                let name = format!("dash-spv.2025-01-{:02}.120000.log", i);
                let path = log_dir.join(&name);
                let mut file = File::create(&path).unwrap();
                writeln!(file, "log {}", i).unwrap();
                drop(file);
                std::thread::sleep(std::time::Duration::from_millis(10));
            }

            cleanup_old_logs(log_dir, 1).unwrap();

            let archived: Vec<_> = fs::read_dir(log_dir)
                .unwrap()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().starts_with(LOG_FILE_PREFIX))
                .collect();
            assert_eq!(archived.len(), 1);
        }
    }

    #[test]
    fn test_consecutive_rotations() {
        let temp_dir = TempDir::new().unwrap();
        let log_dir = temp_dir.path();

        // Simulate 3 consecutive startups
        for _ in 1..=3 {
            let run_log = log_dir.join(ACTIVE_LOG_NAME);
            let mut file = File::create(&run_log).unwrap();
            writeln!(file, "INFO startup").unwrap();
            drop(file);

            // Small delay to ensure different mtime (and thus different archive names)
            std::thread::sleep(std::time::Duration::from_millis(1100));

            rotate_previous_log(log_dir).unwrap();
        }

        // Should have 3 archived logs, no run.log
        assert!(!log_dir.join(ACTIVE_LOG_NAME).exists());

        let archived: Vec<_> = fs::read_dir(log_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(LOG_FILE_PREFIX))
            .collect();
        assert_eq!(archived.len(), 3);
    }

    #[test]
    fn test_cleanup_ignores_non_log_files() {
        let temp_dir = TempDir::new().unwrap();
        let log_dir = temp_dir.path();

        // Create some archived log files with staggered mtimes
        for i in 1..=5 {
            let name = format!("dash-spv.2025-01-{:02}.120000.log", i);
            let path = log_dir.join(&name);
            let mut file = File::create(&path).unwrap();
            writeln!(file, "log {}", i).unwrap();
            drop(file);
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        // Create some non-log files that should not be touched
        File::create(log_dir.join("other.txt")).unwrap();
        File::create(log_dir.join("dash-spv.backup")).unwrap();
        File::create(log_dir.join("something.log")).unwrap();

        // Cleanup with limit of 2
        cleanup_old_logs(log_dir, 2).unwrap();

        // Non-log files should still exist
        assert!(log_dir.join("other.txt").exists());
        assert!(log_dir.join("dash-spv.backup").exists());
        assert!(log_dir.join("something.log").exists());

        // Only 2 archived logs should remain (matching dash-spv.*.log pattern)
        let archived: Vec<_> = fs::read_dir(log_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                name.starts_with(LOG_FILE_PREFIX) && name.ends_with(".log")
            })
            .collect();
        assert_eq!(archived.len(), 2);
    }

    #[test]
    fn test_get_file_modification_time() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");

        File::create(&test_file).unwrap();

        let mtime = get_file_modification_time(&test_file);
        assert!(mtime.is_some());

        // Should be recent (within last minute)
        let now = Local::now();
        let dt = mtime.unwrap();
        let diff = now.signed_duration_since(dt);
        assert!(diff.num_seconds() < 60);
    }

    #[test]
    fn test_get_file_modification_time_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let nonexistent = temp_dir.path().join("does_not_exist.txt");

        let mtime = get_file_modification_time(&nonexistent);
        assert!(mtime.is_none());
    }

    #[test]
    fn test_rotate_preserves_content() {
        let temp_dir = TempDir::new().unwrap();
        let log_dir = temp_dir.path();

        // Create run.log with specific content
        let run_log = log_dir.join(ACTIVE_LOG_NAME);
        let mut file = File::create(&run_log).unwrap();
        writeln!(file, "2025-01-15T14:30:25.123456 INFO first message").unwrap();
        writeln!(file, "2025-01-15T14:30:26.123456 INFO second message").unwrap();
        writeln!(file, "2025-01-15T14:30:27.123456 INFO third message").unwrap();
        drop(file);

        // Rotate
        rotate_previous_log(log_dir).unwrap();

        // Find the archived file
        let archived: Vec<_> = fs::read_dir(log_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(LOG_FILE_PREFIX))
            .collect();
        assert_eq!(archived.len(), 1);

        // Read the archived content
        let content = fs::read_to_string(archived[0].path()).unwrap();
        assert!(content.contains("first message"));
        assert!(content.contains("second message"));
        assert!(content.contains("third message"));
    }

    #[test]
    fn test_init_logging_no_output_succeeds() {
        // Neither console nor file is valid - tracing macros become no-ops
        let result = init_logging(LoggingConfig {
            level: Some(LevelFilter::INFO),
            console: false,
            file: None,
        });

        assert!(result.is_ok());
    }

    #[test]
    fn test_setup_file_logging_creates_directory() {
        let temp_dir = TempDir::new().unwrap();
        let log_dir = temp_dir.path().join("nested").join("logs");

        // Directory doesn't exist yet
        assert!(!log_dir.exists());

        let config = LogFileConfig {
            log_dir: log_dir.clone(),
            max_files: 7,
        };

        let result = setup_file_logging(&config);
        assert!(result.is_ok());

        // Directory should now exist
        assert!(log_dir.exists());

        // run.log should exist
        assert!(log_dir.join(ACTIVE_LOG_NAME).exists());
    }

    #[test]
    fn test_setup_file_logging_rotates_and_cleans() {
        let temp_dir = TempDir::new().unwrap();
        let log_dir = temp_dir.path();

        // Create an existing run.log
        let run_log = log_dir.join(ACTIVE_LOG_NAME);
        let mut file = File::create(&run_log).unwrap();
        writeln!(file, "2025-01-15T10:00:00.000000 INFO old session").unwrap();
        drop(file);

        // Create 5 archived logs
        for i in 1..=5 {
            let name = format!("dash-spv.2025-01-{:02}.120000.log", i);
            let path = log_dir.join(&name);
            let mut f = File::create(&path).unwrap();
            writeln!(f, "log {}", i).unwrap();
            drop(f);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let config = LogFileConfig {
            log_dir: log_dir.to_path_buf(),
            max_files: 3,
        };

        let result = setup_file_logging(&config);
        assert!(result.is_ok());

        // Old run.log should be archived (now we have 6 archives total, but limit is 3)
        // After cleanup, should have 3 archived + 1 new run.log
        let archived: Vec<_> = fs::read_dir(log_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(LOG_FILE_PREFIX))
            .collect();
        assert_eq!(archived.len(), 3);

        // New run.log should exist (and be empty or have just been created)
        assert!(log_dir.join(ACTIVE_LOG_NAME).exists());
    }
}
