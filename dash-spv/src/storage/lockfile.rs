//! Lock file implementation and related unit tests.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::{StorageError, StorageResult};

/// Lock file that prevents concurrent access from multiple processes.
///
/// On Unix the file is unlinked on drop (see `Drop`). Elsewhere it stays. On Windows, deleting a
/// file that is still open either frees the name at once (POSIX semantics) or leaves the file
/// delete-pending until its last handle closes. With the first, std exposes no file identity on
/// stable Rust to check, so an earlier opener could lock the deleted file while a later one locks
/// a new file at the path; with the second, a later opener fails to open the path. The next holder
/// truncates the kept file once locked.
pub(super) struct LockFile {
    #[cfg(unix)]
    path: PathBuf,
    _file: File,
}

/// Opens tried before [`LockFile::new`] gives up on a lock file that keeps being replaced.
const OPEN_ATTEMPTS: usize = 8;

impl LockFile {
    pub(super) fn new(path: PathBuf) -> StorageResult<Self> {
        for _ in 0..OPEN_ATTEMPTS {
            if let Some(file) = hold(&path, open(&path)?)? {
                return Ok(Self {
                    #[cfg(unix)]
                    path,
                    _file: file,
                });
            }
        }
        Err(StorageError::DirectoryLocked(format!(
            "lock file '{}' was replaced on each of {OPEN_ATTEMPTS} opens",
            path.display()
        )))
    }
}

/// Opens the lock file without truncating it: a refused open must leave the holder's PID.
fn open(path: &Path) -> StorageResult<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|e| StorageError::WriteFailed(format!("Failed to create lock file: {}", e)))
}

/// Locks `file`, opened at `path`, and writes this process's PID into it. `None` when the file
/// was unlinked from `path` before the lock was taken: a holder's `Drop` unlinks it (on Unix)
/// before it unlocks, so an opener that opened it earlier would hold a lock no later opener sees
/// (they create a new file at `path`), and must open again.
fn hold(path: &Path, mut file: File) -> StorageResult<Option<File>> {
    let locked = classify_lock_result(file.try_lock(), path)?;
    if locked && !is_at(&file, path)? {
        return Ok(None);
    }
    file.set_len(0)
        .map_err(|e| StorageError::WriteFailed(format!("Failed to truncate lock file: {e}")))?;
    if locked {
        if let Err(e) = writeln!(file, "{}", std::process::id()) {
            tracing::warn!("Failed to write PID to lock file: {}", e);
        }
    }
    Ok(Some(file))
}

/// Whether `file` is the file at `path` (the same device and inode).
#[cfg(unix)]
fn is_at(file: &File, path: &Path) -> StorageResult<bool> {
    use std::os::unix::fs::MetadataExt;
    let failed = |e: std::io::Error| StorageError::WriteFailed(format!("lock file: {e}"));
    let held = file.metadata().map_err(failed)?;
    match std::fs::metadata(path) {
        Ok(at) => Ok((held.dev(), held.ino()) == (at.dev(), at.ino())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(failed(e)),
    }
}

/// Elsewhere a holder never unlinks the lock file (see [`LockFile`]): unless something else
/// deletes or replaces it, the file at `path` is the one opened.
#[cfg(not(unix))]
fn is_at(_: &File, _: &Path) -> StorageResult<bool> {
    Ok(true)
}

/// Interprets the result of [`File::try_lock`] for an advisory data-directory lock.
///
/// Returns `Ok(true)` when the lock was acquired, `Ok(false)` when advisory
/// locking is unsupported on the platform (so the caller should proceed without
/// it), and `Err(..)` when the directory is already locked or a genuine I/O
/// error occurred.
fn classify_lock_result(
    result: Result<(), std::fs::TryLockError>,
    path: &std::path::Path,
) -> StorageResult<bool> {
    match result {
        Ok(()) => Ok(true),
        Err(std::fs::TryLockError::WouldBlock) => Err(StorageError::DirectoryLocked(format!(
            "Data directory '{}' is already in use by another process",
            path.parent().map(|p| p.display().to_string()).unwrap_or_default()
        ))),
        // Some platforms (e.g. Android) do not implement advisory file locking
        // and return `ErrorKind::Unsupported` at the std layer. The lock is only
        // a best-effort guard against multiple processes sharing one data
        // directory; on such single-process platforms its absence is safe, so
        // degrade gracefully instead of failing init.
        Err(std::fs::TryLockError::Error(io_err))
            if io_err.kind() == std::io::ErrorKind::Unsupported =>
        {
            tracing::warn!(
                "advisory file lock not supported on this platform ({io_err}); \
                 continuing without multi-process protection"
            );
            Ok(false)
        }
        Err(std::fs::TryLockError::Error(io_err)) => {
            Err(StorageError::WriteFailed(format!("Failed to acquire lock: {io_err}")))
        }
    }
}

#[cfg(unix)]
impl Drop for LockFile {
    /// Unlinks the file while the lock is still held (the file closes after this body), the order
    /// [`hold`]'s check relies on.
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.path) {
            tracing::warn!("Failed to remove lock file: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom};
    use tempfile::TempDir;

    impl LockFile {
        /// Reads the PID from the lock file.
        fn read_pid(&mut self) -> std::io::Result<u32> {
            self._file.seek(SeekFrom::Start(0))?;
            let mut content = String::new();
            self._file.read_to_string(&mut content)?;
            content
                .trim()
                .parse()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        }
    }

    #[test]
    fn test_lock_file_creation() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let lock_path = temp_dir.path().join(".lock");

        let lock = LockFile::new(lock_path.clone());
        assert!(lock.is_ok(), "Lock file creation should succeed");

        assert!(lock_path.exists(), "Lock file should exist after creation");
    }

    #[test]
    fn test_lock_file_contains_pid() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let lock_path = temp_dir.path().join(".lock");

        let mut lock = LockFile::new(lock_path.clone()).unwrap();
        assert_eq!(lock.read_pid().unwrap(), std::process::id());
    }

    #[test]
    fn test_concurrent_lock_blocked() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let lock_path = temp_dir.path().join(".lock");

        let _lock1 = LockFile::new(lock_path.clone()).unwrap();

        // Second lock on same path should fail
        let lock2 = LockFile::new(lock_path.clone());
        assert!(lock2.is_err(), "Second lock should fail");

        match lock2.err().unwrap() {
            StorageError::DirectoryLocked(msg) => {
                assert!(msg.contains("already in use"));
            }
            other => panic!("Expected DirectoryLocked error, got: {:?}", other),
        }
    }

    /// A new holder replaces a stale lock file's contents with its PID.
    #[test]
    fn a_stale_lock_file_holds_only_the_new_pid() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let lock_path = temp_dir.path().join(".lock");

        std::fs::write(&lock_path, "stale contents longer than any PID\n").unwrap();
        let mut lock = LockFile::new(lock_path.clone()).unwrap();
        assert_eq!(lock.read_pid().unwrap(), std::process::id());
    }

    /// A refused lock leaves the holder's file as it was: its PID is not truncated away.
    #[test]
    fn a_refused_lock_leaves_the_holders_file() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let lock_path = temp_dir.path().join(".lock");

        // Read through the holder's handle: Windows refuses reads of a locked file through others.
        let mut held = LockFile::new(lock_path.clone()).unwrap();
        assert_eq!(held.read_pid().unwrap(), std::process::id());
        assert!(LockFile::new(lock_path.clone()).is_err());
        assert_eq!(held.read_pid().unwrap(), std::process::id());
    }

    /// An opener that opened the file before its holder dropped it, and locks it after, holds
    /// an unlinked file while a later opener holds the one at the path: it must open again.
    #[cfg(unix)]
    #[test]
    fn a_lock_on_an_unlinked_file_is_not_held() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let lock_path = temp_dir.path().join(".lock");

        let first = LockFile::new(lock_path.clone()).unwrap();
        let early = open(&lock_path).unwrap();
        drop(first);
        let _later = LockFile::new(lock_path.clone()).unwrap();
        assert!(hold(&lock_path, early).unwrap().is_none());
        assert!(LockFile::new(lock_path.clone()).is_err(), "the later opener holds it");
    }

    #[test]
    fn test_lock_released_on_drop() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let lock_path = temp_dir.path().join(".lock");

        {
            let _lock = LockFile::new(lock_path.clone()).unwrap();
        } // lock dropped here

        // Should be able to acquire lock again
        let lock2 = LockFile::new(lock_path.clone());
        assert!(lock2.is_ok(), "Should acquire lock after previous one dropped");
    }

    #[test]
    fn test_classify_lock_result_acquired() {
        let path = PathBuf::from("/tmp/data/.lock");
        assert!(classify_lock_result(Ok(()), &path).expect("acquired lock should be Ok"));
    }

    #[test]
    fn test_classify_lock_result_would_block() {
        let path = PathBuf::from("/tmp/data/.lock");
        let result = classify_lock_result(Err(std::fs::TryLockError::WouldBlock), &path);
        match result {
            Err(StorageError::DirectoryLocked(msg)) => {
                assert!(msg.contains("already in use"), "unexpected message: {msg}");
            }
            other => panic!("Expected DirectoryLocked error, got: {:?}", other),
        }
    }

    #[test]
    fn test_classify_lock_result_unsupported_is_non_fatal() {
        // Platforms such as Android return `ErrorKind::Unsupported` from
        // `try_lock`; this must degrade gracefully rather than fail init.
        let path = PathBuf::from("/tmp/data/.lock");
        let io_err =
            std::io::Error::new(std::io::ErrorKind::Unsupported, "try_lock() not supported");
        let result = classify_lock_result(Err(std::fs::TryLockError::Error(io_err)), &path);
        assert!(!result.expect("unsupported lock should be Ok(false)"));
    }

    #[test]
    fn test_classify_lock_result_genuine_io_error_is_fatal() {
        let path = PathBuf::from("/tmp/data/.lock");
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let result = classify_lock_result(Err(std::fs::TryLockError::Error(io_err)), &path);
        match result {
            Err(StorageError::WriteFailed(msg)) => {
                assert!(msg.contains("Failed to acquire lock"), "unexpected message: {msg}");
            }
            other => panic!("Expected WriteFailed error, got: {:?}", other),
        }
    }

    #[test]
    fn test_lock_file_removed_on_drop() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let lock_path = temp_dir.path().join(".lock");

        {
            let _lock = LockFile::new(lock_path.clone()).unwrap();
            assert!(lock_path.exists(), "Lock file should exist while held");
        } // lock dropped here

        #[cfg(unix)]
        assert!(!lock_path.exists(), "Lock file should be removed after drop");
        #[cfg(not(unix))]
        assert!(lock_path.exists(), "Lock file should stay after drop");
    }
}
