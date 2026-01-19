//! Lock file implementation and related unit tests.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use crate::{StorageError, StorageResult};

/// Lock file that prevents concurrent access from multiple processes.
pub(super) struct LockFile {
    path: PathBuf,
    _file: File,
}

impl LockFile {
    pub(super) fn new(path: PathBuf) -> StorageResult<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .map_err(|e| StorageError::WriteFailed(format!("Failed to create lock file: {}", e)))?;

        file.try_lock().map_err(|e| match e {
            std::fs::TryLockError::WouldBlock => StorageError::DirectoryLocked(format!(
                "Data directory '{}' is already in use by another process",
                path.parent().map(|p| p.display().to_string()).unwrap_or_default()
            )),
            std::fs::TryLockError::Error(io_err) => {
                StorageError::WriteFailed(format!("Failed to acquire lock: {}", io_err))
            }
        })?;

        if let Err(e) = writeln!(file, "{}", std::process::id()) {
            tracing::warn!("Failed to write PID to lock file: {}", e);
        }

        Ok(Self {
            path,
            _file: file,
        })
    }
}

impl Drop for LockFile {
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
    fn test_lock_file_removed_on_drop() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let lock_path = temp_dir.path().join(".lock");

        {
            let _lock = LockFile::new(lock_path.clone()).unwrap();
            assert!(lock_path.exists(), "Lock file should exist while held");
        } // lock dropped here

        assert!(!lock_path.exists(), "Lock file should be removed after drop");
    }
}
