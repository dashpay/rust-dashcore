//! Filesystem helpers for test infrastructure.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Recursively copy a directory and all its contents.
pub(super) fn copy_dir(src: &Path, dst: &Path) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let dst_path = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &dst_path)?;
        } else {
            fs::copy(entry.path(), dst_path)?;
        }
    }
    Ok(())
}

/// Remove runtime lock files that must not survive a datadir copy.
///
/// The regtest fixtures are snapshots of a previously running node, so they
/// may contain `regtest/.lock` and per-wallet `.walletlock` files. A live
/// dashd refuses to start (or fails wallet load) when those are present.
pub(super) fn clear_stale_runtime_locks(datadir: &Path) -> io::Result<()> {
    let regtest = datadir.join("regtest");
    remove_if_exists(&regtest.join(".lock"))?;
    // Legacy single-wallet layout stores the lock at regtest/.walletlock.
    remove_if_exists(&regtest.join(".walletlock"))?;

    // Named wallet directories may sit under regtest/<name>/ or regtest/wallets/<name>/.
    let wallets_root = regtest.join("wallets");
    for wallet_root in [&regtest, &wallets_root] {
        let entries = match fs::read_dir(wallet_root) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!("failed to read wallet root {}: {}", wallet_root.display(), e),
                ));
            }
        };
        for entry in entries {
            let entry = entry.map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("failed to read entry in {}: {}", wallet_root.display(), e),
                )
            })?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                remove_if_exists(&path.join(".walletlock"))?;
            }
        }
    }

    Ok(())
}

fn remove_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io::Error::new(
            e.kind(),
            format!("failed to remove stale lock {}: {}", path.display(), e),
        )),
    }
}

/// When `DASHD_TEST_RETAIN_DIR` is set, copy `src` to a test-named
/// subdirectory for post-mortem inspection.
///
/// By default only retains on panic. Set `DASHD_TEST_RETAIN_ALWAYS=1`
/// to also retain directories from passing tests.
pub fn retain_test_dir(src: &Path, label: &str) {
    let retain_always = std::env::var("DASHD_TEST_RETAIN_ALWAYS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if !retain_always && !std::thread::panicking() {
        return;
    }

    retain_test_dir_now(src, label);
}

/// Unconditionally retain `src` when `DASHD_TEST_RETAIN_DIR` is set.
///
/// Use this before panicking during setup that has not yet constructed a type
/// whose `Drop` impl calls [`retain_test_dir`].
pub(super) fn retain_test_dir_now(src: &Path, label: &str) {
    let Ok(retain_dir) = std::env::var("DASHD_TEST_RETAIN_DIR") else {
        return;
    };

    let test_name = std::thread::current().name().unwrap_or("unknown").replace(":", "_");
    let dest = PathBuf::from(&retain_dir).join(&test_name).join(label);
    if dest.exists() {
        let _ = fs::remove_dir_all(&dest);
    }
    if let Err(e) = copy_dir(src, &dest) {
        eprintln!("Failed to retain test data: {}", e);
    } else {
        eprintln!("Test data retained at: {}", dest.display());
    }
}

/// Retains `path` on panic drop when `DASHD_TEST_RETAIN_DIR` is set.
///
/// Used while constructing [`super::DashdTestContext`] so startup failures
/// still leave dashd logs for CI artifacts.
pub(super) struct RetainOnPanic {
    path: PathBuf,
    label: String,
}

impl RetainOnPanic {
    pub(super) fn new(path: impl Into<PathBuf>, label: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            label: label.into(),
        }
    }

    pub(super) fn defuse(self) {
        std::mem::forget(self);
    }
}

impl Drop for RetainOnPanic {
    fn drop(&mut self) {
        if std::thread::panicking() {
            // Already know we are panicking; skip retain_test_dir's re-check.
            retain_test_dir_now(&self.path, &self.label);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn remove_if_exists_treats_missing_file_as_success() {
        let tmp = TempDir::new().unwrap();
        remove_if_exists(&tmp.path().join("missing.lock")).unwrap();
    }

    #[test]
    fn remove_if_exists_propagates_removal_failures() {
        let tmp = TempDir::new().unwrap();
        let lock_path = tmp.path().join(".lock");
        fs::create_dir(&lock_path).unwrap();

        let err = remove_if_exists(&lock_path).unwrap_err();

        assert_ne!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn clear_stale_runtime_locks_treats_missing_roots_as_success() {
        let tmp = TempDir::new().unwrap();
        clear_stale_runtime_locks(tmp.path()).unwrap();
    }

    #[test]
    fn clear_stale_runtime_locks_propagates_directory_read_failures() {
        let tmp = TempDir::new().unwrap();
        let regtest = tmp.path().join("regtest");
        fs::create_dir(&regtest).unwrap();
        fs::write(regtest.join("wallets"), b"not a directory").unwrap();

        let err = clear_stale_runtime_locks(tmp.path()).unwrap_err();

        assert_ne!(err.kind(), io::ErrorKind::NotFound);
    }
}
