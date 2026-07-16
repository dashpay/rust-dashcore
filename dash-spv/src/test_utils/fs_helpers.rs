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
pub(super) fn clear_stale_runtime_locks(datadir: &Path) {
    let regtest = datadir.join("regtest");
    remove_if_exists(&regtest.join(".lock"));

    // Wallet directories may sit under regtest/<name>/ or regtest/wallets/<name>/.
    for wallet_root in [regtest.clone(), regtest.join("wallets")] {
        let Ok(entries) = fs::read_dir(&wallet_root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                remove_if_exists(&path.join(".walletlock"));
            }
        }
    }
}

fn remove_if_exists(path: &Path) {
    if path.exists() {
        if let Err(e) = fs::remove_file(path) {
            eprintln!("Failed to remove stale lock {}: {}", path.display(), e);
        }
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
            retain_test_dir(&self.path, &self.label);
        }
    }
}
