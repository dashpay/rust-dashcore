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
