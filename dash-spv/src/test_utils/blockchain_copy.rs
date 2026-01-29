//! Blockchain copy utility for isolated testing.
//!
//! Provides utilities for copying blockchain data to a temporary directory,
//! allowing tests to modify blockchain state without affecting the source data.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Patterns to skip when copying blockchain data.
const SKIP_PATTERNS: &[&str] = &[
    ".cookie",   // Lock file from previous runs
    ".DS_Store", // macOS artifacts
    ".lock",     // Any lock files
    "debug.log", // Log files
];

/// A temporary copy of blockchain data for isolated testing.
///
/// Creates a full copy of the source blockchain in a temporary directory.
/// The copy is automatically cleaned up when this struct is dropped.
pub struct BlockchainCopy {
    /// The temporary directory containing the blockchain copy.
    /// Kept alive to prevent automatic cleanup until drop.
    _temp_dir: TempDir,
    /// Path to the blockchain data directory.
    datadir: PathBuf,
}

impl BlockchainCopy {
    /// Create a new blockchain copy by copying source data to a temporary directory.
    ///
    /// # Arguments
    /// * `source` - Path to the source blockchain directory (e.g., regtest-1000/)
    ///
    /// # Returns
    /// A `BlockchainCopy` with paths to the copied data.
    ///
    /// # Errors
    /// Returns an error if the source directory doesn't exist or if copying fails.
    pub fn new(source: &Path) -> io::Result<Self> {
        if !source.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Source blockchain directory not found: {:?}", source),
            ));
        }

        let temp_dir = TempDir::new()?;
        let datadir = temp_dir.path().to_path_buf();

        tracing::info!("Copying blockchain from {:?} to {:?}", source, datadir);

        copy_dir_recursive(source, &datadir)?;

        tracing::info!("Blockchain copy complete");

        Ok(Self {
            _temp_dir: temp_dir,
            datadir,
        })
    }

    /// Get the path to use as dashd's datadir.
    pub fn datadir(&self) -> &Path {
        &self.datadir
    }
}

/// Recursively copy a directory, skipping specified patterns.
fn copy_dir_recursive(src: &Path, dst: &Path) -> io::Result<()> {
    if !dst.exists() {
        fs::create_dir_all(dst)?;
    }

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let file_name_str = file_name.to_string_lossy();

        // Skip unwanted files
        if SKIP_PATTERNS.iter().any(|pattern| file_name_str.contains(pattern)) {
            tracing::debug!("Skipping: {:?}", file_name);
            continue;
        }

        let src_path = entry.path();
        let dst_path = dst.join(&file_name);

        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blockchain_copy_creates_temp_dir() {
        // Create a simple test directory structure
        let source = TempDir::new().unwrap();
        let source_path = source.path();

        // Create some test files
        fs::write(source_path.join("test.txt"), "test data").unwrap();
        fs::create_dir(source_path.join("subdir")).unwrap();
        fs::write(source_path.join("subdir/nested.txt"), "nested data").unwrap();

        // Also create a file that should be skipped
        fs::write(source_path.join(".cookie"), "should skip").unwrap();

        // Create blockchain copy
        let copy = BlockchainCopy::new(source_path).unwrap();

        // Verify files were copied
        assert!(copy.datadir().join("test.txt").exists());
        assert!(copy.datadir().join("subdir/nested.txt").exists());

        // Verify skipped files were not copied
        assert!(!copy.datadir().join(".cookie").exists());
    }

    #[test]
    fn test_blockchain_copy_error_on_missing_source() {
        let result = BlockchainCopy::new(Path::new("/nonexistent/path"));
        assert!(result.is_err());
    }
}
