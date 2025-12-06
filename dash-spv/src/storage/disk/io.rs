//! Low-level I/O utilities for reading and writing segment files.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use dashcore::BlockHash;

use crate::error::{StorageError, StorageResult};

/// Get the temporary file path for atomic writes.
/// Uses process ID and a counter to ensure uniqueness even with concurrent writes.
fn get_temp_path(path: &Path) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let mut temp_path = path.to_path_buf();
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("temp");
    let unique_id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    temp_path.set_file_name(format!(".{}.{}.{}.tmp", file_name, pid, unique_id));
    temp_path
}

/// Atomically write data to a file.
/// Uses temporary file + sync + rename pattern for crash resilience.
pub(crate) async fn atomic_write(path: &Path, data: &[u8]) -> StorageResult<()> {
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| StorageError::WriteFailed(format!("Failed to create directory: {}", e)))?;
    }

    let temp_path = get_temp_path(path);

    // Write to temporary file
    let write_result = async {
        tokio::fs::write(&temp_path, data).await?;

        // Sync to disk - open the file and call sync_all
        let file = tokio::fs::File::open(&temp_path).await?;
        file.sync_all().await?;

        Ok::<(), std::io::Error>(())
    }
    .await;

    // Clean up temp file on error
    if let Err(e) = write_result {
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(StorageError::WriteFailed(format!("Failed to write temp file: {}", e)));
    }

    // Atomic rename
    if let Err(e) = tokio::fs::rename(&temp_path, path).await {
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(StorageError::WriteFailed(format!("Failed to rename temp file: {}", e)));
    }

    Ok(())
}

/// Load index from file.
pub(super) async fn load_index_from_file(path: &Path) -> StorageResult<HashMap<BlockHash, u32>> {
    tokio::task::spawn_blocking({
        let path = path.to_path_buf();
        move || {
            let content = fs::read(&path)?;
            bincode::deserialize(&content).map_err(|e| {
                StorageError::ReadFailed(format!("Failed to deserialize index: {}", e))
            })
        }
    })
    .await
    .map_err(|e| StorageError::ReadFailed(format!("Task join error: {}", e)))?
}

/// Save index to disk.
pub(super) async fn save_index_to_disk(
    path: &Path,
    index: &HashMap<BlockHash, u32>,
) -> StorageResult<()> {
    let data = bincode::serialize(index)
        .map_err(|e| StorageError::WriteFailed(format!("Failed to serialize index: {}", e)))?;

    atomic_write(path, &data).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_get_temp_path_uniqueness() {
        let path = Path::new("some").join("path").join("file.dat");

        let temp1 = get_temp_path(&path);
        let temp2 = get_temp_path(&path);

        assert_ne!(temp1, temp2, "Each call should produce a unique temp path");

        // Check temp file is in same directory as original
        assert_eq!(temp1.parent(), path.parent());

        // Check temp file name starts with dot and ends with .tmp
        let file_name = temp1.file_name().unwrap().to_string_lossy();
        assert!(file_name.starts_with(".file.dat."));
        assert!(file_name.ends_with(".tmp"));
    }

    #[tokio::test]
    async fn test_atomic_write_creates_file() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("test.dat");

        let content = b"hello world";
        atomic_write(&path, content).await.unwrap();

        assert!(path.exists());
        let read_content = tokio::fs::read(&path).await.unwrap();
        assert_eq!(read_content, content);
    }

    #[tokio::test]
    async fn test_atomic_write_creates_parent_directories() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("nested").join("dirs").join("test.dat");

        let content = b"nested content";
        atomic_write(&path, content).await.unwrap();

        assert!(path.exists());
        let read_content = tokio::fs::read(&path).await.unwrap();
        assert_eq!(read_content, content);
    }

    #[tokio::test]
    async fn test_atomic_write_overwrites_existing() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("test.dat");

        // Write initial content
        tokio::fs::write(&path, b"initial").await.unwrap();

        // Overwrite with atomic write
        let new_content = b"new content";
        atomic_write(&path, new_content).await.unwrap();

        let read_content = tokio::fs::read(&path).await.unwrap();
        assert_eq!(read_content, new_content);
    }

    #[tokio::test]
    async fn test_atomic_write_no_temp_file_on_success() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("test.dat");

        atomic_write(&path, b"data").await.unwrap();

        // Check no .tmp files remain
        let mut entries = tokio::fs::read_dir(temp_dir.path()).await.unwrap();
        let mut tmp_files = Vec::new();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            if entry.file_name().to_string_lossy().ends_with(".tmp") {
                tmp_files.push(entry.file_name());
            }
        }

        assert!(tmp_files.is_empty(), "No temp files should remain after successful write");
    }

    #[tokio::test]
    async fn test_atomic_write_preserves_original_on_error() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("test.dat");

        // Write initial content
        let original = b"original content";
        tokio::fs::write(&path, original).await.unwrap();

        // Try to write to an invalid path (directory instead of file)
        let invalid_path = temp_dir.path().join("test.dat").join("invalid");

        let result = atomic_write(&invalid_path, b"new content").await;
        assert!(result.is_err());

        // Original file should still have original content
        let read_content = tokio::fs::read(&path).await.unwrap();
        assert_eq!(read_content, original);
    }

    #[tokio::test]
    async fn test_atomic_write_cleans_up_temp_on_error() {
        let temp_dir = TempDir::new().unwrap();

        // Create a file that will block directory creation
        let blocker_path = temp_dir.path().join("blocker");
        tokio::fs::write(&blocker_path, b"I am a file").await.unwrap();

        // Try to write to a path where parent "directory" is actually a file
        let invalid_path = blocker_path.join("subdir").join("file.dat");

        let result = atomic_write(&invalid_path, b"data").await;
        assert!(result.is_err());

        // No temp files should remain in the base temp dir
        let entries: Vec<_> = fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();

        assert!(entries.is_empty(), "No temp files should remain after failed write");
    }

    #[tokio::test]
    async fn test_atomic_write_binary_data() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("binary.dat");

        // Write binary data with null bytes and various byte values
        let binary_data: Vec<u8> = (0u8..=255).collect();
        atomic_write(&path, &binary_data).await.unwrap();

        let read_content = tokio::fs::read(&path).await.unwrap();
        assert_eq!(read_content, binary_data);
    }

    #[tokio::test]
    async fn test_atomic_write_large_data() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("large.dat");

        // Write 1MB of data
        let large_data: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
        atomic_write(&path, &large_data).await.unwrap();

        let read_content = tokio::fs::read(&path).await.unwrap();
        assert_eq!(read_content.len(), large_data.len());
        assert_eq!(read_content, large_data);
    }

    #[tokio::test]
    async fn test_atomic_write_cleans_up_temp_on_rename_failure() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("target.dat");

        // Create a directory at the target path - rename will fail because
        // you cannot rename a file over an existing directory
        tokio::fs::create_dir(&path).await.unwrap();

        let result = atomic_write(&path, b"data").await;
        assert!(result.is_err());

        // The target directory should still exist
        assert!(path.exists());
        assert!(path.is_dir());

        // No temp files should remain
        let entries: Vec<_> = fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();

        assert!(
            entries.is_empty(),
            "No temp files should remain after rename failure, found: {:?}",
            entries.iter().map(|e| e.file_name()).collect::<Vec<_>>()
        );
    }
}
