use std::io;
use std::path::Path;

use async_trait::async_trait;

use super::{Migrator, MigratorError};
use crate::storage::io::atomic_write;

const SNAPSHOT_PATH: &str = "masternodes/engine.dat";

/// Appends to the masternode engine snapshot the blake3 hash of its bytes.
pub struct V5Migrator;

#[async_trait]
impl Migrator for V5Migrator {
    async fn apply_migration(&self, storage_path: &Path) -> Result<(), MigratorError> {
        let path = storage_path.join(SNAPSHOT_PATH);

        let mut bytes = match tokio::fs::read(&path).await {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };

        // A run that stopped before the version bump already wrote it.
        if has_checksum(&bytes) {
            return Ok(());
        }

        let checksum = blake3::hash(&bytes);
        bytes.extend_from_slice(checksum.as_bytes());
        atomic_write(&path, &bytes).await?;

        Ok(())
    }
}

/// Whether `bytes` end in the blake3 hash of the bytes before it.
fn has_checksum(bytes: &[u8]) -> bool {
    bytes.len().checked_sub(blake3::OUT_LEN).is_some_and(|split| {
        let (data, checksum) = bytes.split_at(split);
        blake3::hash(data).as_bytes() == checksum
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;
    use crate::storage::io::ChecksummedFile;

    #[tokio::test]
    async fn test_v5_appends_checksum_once() {
        let temp_dir = TempDir::new().unwrap();
        let snapshot_path = temp_dir.path().join(SNAPSHOT_PATH);

        fs::create_dir_all(snapshot_path.parent().unwrap()).unwrap();
        fs::write(&snapshot_path, b"snapshot").unwrap();

        for _ in 0..2 {
            V5Migrator.apply_migration(temp_dir.path()).await.unwrap();
        }

        let file = ChecksummedFile::<u8>::new(&snapshot_path);
        assert_eq!(file.read_bytes().await.unwrap(), b"snapshot");
    }
}
