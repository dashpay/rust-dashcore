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
