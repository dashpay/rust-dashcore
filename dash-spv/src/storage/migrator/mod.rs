mod v1;
mod v2;
mod v3;
mod v4;

use std::io;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::{StorageError, StorageResult};
use crate::storage::io::atomic_write;
use v1::V1Migrator;
use v2::V2Migrator;
use v3::V3Migrator;
use v4::V4Migrator;

pub const CURRENT_VERSION: u32 = 4;

#[async_trait]
trait Migrator {
    async fn apply_migration(&self, storage_path: &Path) -> Result<(), MigratorError>;
}

#[derive(Debug, thiserror::Error)]
enum MigratorError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error("{0}")]
    Corruption(String),
    // We cannot recover from this, errors in the storage system itself
    // E.g. atommic_write failing
    #[error(transparent)]
    Storage(#[from] StorageError),
}

impl From<MigratorError> for StorageError {
    fn from(e: MigratorError) -> Self {
        match e {
            MigratorError::Io(e) => StorageError::Io(e),
            MigratorError::Serde(e) => StorageError::Corruption(format!(
                "Storage is corrupted and cannot be recovered: {}",
                e
            )),
            MigratorError::Corruption(e) => StorageError::Corruption(e),
            MigratorError::Storage(e) => e,
        }
    }
}

pub struct StorageMigrator;

impl StorageMigrator {
    pub async fn migrate(storage_path: &PathBuf) -> StorageResult<()> {
        // First try, retry if corruption is detected, by clearing the storage and starting over
        let Err(e) = migration_loop(storage_path).await else {
            return Ok(());
        };

        match e {
            MigratorError::Io(error) => {
                return Err(StorageError::Io(error));
            }
            MigratorError::Storage(error) => {
                return Err(error);
            }
            MigratorError::Serde(_) | MigratorError::Corruption(_) => {
                // Corrupted storage, clear and start over
            }
        }

        tracing::warn!("Storage migration failed, clearing storage and starting over: {}", e);

        let mut entries = tokio::fs::read_dir(storage_path).await?;
        while let Some(entry) = entries.next_entry().await? {
            let file_type = entry.file_type().await?;

            // Skip logs directory, first storage versions persist logs
            // in the storage directory, but they are independent of our
            // storage system
            if file_type.is_dir() && entry.file_name() != "logs" {
                tokio::fs::remove_dir_all(entry.path()).await?;
            } else if file_type.is_file() {
                tokio::fs::remove_file(entry.path()).await?;
            }
        }

        // Now try again, this time it should succeed
        let Err(e) = migration_loop(storage_path).await else {
            return Ok(());
        };

        Err(e.into())
    }
}

async fn migration_loop(storage_path: &Path) -> Result<(), MigratorError> {
    #[derive(Deserialize, Serialize)]
    struct Version {
        version: u32,
    }

    let version_path = storage_path.join("version.json");

    let mut version = if version_path.exists() && version_path.is_file() {
        let bytes = tokio::fs::read(&version_path).await?;
        serde_json::from_slice::<Version>(&bytes)?.version
    } else {
        0
    };

    if version > CURRENT_VERSION {
        return Err(MigratorError::Corruption(format!(
            "Storage version {} is newer than current version {}",
            version, CURRENT_VERSION
        )));
    }

    while version < CURRENT_VERSION {
        tracing::info!("Migrating storage from version {} to {}", version, version + 1);

        const MIGRATORS: &[&dyn Migrator; CURRENT_VERSION as usize] =
            &[&V1Migrator, &V2Migrator, &V3Migrator, &V4Migrator];

        MIGRATORS[version as usize].apply_migration(storage_path).await?;

        version += 1;

        let version = serde_json::to_string_pretty(&Version {
            version,
        })?;

        atomic_write(&version_path, version.as_bytes()).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::StorageMigrator;
    use tempfile::TempDir;
    use test_case::test_case;
    use tokio::fs;

    #[test_case(true; "old snapshot")]
    #[test_case(false; "missing snapshot")]
    #[tokio::test]
    async fn storage_v3_discards_the_old_engine_snapshot(present: bool) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_path_buf();
        fs::write(path.join("version.json"), br#"{"version":3}"#).await.unwrap();
        fs::create_dir(path.join("masternodes")).await.unwrap();
        let snapshot = path.join("masternodes/engine.dat");
        if present {
            fs::write(&snapshot, b"old engine snapshot").await.unwrap();
        }
        fs::write(path.join("headers.dat"), b"keep headers").await.unwrap();
        StorageMigrator::migrate(&path).await.unwrap();
        assert!(!snapshot.exists());
        let version: serde_json::Value =
            serde_json::from_slice(&fs::read(path.join("version.json")).await.unwrap()).unwrap();
        assert_eq!(version["version"], 4);
        assert_eq!(fs::read(path.join("headers.dat")).await.unwrap(), b"keep headers");
        fs::write(&snapshot, b"current engine snapshot").await.unwrap();
        StorageMigrator::migrate(&path).await.unwrap();
        assert_eq!(fs::read(&snapshot).await.unwrap(), b"current engine snapshot");
    }
}
