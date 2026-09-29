mod v1;

use std::io;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::{StorageError, StorageResult};
use crate::storage::io::atomic_write;
use v1::V1Migrator;

pub const CURRENT_VERSION: u32 = 1;

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

        const MIGRATORS: &[&dyn Migrator; CURRENT_VERSION as usize] = &[&V1Migrator];

        MIGRATORS[version as usize].apply_migration(storage_path).await?;

        version += 1;

        let version = serde_json::to_string_pretty(&Version {
            version,
        })?;

        atomic_write(&version_path, version.as_bytes()).await?;
    }

    Ok(())
}
