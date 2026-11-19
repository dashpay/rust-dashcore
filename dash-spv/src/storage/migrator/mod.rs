mod v1;
mod v2;
mod v3;
mod v4;
mod v5;

use std::io;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::thread;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;

use crate::error::{StorageError, StorageResult};
use crate::storage::io::{atomic_write, ChecksummedFile};
use crate::storage::segments::{Persistable, SegmentCache};
use crate::types::{HashedBlock, HashedBlockHeader};
use dashcore::hash_types::FilterHeader;
use v1::V1Migrator;
use v2::V2Migrator;
use v3::V3Migrator;
use v4::V4Migrator;
use v5::V5Migrator;

pub const CURRENT_VERSION: u32 = 5;

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
    Storage(StorageError),
}

impl From<StorageError> for MigratorError {
    fn from(e: StorageError) -> Self {
        match e {
            StorageError::Corruption(e) => MigratorError::Corruption(e),
            e => MigratorError::Storage(e),
        }
    }
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
    let marker_path = storage_path.join("migration_in_progress");

    // Migrators skip `sync_all`, so files of an interrupted migration may be truncated.
    if marker_path.exists() {
        return Err(MigratorError::Corruption("A storage migration was interrupted".into()));
    }

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

    let migrating = version < CURRENT_VERSION;
    if migrating {
        atomic_write(&marker_path, &[]).await?;
    }

    while version < CURRENT_VERSION {
        tracing::info!("Migrating storage from version {} to {}", version, version + 1);

        const MIGRATORS: &[&dyn Migrator; CURRENT_VERSION as usize] =
            &[&V1Migrator, &V2Migrator, &V3Migrator, &V4Migrator, &V5Migrator];

        MIGRATORS[version as usize].apply_migration(storage_path).await?;

        version += 1;

        let version = serde_json::to_string_pretty(&Version {
            version,
        })?;

        atomic_write(&version_path, version.as_bytes()).await?;
    }

    if migrating {
        tokio::fs::remove_file(&marker_path).await?;
    }

    verify_segments(storage_path).await
}

async fn verify_segments(storage_path: &Path) -> Result<(), MigratorError> {
    verify_folder::<HashedBlockHeader>(&storage_path.join("block_headers")).await?;
    verify_folder::<FilterHeader>(&storage_path.join("filter_headers")).await?;
    verify_folder::<Vec<u8>>(&storage_path.join("filters")).await?;
    verify_folder::<HashedBlock>(&storage_path.join("blocks")).await
}

async fn verify_folder<I: Persistable>(folder: &Path) -> Result<(), MigratorError> {
    let mut entries = match tokio::fs::read_dir(folder).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };

    let mut segments = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        if entry.file_name().to_str().and_then(SegmentCache::<I>::parse_segment_id).is_some() {
            segments.push(entry.path());
        }
    }

    for_each_file_blocking(segments, |path| Ok(ChecksummedFile::<I>::new(path).verify_blocking()?))
        .await
}

/// Runs `f` on every path in `spawn_blocking`, with at most one task per core.
/// The limit bounds memory, since each task holds a whole file.
async fn for_each_file_blocking<F>(paths: Vec<PathBuf>, f: F) -> Result<(), MigratorError>
where
    F: Fn(PathBuf) -> Result<(), MigratorError> + Clone + Send + 'static,
{
    let limit = thread::available_parallelism().map_or(1, NonZeroUsize::get);
    let mut tasks = JoinSet::new();

    for path in paths {
        if tasks.len() >= limit {
            join_one(&mut tasks).await?;
        }
        let f = f.clone();
        tasks.spawn_blocking(move || f(path));
    }

    while !tasks.is_empty() {
        join_one(&mut tasks).await?;
    }

    Ok(())
}

async fn join_one(tasks: &mut JoinSet<Result<(), MigratorError>>) -> Result<(), MigratorError> {
    match tasks.join_next().await {
        Some(result) => result.map_err(io::Error::other)?,
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    #[tokio::test]
    async fn test_interrupted_migration_wipes_storage() {
        let temp_dir = TempDir::new().unwrap();
        let storage_path = temp_dir.path().to_path_buf();
        let marker_path = storage_path.join("migration_in_progress");
        let snapshot_path = storage_path.join("masternodes").join("engine.dat");

        StorageMigrator::migrate(&storage_path).await.unwrap();
        assert!(!marker_path.exists());

        fs::create_dir_all(snapshot_path.parent().unwrap()).unwrap();
        fs::write(&snapshot_path, b"snapshot").unwrap();
        fs::write(&marker_path, []).unwrap();
        StorageMigrator::migrate(&storage_path).await.unwrap();

        assert!(!snapshot_path.exists());
        assert!(!marker_path.exists());
    }
}
