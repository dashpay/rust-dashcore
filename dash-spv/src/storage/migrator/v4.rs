use std::io;
use std::path::Path;

use async_trait::async_trait;
use tokio::fs;

use super::{Migrator, MigratorError};

/// Removes snapshots whose cycles can contain quorums from another cycle.
pub(super) struct V4Migrator;

#[async_trait]
impl Migrator for V4Migrator {
    async fn apply_migration(&self, storage_path: &Path) -> Result<(), MigratorError> {
        match fs::remove_file(storage_path.join("masternodes/engine.dat")).await {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            result => Ok(result?),
        }
    }
}
