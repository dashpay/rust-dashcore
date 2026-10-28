use std::io;
use std::path::Path;

use async_trait::async_trait;

use super::{Migrator, MigratorError};

const MASTERNODES_DIR: &str = "masternodes";

/// Drops the masternode messages earlier versions stored. The storage now
/// keeps snapshots of the masternode list engine instead, so the first start
/// after the migration syncs the masternode lists from the network again.
pub struct V3Migrator;

#[async_trait]
impl Migrator for V3Migrator {
    async fn apply_migration(&self, storage_path: &Path) -> Result<(), MigratorError> {
        match tokio::fs::remove_dir_all(storage_path.join(MASTERNODES_DIR)).await {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            result => Ok(result?),
        }
    }
}
