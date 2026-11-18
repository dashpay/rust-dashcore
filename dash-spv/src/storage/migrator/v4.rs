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

#[cfg(test)]
mod tests {
    use crate::storage::migrator::StorageMigrator;
    use serde_json::Value;
    use tempfile::TempDir;
    use test_case::test_case;
    use tokio::fs;

    #[test_case(true; "old snapshot")]
    #[test_case(false; "missing snapshot")]
    #[tokio::test]
    async fn should_remove_the_engine_snapshot(present: bool) {
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
        let version: Value =
            serde_json::from_slice(&fs::read(path.join("version.json")).await.unwrap()).unwrap();
        assert_eq!(version["version"], 4);
        assert_eq!(fs::read(path.join("headers.dat")).await.unwrap(), b"keep headers");
        fs::write(&snapshot, b"current engine snapshot").await.unwrap();
        StorageMigrator::migrate(&path).await.unwrap();
        assert_eq!(fs::read(&snapshot).await.unwrap(), b"current engine snapshot");
    }
}
