use std::path::Path;

use async_trait::async_trait;

use super::{Migrator, MigratorError};

pub struct V1Migrator;

#[async_trait]
impl Migrator for V1Migrator {
    async fn apply_migration(&self, _storage_path: &Path) -> Result<(), MigratorError> {
        // There is no migration to apply for this version
        // This is the first migrator after implementing the Migration system

        Ok(())
    }
}
