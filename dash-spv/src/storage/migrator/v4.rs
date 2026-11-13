use std::io;
use std::path::Path;

use async_trait::async_trait;

use super::{Migrator, MigratorError};
use crate::storage::io::atomic_write;

const SEGMENT_FOLDERS: [&str; 4] = ["block_headers", "filter_headers", "filters", "blocks"];
const SEGMENT_PREFIX: &str = "segment_";
const SEGMENT_EXTENSION: &str = ".dat";

/// Appends to every segment the blake3 hash of its items, which `Segment::load` checks.
pub struct V4Migrator;

#[async_trait]
impl Migrator for V4Migrator {
    async fn apply_migration(&self, storage_path: &Path) -> Result<(), MigratorError> {
        for folder in SEGMENT_FOLDERS {
            let mut entries = match tokio::fs::read_dir(storage_path.join(folder)).await {
                Ok(entries) => entries,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };

            // Collected before writing, so a rewritten file is not listed again.
            let mut segments = Vec::new();
            while let Some(entry) = entries.next_entry().await? {
                if entry.file_name().to_str().is_some_and(is_segment_file_name) {
                    segments.push(entry.path());
                }
            }

            for path in segments {
                let mut bytes = tokio::fs::read(&path).await?;
                let checksum = blake3::hash(&bytes);
                bytes.extend_from_slice(checksum.as_bytes());
                atomic_write(&path, &bytes).await?;
            }
        }

        Ok(())
    }
}

fn is_segment_file_name(name: &str) -> bool {
    name.strip_prefix(SEGMENT_PREFIX)
        .and_then(|rest| rest.strip_suffix(SEGMENT_EXTENSION))
        .is_some_and(|id| id.parse::<u32>().is_ok())
}
