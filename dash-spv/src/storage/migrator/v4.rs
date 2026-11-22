use std::fs;
use std::io;
use std::path::Path;

use async_trait::async_trait;

use super::{for_each_file_blocking, Migrator, MigratorError};
use crate::storage::io::atomic_write_blocking;

const SEGMENT_FOLDERS: [&str; 4] = ["block_headers", "filter_headers", "filters", "blocks"];
const SEGMENT_PREFIX: &str = "segment_";
const SEGMENT_EXTENSION: &str = ".dat";

/// Appends to every segment the blake3 hash of its items, which `Segment::load` checks.
pub struct V4Migrator;

#[async_trait]
impl Migrator for V4Migrator {
    async fn apply_migration(&self, storage_path: &Path) -> Result<(), MigratorError> {
        // Collected before writing, so a rewritten file is not listed again.
        let mut segments = Vec::new();
        for folder in SEGMENT_FOLDERS {
            let mut entries = match tokio::fs::read_dir(storage_path.join(folder)).await {
                Ok(entries) => entries,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };

            while let Some(entry) = entries.next_entry().await? {
                if entry.file_name().to_str().is_some_and(is_segment_file_name) {
                    segments.push(entry.path());
                }
            }
        }

        for_each_file_blocking(segments, |path| {
            let mut bytes = fs::read(&path)?;
            // A run that stopped before the version bump already wrote it.
            if has_checksum(&bytes) {
                return Ok(());
            }

            let checksum = blake3::hash(&bytes);
            bytes.extend_from_slice(checksum.as_bytes());
            atomic_write_blocking(&path, &bytes)?;
            Ok(())
        })
        .await
    }
}

fn is_segment_file_name(name: &str) -> bool {
    name.strip_prefix(SEGMENT_PREFIX)
        .and_then(|rest| rest.strip_suffix(SEGMENT_EXTENSION))
        .is_some_and(|id| id.parse::<u32>().is_ok())
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
    use dashcore::block::Header;
    use dashcore::consensus::Encodable;
    use tempfile::TempDir;

    use super::*;
    use crate::storage::io::ChecksummedFile;
    use crate::types::HashedBlockHeader;

    #[tokio::test]
    async fn test_v4_appends_checksum_once() {
        let temp_dir = TempDir::new().unwrap();
        let segment_path = temp_dir.path().join("block_headers").join("segment_000000.dat");

        let headers: Vec<HashedBlockHeader> =
            (0..3).map(|height| HashedBlockHeader::from(Header::dummy(height))).collect();
        let mut segment = Vec::new();
        for header in &headers {
            header.consensus_encode(&mut segment).unwrap();
        }
        fs::create_dir_all(segment_path.parent().unwrap()).unwrap();
        fs::write(&segment_path, segment).unwrap();

        for _ in 0..2 {
            V4Migrator.apply_migration(temp_dir.path()).await.unwrap();
        }

        let file = ChecksummedFile::<HashedBlockHeader>::new(&segment_path);
        assert_eq!(file.read().await.unwrap(), headers);
    }
}
