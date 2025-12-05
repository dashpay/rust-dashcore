//! Low-level I/O utilities for reading and writing segment files.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::BufReader;
use std::path::Path;

use dashcore::{
    block::Header as BlockHeader,
    consensus::{encode, Decodable},
    hash_types::FilterHeader,
    BlockHash,
};

use crate::error::{StorageError, StorageResult};

/// Load headers from file.
pub(super) async fn load_headers_from_file(path: &Path) -> StorageResult<Vec<BlockHeader>> {
    tokio::task::spawn_blocking({
        let path = path.to_path_buf();
        move || {
            let file = File::open(&path)?;
            let mut reader = BufReader::new(file);
            let mut headers = Vec::new();

            loop {
                match BlockHeader::consensus_decode(&mut reader) {
                    Ok(header) => headers.push(header),
                    Err(encode::Error::Io(ref e))
                        if e.kind() == std::io::ErrorKind::UnexpectedEof =>
                    {
                        break
                    }
                    Err(e) => {
                        return Err(StorageError::ReadFailed(format!(
                            "Failed to decode header: {}",
                            e
                        )))
                    }
                }
            }

            Ok(headers)
        }
    })
    .await
    .map_err(|e| StorageError::ReadFailed(format!("Task join error: {}", e)))?
}

/// Load filter headers from file.
pub(super) async fn load_filter_headers_from_file(path: &Path) -> StorageResult<Vec<FilterHeader>> {
    tokio::task::spawn_blocking({
        let path = path.to_path_buf();
        move || {
            let file = File::open(&path)?;
            let mut reader = BufReader::new(file);
            let mut headers = Vec::new();

            loop {
                match FilterHeader::consensus_decode(&mut reader) {
                    Ok(header) => headers.push(header),
                    Err(encode::Error::Io(ref e))
                        if e.kind() == std::io::ErrorKind::UnexpectedEof =>
                    {
                        break
                    }
                    Err(e) => {
                        return Err(StorageError::ReadFailed(format!(
                            "Failed to decode filter header: {}",
                            e
                        )))
                    }
                }
            }

            Ok(headers)
        }
    })
    .await
    .map_err(|e| StorageError::ReadFailed(format!("Task join error: {}", e)))?
}

/// Load index from file.
pub(super) async fn load_index_from_file(path: &Path) -> StorageResult<HashMap<BlockHash, u32>> {
    tokio::task::spawn_blocking({
        let path = path.to_path_buf();
        move || {
            let content = fs::read(&path)?;
            bincode::deserialize(&content).map_err(|e| {
                StorageError::ReadFailed(format!("Failed to deserialize index: {}", e))
            })
        }
    })
    .await
    .map_err(|e| StorageError::ReadFailed(format!("Task join error: {}", e)))?
}

/// Save index to disk.
pub(super) async fn save_index_to_disk(
    path: &Path,
    index: &HashMap<BlockHash, u32>,
) -> StorageResult<()> {
    tokio::task::spawn_blocking({
        let path = path.to_path_buf();
        let index = index.clone();
        move || {
            let data = bincode::serialize(&index).map_err(|e| {
                StorageError::WriteFailed(format!("Failed to serialize index: {}", e))
            })?;
            fs::write(&path, data)?;
            Ok(())
        }
    })
    .await
    .map_err(|e| StorageError::WriteFailed(format!("Task join error: {}", e)))?
}
