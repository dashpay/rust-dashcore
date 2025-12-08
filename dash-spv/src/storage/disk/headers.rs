//! Header storage operations for DiskStorageManager.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use dashcore::block::Header as BlockHeader;
use dashcore::BlockHash;

use crate::error::StorageResult;
use crate::StorageError;

use super::manager::DiskStorageManager;

impl DiskStorageManager {
    /// Store headers with optional precomputed hashes for performance optimization.
    ///
    /// This is a performance optimization for hot paths that have already computed header hashes.
    /// When called from header sync with CachedHeader wrappers, passing precomputed hashes avoids
    /// recomputing the expensive X11 hash for indexing (saves ~35% of CPU during sync).
    pub async fn store_headers_internal(&mut self, headers: &[BlockHeader]) -> StorageResult<()> {
        let hashes = headers.iter().map(|header| header.block_hash()).collect::<Vec<_>>();

        let mut height = if let Some(height) = self.active_segments.read().await.tip_height() {
            height + 1
        } else {
            0
        };

        self.active_segments.write().await.store_headers(headers, self).await?;

        // Update reverse index
        let mut reverse_index = self.header_hash_index.write().await;

        for hash in hashes {
            reverse_index.insert(hash, height);
            height += 1;
        }

        // Release locks before saving (to avoid deadlocks during background saves)
        drop(reverse_index);

        Ok(())
    }

    /// Get header height by hash.
    pub async fn get_header_height_by_hash(&self, hash: &BlockHash) -> StorageResult<Option<u32>> {
        Ok(self.header_hash_index.read().await.get(hash).copied())
    }
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
