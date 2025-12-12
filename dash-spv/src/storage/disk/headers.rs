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
    pub async fn store_headers_at_height(
        &mut self,
        headers: &[BlockHeader],
        mut height: u32,
    ) -> StorageResult<()> {
        let hashes = headers.iter().map(|header| header.block_hash()).collect::<Vec<_>>();

        self.block_headers.write().await.store_items_at_height(headers, height, self).await?;

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

    pub async fn store_headers(&mut self, headers: &[BlockHeader]) -> StorageResult<()> {
        let height = self.block_headers.read().await.next_height();
        self.store_headers_at_height(headers, height).await
    }

    /// Get header height by hash.
    pub async fn get_header_height_by_hash(&self, hash: &BlockHash) -> StorageResult<Option<u32>> {
        Ok(self.header_hash_index.read().await.get(hash).copied())
    }
}

/// Load index from file, if it fails it tries to build it from block
/// header segments and, if that also fails, it return an empty index.
///
/// IO and deserialize errors are returned, the empty index is only built
/// if there is no persisted data to recreate it.
pub(super) async fn load_block_index(
    manager: &DiskStorageManager,
) -> StorageResult<HashMap<BlockHash, u32>> {
    let index_path = manager.base_path.join("headers/index.dat");

    if let Ok(content) = tokio::fs::read(&index_path).await {
        bincode::deserialize(&content)
            .map_err(|e| StorageError::ReadFailed(format!("Failed to deserialize index: {}", e)))
    } else {
        manager.block_headers.write().await.build_block_index_from_segments().await
    }
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
