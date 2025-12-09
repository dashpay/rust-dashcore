//! Filter storage operations for DiskStorageManager.

use crate::error::StorageResult;

use super::io::atomic_write;
use super::manager::DiskStorageManager;

impl DiskStorageManager {
    /// Store a compact filter.
    pub async fn store_filter(&mut self, height: u32, filter: &[u8]) -> StorageResult<()> {
        let path = self.base_path.join(format!("filters/{}.dat", height));
        atomic_write(&path, filter).await
    }

    /// Load a compact filter.
    pub async fn load_filter(&self, height: u32) -> StorageResult<Option<Vec<u8>>> {
        let path = self.base_path.join(format!("filters/{}.dat", height));
        if !path.exists() {
            return Ok(None);
        }

        let data = tokio::fs::read(path).await?;
        Ok(Some(data))
    }

    /// Clear all filter data.
    pub async fn clear_filters(&mut self) -> StorageResult<()> {
        // Stop worker to prevent concurrent writes to filter directories
        self.stop_worker().await;

        // Clear in-memory and on-disk filter headers segments
        self.filter_headers.write().await.clear_all().await?;

        // Remove on-disk compact filter files
        let filters_dir = self.base_path.join("filters");
        if filters_dir.exists() {
            tokio::fs::remove_dir_all(&filters_dir).await?;
        }
        tokio::fs::create_dir_all(&filters_dir).await?;

        // Restart background worker for future operations
        self.start_worker().await;

        Ok(())
    }
}
