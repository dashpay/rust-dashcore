//! Filter re-checking operations for gap limit changes

use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::sync::filters::recheck::RecheckRange;
use crate::sync::sequential::SequentialSyncManager;
use dashcore::BlockHash;
use key_wallet_manager::wallet_interface::WalletInterface;

impl<
        S: StorageManager + Send + Sync + 'static,
        N: NetworkManager + Send + Sync + 'static,
        W: WalletInterface,
    > SequentialSyncManager<S, N, W>
{
    /// Re-check compact filters for a given range of heights
    ///
    /// This is called when gap limits change during block processing.
    /// It re-checks previously evaluated filters with the new, larger set of addresses.
    ///
    /// Returns a list of (block_hash, height) pairs for blocks that match the updated address set.
    pub(super) async fn recheck_filters_for_range(
        &mut self,
        storage: &S,
        _network: &mut N,
        range: &RecheckRange,
    ) -> SyncResult<Vec<(BlockHash, u32)>> {
        let mut new_matches = Vec::new();

        tracing::debug!(
            "Re-checking filters for range {}-{} with updated address set",
            range.start,
            range.end
        );

        // Lock wallet once for the entire range
        let mut wallet = self.wallet.write().await;

        // Iterate through the height range
        for height in range.start..=range.end {
            // Get the block hash for this height
            let header = match storage.get_header(height).await {
                Ok(Some(header)) => header,
                Ok(None) => {
                    tracing::debug!("No header at height {}, skipping", height);
                    continue;
                }
                Err(e) => {
                    tracing::warn!("Failed to get header at height {}: {}", height, e);
                    continue;
                }
            };

            let block_hash = header.block_hash();

            // Get the compact filter for this height
            let filter_data = match storage.load_filter(height).await {
                Ok(Some(data)) => data,
                Ok(None) => {
                    tracing::debug!("No filter at height {}, skipping", height);
                    continue;
                }
                Err(e) => {
                    tracing::warn!("Failed to load filter at height {}: {}", height, e);
                    continue;
                }
            };

            // Create BlockFilter from raw data (pass as slice)
            let filter = dashcore::bip158::BlockFilter::new(&filter_data[..]);

            // Check filter with wallet's CURRENT (updated) address set
            let matches =
                wallet.check_compact_filter(&filter, &block_hash, self.config.network).await;

            if matches {
                tracing::info!(
                    "🎯 Filter re-check found new match at height {} (block {})",
                    height,
                    block_hash
                );
                new_matches.push((block_hash, height));
            }
        }

        drop(wallet);

        if !new_matches.is_empty() {
            tracing::info!(
                "Re-check complete: Found {} new matches in range {}-{}",
                new_matches.len(),
                range.start,
                range.end
            );
        } else {
            tracing::debug!(
                "Re-check complete: No new matches in range {}-{}",
                range.start,
                range.end
            );
        }

        Ok(new_matches)
    }
}
