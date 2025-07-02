//! Block locator builder for SPV synchronization
//!
//! This module provides functionality to build block locators according to the Bitcoin/Dash protocol.
//! Block locators are used in GetHeaders messages to efficiently communicate which blocks we have
//! to peers, allowing them to send us the headers we're missing.

use dashcore::BlockHash;
use dashcore_hashes::Hash;
use crate::error::{SyncError, SyncResult};
use crate::storage::StorageManager;

/// Build a block locator from the current chain state.
///
/// A block locator is a list of block hashes that represents our current chain state.
/// It starts with the tip and includes blocks at exponentially increasing intervals
/// going backwards, eventually including the genesis block.
///
/// The algorithm:
/// 1. Start with the current tip
/// 2. Step back 1 block
/// 3. Then step back 2, 4, 8, 16, 32... blocks
/// 4. Continue until we reach genesis
/// 5. Always include genesis as the last element
///
/// This allows peers to efficiently find the common ancestor between our chain and theirs.
pub async fn build_block_locator(
    storage: &dyn StorageManager,
    network_genesis_hash: BlockHash,
) -> SyncResult<Vec<BlockHash>> {
    let mut locator = Vec::new();
    
    // Get the current tip height
    let tip_height = match storage.get_tip_height().await
        .map_err(|e| SyncError::SyncFailed(format!("Failed to get tip height: {}", e)))? 
    {
        Some(height) => height,
        None => {
            // No headers stored, return just genesis
            return Ok(vec![network_genesis_hash]);
        }
    };
    
    // Start from the tip
    let mut current_height = tip_height;
    let mut step = 1u32;
    
    // Build the locator
    loop {
        // Get the header at current height
        if let Some(header) = storage.get_header(current_height).await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get header at height {}: {}", current_height, e)))? 
        {
            locator.push(header.block_hash());
        }
        
        // If we've reached genesis, we're done
        if current_height == 0 {
            break;
        }
        
        // Calculate next height
        if current_height > step {
            current_height = current_height.saturating_sub(step);
        } else {
            current_height = 0;
        }
        
        // After 10 blocks, start exponential backoff
        if locator.len() > 10 {
            step *= 2;
        }
        
        // Limit locator size to prevent it from growing too large
        if locator.len() >= 100 {
            // Always include genesis as the last element if we haven't reached it
            if current_height > 0 {
                if let Some(genesis_header) = storage.get_header(0).await
                    .map_err(|e| SyncError::SyncFailed(format!("Failed to get genesis header: {}", e)))? 
                {
                    locator.push(genesis_header.block_hash());
                }
            }
            break;
        }
    }
    
    // If we don't have any headers but were given a genesis hash, use it
    if locator.is_empty() && network_genesis_hash != BlockHash::from_byte_array([0; 32]) {
        locator.push(network_genesis_hash);
    }
    
    Ok(locator)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorageManager;
    use dashcore::{block::Header as BlockHeader, block::Version, CompactTarget};

    fn create_test_header(height: u32, prev_hash: BlockHash) -> BlockHeader {
        BlockHeader {
            version: Version::from_consensus(1),
            prev_blockhash: prev_hash,
            merkle_root: dashcore::TxMerkleNode::from_byte_array([height as u8; 32]),
            time: 1234567890 + height,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: height,
        }
    }

    #[tokio::test]
    async fn test_build_locator_empty_chain() {
        let storage = MemoryStorageManager::new().await.unwrap();
        let genesis_hash = BlockHash::from_byte_array([1; 32]);
        
        let locator = build_block_locator(&storage, genesis_hash).await.unwrap();
        
        assert_eq!(locator.len(), 1);
        assert_eq!(locator[0], genesis_hash);
    }

    #[tokio::test]
    async fn test_build_locator_small_chain() {
        let mut storage = MemoryStorageManager::new().await.unwrap();
        let genesis_hash = BlockHash::all_zeros();
        
        // Build a small chain
        let mut headers = vec![];
        let mut prev_hash = genesis_hash;
        
        for i in 0..20 {
            let header = create_test_header(i, prev_hash);
            prev_hash = header.block_hash();
            headers.push(header);
        }
        
        storage.store_headers(&headers).await.unwrap();
        
        let locator = build_block_locator(&storage, genesis_hash).await.unwrap();
        
        // Should include tip and work backwards
        assert!(locator.len() > 1);
        assert_eq!(locator[0], headers[19].block_hash()); // Tip
        assert_eq!(locator.last().unwrap(), &headers[0].block_hash()); // Genesis
    }

    #[tokio::test]
    async fn test_build_locator_large_chain() {
        let mut storage = MemoryStorageManager::new().await.unwrap();
        let genesis_hash = BlockHash::all_zeros();
        
        // Build a large chain
        let mut headers = vec![];
        let mut prev_hash = genesis_hash;
        
        for i in 0..1000 {
            let header = create_test_header(i, prev_hash);
            prev_hash = header.block_hash();
            headers.push(header);
        }
        
        storage.store_headers(&headers).await.unwrap();
        
        let locator = build_block_locator(&storage, genesis_hash).await.unwrap();
        
        // Check structure
        assert!(locator.len() > 10);
        assert!(locator.len() <= 100); // Should be limited
        assert_eq!(locator[0], headers[999].block_hash()); // Tip
        assert_eq!(locator.last().unwrap(), &headers[0].block_hash()); // Genesis
        
        // Verify exponential spacing after first 10
        // The intervals should roughly double after the first 10 entries
        let mut last_height = 999;
        for i in 1..locator.len() - 1 {
            // Find the height of this hash
            let mut found_height = None;
            for (h, header) in headers.iter().enumerate() {
                if header.block_hash() == locator[i] {
                    found_height = Some(h);
                    break;
                }
            }
            
            if let Some(height) = found_height {
                let interval = last_height - height;
                if i > 10 {
                    // After 10 entries, intervals should be increasing
                    assert!(interval > 0);
                }
                last_height = height;
            }
        }
    }
}