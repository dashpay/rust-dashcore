// TODO: This example needs to be updated as the reorganize() method was removed
// The reorganization logic is now handled internally by the SPV client
// and wallet state is managed through the WalletInterface

#![allow(dead_code)]

//! Demo showing that chain reorganization now works without borrow conflicts

// Temporarily disable this example
fn main() {
    println!("This example is temporarily disabled pending updates to use the new architecture");
}

#[cfg(skip_example)]
mod disabled_example {
    use dash_spv::chain::{ChainWork, Fork, ReorgManager};
    use dash_spv::storage::{MemoryStorageManager, StorageManager};
    use dash_spv::types::ChainState;
    use dashcore::{blockdata::constants::genesis_block, Header as BlockHeader, Network};
    use dashcore_hashes::Hash;
    use key_wallet_manager::spv_wallet_manager::SPVWalletManager;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn create_test_header(prev: &BlockHeader, nonce: u32) -> BlockHeader {
        let mut header = prev.clone();
        header.prev_blockhash = prev.block_hash();
        header.nonce = nonce;
        header.time = prev.time + 600; // 10 minutes later
        header
    }

    #[tokio::main]
    async fn main() -> Result<(), Box<dyn std::error::Error>> {
        println!("🔧 Chain Reorganization Demo - Testing Borrow Conflict Fix\n");

        // Create test components
        let network = Network::Dash;
        let genesis = genesis_block(network).header;
        let mut chain_state = ChainState::new_for_network(network);
        let wallet_manager = Arc::new(RwLock::new(SPVWalletManager::new()));
        let mut storage = MemoryStorageManager::new().await?;

        println!("📦 Building main chain: genesis -> block1 -> block2");

        // Build main chain: genesis -> block1 -> block2
        let block1 = create_test_header(&genesis, 1);
        let block2 = create_test_header(&block1, 2);

        // Store main chain
        storage.store_headers(&[genesis]).await?;
        storage.store_headers(&[block1]).await?;
        storage.store_headers(&[block2]).await?;

        // Update chain state
        chain_state.add_header(genesis);
        chain_state.add_header(block1);
        chain_state.add_header(block2);

        println!("✅ Main chain height: {}", chain_state.get_height());

        println!("\n📦 Building fork: genesis -> block1' -> block2' -> block3'");

        // Build fork chain: genesis -> block1' -> block2' -> block3'
        let block1_fork = create_test_header(&genesis, 100); // Different nonce
        let block2_fork = create_test_header(&block1_fork, 101);
        let block3_fork = create_test_header(&block2_fork, 102);

        // Create fork with more work
        let fork = Fork {
            fork_point: genesis.block_hash(),
            fork_height: 0, // Fork from genesis
            tip_hash: block3_fork.block_hash(),
            tip_height: 3,
            headers: vec![block1_fork, block2_fork, block3_fork],
            chain_work: ChainWork::from_bytes([255u8; 32]), // Maximum work
        };

        println!("✅ Fork chain height: {}", fork.tip_height);
        println!("✅ Fork has more work than main chain");

        println!("\n🔄 Attempting reorganization...");
        println!("   This previously failed with borrow conflict!");

        // Create reorg manager
        let reorg_manager = ReorgManager::new(100, false);

        // This should now work without borrow conflicts!
        // Note: reorganize now takes wallet as an Arc<RwLock<W>> where W: WalletInterface
        match reorg_manager
            .reorganize(&mut chain_state, wallet_manager.clone(), &fork, &mut storage)
            .await
        {
            Ok(event) => {
                println!("\n✅ Reorganization SUCCEEDED!");
                println!(
                    "   - Common ancestor: {} at height {}",
                    event.common_ancestor, event.common_height
                );
                println!("   - Disconnected {} headers", event.disconnected_headers.len());
                println!("   - Connected {} headers", event.connected_headers.len());
                println!("   - New chain height: {}", chain_state.get_height());

                // Verify new headers were stored
                let header_at_3 = storage.get_header(3).await?;
                if header_at_3.is_some() {
                    println!("\n✅ New chain tip verified in storage!");
                }

                println!("\n🎉 Borrow conflict has been resolved!");
                println!("   The reorganization now uses a phased approach:");
                println!("   1. Read phase: Collect all necessary data");
                println!("   2. Write phase: Apply changes using only StorageManager");
            }
            Err(e) => {
                println!("\n❌ Reorganization failed: {}", e);
                println!("   This suggests the borrow conflict still exists.");
            }
        }

        Ok(())
    }
} // end of disabled_example module
