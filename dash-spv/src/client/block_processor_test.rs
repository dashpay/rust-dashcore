//! Unit tests for block processing functionality

#[cfg(test)]
mod tests {
    use crate::client::block_processor::{BlockProcessingTask, BlockProcessor};
    use crate::error::SpvError;
    use crate::storage::memory::MemoryStorageManager;
    use crate::types::{SpvEvent, SpvStats, WatchItem};
    use dashcore::{
        blockdata::constants::genesis_block, consensus::encode::serialize, hash_types::FilterHash,
        Address, Block, Network, Transaction,
    };
    use std::str::FromStr;
    use std::sync::Arc;
    use tokio::sync::{mpsc, Mutex, RwLock};

    // Mock WalletInterface implementation for testing
    struct MockWallet {
        network: Network,
        processed_blocks: Arc<Mutex<Vec<(dashcore::BlockHash, u32)>>>,
        processed_transactions: Arc<Mutex<Vec<dashcore::Txid>>>,
    }

    impl MockWallet {
        fn new(network: Network) -> Self {
            Self {
                network,
                processed_blocks: Arc::new(Mutex::new(Vec::new())),
                processed_transactions: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    #[async_trait::async_trait]
    impl key_wallet_manager::wallet_interface::WalletInterface for MockWallet {
        async fn process_block(&mut self, block: &Block, height: u32) -> Vec<dashcore::Txid> {
            let mut processed = self.processed_blocks.lock().await;
            processed.push((block.block_hash(), height));

            // Return txids of all transactions in block as "relevant"
            block.txdata.iter().map(|tx| tx.txid()).collect()
        }

        async fn process_mempool_transaction(&mut self, tx: &Transaction) {
            let mut processed = self.processed_transactions.lock().await;
            processed.push(tx.txid());
        }

        async fn handle_reorg(&mut self, _from_height: u32, _to_height: u32) {
            // Not tested here
        }

        async fn check_compact_filter(
            &self,
            _filter: &[u8],
            _block_hash: &dashcore::BlockHash,
        ) -> bool {
            // Return true for all filters in test
            true
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    fn create_test_block(network: Network) -> Block {
        genesis_block(network)
    }

    async fn setup_processor() -> (
        BlockProcessor,
        mpsc::UnboundedSender<BlockProcessingTask>,
        mpsc::UnboundedReceiver<SpvEvent>,
        Arc<RwLock<Box<dyn key_wallet_manager::wallet_interface::WalletInterface>>>,
        Arc<Mutex<Box<dyn crate::storage::StorageManager>>>,
    ) {
        let (task_tx, task_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let stats = Arc::new(RwLock::new(SpvStats::default()));
        let wallet = MockWallet::new(Network::Dash);
        let wallet: Arc<RwLock<Box<dyn key_wallet_manager::wallet_interface::WalletInterface>>> =
            Arc::new(RwLock::new(Box::new(wallet)));
        let storage = Arc::new(Mutex::new(Box::new(MemoryStorageManager::new().await.unwrap())
            as Box<dyn crate::storage::StorageManager>));

        let processor =
            BlockProcessor::new(task_rx, event_tx, stats, wallet.clone(), storage.clone());

        (processor, task_tx, event_rx, wallet, storage)
    }

    #[tokio::test]
    async fn test_process_block() {
        let (mut processor, task_tx, mut event_rx, wallet, storage) = setup_processor().await;

        // Create a test block
        let block = create_test_block(Network::Dash);
        let block_hash = block.block_hash();
        let serialized = serialize(&block);

        // Store a header for the block first
        {
            let mut storage = storage.lock().await;
            storage.store_headers(&[block.header]).await.unwrap();
        }

        // Send block processing task
        task_tx
            .send(BlockProcessingTask::ProcessBlock {
                block_hash,
                block_data: serialized,
            })
            .unwrap();

        // Process the block in a separate task
        let processor_handle = tokio::spawn(async move { processor.run().await });

        // Wait for event
        tokio::time::timeout(std::time::Duration::from_millis(100), async {
            while let Some(event) = event_rx.recv().await {
                if let SpvEvent::BlockProcessed {
                    hash,
                    ..
                } = event
                {
                    assert_eq!(hash, block_hash);
                    break;
                }
            }
        })
        .await
        .expect("Should receive block processed event");

        // Verify wallet was called
        {
            let wallet = wallet.read().await;
            let mock_wallet = wallet.as_any().downcast_ref::<MockWallet>().unwrap();
            let processed = mock_wallet.processed_blocks.lock().await;
            assert_eq!(processed.len(), 1);
            assert_eq!(processed[0].0, block_hash);
        }

        // Shutdown
        drop(task_tx);
        let _ = processor_handle.await;
    }

    #[tokio::test]
    async fn test_process_compact_filter() {
        let (mut processor, task_tx, mut event_rx, wallet, _storage) = setup_processor().await;

        let block_hash = create_test_block(Network::Dash).block_hash();
        let filter_data = vec![1, 2, 3, 4, 5]; // Mock filter data

        // Send filter processing task
        task_tx
            .send(BlockProcessingTask::ProcessCompactFilter {
                block_hash,
                filter_data: filter_data.clone(),
            })
            .unwrap();

        // Process in a separate task
        let processor_handle = tokio::spawn(async move { processor.run().await });

        // Wait for event
        tokio::time::timeout(std::time::Duration::from_millis(100), async {
            while let Some(event) = event_rx.recv().await {
                if let SpvEvent::CompactFilterMatched {
                    hash,
                    ..
                } = event
                {
                    assert_eq!(hash, block_hash);
                    break;
                }
            }
        })
        .await
        .expect("Should receive filter matched event");

        // Verify wallet check_compact_filter was called (returns true in mock)
        // The event being received confirms it was called

        // Shutdown
        drop(task_tx);
        let _ = processor_handle.await;
    }

    #[tokio::test]
    async fn test_process_mempool_transaction() {
        let (mut processor, task_tx, mut event_rx, wallet, _storage) = setup_processor().await;

        // Create a test transaction
        let block = create_test_block(Network::Dash);
        let tx = block.txdata[0].clone();
        let txid = tx.txid();

        // Send mempool transaction task
        task_tx.send(BlockProcessingTask::ProcessMempoolTransaction(tx.clone())).unwrap();

        // Process in a separate task
        let processor_handle = tokio::spawn(async move { processor.run().await });

        // Wait a bit for processing
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Verify wallet was called
        {
            let wallet = wallet.read().await;
            let mock_wallet = wallet.as_any().downcast_ref::<MockWallet>().unwrap();
            let processed = mock_wallet.processed_transactions.lock().await;
            assert_eq!(processed.len(), 1);
            assert_eq!(processed[0], txid);
        }

        // Shutdown
        drop(task_tx);
        let _ = processor_handle.await;
    }

    #[tokio::test]
    async fn test_shutdown() {
        let (mut processor, task_tx, _event_rx, _wallet, _storage) = setup_processor().await;

        // Start processor
        let processor_handle = tokio::spawn(async move { processor.run().await });

        // Send shutdown signal by dropping sender
        drop(task_tx);

        // Should shutdown gracefully
        tokio::time::timeout(std::time::Duration::from_millis(100), processor_handle)
            .await
            .expect("Processor should shutdown quickly")
            .expect("Processor should shutdown without error");
    }

    #[tokio::test]
    async fn test_block_not_found_in_storage() {
        let (mut processor, task_tx, mut event_rx, _wallet, _storage) = setup_processor().await;

        let block = create_test_block(Network::Dash);
        let block_hash = block.block_hash();
        let serialized = serialize(&block);

        // Don't store header - should fail to find height

        // Send block processing task
        task_tx
            .send(BlockProcessingTask::ProcessBlock {
                block_hash,
                block_data: serialized,
            })
            .unwrap();

        // Process in a separate task
        let processor_handle = tokio::spawn(async move { processor.run().await });

        // Should still process but with height 0
        tokio::time::timeout(std::time::Duration::from_millis(100), async {
            while let Some(event) = event_rx.recv().await {
                if let SpvEvent::BlockProcessed {
                    hash,
                    height,
                    ..
                } = event
                {
                    assert_eq!(hash, block_hash);
                    assert_eq!(height, 0); // Default height when not found
                    break;
                }
            }
        })
        .await
        .expect("Should receive block processed event");

        // Shutdown
        drop(task_tx);
        let _ = processor_handle.await;
    }
}
