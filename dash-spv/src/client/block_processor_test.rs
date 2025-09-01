//! Unit tests for block processing functionality

#[cfg(test)]
mod tests {
    use crate::client::block_processor::{BlockProcessingTask, BlockProcessor};

    use crate::storage::memory::MemoryStorageManager;
    use crate::storage::StorageManager;
    use crate::types::{SpvEvent, SpvStats};
    use dashcore::{blockdata::constants::genesis_block, Block, Network, Transaction};

    use std::sync::Arc;
    use tokio::sync::{mpsc, oneshot, Mutex, RwLock};

    // Mock WalletInterface implementation for testing
    struct MockWallet {
        processed_blocks: Arc<Mutex<Vec<(dashcore::BlockHash, u32)>>>,
        processed_transactions: Arc<Mutex<Vec<dashcore::Txid>>>,
    }

    impl MockWallet {
        fn new() -> Self {
            Self {
                processed_blocks: Arc::new(Mutex::new(Vec::new())),
                processed_transactions: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    #[async_trait::async_trait]
    impl key_wallet_manager::wallet_interface::WalletInterface for MockWallet {
        async fn process_block(
            &mut self,
            block: &Block,
            height: u32,
            _network: Network,
        ) -> Vec<dashcore::Txid> {
            let mut processed = self.processed_blocks.lock().await;
            processed.push((block.block_hash(), height));

            // Return txids of all transactions in block as "relevant"
            block.txdata.iter().map(|tx| tx.txid()).collect()
        }

        async fn process_mempool_transaction(&mut self, tx: &Transaction, _network: Network) {
            let mut processed = self.processed_transactions.lock().await;
            processed.push(tx.txid());
        }

        async fn handle_reorg(&mut self, _from_height: u32, _to_height: u32, _network: Network) {
            // Not tested here
        }

        async fn check_compact_filter(
            &mut self,
            _filter: &dashcore::bip158::BlockFilter,
            _block_hash: &dashcore::BlockHash,
            _network: Network,
        ) -> bool {
            // Return true for all filters in test
            true
        }
    }

    fn create_test_block(network: Network) -> Block {
        genesis_block(network)
    }

    async fn setup_processor() -> (
        BlockProcessor<MockWallet, MemoryStorageManager>,
        mpsc::UnboundedSender<BlockProcessingTask>,
        mpsc::UnboundedReceiver<SpvEvent>,
        Arc<RwLock<MockWallet>>,
        Arc<Mutex<MemoryStorageManager>>,
    ) {
        let (task_tx, task_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let stats = Arc::new(RwLock::new(SpvStats::default()));
        let wallet = Arc::new(RwLock::new(MockWallet::new()));
        let storage = Arc::new(Mutex::new(MemoryStorageManager::new().await.unwrap()));
        let processor = BlockProcessor::new(
            task_rx,
            wallet.clone(),
            storage.clone(),
            stats,
            event_tx,
            Network::Dash,
        );

        (processor, task_tx, event_rx, wallet, storage)
    }

    #[tokio::test]
    async fn test_process_block() {
        let (processor, task_tx, mut event_rx, wallet, storage) = setup_processor().await;

        // Create a test block
        let block = create_test_block(Network::Dash);
        let block_hash = block.block_hash();

        // Store a header for the block first
        {
            let mut storage = storage.lock().await;
            storage.store_headers(&[block.header]).await.unwrap();
        }

        // Send block processing task
        let (response_tx, _response_rx) = oneshot::channel();
        task_tx
            .send(BlockProcessingTask::ProcessBlock {
                block: Box::new(block.clone()),
                response_tx,
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
                    assert_eq!(hash.to_string(), block_hash.to_string());
                    break;
                }
            }
        })
        .await
        .expect("Should receive block processed event");

        // Verify wallet was called
        {
            let wallet = wallet.read().await;
            // Since we're using key_wallet_manager::wallet_interface::WalletInterface,
            // we need to use the trait to access as_any
            use key_wallet_manager::wallet_interface::WalletInterface;
            let processed = wallet.processed_blocks.lock().await;
            assert_eq!(processed.len(), 1);
            assert_eq!(processed[0].0, block_hash);
        }

        // Shutdown
        drop(task_tx);
        let _ = processor_handle.await;
    }

    #[tokio::test]
    async fn test_process_compact_filter() {
        let (processor, task_tx, mut event_rx, _wallet, _storage) = setup_processor().await;

        // Create a test block
        let block = create_test_block(Network::Dash);
        let block_hash = block.block_hash();

        // Create mock filter data (in real scenario, this would be a GCS filter)
        // For testing, we just use some dummy data
        let filter_data = vec![1, 2, 3, 4, 5];

        // Send filter processing task
        let (response_tx, response_rx) = oneshot::channel();
        let filter = dashcore::bip158::BlockFilter::new(&filter_data);
        task_tx
            .send(BlockProcessingTask::ProcessCompactFilter {
                filter,
                block_hash,
                response_tx,
            })
            .unwrap();

        // Process in a separate task
        let processor_handle = tokio::spawn(async move { processor.run().await });

        // Wait for response
        let matches = tokio::time::timeout(std::time::Duration::from_millis(100), response_rx)
            .await
            .expect("Should receive response")
            .expect("Should receive Ok result")
            .expect("Should receive Ok from processor");

        // Our mock wallet always returns true for check_compact_filter
        assert!(matches, "Filter should match (mock wallet returns true)");

        // Wait for event
        tokio::time::timeout(std::time::Duration::from_millis(100), async {
            while let Some(event) = event_rx.recv().await {
                if let SpvEvent::CompactFilterMatched {
                    hash,
                } = event
                {
                    assert_eq!(hash, block_hash.to_string());
                    break;
                }
            }
        })
        .await
        .expect("Should receive filter matched event");

        // Shutdown
        drop(task_tx);
        let _ = processor_handle.await;
    }

    #[tokio::test]
    async fn test_process_compact_filter_no_match() {
        // Create a custom mock wallet that returns false for filter checks
        struct NonMatchingWallet {}

        #[async_trait::async_trait]
        impl key_wallet_manager::wallet_interface::WalletInterface for NonMatchingWallet {
            async fn process_block(
                &mut self,
                _block: &Block,
                _height: u32,
                _network: Network,
            ) -> Vec<dashcore::Txid> {
                Vec::new()
            }

            async fn process_mempool_transaction(&mut self, _tx: &Transaction, _network: Network) {}

            async fn handle_reorg(
                &mut self,
                _from_height: u32,
                _to_height: u32,
                _network: Network,
            ) {
            }

            async fn check_compact_filter(
                &mut self,
                _filter: &dashcore::bip158::BlockFilter,
                _block_hash: &dashcore::BlockHash,
                _network: Network,
            ) -> bool {
                // Always return false - filter doesn't match
                false
            }
        }

        let (task_tx, task_rx) = mpsc::unbounded_channel();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let stats = Arc::new(RwLock::new(SpvStats::default()));
        let wallet = Arc::new(RwLock::new(NonMatchingWallet {}));
        let storage = Arc::new(Mutex::new(MemoryStorageManager::new().await.unwrap()));

        let processor =
            BlockProcessor::new(task_rx, wallet, storage, stats, event_tx, Network::Dash);

        let block_hash = create_test_block(Network::Dash).block_hash();
        let filter_data = vec![1, 2, 3, 4, 5];

        // Send filter processing task
        let (response_tx, response_rx) = oneshot::channel();
        let filter = dashcore::bip158::BlockFilter::new(&filter_data);
        task_tx
            .send(BlockProcessingTask::ProcessCompactFilter {
                filter,
                block_hash,
                response_tx,
            })
            .unwrap();

        // Process in a separate task
        let processor_handle = tokio::spawn(async move { processor.run().await });

        // Wait for response
        let matches = tokio::time::timeout(std::time::Duration::from_millis(100), response_rx)
            .await
            .expect("Should receive response")
            .expect("Should receive Ok result")
            .expect("Should receive Ok from processor");

        // Should not match
        assert!(!matches, "Filter should not match");

        // Should NOT receive a CompactFilterMatched event
        let event_result =
            tokio::time::timeout(std::time::Duration::from_millis(50), event_rx.recv()).await;
        assert!(event_result.is_err(), "Should not receive any event for non-matching filter");

        // Shutdown
        drop(task_tx);
        let _ = processor_handle.await;
    }

    #[tokio::test]
    async fn test_process_mempool_transaction() {
        let (processor, task_tx, _event_rx, wallet, _storage) = setup_processor().await;

        // Create a test transaction
        let block = create_test_block(Network::Dash);
        let tx = block.txdata[0].clone();
        let txid = tx.txid();

        // Send mempool transaction task
        let (response_tx, _response_rx) = oneshot::channel();
        task_tx
            .send(BlockProcessingTask::ProcessTransaction {
                tx: Box::new(tx.clone()),
                response_tx,
            })
            .unwrap();

        // Process in a separate task
        let processor_handle = tokio::spawn(async move { processor.run().await });

        // Wait a bit for processing
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Verify wallet was called
        {
            let wallet = wallet.read().await;
            let processed = wallet.processed_transactions.lock().await;
            assert_eq!(processed.len(), 1);
            assert_eq!(processed[0], txid);
        }

        // Shutdown
        drop(task_tx);
        let _ = processor_handle.await;
    }

    #[tokio::test]
    async fn test_shutdown() {
        let (processor, task_tx, _event_rx, _wallet, _storage) = setup_processor().await;

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
        let (processor, task_tx, mut event_rx, _wallet, _storage) = setup_processor().await;

        let block = create_test_block(Network::Dash);
        let block_hash = block.block_hash();

        // Don't store header - should fail to find height

        // Send block processing task
        let (response_tx, _response_rx) = oneshot::channel();
        task_tx
            .send(BlockProcessingTask::ProcessBlock {
                block: Box::new(block.clone()),
                response_tx,
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
                    assert_eq!(hash.to_string(), block_hash.to_string());
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
