//! Unit tests for block processing functionality

#[cfg(test)]
mod tests {
    use crate::client::block_processor::{BlockProcessingTask, BlockProcessor};

    use crate::storage::DiskStorageManager;
    use crate::types::{SpvEvent, SpvStats};
    use dashcore::{blockdata::constants::genesis_block, Block, Network, Transaction};
    use key_wallet_manager::test_utils::MockWallet;

    use std::sync::Arc;
    use tokio::sync::{mpsc, oneshot, Mutex, RwLock};

    fn create_test_block(network: Network) -> Block {
        genesis_block(network)
    }

    async fn setup_processor() -> (
        BlockProcessor<MockWallet, DiskStorageManager>,
        mpsc::UnboundedSender<BlockProcessingTask>,
        mpsc::UnboundedReceiver<SpvEvent>,
        Arc<RwLock<MockWallet>>,
        Arc<Mutex<DiskStorageManager>>,
    ) {
        let (task_tx, task_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let stats = Arc::new(RwLock::new(SpvStats::default()));
        let wallet = Arc::new(RwLock::new(MockWallet::new()));
        let storage = Arc::new(Mutex::new(
            DiskStorageManager::with_temp_dir().await.expect("Failed to create tmp storage"),
        ));
        let processor =
            BlockProcessor::new(task_rx, wallet.clone(), storage.clone(), stats, event_tx);

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

        // Prime wallet with an effect for the coinbase tx in the genesis block
        let txid = block.txdata[0].txid();
        {
            let wallet_guard = wallet.read().await;
            wallet_guard
                .set_effect(txid, 1234, vec!["XyTestAddr1".to_string(), "XyTestAddr2".to_string()])
                .await;
        }
        task_tx
            .send(BlockProcessingTask::ProcessBlock {
                block: Box::new(block.clone()),
                response_tx,
            })
            .unwrap();

        // Process the block in a separate task
        let processor_handle = tokio::spawn(async move { processor.run().await });

        // Wait for events; capture the TransactionDetected for our tx
        let mut saw_tx_event = false;
        tokio::time::timeout(std::time::Duration::from_millis(100), async {
            while let Some(event) = event_rx.recv().await {
                match event {
                    SpvEvent::TransactionDetected {
                        txid: tid,
                        amount,
                        addresses,
                        confirmed,
                        block_height,
                    } => {
                        // Should use wallet-provided values
                        assert_eq!(tid, txid.to_string());
                        assert_eq!(amount, 1234);
                        assert_eq!(
                            addresses,
                            vec!["XyTestAddr1".to_string(), "XyTestAddr2".to_string()]
                        );
                        assert!(confirmed);
                        assert_eq!(block_height, Some(0));
                        saw_tx_event = true;
                    }
                    SpvEvent::BlockProcessed {
                        hash,
                        ..
                    } => {
                        assert_eq!(hash.to_string(), block_hash.to_string());
                        if saw_tx_event {
                            break;
                        }
                    }
                    _ => {}
                }
            }
        })
        .await
        .expect("Should receive block processed event");

        assert!(saw_tx_event, "Should emit TransactionDetected with wallet-provided effect");

        // Verify wallet was called
        {
            let wallet = wallet.read().await;
            let processed_blocks = wallet.processed_blocks();
            let processed = processed_blocks.lock().await;
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
            async fn process_block(&mut self, _block: &Block, _height: u32) -> Vec<dashcore::Txid> {
                Vec::new()
            }

            async fn process_mempool_transaction(&mut self, _tx: &Transaction) {}

            async fn check_compact_filter(
                &mut self,
                _filter: &dashcore::bip158::BlockFilter,
                _block_hash: &dashcore::BlockHash,
            ) -> bool {
                // Always return false - filter doesn't match
                false
            }

            async fn describe(&self) -> String {
                "NonMatchingWallet (test implementation)".to_string()
            }
        }

        let (task_tx, task_rx) = mpsc::unbounded_channel();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let stats = Arc::new(RwLock::new(SpvStats::default()));
        let wallet = Arc::new(RwLock::new(NonMatchingWallet {}));
        let storage = Arc::new(Mutex::new(
            DiskStorageManager::with_temp_dir().await.expect("Failed to create tmp storage"),
        ));

        let processor = BlockProcessor::new(task_rx, wallet, storage, stats, event_tx);

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
    async fn test_transaction_detected_fallback_when_no_wallet_effect() {
        let (processor, task_tx, mut event_rx, _wallet, storage) = setup_processor().await;

        // Create a test block
        let block = create_test_block(Network::Dash);
        let block_hash = block.block_hash();
        let txid = block.txdata[0].txid();

        // Store header so height lookup succeeds
        {
            let mut storage = storage.lock().await;
            storage.store_headers(&[block.header]).await.unwrap();
        }

        // Send block processing task without priming any effect (transaction_effect will return None)
        let (response_tx, _response_rx) = oneshot::channel();
        task_tx
            .send(BlockProcessingTask::ProcessBlock {
                block: Box::new(block.clone()),
                response_tx,
            })
            .unwrap();

        // Process
        let processor_handle = tokio::spawn(async move { processor.run().await });

        let mut saw_tx_event = false;
        tokio::time::timeout(std::time::Duration::from_millis(100), async {
            while let Some(event) = event_rx.recv().await {
                match event {
                    SpvEvent::TransactionDetected {
                        txid: tid,
                        amount,
                        addresses,
                        confirmed,
                        block_height,
                    } => {
                        assert_eq!(tid, txid.to_string());
                        assert_eq!(
                            amount, 0,
                            "fallback amount should be 0 when no effect available"
                        );
                        assert!(addresses.is_empty(), "fallback addresses should be empty");
                        assert!(confirmed);
                        assert_eq!(block_height, Some(0));
                        saw_tx_event = true;
                    }
                    SpvEvent::BlockProcessed {
                        hash,
                        ..
                    } => {
                        assert_eq!(hash.to_string(), block_hash.to_string());
                        if saw_tx_event {
                            break;
                        }
                    }
                    _ => {}
                }
            }
        })
        .await
        .expect("Should receive events");

        assert!(saw_tx_event, "Should emit TransactionDetected with fallback values");

        // Shutdown
        drop(task_tx);
        let _ = processor_handle.await;
    }

    #[tokio::test]
    async fn test_transaction_detected_negative_amount_and_duplicate_addresses() {
        let (processor, task_tx, mut event_rx, wallet, storage) = setup_processor().await;

        // Create a test block
        let block = create_test_block(Network::Dash);
        let block_hash = block.block_hash();
        let txid = block.txdata[0].txid();

        // Store header so height lookup succeeds
        {
            let mut storage = storage.lock().await;
            storage.store_headers(&[block.header]).await.unwrap();
        }

        // Prime wallet with negative amount and duplicate addresses
        {
            let wallet_guard = wallet.read().await;
            wallet_guard
                .set_effect(
                    txid,
                    -500,
                    vec!["DupAddr".to_string(), "DupAddr".to_string(), "UniqueAddr".to_string()],
                )
                .await;
        }

        // Send block processing task
        let (response_tx, _response_rx) = oneshot::channel();
        task_tx
            .send(BlockProcessingTask::ProcessBlock {
                block: Box::new(block.clone()),
                response_tx,
            })
            .unwrap();

        // Process
        let processor_handle = tokio::spawn(async move { processor.run().await });

        let mut saw_tx_event = false;
        tokio::time::timeout(std::time::Duration::from_millis(100), async {
            while let Some(event) = event_rx.recv().await {
                match event {
                    SpvEvent::TransactionDetected {
                        txid: tid,
                        amount,
                        addresses,
                        confirmed,
                        block_height,
                    } => {
                        assert_eq!(tid, txid.to_string());
                        assert_eq!(amount, -500);
                        // BlockProcessor uses wallet-provided addresses as-is (no dedup here)
                        assert_eq!(addresses, vec!["DupAddr", "DupAddr", "UniqueAddr"]);
                        assert!(confirmed);
                        assert_eq!(block_height, Some(0));
                        saw_tx_event = true;
                    }
                    SpvEvent::BlockProcessed {
                        hash,
                        ..
                    } => {
                        assert_eq!(hash.to_string(), block_hash.to_string());
                        if saw_tx_event {
                            break;
                        }
                    }
                    _ => {}
                }
            }
        })
        .await
        .expect("Should receive events");

        assert!(saw_tx_event, "Should emit TransactionDetected with negative net and duplicates");

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
            let processed_transactions = wallet.processed_transactions();
            let processed = processed_transactions.lock().await;
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
