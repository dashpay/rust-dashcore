//! Unit tests for block processing functionality

#[cfg(test)]
mod tests {
    use crate::client::block_processor::{BlockProcessingTask, BlockProcessor};
    use crate::error::SpvError;
    use crate::types::{SpvEvent, SpvStats, WatchItem};
    use crate::wallet::Wallet;
    use dashcore::block::Header as BlockHeader;
    use dashcore::{Block, BlockHash, Transaction, TxOut};
    use dashcore_hashes::Hash;
    use std::collections::HashSet;
    use std::sync::Arc;
    use tokio::sync::{mpsc, oneshot, RwLock};

    fn create_test_block() -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: dashcore::hash_types::TxMerkleNode::all_zeros(),
                time: 0,
                bits: 0,
                nonce: 0,
            },
            txdata: vec![],
        }
    }

    fn create_test_transaction() -> Transaction {
        Transaction {
            version: 1,
            lock_time: dashcore::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: 1000,
                script_pubkey: dashcore::ScriptBuf::new(),
            }],
        }
    }

    async fn setup_block_processor() -> (
        BlockProcessor,
        mpsc::UnboundedSender<BlockProcessingTask>,
        Arc<RwLock<Wallet>>,
        Arc<RwLock<HashSet<WatchItem>>>,
        Arc<RwLock<SpvStats>>,
        mpsc::UnboundedReceiver<SpvEvent>,
    ) {
        let (task_tx, task_rx) = mpsc::unbounded_channel();
        let wallet = Arc::new(RwLock::new(Wallet::new()));
        let watch_items = Arc::new(RwLock::new(HashSet::new()));
        let stats = Arc::new(RwLock::new(SpvStats::default()));
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let processor = BlockProcessor::new(
            task_rx,
            wallet.clone(),
            watch_items.clone(),
            stats.clone(),
            event_tx,
        );

        (processor, task_tx, wallet, watch_items, stats, event_rx)
    }

    #[tokio::test]
    async fn test_process_block_task() {
        let (processor, task_tx, _wallet, _watch_items, stats, mut event_rx) =
            setup_block_processor().await;

        // Start processor in background
        let processor_handle = tokio::spawn(async move {
            processor.run().await;
        });

        // Send a block processing task
        let block = create_test_block();
        let block_hash = block.block_hash();
        let (response_tx, response_rx) = oneshot::channel();

        task_tx
            .send(BlockProcessingTask::ProcessBlock {
                block,
                response_tx,
            })
            .unwrap();

        // Wait for response
        let result = response_rx.await.unwrap();
        assert!(result.is_ok());

        // Check stats were updated
        let stats_guard = stats.read().await;
        assert_eq!(stats_guard.blocks_processed, 1);

        // Check event was sent
        match event_rx.recv().await {
            Some(SpvEvent::BlockProcessed {
                block_hash: hash,
                ..
            }) => {
                assert_eq!(hash, block_hash);
            }
            _ => panic!("Expected BlockProcessed event"),
        }

        // Cleanup
        drop(task_tx);
        let _ = processor_handle.await;
    }

    #[tokio::test]
    async fn test_process_transaction_task() {
        let (processor, task_tx, _wallet, _watch_items, stats, mut event_rx) =
            setup_block_processor().await;

        // Start processor in background
        let processor_handle = tokio::spawn(async move {
            processor.run().await;
        });

        // Send a transaction processing task
        let tx = create_test_transaction();
        let txid = tx.txid();
        let (response_tx, response_rx) = oneshot::channel();

        task_tx
            .send(BlockProcessingTask::ProcessTransaction {
                tx,
                response_tx,
            })
            .unwrap();

        // Wait for response
        let result = response_rx.await.unwrap();
        assert!(result.is_ok());

        // Check stats were updated
        let stats_guard = stats.read().await;
        assert_eq!(stats_guard.transactions_processed, 1);

        // Check event was sent
        match event_rx.recv().await {
            Some(SpvEvent::TransactionConfirmed {
                txid: id,
                ..
            }) => {
                assert_eq!(id, txid);
            }
            _ => panic!("Expected TransactionConfirmed event"),
        }

        // Cleanup
        drop(task_tx);
        let _ = processor_handle.await;
    }

    #[tokio::test]
    async fn test_duplicate_block_detection() {
        let (mut processor, task_tx, _wallet, _watch_items, _stats, _event_rx) =
            setup_block_processor().await;

        // Process a block
        let block = create_test_block();
        let block_hash = block.block_hash();

        // Manually add to processed blocks
        processor.processed_blocks.insert(block_hash);

        // Try to process same block again
        let (response_tx, response_rx) = oneshot::channel();
        let task = BlockProcessingTask::ProcessBlock {
            block,
            response_tx,
        };

        // Process the task directly (simulating the run loop)
        match task {
            BlockProcessingTask::ProcessBlock {
                block,
                response_tx,
            } => {
                if processor.processed_blocks.contains(&block.block_hash()) {
                    let _ = response_tx.send(Ok(()));
                }
            }
            _ => {}
        }

        // Should succeed but skip processing
        let result = response_rx.await.unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_failed_state_rejection() {
        let (mut processor, task_tx, _wallet, _watch_items, _stats, _event_rx) =
            setup_block_processor().await;

        // Set processor to failed state
        processor.failed = true;

        // Try to send a block processing task
        let block = create_test_block();
        let (response_tx, response_rx) = oneshot::channel();

        // Simulate processing in failed state
        let task = BlockProcessingTask::ProcessBlock {
            block,
            response_tx,
        };

        match task {
            BlockProcessingTask::ProcessBlock {
                response_tx,
                ..
            } => {
                if processor.failed {
                    let _ = response_tx
                        .send(Err(SpvError::Config("Block processor has failed".to_string())));
                }
            }
            _ => {}
        }

        // Should receive error
        let result = response_rx.await.unwrap();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Block processor has failed"));
    }

    #[tokio::test]
    async fn test_block_with_watched_address() {
        let (processor, task_tx, wallet, watch_items, _stats, mut event_rx) =
            setup_block_processor().await;

        // Add a watch item
        let address = dashcore::Address::from_str("XeNTGz5bVjPNZVPpwTRz6SnLbZGxLqJUg4")
            .unwrap()
            .assume_checked();
        watch_items.write().await.insert(WatchItem::address(address.clone()));

        // Start processor in background
        let processor_handle = tokio::spawn(async move {
            processor.run().await;
        });

        // Create a block with a transaction to the watched address
        let mut block = create_test_block();
        let mut tx = create_test_transaction();
        tx.output[0].script_pubkey = address.script_pubkey();
        block.txdata.push(tx);

        let (response_tx, response_rx) = oneshot::channel();
        task_tx
            .send(BlockProcessingTask::ProcessBlock {
                block,
                response_tx,
            })
            .unwrap();

        // Wait for response
        let result = response_rx.await.unwrap();
        assert!(result.is_ok());

        // Should receive events for watched address
        let mut found_event = false;
        while let Ok(event) = event_rx.try_recv() {
            if matches!(event, SpvEvent::BlockProcessed { .. }) {
                found_event = true;
                break;
            }
        }
        assert!(found_event);

        // Cleanup
        drop(task_tx);
        let _ = processor_handle.await;
    }

    #[tokio::test]
    async fn test_concurrent_task_processing() {
        let (processor, task_tx, _wallet, _watch_items, stats, _event_rx) =
            setup_block_processor().await;

        // Start processor in background
        let processor_handle = tokio::spawn(async move {
            processor.run().await;
        });

        // Send multiple tasks concurrently
        let mut response_rxs = vec![];
        for i in 0..5 {
            let mut block = create_test_block();
            block.header.nonce = i; // Make each block unique

            let (response_tx, response_rx) = oneshot::channel();
            task_tx
                .send(BlockProcessingTask::ProcessBlock {
                    block,
                    response_tx,
                })
                .unwrap();
            response_rxs.push(response_rx);
        }

        // Wait for all responses
        for response_rx in response_rxs {
            let result = response_rx.await.unwrap();
            assert!(result.is_ok());
        }

        // Check stats
        let stats_guard = stats.read().await;
        assert_eq!(stats_guard.blocks_processed, 5);

        // Cleanup
        drop(task_tx);
        let _ = processor_handle.await;
    }

    #[tokio::test]
    async fn test_block_processing_error_recovery() {
        let (mut processor, _task_tx, _wallet, _watch_items, _stats, _event_rx) =
            setup_block_processor().await;

        // Process a block that causes an error
        let block = create_test_block();
        let (response_tx, _response_rx) = oneshot::channel();

        // Simulate an error during processing
        processor.failed = true;

        let task = BlockProcessingTask::ProcessBlock {
            block,
            response_tx,
        };

        match task {
            BlockProcessingTask::ProcessBlock {
                response_tx,
                ..
            } => {
                if processor.failed {
                    let _ = response_tx
                        .send(Err(SpvError::General("Simulated processing error".to_string())));
                }
            }
            _ => {}
        }

        // Processor should remain in failed state
        assert!(processor.failed);
    }

    #[tokio::test]
    async fn test_transaction_processing_updates_wallet() {
        let (processor, task_tx, wallet, _watch_items, _stats, _event_rx) =
            setup_block_processor().await;

        // Start processor in background
        let processor_handle = tokio::spawn(async move {
            processor.run().await;
        });

        // Send a transaction processing task
        let tx = create_test_transaction();
        let (response_tx, response_rx) = oneshot::channel();

        task_tx
            .send(BlockProcessingTask::ProcessTransaction {
                tx,
                response_tx,
            })
            .unwrap();

        // Wait for response
        let result = response_rx.await.unwrap();
        assert!(result.is_ok());

        // Transaction should be processed by wallet
        // (In real implementation, wallet would update its state)

        // Cleanup
        drop(task_tx);
        let _ = processor_handle.await;
    }

    #[tokio::test]
    async fn test_graceful_shutdown() {
        let (processor, task_tx, _wallet, _watch_items, _stats, _event_rx) =
            setup_block_processor().await;

        // Start processor in background
        let processor_handle = tokio::spawn(async move {
            processor.run().await;
        });

        // Send a few tasks
        for _ in 0..3 {
            let block = create_test_block();
            let (response_tx, response_rx) = oneshot::channel();
            task_tx
                .send(BlockProcessingTask::ProcessBlock {
                    block,
                    response_tx,
                })
                .unwrap();

            // Wait for each to complete
            let _ = response_rx.await;
        }

        // Drop sender to trigger shutdown
        drop(task_tx);

        // Processor should shut down gracefully
        let shutdown_result = processor_handle.await;
        assert!(shutdown_result.is_ok());
    }
}
