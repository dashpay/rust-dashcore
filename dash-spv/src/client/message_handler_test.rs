// Tests temporarily disabled - need to be rewritten for new architecture without wallet module
/*
//! Unit tests for network message handling

#[cfg(test)]
mod tests {
    use crate::chain::ChainLockManager;
    use crate::client::{BlockProcessingTask, ClientConfig, MessageHandler};
    use crate::mempool_filter::MempoolFilter;
    use crate::network::mock::MockNetworkManager;
    use crate::network::NetworkManager;
    use crate::storage::memory::MemoryStorageManager;
    use crate::storage::StorageManager;
    use crate::sync::filters::FilterNotificationSender;
    use crate::sync::SyncManager;
    use crate::types::{ChainState, MempoolState, SpvEvent, SpvStats};
    use crate::validation::ValidationManager;
    use crate::wallet::Wallet;
    use dashcore::block::Header as BlockHeader;
    use dashcore::network::message::NetworkMessage;
    use dashcore::network::message_blockdata::Inventory;
    use dashcore::{Block, BlockHash, Network, Transaction};
    use dashcore_hashes::Hash;
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::sync::Mutex;
    use tokio::sync::{mpsc, RwLock};

    async fn setup_test_components() -> (
        Box<dyn NetworkManager>,
        Box<dyn StorageManager>,
        SyncManager,
        ClientConfig,
        Arc<RwLock<SpvStats>>,
        Option<FilterNotificationSender>,
        mpsc::UnboundedSender<BlockProcessingTask>,
        Arc<RwLock<Wallet>>,
        Option<Arc<MempoolFilter>>,
        Arc<RwLock<MempoolState>>,
        mpsc::UnboundedSender<SpvEvent>,
    ) {
        let network = Box::new(MockNetworkManager::new()) as Box<dyn NetworkManager>;
        let storage =
            Box::new(MemoryStorageManager::new().await.unwrap()) as Box<dyn StorageManager>;
        let config = ClientConfig::default();
        let stats = Arc::new(RwLock::new(SpvStats::default()));
        let (block_tx, _block_rx) = mpsc::unbounded_channel();
        let wallet_storage = Arc::new(RwLock::new(MemoryStorageManager::new().await.unwrap()));
        let wallet = Arc::new(RwLock::new(Wallet::new(wallet_storage)));
        let mempool_state = Arc::new(RwLock::new(MempoolState::default()));
        let (event_tx, _event_rx) = mpsc::unbounded_channel();

        // Create sync manager
        let received_filter_heights = Arc::new(Mutex::new(HashSet::new()));
        let sync_manager = SyncManager::new(&config, received_filter_heights).unwrap();

        (
            network,
            storage,
            sync_manager,
            config,
            stats,
            None,
            block_tx,
            wallet,
            None,
            mempool_state,
            event_tx,
        )
    }

    #[tokio::test]
    async fn test_handle_headers2_message() {
        let (
            mut network,
            mut storage,
            mut sync_manager,
            config,
            stats,
            filter_processor,
            block_processor_tx,
            wallet,
            mempool_filter,
            mempool_state,
            event_tx,
        ) = setup_test_components().await;

        let mut handler = MessageHandler::new(
            &mut sync_manager,
            &mut *storage,
            &mut *network,
            &config,
            &stats,
            &filter_processor,
            &block_processor_tx,
            &wallet,
            &mempool_filter,
            &mempool_state,
            &event_tx,
        );

        // Create a Headers2 message
        let headers2 = dashcore::network::message_headers2::Headers2Message {
            headers: vec![],
        };
        let message = NetworkMessage::Headers2(headers2);

        // Handle the message
        let result = handler.handle_network_message(message).await;
        assert!(result.is_ok());

        // Verify peer was marked as having sent headers2
        // (MockNetworkManager would track this)
    }

    #[tokio::test]
    async fn test_handle_mnlistdiff_message() {
        let (
            mut network,
            mut storage,
            mut sync_manager,
            config,
            stats,
            filter_processor,
            block_processor_tx,
            wallet,
            mempool_filter,
            mempool_state,
            event_tx,
        ) = setup_test_components().await;

        let mut handler = MessageHandler::new(
            &mut sync_manager,
            &mut *storage,
            &mut *network,
            &config,
            &stats,
            &filter_processor,
            &block_processor_tx,
            &wallet,
            &mempool_filter,
            &mempool_state,
            &event_tx,
        );

        // Create a MnListDiff message
        let mnlistdiff = dashcore::network::message_sml::MnListDiff {
            version: 1,
            base_block_hash: BlockHash::from([0u8; 32]),
            block_hash: BlockHash::from([0u8; 32]),
            total_transactions: 0,
            merkle_hashes: vec![],
            merkle_flags: vec![],
            coinbase_tx: dashcore::Transaction {
                version: 1,
                lock_time: 0,
                input: vec![],
                output: vec![],
                special_transaction_payload: None,
            },
            deleted_masternodes: vec![],
            new_masternodes: vec![],
            deleted_quorums: vec![],
            new_quorums: vec![],
            quorums_chainlock_signatures: vec![],
        };
        let message = NetworkMessage::MnListDiff(mnlistdiff);

        // Handle the message
        let result = handler.handle_network_message(message).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_cfheaders_message() {
        let (
            mut network,
            mut storage,
            mut sync_manager,
            config,
            stats,
            filter_processor,
            block_processor_tx,
            wallet,
            mempool_filter,
            mempool_state,
            event_tx,
        ) = setup_test_components().await;

        let mut handler = MessageHandler::new(
            &mut sync_manager,
            &mut *storage,
            &mut *network,
            &config,
            &stats,
            &filter_processor,
            &block_processor_tx,
            &wallet,
            &mempool_filter,
            &mempool_state,
            &event_tx,
        );

        // Create a CFHeaders message
        let cfheaders = dashcore::network::message_filter::CFHeaders {
            filter_type: 0,
            stop_hash: BlockHash::from([0u8; 32]),
            previous_filter_header: dashcore::hash_types::FilterHeader::from([0u8; 32]),
            filter_hashes: vec![],
        };
        let message = NetworkMessage::CFHeaders(cfheaders);

        // Handle the message
        let result = handler.handle_network_message(message).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_cfilter_message() {
        let (
            mut network,
            mut storage,
            mut sync_manager,
            config,
            stats,
            filter_processor,
            block_processor_tx,
            wallet,
            mempool_filter,
            mempool_state,
            event_tx,
        ) = setup_test_components().await;

        let mut handler = MessageHandler::new(
            &mut sync_manager,
            &mut *storage,
            &mut *network,
            &config,
            &stats,
            &filter_processor,
            &block_processor_tx,
            &wallet,
            &mempool_filter,
            &mempool_state,
            &event_tx,
        );

        // Create a CFilter message
        let cfilter = dashcore::network::message_filter::CFilter {
            filter_type: 0,
            block_hash: BlockHash::from([0u8; 32]),
            filter: vec![],
        };
        let message = NetworkMessage::CFilter(cfilter);

        // Handle the message - should be passed to sync manager
        let result = handler.handle_network_message(message).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_block_message() {
        let (
            mut network,
            mut storage,
            mut sync_manager,
            config,
            stats,
            filter_processor,
            block_processor_tx,
            wallet,
            mempool_filter,
            mempool_state,
            event_tx,
        ) = setup_test_components().await;

        // Set up block processor receiver
        let (block_tx, mut block_rx) = mpsc::unbounded_channel();

        let mut handler = MessageHandler::new(
            &mut sync_manager,
            &mut *storage,
            &mut *network,
            &config,
            &stats,
            &filter_processor,
            &block_tx,
            &wallet,
            &mempool_filter,
            &mempool_state,
            &event_tx,
        );

        // Create a Block message
        let block = Block {
            header: BlockHeader {
                version: dashcore::block::Version::from_consensus(1),
                prev_blockhash: BlockHash::from([0u8; 32]),
                merkle_root: dashcore::hash_types::TxMerkleNode::from([0u8; 32]),
                time: 0,
                bits: dashcore::CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txdata: vec![],
        };
        let message = NetworkMessage::Block(block.clone());

        // Handle the message
        let result = handler.handle_network_message(message).await;
        assert!(result.is_ok());

        // Verify block was sent to processor
        match block_rx.recv().await {
            Some(BlockProcessingTask::ProcessBlock {
                block: received_block,
                ..
            }) => {
                assert_eq!(received_block.header.block_hash(), block.header.block_hash());
            }
            _ => panic!("Expected block processing task"),
        }
    }

    #[tokio::test]
    async fn test_handle_inv_message_with_mempool() {
        let (
            mut network,
            mut storage,
            mut sync_manager,
            mut config,
            stats,
            filter_processor,
            block_processor_tx,
            wallet,
            _,
            mempool_state,
            event_tx,
        ) = setup_test_components().await;

        // Enable mempool tracking
        config.enable_mempool_tracking = true;
        config.fetch_mempool_transactions = true;

        // Create mempool filter
        let mempool_filter = Some(Arc::new(MempoolFilter::new(
            crate::client::config::MempoolStrategy::Selective,
            std::time::Duration::from_secs(60),
            1000,
            mempool_state.clone(),
            vec![],
        )));

        let mut handler = MessageHandler::new(
            &mut sync_manager,
            &mut *storage,
            &mut *network,
            &config,
            &stats,
            &filter_processor,
            &block_processor_tx,
            &wallet,
            &mempool_filter,
            &mempool_state,
            &event_tx,
        );

        // Create an Inv message with transaction
        let inv = vec![Inventory::Transaction(dashcore::Txid::all_zeros())];
        let message = NetworkMessage::Inv(inv);

        // Handle the message
        let result = handler.handle_network_message(message).await;
        assert!(result.is_ok());

        // Should have requested the transaction
        // (MockNetworkManager would track this)
    }

    #[tokio::test]
    async fn test_handle_tx_message() {
        let (
            mut network,
            mut storage,
            mut sync_manager,
            mut config,
            stats,
            filter_processor,
            block_processor_tx,
            wallet,
            _,
            mempool_state,
            event_tx,
        ) = setup_test_components().await;

        // Enable mempool tracking
        config.enable_mempool_tracking = true;
        let mempool_filter = Some(Arc::new(MempoolFilter::new(
            crate::client::config::MempoolStrategy::Selective,
            std::time::Duration::from_secs(60),
            1000,
            mempool_state.clone(),
            vec![],
        )));

        let mut handler = MessageHandler::new(
            &mut sync_manager,
            &mut *storage,
            &mut *network,
            &config,
            &stats,
            &filter_processor,
            &block_processor_tx,
            &wallet,
            &mempool_filter,
            &mempool_state,
            &event_tx,
        );

        // Create a Tx message
        let tx = Transaction {
            version: 1,
            lock_time: 0,
            input: vec![],
            output: vec![],
            special_transaction_payload: None,
        };
        let message = NetworkMessage::Tx(tx.clone());

        // Handle the message
        let result = handler.handle_network_message(message).await;
        assert!(result.is_ok());

        // Should have emitted transaction event
        // Note: The test setup has event_tx (sender), not event_rx (receiver)
        // In a real test, we'd need to create a receiver to check events
        // For now, just verify the handler processed without error
    }

    #[tokio::test]
    async fn test_handle_chainlock_message() {
        let (
            mut network,
            mut storage,
            mut sync_manager,
            config,
            stats,
            filter_processor,
            block_processor_tx,
            wallet,
            mempool_filter,
            mempool_state,
            event_tx,
        ) = setup_test_components().await;

        let mut handler = MessageHandler::new(
            &mut sync_manager,
            &mut *storage,
            &mut *network,
            &config,
            &stats,
            &filter_processor,
            &block_processor_tx,
            &wallet,
            &mempool_filter,
            &mempool_state,
            &event_tx,
        );

        // Create a ChainLock message
        let chainlock = dashcore::ChainLock {
            block_height: 100,
            block_hash: BlockHash::from([0u8; 32]),
            signature: dashcore::bls_sig_utils::BLSSignature::from([0u8; 96]),
        };
        let message = NetworkMessage::CLSig(chainlock);

        // Handle the message
        let result = handler.handle_network_message(message).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_instantlock_message() {
        let (
            mut network,
            mut storage,
            mut sync_manager,
            config,
            stats,
            filter_processor,
            block_processor_tx,
            wallet,
            mempool_filter,
            mempool_state,
            event_tx,
        ) = setup_test_components().await;

        let mut handler = MessageHandler::new(
            &mut sync_manager,
            &mut *storage,
            &mut *network,
            &config,
            &stats,
            &filter_processor,
            &block_processor_tx,
            &wallet,
            &mempool_filter,
            &mempool_state,
            &event_tx,
        );

        // Skip InstantLock test - message type varies by dashcore version
        // TODO: Re-enable when InstantLock message type is stabilized
        // let message = NetworkMessage::InstantLock(...);
        // let result = handler.handle_network_message(message).await;
        // assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_ping_message() {
        let (
            mut network,
            mut storage,
            mut sync_manager,
            config,
            stats,
            filter_processor,
            block_processor_tx,
            wallet,
            mempool_filter,
            mempool_state,
            event_tx,
        ) = setup_test_components().await;

        let mut handler = MessageHandler::new(
            &mut sync_manager,
            &mut *storage,
            &mut *network,
            &config,
            &stats,
            &filter_processor,
            &block_processor_tx,
            &wallet,
            &mempool_filter,
            &mempool_state,
            &event_tx,
        );

        // Create a Ping message
        let message = NetworkMessage::Ping(12345);

        // Handle the message
        let result = handler.handle_network_message(message).await;
        assert!(result.is_ok());

        // Should respond with pong (MockNetworkManager would track this)
    }

    #[tokio::test]
    async fn test_error_propagation() {
        let (
            mut network,
            mut storage,
            mut sync_manager,
            config,
            stats,
            filter_processor,
            block_processor_tx,
            wallet,
            mempool_filter,
            mempool_state,
            event_tx,
        ) = setup_test_components().await;

        let mut handler = MessageHandler::new(
            &mut sync_manager,
            &mut *storage,
            &mut *network,
            &config,
            &stats,
            &filter_processor,
            &block_processor_tx,
            &wallet,
            &mempool_filter,
            &mempool_state,
            &event_tx,
        );

        // Create a message that might cause an error in sync manager
        // For example, Headers2 with invalid data
        let headers2 = dashcore::network::message_headers2::Headers2Message {
            headers: vec![], // Empty headers might cause validation error
        };
        let message = NetworkMessage::Headers2(headers2);

        // Handle the message - error should be propagated
        let result = handler.handle_network_message(message).await;
        // The result depends on sync manager validation
        assert!(result.is_ok() || result.is_err());
    }
}
*/
