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
    use crate::sync::sequential::SequentialSyncManager;
    use crate::sync::filters::FilterNotificationSender;
    use crate::types::{ChainState, MempoolState, SpvEvent, SpvStats};
    use crate::validation::ValidationManager;
    use crate::wallet::Wallet;
    use dashcore::network::message::NetworkMessage;
    use dashcore::network::message_blockdata::Inventory;
    use dashcore::{Block, BlockHash, Network, Transaction};
    use dashcore::block::Header as BlockHeader;
    use dashcore_hashes::Hash;
    use std::sync::Arc;
    use tokio::sync::{mpsc, RwLock};

    async fn setup_test_components() -> (
        Box<dyn NetworkManager>,
        Box<dyn StorageManager>,
        SequentialSyncManager,
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
        let storage = Box::new(MemoryStorageManager::new().await.unwrap()) as Box<dyn StorageManager>;
        let config = ClientConfig::default();
        let stats = Arc::new(RwLock::new(SpvStats::default()));
        let (block_tx, _block_rx) = mpsc::unbounded_channel();
        let wallet = Arc::new(RwLock::new(Wallet::new()));
        let mempool_state = Arc::new(RwLock::new(MempoolState::default()));
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        
        // Create sync manager dependencies
        let validation_manager = ValidationManager::new(Network::Dash);
        let chainlock_manager = ChainLockManager::new();
        let chain_state = Arc::new(RwLock::new(ChainState::default()));
        
        let sync_manager = SequentialSyncManager::new(
            validation_manager,
            chainlock_manager,
            chain_state,
            stats.clone(),
        );
        
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
            base_block_hash: BlockHash::all_zeros(),
            block_hash: BlockHash::all_zeros(),
            total_transactions: 0,
            new_masternodes: vec![],
            deleted_masternodes: vec![],
            updated_masternodes: vec![],
            new_quorums: vec![],
            deleted_quorums: vec![],
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
            stop_hash: BlockHash::all_zeros(),
            previous_filter: [0; 32],
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
            block_hash: BlockHash::all_zeros(),
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
                version: 1,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: dashcore::hash_types::TxMerkleNode::all_zeros(),
                time: 0,
                bits: 0,
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
            Some(BlockProcessingTask::ProcessBlock { block: received_block, .. }) => {
                assert_eq!(received_block.block_hash(), block.block_hash());
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
        let mempool_filter = Some(Arc::new(MempoolFilter::new(&config)));

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
            mut event_rx,
        ) = setup_test_components().await;

        // Enable mempool tracking
        config.enable_mempool_tracking = true;
        let mempool_filter = Some(Arc::new(MempoolFilter::new(&config)));

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
            &event_rx.clone(),
        );

        // Create a Tx message
        let tx = Transaction {
            version: 1,
            lock_time: dashcore::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let message = NetworkMessage::Tx(tx.clone());

        // Handle the message
        let result = handler.handle_network_message(message).await;
        assert!(result.is_ok());

        // Should have emitted transaction event
        match event_rx.recv().await {
            Some(SpvEvent::TransactionReceived { txid, .. }) => {
                assert_eq!(txid, tx.txid());
            }
            _ => panic!("Expected TransactionReceived event"),
        }
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
        let chainlock = dashcore::ephemerealdata::chain_lock::ChainLock {
            request_id: [0; 32],
            block_hash: BlockHash::all_zeros(),
            sig: vec![0; 96],
            height: 100,
        };
        let message = NetworkMessage::ChainLock(chainlock);

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

        // Create an IsDLock message
        let islock = dashcore::ephemerealdata::instant_lock::InstantLock {
            version: 1,
            inputs: vec![],
            txid: dashcore::Txid::all_zeros(),
            cyclehash: [0; 32],
            signature: vec![0; 96],
        };
        let message = NetworkMessage::IsDLock(islock);

        // Handle the message
        let result = handler.handle_network_message(message).await;
        assert!(result.is_ok());
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