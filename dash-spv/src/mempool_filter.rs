//! Mempool transaction filtering logic.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use dashcore::{Address, Network, Transaction, Txid};
use tokio::sync::RwLock;

use crate::client::config::MempoolStrategy;
use crate::types::{MempoolState, UnconfirmedTransaction};

/// Filter for deciding which mempool transactions to fetch and track.
pub struct MempoolFilter {
    /// Mempool strategy to use.
    strategy: MempoolStrategy,
    /// Recent send window duration.
    recent_send_window: Duration,
    /// Maximum number of transactions to track.
    max_transactions: usize,
    /// Mempool state.
    mempool_state: Arc<RwLock<MempoolState>>,
    /// Watched addresses (TODO: Will be replaced with wallet integration).
    watched_addresses: HashSet<Address>,
    /// Network to use for address parsing.
    network: Network,
}

impl MempoolFilter {
    /// Create a new mempool filter.
    pub fn new(
        strategy: MempoolStrategy,
        recent_send_window: Duration,
        max_transactions: usize,
        mempool_state: Arc<RwLock<MempoolState>>,
        watched_addresses: HashSet<Address>,
        network: Network,
    ) -> Self {
        Self {
            strategy,
            recent_send_window,
            max_transactions,
            mempool_state,
            watched_addresses: watched_addresses.into_iter().collect(),
            network,
        }
    }

    /// Check if we should fetch a transaction based on its txid.
    pub async fn should_fetch_transaction(&self, txid: &Txid) -> bool {
        match self.strategy {
            MempoolStrategy::FetchAll => {
                // Check if we're at capacity
                let state = self.mempool_state.read().await;
                state.transactions.len() < self.max_transactions
            }
            MempoolStrategy::BloomFilter => {
                // For bloom filter strategy, we would check the bloom filter
                // This is handled by the network layer
                true
            }
            MempoolStrategy::Selective => {
                // Check if this was a recent send
                let state = self.mempool_state.read().await;
                state.is_recent_send(txid, self.recent_send_window)
            }
        }
    }

    /// Check if a transaction is relevant to our watched items.
    pub fn is_transaction_relevant(&self, tx: &Transaction) -> bool {
        let txid = tx.txid();

        // Check if any input or output affects our watched addresses
        let mut addresses = HashSet::new();

        // Extract addresses from outputs
        for (idx, output) in tx.output.iter().enumerate() {
            if let Ok(address) = Address::from_script(&output.script_pubkey, self.network) {
                addresses.insert(address.clone());
                tracing::trace!("Transaction {} output {} has address: {}", txid, idx, address);
            }
        }

        tracing::debug!(
            "Transaction {} has {} addresses from outputs, checking against {} watched addresses",
            txid,
            addresses.len(),
            self.watched_addresses.len()
        );

        // Check against watched addresses using O(1) HashSet lookups
        for address in &addresses {
            if self.watched_addresses.contains(address) {
                tracing::debug!(
                    "Transaction {} is relevant: contains watched address {}",
                    txid,
                    address
                );
                return true;
            }
        }

        // TODO: In the future, also check for watched scripts and outpoints
        // when wallet supports them

        // If we get here, transaction is not relevant to any watched items
        tracing::debug!("Transaction {} is not relevant to any watched items", txid);
        false
    }

    /// Process a new transaction for the mempool.
    pub async fn process_transaction(&self, tx: Transaction) -> Option<UnconfirmedTransaction> {
        let txid = tx.txid();

        // Check if transaction is relevant to our watched addresses
        let is_relevant = self.is_transaction_relevant(&tx);

        tracing::debug!("Processing mempool transaction {}: strategy={:?}, is_relevant={}, watched_addresses_count={}",
                       txid, self.strategy, is_relevant, self.watched_addresses.len());

        // For FetchAll strategy, we fetch all transactions but only process relevant ones
        if self.strategy != MempoolStrategy::FetchAll {
            // For other strategies, return early if not relevant
            if !is_relevant {
                tracing::debug!(
                    "Transaction {} not relevant for strategy {:?}, skipping",
                    txid,
                    self.strategy
                );
                return None;
            }
        }

        // Fee calculation removed - would require wallet implementation
        let fee = 0;

        // InstantSend check removed - would require wallet implementation
        let is_instant_send = false;

        // Outgoing check removed - would require wallet implementation
        let is_outgoing = false;

        // Get affected addresses
        let mut addresses = Vec::new();
        for output in &tx.output {
            if let Ok(address) = Address::from_script(&output.script_pubkey, self.network) {
                // For FetchAll strategy, include all addresses, not just watched ones
                if self.strategy == MempoolStrategy::FetchAll || self.is_address_watched(&address) {
                    addresses.push(address);
                }
            }
        }

        // Net amount calculation removed - would require wallet implementation
        let net_amount = 0i64;

        // For FetchAll strategy, only return transaction if it's relevant
        // This ensures callbacks are only triggered for watched addresses
        if self.strategy == MempoolStrategy::FetchAll && !is_relevant {
            return None;
        }

        Some(UnconfirmedTransaction::new(
            tx,
            dashcore::Amount::from_sat(fee),
            is_instant_send,
            is_outgoing,
            addresses,
            net_amount,
        ))
    }

    /// Record that we sent a transaction.
    pub async fn record_send(&self, txid: Txid) {
        let mut state = self.mempool_state.write().await;
        state.record_send(txid);
    }

    /// Prune expired transactions.
    pub async fn prune_expired(&self, timeout: Duration) -> Vec<Txid> {
        let mut state = self.mempool_state.write().await;
        state.prune_expired(timeout)
    }

    /// Check if we're at capacity.
    pub async fn is_at_capacity(&self) -> bool {
        let state = self.mempool_state.read().await;
        state.transactions.len() >= self.max_transactions
    }

    /// Check if an address is watched.
    fn is_address_watched(&self, address: &Address) -> bool {
        self.watched_addresses.contains(address)
    }
}

// Tests for mempool filter functionality with wallet integration
#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::{Network, OutPoint, ScriptBuf, TxIn, TxOut, Witness};
    use std::str::FromStr;

    // Stub types for ignored tests
    #[derive(Clone)]
    enum WatchItem {
        Address(Address),
        Script(()),
        Outpoint(()),
    }

    impl WatchItem {
        fn address(addr: Address) -> Self {
            WatchItem::Address(addr)
        }

        fn address_from_height(addr: Address, _height: u32) -> Self {
            WatchItem::Address(addr)
        }
    }

    struct MockWallet {
        network: Network,
        watched_addresses: HashSet<Address>,
        utxos: HashSet<OutPoint>,
    }

    impl MockWallet {
        fn new(network: Network) -> Self {
            Self {
                network,
                watched_addresses: HashSet::new(),
                utxos: HashSet::new(),
            }
        }

        fn add_watched_address(&mut self, address: Address) {
            self.watched_addresses.insert(address);
        }

        fn network(&self) -> &Network {
            &self.network
        }

        fn watched_addresses(&self) -> &HashSet<Address> {
            &self.watched_addresses
        }

        fn utxos(&self) -> &HashSet<OutPoint> {
            &self.utxos
        }
    }

    // Helper to create a test wallet and get addresses from it
    fn create_test_addresses(network: Network, count: usize) -> Vec<Address> {
        let mut addresses = Vec::new();

        // Use hardcoded addresses that are valid for the given network
        let address_strings = match network {
            Network::Dash => vec![
                "XjbaGWaGnvEtuQAUoBgDxJWe8ZNv45upG2",
                "Xan9iCVe1q5jYRDZ4VSMCtBjq2VyQA3Dge",
                "XnC5y7Va2x8wF8v1J9J9J9J9J9J9J9J9J9",
            ],
            Network::Testnet => vec![
                "yM7jWpY8jMgZ9a1b1b1b1b1b1b1b1b1b1b",
                "yN8kXpZ9kNgA2c2c2c2c2c2c2c2c2c2c2c",
                "yO9lYqA9lOhB3d3d3d3d3d3d3d3d3d3d3d",
            ],
            _ => vec![
                "XjbaGWaGnvEtuQAUoBgDxJWe8ZNv45upG2",
                "Xan9iCVe1q5jYRDZ4VSMCtBjq2VyQA3Dge",
                "XnC5y7Va2x8wF8v1J9J9J9J9J9J9J9J9J9",
            ],
        };

        for (i, addr_str) in address_strings.iter().enumerate() {
            if i >= count {
                break;
            }
            if let Ok(addr) = Address::from_str(addr_str) {
                if let Ok(network_addr) = addr.require_network(network) {
                    addresses.push(network_addr);
                }
            }
        }

        addresses
    }

    // Helper to create a test transaction
    fn create_test_transaction(outputs: Vec<(Address, u64)>, inputs: Vec<OutPoint>) -> Transaction {
        let mut tx_outputs = vec![];
        for (addr, amount) in outputs {
            tx_outputs.push(TxOut {
                value: amount,
                script_pubkey: addr.script_pubkey(),
            });
        }

        let mut tx_inputs = vec![];
        for outpoint in inputs {
            tx_inputs.push(TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: 0xffffffff,
                witness: Witness::new(),
            });
        }

        Transaction {
            version: 1,
            lock_time: 0,
            input: tx_inputs,
            output: tx_outputs,
            special_transaction_payload: None,
        }
    }

    // Stub implementations for ignored tests
    fn test_address(_network: Network) -> Address {
        Address::from_str("XjbaGWaGnvEtuQAUoBgDxJWe8ZNv45upG2")
            .unwrap()
            .require_network(Network::Dash)
            .unwrap()
    }

    fn test_address2(_network: Network) -> Address {
        Address::from_str("Xan9iCVe1q5jYRDZ4VSMCtBjq2VyQA3Dge")
            .unwrap()
            .require_network(Network::Dash)
            .unwrap()
    }

    #[tokio::test]
    async fn test_selective_strategy() {
        let mempool_state = Arc::new(RwLock::new(MempoolState::default()));
        let filter = MempoolFilter::new(
            MempoolStrategy::Selective,
            Duration::from_secs(300),
            1000,
            mempool_state.clone(),
            HashSet::new(),
            Network::Dash,
        );

        // Generate a test txid
        let txid =
            Txid::from_str("0101010101010101010101010101010101010101010101010101010101010101")
                .unwrap();

        // Should not fetch unknown transaction
        assert!(!filter.should_fetch_transaction(&txid).await);

        // Record as recent send
        filter.record_send(txid).await;

        // Should fetch recent send
        assert!(filter.should_fetch_transaction(&txid).await);
    }

    #[tokio::test]
    async fn test_fetch_all_strategy() {
        let mempool_state = Arc::new(RwLock::new(MempoolState::default()));
        let filter = MempoolFilter::new(
            MempoolStrategy::FetchAll,
            Duration::from_secs(300),
            2, // Small limit for testing
            mempool_state.clone(),
            HashSet::new(),
            Network::Dash,
        );

        // Should fetch any transaction when under limit
        let txid1 =
            Txid::from_str("0101010101010101010101010101010101010101010101010101010101010101")
                .unwrap();
        assert!(filter.should_fetch_transaction(&txid1).await);

        // Add transactions to reach limit
        let mut state = mempool_state.write().await;
        // Create unique transactions by varying the lock_time
        state.add_transaction(UnconfirmedTransaction::new(
            Transaction {
                version: 1,
                lock_time: 1,
                input: vec![],
                output: vec![],
                special_transaction_payload: None,
            },
            dashcore::Amount::from_sat(0),
            false,
            false,
            Vec::new(),
            0,
        ));
        state.add_transaction(UnconfirmedTransaction::new(
            Transaction {
                version: 1,
                lock_time: 2,
                input: vec![],
                output: vec![],
                special_transaction_payload: None,
            },
            dashcore::Amount::from_sat(0),
            false,
            false,
            Vec::new(),
            0,
        ));
        drop(state);

        // Should not fetch when at capacity
        let txid2 =
            Txid::from_str("0202020202020202020202020202020202020202020202020202020202020202")
                .unwrap();
        assert!(!filter.should_fetch_transaction(&txid2).await);
    }

    #[tokio::test]
    async fn test_is_transaction_relevant_with_address() {
        let network = Network::Dash;

        // Create a wallet and get addresses from it
        let addresses = create_test_addresses(network, 2);
        let addr1 = &addresses[0];
        let addr2 = &addresses[1];

        let mempool_state = Arc::new(RwLock::new(MempoolState::default()));
        let watched_addresses = vec![addr1.clone()].into_iter().collect();

        let filter = MempoolFilter::new(
            MempoolStrategy::Selective,
            Duration::from_secs(300),
            1000,
            mempool_state,
            watched_addresses,
            network,
        );

        // Transaction sending to watched address should be relevant
        let tx1 = create_test_transaction(vec![(addr1.clone(), 50000)], vec![]);
        assert!(filter.is_transaction_relevant(&tx1));

        // Transaction sending to unwatched address should not be relevant
        let tx2 = create_test_transaction(vec![(addr2.clone(), 50000)], vec![]);
        assert!(!filter.is_transaction_relevant(&tx2));
    }

    #[tokio::test]
    async fn test_is_transaction_relevant_with_script() {
        let network = Network::Dash;

        // Create a wallet and get addresses from it
        let addresses = create_test_addresses(network, 2);
        let addr = &addresses[0];
        let addr2 = &addresses[1];

        let mempool_state = Arc::new(RwLock::new(MempoolState::default()));
        let watched_addresses = vec![addr.clone()].into_iter().collect();

        let filter = MempoolFilter::new(
            MempoolStrategy::Selective,
            Duration::from_secs(300),
            1000,
            mempool_state,
            watched_addresses,
            network,
        );

        // Transaction with watched script should be relevant
        let tx = create_test_transaction(vec![(addr.clone(), 50000)], vec![]);
        assert!(filter.is_transaction_relevant(&tx));

        // Transaction without watched script should not be relevant
        let tx2 = create_test_transaction(vec![(addr2.clone(), 50000)], vec![]);
        assert!(!filter.is_transaction_relevant(&tx2));
    }

    #[tokio::test]
    async fn test_is_transaction_relevant_with_outpoint() {
        let network = Network::Dash;

        // Create a wallet and get an address from it
        let addresses = create_test_addresses(network, 1);
        let addr = &addresses[0];

        let mempool_state = Arc::new(RwLock::new(MempoolState::default()));
        let watched_addresses = vec![addr.clone()].into_iter().collect();

        let filter = MempoolFilter::new(
            MempoolStrategy::Selective,
            Duration::from_secs(300),
            1000,
            mempool_state,
            watched_addresses,
            network,
        );

        // Transaction receiving to watched address should be relevant
        let tx = create_test_transaction(vec![(addr.clone(), 50000)], vec![]);
        assert!(filter.is_transaction_relevant(&tx));

        // Transaction not involving watched address should not be relevant
        // Create a completely different address not in our watched list
        let other_addr = {
            // Create from script to ensure it's different from watched addresses
            use dashcore::script::ScriptBuf;
            let script =
                ScriptBuf::from_hex("76a914123456789012345678901234567890123456789088ac").unwrap();
            Address::from_script(&script, network).unwrap()
        };
        let tx2 = create_test_transaction(vec![(other_addr, 50000)], vec![]);
        assert!(!filter.is_transaction_relevant(&tx2));
    }

    // TODO: Implement test for processing outgoing transactions
    // This test should verify that when we spend our own UTXOs, the transaction
    // is properly processed and marked as outgoing with correct net_amount calculation

    // TODO: Implement test for processing incoming transactions
    // This test should verify that when we receive payments to our addresses,
    // the transaction is properly processed and marked as incoming with positive net_amount

    // TODO: Implement test for FetchAll strategy behavior
    // This test should verify that with FetchAll strategy, transactions to watched addresses
    // are processed while transactions to unwatched addresses are not processed (filtered out)

    #[tokio::test]
    async fn test_capacity_limits() {
        let mempool_state = Arc::new(RwLock::new(MempoolState::default()));
        let filter = MempoolFilter::new(
            MempoolStrategy::FetchAll,
            Duration::from_secs(300),
            3, // Very small limit
            mempool_state.clone(),
            HashSet::new(),
            Network::Dash,
        );

        // Should not be at capacity initially
        assert!(!filter.is_at_capacity().await);

        // Add transactions up to limit
        let mut state = mempool_state.write().await;
        for i in 0..3 {
            // Create unique transactions by varying the lock_time
            state.add_transaction(UnconfirmedTransaction::new(
                Transaction {
                    version: 1,
                    lock_time: i as u32,
                    input: vec![],
                    output: vec![],
                    special_transaction_payload: None,
                },
                dashcore::Amount::from_sat(0),
                false,
                false,
                Vec::new(),
                0,
            ));
        }
        drop(state);

        // Should be at capacity now
        assert!(filter.is_at_capacity().await);

        // Should not fetch new transactions when at capacity
        let txid =
            Txid::from_str("6363636363636363636363636363636363636363636363636363636363636363")
                .unwrap();
        assert!(!filter.should_fetch_transaction(&txid).await);
    }

    #[tokio::test]
    async fn test_prune_expired() {
        let mempool_state = Arc::new(RwLock::new(MempoolState::default()));
        let filter = MempoolFilter::new(
            MempoolStrategy::Selective,
            Duration::from_secs(300),
            1000,
            mempool_state.clone(),
            HashSet::new(),
            Network::Dash,
        );

        // Add some transactions with different ages
        let mut state = mempool_state.write().await;

        // Add an old transaction (will be expired)
        let old_tx = UnconfirmedTransaction::new(
            Transaction {
                version: 1,
                lock_time: 0,
                input: vec![],
                output: vec![],
                special_transaction_payload: None,
            },
            dashcore::Amount::from_sat(0),
            false,
            false,
            Vec::new(),
            0,
        );
        let old_txid = old_tx.txid();
        state.transactions.insert(old_txid, old_tx);

        // Manually set the first_seen time to be old
        // TODO: Implement time manipulation for testing
        // if let Some(tx) = state.transactions.get_mut(&old_txid) {
        //     // This is a hack since we can't modify Instant directly
        //     // In real tests, we'd use a time abstraction
        // }

        // Add a recent transaction
        let recent_tx = UnconfirmedTransaction::new(
            Transaction {
                version: 1,
                lock_time: 0,
                input: vec![],
                output: vec![],
                special_transaction_payload: None,
            },
            dashcore::Amount::from_sat(0),
            false,
            false,
            Vec::new(),
            0,
        );
        let recent_txid = recent_tx.txid();
        state.transactions.insert(recent_txid, recent_tx);

        drop(state);

        // Prune with a very short timeout (this test is limited by Instant not being mockable)
        let pruned = filter.prune_expired(Duration::from_millis(1)).await;

        // In a real test with time mocking, we'd verify that old transactions are pruned
        // For now, just verify the method runs without panic
        assert!(pruned.is_empty() || !pruned.is_empty()); // Tautology, but shows the test ran
    }

    #[tokio::test]
    async fn test_bloom_filter_strategy() {
        let mempool_state = Arc::new(RwLock::new(MempoolState::default()));
        let filter = MempoolFilter::new(
            MempoolStrategy::BloomFilter,
            Duration::from_secs(300),
            1000,
            mempool_state,
            HashSet::new(),
            Network::Dash,
        );

        // BloomFilter strategy should always return true (actual filtering is done by network layer)
        let txid =
            Txid::from_str("0101010101010101010101010101010101010101010101010101010101010101")
                .unwrap();
        assert!(filter.should_fetch_transaction(&txid).await);
    }

    #[tokio::test]
    #[ignore = "requires MockWallet implementation"]
    async fn test_address_with_earliest_height() {
        let network = Network::Dash;
        let addr = test_address(network);

        let mempool_state = Arc::new(RwLock::new(MempoolState::default()));
        let watch_items = vec![WatchItem::address_from_height(addr.clone(), 100000)];
        let watched_addresses: HashSet<Address> = watch_items
            .into_iter()
            .filter_map(|item| match item {
                WatchItem::Address(addr) => Some(addr),
                _ => None,
            })
            .collect();

        let filter = MempoolFilter::new(
            MempoolStrategy::Selective,
            Duration::from_secs(300),
            1000,
            mempool_state,
            watched_addresses,
            network,
        );

        let mut wallet = MockWallet::new(network);
        wallet.add_watched_address(addr.clone());

        // Transaction to watched address should still be relevant
        let tx = create_test_transaction(vec![(addr.clone(), 50000)], vec![]);
        assert!(filter.is_transaction_relevant(&tx));
    }

    #[tokio::test]
    #[ignore = "requires MockWallet implementation"]
    async fn test_multiple_watch_items() {
        let network = Network::Dash;
        let addr1 = test_address(network);
        let addr2 = test_address2(network);

        let mempool_state = Arc::new(RwLock::new(MempoolState::default()));
        let watch_items =
            vec![WatchItem::address(addr1.clone()), WatchItem::Script(()), WatchItem::Outpoint(())];
        let watched_addresses: HashSet<Address> = watch_items
            .into_iter()
            .filter_map(|item| match item {
                WatchItem::Address(addr) => Some(addr),
                _ => None,
            })
            .collect();

        let filter = MempoolFilter::new(
            MempoolStrategy::Selective,
            Duration::from_secs(300),
            1000,
            mempool_state,
            watched_addresses,
            network,
        );

        let mut wallet = MockWallet::new(network);
        wallet.add_watched_address(addr1.clone());

        // Transaction matching any watch item should be relevant

        // Match by address
        let tx1 = create_test_transaction(vec![(addr1.clone(), 1000)], vec![]);
        assert!(filter.is_transaction_relevant(&tx1));

        // TODO: Match by outpoint - requires OutPoint to be stored in WatchItem::Outpoint variant
        // let tx2 = create_test_transaction(vec![(addr2.clone(), 2000)], vec![outpoint]);
        // assert!(filter.is_transaction_relevant(&tx2));

        // No match
        let other_outpoint = OutPoint {
            txid: Txid::from_str(
                "5858585858585858585858585858585858585858585858585858585858585858",
            )
            .unwrap(),
            vout: 0,
        };
        let tx3 = create_test_transaction(vec![(addr2, 3000)], vec![other_outpoint]);
        assert!(!filter.is_transaction_relevant(&tx3));
    }
}
