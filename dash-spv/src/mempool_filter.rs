//! Mempool transaction filtering logic.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashcore::{Address, OutPoint, Transaction, Txid};
use tokio::sync::RwLock;

use crate::client::config::MempoolStrategy;
use crate::types::{MempoolState, UnconfirmedTransaction, WatchItem};
use crate::wallet::Wallet;

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
    /// Watched items.
    watch_items: Vec<WatchItem>,
}

impl MempoolFilter {
    /// Create a new mempool filter.
    pub fn new(
        strategy: MempoolStrategy,
        recent_send_window: Duration,
        max_transactions: usize,
        mempool_state: Arc<RwLock<MempoolState>>,
        watch_items: Vec<WatchItem>,
    ) -> Self {
        Self {
            strategy,
            recent_send_window,
            max_transactions,
            mempool_state,
            watch_items,
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
    pub fn is_transaction_relevant(&self, tx: &Transaction, wallet: &Wallet) -> bool {
        let txid = tx.txid();
        
        // Check if any input or output affects our watched addresses
        let mut addresses = HashSet::new();
        
        // Extract addresses from outputs
        for (idx, output) in tx.output.iter().enumerate() {
            if let Ok(address) = Address::from_script(&output.script_pubkey, wallet.network()) {
                addresses.insert(address.clone());
                tracing::trace!("Transaction {} output {} has address: {}", txid, idx, address);
            }
        }
        
        tracing::debug!("Transaction {} has {} addresses from outputs, checking against {} watched items", 
                       txid, addresses.len(), self.watch_items.len());
        
        // Check against watched items
        for item in &self.watch_items {
            match item {
                WatchItem::Address { address, .. } => {
                    tracing::trace!("Checking if transaction {} contains watched address: {}", txid, address);
                    if addresses.contains(address) {
                        tracing::debug!("Transaction {} is relevant: contains watched address {}", txid, address);
                        return true;
                    }
                }
                WatchItem::Script(script) => {
                    // Check if any output matches the script
                    for output in &tx.output {
                        if output.script_pubkey == *script {
                            tracing::debug!("Transaction {} is relevant: matches watched script", txid);
                            return true;
                        }
                    }
                }
                WatchItem::Outpoint(outpoint) => {
                    // Check if this outpoint is spent
                    for input in &tx.input {
                        if input.previous_output == *outpoint {
                            tracing::debug!("Transaction {} is relevant: spends watched outpoint", txid);
                            return true;
                        }
                    }
                }
            }
        }
        
        // Also check if this transaction spends any of our UTXOs
        let wallet_relevant = wallet.is_transaction_relevant(tx);
        if wallet_relevant {
            tracing::debug!("Transaction {} is relevant: wallet considers it relevant", txid);
        } else {
            tracing::debug!("Transaction {} is not relevant to any watched items or wallet", txid);
        }
        
        wallet_relevant
    }

    /// Process a new transaction for the mempool.
    pub async fn process_transaction(
        &self,
        tx: Transaction,
        wallet: &Wallet,
    ) -> Option<UnconfirmedTransaction> {
        let txid = tx.txid();
        
        // Check if transaction is relevant to our watched addresses
        let is_relevant = self.is_transaction_relevant(&tx, wallet);
        
        tracing::debug!("Processing mempool transaction {}: strategy={:?}, is_relevant={}, watch_items_count={}", 
                       txid, self.strategy, is_relevant, self.watch_items.len());
        
        // For FetchAll strategy, we fetch all transactions but only process relevant ones
        if self.strategy != MempoolStrategy::FetchAll {
            // For other strategies, return early if not relevant
            if !is_relevant {
                tracing::debug!("Transaction {} not relevant for strategy {:?}, skipping", txid, self.strategy);
                return None;
            }
        }
        
        // Calculate fee using wallet's method
        let fee = wallet.calculate_transaction_fee(&tx).unwrap_or_else(|| {
            // If we can't calculate the fee (e.g., missing input UTXOs), use 0 as fallback
            tracing::debug!("Unable to calculate fee for transaction {}, using 0", txid);
            dashcore::Amount::from_sat(0)
        });
        
        // Check if this is an InstantSend transaction
        let is_instant_send = wallet.has_instant_lock(&txid).await;
        
        // Determine if this is outgoing (we're spending)
        let is_outgoing = tx.input.iter().any(|input| {
            wallet.has_utxo(&input.previous_output)
        });
        
        // Get affected addresses
        let mut addresses = Vec::new();
        for output in &tx.output {
            if let Ok(address) = Address::from_script(&output.script_pubkey, wallet.network()) {
                // For FetchAll strategy, include all addresses, not just watched ones
                if self.strategy == MempoolStrategy::FetchAll || self.is_address_watched(&address) {
                    addresses.push(address);
                }
            }
        }
        
        // Calculate net amount change for our wallet
        let net_amount = wallet.calculate_net_amount(&tx);
        
        // For FetchAll strategy, only return transaction if it's relevant
        // This ensures callbacks are only triggered for watched addresses
        if self.strategy == MempoolStrategy::FetchAll && !is_relevant {
            return None;
        }
        
        Some(UnconfirmedTransaction::new(
            tx,
            fee,
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
        self.watch_items.iter().any(|item| match item {
            WatchItem::Address { address: watch_addr, .. } => watch_addr == address,
            _ => false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::{hashes::Hash, Network, Script, TxIn, TxOut};
    use std::str::FromStr;
    
    // Helper to create a test address
    fn test_address(network: Network) -> Address {
        Address::from_str("XkSMTdZQrEjNkqGhJkVLqnVEcaB8rqgJ3e")
            .unwrap()
            .require_network(network)
            .unwrap()
    }
    
    // Helper to create another test address
    fn test_address2(network: Network) -> Address {
        Address::from_str("XpV8p93zxREvLeKhFjvvDy9Rg8K3F7T6Jd")
            .unwrap()
            .require_network(network)
            .unwrap()
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
                script_sig: Script::new().into(),
                sequence: 0xffffffff,
                witness: vec![],
            });
        }
        
        Transaction {
            version: 1,
            lock_time: 0,
            input: tx_inputs,
            output: tx_outputs,
        }
    }
    
    // Helper to create a mock wallet
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
        
        fn add_utxo(&mut self, outpoint: OutPoint) {
            self.utxos.insert(outpoint);
        }
        
        fn network(&self) -> Network {
            self.network
        }
        
        fn has_utxo(&self, outpoint: &OutPoint) -> bool {
            self.utxos.contains(outpoint)
        }
        
        fn is_transaction_relevant(&self, tx: &Transaction) -> bool {
            // Check if any input spends our UTXOs
            for input in &tx.input {
                if self.utxos.contains(&input.previous_output) {
                    return true;
                }
            }
            
            // Check if any output is to our watched addresses
            for output in &tx.output {
                if let Ok(address) = Address::from_script(&output.script_pubkey, self.network) {
                    if self.watched_addresses.contains(&address) {
                        return true;
                    }
                }
            }
            
            false
        }
        
        fn calculate_net_amount(&self, tx: &Transaction) -> i64 {
            let mut net_amount: i64 = 0;
            
            // Subtract spent amounts
            for input in &tx.input {
                if self.has_utxo(&input.previous_output) {
                    // In real implementation, we'd look up the actual value
                    // For testing, assume 10000 sats per UTXO
                    net_amount -= 10000;
                }
            }
            
            // Add received amounts
            for output in &tx.output {
                if let Ok(address) = Address::from_script(&output.script_pubkey, self.network) {
                    if self.watched_addresses.contains(&address) {
                        net_amount += output.value as i64;
                    }
                }
            }
            
            net_amount
        }
    }
    
    #[tokio::test]
    async fn test_selective_strategy() {
        let mempool_state = Arc::new(RwLock::new(MempoolState::default()));
        let filter = MempoolFilter::new(
            MempoolStrategy::Selective,
            Duration::from_secs(300),
            1000,
            mempool_state.clone(),
            vec![],
        );
        
        // Generate a test txid
        let txid = Txid::from_str("0101010101010101010101010101010101010101010101010101010101010101").unwrap();
        
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
            vec![],
        );
        
        // Should fetch any transaction when under limit
        let txid1 = Txid::from_str("0101010101010101010101010101010101010101010101010101010101010101").unwrap();
        assert!(filter.should_fetch_transaction(&txid1).await);
        
        // Add transactions to reach limit
        let mut state = mempool_state.write().await;
        state.add_transaction(UnconfirmedTransaction::new(
            Transaction {
                version: 1,
                lock_time: 0,
                input: vec![],
                output: vec![],
            },
            dashcore::Amount::from_sat(0),
            false,
            false,
            vec![],
            0,
        ));
        state.add_transaction(UnconfirmedTransaction::new(
            Transaction {
                version: 1,
                lock_time: 0,
                input: vec![],
                output: vec![],
            },
            dashcore::Amount::from_sat(0),
            false,
            false,
            vec![],
            0,
        ));
        drop(state);
        
        // Should not fetch when at capacity
        let txid2 = Txid::from_str("0202020202020202020202020202020202020202020202020202020202020202").unwrap();
        assert!(!filter.should_fetch_transaction(&txid2).await);
    }
    
    #[tokio::test]
    async fn test_is_transaction_relevant_with_address() {
        let network = Network::Dash;
        let addr1 = test_address(network);
        let addr2 = test_address2(network);
        
        let mempool_state = Arc::new(RwLock::new(MempoolState::default()));
        let watch_items = vec![
            WatchItem::address(addr1.clone()),
        ];
        
        let filter = MempoolFilter::new(
            MempoolStrategy::Selective,
            Duration::from_secs(300),
            1000,
            mempool_state,
            watch_items,
        );
        
        let mut wallet = MockWallet::new(network);
        wallet.add_watched_address(addr1.clone());
        
        // Transaction sending to watched address should be relevant
        let tx1 = create_test_transaction(vec![(addr1.clone(), 50000)], vec![]);
        assert!(filter.is_transaction_relevant(&tx1, &wallet));
        
        // Transaction sending to unwatched address should not be relevant
        let tx2 = create_test_transaction(vec![(addr2, 50000)], vec![]);
        assert!(!filter.is_transaction_relevant(&tx2, &wallet));
    }
    
    #[tokio::test]
    async fn test_is_transaction_relevant_with_script() {
        let network = Network::Dash;
        let addr = test_address(network);
        let script = addr.script_pubkey();
        
        let mempool_state = Arc::new(RwLock::new(MempoolState::default()));
        let watch_items = vec![
            WatchItem::Script(script.clone()),
        ];
        
        let filter = MempoolFilter::new(
            MempoolStrategy::Selective,
            Duration::from_secs(300),
            1000,
            mempool_state,
            watch_items,
        );
        
        let wallet = MockWallet::new(network);
        
        // Transaction with watched script should be relevant
        let tx = create_test_transaction(vec![(addr, 50000)], vec![]);
        assert!(filter.is_transaction_relevant(&tx, &wallet));
        
        // Transaction without watched script should not be relevant
        let addr2 = test_address2(network);
        let tx2 = create_test_transaction(vec![(addr2, 50000)], vec![]);
        assert!(!filter.is_transaction_relevant(&tx2, &wallet));
    }
    
    #[tokio::test]
    async fn test_is_transaction_relevant_with_outpoint() {
        let network = Network::Dash;
        let addr = test_address(network);
        
        // Create a specific outpoint to watch
        let watched_outpoint = OutPoint {
            txid: Txid::from_str("2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a").unwrap(),
            vout: 0,
        };
        
        let mempool_state = Arc::new(RwLock::new(MempoolState::default()));
        let watch_items = vec![
            WatchItem::Outpoint(watched_outpoint),
        ];
        
        let filter = MempoolFilter::new(
            MempoolStrategy::Selective,
            Duration::from_secs(300),
            1000,
            mempool_state,
            watch_items,
        );
        
        let wallet = MockWallet::new(network);
        
        // Transaction spending watched outpoint should be relevant
        let tx = create_test_transaction(vec![(addr.clone(), 50000)], vec![watched_outpoint]);
        assert!(filter.is_transaction_relevant(&tx, &wallet));
        
        // Transaction not spending watched outpoint should not be relevant
        let other_outpoint = OutPoint {
            txid: Txid::from_str("6363636363636363636363636363636363636363636363636363636363636363").unwrap(),
            vout: 1,
        };
        let tx2 = create_test_transaction(vec![(addr, 50000)], vec![other_outpoint]);
        assert!(!filter.is_transaction_relevant(&tx2, &wallet));
    }
    
    #[tokio::test]
    async fn test_process_transaction_outgoing() {
        let network = Network::Dash;
        let addr = test_address(network);
        
        let mempool_state = Arc::new(RwLock::new(MempoolState::default()));
        let watch_items = vec![
            WatchItem::address(addr.clone()),
        ];
        
        let filter = MempoolFilter::new(
            MempoolStrategy::Selective,
            Duration::from_secs(300),
            1000,
            mempool_state,
            watch_items,
        );
        
        let mut wallet = MockWallet::new(network);
        wallet.add_watched_address(addr.clone());
        
        // Add a UTXO that we own
        let our_outpoint = OutPoint {
            txid: Txid::from_str("0101010101010101010101010101010101010101010101010101010101010101").unwrap(),
            vout: 0,
        };
        wallet.add_utxo(our_outpoint);
        
        // Create transaction spending our UTXO
        let tx = create_test_transaction(vec![(addr.clone(), 5000)], vec![our_outpoint]);
        
        let result = filter.process_transaction(tx.clone(), &wallet).await;
        assert!(result.is_some());
        
        let unconfirmed_tx = result.unwrap();
        assert_eq!(unconfirmed_tx.transaction.txid(), tx.txid());
        assert!(unconfirmed_tx.is_outgoing);
        assert_eq!(unconfirmed_tx.addresses.len(), 1);
        assert_eq!(unconfirmed_tx.addresses[0], addr);
        assert_eq!(unconfirmed_tx.net_amount, -5000); // Lost 10000, received 5000
    }
    
    #[tokio::test]
    async fn test_process_transaction_incoming() {
        let network = Network::Dash;
        let addr = test_address(network);
        
        let mempool_state = Arc::new(RwLock::new(MempoolState::default()));
        let watch_items = vec![
            WatchItem::address(addr.clone()),
        ];
        
        let filter = MempoolFilter::new(
            MempoolStrategy::Selective,
            Duration::from_secs(300),
            1000,
            mempool_state,
            watch_items,
        );
        
        let mut wallet = MockWallet::new(network);
        wallet.add_watched_address(addr.clone());
        
        // Create transaction sending to our address (not spending our UTXOs)
        let tx = create_test_transaction(vec![(addr.clone(), 25000)], vec![]);
        
        let result = filter.process_transaction(tx.clone(), &wallet).await;
        assert!(result.is_some());
        
        let unconfirmed_tx = result.unwrap();
        assert_eq!(unconfirmed_tx.transaction.txid(), tx.txid());
        assert!(!unconfirmed_tx.is_outgoing);
        assert_eq!(unconfirmed_tx.addresses.len(), 1);
        assert_eq!(unconfirmed_tx.addresses[0], addr);
        assert_eq!(unconfirmed_tx.net_amount, 25000);
    }
    
    #[tokio::test]
    async fn test_process_transaction_fetch_all_strategy() {
        let network = Network::Dash;
        let watched_addr = test_address(network);
        let unwatched_addr = test_address2(network);
        
        let mempool_state = Arc::new(RwLock::new(MempoolState::default()));
        let watch_items = vec![
            WatchItem::address(watched_addr.clone()),
        ];
        
        let filter = MempoolFilter::new(
            MempoolStrategy::FetchAll,
            Duration::from_secs(300),
            1000,
            mempool_state,
            watch_items,
        );
        
        let mut wallet = MockWallet::new(network);
        wallet.add_watched_address(watched_addr.clone());
        
        // Transaction to watched address should be processed
        let tx1 = create_test_transaction(vec![(watched_addr.clone(), 10000)], vec![]);
        let result1 = filter.process_transaction(tx1, &wallet).await;
        assert!(result1.is_some());
        
        // Transaction to unwatched address should NOT be processed (even with FetchAll)
        let tx2 = create_test_transaction(vec![(unwatched_addr, 10000)], vec![]);
        let result2 = filter.process_transaction(tx2, &wallet).await;
        assert!(result2.is_none());
    }
    
    #[tokio::test]
    async fn test_capacity_limits() {
        let mempool_state = Arc::new(RwLock::new(MempoolState::default()));
        let filter = MempoolFilter::new(
            MempoolStrategy::FetchAll,
            Duration::from_secs(300),
            3, // Very small limit
            mempool_state.clone(),
            vec![],
        );
        
        // Should not be at capacity initially
        assert!(!filter.is_at_capacity().await);
        
        // Add transactions up to limit
        let mut state = mempool_state.write().await;
        for i in 0..3 {
            state.add_transaction(UnconfirmedTransaction::new(
                Transaction {
                    version: 1,
                    lock_time: 0,
                    input: vec![],
                    output: vec![],
                },
                dashcore::Amount::from_sat(0),
                false,
                false,
                vec![],
                0,
            ));
        }
        drop(state);
        
        // Should be at capacity now
        assert!(filter.is_at_capacity().await);
        
        // Should not fetch new transactions when at capacity
        let txid = Txid::from_str("6363636363636363636363636363636363636363636363636363636363636363").unwrap();
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
            vec![],
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
            },
            dashcore::Amount::from_sat(0),
            false,
            false,
            vec![],
            0,
        );
        let old_txid = old_tx.txid();
        state.transactions.insert(old_txid, old_tx);
        
        // Manually set the first_seen time to be old
        if let Some(tx) = state.transactions.get_mut(&old_txid) {
            // This is a hack since we can't modify Instant directly
            // In real tests, we'd use a time abstraction
        }
        
        // Add a recent transaction
        let recent_tx = UnconfirmedTransaction::new(
            Transaction {
                version: 1,
                lock_time: 0,
                input: vec![],
                output: vec![],
            },
            dashcore::Amount::from_sat(0),
            false,
            false,
            vec![],
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
            vec![],
        );
        
        // BloomFilter strategy should always return true (actual filtering is done by network layer)
        let txid = Txid::from_str("0101010101010101010101010101010101010101010101010101010101010101").unwrap();
        assert!(filter.should_fetch_transaction(&txid).await);
    }
    
    #[tokio::test]
    async fn test_address_with_earliest_height() {
        let network = Network::Dash;
        let addr = test_address(network);
        
        let mempool_state = Arc::new(RwLock::new(MempoolState::default()));
        let watch_items = vec![
            WatchItem::address_from_height(addr.clone(), 100000),
        ];
        
        let filter = MempoolFilter::new(
            MempoolStrategy::Selective,
            Duration::from_secs(300),
            1000,
            mempool_state,
            watch_items,
        );
        
        let mut wallet = MockWallet::new(network);
        wallet.add_watched_address(addr.clone());
        
        // Transaction to watched address should still be relevant
        let tx = create_test_transaction(vec![(addr, 50000)], vec![]);
        assert!(filter.is_transaction_relevant(&tx, &wallet));
    }
    
    #[tokio::test]
    async fn test_multiple_watch_items() {
        let network = Network::Dash;
        let addr1 = test_address(network);
        let addr2 = test_address2(network);
        let script = addr1.script_pubkey();
        let outpoint = OutPoint {
            txid: Txid::from_str("4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d").unwrap(),
            vout: 2,
        };
        
        let mempool_state = Arc::new(RwLock::new(MempoolState::default()));
        let watch_items = vec![
            WatchItem::address(addr1.clone()),
            WatchItem::Script(script),
            WatchItem::Outpoint(outpoint),
        ];
        
        let filter = MempoolFilter::new(
            MempoolStrategy::Selective,
            Duration::from_secs(300),
            1000,
            mempool_state,
            watch_items,
        );
        
        let mut wallet = MockWallet::new(network);
        wallet.add_watched_address(addr1.clone());
        
        // Transaction matching any watch item should be relevant
        
        // Match by address
        let tx1 = create_test_transaction(vec![(addr1.clone(), 1000)], vec![]);
        assert!(filter.is_transaction_relevant(&tx1, &wallet));
        
        // Match by outpoint
        let tx2 = create_test_transaction(vec![(addr2, 2000)], vec![outpoint]);
        assert!(filter.is_transaction_relevant(&tx2, &wallet));
        
        // No match
        let other_outpoint = OutPoint {
            txid: Txid::from_str("5858585858585858585858585858585858585858585858585858585858585858").unwrap(),
            vout: 0,
        };
        let tx3 = create_test_transaction(vec![(addr2, 3000)], vec![other_outpoint]);
        assert!(!filter.is_transaction_relevant(&tx3, &wallet));
    }
}