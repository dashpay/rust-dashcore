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
        
        // Calculate fee (this is simplified - in reality we'd need input values)
        let fee = dashcore::Amount::from_sat(0); // TODO: Calculate actual fee
        
        // Check if this is an InstantSend transaction
        let is_instant_send = false; // TODO: Check InstantSend status
        
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
    use dashcore::Network;
    
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
        let txid = Txid::from_slice(&[1u8; 32]).unwrap();
        
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
        let txid1 = Txid::from_slice(&[1u8; 32]).unwrap();
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
        let txid2 = Txid::from_slice(&[2u8; 32]).unwrap();
        assert!(!filter.should_fetch_transaction(&txid2).await);
    }
}