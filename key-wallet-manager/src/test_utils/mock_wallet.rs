use crate::{BlockProcessingResult, MempoolTransactionResult, WalletEvent, WalletInterface};
use dashcore::prelude::CoreBlockHeight;
use dashcore::{Address, Block, OutPoint, Transaction, Txid};
use key_wallet::transaction_checking::TransactionContext;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};

pub struct MockWallet {
    processed_blocks: Arc<Mutex<Vec<(dashcore::BlockHash, u32)>>>,
    processed_transactions: Arc<Mutex<Vec<dashcore::Txid>>>,
    synced_height: CoreBlockHeight,
    event_sender: broadcast::Sender<WalletEvent>,
    /// When true, process_mempool_transaction returns is_relevant=true.
    mempool_relevant: bool,
    /// Addresses returned by monitored_addresses.
    addresses: Vec<Address>,
    /// Outpoints returned by watched_outpoints.
    outpoints: Vec<OutPoint>,
    /// Net amount returned by process_mempool_transaction.
    mempool_net_amount: i64,
    /// Addresses returned by process_mempool_transaction.
    mempool_addresses: Vec<Address>,
    /// New addresses returned by process_mempool_transaction.
    mempool_new_addresses: Vec<Address>,
    /// Recorded status change notifications for test assertions.
    status_changes: Arc<Mutex<Vec<(Txid, TransactionContext)>>>,
    /// Monitor revision counter for staleness detection.
    monitor_revision: u64,
}

impl Default for MockWallet {
    fn default() -> Self {
        Self::new()
    }
}

impl MockWallet {
    pub fn new() -> Self {
        let (event_sender, _) = broadcast::channel(16);
        Self {
            processed_blocks: Arc::new(Mutex::new(Vec::new())),
            processed_transactions: Arc::new(Mutex::new(Vec::new())),
            synced_height: 0,
            event_sender,
            mempool_relevant: false,
            addresses: Vec::new(),
            outpoints: Vec::new(),
            mempool_net_amount: 0,
            mempool_addresses: Vec::new(),
            mempool_new_addresses: Vec::new(),
            status_changes: Arc::new(Mutex::new(Vec::new())),
            monitor_revision: 0,
        }
    }

    /// Configure whether mempool transactions are reported as relevant.
    pub fn set_mempool_relevant(&mut self, relevant: bool) {
        self.mempool_relevant = relevant;
    }

    /// Set the addresses returned by monitored_addresses.
    pub fn set_addresses(&mut self, addresses: Vec<Address>) {
        self.addresses = addresses;
        self.monitor_revision += 1;
    }

    /// Set the outpoints returned by watched_outpoints.
    pub fn set_outpoints(&mut self, outpoints: Vec<OutPoint>) {
        self.outpoints = outpoints;
        self.monitor_revision += 1;
    }

    /// Set the net amount returned by process_mempool_transaction.
    pub fn set_mempool_net_amount(&mut self, amount: i64) {
        self.mempool_net_amount = amount;
    }

    /// Set the addresses returned by process_mempool_transaction.
    pub fn set_mempool_addresses(&mut self, addresses: Vec<Address>) {
        self.mempool_addresses = addresses;
    }

    /// Set new addresses returned by process_mempool_transaction.
    pub fn set_mempool_new_addresses(&mut self, addresses: Vec<Address>) {
        self.mempool_new_addresses = addresses;
    }

    pub fn status_changes(&self) -> Arc<Mutex<Vec<(Txid, TransactionContext)>>> {
        self.status_changes.clone()
    }

    pub fn processed_blocks(&self) -> Arc<Mutex<Vec<(dashcore::BlockHash, u32)>>> {
        self.processed_blocks.clone()
    }

    pub fn processed_transactions(&self) -> Arc<Mutex<Vec<dashcore::Txid>>> {
        self.processed_transactions.clone()
    }
}

#[async_trait::async_trait]
impl WalletInterface for MockWallet {
    async fn process_block(&mut self, block: &Block, height: u32) -> BlockProcessingResult {
        let mut processed = self.processed_blocks.lock().await;
        processed.push((block.block_hash(), height));

        BlockProcessingResult {
            new_txids: block.txdata.iter().map(|tx| tx.txid()).collect(),
            existing_txids: Vec::new(),
            new_addresses: Vec::new(),
        }
    }

    async fn process_mempool_transaction(
        &mut self,
        tx: &Transaction,
        _is_instant_send: bool,
    ) -> MempoolTransactionResult {
        let mut processed = self.processed_transactions.lock().await;
        processed.push(tx.txid());

        if !self.mempool_relevant {
            return MempoolTransactionResult::default();
        }

        MempoolTransactionResult {
            is_relevant: true,
            net_amount: self.mempool_net_amount,
            is_outgoing: self.mempool_net_amount < 0,
            addresses: self.mempool_addresses.clone(),
            new_addresses: self.mempool_new_addresses.clone(),
        }
    }

    async fn describe(&self) -> String {
        "MockWallet (test implementation)".to_string()
    }

    fn monitored_addresses(&self) -> Vec<Address> {
        self.addresses.clone()
    }

    fn watched_outpoints(&self) -> Vec<OutPoint> {
        self.outpoints.clone()
    }

    fn synced_height(&self) -> CoreBlockHeight {
        self.synced_height
    }

    fn update_synced_height(&mut self, height: CoreBlockHeight) {
        self.synced_height = height;
    }

    fn monitor_revision(&self) -> u64 {
        self.monitor_revision
    }

    fn subscribe_events(&self) -> broadcast::Receiver<WalletEvent> {
        self.event_sender.subscribe()
    }

    fn process_instant_send_lock(&mut self, txid: Txid) {
        let mut changes =
            self.status_changes.try_lock().expect("status_changes lock contention in test helper");
        changes.push((txid, TransactionContext::InstantSend));
    }
}

/// Mock wallet that returns false for filter checks
pub struct NonMatchingMockWallet {
    synced_height: CoreBlockHeight,
    event_sender: broadcast::Sender<WalletEvent>,
}

impl Default for NonMatchingMockWallet {
    fn default() -> Self {
        Self::new()
    }
}

impl NonMatchingMockWallet {
    pub fn new() -> Self {
        let (event_sender, _) = broadcast::channel(16);
        Self {
            synced_height: 0,
            event_sender,
        }
    }
}

#[async_trait::async_trait]
impl WalletInterface for NonMatchingMockWallet {
    async fn process_block(&mut self, _block: &Block, _height: u32) -> BlockProcessingResult {
        BlockProcessingResult::default()
    }

    async fn process_mempool_transaction(
        &mut self,
        _tx: &Transaction,
        _is_instant_send: bool,
    ) -> MempoolTransactionResult {
        MempoolTransactionResult::default()
    }

    fn monitored_addresses(&self) -> Vec<Address> {
        Vec::new()
    }

    fn watched_outpoints(&self) -> Vec<OutPoint> {
        Vec::new()
    }

    fn synced_height(&self) -> CoreBlockHeight {
        self.synced_height
    }

    fn update_synced_height(&mut self, height: CoreBlockHeight) {
        self.synced_height = height;
    }

    fn subscribe_events(&self) -> broadcast::Receiver<WalletEvent> {
        self.event_sender.subscribe()
    }

    async fn describe(&self) -> String {
        "NonMatchingWallet (test implementation)".to_string()
    }
}
