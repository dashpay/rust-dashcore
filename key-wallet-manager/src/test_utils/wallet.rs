use crate::{wallet_interface::WalletInterface, BlockProcessingResult};
use dashcore::prelude::CoreBlockHeight;
use dashcore::{Address, Block, Transaction, Txid};
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::Mutex;

// Type alias for transaction effects map
type TransactionEffectsMap = Arc<Mutex<BTreeMap<Txid, (i64, Vec<String>)>>>;

#[derive(Default)]
pub struct MockWallet {
    processed_blocks: Arc<Mutex<Vec<(dashcore::BlockHash, u32)>>>,
    processed_transactions: Arc<Mutex<Vec<dashcore::Txid>>>,
    // Map txid -> (net_amount, addresses)
    effects: TransactionEffectsMap,
    synced_height: CoreBlockHeight,
}

impl MockWallet {
    pub fn new() -> Self {
        Self {
            processed_blocks: Arc::new(Mutex::new(Vec::new())),
            processed_transactions: Arc::new(Mutex::new(Vec::new())),
            effects: Arc::new(Mutex::new(BTreeMap::new())),
            synced_height: 0,
        }
    }

    pub async fn set_effect(&self, txid: dashcore::Txid, net: i64, addresses: Vec<String>) {
        let mut map = self.effects.lock().await;
        map.insert(txid, (net, addresses));
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

    async fn process_mempool_transaction(&mut self, tx: &Transaction) {
        let mut processed = self.processed_transactions.lock().await;
        processed.push(tx.txid());
    }

    async fn describe(&self) -> String {
        "MockWallet (test implementation)".to_string()
    }

    async fn transaction_effect(&self, tx: &Transaction) -> Option<(i64, Vec<String>)> {
        let map = self.effects.lock().await;
        map.get(&tx.txid()).cloned()
    }

    fn monitored_addresses(&self) -> Vec<Address> {
        Vec::new()
    }

    fn synced_height(&self) -> CoreBlockHeight {
        self.synced_height
    }

    fn update_synced_height(&mut self, height: CoreBlockHeight) {
        self.synced_height = height;
    }
}

/// Mock wallet that returns false for filter checks
#[derive(Default)]
pub struct NonMatchingMockWallet {
    synced_height: CoreBlockHeight,
}

impl NonMatchingMockWallet {
    pub fn new() -> Self {
        Self {
            synced_height: 0,
        }
    }
}

#[async_trait::async_trait]
impl WalletInterface for NonMatchingMockWallet {
    async fn process_block(&mut self, _block: &Block, _height: u32) -> BlockProcessingResult {
        BlockProcessingResult::default()
    }

    async fn process_mempool_transaction(&mut self, _tx: &Transaction) {}

    fn monitored_addresses(&self) -> Vec<Address> {
        Vec::new()
    }

    fn synced_height(&self) -> CoreBlockHeight {
        self.synced_height
    }

    fn update_synced_height(&mut self, height: CoreBlockHeight) {
        self.synced_height = height;
    }

    async fn describe(&self) -> String {
        "NonMatchingWallet (test implementation)".to_string()
    }
}
