use std::{collections::BTreeMap, sync::Arc};

use dashcore::{Block, Transaction, Txid};
use tokio::sync::Mutex;

use crate::wallet_interface::WalletInterface;

pub struct MockWallet {
    processed_blocks: Arc<Mutex<Vec<(dashcore::BlockHash, u32)>>>,
    processed_transactions: Arc<Mutex<Vec<dashcore::Txid>>>,
    // Map txid -> (net_amount, addresses)
    effects: Arc<Mutex<BTreeMap<Txid, (i64, Vec<String>)>>>,
}

impl MockWallet {
    pub fn new() -> Self {
        Self {
            processed_blocks: Arc::new(Mutex::new(Vec::new())),
            processed_transactions: Arc::new(Mutex::new(Vec::new())),
            effects: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
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
    async fn process_block(&mut self, block: &Block, height: u32) -> Vec<dashcore::Txid> {
        let mut processed = self.processed_blocks.lock().await;
        processed.push((block.block_hash(), height));

        // Return txids of all transactions in block as "relevant"
        block.txdata.iter().map(|tx| tx.txid()).collect()
    }

    async fn process_mempool_transaction(&mut self, tx: &Transaction) {
        let mut processed = self.processed_transactions.lock().await;
        processed.push(tx.txid());
    }

    async fn check_compact_filter(
        &mut self,
        _filter: &dashcore::bip158::BlockFilter,
        _block_hash: &dashcore::BlockHash,
    ) -> bool {
        // Return true for all filters in test
        true
    }

    async fn describe(&self) -> String {
        "MockWallet (test implementation)".to_string()
    }

    async fn transaction_effect(&self, tx: &Transaction) -> Option<(i64, Vec<String>)> {
        let map = self.effects.lock().await;
        map.get(&tx.txid()).cloned()
    }
}
