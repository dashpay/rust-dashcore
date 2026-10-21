use crate::{
    BlockProcessingResult, MempoolTransactionResult, WalletEvent, WalletId, WalletInterface,
};
use dashcore::ephemerealdata::chain_lock::ChainLock;
use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::prelude::CoreBlockHeight;
use dashcore::{Address, Block, OutPoint, ScriptBuf, Transaction, Txid};
use key_wallet::transaction_checking::TransactionContext;
use std::collections::BTreeSet;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};

// Type alias for captured IS lock payloads
type InstantLockCaptures = Arc<Mutex<Vec<(Txid, Option<InstantLock>)>>>;

/// Default wallet ID used by `MockWallet` and `NonMatchingMockWallet` for tests
/// that don't care about per-wallet attribution.
pub const MOCK_WALLET_ID: WalletId = [0u8; 32];

pub struct MockWallet {
    wallet_id: WalletId,
    processed_blocks: Arc<Mutex<Vec<(dashcore::BlockHash, u32)>>>,
    processed_transactions: Arc<Mutex<Vec<dashcore::Txid>>>,
    last_processed_height: CoreBlockHeight,
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
    /// Captured `InstantLock` payloads from both `process_mempool_transaction` and
    /// `process_instant_send_lock`, for test assertions.
    pub processed_instant_locks: InstantLockCaptures,
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
            wallet_id: MOCK_WALLET_ID,
            processed_blocks: Arc::new(Mutex::new(Vec::new())),
            processed_transactions: Arc::new(Mutex::new(Vec::new())),
            last_processed_height: 0,
            synced_height: 0,
            event_sender,
            mempool_relevant: false,
            addresses: Vec::new(),
            outpoints: Vec::new(),
            mempool_net_amount: 0,
            mempool_addresses: Vec::new(),
            mempool_new_addresses: Vec::new(),
            status_changes: Arc::new(Mutex::new(Vec::new())),
            processed_instant_locks: Arc::new(Mutex::new(Vec::new())),
            monitor_revision: 0,
        }
    }

    /// Override the wallet id used for per-wallet API surfaces.
    pub fn set_wallet_id(&mut self, wallet_id: WalletId) {
        self.wallet_id = wallet_id;
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
    async fn process_block_for_wallets(
        &mut self,
        block: &Block,
        height: u32,
        wallets: &BTreeSet<WalletId>,
    ) -> BlockProcessingResult {
        if !wallets.contains(&self.wallet_id) {
            return BlockProcessingResult::default();
        }
        let mut processed = self.processed_blocks.lock().await;
        processed.push((block.block_hash(), height));
        if height > self.last_processed_height {
            self.last_processed_height = height;
        }

        BlockProcessingResult {
            new_txids: block.txdata.iter().map(|tx| tx.txid()).collect(),
            existing_txids: Vec::new(),
            new_scripts: Default::default(),
        }
    }

    async fn process_mempool_transaction(
        &mut self,
        tx: &Transaction,
        instant_lock: Option<InstantLock>,
    ) -> MempoolTransactionResult {
        let mut processed = self.processed_transactions.lock().await;
        processed.push(tx.txid());

        let mut locks = self.processed_instant_locks.lock().await;
        locks.push((tx.txid(), instant_lock));
        drop(locks);

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

    fn monitored_script_pubkeys_for(&self, wallet_id: &WalletId) -> Vec<ScriptBuf> {
        if wallet_id == &self.wallet_id {
            self.addresses.iter().map(|a| a.script_pubkey()).collect()
        } else {
            Vec::new()
        }
    }

    fn watched_outpoints(&self) -> Vec<OutPoint> {
        self.outpoints.clone()
    }

    fn last_processed_height(&self) -> CoreBlockHeight {
        self.last_processed_height
    }

    fn synced_height(&self) -> CoreBlockHeight {
        self.synced_height
    }

    fn wallets_behind(&self, height: CoreBlockHeight) -> BTreeSet<WalletId> {
        if self.synced_height < height {
            BTreeSet::from([self.wallet_id])
        } else {
            BTreeSet::new()
        }
    }

    fn wallet_synced_height(&self, wallet_id: &WalletId) -> CoreBlockHeight {
        if wallet_id == &self.wallet_id {
            self.synced_height
        } else {
            0
        }
    }

    fn update_wallet_synced_height(&mut self, wallet_id: &WalletId, height: CoreBlockHeight) {
        if wallet_id == &self.wallet_id && height > self.synced_height {
            self.synced_height = height;
        }
    }

    fn update_wallet_last_processed_height(
        &mut self,
        wallet_id: &WalletId,
        height: CoreBlockHeight,
    ) {
        if wallet_id == &self.wallet_id && height > self.last_processed_height {
            self.last_processed_height = height;
        }
    }

    fn monitor_revision(&self) -> u64 {
        self.monitor_revision
    }

    fn subscribe_events(&self) -> broadcast::Receiver<WalletEvent> {
        self.event_sender.subscribe()
    }

    fn process_instant_send_lock(&mut self, instant_lock: InstantLock) {
        let txid = instant_lock.txid;
        let mut locks = self
            .processed_instant_locks
            .try_lock()
            .expect("processed_instant_locks lock contention in test helper");
        locks.push((txid, Some(instant_lock.clone())));
        drop(locks);

        let mut changes =
            self.status_changes.try_lock().expect("status_changes lock contention in test helper");
        changes.push((txid, TransactionContext::InstantSend(instant_lock)));
    }

    fn apply_chain_lock(&mut self, _chain_lock: ChainLock) {
        panic!("apply_chain_lock not supported for MockWallet");
    }
}

/// Mock wallet that returns false for filter checks
pub struct NonMatchingMockWallet {
    wallet_id: WalletId,
    last_processed_height: CoreBlockHeight,
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
            wallet_id: MOCK_WALLET_ID,
            last_processed_height: 0,
            synced_height: 0,
            event_sender,
        }
    }
}

#[async_trait::async_trait]
impl WalletInterface for NonMatchingMockWallet {
    async fn process_block_for_wallets(
        &mut self,
        _block: &Block,
        height: u32,
        wallets: &BTreeSet<WalletId>,
    ) -> BlockProcessingResult {
        if wallets.contains(&self.wallet_id) && height > self.last_processed_height {
            self.last_processed_height = height;
        }
        BlockProcessingResult::default()
    }

    async fn process_mempool_transaction(
        &mut self,
        _tx: &Transaction,
        _instant_lock: Option<InstantLock>,
    ) -> MempoolTransactionResult {
        MempoolTransactionResult::default()
    }

    fn monitored_addresses(&self) -> Vec<Address> {
        Vec::new()
    }

    fn monitored_script_pubkeys_for(&self, _wallet_id: &WalletId) -> Vec<ScriptBuf> {
        Vec::new()
    }

    fn watched_outpoints(&self) -> Vec<OutPoint> {
        Vec::new()
    }

    fn last_processed_height(&self) -> CoreBlockHeight {
        self.last_processed_height
    }

    fn synced_height(&self) -> CoreBlockHeight {
        self.synced_height
    }

    fn wallets_behind(&self, height: CoreBlockHeight) -> BTreeSet<WalletId> {
        if self.synced_height < height {
            BTreeSet::from([self.wallet_id])
        } else {
            BTreeSet::new()
        }
    }

    fn wallet_synced_height(&self, wallet_id: &WalletId) -> CoreBlockHeight {
        if wallet_id == &self.wallet_id {
            self.synced_height
        } else {
            0
        }
    }

    fn update_wallet_synced_height(&mut self, wallet_id: &WalletId, height: CoreBlockHeight) {
        if wallet_id == &self.wallet_id && height > self.synced_height {
            self.synced_height = height;
        }
    }

    fn update_wallet_last_processed_height(
        &mut self,
        wallet_id: &WalletId,
        height: CoreBlockHeight,
    ) {
        if wallet_id == &self.wallet_id && height > self.last_processed_height {
            self.last_processed_height = height;
        }
    }

    fn subscribe_events(&self) -> broadcast::Receiver<WalletEvent> {
        self.event_sender.subscribe()
    }

    fn apply_chain_lock(&mut self, _chain_lock: ChainLock) {
        panic!("apply_chain_lock not supported for NonMatchingMockWallet");
    }

    async fn describe(&self) -> String {
        "NonMatchingWallet (test implementation)".to_string()
    }
}

/// Per-wallet state held inside `MultiMockWallet`.
#[derive(Default)]
pub struct MockWalletState {
    pub addresses: Vec<Address>,
    pub synced_height: CoreBlockHeight,
    pub last_processed_height: CoreBlockHeight,
}

/// Multi-wallet mock that holds independent state for several wallet IDs,
/// enabling tests that exercise per-wallet attribution paths.
pub struct MultiMockWallet {
    wallets: std::collections::BTreeMap<WalletId, MockWalletState>,
    event_sender: broadcast::Sender<WalletEvent>,
    /// Track every block processed for assertions.
    processed: Arc<Mutex<Vec<(WalletId, dashcore::BlockHash, u32)>>>,
}

impl Default for MultiMockWallet {
    fn default() -> Self {
        Self::new()
    }
}

impl MultiMockWallet {
    pub fn new() -> Self {
        let (event_sender, _) = broadcast::channel(16);
        Self {
            wallets: std::collections::BTreeMap::new(),
            event_sender,
            processed: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Insert or replace a wallet's state.
    pub fn insert_wallet(&mut self, wallet_id: WalletId, state: MockWalletState) {
        self.wallets.insert(wallet_id, state);
    }

    /// Mutable access to a wallet's state, panicking if absent.
    pub fn wallet_mut(&mut self, wallet_id: &WalletId) -> &mut MockWalletState {
        self.wallets.get_mut(wallet_id).expect("wallet present")
    }

    pub fn processed(&self) -> Arc<Mutex<Vec<(WalletId, dashcore::BlockHash, u32)>>> {
        self.processed.clone()
    }
}

#[async_trait::async_trait]
impl WalletInterface for MultiMockWallet {
    async fn process_block_for_wallets(
        &mut self,
        block: &Block,
        height: CoreBlockHeight,
        wallets: &BTreeSet<WalletId>,
    ) -> BlockProcessingResult {
        let hash = block.block_hash();
        let mut processed = self.processed.lock().await;
        for wallet_id in wallets {
            if let Some(state) = self.wallets.get_mut(wallet_id) {
                processed.push((*wallet_id, hash, height));
                if height > state.last_processed_height {
                    state.last_processed_height = height;
                }
            }
        }
        BlockProcessingResult::default()
    }

    async fn process_mempool_transaction(
        &mut self,
        _tx: &Transaction,
        _instant_lock: Option<InstantLock>,
    ) -> MempoolTransactionResult {
        MempoolTransactionResult::default()
    }

    fn monitored_addresses(&self) -> Vec<Address> {
        self.wallets.values().flat_map(|s| s.addresses.iter().cloned()).collect()
    }

    fn monitored_script_pubkeys_for(&self, wallet_id: &WalletId) -> Vec<ScriptBuf> {
        self.wallets
            .get(wallet_id)
            .map(|s| s.addresses.iter().map(|a| a.script_pubkey()).collect())
            .unwrap_or_default()
    }

    fn watched_outpoints(&self) -> Vec<OutPoint> {
        Vec::new()
    }

    fn last_processed_height(&self) -> CoreBlockHeight {
        self.wallets.values().map(|s| s.last_processed_height).max().unwrap_or(0)
    }

    fn synced_height(&self) -> CoreBlockHeight {
        self.wallets.values().map(|s| s.synced_height).min().unwrap_or(0)
    }

    fn wallets_behind(&self, height: CoreBlockHeight) -> BTreeSet<WalletId> {
        self.wallets
            .iter()
            .filter_map(|(id, s)| {
                if s.synced_height < height {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect()
    }

    fn wallet_synced_height(&self, wallet_id: &WalletId) -> CoreBlockHeight {
        self.wallets.get(wallet_id).map(|s| s.synced_height).unwrap_or(0)
    }

    fn update_wallet_synced_height(&mut self, wallet_id: &WalletId, height: CoreBlockHeight) {
        if let Some(state) = self.wallets.get_mut(wallet_id) {
            if height > state.synced_height {
                state.synced_height = height;
            }
        }
    }

    fn update_wallet_last_processed_height(
        &mut self,
        wallet_id: &WalletId,
        height: CoreBlockHeight,
    ) {
        if let Some(state) = self.wallets.get_mut(wallet_id) {
            if height > state.last_processed_height {
                state.last_processed_height = height;
            }
        }
    }

    fn subscribe_events(&self) -> broadcast::Receiver<WalletEvent> {
        self.event_sender.subscribe()
    }

    fn apply_chain_lock(&mut self, _chain_lock: ChainLock) {
        panic!("apply_chain_lock not supported for MultiMockWallet");
    }

    async fn describe(&self) -> String {
        "MultiMockWallet (test implementation)".to_string()
    }
}
