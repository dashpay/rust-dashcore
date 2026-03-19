use dashcore::{Address, Network, Transaction, Txid};

use crate::{
    account::{ManagedCoreAccount, TransactionRecord},
    transaction_checking::{TransactionCheckResult, TransactionContext, WalletTransactionChecker},
    wallet::{initialization::WalletAccountCreationOptions, ManagedWalletInfo},
    ExtendedPubKey, Utxo, Wallet,
};

impl ManagedWalletInfo {
    pub fn dummy(id: u8) -> Self {
        ManagedWalletInfo::new(Network::Regtest, [id; 32])
    }
}

use crate::manager::MempoolTransactionResult;
use crate::manager::{BlockProcessingResult, WalletEvent, WalletInterface};
use dashcore::address::NetworkUnchecked;
use dashcore::prelude::CoreBlockHeight;
use dashcore::{Block, OutPoint};
use std::str::FromStr;
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::{broadcast, Mutex};

// Type alias for transaction effects map
type TransactionEffectsMap = Arc<Mutex<BTreeMap<Txid, (i64, Vec<String>)>>>;

pub struct MockWallet {
    processed_blocks: Arc<Mutex<Vec<(dashcore::BlockHash, u32)>>>,
    processed_transactions: Arc<Mutex<Vec<dashcore::Txid>>>,
    // Map txid -> (net_amount, addresses)
    effects: TransactionEffectsMap,
    synced_height: CoreBlockHeight,
    event_sender: broadcast::Sender<WalletEvent>,
    /// When true, process_mempool_transaction returns is_relevant=true.
    mempool_relevant: bool,
    /// Addresses returned by monitored_addresses.
    addresses: Vec<Address>,
    /// Outpoints returned by watched_outpoints.
    outpoints: Vec<OutPoint>,
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
            effects: Arc::new(Mutex::new(BTreeMap::new())),
            synced_height: 0,
            event_sender,
            mempool_relevant: false,
            addresses: Vec::new(),
            outpoints: Vec::new(),
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

    /// Set new addresses returned by process_mempool_transaction.
    pub fn set_mempool_new_addresses(&mut self, addresses: Vec<Address>) {
        self.mempool_new_addresses = addresses;
    }

    pub fn status_changes(&self) -> Arc<Mutex<Vec<(Txid, TransactionContext)>>> {
        self.status_changes.clone()
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

        let effects = self.effects.lock().await;
        let (net_amount, addresses) = if let Some((net, addr_strs)) = effects.get(&tx.txid()) {
            let addrs = addr_strs
                .iter()
                .filter_map(|s| {
                    Address::<NetworkUnchecked>::from_str(s).ok().map(|a| a.assume_checked())
                })
                .collect();
            (*net, addrs)
        } else {
            (0, Vec::new())
        };

        MempoolTransactionResult {
            is_relevant: true,
            net_amount,
            is_outgoing: net_amount < 0,
            addresses,
            new_addresses: self.mempool_new_addresses.clone(),
        }
    }

    async fn describe(&self) -> String {
        "MockWallet (test implementation)".to_string()
    }

    async fn transaction_effect(&self, tx: &Transaction) -> Option<(i64, Vec<String>)> {
        let map = self.effects.lock().await;
        map.get(&tx.txid()).cloned()
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

/// Pre-built wallet context for transaction checking tests.
///
/// Provides a testnet wallet with a default BIP44 account, a pre-derived
/// receive address, and the corresponding extended public key.
pub struct TestWalletContext {
    pub managed_wallet: ManagedWalletInfo,
    pub wallet: Wallet,
    pub receive_address: Address,
    pub xpub: ExtendedPubKey,
}

impl TestWalletContext {
    /// Creates a new random testnet wallet with a BIP44 account and one
    /// pre-derived receive address.
    pub fn new_random() -> Self {
        let wallet = Wallet::new_random(Network::Testnet, WalletAccountCreationOptions::Default)
            .expect("Should create wallet");
        let mut managed_wallet =
            ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

        let xpub = wallet
            .accounts
            .standard_bip44_accounts
            .get(&0)
            .expect("Should have BIP44 account")
            .account_xpub;

        let receive_address = managed_wallet
            .first_bip44_managed_account_mut()
            .expect("Should have managed account")
            .next_receive_address(Some(&xpub), true)
            .expect("Should get address");

        Self {
            managed_wallet,
            wallet,
            receive_address,
            xpub,
        }
    }

    /// Returns the first BIP44 managed account (immutable).
    pub fn bip44_account(&self) -> &ManagedCoreAccount {
        self.managed_wallet.first_bip44_managed_account().expect("Should have BIP44 account")
    }

    /// Returns a transaction record by txid from the first BIP44 account.
    pub fn transaction(&self, txid: &Txid) -> &TransactionRecord {
        self.bip44_account().transactions.get(txid).expect("Should have transaction")
    }

    /// Returns the first UTXO from the first BIP44 account.
    pub fn first_utxo(&self) -> &Utxo {
        self.bip44_account().utxos.values().next().expect("Should have UTXO")
    }

    /// Processes a transaction: runs `check_core_transaction` with `update_state = true`.
    pub async fn check_transaction(
        &mut self,
        tx: &Transaction,
        context: TransactionContext,
    ) -> TransactionCheckResult {
        self.managed_wallet.check_core_transaction(tx, context, &mut self.wallet, true, true).await
    }

    /// Funds the wallet's receive address via a mempool transaction and
    /// asserts it was accepted. Returns the context and the funding transaction.
    pub async fn with_mempool_funding(mut self, amount: u64) -> (Self, Transaction) {
        let tx = Transaction::dummy(&self.receive_address, 0..1, &[amount]);

        let result = self.check_transaction(&tx, TransactionContext::Mempool).await;
        assert!(result.is_relevant);
        assert!(result.is_new_transaction);

        (self, tx)
    }
}
