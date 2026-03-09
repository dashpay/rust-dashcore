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

use crate::manager::{BlockProcessingResult, WalletEvent, WalletInterface};
use dashcore::prelude::CoreBlockHeight;
use dashcore::Block;
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

    fn subscribe_events(&self) -> broadcast::Receiver<WalletEvent> {
        self.event_sender.subscribe()
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
