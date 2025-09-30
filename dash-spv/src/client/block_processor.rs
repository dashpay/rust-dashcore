//! Block processing functionality for the Dash SPV client.

use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};

use crate::error::{Result, SpvError};
use crate::storage::StorageManager;
use crate::types::{SpvEvent, SpvStats};
use key_wallet_manager::wallet_interface::WalletInterface;

/// Task for the block processing worker.
#[derive(Debug)]
pub enum BlockProcessingTask {
    ProcessBlock {
        block: Box<dashcore::Block>,
        response_tx: oneshot::Sender<Result<()>>,
    },
    ProcessTransaction {
        tx: Box<dashcore::Transaction>,
        response_tx: oneshot::Sender<Result<()>>,
    },
    ProcessCompactFilter {
        filter: dashcore::bip158::BlockFilter,
        block_hash: dashcore::BlockHash,
        response_tx: oneshot::Sender<Result<bool>>,
    },
}

/// Block processing worker that handles blocks in a separate task.
pub struct BlockProcessor<W: WalletInterface, S: StorageManager> {
    receiver: mpsc::UnboundedReceiver<BlockProcessingTask>,
    wallet: Arc<RwLock<W>>,
    storage: Arc<Mutex<S>>,
    stats: Arc<RwLock<SpvStats>>,
    event_tx: mpsc::UnboundedSender<SpvEvent>,
    processed_blocks: HashSet<dashcore::BlockHash>,
    failed: bool,
    network: dashcore::Network,
}

impl<W: WalletInterface + Send + Sync + 'static, S: StorageManager + Send + Sync + 'static>
    BlockProcessor<W, S>
{
    /// Create a new block processor.
    pub fn new(
        receiver: mpsc::UnboundedReceiver<BlockProcessingTask>,
        wallet: Arc<RwLock<W>>,
        storage: Arc<Mutex<S>>,
        stats: Arc<RwLock<SpvStats>>,
        event_tx: mpsc::UnboundedSender<SpvEvent>,
        network: dashcore::Network,
    ) -> Self {
        Self {
            receiver,
            wallet,
            storage,
            stats,
            event_tx,
            processed_blocks: HashSet::new(),
            failed: false,
            network,
        }
    }

    /// Run the block processor worker loop.
    pub async fn run(mut self) {
        tracing::info!("🏭 Block processor worker started");

        while let Some(task) = self.receiver.recv().await {
            // If we're in failed state, reject all new tasks
            if self.failed {
                match task {
                    BlockProcessingTask::ProcessBlock {
                        response_tx,
                        block,
                    } => {
                        let block_hash = block.block_hash();
                        tracing::error!(
                            "❌ Block processor in failed state, rejecting block {}",
                            block_hash
                        );
                        let _ = response_tx
                            .send(Err(SpvError::Config("Block processor has failed".to_string())));
                    }
                    BlockProcessingTask::ProcessTransaction {
                        response_tx,
                        tx,
                    } => {
                        let txid = tx.txid();
                        tracing::error!(
                            "❌ Block processor in failed state, rejecting transaction {}",
                            txid
                        );
                        let _ = response_tx
                            .send(Err(SpvError::Config("Block processor has failed".to_string())));
                    }
                    BlockProcessingTask::ProcessCompactFilter {
                        response_tx,
                        block_hash,
                        ..
                    } => {
                        tracing::error!(
                            "❌ Block processor in failed state, rejecting compact filter for block {}",
                            block_hash
                        );
                        let _ = response_tx
                            .send(Err(SpvError::Config("Block processor has failed".to_string())));
                    }
                }
                continue;
            }

            match task {
                BlockProcessingTask::ProcessBlock {
                    block,
                    response_tx,
                } => {
                    let block_hash = block.block_hash();

                    // Check for duplicate blocks
                    if self.processed_blocks.contains(&block_hash) {
                        tracing::warn!("⚡ Block {} already processed, skipping", block_hash);
                        let _ = response_tx.send(Ok(()));
                        continue;
                    }

                    // Process block and handle errors
                    let result = self.process_block_internal(*block).await;

                    match &result {
                        Ok(()) => {
                            // Mark block as successfully processed
                            self.processed_blocks.insert(block_hash);

                            // Update blocks processed statistics
                            {
                                let mut stats = self.stats.write().await;
                                stats.blocks_processed += 1;
                            }

                            tracing::info!("✅ Block {} processed successfully", block_hash);
                        }
                        Err(e) => {
                            // Log error with block hash and enter failed state
                            tracing::error!(
                                "❌ BLOCK PROCESSING FAILED for block {}: {}",
                                block_hash,
                                e
                            );
                            tracing::error!("❌ Block processor entering failed state - no more blocks will be processed");
                            self.failed = true;
                        }
                    }

                    let _ = response_tx.send(result);
                }
                BlockProcessingTask::ProcessTransaction {
                    tx,
                    response_tx,
                } => {
                    let txid = tx.txid();
                    let result = self.process_transaction_internal(*tx).await;

                    if let Err(e) = &result {
                        tracing::error!("❌ TRANSACTION PROCESSING FAILED for tx {}: {}", txid, e);
                        tracing::error!("❌ Block processor entering failed state");
                        self.failed = true;
                    }

                    let _ = response_tx.send(result);
                }
                BlockProcessingTask::ProcessCompactFilter {
                    filter,
                    block_hash,
                    response_tx,
                } => {
                    // Check compact filter with wallet
                    let mut wallet = self.wallet.write().await;
                    let matches =
                        wallet.check_compact_filter(&filter, &block_hash, self.network).await;

                    if matches {
                        tracing::info!("🎯 Compact filter matched for block {}", block_hash);
                        drop(wallet);
                        // Emit event if filter matched
                        let _ = self.event_tx.send(SpvEvent::CompactFilterMatched {
                            hash: block_hash.to_string(),
                        });
                    } else {
                        tracing::debug!(
                            "Compact filter did not match for block {}, {}",
                            block_hash,
                            wallet.describe(self.network).await
                        );
                        drop(wallet);
                    }

                    let _ = response_tx.send(Ok(matches));
                }
            }
        }

        tracing::info!("🏭 Block processor worker stopped");
    }

    /// Process a block internally.
    async fn process_block_internal(&mut self, block: dashcore::Block) -> Result<()> {
        let block_hash = block.block_hash();

        tracing::info!("📦 Processing downloaded block: {}", block_hash);

        // Get block height from storage
        let height = {
            let storage = self.storage.lock().await;
            match storage.get_header_height_by_hash(&block_hash).await {
                Ok(Some(h)) => h,
                _ => {
                    tracing::warn!("⚠️ Could not find height for block {}, using 0", block_hash);
                    0u32
                }
            }
        };

        tracing::debug!("Block {} is at height {}", block_hash, height);

        // Process block with wallet
        let mut wallet = self.wallet.write().await;
        let txids = wallet.process_block(&block, height, self.network).await;
        if !txids.is_empty() {
            tracing::info!(
                "🎯 Wallet found {} relevant transactions in block {} at height {}",
                txids.len(),
                block_hash,
                height
            );
        }
        drop(wallet); // Release lock

        // Emit BlockProcessed event with actual relevant transaction count
        let _ = self.event_tx.send(SpvEvent::BlockProcessed {
            height,
            hash: block_hash.to_string(),
            transactions_count: block.txdata.len(),
            relevant_transactions: txids.len(),
        });

        // Update chain state if needed
        self.update_chain_state_with_block(&block).await?;

        Ok(())
    }

    /// Process a transaction internally.
    async fn process_transaction_internal(&mut self, tx: dashcore::Transaction) -> Result<()> {
        let txid = tx.txid();
        tracing::debug!("Processing mempool transaction: {}", txid);

        // Let the wallet process the mempool transaction
        let mut wallet = self.wallet.write().await;
        wallet.process_mempool_transaction(&tx, self.network).await;
        drop(wallet);

        // TODO: Check if transaction affects watched addresses/scripts
        // TODO: Emit appropriate events if transaction is relevant

        Ok(())
    }

    /* TODO: Re-implement with wallet integration
    /// Process transactions in a block to check for matches with watch items.
    async fn process_block_transactions(
        &mut self,
        block: &dashcore::Block,
    ) -> Result<()> {
        let block_hash = block.block_hash();
        let mut relevant_transactions = 0;
        let mut new_outpoints_to_watch = Vec::new();
        let mut balance_changes: HashMap<dashcore::Address, i64> = HashMap::new();

        // Get block height from storage
        let block_height = {
            let storage = self.storage.lock().await;
            match storage.get_header_height_by_hash(&block_hash).await {
                Ok(Some(h)) => h,
                _ => {
                    tracing::warn!(
                        "⚠️ Could not find height for block {} in transaction processing, using 0",
                        block_hash
                    );
                    0u32
                }
            }
        };

        for (tx_index, transaction) in block.txdata.iter().enumerate() {
            let txid = transaction.txid();
            let is_coinbase = tx_index == 0;

            // Wrap transaction processing in error handling to log failing txid
            match self
                .process_single_transaction_in_block(
                    transaction,
                    tx_index,
                    watch_items,
                    &mut balance_changes,
                    &mut new_outpoints_to_watch,
                    block_height,
                    is_coinbase,
                )
                .await
            {
                Ok(is_relevant) => {
                    if is_relevant {
                        relevant_transactions += 1;
                        tracing::debug!(
                            "📝 Transaction {}: {} (index {}) is relevant",
                            txid,
                            if is_coinbase {
                                "coinbase"
                            } else {
                                "regular"
                            },
                            tx_index
                        );
                    }
                }
                Err(e) => {
                    // Log error with both block hash and failing transaction ID
                    tracing::error!(
                        "❌ TRANSACTION PROCESSING FAILED in block {} for tx {} (index {}): {}",
                        block_hash,
                        txid,
                        tx_index,
                        e
                    );
                    return Err(e);
                }
            }
        }

        if relevant_transactions > 0 {
            tracing::info!(
                "🎯 Block {} contains {} relevant transactions affecting watched items",
                block_hash,
                relevant_transactions
            );

            // Update statistics since we found a block with relevant transactions
            {
                let mut stats = self.stats.write().await;
                stats.blocks_with_relevant_transactions += 1;
            }

            tracing::info!("🚨 BLOCK MATCH DETECTED! Block {} at height {} contains {} transactions affecting watched addresses/scripts",
                          block_hash, block_height, relevant_transactions);

            // Report balance changes
            if !balance_changes.is_empty() {
                self.report_balance_changes(&balance_changes, block_height).await?;
            }
        }

        // Always emit block processed event (even if no relevant transactions)
        let _ = self.event_tx.send(SpvEvent::BlockProcessed {
            height: block_height,
            hash: block_hash.to_string(),
            transactions_count: block.txdata.len(),
            relevant_transactions,
        });

        Ok(())
    }

    /// Process a single transaction within a block for watch item matches.
    /// Returns whether the transaction is relevant to any watch items.
    async fn process_single_transaction_in_block(
        &mut self,
        transaction: &dashcore::Transaction,
        _tx_index: usize,
        watch_items: &[WatchItem],
        balance_changes: &mut HashMap<dashcore::Address, i64>,
        new_outpoints_to_watch: &mut Vec<dashcore::OutPoint>,
        block_height: u32,
        is_coinbase: bool,
    ) -> Result<bool> {
        let txid = transaction.txid();
        let mut transaction_relevant = false;
        let mut tx_balance_changes: HashMap<dashcore::Address, i64> = HashMap::new();

        // Process inputs first (spending UTXOs)
        if !is_coinbase {
            for (vin, input) in transaction.input.iter().enumerate() {
                // Check if this input spends a UTXO from our watched addresses
                // Note: WalletInterface doesn't expose UTXO tracking directly
                // The wallet will handle this internally in process_block

                // Also check against explicitly watched outpoints
                for watch_item in watch_items {
                    if let WatchItem::Outpoint(watched_outpoint) = watch_item {
                        if &input.previous_output == watched_outpoint {
                            transaction_relevant = true;
                            tracing::info!(
                                "💸 TX {} input {}:{} spending explicitly watched outpoint {:?}",
                                txid,
                                txid,
                                vin,
                                watched_outpoint
                            );
                        }
                    }
                }
            }
        }

        // Process outputs (creating new UTXOs)
        for (vout, output) in transaction.output.iter().enumerate() {
            for watch_item in watch_items {
                let (matches, matched_address) = match watch_item {
                    WatchItem::Address {
                        address,
                        ..
                    } => (address.script_pubkey() == output.script_pubkey, Some(address.clone())),
                    WatchItem::Script(script) => (script == &output.script_pubkey, None),
                    WatchItem::Outpoint(_) => (false, None), // Outpoints don't match outputs
                };

                if matches {
                    transaction_relevant = true;
                    let outpoint = dashcore::OutPoint {
                        txid,
                        vout: vout as u32,
                    };
                    let amount = dashcore::Amount::from_sat(output.value);

                    // Create and store UTXO if we have an address
                    if let Some(address) = matched_address {
                        let balance_impact = amount.to_sat() as i64;
                        tracing::info!("💰 TX {} output {}:{} to {:?} (value: {}) - Address {} balance impact: +{}",
                                      txid, txid, vout, watch_item, amount, address, balance_impact);

                        // WalletInterface doesn't have add_utxo method - this will be handled by process_block
                        // Just track the balance changes
                        tracing::debug!("📝 Found UTXO {}:{} for address {}", txid, vout, address);

                        // Update balance change for this address (add)
                        *balance_changes.entry(address.clone()).or_insert(0) += balance_impact;
                        *tx_balance_changes.entry(address.clone()).or_insert(0) += balance_impact;
                    } else {
                        tracing::info!("💰 TX {} output {}:{} to {:?} (value: {}) - No address to track balance",
                                      txid, txid, vout, watch_item, amount);
                    }

                    // Track this outpoint so we can detect when it's spent
                    new_outpoints_to_watch.push(outpoint);
                    tracing::debug!(
                        "📍 Now watching outpoint {}:{} for future spending",
                        txid,
                        vout
                    );
                }
            }
        }

        // Report per-transaction balance changes if this transaction was relevant
        if transaction_relevant && !tx_balance_changes.is_empty() {
            tracing::info!("🧾 Transaction {} balance summary:", txid);
            for (address, change_sat) in &tx_balance_changes {
                if *change_sat != 0 {
                    let change_amount = dashcore::Amount::from_sat(change_sat.abs() as u64);
                    let sign = if *change_sat > 0 {
                        "+"
                    } else {
                        "-"
                    };
                    tracing::info!(
                        "  📊 Address {}: {}{} (net change for this tx)",
                        address,
                        sign,
                        change_amount
                    );
                }
            }
        }

        // Emit transaction event if relevant
        if transaction_relevant {
            let net_amount: i64 = tx_balance_changes.values().sum();
            let affected_addresses: Vec<String> =
                tx_balance_changes.keys().map(|addr| addr.to_string()).collect();

            let _ = self.event_tx.send(SpvEvent::TransactionDetected {
                txid: txid.to_string(),
                confirmed: true, // Block transactions are confirmed
                block_height: Some(block_height),
                amount: net_amount,
                addresses: affected_addresses,
            });
        }

        Ok(transaction_relevant)
    }

    /// Report balance changes for watched addresses.
    async fn report_balance_changes(
        &self,
        balance_changes: &HashMap<dashcore::Address, i64>,
        block_height: u32,
    ) -> Result<()> {
        tracing::info!("💰 Balance changes detected in block at height {}:", block_height);

        for (address, change_sat) in balance_changes {
            if *change_sat != 0 {
                let change_amount = dashcore::Amount::from_sat(change_sat.abs() as u64);
                let sign = if *change_sat > 0 {
                    "+"
                } else {
                    "-"
                };
                tracing::info!(
                    "  📍 Address {}: {}{} (net change for this block)",
                    address,
                    sign,
                    change_amount
                );

                // Additional context about the change
                if *change_sat > 0 {
                    tracing::info!(
                        "    ⬆️  Net increase indicates received more than spent in this block"
                    );
                } else {
                    tracing::info!(
                        "    ⬇️  Net decrease indicates spent more than received in this block"
                    );
                }
            }
        }

        // Calculate and report current balances for all watched addresses
        let watch_items: Vec<_> = self.watch_items.read().await.iter().cloned().collect();
        for watch_item in watch_items.iter() {
            if let WatchItem::Address {
                address,
                ..
            } = watch_item
            {
                match self.get_address_balance(address).await {
                    Ok(balance) => {
                        tracing::info!(
                            "  💼 Address {} balance: {} (confirmed: {}, unconfirmed: {})",
                            address,
                            balance.total(),
                            balance.confirmed,
                            balance.unconfirmed
                        );
                    }
                    Err(e) => {
                        tracing::error!("Failed to get balance for address {}: {}", address, e);
                        tracing::warn!(
                            "Continuing balance reporting despite failure for address {}",
                            address
                        );
                        // Continue with other addresses even if this one fails
                    }
                }
            }
        }

        // Emit balance update event by aggregating address balances if there were changes
        if !balance_changes.is_empty() {
            let mut confirmed_total: u64 = 0;
            let mut unconfirmed_total: u64 = 0;

            // Aggregate balances for all watched addresses
            let watch_items: Vec<_> = self.watch_items.read().await.iter().cloned().collect();
            for watch_item in watch_items.iter() {
                if let WatchItem::Address { address, .. } = watch_item {
                    if let Ok(balance) = self.get_address_balance(address).await {
                        confirmed_total = confirmed_total.saturating_add(balance.confirmed.to_sat());
                        unconfirmed_total = unconfirmed_total.saturating_add(balance.unconfirmed.to_sat());
                    }
                }
            }

            let total = confirmed_total.saturating_add(unconfirmed_total);
            let _ = self.event_tx.send(crate::types::SpvEvent::BalanceUpdate {
                confirmed: confirmed_total,
                unconfirmed: unconfirmed_total,
                total,
            });
            tracing::debug!(
                "🔔 Emitted BalanceUpdate after block {}: confirmed={}, unconfirmed={}, total={}",
                block_height,
                confirmed_total,
                unconfirmed_total,
                total
            );
        }

        Ok(())
    }

    */

    /// Update chain state with information from the processed block.
    async fn update_chain_state_with_block(&mut self, block: &dashcore::Block) -> Result<()> {
        let block_hash = block.block_hash();

        // Get the block height from storage
        let height = {
            let storage = self.storage.lock().await;
            match storage.get_header_height_by_hash(&block_hash).await {
                Ok(Some(h)) => h,
                _ => {
                    tracing::warn!(
                        "⚠️ Could not find height for block {} in chain state update, using 0",
                        block_hash
                    );
                    0u32
                }
            }
        };

        if height > 0 {
            tracing::debug!(
                "📊 Updating chain state with block {} at height {}",
                block_hash,
                height
            );

            // Update stats
            {
                let mut stats = self.stats.write().await;
                stats.blocks_requested += 1;
            }
        }

        Ok(())
    }
}
