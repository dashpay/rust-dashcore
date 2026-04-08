//! Implementation of `WalletInterface` for `WalletManager`.
//!
//! This bridges the per-wallet `WalletInfoInterface` model used internally
//! by `WalletManager` to the aggregate `WalletInterface` trait that SPV
//! clients consume.

use async_trait::async_trait;
use dashcore::prelude::CoreBlockHeight;
use dashcore::{Address, Block, OutPoint, Transaction, Txid};
use key_wallet::transaction_checking::TransactionContext;
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use tokio::sync::broadcast;

use crate::wallet_interface::{BlockProcessingResult, MempoolTransactionResult, WalletInterface};
use crate::{WalletEvent, WalletManager};

#[async_trait]
impl<T: WalletInfoInterface + Send + Sync + 'static> WalletInterface for WalletManager<T> {
    async fn process_block(
        &mut self,
        block: &Block,
        height: CoreBlockHeight,
    ) -> BlockProcessingResult {
        use key_wallet::transaction_checking::BlockInfo;

        let block_info = BlockInfo::new(height, block.block_hash(), block.header.time);
        let context = TransactionContext::InBlock(block_info);

        // Snapshot balances BEFORE processing transactions so we can detect changes.
        let old_balances = self.snapshot_balances().await;

        let mut result = BlockProcessingResult::default();
        for tx in &block.txdata {
            let check = self
                .check_transaction_in_all_wallets(tx, context, true, false)
                .await;
            if !check.affected_wallets.is_empty() {
                if check.is_new_transaction {
                    result.new_txids.push(tx.txid());
                } else {
                    result.existing_txids.push(tx.txid());
                }
                result.new_addresses.extend(check.new_addresses);
            }
        }

        // Update synced height and recalculate balances on each wallet.
        self.synced_height = height;
        for arc in self.get_all_wallet_arcs().values() {
            let mut state = arc.write().await;
            state.update_synced_height(height);
        }

        // Emit balance change events by comparing pre-block snapshot.
        self.emit_balance_changes(&old_balances).await;

        result
    }

    async fn process_mempool_transaction(
        &mut self,
        tx: &Transaction,
        is_instant_send: bool,
    ) -> MempoolTransactionResult {
        let context = if is_instant_send {
            TransactionContext::InstantSend
        } else {
            TransactionContext::Mempool
        };

        let old_balances = self.snapshot_balances().await;

        let check = self
            .check_transaction_in_all_wallets(tx, context, true, true)
            .await;

        self.emit_balance_changes(&old_balances).await;

        if check.affected_wallets.is_empty() {
            return MempoolTransactionResult::default();
        }

        let net_amount =
            check.total_received as i64 - check.total_sent as i64;

        MempoolTransactionResult {
            is_relevant: true,
            net_amount,
            is_outgoing: net_amount < 0,
            addresses: check.involved_addresses,
            new_addresses: check.new_addresses,
        }
    }

    async fn monitored_addresses(&self) -> Vec<Address> {
        self.monitored_addresses().await
    }

    async fn watched_outpoints(&self) -> Vec<OutPoint> {
        self.watched_outpoints().await
    }

    fn synced_height(&self) -> CoreBlockHeight {
        self.synced_height
    }

    async fn update_synced_height(&mut self, height: CoreBlockHeight) {
        self.synced_height = height;
        for arc in self.wallets.values() {
            let mut state = arc.write().await;
            state.update_synced_height(height);
            state.update_balance();
        }
    }

    fn filter_committed_height(&self) -> CoreBlockHeight {
        self.filter_committed_height
    }

    async fn update_filter_committed_height(&mut self, height: CoreBlockHeight) {
        self.filter_committed_height = height;
        if height > self.synced_height {
            self.update_synced_height(height).await;
        }
    }

    async fn earliest_required_height(&self) -> CoreBlockHeight {
        let mut min_height = None;
        let wallet_count = self.get_all_wallet_arcs().len();
        for arc in self.get_all_wallet_arcs().values() {
            let state = arc.read().await;
            let h = state.birth_height();
            min_height = Some(min_height.map_or(h, |m: CoreBlockHeight| m.min(h)));
        }
        let result = min_height.unwrap_or(0);
        tracing::info!("WalletManager::earliest_required_height: {} wallets, result={}", wallet_count, result);
        result
    }

    async fn monitor_revision(&self) -> u64 {
        self.monitor_revision().await
    }

    fn subscribe_events(&self) -> broadcast::Receiver<WalletEvent> {
        self.subscribe_events()
    }

    async fn process_instant_send_lock(&mut self, txid: Txid) {
        let old_balances = self.snapshot_balances().await;
        let mut any_changed = false;

        for (wallet_id, arc) in self.get_all_wallet_arcs().iter() {
            let mut state = arc.write().await;
            let (changed, _changeset) = state.mark_instant_send_utxos(&txid);
            if changed {
                any_changed = true;
                state.update_balance();
                drop(state);

                let event = WalletEvent::TransactionStatusChanged {
                    wallet_id: *wallet_id,
                    txid,
                    status: TransactionContext::InstantSend,
                };
                let _ = self.event_sender().send(event);
            }
        }

        if any_changed {
            self.emit_balance_changes(&old_balances).await;
        }
    }

    async fn describe(&self) -> String {
        format!(
            "WalletManager({} wallets, network={:?}, synced_height={})",
            self.wallet_count(),
            self.network(),
            self.synced_height
        )
    }
}
