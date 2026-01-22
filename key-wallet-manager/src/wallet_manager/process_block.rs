use crate::wallet_interface::{BlockProcessingResult, WalletInterface};
use crate::WalletManager;
use alloc::string::String;
use alloc::vec::Vec;
use async_trait::async_trait;
use core::fmt::Write as _;
use dashcore::bip158::BlockFilter;
use dashcore::prelude::CoreBlockHeight;
use dashcore::{Block, BlockHash, Transaction};
use key_wallet::transaction_checking::transaction_router::TransactionRouter;
use key_wallet::transaction_checking::TransactionContext;
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;

#[async_trait]
impl<T: WalletInfoInterface + Send + Sync + 'static> WalletInterface for WalletManager<T> {
    async fn process_block(
        &mut self,
        block: &Block,
        height: CoreBlockHeight,
    ) -> BlockProcessingResult {
        let mut result = BlockProcessingResult::default();
        let block_hash = Some(block.block_hash());
        let timestamp = block.header.time;

        // Process each transaction using the base manager
        for tx in &block.txdata {
            let context = TransactionContext::InBlock {
                height,
                block_hash,
                timestamp: Some(timestamp),
            };

            let check_result = self.check_transaction_in_all_wallets(tx, context, true).await;

            if !check_result.affected_wallets.is_empty() {
                if check_result.is_new_transaction {
                    result.new_txids.push(tx.txid());
                } else {
                    result.existing_txids.push(tx.txid());
                }
            }

            result.new_addresses.extend(check_result.new_addresses);
        }

        self.update_height(height);

        result
    }

    async fn process_mempool_transaction(&mut self, tx: &Transaction) {
        let context = TransactionContext::Mempool;

        // Check transaction against all wallets
        self.check_transaction_in_all_wallets(
            tx, context, true, // update state
        )
        .await;
    }

    async fn check_compact_filter(&mut self, filter: &BlockFilter, block_hash: &BlockHash) -> bool {
        // Collect all scripts we're watching
        let mut script_bytes = Vec::new();

        // Get all wallet addresses for this network
        for info in self.wallet_infos.values() {
            let monitored = info.monitored_addresses();
            for address in monitored {
                script_bytes.push(address.script_pubkey().as_bytes().to_vec());
            }
        }

        // If we don't watch any scripts for this network, there can be no match.
        // Note: BlockFilterReader::match_any returns true for an empty query set,
        // so we must guard this case explicitly to avoid false positives.
        let hit = if script_bytes.is_empty() {
            false
        } else {
            filter
                .match_any(block_hash, &mut script_bytes.iter().map(|s| s.as_slice()))
                .unwrap_or(false)
        };

        hit
    }

    async fn transaction_effect(&self, tx: &Transaction) -> Option<(i64, Vec<String>)> {
        // Aggregate across all managed wallets. If any wallet considers it relevant,
        // compute net = total_received - total_sent and collect involved addresses.
        let mut total_received: u64 = 0;
        let mut total_sent: u64 = 0;
        let mut addresses: Vec<String> = Vec::new();

        let mut is_relevant_any = false;
        for info in self.wallet_infos.values() {
            let collection = info.accounts();
            // Reuse the same routing/check logic used in normal processing
            let tx_type = TransactionRouter::classify_transaction(tx);
            let account_types = TransactionRouter::get_relevant_account_types(&tx_type);
            let result = collection.check_transaction(tx, &account_types);

            if result.is_relevant {
                is_relevant_any = true;
                total_received = total_received.saturating_add(result.total_received);
                total_sent = total_sent.saturating_add(result.total_sent);

                // Collect involved addresses from affected accounts
                for account_match in result.affected_accounts {
                    for addr_info in account_match.account_type_match.all_involved_addresses() {
                        addresses.push(addr_info.address.to_string());
                    }
                }
            }
        }

        if is_relevant_any {
            // Deduplicate addresses while preserving order
            let mut seen = alloc::collections::BTreeSet::new();
            addresses.retain(|a| seen.insert(a.clone()));
            let net = (total_received as i64) - (total_sent as i64);
            Some((net, addresses))
        } else {
            None
        }
    }

    async fn earliest_required_height(&self) -> CoreBlockHeight {
        self.wallet_infos.values().map(|info| info.birth_height()).min().unwrap_or(0)
    }

    async fn describe(&self) -> String {
        let wallet_count = self.wallet_infos.len();
        if wallet_count == 0 {
            return format!("WalletManager: 0 wallets (network {})", self.network);
        }

        let mut details = Vec::with_capacity(wallet_count);
        for (wallet_id, info) in &self.wallet_infos {
            let name = info.name().unwrap_or("unnamed");

            let mut wallet_id_hex = String::with_capacity(wallet_id.len() * 2);
            for byte in wallet_id {
                let _ = write!(&mut wallet_id_hex, "{:02x}", byte);
            }

            let script_count = info.monitored_addresses().len();
            let summary = format!("{} scripts", script_count);

            details.push(format!("{} ({}): {}", name, wallet_id_hex, summary));
        }

        format!(
            "WalletManager: {} wallet(s) on {}\n{}",
            wallet_count,
            self.network,
            details.join("\n")
        )
    }
}
