use crate::wallet_interface::WalletInterface;
use crate::{Network, WalletManager};
use alloc::string::String;
use alloc::vec::Vec;
use async_trait::async_trait;
use core::fmt::Write as _;
use dashcore::bip158::BlockFilter;
use dashcore::prelude::CoreBlockHeight;
use dashcore::{Block, BlockHash, Transaction, Txid};
use key_wallet::transaction_checking::transaction_router::TransactionRouter;
use key_wallet::transaction_checking::TransactionContext;
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;

#[async_trait]
impl<T: WalletInfoInterface + Send + Sync + 'static> WalletInterface for WalletManager<T> {
    async fn process_block(
        &mut self,
        block: &Block,
        height: CoreBlockHeight,
        network: Network,
    ) -> (Vec<Txid>, bool) {
        // Capture address count before processing
        let addresses_before: usize =
            self.wallet_infos.values().map(|info| info.monitored_addresses(network).len()).sum();

        let mut relevant_txids = Vec::new();
        let block_hash = Some(block.block_hash());
        let timestamp = block.header.time;

        // Process each transaction using the base manager
        for tx in &block.txdata {
            let context = TransactionContext::InBlock {
                height,
                block_hash,
                timestamp: Some(timestamp),
            };

            let affected_wallets = self
                .check_transaction_in_all_wallets(
                    tx, network, context, true, // update state
                )
                .await;

            if !affected_wallets.is_empty() {
                relevant_txids.push(tx.txid());
            }
        }

        // Update network state height
        if let Some(state) = self.network_states.get_mut(&network) {
            state.current_height = height;
        }

        // Capture address count after processing
        let addresses_after: usize =
            self.wallet_infos.values().map(|info| info.monitored_addresses(network).len()).sum();

        // Determine if gap limit changed (new addresses were generated)
        let gap_limit_changed = addresses_after > addresses_before;

        // Note: Gap limit changes will be logged by the SPV client

        (relevant_txids, gap_limit_changed)
    }

    async fn process_mempool_transaction(&mut self, tx: &Transaction, network: Network) {
        let context = TransactionContext::Mempool;

        // Check transaction against all wallets
        self.check_transaction_in_all_wallets(
            tx, network, context, true, // update state
        )
        .await;
    }

    async fn handle_reorg(
        &mut self,
        from_height: CoreBlockHeight,
        to_height: CoreBlockHeight,
        network: Network,
    ) {
        if let Some(state) = self.network_states.get_mut(&network) {
            // Roll back to the reorg point
            if state.current_height >= from_height {
                // Remove transactions above the reorg height
                state.transactions.retain(|_, record| {
                    if let Some(height) = record.height {
                        height < from_height
                    } else {
                        true // Keep mempool transactions
                    }
                });

                // Update current height
                state.current_height = to_height;
            }
        }
    }

    async fn check_compact_filter(
        &mut self,
        filter: &BlockFilter,
        block_hash: &BlockHash,
        network: Network,
    ) -> bool {
        // Check if we've already evaluated this filter
        if let Some(network_cache) = self.filter_matches.get(&network) {
            if let Some(&matched) = network_cache.get(block_hash) {
                return matched;
            }
        }

        // Collect all scripts we're watching
        let mut script_bytes = Vec::new();

        // Get all wallet addresses for this network
        for info in self.wallet_infos.values() {
            let monitored = info.monitored_addresses(network);
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

        // Cache the result
        self.filter_matches.entry(network).or_default().insert(*block_hash, hit);

        hit
    }

    async fn transaction_effect(
        &self,
        tx: &Transaction,
        network: Network,
    ) -> Option<(i64, Vec<String>)> {
        // Aggregate across all managed wallets. If any wallet considers it relevant,
        // compute net = total_received - total_sent and collect involved addresses.
        let mut total_received: u64 = 0;
        let mut total_sent: u64 = 0;
        let mut addresses: Vec<String> = Vec::new();

        let mut is_relevant_any = false;
        for info in self.wallet_infos.values() {
            // Only consider wallets tracking this network
            if let Some(collection) = info.accounts(network) {
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

    async fn earliest_required_height(&self, network: Network) -> Option<CoreBlockHeight> {
        let mut earliest: Option<CoreBlockHeight> = None;

        for info in self.wallet_infos.values() {
            // Only consider wallets that actually track this network AND have a known birth height
            if info.accounts(network).is_some() {
                if let Some(birth_height) = info.birth_height() {
                    earliest = Some(match earliest {
                        Some(current) => current.min(birth_height),
                        None => birth_height,
                    });
                }
            }
        }

        // Return None if no wallets with known birth heights were found for this network
        earliest
    }

    async fn describe(&self, network: Network) -> String {
        let wallet_count = self.wallet_infos.len();
        if wallet_count == 0 {
            return format!("WalletManager: 0 wallets (network {})", network);
        }

        let mut details = Vec::with_capacity(wallet_count);
        for (wallet_id, info) in &self.wallet_infos {
            let name = info.name().unwrap_or("unnamed");

            let mut wallet_id_hex = String::with_capacity(wallet_id.len() * 2);
            for byte in wallet_id {
                let _ = write!(&mut wallet_id_hex, "{:02x}", byte);
            }

            let script_count = info.monitored_addresses(network).len();
            let summary = format!("{} scripts", script_count);

            details.push(format!("{} ({}): {}", name, wallet_id_hex, summary));
        }

        format!("WalletManager: {} wallet(s) on {}\n{}", wallet_count, network, details.join("\n"))
    }
}
