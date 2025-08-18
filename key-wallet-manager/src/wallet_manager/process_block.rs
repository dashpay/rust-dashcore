use crate::{Network, WalletManager};
use dashcore::bip158::BlockFilter;
use dashcore::prelude::CoreBlockHeight;
use dashcore::{Block, BlockHash, Txid};
use key_wallet::transaction_checking::TransactionContext;
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;

impl WalletManager {
    pub fn process_block(&mut self, block: &Block, height: u32, network: Network) -> Vec<Txid> {
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

            let affected_wallets = self.check_transaction_in_all_wallets(
                tx, network, context, true, // update state
            );

            if !affected_wallets.is_empty() {
                relevant_txids.push(tx.txid());
            }
        }

        // Update network state height
        if let Some(state) = self.network_states.get_mut(&network) {
            state.current_height = height;
        }

        relevant_txids
    }

    pub fn handle_reorg(
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

    pub fn check_compact_filter(
        &self,
        filter: &BlockFilter,
        block_hash: &BlockHash,
        network: Network,
    ) -> bool {
        // Collect all scripts we're watching
        let mut script_bytes = Vec::new();

        // Get all wallet addresses for this network
        for info in self.wallet_infos.values() {
            let monitored = info.monitored_addresses(network);
            for address in monitored {
                script_bytes.push(address.script_pubkey().as_bytes().to_vec());
            }
        }

        // Check if any of our scripts match the filter
        filter
            .match_any(block_hash, &mut script_bytes.iter().map(|s| s.as_slice()))
            .unwrap_or(false)
    }
}
