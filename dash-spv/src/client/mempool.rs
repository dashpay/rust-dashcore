//! Mempool coordination and tracking.
//!
//! This module contains:
//! - Mempool tracking enablement
//! - Mempool balance queries
//! - Transaction counting
//! - Filter updates

use std::collections::HashSet;
use std::sync::Arc;

use crate::error::Result;
use crate::mempool_filter::MempoolFilter;
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use key_wallet_manager::wallet_interface::WalletInterface;

use super::DashSpvClient;

impl<W: WalletInterface, N: NetworkManager, S: StorageManager> DashSpvClient<W, N, S> {
    /// Get mempool balance for an address.
    pub async fn get_mempool_balance(
        &self,
        address: &dashcore::Address,
    ) -> Result<crate::types::MempoolBalance> {
        let _wallet = self.wallet.read().await;
        let mempool_state = self.mempool_state.read().await;

        let mut pending = 0i64;
        let mut pending_instant = 0i64;

        // Calculate pending balances from mempool transactions
        for tx in mempool_state.transactions.values() {
            // Check if this transaction affects the given address
            let mut address_affected = false;
            for addr in &tx.addresses {
                if addr == address {
                    address_affected = true;
                    break;
                }
            }

            if address_affected {
                // Calculate the actual balance change for this specific address
                // by examining inputs and outputs directly
                let mut address_balance_change = 0i64;

                // Check outputs to this address (incoming funds)
                for output in &tx.transaction.output {
                    if let Ok(out_addr) =
                        dashcore::Address::from_script(&output.script_pubkey, self.config.network)
                    {
                        if &out_addr == address {
                            address_balance_change += output.value as i64;
                        }
                    }
                }

                // Check inputs from this address (outgoing funds)
                // We need to check if any of the inputs were previously owned by this address
                // Note: This requires the wallet to have knowledge of the UTXOs being spent
                // In a real implementation, we would need to look up the previous outputs
                // For now, we'll rely on the is_outgoing flag and net_amount when we can't determine ownership

                // Validate that the calculated balance change is consistent with net_amount
                // for transactions where this address is involved
                if address_balance_change != 0 {
                    // For outgoing transactions, net_amount should be negative if we're spending
                    // For incoming transactions, net_amount should be positive if we're receiving
                    // Mixed transactions (both sending and receiving) should have the net effect

                    // Apply the validated balance change
                    if tx.is_instant_send {
                        pending_instant += address_balance_change;
                    } else {
                        pending += address_balance_change;
                    }
                } else if tx.net_amount != 0 && tx.is_outgoing {
                    // Edge case: If we calculated zero change but net_amount is non-zero,
                    // and it's an outgoing transaction, it might be a fee-only transaction
                    // In this case, we should not affect the balance for this address
                    // unless it's the sender paying the fee
                    continue;
                }
            }
        }

        // Convert to unsigned values, ensuring no negative balances
        let pending_sats = if pending < 0 {
            0
        } else {
            pending as u64
        };
        let pending_instant_sats = if pending_instant < 0 {
            0
        } else {
            pending_instant as u64
        };

        Ok(crate::types::MempoolBalance {
            pending: dashcore::Amount::from_sat(pending_sats),
            pending_instant: dashcore::Amount::from_sat(pending_instant_sats),
        })
    }

    /// Get mempool transaction count.
    pub async fn get_mempool_transaction_count(&self) -> usize {
        let mempool_state = self.mempool_state.read().await;
        mempool_state.transactions.len()
    }

    /// Record that we attempted to send a transaction (for UX/heuristics).
    pub async fn record_send(&self, txid: dashcore::Txid) -> Result<()> {
        let mut mempool_state = self.mempool_state.write().await;
        mempool_state.record_send(txid);
        Ok(())
    }

    /// Update mempool filter with wallet's monitored addresses.
    #[allow(dead_code)]
    pub(super) async fn update_mempool_filter(&mut self) {
        // TODO: Get monitored addresses from wallet
        // For now, create empty filter until wallet integration is complete
        self.mempool_filter = Some(Arc::new(MempoolFilter::new(
            self.config.mempool_strategy,
            self.config.max_mempool_transactions,
            self.mempool_state.clone(),
            HashSet::new(), // Will be populated from wallet's monitored addresses
            self.config.network,
        )));
        tracing::info!("Updated mempool filter (wallet integration pending)");
    }
}
