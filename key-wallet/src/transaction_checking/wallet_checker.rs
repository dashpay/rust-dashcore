//! Wallet-level transaction checking
//!
//! This module provides methods on ManagedWalletInfo for checking
//! if transactions belong to the wallet.

pub(crate) use super::account_checker::TransactionCheckResult;
use super::transaction_router::TransactionRouter;
use crate::wallet::immature_transaction::ImmatureTransaction;
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::wallet::managed_wallet_info::ManagedWalletInfo;
use crate::{Network, Wallet};
use dashcore::blockdata::transaction::Transaction;
use dashcore::BlockHash;
use dashcore_hashes::Hash;

/// Context for transaction processing
#[derive(Debug, Clone, Copy)]
pub enum TransactionContext {
    /// Transaction is in the mempool (unconfirmed)
    Mempool,
    /// Transaction is in a block at the given height
    InBlock {
        height: u32,
        block_hash: Option<BlockHash>,
        timestamp: Option<u32>,
    },
    /// Transaction is in a chain-locked block at the given height
    InChainLockedBlock {
        height: u32,
        block_hash: Option<BlockHash>,
        timestamp: Option<u32>,
    },
}

/// Extension trait for ManagedWalletInfo to add transaction checking capabilities
pub trait WalletTransactionChecker {
    /// Check if a transaction belongs to this wallet with optimized routing
    /// Only checks relevant account types based on transaction type
    /// If update_state_if_found is Some, updates account state when transaction is found.
    /// The wallet is needed to generate more addresses.
    /// The context parameter indicates where the transaction comes from (mempool, block, etc.)
    ///
    fn check_transaction(
        &mut self,
        tx: &Transaction,
        network: Network,
        context: TransactionContext,
        update_state_with_wallet_if_found: Option<&Wallet>,
    ) -> TransactionCheckResult;
}

impl WalletTransactionChecker for ManagedWalletInfo {
    fn check_transaction(
        &mut self,
        tx: &Transaction,
        network: Network,
        context: TransactionContext,
        update_state_with_wallet_if_found: Option<&Wallet>,
    ) -> TransactionCheckResult {
        // Get the account collection for this network
        if let Some(collection) = self.accounts.get(&network) {
            // Classify the transaction
            let tx_type = TransactionRouter::classify_transaction(tx);

            // Get relevant account types for this transaction type
            let relevant_types = TransactionRouter::get_relevant_account_types(&tx_type);

            // Check only relevant account types
            let result = collection.check_transaction(tx, &relevant_types);

            // Update state if requested and transaction is relevant
            if update_state_with_wallet_if_found.is_some() && result.is_relevant {
                if let Some(collection) = self.accounts.get_mut(&network) {
                    for account_match in &result.affected_accounts {
                        // Find and update the specific account
                        use super::account_checker::AccountTypeMatch;
                        let account = match &account_match.account_type_match {
                            AccountTypeMatch::StandardBIP44 {
                                account_index,
                                ..
                            } => collection.standard_bip44_accounts.get_mut(account_index),
                            AccountTypeMatch::StandardBIP32 {
                                account_index,
                                ..
                            } => collection.standard_bip32_accounts.get_mut(account_index),
                            AccountTypeMatch::CoinJoin {
                                account_index,
                                ..
                            } => collection.coinjoin_accounts.get_mut(account_index),
                            AccountTypeMatch::IdentityRegistration {
                                ..
                            } => collection.identity_registration.as_mut(),
                            AccountTypeMatch::IdentityTopUp {
                                account_index,
                                ..
                            } => collection.identity_topup.get_mut(account_index),
                            AccountTypeMatch::IdentityTopUpNotBound {
                                ..
                            } => collection.identity_topup_not_bound.as_mut(),
                            AccountTypeMatch::IdentityInvitation {
                                ..
                            } => collection.identity_invitation.as_mut(),
                            AccountTypeMatch::ProviderVotingKeys {
                                ..
                            } => collection.provider_voting_keys.as_mut(),
                            AccountTypeMatch::ProviderOwnerKeys {
                                ..
                            } => collection.provider_owner_keys.as_mut(),
                            AccountTypeMatch::ProviderOperatorKeys {
                                ..
                            } => collection.provider_operator_keys.as_mut(),
                            AccountTypeMatch::ProviderPlatformKeys {
                                ..
                            } => collection.provider_platform_keys.as_mut(),
                        };

                        if let Some(account) = account {
                            // Add transaction record with height/confirmation info from context
                            let net_amount =
                                account_match.received as i64 - account_match.sent as i64;

                            // Extract height, block hash, and timestamp from context
                            let (height, block_hash, timestamp) = match context {
                                TransactionContext::Mempool => (None, None, 0u64),
                                TransactionContext::InBlock {
                                    height,
                                    block_hash,
                                    timestamp,
                                }
                                | TransactionContext::InChainLockedBlock {
                                    height,
                                    block_hash,
                                    timestamp,
                                } => (Some(height), block_hash, timestamp.unwrap_or(0) as u64),
                            };

                            let tx_record = crate::account::TransactionRecord {
                                transaction: tx.clone(),
                                txid: tx.txid(),
                                height,
                                block_hash,
                                timestamp,
                                net_amount,
                                fee: None,
                                label: None,
                                is_ours: net_amount < 0,
                            };

                            // Check if this is an immature transaction (coinbase that needs maturity)
                            let is_coinbase = tx.is_coin_base();
                            let needs_maturity = is_coinbase
                                && matches!(
                                    context,
                                    TransactionContext::InBlock { .. }
                                        | TransactionContext::InChainLockedBlock { .. }
                                );

                            if needs_maturity {
                                // Handle as immature transaction
                                if let TransactionContext::InBlock {
                                    height,
                                    block_hash,
                                    timestamp,
                                }
                                | TransactionContext::InChainLockedBlock {
                                    height,
                                    block_hash,
                                    timestamp,
                                } = context
                                {
                                    // Create immature transaction
                                    let _immature_tx = ImmatureTransaction::new(
                                        tx.clone(),
                                        height,
                                        block_hash.unwrap_or_else(BlockHash::all_zeros),
                                        timestamp.unwrap_or(0) as u64,
                                        100,  // Standard coinbase maturity
                                        true, // is_coinbase
                                    );

                                    // todo!()
                                    // Track in immature transactions instead of regular transactions
                                    // This would need to be implemented in the account
                                    // For now, we'll still add to regular transactions
                                }
                            }

                            account.transactions.insert(tx.txid(), tx_record);

                            // Mark involved addresses as used
                            for address_info in
                                account_match.account_type_match.all_involved_addresses()
                            {
                                account.mark_address_used(&address_info.address);
                            }

                            // Generate new addresses up to the gap limit if wallet is provided
                            if let Some(wallet) = update_state_with_wallet_if_found {
                                // Get the account's xpub from the wallet for address generation
                                let account_type_to_check =
                                    account_match.account_type_match.to_account_type_to_check();
                                let xpub_opt = wallet.extended_public_key_for_account_type(
                                    &account_type_to_check,
                                    account_match.account_type_match.account_index(),
                                    network,
                                );

                                // Maintain gap limit for the address pools
                                if let Some(xpub) = xpub_opt {
                                    let key_source =
                                        crate::managed_account::address_pool::KeySource::Public(
                                            xpub,
                                        );

                                    // For standard accounts, maintain gap limit on both pools
                                    if let crate::managed_account::managed_account_type::ManagedAccountType::Standard {
                                        external_addresses,
                                        internal_addresses,
                                        ..
                                    } = &mut account.account_type {
                                        // Maintain gap limit for external addresses
                                        let _ = external_addresses.maintain_gap_limit(&key_source);
                                        // Maintain gap limit for internal addresses  
                                        let _ = internal_addresses.maintain_gap_limit(&key_source);
                                    } else {
                                        // For other account types, get the single address pool
                                        for pool in account.account_type.address_pools_mut() {
                                            let _ = pool.maintain_gap_limit(&key_source);
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Update wallet metadata
                    self.metadata.total_transactions += 1;

                    // Update cached balance
                    self.update_balance();
                }
            }

            result
        } else {
            // No accounts for this network
            TransactionCheckResult {
                is_relevant: false,
                affected_accounts: Vec::new(),
                total_received: 0,
                total_sent: 0,
                total_received_for_credit_conversion: 0,
            }
        }
    }
}
