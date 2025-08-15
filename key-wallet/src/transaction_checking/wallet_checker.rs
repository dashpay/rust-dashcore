//! Wallet-level transaction checking
//!
//! This module provides methods on ManagedWalletInfo for checking
//! if transactions belong to the wallet.

use crate::wallet::immature_transaction::{AffectedAccounts, ImmatureTransaction};
use crate::wallet::managed_wallet_info::ManagedWalletInfo;
use crate::Network;
pub(crate) use super::account_checker::TransactionCheckResult;
use super::transaction_router::TransactionRouter;
use dashcore::blockdata::transaction::Transaction;
use dashcore::BlockHash;

/// Extension trait for ManagedWalletInfo to add transaction checking capabilities
pub trait WalletTransactionChecker {
    /// Check if a transaction belongs to this wallet with optimized routing
    /// Only checks relevant account types based on transaction type
    /// If update_state_if_found is true, updates account state when transaction is found
    fn check_transaction(&mut self, tx: &Transaction, network: Network, update_state_if_found: bool) -> TransactionCheckResult;
    
    /// Check and process an immature transaction (like coinbase)
    /// Returns the check result and whether it was added as immature
    fn check_immature_transaction(
        &mut self, 
        tx: &Transaction, 
        network: Network, 
        height: u32,
        block_hash: BlockHash,
        timestamp: u64,
        maturity_confirmations: u32,
    ) -> (TransactionCheckResult, bool);
}

impl WalletTransactionChecker for ManagedWalletInfo {
    fn check_transaction(&mut self, tx: &Transaction, network: Network, update_state_if_found: bool) -> TransactionCheckResult {
        // Get the account collection for this network
        if let Some(collection) = self.accounts.get(&network) {
            // Classify the transaction
            let tx_type = TransactionRouter::classify_transaction(tx);
            
            // Get relevant account types for this transaction type
            let relevant_types = TransactionRouter::get_relevant_account_types(&tx_type);
            
            // Check only relevant account types
            let result = collection.check_transaction(tx, &relevant_types);
            
            // Update state if requested and transaction is relevant
            if update_state_if_found && result.is_relevant {
                if let Some(collection) = self.accounts.get_mut(&network) {
                    for account_match in &result.affected_accounts {
                        // Find and update the specific account
                        let account = match &account_match.account_type {
                            super::transaction_router::AccountTypeToCheck::StandardBIP44 => {
                                account_match.account_index
                                    .and_then(|idx| collection.standard_bip44_accounts.get_mut(&idx))
                            }
                            super::transaction_router::AccountTypeToCheck::StandardBIP32 => {
                                account_match.account_index
                                    .and_then(|idx| collection.standard_bip32_accounts.get_mut(&idx))
                            }
                            super::transaction_router::AccountTypeToCheck::CoinJoin => {
                                account_match.account_index
                                    .and_then(|idx| collection.coinjoin_accounts.get_mut(&idx))
                            }
                            super::transaction_router::AccountTypeToCheck::IdentityRegistration => {
                                collection.identity_registration.as_mut()
                            }
                            super::transaction_router::AccountTypeToCheck::IdentityTopUp => {
                                account_match.account_index
                                    .and_then(|idx| collection.identity_topup.get_mut(&idx))
                            }
                            super::transaction_router::AccountTypeToCheck::IdentityTopUpNotBound => {
                                collection.identity_topup_not_bound.as_mut()
                            }
                            super::transaction_router::AccountTypeToCheck::IdentityInvitation => {
                                collection.identity_invitation.as_mut()
                            }
                            super::transaction_router::AccountTypeToCheck::ProviderVotingKeys => {
                                collection.provider_voting_keys.as_mut()
                            }
                            super::transaction_router::AccountTypeToCheck::ProviderOwnerKeys => {
                                collection.provider_owner_keys.as_mut()
                            }
                            super::transaction_router::AccountTypeToCheck::ProviderOperatorKeys => {
                                collection.provider_operator_keys.as_mut()
                            }
                            super::transaction_router::AccountTypeToCheck::ProviderPlatformKeys => {
                                collection.provider_platform_keys.as_mut()
                            }
                        };
                        
                        if let Some(account) = account {
                            // Add transaction record without height/confirmation info
                            let net_amount = account_match.received as i64 - account_match.sent as i64;
                            let tx_record = crate::account::TransactionRecord {
                                transaction: tx.clone(),
                                txid: tx.txid(),
                                height: None,
                                block_hash: None,
                                timestamp: 0, // Would need current time
                                net_amount,
                                fee: None,
                                label: None,
                                is_ours: net_amount < 0,
                            };
                            
                            account.transactions.insert(tx.txid(), tx_record);
                            
                            // Mark involved addresses as used
                            for address in &account_match.involved_addresses {
                                account.mark_address_used(address);
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
            }
        }
    }

    fn check_immature_transaction(
        &mut self, 
        tx: &Transaction, 
        network: Network, 
        height: u32,
        block_hash: BlockHash,
        timestamp: u64,
        maturity_confirmations: u32,
    ) -> (TransactionCheckResult, bool) {
        // First check if the transaction belongs to us
        let result = self.check_transaction(tx, network, false);
        
        if result.is_relevant {
            // Determine if this is a coinbase transaction
            let is_coinbase = tx.is_coin_base();
            
            // Create immature transaction
            let mut immature_tx = ImmatureTransaction::new(
                tx.clone(),
                height,
                block_hash,
                timestamp,
                maturity_confirmations,
                is_coinbase,
            );
            
            // Build affected accounts from the check result
            let mut affected_accounts = AffectedAccounts::new();
            for account_match in &result.affected_accounts {
                use crate::transaction_checking::transaction_router::AccountTypeToCheck;
                
                match &account_match.account_type {
                    AccountTypeToCheck::StandardBIP44 => {
                        if let Some(index) = account_match.account_index {
                            affected_accounts.add_bip44(index);
                        }
                    }
                    AccountTypeToCheck::StandardBIP32 => {
                        if let Some(index) = account_match.account_index {
                            affected_accounts.add_bip32(index);
                        }
                    }
                    AccountTypeToCheck::CoinJoin => {
                        if let Some(index) = account_match.account_index {
                            affected_accounts.add_coinjoin(index);
                        }
                    }
                    _ => {
                        // Other account types don't typically receive immature funds
                    }
                }
            }
            
            immature_tx.affected_accounts = affected_accounts;
            immature_tx.total_received = result.total_received;
            
            // Add to immature transactions
            self.add_immature_transaction(network, immature_tx);
            
            (result, true)
        } else {
            (result, false)
        }
    }
}