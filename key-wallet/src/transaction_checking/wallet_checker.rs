//! Wallet-level transaction checking
//!
//! This module provides methods on ManagedWalletInfo for checking
//! if transactions belong to the wallet.

pub(crate) use super::account_checker::TransactionCheckResult;
use super::transaction_router::TransactionRouter;
use crate::wallet::managed_wallet_info::ManagedWalletInfo;
use crate::{Utxo, Wallet};
use async_trait::async_trait;
use dashcore::blockdata::transaction::Transaction;
use dashcore::BlockHash;
use dashcore::{Address as DashAddress, OutPoint};

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
#[async_trait]
pub trait WalletTransactionChecker {
    /// Check if a transaction belongs to this wallet with optimized routing
    /// Only checks relevant account types based on transaction type
    ///
    /// The mutable wallet reference is required to support address generation and potential
    /// platform queries (e.g., for DashPay transactions).
    ///
    /// If `update_state` is true, updates account state (transactions, UTXOs, balances, addresses).
    /// If `update_state` is false, only checks relevance without modifying state (useful for previews).
    ///
    /// The context parameter indicates where the transaction comes from (mempool, block, etc.)
    ///
    async fn check_transaction(
        &mut self,
        tx: &Transaction,
        context: TransactionContext,
        wallet: &mut Wallet,
        update_state: bool,
    ) -> TransactionCheckResult;
}

#[async_trait]
impl WalletTransactionChecker for ManagedWalletInfo {
    async fn check_transaction(
        &mut self,
        tx: &Transaction,
        context: TransactionContext,
        wallet: &mut Wallet,
        update_state: bool,
    ) -> TransactionCheckResult {
        let network = self.network;

        // Classify the transaction
        let tx_type = TransactionRouter::classify_transaction(tx);

        // Get relevant account types for this transaction type
        let relevant_types = TransactionRouter::get_relevant_account_types(&tx_type);

        // Check only relevant account types
        let mut result = self.accounts.check_transaction(tx, &relevant_types);

        // Update state if requested and transaction is relevant
        if update_state && result.is_relevant {
            // Check if this transaction already exists in any affected account.
            // If so, mark it as not new.
            let txid = tx.txid();
            for account_match in &result.affected_accounts {
                if let Some(account) =
                    self.accounts.get_by_account_type_match(&account_match.account_type_match)
                {
                    if account.transactions.contains_key(&txid) {
                        result.is_new_transaction = false;
                        break;
                    }
                }
            }

            for account_match in &result.affected_accounts {
                // Find and update the specific account
                use super::account_checker::AccountTypeMatch;
                let account = match &account_match.account_type_match {
                    AccountTypeMatch::StandardBIP44 {
                        account_index,
                        ..
                    } => self.accounts.standard_bip44_accounts.get_mut(account_index),
                    AccountTypeMatch::StandardBIP32 {
                        account_index,
                        ..
                    } => self.accounts.standard_bip32_accounts.get_mut(account_index),
                    AccountTypeMatch::CoinJoin {
                        account_index,
                        ..
                    } => self.accounts.coinjoin_accounts.get_mut(account_index),
                    AccountTypeMatch::IdentityRegistration {
                        ..
                    } => self.accounts.identity_registration.as_mut(),
                    AccountTypeMatch::IdentityTopUp {
                        account_index,
                        ..
                    } => self.accounts.identity_topup.get_mut(account_index),
                    AccountTypeMatch::IdentityTopUpNotBound {
                        ..
                    } => self.accounts.identity_topup_not_bound.as_mut(),
                    AccountTypeMatch::IdentityInvitation {
                        ..
                    } => self.accounts.identity_invitation.as_mut(),
                    AccountTypeMatch::ProviderVotingKeys {
                        ..
                    } => self.accounts.provider_voting_keys.as_mut(),
                    AccountTypeMatch::ProviderOwnerKeys {
                        ..
                    } => self.accounts.provider_owner_keys.as_mut(),
                    AccountTypeMatch::ProviderOperatorKeys {
                        ..
                    } => self.accounts.provider_operator_keys.as_mut(),
                    AccountTypeMatch::ProviderPlatformKeys {
                        ..
                    } => self.accounts.provider_platform_keys.as_mut(),
                    AccountTypeMatch::DashpayReceivingFunds {
                        ..
                    }
                    | AccountTypeMatch::DashpayExternalAccount {
                        ..
                    } => {
                        // DashPay managed accounts are not persisted here yet
                        None
                    }
                    AccountTypeMatch::PlatformPayment {
                        ..
                    } => {
                        // Platform Payment addresses are NOT used in Core chain transactions.
                        // This branch should never be reached by design (per DIP-17).
                        None
                    }
                };

                if let Some(account) = account {
                    // Only update transaction record and UTXOs for new transactions.
                    // For existing transactions (rescan), the stored values are correct
                    // and the UTXO state has already been updated. Recalculating would
                    // produce wrong values since spent UTXOs have been removed.
                    if !result.is_new_transaction {
                        tracing::debug!(
                            txid = %tx.txid(),
                            "Skipping UTXO update for existing transaction"
                        );
                    }
                    if result.is_new_transaction {
                        // Add transaction record with height/confirmation info from context
                        let net_amount = account_match.received as i64 - account_match.sent as i64;

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

                        account.transactions.insert(tx.txid(), tx_record);

                        // Ingest UTXOs for outputs that pay to our addresses and
                        // remove UTXOs that are spent by this transaction's inputs.
                        // Only apply for spendable account types (Standard, CoinJoin).
                        match &mut account.account_type {
                            crate::managed_account::managed_account_type::ManagedAccountType::Standard { .. }
                            | crate::managed_account::managed_account_type::ManagedAccountType::CoinJoin { .. }
                            | crate::managed_account::managed_account_type::ManagedAccountType::DashpayReceivingFunds { .. }
                            | crate::managed_account::managed_account_type::ManagedAccountType::DashpayExternalAccount { .. } => {
                                // Build a set of addresses involved for fast membership tests
                                let mut involved_addrs = alloc::collections::BTreeSet::new();
                                for info in account_match.account_type_match.all_involved_addresses() {
                                    involved_addrs.insert(info.address.clone());
                                }

                                // Determine confirmation state and block height for UTXOs
                                let (is_confirmed, utxo_height) = match context {
                                    TransactionContext::Mempool => (false, 0u32),
                                    TransactionContext::InBlock { height, .. }
                                    | TransactionContext::InChainLockedBlock { height, .. } => (true, height),
                                };

                                // Insert UTXOs for matching outputs
                                let txid = tx.txid();
                                for (vout, output) in tx.output.iter().enumerate() {
                                    if let Ok(addr) = DashAddress::from_script(&output.script_pubkey, network) {
                                        if involved_addrs.contains(&addr) {
                                            let outpoint = OutPoint { txid, vout: vout as u32 };
                                            let txout = dashcore::TxOut {
                                                value: output.value,
                                                script_pubkey: output.script_pubkey.clone(),
                                            };
                                            let mut utxo = Utxo::new(
                                                outpoint,
                                                txout.clone(),
                                                addr,
                                                utxo_height,
                                                tx.is_coin_base(),
                                            );
                                            utxo.is_confirmed = is_confirmed;
                                            account.utxos.insert(outpoint, utxo);

                                            // Check if any transaction had an unresolved input for this UTXO.
                                            // If so, this UTXO was already spent by that transaction,
                                            // so we need to remove it and update that transaction's net_amount.
                                            if let Some(waiting_txid) = account.unresolved_inputs.remove(&outpoint) {
                                                // Remove the UTXO since it was spent by the waiting transaction
                                                account.utxos.remove(&outpoint);

                                                // Update that transaction's sent (via net_amount)
                                                if let Some(tx_record) = account.transactions.get_mut(&waiting_txid) {
                                                    let utxo_value = txout.value as i64;
                                                    tx_record.net_amount -= utxo_value;
                                                    tracing::debug!(
                                                        resolved_for_txid = %waiting_txid,
                                                        utxo_outpoint = %outpoint,
                                                        utxo_value = utxo_value,
                                                        new_net_amount = tx_record.net_amount,
                                                        "Resolved unresolved input - UTXO removed as spent"
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }

                                // Remove any UTXOs that are being spent by this transaction.
                                // Track inputs where we don't have the UTXO - they might be
                                // resolved when earlier blocks are processed (out-of-order).
                                for input in &tx.input {
                                    if account.utxos.remove(&input.previous_output).is_none() {
                                        // UTXO not found - track as unresolved so we can update
                                        // this transaction when the UTXO is created later
                                        account.unresolved_inputs.insert(input.previous_output, txid);
                                    }
                                }
                            }
                            _ => {
                                // Skip UTXO ingestion for identity/provider accounts
                            }
                        }
                    }

                    // Mark involved addresses as used
                    for address_info in account_match.account_type_match.all_involved_addresses() {
                        account.mark_address_used(&address_info.address);
                    }

                    // Generate new addresses up to the gap limit
                    let account_type_to_check =
                        account_match.account_type_match.to_account_type_to_check();
                    let xpub_opt = wallet.extended_public_key_for_account_type(
                        &account_type_to_check,
                        account_match.account_type_match.account_index(),
                    );

                    if let Some(xpub) = xpub_opt {
                        let key_source =
                            crate::managed_account::address_pool::KeySource::Public(xpub);

                        if let crate::managed_account::managed_account_type::ManagedAccountType::Standard {
                            external_addresses,
                            internal_addresses,
                            ..
                        } = &mut account.account_type {
                            match external_addresses.maintain_gap_limit(&key_source) {
                                Ok(new_addrs) => result.new_addresses.extend(new_addrs),
                                Err(e) => {
                                    tracing::error!(
                                        account_index = ?account_match.account_type_match.account_index(),
                                        pool_type = "external",
                                        error = %e,
                                        "Failed to maintain gap limit for address pool"
                                    );
                                }
                            }
                            match internal_addresses.maintain_gap_limit(&key_source) {
                                Ok(new_addrs) => result.new_addresses.extend(new_addrs),
                                Err(e) => {
                                    tracing::error!(
                                        account_index = ?account_match.account_type_match.account_index(),
                                        pool_type = "internal",
                                        error = %e,
                                        "Failed to maintain gap limit for address pool"
                                    );
                                }
                            }
                        } else {
                            for pool in account.account_type.address_pools_mut() {
                                match pool.maintain_gap_limit(&key_source) {
                                    Ok(new_addrs) => result.new_addresses.extend(new_addrs),
                                    Err(e) => {
                                        tracing::error!(
                                            account_index = ?account_match.account_type_match.account_index(),
                                            pool_type = ?pool.pool_type,
                                            error = %e,
                                            "Failed to maintain gap limit for address pool"
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Update wallet metadata and log only for new transactions.
            // For existing transactions (rescan), the recalculated sent/received values
            // are incorrect because spent UTXOs have been removed.
            if result.is_new_transaction {
                self.metadata.total_transactions += 1;

                // Log the detected transaction
                let wallet_net: i64 = (result.total_received as i64) - (result.total_sent as i64);
                let ctx = match context {
                    TransactionContext::Mempool => "mempool".to_string(),
                    TransactionContext::InBlock {
                        height,
                        ..
                    } => alloc::format!("block {}", height),
                    TransactionContext::InChainLockedBlock {
                        height,
                        ..
                    } => {
                        alloc::format!("chainlocked block {}", height)
                    }
                };
                tracing::info!(
                    txid = %tx.txid(),
                    context = %ctx,
                    net_change = wallet_net,
                    received = result.total_received,
                    sent = result.total_sent,
                    "Wallet transaction detected: net balance change"
                );
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
    use crate::wallet::{ManagedWalletInfo, Wallet};
    use crate::Network;
    use dashcore::blockdata::script::ScriptBuf;
    use dashcore::blockdata::transaction::Transaction;
    use dashcore::OutPoint;
    use dashcore::TxOut;
    use dashcore::{Address, BlockHash, TxIn, Txid};
    use dashcore_hashes::Hash;

    /// Create a test transaction that sends to a given address
    fn create_transaction_to_address(address: &Address, amount: u64) -> Transaction {
        Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([1u8; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: 0xffffffff,
                witness: dashcore::Witness::new(),
            }],
            output: vec![TxOut {
                value: amount,
                script_pubkey: address.script_pubkey(),
            }],
            special_transaction_payload: None,
        }
    }

    /// Test wallet checker with unrelated transaction
    #[tokio::test]
    async fn test_wallet_checker_unrelated_transaction() {
        let network = Network::Testnet;

        // Create wallet on testnet
        let wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
            .expect("Should create wallet");

        let mut managed_wallet =
            ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

        // Create a transaction to an external address
        let dummy_address = Address::p2pkh(
            &dashcore::PublicKey::from_slice(&[0x02; 33]).expect("Should create pubkey"),
            network,
        );
        let tx = create_transaction_to_address(&dummy_address, 100_000);

        let context = TransactionContext::Mempool;

        let mut wallet_mut = wallet;
        let result = managed_wallet.check_transaction(&tx, context, &mut wallet_mut, true).await;

        // Should return default result with no relevance
        assert!(!result.is_relevant);
        assert_eq!(result.total_received, 0);
        assert_eq!(result.total_sent, 0);
        assert!(result.affected_accounts.is_empty());
    }

    /// Test wallet checker with different account types to cover error branches
    #[tokio::test]
    async fn test_wallet_checker_different_account_types() {
        let network = Network::Testnet;

        // Create wallet with multiple account types
        let mut wallet = Wallet::new_random(network, WalletAccountCreationOptions::None)
            .expect("Should create wallet");

        // Add different types of accounts
        use crate::account::AccountType;
        use crate::account::StandardAccountType;

        // Add BIP32 account
        wallet
            .add_account(
                AccountType::Standard {
                    index: 0,
                    standard_account_type: StandardAccountType::BIP32Account,
                },
                None,
            )
            .expect("Should add BIP32 account");

        // Add CoinJoin account
        wallet
            .add_account(
                AccountType::CoinJoin {
                    index: 0,
                },
                None,
            )
            .expect("Should add CoinJoin account");

        // Add identity accounts
        wallet
            .add_account(AccountType::IdentityRegistration, None)
            .expect("Should add identity registration account");

        let mut managed_wallet =
            ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

        // Get BIP32 account address - scope the immutable borrow
        let (bip32_xpub, bip32_address) = {
            if let Some(bip32_account) = wallet.accounts.standard_bip32_accounts.get(&0) {
                let xpub = bip32_account.account_xpub;
                if let Some(managed_account) = managed_wallet.first_bip32_managed_account_mut() {
                    let address = managed_account
                        .next_receive_address(Some(&xpub), true)
                        .expect("Should get BIP32 address");
                    (Some(xpub), Some(address))
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            }
        };

        if let (Some(_xpub), Some(address)) = (bip32_xpub, bip32_address) {
            let tx = create_transaction_to_address(&address, 50_000);

            let context = TransactionContext::InBlock {
                height: 100000,
                block_hash: Some(
                    BlockHash::from_slice(&[0u8; 32]).expect("Should create block hash"),
                ),
                timestamp: Some(1234567890),
            };

            // This should exercise BIP32 account branch in the update logic
            let result = managed_wallet.check_transaction(&tx, context, &mut wallet, true).await;

            // Should be relevant since it's our address
            assert!(result.is_relevant);
            assert_eq!(result.total_received, 50_000);
        }

        // Get CoinJoin account address - scope the immutable borrow
        let (coinjoin_xpub, coinjoin_address) = {
            if let Some(coinjoin_account) = wallet.accounts.coinjoin_accounts.get(&0) {
                let xpub = coinjoin_account.account_xpub;
                if let Some(managed_account) = managed_wallet.first_coinjoin_managed_account_mut() {
                    let address = managed_account
                        .next_address(Some(&xpub), true)
                        .expect("Should get CoinJoin address");
                    (Some(xpub), Some(address))
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            }
        };

        if let (Some(_xpub), Some(address)) = (coinjoin_xpub, coinjoin_address) {
            let tx = create_transaction_to_address(&address, 75_000);

            let context = TransactionContext::InChainLockedBlock {
                height: 100001,
                block_hash: Some(
                    BlockHash::from_slice(&[1u8; 32]).expect("Should create block hash"),
                ),
                timestamp: Some(1234567891),
            };

            // This should exercise CoinJoin account branch in the update logic
            let result = managed_wallet.check_transaction(&tx, context, &mut wallet, true).await;

            // Since this is not a coinjoin looking transaction, we should not pick up on it.
            assert!(!result.is_relevant);
            assert_eq!(result.total_received, 0);
        }
    }

    /// Test coinbase transaction handling for immature transaction logic
    #[tokio::test]
    async fn test_wallet_checker_coinbase_immature_handling() {
        let network = Network::Testnet;
        let mut wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
            .expect("Should create wallet");

        let mut managed_wallet =
            ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

        // Get a wallet address
        let account =
            wallet.accounts.standard_bip44_accounts.get(&0).expect("Should have BIP44 account");
        let xpub = account.account_xpub;

        let address = managed_wallet
            .first_bip44_managed_account_mut()
            .expect("Should have managed account")
            .next_receive_address(Some(&xpub), true)
            .expect("Should get address");

        // Create a coinbase transaction
        let coinbase_tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::all_zeros(), // Coinbase has null previous output
                    vout: 0xffffffff,
                },
                script_sig: ScriptBuf::new(),
                sequence: 0xffffffff,
                witness: dashcore::Witness::new(),
            }],
            output: vec![TxOut {
                value: 5_000_000_000, // 50 DASH block reward
                script_pubkey: address.script_pubkey(),
            }],
            special_transaction_payload: None,
        };

        let block_height = 100000;

        // Test with InBlock context
        let context = TransactionContext::InBlock {
            height: block_height,
            block_hash: Some(BlockHash::from_slice(&[1u8; 32]).expect("Should create block hash")),
            timestamp: Some(1234567890),
        };

        let result =
            managed_wallet.check_transaction(&coinbase_tx, context, &mut wallet, true).await;
        // Set synced_height to block where coinbase was received to trigger balance updates.
        managed_wallet.update_synced_height(block_height);

        // Should be relevant
        assert!(result.is_relevant);
        assert_eq!(result.total_received, 5_000_000_000);

        let managed_account =
            managed_wallet.first_bip44_managed_account().expect("Should have managed account");
        assert!(
            managed_account.transactions.contains_key(&coinbase_tx.txid()),
            "Coinbase should be in regular transactions"
        );

        // UTXO should be created with is_coinbase = true
        assert!(!managed_account.utxos.is_empty(), "UTXO should be created for coinbase");
        let utxo = managed_account.utxos.values().next().expect("Should have UTXO");
        assert!(utxo.is_coinbase, "UTXO should be marked as coinbase");

        // Coinbase should be in immature_transactions() since it hasn't matured
        let immature_txs = managed_wallet.immature_transactions();
        assert_eq!(immature_txs.len(), 1, "Should have one immature transaction");
        assert_eq!(immature_txs[0].txid(), coinbase_tx.txid());

        // Immature balance should reflect the coinbase value
        assert_eq!(managed_wallet.balance().immature(), 5_000_000_000);

        // Spendable UTXOs should be empty (coinbase not mature)
        assert!(
            managed_wallet.get_spendable_utxos().is_empty(),
            "Coinbase UTXO should not be spendable until mature"
        );
    }

    /// Test that spending a wallet-owned UTXO without creating change is detected
    #[tokio::test]
    async fn test_wallet_checker_detects_spend_only_transaction() {
        let network = Network::Testnet;
        let mut wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
            .expect("Should create wallet");

        let mut managed_wallet =
            ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

        // Prepare a managed BIP44 account and derive a receive address
        let wallet_account =
            wallet.accounts.standard_bip44_accounts.get(&0).expect("Should have BIP44 account");

        let receive_address = managed_wallet
            .first_bip44_managed_account_mut()
            .expect("Should have managed account")
            .next_receive_address(Some(&wallet_account.account_xpub), true)
            .expect("Should derive receive address");

        // Fund the wallet with a transaction paying to the receive address
        let funding_value = 50_000_000u64;
        let funding_tx = create_transaction_to_address(&receive_address, funding_value);
        let funding_context = TransactionContext::InBlock {
            height: 1,
            block_hash: Some(BlockHash::from_slice(&[2u8; 32]).expect("Should create block hash")),
            timestamp: Some(1_650_000_000),
        };

        let funding_result =
            managed_wallet.check_transaction(&funding_tx, funding_context, &mut wallet, true).await;
        assert!(funding_result.is_relevant, "Funding transaction must be relevant");
        assert_eq!(funding_result.total_received, funding_value);

        // Build a spend transaction that sends funds to an external address only
        let external_address = Address::p2pkh(
            &dashcore::PublicKey::from_slice(&[0x02; 33]).expect("Should create pubkey"),
            network,
        );
        let spend_tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: funding_tx.txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: 0xffffffff,
                witness: dashcore::Witness::new(),
            }],
            output: vec![TxOut {
                value: funding_value - 1_000, // leave a small fee
                script_pubkey: external_address.script_pubkey(),
            }],
            special_transaction_payload: None,
        };

        let spend_context = TransactionContext::InBlock {
            height: 2,
            block_hash: Some(BlockHash::from_slice(&[3u8; 32]).expect("Should create block hash")),
            timestamp: Some(1_650_000_100),
        };

        let spend_result =
            managed_wallet.check_transaction(&spend_tx, spend_context, &mut wallet, true).await;

        assert!(spend_result.is_relevant, "Spend transaction should be detected");
        assert_eq!(spend_result.total_received, 0);
        assert_eq!(spend_result.total_sent, funding_value);

        // Ensure the UTXO was removed and the transaction record reflects the spend
        let account = managed_wallet
            .accounts
            .standard_bip44_accounts
            .get(&0)
            .expect("Should have managed BIP44 account");

        assert!(account.utxos.is_empty(), "Spent UTXO should be removed");

        let record = account
            .transactions
            .get(&spend_tx.txid())
            .expect("Spend transaction should be recorded");
        assert_eq!(record.net_amount, -(funding_value as i64));
    }

    /// Test the full coinbase maturity flow - immature to mature transition
    #[tokio::test]
    async fn test_wallet_checker_immature_transaction_flow() {
        use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;

        let network = Network::Testnet;
        let mut wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
            .expect("Should create wallet");

        let mut managed_wallet =
            ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

        // Get a wallet address
        let account =
            wallet.accounts.standard_bip44_accounts.get(&0).expect("Should have BIP44 account");
        let xpub = account.account_xpub;

        let address = managed_wallet
            .first_bip44_managed_account_mut()
            .expect("Should have managed account")
            .next_receive_address(Some(&xpub), true)
            .expect("Should get address");

        // Create a coinbase transaction
        let coinbase_tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::all_zeros(), // Coinbase has null previous output
                    vout: 0xffffffff,
                },
                script_sig: ScriptBuf::new(),
                sequence: 0xffffffff,
                witness: dashcore::Witness::new(),
            }],
            output: vec![TxOut {
                value: 5_000_000_000, // 50 DASH block reward
                script_pubkey: address.script_pubkey(),
            }],
            special_transaction_payload: None,
        };

        let block_height = 100000;

        let context = TransactionContext::InBlock {
            height: block_height,
            block_hash: Some(BlockHash::from_slice(&[1u8; 32]).expect("Should create block hash")),
            timestamp: Some(1234567890),
        };

        // Process the coinbase transaction
        let result =
            managed_wallet.check_transaction(&coinbase_tx, context, &mut wallet, true).await;
        // Set synced_height to block where coinbase was received to trigger balance updates.
        managed_wallet.update_synced_height(block_height);

        // Should be relevant
        assert!(result.is_relevant);
        assert_eq!(result.total_received, 5_000_000_000);

        let managed_account =
            managed_wallet.first_bip44_managed_account().expect("Should have managed account");
        assert!(
            managed_account.transactions.contains_key(&coinbase_tx.txid()),
            "Coinbase should be in regular transactions"
        );

        assert!(!managed_account.utxos.is_empty(), "UTXO should be created for coinbase");
        let utxo = managed_account.utxos.values().next().expect("Should have UTXO");
        assert!(utxo.is_coinbase, "UTXO should be marked as coinbase");
        assert_eq!(utxo.height, block_height);

        // Coinbase is in immature_transactions() since it hasn't matured
        let immature_txs = managed_wallet.immature_transactions();
        assert_eq!(immature_txs.len(), 1, "Should have one immature transaction");

        // Immature balance should reflect the coinbase value
        assert_eq!(managed_wallet.balance().immature(), 5_000_000_000);

        // Spendable UTXOs should be empty (coinbase not mature yet)
        assert!(
            managed_wallet.get_spendable_utxos().is_empty(),
            "No spendable UTXOs while coinbase is immature"
        );

        // Spendable UTXOs should be empty (coinbase not mature yet)
        assert!(
            managed_wallet.get_spendable_utxos().is_empty(),
            "No spendable UTXOs while coinbase is immature"
        );

        // Now advance the chain height past maturity (100 blocks)
        let mature_height = block_height + 100;
        managed_wallet.update_synced_height(mature_height);

        let managed_account =
            managed_wallet.first_bip44_managed_account().expect("Should have managed account");
        assert!(
            managed_account.transactions.contains_key(&coinbase_tx.txid()),
            "Coinbase should still be in regular transactions"
        );

        // Coinbase is no longer in immature_transactions()
        let immature_txs = managed_wallet.immature_transactions();
        assert!(immature_txs.is_empty(), "Matured coinbase should not be in immature transactions");

        // Immature balance should now be zero
        let immature_balance = managed_wallet.balance().immature();
        assert_eq!(immature_balance, 0, "Immature balance should be zero after maturity");

        // Spendable UTXOs should now contain the matured coinbase
        let spendable = managed_wallet.get_spendable_utxos();
        assert_eq!(spendable.len(), 1, "Should have one spendable UTXO after maturity");
    }

    /// Test mempool context for timestamp/height handling
    #[tokio::test]
    async fn test_wallet_checker_mempool_context() {
        let network = Network::Testnet;
        let mut wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
            .expect("Should create wallet");

        let mut managed_wallet =
            ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

        // Get a wallet address
        let account =
            wallet.accounts.standard_bip44_accounts.get(&0).expect("Should have BIP44 account");
        let xpub = account.account_xpub;

        let address = managed_wallet
            .first_bip44_managed_account_mut()
            .expect("Should have managed account")
            .next_receive_address(Some(&xpub), true)
            .expect("Should get address");

        let tx = create_transaction_to_address(&address, 100_000);

        // Test with Mempool context
        let context = TransactionContext::Mempool;

        let result = managed_wallet.check_transaction(&tx, context, &mut wallet, true).await;

        // Should be relevant
        assert!(result.is_relevant);
        assert_eq!(result.total_received, 100_000);

        // Check that transaction was stored with correct context (no height, no block hash)
        let managed_account =
            managed_wallet.first_bip44_managed_account().expect("Should have managed account");

        let stored_tx =
            managed_account.transactions.get(&tx.txid()).expect("Should have stored transaction");
        assert_eq!(stored_tx.height, None, "Mempool transaction should have no height");
        assert_eq!(stored_tx.block_hash, None, "Mempool transaction should have no block hash");
        assert_eq!(stored_tx.timestamp, 0, "Mempool transaction should have timestamp 0");
    }

    /// Test that rescanning a block marks transactions as existing
    #[tokio::test]
    async fn test_transaction_rescan_marks_as_existing() {
        let network = Network::Testnet;
        let mut wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
            .expect("Should create wallet");

        let mut managed_wallet =
            ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

        // Get a wallet address
        let account =
            wallet.accounts.standard_bip44_accounts.get(&0).expect("Should have BIP44 account");
        let xpub = account.account_xpub;

        let address = managed_wallet
            .first_bip44_managed_account_mut()
            .expect("Should have managed account")
            .next_receive_address(Some(&xpub), true)
            .expect("Should get address");

        let tx = create_transaction_to_address(&address, 100_000);

        let context = TransactionContext::InBlock {
            height: 100,
            block_hash: Some(BlockHash::from_slice(&[1u8; 32]).expect("Should create block hash")),
            timestamp: Some(1234567890),
        };

        // First processing - should be marked as new
        let result1 = managed_wallet.check_transaction(&tx, context, &mut wallet, true).await;

        assert!(result1.is_relevant, "Transaction should be relevant");
        assert!(
            result1.is_new_transaction,
            "First time seeing transaction should be marked as new"
        );
        assert_eq!(result1.total_received, 100_000);

        // Verify transaction is stored
        let managed_account =
            managed_wallet.first_bip44_managed_account().expect("Should have managed account");
        assert!(
            managed_account.transactions.contains_key(&tx.txid()),
            "Transaction should be stored"
        );
        let tx_count_before = managed_account.transactions.len();
        let total_tx_count_before = managed_wallet.metadata.total_transactions;
        assert_eq!(
            total_tx_count_before, 1,
            "total_transactions should be 1 after first processing"
        );

        // Second processing (simulating rescan) - should be marked as existing
        let result2 = managed_wallet.check_transaction(&tx, context, &mut wallet, true).await;

        assert!(result2.is_relevant, "Transaction should still be relevant on rescan");
        assert!(
            !result2.is_new_transaction,
            "Re-processing transaction should be marked as existing, not new"
        );
        assert_eq!(result2.total_received, 100_000);

        // Verify transaction count hasn't changed (no duplicates)
        let managed_account =
            managed_wallet.first_bip44_managed_account().expect("Should have managed account");
        assert_eq!(
            managed_account.transactions.len(),
            tx_count_before,
            "Transaction count should not increase on rescan"
        );

        // Verify total_transactions metadata hasn't changed on rescan
        assert_eq!(
            managed_wallet.metadata.total_transactions, total_tx_count_before,
            "total_transactions should not increase on rescan"
        );
    }
}
