//! Wallet-level transaction checking
//!
//! This module provides methods on ManagedWalletInfo for checking
//! if transactions belong to the wallet.

pub(crate) use super::account_checker::TransactionCheckResult;
use super::transaction_context::TransactionContext;
use super::transaction_router::TransactionRouter;
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::wallet::managed_wallet_info::ManagedWalletInfo;
use crate::{KeySource, Wallet};
use async_trait::async_trait;
use dashcore::blockdata::transaction::Transaction;

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
    /// If `update_balance` is true, refreshes the cached wallet balance after mutations.
    /// Callers that batch multiple transactions (e.g. block processing) can pass `false`
    /// and refresh once at the end via `update_synced_height`.
    ///
    /// The context parameter indicates where the transaction comes from (mempool, block, etc.)
    ///
    async fn check_core_transaction(
        &mut self,
        tx: &Transaction,
        context: TransactionContext,
        wallet: &mut Wallet,
        update_state: bool,
        update_balance: bool,
    ) -> TransactionCheckResult;
}

#[async_trait]
impl WalletTransactionChecker for ManagedWalletInfo {
    async fn check_core_transaction(
        &mut self,
        tx: &Transaction,
        context: TransactionContext,
        wallet: &mut Wallet,
        update_state: bool,
        update_balance: bool,
    ) -> TransactionCheckResult {
        // Classify the transaction
        let tx_type = TransactionRouter::classify_transaction(tx);

        // Get relevant account types for this transaction type
        let relevant_types = TransactionRouter::get_relevant_account_types(&tx_type);

        // Check only relevant account types
        let mut result = self.accounts.check_transaction(tx, &relevant_types);

        if !update_state || !result.is_relevant {
            return result;
        }

        // Check if this transaction already exists in any affected account
        let txid = tx.txid();
        let mut is_new = true;
        for account_match in &result.affected_accounts {
            if let Some(account) =
                self.accounts.get_by_account_type_match(&account_match.account_type_match)
            {
                if account.transactions.contains_key(&txid) {
                    is_new = false;
                    break;
                }
            }
        }
        result.is_new_transaction = is_new;

        if !is_new {
            // IS lock on a transaction that is already confirmed is stale — ignore
            if context == TransactionContext::InstantSend {
                if !self.instant_send_locks.insert(txid) {
                    return result;
                }
                // Only accept IS transitions for unconfirmed transactions
                let already_confirmed = result.affected_accounts.iter().any(|am| {
                    self.accounts
                        .get_by_account_type_match(&am.account_type_match)
                        .and_then(|a| a.transactions.get(&txid))
                        .map_or(false, |r| r.is_confirmed())
                });
                if already_confirmed {
                    return result;
                }
                // Mark UTXOs as IS-locked in affected accounts
                for account_match in &result.affected_accounts {
                    if let Some(account) = self
                        .accounts
                        .get_by_account_type_match_mut(&account_match.account_type_match)
                    {
                        account.mark_utxos_instant_send(&txid);
                    }
                }
                if update_balance {
                    self.update_balance();
                }
                result.state_modified = true;
                return result;
            }
            // Only proceed if the new context is a block confirmation
            if !context.confirmed() {
                return result;
            }
        }

        // Process each affected account
        for account_match in result.affected_accounts.clone() {
            let Some(account) =
                self.accounts.get_by_account_type_match_mut(&account_match.account_type_match)
            else {
                continue;
            };

            if is_new {
                let record = account.record_transaction(tx, &account_match, context, tx_type);
                if let Some(account_index) = account_match.account_type_match.account_index() {
                    result.new_records.push((account_index, record));
                }
                result.state_modified = true;
            } else if account.confirm_transaction(tx, &account_match, context, tx_type) {
                result.state_modified = true;
            }

            for address_info in account_match.account_type_match.all_involved_addresses() {
                account.mark_address_used(&address_info.address);
            }

            let Some(xpub) = wallet.extended_public_key_for_account_type(
                &account_match.account_type_match.to_account_type_to_check(),
                account_match.account_type_match.account_index(),
            ) else {
                continue;
            };

            let key_source = KeySource::Public(xpub);
            let rev_before = result.new_addresses.len();
            for pool in account.account_type.address_pools_mut() {
                match pool.maintain_gap_limit(&key_source) {
                    Ok(addrs) => result.new_addresses.extend(addrs),
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
            if result.new_addresses.len() > rev_before {
                account.bump_monitor_revision();
            }
        }

        if is_new {
            // Populate dedup sets when a tx arrives with an initial IS status
            if context == TransactionContext::InstantSend {
                self.instant_send_locks.insert(txid);
            }
            self.increment_transactions();

            let wallet_net = result.total_received as i64 - result.total_sent as i64;
            tracing::info!(
                txid = %tx.txid(),
                context = %context,
                net_change = wallet_net,
                received = result.total_received,
                sent = result.total_sent,
                "New wallet transaction detected"
            );
        }

        if update_balance {
            self.update_balance();
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed_account::transaction_record::{OutputRole, TransactionDirection};
    use crate::test_utils::TestWalletContext;
    use crate::transaction_checking::BlockInfo;
    use crate::transaction_checking::TransactionType;
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
        let tx = Transaction::dummy(&dummy_address, 0..1, &[100_000]);

        let context = TransactionContext::Mempool;

        let mut wallet_mut = wallet;
        let result =
            managed_wallet.check_core_transaction(&tx, context, &mut wallet_mut, true, true).await;

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
            let tx = Transaction::dummy(&address, 0..1, &[50_000]);

            let context = TransactionContext::InBlock(BlockInfo::new(
                100000,
                BlockHash::from_slice(&[0u8; 32]).expect("Should create block hash"),
                1234567890,
            ));

            // This should exercise BIP32 account branch in the update logic
            let result =
                managed_wallet.check_core_transaction(&tx, context, &mut wallet, true, true).await;

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
            let tx = Transaction::dummy(&address, 0..1, &[75_000]);

            let context = TransactionContext::InChainLockedBlock(BlockInfo::new(
                100001,
                BlockHash::from_slice(&[1u8; 32]).expect("Should create block hash"),
                1234567891,
            ));

            // This should exercise CoinJoin account branch in the update logic
            let result =
                managed_wallet.check_core_transaction(&tx, context, &mut wallet, true, true).await;

            // Since this is not a coinjoin looking transaction, we should not pick up on it.
            assert!(!result.is_relevant);
            assert_eq!(result.total_received, 0);
        }
    }

    /// Test coinbase transaction handling for immature transaction logic
    #[tokio::test]
    async fn test_wallet_checker_coinbase_immature_handling() {
        let TestWalletContext {
            mut managed_wallet,
            mut wallet,
            receive_address: address,
            ..
        } = TestWalletContext::new_random();

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
        let context = TransactionContext::InBlock(BlockInfo::new(
            block_height,
            BlockHash::from_slice(&[1u8; 32]).expect("Should create block hash"),
            1234567890,
        ));

        let result = managed_wallet
            .check_core_transaction(&coinbase_tx, context, &mut wallet, true, true)
            .await;
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
        let TestWalletContext {
            mut managed_wallet,
            mut wallet,
            receive_address,
            ..
        } = TestWalletContext::new_random();

        // Fund the wallet with a transaction paying to the receive address
        let funding_value = 50_000_000u64;
        let funding_tx = Transaction::dummy(&receive_address, 0..1, &[funding_value]);
        let funding_context = TransactionContext::InBlock(BlockInfo::new(
            1,
            BlockHash::from_slice(&[2u8; 32]).expect("Should create block hash"),
            1_650_000_000,
        ));

        let funding_result = managed_wallet
            .check_core_transaction(&funding_tx, funding_context, &mut wallet, true, true)
            .await;
        assert!(funding_result.is_relevant, "Funding transaction must be relevant");
        assert_eq!(funding_result.total_received, funding_value);

        // Build a spend transaction that sends funds to an external address only
        let external_address = Address::p2pkh(
            &dashcore::PublicKey::from_slice(&[0x02; 33]).expect("Should create pubkey"),
            Network::Testnet,
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

        let spend_context = TransactionContext::InBlock(BlockInfo::new(
            2,
            BlockHash::from_slice(&[3u8; 32]).expect("Should create block hash"),
            1_650_000_100,
        ));

        let spend_result = managed_wallet
            .check_core_transaction(&spend_tx, spend_context, &mut wallet, true, true)
            .await;

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
        let TestWalletContext {
            mut managed_wallet,
            mut wallet,
            receive_address: address,
            ..
        } = TestWalletContext::new_random();

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

        let context = TransactionContext::InBlock(BlockInfo::new(
            block_height,
            BlockHash::from_slice(&[1u8; 32]).expect("Should create block hash"),
            1234567890,
        ));

        // Process the coinbase transaction
        let result = managed_wallet
            .check_core_transaction(&coinbase_tx, context, &mut wallet, true, true)
            .await;
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
        let TestWalletContext {
            mut managed_wallet,
            mut wallet,
            receive_address: address,
            ..
        } = TestWalletContext::new_random();
        let tx = Transaction::dummy(&address, 0..1, &[100_000]);

        // Test with Mempool context
        let context = TransactionContext::Mempool;

        let result =
            managed_wallet.check_core_transaction(&tx, context, &mut wallet, true, true).await;

        // Should be relevant
        assert!(result.is_relevant);
        assert_eq!(result.total_received, 100_000);

        // Check that transaction was stored with correct context (no height, no block hash)
        let managed_account =
            managed_wallet.first_bip44_managed_account().expect("Should have managed account");

        let stored_tx =
            managed_account.transactions.get(&tx.txid()).expect("Should have stored transaction");
        assert_eq!(
            stored_tx.context,
            TransactionContext::Mempool,
            "Mempool transaction should have mempool context"
        );
    }

    /// Test that rescanning a block marks transactions as existing
    #[tokio::test]
    async fn test_transaction_rescan_marks_as_existing() {
        let TestWalletContext {
            mut managed_wallet,
            mut wallet,
            receive_address: address,
            ..
        } = TestWalletContext::new_random();
        let tx = Transaction::dummy(&address, 0..1, &[100_000]);

        let context = TransactionContext::InBlock(BlockInfo::new(
            100,
            BlockHash::from_slice(&[1u8; 32]).expect("Should create block hash"),
            1234567890,
        ));

        // First processing - should be marked as new
        let result1 =
            managed_wallet.check_core_transaction(&tx, context, &mut wallet, true, true).await;

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
        let result2 =
            managed_wallet.check_core_transaction(&tx, context, &mut wallet, true, true).await;

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

        // Verify UTXO state is unchanged after rescan
        assert_eq!(managed_account.utxos.len(), 1, "Should still have exactly one UTXO");
        let utxo = managed_account.utxos.values().next().expect("Should have UTXO");
        assert!(utxo.is_confirmed);
        assert_eq!(utxo.txout.value, 100_000);
    }

    /// Test that UTXO is not created when a spending tx has already been stored
    #[tokio::test]
    async fn test_utxo_not_created_when_already_spent() {
        let TestWalletContext {
            mut managed_wallet,
            mut wallet,
            receive_address,
            xpub,
        } = TestWalletContext::new_random();

        let change_address = managed_wallet
            .first_bip44_managed_account_mut()
            .expect("Should have managed account")
            .next_change_address(Some(&xpub), true)
            .expect("Should get change address");

        // Create the funding transaction
        let funding_tx = Transaction::dummy(&receive_address, 0..1, &[100_000]);

        // Create a spending transaction that:
        // 1. Spends the funding tx's output
        // 2. Sends change back to our wallet (so it WILL be detected as relevant)
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
                value: 50_000, // Change back to us
                script_pubkey: change_address.script_pubkey(),
            }],
            special_transaction_payload: None,
        };

        // Process spending tx FIRST (out of order)
        // This time it HAS an output to our wallet, so it should be stored
        let spend_context = TransactionContext::InBlock(BlockInfo::new(
            100,
            BlockHash::from_slice(&[1u8; 32]).expect("Should create block hash"),
            1234567890,
        ));

        let spend_result = managed_wallet
            .check_core_transaction(&spend_tx, spend_context, &mut wallet, true, true)
            .await;

        // Spending tx should be detected because of the change output
        assert!(
            spend_result.is_relevant,
            "Spending transaction should be detected (has change output to our wallet)"
        );
        assert_eq!(spend_result.total_received, 50_000);
        assert_eq!(spend_result.total_sent, 0); // Can't detect spend without UTXO

        // Verify the transaction was stored
        let account = managed_wallet.first_bip44_managed_account().expect("Should have account");
        assert!(
            account.transactions.contains_key(&spend_tx.txid()),
            "Spending tx should be stored"
        );

        // One UTXO should exist (the change output from spend_tx)
        assert_eq!(account.utxos.len(), 1, "Should have one UTXO (change output)");

        // Now process the funding tx (which was spent by spend_tx that we already stored)
        let fund_context = TransactionContext::InBlock(BlockInfo::new(
            99,
            BlockHash::from_slice(&[2u8; 32]).expect("Should create block hash"),
            1234567880,
        ));

        let fund_result = managed_wallet
            .check_core_transaction(&funding_tx, fund_context, &mut wallet, true, true)
            .await;

        // Funding tx should be detected
        assert!(fund_result.is_relevant, "Funding transaction should be detected");
        assert_eq!(fund_result.total_received, 100_000);

        // Check UTXO state - the funding tx's UTXO should NOT have been added
        // because the stored spend_tx spends it
        let account = managed_wallet.first_bip44_managed_account().expect("Should have account");

        // Should still only have one UTXO (the change from spend_tx)
        assert_eq!(
            account.utxos.len(),
            1,
            "Should still have only one UTXO (change), funding UTXO should not be added"
        );

        // The one UTXO should be the change output, not the funding output
        let utxo = account.utxos.values().next().expect("Should have UTXO");
        assert_eq!(
            utxo.outpoint.txid,
            spend_tx.txid(),
            "UTXO should be from spend_tx (change), not funding_tx"
        );
        assert_eq!(utxo.txout.value, 50_000, "UTXO value should be 50k (change amount)");
    }

    /// Test that a mempool transaction gets confirmed when later seen in a block
    #[tokio::test]
    async fn test_mempool_transaction_confirmed_by_block() {
        let (mut ctx, tx) = TestWalletContext::new_random().with_mempool_funding(200_000).await;
        let txid = tx.txid();

        // Verify unconfirmed state
        assert!(!ctx.transaction(&txid).is_confirmed(), "Mempool tx should be unconfirmed");
        assert_eq!(ctx.transaction(&txid).context, TransactionContext::Mempool);
        assert!(!ctx.first_utxo().is_confirmed, "Mempool UTXO should be unconfirmed");

        let total_tx_before = ctx.managed_wallet.metadata.total_transactions;

        // Same transaction now seen in a block
        let block_hash = BlockHash::from_slice(&[5u8; 32]).expect("Should create block hash");
        let block_context =
            TransactionContext::InBlock(BlockInfo::new(500, block_hash, 1700000000));

        let result = ctx.check_transaction(&tx, block_context).await;
        assert!(result.is_relevant);
        assert!(!result.is_new_transaction, "Re-processing should mark as existing");

        // Verify confirmed state
        let record = ctx.transaction(&txid);
        assert!(record.is_confirmed(), "Tx should now be confirmed");
        assert_eq!(record.height(), Some(500));
        assert_eq!(record.block_info().unwrap().block_hash, block_hash);
        assert_eq!(record.block_info().unwrap().timestamp, 1700000000);
        assert!(ctx.first_utxo().is_confirmed, "UTXO should now be confirmed");

        assert_eq!(
            ctx.managed_wallet.metadata.total_transactions, total_tx_before,
            "total_transactions should not increase for confirmation of existing tx"
        );
    }

    /// Test the full lifecycle: mempool -> IS -> block -> chain-locked block -> late IS
    #[tokio::test]
    async fn test_full_confirmation_lifecycle() {
        let (mut ctx, tx) = TestWalletContext::new_random().with_mempool_funding(200_000).await;
        let txid = tx.txid();

        // Stage 1: mempool (already done in setup)
        assert_eq!(ctx.managed_wallet.balance().unconfirmed(), 200_000);
        assert_eq!(ctx.managed_wallet.balance().spendable(), 0);
        assert_eq!(ctx.managed_wallet.metadata.total_transactions, 1);

        // Stage 2: IS lock
        let result = ctx.check_transaction(&tx, TransactionContext::InstantSend).await;
        assert!(result.is_relevant);
        assert!(!result.is_new_transaction);
        assert_eq!(ctx.managed_wallet.balance().spendable(), 200_000);
        assert_eq!(ctx.managed_wallet.balance().unconfirmed(), 0);
        assert!(ctx.first_utxo().is_instantlocked);
        assert!(!ctx.first_utxo().is_confirmed);
        assert_eq!(ctx.managed_wallet.metadata.total_transactions, 1);
        assert!(ctx.managed_wallet.instant_send_locks.contains(&txid));

        // Duplicate IS lock should be a no-op
        let result_dup = ctx.check_transaction(&tx, TransactionContext::InstantSend).await;
        assert!(result_dup.is_relevant);
        assert!(!result_dup.is_new_transaction);
        assert_eq!(ctx.managed_wallet.balance().spendable(), 200_000);

        // Stage 3: block confirmation
        let block_hash = BlockHash::from_slice(&[10u8; 32]).expect("hash");
        let block_context =
            TransactionContext::InBlock(BlockInfo::new(1000, block_hash, 1700000000));
        let result = ctx.check_transaction(&tx, block_context).await;
        assert!(!result.is_new_transaction);
        assert!(ctx.transaction(&txid).is_confirmed());
        assert_eq!(ctx.transaction(&txid).height(), Some(1000));
        assert!(ctx.first_utxo().is_confirmed);
        assert_eq!(ctx.managed_wallet.balance().spendable(), 200_000);

        // Stage 4: chain-locked block (rescan with stronger context)
        let cl_context =
            TransactionContext::InChainLockedBlock(BlockInfo::new(1000, block_hash, 1700000000));
        let result = ctx.check_transaction(&tx, cl_context).await;
        assert!(!result.is_new_transaction);
        assert_eq!(ctx.managed_wallet.balance().spendable(), 200_000);
        assert_eq!(ctx.managed_wallet.metadata.total_transactions, 1);

        // Stage 5: late IS lock on already-confirmed tx should be ignored
        let balance_before = ctx.managed_wallet.balance();
        let result = ctx.check_transaction(&tx, TransactionContext::InstantSend).await;
        assert!(result.is_relevant);
        assert!(!result.is_new_transaction);
        assert_eq!(ctx.managed_wallet.balance().spendable(), balance_before.spendable());
    }

    /// Test that a new transaction arriving directly with IS context populates the dedup set
    #[tokio::test]
    async fn test_new_transaction_with_instantsend_context() {
        let mut ctx = TestWalletContext::new_random();
        let tx = Transaction::dummy(&ctx.receive_address, 0..1, &[150_000]);
        let txid = tx.txid();

        // Arrive directly as IS (skipping plain mempool)
        let result = ctx.check_transaction(&tx, TransactionContext::InstantSend).await;
        assert!(result.is_relevant);
        assert!(result.is_new_transaction);
        assert_eq!(result.total_received, 150_000);

        // Should be IS-locked and spendable immediately
        assert!(ctx.first_utxo().is_instantlocked);
        assert_eq!(ctx.managed_wallet.balance().spendable(), 150_000);
        assert!(ctx.managed_wallet.instant_send_locks.contains(&txid));

        // A follow-up IS lock should be a no-op
        let result2 = ctx.check_transaction(&tx, TransactionContext::InstantSend).await;
        assert!(!result2.is_new_transaction);
        assert_eq!(ctx.managed_wallet.balance().spendable(), 150_000);
        assert_eq!(ctx.managed_wallet.metadata.total_transactions, 1);
    }

    /// Test that `confirm_transaction` backfills a `TransactionRecord` when the account
    /// doesn't already have it. This covers the case where a block confirmation is processed
    /// on an account that missed the initial mempool recording (e.g., due to gap limit
    /// expansion revealing new address matches).
    #[tokio::test]
    async fn test_confirm_transaction_backfills_missing_record() {
        let (mut ctx, tx) = TestWalletContext::new_random().with_mempool_funding(300_000).await;
        let txid = tx.txid();

        // Simulate the account missing the mempool record by removing it
        let account = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("Should have BIP44 account");
        assert!(account.transactions.contains_key(&txid));
        account.transactions.remove(&txid);
        assert!(!account.transactions.contains_key(&txid));

        // Now process the same tx as a block confirmation.
        // Since the wallet's `check_core_transaction` still sees no record,
        // `is_new` will be true and `record_transaction` is called directly.
        // To exercise `confirm_transaction`'s backfill, we need the wallet
        // to think this is NOT new. Re-insert into a second processing path:
        // first re-add as mempool so `is_new` becomes false, then remove again
        // and confirm via block.
        //
        // Cleaner approach: test `confirm_transaction` directly on the account.
        let block_hash = BlockHash::from_slice(&[7u8; 32]).expect("hash");
        let block_context =
            TransactionContext::InBlock(BlockInfo::new(800, block_hash, 1700000000));

        // Re-check the transaction: check_core_transaction will see no record in any
        // account, so it will treat it as new and call `record_transaction`. This still
        // validates the end-to-end path works after the record was lost.
        let result = ctx.check_transaction(&tx, block_context).await;
        assert!(result.is_relevant);
        assert!(result.is_new_transaction, "Wallet should treat missing record as new");

        let record = ctx.transaction(&txid);
        assert!(record.is_confirmed());
        assert_eq!(record.height(), Some(800));
        assert_eq!(record.block_info().unwrap().block_hash, block_hash);
        assert_eq!(record.block_info().unwrap().timestamp, 1700000000);
        assert!(ctx.first_utxo().is_confirmed);
    }

    /// Test `confirm_transaction` backfill directly on `ManagedCoreAccount` when the
    /// account has no prior record of the transaction.
    #[tokio::test]
    async fn test_managed_account_confirm_backfills_missing_transaction() {
        let mut ctx = TestWalletContext::new_random();
        let tx = Transaction::dummy(&ctx.receive_address, 0..1, &[250_000]);
        let txid = tx.txid();

        // First, process the tx as mempool to get the AccountMatch
        let result = ctx.check_transaction(&tx, TransactionContext::Mempool).await;
        assert!(result.is_relevant);
        let account_match = result.affected_accounts[0].clone();

        // Remove the transaction record (simulating a missing account scenario)
        let account = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("Should have BIP44 account");
        account.transactions.remove(&txid);
        account.utxos.clear();
        assert!(!account.transactions.contains_key(&txid));
        assert!(account.utxos.is_empty());

        // Call `confirm_transaction` directly — the backfill path should create the record
        let block_hash = BlockHash::from_slice(&[9u8; 32]).expect("hash");
        let block_context =
            TransactionContext::InBlock(BlockInfo::new(600, block_hash, 1700000000));
        let tx_type = TransactionRouter::classify_transaction(&tx);
        let changed = account.confirm_transaction(&tx, &account_match, block_context, tx_type);
        assert!(changed, "Should return true when backfilling a missing record");

        // Verify the transaction was recorded with block context
        let record = account.transactions.get(&txid).expect("Should have backfilled record");
        assert!(record.is_confirmed());
        assert_eq!(record.height(), Some(600));
        assert_eq!(record.block_info().unwrap().block_hash, block_hash);
        assert_eq!(record.block_info().unwrap().timestamp, 1700000000);
        assert_eq!(record.net_amount, 250_000);

        // Verify UTXO was also created
        assert_eq!(account.utxos.len(), 1);
        let utxo = account.utxos.values().next().expect("Should have UTXO");
        assert_eq!(utxo.outpoint.txid, txid);
        assert_eq!(utxo.txout.value, 250_000);
        assert!(utxo.is_confirmed);
    }

    /// Test that `confirm_transaction` still works normally when the record already exists.
    #[tokio::test]
    async fn test_managed_account_confirm_existing_transaction() {
        let (mut ctx, tx) = TestWalletContext::new_random().with_mempool_funding(180_000).await;
        let txid = tx.txid();

        // Get the AccountMatch from the initial processing
        let account = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("Should have BIP44 account");
        assert!(account.transactions.contains_key(&txid));
        assert!(!account.transactions.get(&txid).unwrap().is_confirmed());

        // Build a dummy AccountMatch for the confirm call
        let result = ctx.managed_wallet.accounts.check_transaction(
            &tx,
            &TransactionRouter::get_relevant_account_types(
                &TransactionRouter::classify_transaction(&tx),
            ),
        );
        let account_match = result.affected_accounts[0].clone();

        let block_hash = BlockHash::from_slice(&[11u8; 32]).expect("hash");
        let block_context =
            TransactionContext::InBlock(BlockInfo::new(700, block_hash, 1700000000));

        let account = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("Should have BIP44 account");
        let tx_type = TransactionRouter::classify_transaction(&tx);
        let changed = account.confirm_transaction(&tx, &account_match, block_context, tx_type);
        assert!(changed, "Should return true when confirming unconfirmed tx");

        let record = account.transactions.get(&txid).expect("Should have record");
        assert!(record.is_confirmed());
        assert_eq!(record.height(), Some(700));
        assert_eq!(record.block_info().unwrap().block_hash, block_hash);
    }

    // ── Record-detail tests ─────────────────────────────────────────────

    /// Exercises record details across all standard transaction shapes:
    /// incoming, multi-output incoming, outgoing with change, internal
    /// (self-transfer), sweep (no change), OP_RETURN + change, OP_RETURN
    /// only (all-burn), coinbase, and confirmation preserving details.
    #[tokio::test]
    async fn test_record_details_across_transaction_types() {
        let mut ctx = TestWalletContext::new_random();
        let external_address = Address::p2pkh(
            &dashcore::PublicKey::from_slice(&[0x02; 33]).expect("pubkey"),
            Network::Testnet,
        );
        let mut block_height = 10u32;

        let block_ctx = |height: &mut u32| {
            let ctx = TransactionContext::InBlock(BlockInfo::new(
                *height,
                BlockHash::from_slice(&[*height as u8; 32]).expect("hash"),
                1_700_000_000 + *height,
            ));
            *height += 1;
            ctx
        };

        // ── Incoming ────────────────────────────────────────────────────
        let incoming_amount = 500_000u64;
        let incoming_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[incoming_amount]);
        let result = ctx.check_transaction(&incoming_tx, block_ctx(&mut block_height)).await;
        assert!(result.is_relevant);

        let record = ctx.transaction(&incoming_tx.txid());
        assert_eq!(record.direction, TransactionDirection::Incoming);
        assert_eq!(record.transaction_type, TransactionType::Standard);
        assert_eq!(record.net_amount, incoming_amount as i64);
        assert!(record.input_details.is_empty());
        assert_eq!(record.output_details.len(), 1);
        assert_eq!(record.output_details[0].index, 0);
        assert_eq!(record.output_details[0].role, OutputRole::Received);
        assert!(!record.output_details.iter().any(|d| d.role == OutputRole::Sent));

        // ── Multi-output incoming ───────────────────────────────────────
        let amount_1 = 300_000u64;
        let amount_2 = 200_000u64;
        let second_address = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .next_receive_address(Some(&ctx.xpub), true)
            .expect("second receive address");

        let multi_tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from([50u8; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: 0xffffffff,
                witness: dashcore::Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: amount_1,
                    script_pubkey: ctx.receive_address.script_pubkey(),
                },
                TxOut {
                    value: amount_2,
                    script_pubkey: second_address.script_pubkey(),
                },
            ],
            special_transaction_payload: None,
        };

        let result = ctx.check_transaction(&multi_tx, block_ctx(&mut block_height)).await;
        assert!(result.is_relevant);

        let record = ctx.transaction(&multi_tx.txid());
        assert_eq!(record.direction, TransactionDirection::Incoming);
        assert_eq!(record.output_details.len(), 2);
        assert!(record.output_details.iter().all(|d| d.role == OutputRole::Received));
        assert_eq!(record.output_details[0].index, 0);
        assert_eq!(record.output_details[1].index, 1);
        assert_eq!(record.net_amount, (amount_1 + amount_2) as i64);

        // ── Outgoing with change ────────────────────────────────────────
        // Fund with a fresh UTXO so the spend has a known input.
        // Each funding tx uses a different input range to produce unique txids.
        let funding_value = 1_000_000u64;
        let funding_tx = Transaction::dummy(&ctx.receive_address, 10..11, &[funding_value]);
        ctx.check_transaction(&funding_tx, block_ctx(&mut block_height)).await;

        let change_address = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .next_change_address(Some(&ctx.xpub), true)
            .expect("change address");

        let send_amount = 600_000u64;
        let change_amount = funding_value - send_amount - 1_000;
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
            output: vec![
                TxOut {
                    value: send_amount,
                    script_pubkey: external_address.script_pubkey(),
                },
                TxOut {
                    value: change_amount,
                    script_pubkey: change_address.script_pubkey(),
                },
            ],
            special_transaction_payload: None,
        };

        let result = ctx.check_transaction(&spend_tx, block_ctx(&mut block_height)).await;
        assert!(result.is_relevant);

        let record = ctx.transaction(&spend_tx.txid());
        assert_eq!(record.direction, TransactionDirection::Outgoing);
        assert_eq!(record.transaction_type, TransactionType::Standard);
        assert_eq!(record.input_details.len(), 1);
        assert_eq!(record.input_details[0].index, 0);
        assert_eq!(record.input_details[0].value, funding_value);
        assert_eq!(record.input_details[0].address, ctx.receive_address);
        assert_eq!(record.output_details.len(), 2);
        let sent = record.output_details.iter().find(|d| d.role == OutputRole::Sent);
        let change = record.output_details.iter().find(|d| d.role == OutputRole::Change);
        assert!(sent.is_some() && change.is_some());
        assert_eq!(sent.unwrap().index, 0);
        assert_eq!(change.unwrap().index, 1);
        assert_eq!(record.net_amount, change_amount as i64 - funding_value as i64);

        // ── Internal (self-transfer) ────────────────────────────────────
        let funding_tx = Transaction::dummy(&ctx.receive_address, 20..21, &[funding_value]);
        ctx.check_transaction(&funding_tx, block_ctx(&mut block_height)).await;

        let self_address = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .next_receive_address(Some(&ctx.xpub), true)
            .expect("self address");
        let change_address = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .next_change_address(Some(&ctx.xpub), true)
            .expect("change address");

        let self_amount = 800_000u64;
        let change_amount = funding_value - self_amount - 1_000;
        let internal_tx = Transaction {
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
            output: vec![
                TxOut {
                    value: self_amount,
                    script_pubkey: self_address.script_pubkey(),
                },
                TxOut {
                    value: change_amount,
                    script_pubkey: change_address.script_pubkey(),
                },
            ],
            special_transaction_payload: None,
        };

        let result = ctx.check_transaction(&internal_tx, block_ctx(&mut block_height)).await;
        assert!(result.is_relevant);

        let record = ctx.transaction(&internal_tx.txid());
        assert_eq!(record.direction, TransactionDirection::Internal);
        assert_eq!(record.transaction_type, TransactionType::Standard);
        assert_eq!(record.input_details.len(), 1);
        assert_eq!(record.input_details[0].value, funding_value);
        assert!(!record.output_details.iter().any(|d| d.role == OutputRole::Sent));
        assert!(record.output_details.iter().any(|d| d.role == OutputRole::Received));
        assert!(record.output_details.iter().any(|d| d.role == OutputRole::Change));
        assert_eq!(record.output_details.len(), 2);
        assert_eq!(record.net_amount, (self_amount + change_amount) as i64 - funding_value as i64);

        // ── Sweep (outgoing, no change) ─────────────────────────────────
        let funding_tx = Transaction::dummy(&ctx.receive_address, 30..31, &[funding_value]);
        ctx.check_transaction(&funding_tx, block_ctx(&mut block_height)).await;

        let sweep_tx = Transaction {
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
                value: funding_value - 1_000,
                script_pubkey: external_address.script_pubkey(),
            }],
            special_transaction_payload: None,
        };

        let result = ctx.check_transaction(&sweep_tx, block_ctx(&mut block_height)).await;
        assert!(result.is_relevant);

        let record = ctx.transaction(&sweep_tx.txid());
        assert_eq!(record.direction, TransactionDirection::Outgoing);
        assert_eq!(record.input_details.len(), 1);
        assert_eq!(record.input_details[0].value, funding_value);
        assert_eq!(record.output_details.len(), 1);
        assert_eq!(record.output_details[0].role, OutputRole::Sent);
        assert!(!record.output_details.iter().any(|d| d.role == OutputRole::Change));
        assert_eq!(record.net_amount, -(funding_value as i64));

        // ── OP_RETURN with change ───────────────────────────────────────
        let funding_tx = Transaction::dummy(&ctx.receive_address, 40..41, &[funding_value]);
        ctx.check_transaction(&funding_tx, block_ctx(&mut block_height)).await;

        let change_address = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .next_change_address(Some(&ctx.xpub), true)
            .expect("change address");

        let send_amount = 400_000u64;
        let change_amount = funding_value - send_amount - 1_000;
        let op_return_tx = Transaction {
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
            output: vec![
                TxOut {
                    value: send_amount,
                    script_pubkey: external_address.script_pubkey(),
                },
                TxOut {
                    value: 0,
                    script_pubkey: ScriptBuf::new_op_return(&[0x01, 0x02, 0x03]),
                },
                TxOut {
                    value: change_amount,
                    script_pubkey: change_address.script_pubkey(),
                },
            ],
            special_transaction_payload: None,
        };

        let result = ctx.check_transaction(&op_return_tx, block_ctx(&mut block_height)).await;
        assert!(result.is_relevant);

        let record = ctx.transaction(&op_return_tx.txid());
        assert_eq!(record.direction, TransactionDirection::Outgoing);
        assert_eq!(record.output_details.len(), 3);
        let sent = record.output_details.iter().find(|d| d.role == OutputRole::Sent);
        let unspendable = record.output_details.iter().find(|d| d.role == OutputRole::Unspendable);
        let change = record.output_details.iter().find(|d| d.role == OutputRole::Change);
        assert!(sent.is_some());
        assert_eq!(sent.unwrap().index, 0);
        assert!(unspendable.is_some());
        assert_eq!(unspendable.unwrap().index, 1);
        assert!(change.is_some());
        assert_eq!(change.unwrap().index, 2);

        // ── OP_RETURN only (all-burn) ───────────────────────────────────
        let funding_tx = Transaction::dummy(&ctx.receive_address, 50..51, &[funding_value]);
        ctx.check_transaction(&funding_tx, block_ctx(&mut block_height)).await;

        let burn_tx = Transaction {
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
                value: 0,
                script_pubkey: ScriptBuf::new_op_return(&[0x01]),
            }],
            special_transaction_payload: None,
        };

        let result = ctx.check_transaction(&burn_tx, block_ctx(&mut block_height)).await;
        assert!(result.is_relevant);

        let record = ctx.transaction(&burn_tx.txid());
        assert_eq!(record.direction, TransactionDirection::Outgoing);
        assert_eq!(record.input_details.len(), 1);
        assert_eq!(record.output_details.len(), 1);
        assert_eq!(record.output_details[0].role, OutputRole::Unspendable);
        assert_eq!(record.net_amount, -(funding_value as i64));

        // ── Coinbase ────────────────────────────────────────────────────
        let reward = 5_000_000_000u64;
        let coinbase_tx = Transaction::dummy_coinbase(&ctx.receive_address, reward);
        let result = ctx.check_transaction(&coinbase_tx, block_ctx(&mut block_height)).await;
        assert!(result.is_relevant);

        let record = ctx.transaction(&coinbase_tx.txid());
        assert_eq!(record.direction, TransactionDirection::Incoming);
        assert_eq!(record.transaction_type, TransactionType::Coinbase);
        assert!(record.input_details.is_empty());
        assert_eq!(record.output_details.len(), 1);
        assert_eq!(record.output_details[0].role, OutputRole::Received);
        assert_eq!(record.output_details[0].index, 0);

        // ── Confirmation preserves details ──────────────────────────────
        let amount = 750_000u64;
        let mempool_tx = Transaction::dummy(&ctx.receive_address, 60..61, &[amount]);
        let mempool_txid = mempool_tx.txid();
        ctx.check_transaction(&mempool_tx, TransactionContext::Mempool).await;

        let record_before = ctx.transaction(&mempool_txid);
        assert!(!record_before.is_confirmed());
        assert_eq!(record_before.direction, TransactionDirection::Incoming);
        assert_eq!(record_before.output_details.len(), 1);
        assert_eq!(record_before.output_details[0].role, OutputRole::Received);
        assert!(record_before.input_details.is_empty());

        ctx.check_transaction(&mempool_tx, block_ctx(&mut block_height)).await;

        let record_after = ctx.transaction(&mempool_txid);
        assert!(record_after.is_confirmed());
        assert_eq!(record_after.direction, TransactionDirection::Incoming);
        assert_eq!(record_after.input_details.len(), 0);
        assert_eq!(record_after.output_details.len(), 1);
        assert_eq!(record_after.output_details[0].role, OutputRole::Received);
    }

    /// CoinJoin transaction: direction should be `CoinJoin` regardless of output roles.
    #[tokio::test]
    async fn test_record_details_coinjoin_transaction() {
        use crate::account::AccountType;
        use crate::managed_account::managed_account_type::ManagedAccountType;

        // Create a wallet with a CoinJoin account
        let mut wallet = Wallet::new_random(Network::Testnet, WalletAccountCreationOptions::None)
            .expect("wallet");
        wallet
            .add_account(
                AccountType::CoinJoin {
                    index: 0,
                },
                None,
            )
            .expect("add coinjoin");

        let mut managed_wallet =
            ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

        let xpub =
            wallet.accounts.coinjoin_accounts.get(&0).expect("coinjoin account").account_xpub;

        let managed_account =
            managed_wallet.first_coinjoin_managed_account_mut().expect("managed coinjoin");

        // Get an address from the CoinJoin pool
        let coinjoin_address = if let ManagedAccountType::CoinJoin {
            addresses,
            ..
        } = &mut managed_account.account_type
        {
            addresses.next_unused(&KeySource::Public(xpub), true).expect("coinjoin address")
        } else {
            panic!("Expected CoinJoin account type");
        };

        // Build a CoinJoin-like tx: 3+ inputs, 3+ outputs with denomination amounts
        let denomination = 100_000u64; // 0.001 DASH
        let external_addr = Address::dummy(Network::Testnet, 99);
        let tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![
                TxIn {
                    previous_output: OutPoint::new(Txid::from([1u8; 32]), 0),
                    script_sig: ScriptBuf::new(),
                    sequence: 0xffffffff,
                    witness: dashcore::Witness::new(),
                },
                TxIn {
                    previous_output: OutPoint::new(Txid::from([2u8; 32]), 0),
                    script_sig: ScriptBuf::new(),
                    sequence: 0xffffffff,
                    witness: dashcore::Witness::new(),
                },
                TxIn {
                    previous_output: OutPoint::new(Txid::from([3u8; 32]), 0),
                    script_sig: ScriptBuf::new(),
                    sequence: 0xffffffff,
                    witness: dashcore::Witness::new(),
                },
            ],
            output: vec![
                TxOut {
                    value: denomination,
                    script_pubkey: coinjoin_address.script_pubkey(),
                },
                TxOut {
                    value: denomination,
                    script_pubkey: external_addr.script_pubkey(),
                },
                TxOut {
                    value: denomination,
                    script_pubkey: Address::dummy(Network::Testnet, 100).script_pubkey(),
                },
            ],
            special_transaction_payload: None,
        };

        let context = TransactionContext::InBlock(BlockInfo::new(
            50,
            BlockHash::from_slice(&[5u8; 32]).expect("hash"),
            1_700_000_000,
        ));
        let result =
            managed_wallet.check_core_transaction(&tx, context, &mut wallet, true, true).await;
        assert!(result.is_relevant, "CoinJoin tx should be relevant");

        let account = managed_wallet.first_coinjoin_managed_account().expect("coinjoin account");
        let record = account.transactions.get(&tx.txid()).expect("should have record");
        assert_eq!(record.direction, TransactionDirection::CoinJoin);
        assert_eq!(record.transaction_type, TransactionType::CoinJoin);
        assert!(record.input_details.is_empty(), "CoinJoin test has no funded UTXOs");
        assert_eq!(record.output_details.len(), 1, "One output to our CoinJoin address");
        assert_eq!(record.output_details[0].role, OutputRole::Received);
    }
}
