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
use dashcore::{Amount, SignedAmount};

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
    /// and refresh once at the end via `update_last_processed_height`.
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

        // #649: remember every spend seen in a block, independent of the
        // spending tx's classification or whether the wallet can attribute it.
        // Insert-only here (no account mutation), so a spend that IS attributed
        // still has its `input_details` built from the live funding UTXO by
        // `record_transaction` below. Mempool / IS-lock spends are deliberately
        // never recorded — an unconfirmed spend must not invalidate a coin.
        let block_height = if update_state {
            context.block_info().map(|info| info.height())
        } else {
            None
        };
        if let Some(height) = block_height {
            // The observed-spent map is persisted wallet state: growing it is a
            // state modification in its own right, even when the tx is
            // otherwise irrelevant — losing an entry across a restart would
            // reopen #649 for that coin.
            if self.record_observed_spends(tx, height) {
                result.state_modified = true;
            }
        }

        // A final arrival settles its inputs whether or not this transaction
        // looks relevant to us. Relevance is computed from matching outputs
        // and from inputs still present in `utxos` — but a recorded loser
        // already removed the shared input, so a winner that spends our coin
        // and pays only external addresses matches nothing and would return
        // below with the loser still credited. Sweep first, wallet-wide, next
        // to `record_observed_spends` above for the same reason it is
        // unconditional.
        if update_state && (context.confirmed() || context.is_instant_send()) {
            let sweep = self.sweep_conflicts(tx, &context);
            if !sweep.is_empty() {
                result.state_modified = true;
            }
            result.swept_transactions = sweep.txids;
            result.released_outpoints = sweep.released_outpoints;
        }

        if !update_state || !result.is_relevant {
            return result;
        }

        // Wallet-wide view of this transaction's input parents, taken while
        // every account is still readable and before any `update_utxos` call
        // starts removing spent parents. Without it a pooled self-send — the
        // normal shape for asset locks, which fund from BIP44 + BIP32 + the
        // DashPay contact-receiving accounts — is not recognised as ours by
        // the account holding the change, and that change lands in the
        // `unconfirmed` bucket.
        let external_final_parents = self.accounts.final_parents_of(tx);

        // Check if this transaction already exists in any affected account
        let txid = tx.txid();
        let mut is_new = true;
        for account_match in &result.affected_accounts {
            if let Some(account) =
                self.accounts.get_by_account_type_match(&account_match.account_type_match)
            {
                if account.has_transaction(&txid) {
                    is_new = false;
                    break;
                }
            }
        }
        result.is_new_transaction = is_new;

        if !is_new {
            // IS lock on a transaction that is already confirmed is stale — ignore
            if context.is_instant_send() {
                if !self.instant_send_locks.insert(txid) {
                    return result;
                }
                // Only accept IS transitions for unconfirmed transactions.
                // A chainlocked tx may have had its full record dropped
                // under the default feature config — `transaction_is_finalized`
                // catches that case via `finalized_txids` and the in-map
                // record check covers `InBlock`.
                let already_confirmed = result.affected_accounts.iter().any(|am| {
                    let Some(account) =
                        self.accounts.get_by_account_type_match(&am.account_type_match)
                    else {
                        return false;
                    };
                    if account.transaction_is_finalized(&txid) {
                        return true;
                    }
                    account.transactions().get(&txid).is_some_and(|r| r.is_confirmed())
                });
                if already_confirmed {
                    return result;
                }
                // Mark UTXOs as IS-locked and update the transaction context.
                // An account can match (its address pool detects the tx) without
                // already holding a record — backfill via `record_transaction`
                // before marking UTXOs so the freshly registered UTXOs get the
                // IS-lock flag too.
                for account_match in result.affected_accounts.clone() {
                    let Some(mut account) = self
                        .accounts
                        .get_by_account_type_match_mut(&account_match.account_type_match)
                    else {
                        continue;
                    };
                    if account.transactions().contains_key(&txid) {
                        account.mark_utxos_instant_send(&txid);
                        if let Some(record) = account.transactions_mut().get_mut(&txid) {
                            record.update_context(context.clone());
                            result.updated_records.push(record.clone());
                        }
                    } else {
                        let record = account.record_transaction_with_observed_spends(
                            tx,
                            &account_match,
                            context.clone(),
                            tx_type,
                            &self.observed_spent_outpoints,
                            &external_final_parents,
                        );
                        account.mark_utxos_instant_send(&txid);
                        result.new_records.push(record);
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
            let Some(mut account) =
                self.accounts.get_by_account_type_match_mut(&account_match.account_type_match)
            else {
                continue;
            };

            if is_new {
                let record = account.record_transaction_with_observed_spends(
                    tx,
                    &account_match,
                    context.clone(),
                    tx_type,
                    &self.observed_spent_outpoints,
                    &external_final_parents,
                );
                result.new_records.push(record);
                result.state_modified = true;
            } else {
                let existed_before = account.has_transaction(&tx.txid());
                if let Some(record) = account.confirm_transaction_with_observed_spends(
                    tx,
                    &account_match,
                    context.clone(),
                    tx_type,
                    &self.observed_spent_outpoints,
                    &external_final_parents,
                ) {
                    result.state_modified = true;
                    if existed_before {
                        result.updated_records.push(record);
                    } else {
                        result.new_records.push(record);
                    }
                }
            }

            for address_info in account_match.account_type_match.all_involved_addresses() {
                account.mark_address_used(&address_info.address);
            }

            let key_source = wallet.key_source_for_account_type(
                &account_match.account_type_match.to_account_type_to_check(),
                account_match.account_type_match.account_index(),
            );
            if matches!(key_source, KeySource::NoKeySource) {
                continue;
            }
            let rev_before = result.new_addresses.len();
            let owning_account_type = account.managed_account_type().to_account_type();
            for pool in account.managed_account_type_mut().address_pools_mut() {
                let pool_type = pool.pool_type;
                match pool.maintain_gap_limit(&key_source) {
                    Ok(infos) => result.new_addresses.extend(infos.into_iter().map(|info| {
                        super::account_checker::DerivedAddressInfo {
                            account_type: owning_account_type,
                            pool_type,
                            info,
                        }
                    })),
                    Err(e) => {
                        tracing::error!(
                            account_index = ?account_match.account_type_match.account_index(),
                            pool_type = ?pool_type,
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
            if context.is_instant_send() {
                self.instant_send_locks.insert(txid);
            }

            let wallet_net = result.total_received as i64 - result.total_sent as i64;
            tracing::info!(
                txid = %tx.txid(),
                context = %context,
                net_change = %SignedAmount::from_sat(wallet_net),
                received = %Amount::from_sat(result.total_received),
                sent = %Amount::from_sat(result.total_sent),
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
    use crate::account::account_type::StandardAccountType;
    use crate::managed_account::managed_account_trait::ManagedAccountTrait;
    use crate::managed_account::transaction_record::{OutputRole, TransactionDirection};
    use crate::test_utils::TestWalletContext;
    use crate::transaction_checking::BlockInfo;
    use crate::transaction_checking::TransactionType;
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
    use crate::wallet::{ManagedWalletInfo, Wallet};
    use crate::{AccountType, Network};
    use dashcore::blockdata::script::ScriptBuf;
    use dashcore::blockdata::transaction::Transaction;
    use dashcore::ephemerealdata::instant_lock::InstantLock;
    use dashcore::OutPoint;
    use dashcore::TxOut;
    use dashcore::{Address, BlockHash, TxIn, Txid};
    use dashcore_hashes::Hash;
    use std::collections::{BTreeMap, BTreeSet};

    /// Test wallet checker with unrelated transaction
    #[tokio::test]
    async fn test_wallet_checker_unrelated_transaction() {
        let network = Network::Testnet;

        // Create wallet on testnet
        let wallet = Wallet::new_random(network, WalletAccountCreationOptions::Default)
            .expect("Should create wallet");

        let mut managed_wallet =
            ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string(), 0);

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
            ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string(), 0);

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

            // The tx does not look like CoinJoin (it classifies as Standard), but routing checks
            // every fund-bearing account, so a payment to our CoinJoin address is still picked up.
            // Discovery is membership-based, like Dash Core's `IsMine`, not gated on the tx shape.
            assert!(result.is_relevant);
            assert_eq!(result.total_received, 75_000);
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
        // Set last_processed_height to block where coinbase was received to trigger balance updates.
        managed_wallet.update_last_processed_height(block_height);

        // Should be relevant
        assert!(result.is_relevant);
        assert_eq!(result.total_received, 5_000_000_000);

        let managed_account =
            managed_wallet.first_bip44_managed_account().expect("Should have managed account");
        assert!(
            managed_account.transactions().contains_key(&coinbase_tx.txid()),
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
        assert_eq!(managed_wallet.balance.immature(), 5_000_000_000);

        // Spendable UTXOs should be empty (coinbase not mature)
        let last_processed_height = managed_wallet.last_processed_height();
        assert!(
            managed_wallet
                .first_bip44_managed_account()
                .expect("Should have managed account")
                .spendable_utxos(last_processed_height)
                .is_empty(),
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
            .transactions()
            .get(&spend_tx.txid())
            .expect("Spend transaction should be recorded");
        assert_eq!(record.net_amount, -(funding_value as i64));
    }

    /// Regression: an asset-lock transaction that spends a CoinJoin UTXO must
    /// debit that UTXO.
    ///
    /// `check_core_transaction` only marks a UTXO spent for the account types
    /// returned by `TransactionRouter::get_relevant_account_types`. Before the
    /// fix, the `AssetLock` arm omitted `CoinJoin` (and the DashPay accounts),
    /// so an asset lock funded from a CoinJoin UTXO never had that input
    /// debited: the spent UTXO kept counting toward the balance while the BIP44
    /// change output was still credited, inflating the balance by exactly the
    /// spent amount — on both relay and rescan (dashpay/platform#4073, #4074,
    /// dashpay/dash-wallet#1507).
    #[tokio::test]
    async fn test_asset_lock_spending_coinjoin_utxo_is_debited() {
        use crate::account::AccountType;
        use crate::managed_account::managed_account_type::ManagedAccountType;
        use dashcore::blockdata::transaction::special_transaction::asset_lock::AssetLockPayload;
        use dashcore::blockdata::transaction::special_transaction::TransactionPayload;

        let network = Network::Testnet;

        // Wallet with a BIP44 account (asset-lock change lands here) and a
        // CoinJoin account (funds the asset lock).
        let mut wallet = Wallet::new_random(network, WalletAccountCreationOptions::None)
            .expect("Should create wallet");
        wallet
            .add_account(
                AccountType::Standard {
                    index: 0,
                    standard_account_type: StandardAccountType::BIP44Account,
                },
                None,
            )
            .expect("Should add BIP44 account");
        wallet
            .add_account(
                AccountType::CoinJoin {
                    index: 0,
                },
                None,
            )
            .expect("Should add CoinJoin account");

        let mut managed_wallet =
            ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string(), 0);

        // Derive a CoinJoin external address and a BIP44 change address.
        let coinjoin_xpub =
            wallet.accounts.coinjoin_accounts.get(&0).expect("coinjoin account").account_xpub;
        let coinjoin_address = {
            let managed_account =
                managed_wallet.first_coinjoin_managed_account_mut().expect("managed coinjoin");
            if let ManagedAccountType::CoinJoin {
                external_addresses,
                ..
            } = managed_account.managed_account_type_mut()
            {
                external_addresses
                    .next_unused(&KeySource::Public(coinjoin_xpub), true)
                    .expect("coinjoin address")
            } else {
                panic!("Expected CoinJoin account type");
            }
        };
        let bip44_xpub =
            wallet.accounts.standard_bip44_accounts.get(&0).expect("bip44 account").account_xpub;
        let change_address = managed_wallet
            .first_bip44_managed_account_mut()
            .expect("managed bip44")
            .next_change_address(Some(&bip44_xpub), true)
            .expect("bip44 change address");

        // Fund the CoinJoin address, creating a CoinJoin UTXO.
        let funding_value = 100_000_000u64;
        let funding_tx = Transaction::dummy(&coinjoin_address, 0..1, &[funding_value]);
        let funding_context = TransactionContext::InChainLockedBlock(BlockInfo::new(
            1,
            BlockHash::from_slice(&[7u8; 32]).expect("Should create block hash"),
            1_650_000_000,
        ));
        let funding_result = managed_wallet
            .check_core_transaction(&funding_tx, funding_context, &mut wallet, true, true)
            .await;
        assert!(funding_result.is_relevant, "CoinJoin funding must be relevant");
        assert_eq!(funding_result.total_received, funding_value);
        assert_eq!(
            managed_wallet.first_coinjoin_managed_account().expect("coinjoin account").utxos.len(),
            1,
            "CoinJoin funding must create a UTXO"
        );

        // Build an asset-lock tx spending the CoinJoin UTXO, with BIP44 change.
        let credit_value = 40_000_000u64;
        let change_value = funding_value - credit_value - 1_000; // small fee
        let asset_lock_tx = Transaction {
            version: 3,
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
                value: change_value,
                script_pubkey: change_address.script_pubkey(),
            }],
            special_transaction_payload: Some(TransactionPayload::AssetLockPayloadType(
                AssetLockPayload {
                    version: 1,
                    credit_outputs: vec![TxOut {
                        value: credit_value,
                        script_pubkey: change_address.script_pubkey(),
                    }],
                },
            )),
        };
        assert_eq!(
            TransactionRouter::classify_transaction(&asset_lock_tx),
            TransactionType::AssetLock,
            "tx must classify as AssetLock so it routes through the AssetLock arm"
        );

        let spend_context = TransactionContext::InChainLockedBlock(BlockInfo::new(
            2,
            BlockHash::from_slice(&[8u8; 32]).expect("Should create block hash"),
            1_650_000_100,
        ));
        let spend_result = managed_wallet
            .check_core_transaction(&asset_lock_tx, spend_context, &mut wallet, true, true)
            .await;

        assert!(spend_result.is_relevant, "asset lock spending our UTXO must be relevant");
        // The load-bearing assertion: the CoinJoin input must be debited.
        assert_eq!(
            spend_result.total_sent, funding_value,
            "asset lock must debit the CoinJoin UTXO it spends"
        );
        assert_eq!(
            spend_result.total_received, change_value,
            "BIP44 change output must be credited"
        );
        assert!(
            managed_wallet
                .first_coinjoin_managed_account()
                .expect("coinjoin account")
                .utxos
                .is_empty(),
            "spent CoinJoin UTXO must be removed"
        );

        // Aggregate wallet balance — the actual regression is balance inflation.
        // `check_core_transaction` was called with `update_balance = true`, so
        // the cached balance now reflects the spend. If the spent CoinJoin coin
        // were NOT debited, the wallet would still count its `funding_value`
        // (100_000_000) on top of the new BIP44 change, reporting
        // `funding_value + change_value`. After a correct debit only the
        // confirmed BIP44 change UTXO remains (the asset-lock credit output is
        // locked into Platform, never counted as a spendable wallet UTXO — see
        // the `total_received == change_value` assertion above).
        assert_eq!(
            managed_wallet.balance.confirmed(),
            change_value,
            "confirmed balance must be only the BIP44 change; the spent CoinJoin \
             coin must not inflate it"
        );
        assert_eq!(
            managed_wallet.balance.spendable(),
            change_value,
            "spendable balance must fall from funding_value to change_value after the spend"
        );
        assert_eq!(
            managed_wallet.balance.total(),
            change_value,
            "total balance must not double-count the spent CoinJoin UTXO"
        );
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
        // Set last_processed_height to block where coinbase was received to trigger balance updates.
        managed_wallet.update_last_processed_height(block_height);

        // Should be relevant
        assert!(result.is_relevant);
        assert_eq!(result.total_received, 5_000_000_000);

        let managed_account =
            managed_wallet.first_bip44_managed_account().expect("Should have managed account");
        assert!(
            managed_account.transactions().contains_key(&coinbase_tx.txid()),
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
        assert_eq!(managed_wallet.balance.immature(), 5_000_000_000);

        // Spendable UTXOs should be empty (coinbase not mature yet)
        let last_processed_height = managed_wallet.last_processed_height();
        assert!(
            managed_wallet
                .first_bip44_managed_account()
                .expect("Should have managed account")
                .spendable_utxos(last_processed_height)
                .is_empty(),
            "No spendable UTXOs while coinbase is immature"
        );

        // Now advance the chain height past maturity (100 blocks)
        let mature_height = block_height + 100;
        managed_wallet.update_last_processed_height(mature_height);

        let managed_account =
            managed_wallet.first_bip44_managed_account().expect("Should have managed account");
        assert!(
            managed_account.transactions().contains_key(&coinbase_tx.txid()),
            "Coinbase should still be in regular transactions"
        );

        // Coinbase is no longer in immature_transactions()
        let immature_txs = managed_wallet.immature_transactions();
        assert!(immature_txs.is_empty(), "Matured coinbase should not be in immature transactions");

        // Immature balance should now be zero
        let immature_balance = managed_wallet.balance.immature();
        assert_eq!(immature_balance, 0, "Immature balance should be zero after maturity");

        // Spendable UTXOs should now contain the matured coinbase
        let last_processed_height = managed_wallet.last_processed_height();
        let spendable = managed_wallet
            .first_bip44_managed_account()
            .expect("Should have managed account")
            .spendable_utxos(last_processed_height);
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
            managed_account.transactions().get(&tx.txid()).expect("Should have stored transaction");
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
        let result1 = managed_wallet
            .check_core_transaction(&tx, context.clone(), &mut wallet, true, true)
            .await;

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
            managed_account.transactions().contains_key(&tx.txid()),
            "Transaction should be stored"
        );
        let tx_count_before = managed_account.transactions().len();

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
            managed_account.transactions().len(),
            tx_count_before,
            "Transaction count should not increase on rescan"
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
            account.transactions().contains_key(&spend_tx.txid()),
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
    }

    /// Test the full lifecycle: mempool -> IS -> block -> chain-locked block -> late IS
    #[tokio::test]
    async fn test_full_confirmation_lifecycle() {
        let (mut ctx, tx) = TestWalletContext::new_random().with_mempool_funding(200_000).await;
        let txid = tx.txid();

        // Stage 1: mempool (already done in setup). Mempool funds land
        // in the unconfirmed bucket but are spendable.
        assert_eq!(ctx.managed_wallet.balance.unconfirmed(), 200_000);
        assert_eq!(ctx.managed_wallet.balance.confirmed(), 0);
        assert_eq!(ctx.managed_wallet.balance.spendable(), 200_000);

        // Stage 2: IS lock
        let is_lock = InstantLock {
            txid,
            ..InstantLock::default()
        };
        let result = ctx.check_transaction(&tx, TransactionContext::InstantSend(is_lock)).await;
        assert!(result.is_relevant);
        assert!(!result.is_new_transaction);
        assert_eq!(ctx.managed_wallet.balance.spendable(), 200_000);
        assert_eq!(ctx.managed_wallet.balance.unconfirmed(), 0);
        assert!(ctx.first_utxo().is_instantlocked);
        assert!(!ctx.first_utxo().is_confirmed);
        assert!(ctx.managed_wallet.instant_send_locks.contains(&txid));

        // Verify the TransactionRecord stores the IS lock payload
        let record = ctx.transaction(&txid);
        if let TransactionContext::InstantSend(ref lock) = record.context {
            assert_eq!(lock.txid, txid);
        } else {
            panic!("expected InstantSend context, got {:?}", record.context);
        }

        // Duplicate IS lock should be a no-op
        let result_dup = ctx
            .check_transaction(&tx, TransactionContext::InstantSend(InstantLock::default()))
            .await;
        assert!(result_dup.is_relevant);
        assert!(!result_dup.is_new_transaction);
        assert_eq!(ctx.managed_wallet.balance.spendable(), 200_000);

        // Stage 3: block confirmation
        let block_hash = BlockHash::from_slice(&[10u8; 32]).expect("hash");
        let block_context =
            TransactionContext::InBlock(BlockInfo::new(1000, block_hash, 1700000000));
        let result = ctx.check_transaction(&tx, block_context).await;
        assert!(!result.is_new_transaction);
        assert!(ctx.transaction(&txid).is_confirmed());
        assert_eq!(ctx.transaction(&txid).height(), Some(1000));
        assert!(ctx.first_utxo().is_confirmed);
        // The earlier IS lock must survive the mempool→block reprocess.
        assert!(ctx.first_utxo().is_instantlocked, "IS-lock flag must not be lost on confirmation");
        assert_eq!(ctx.managed_wallet.balance.spendable(), 200_000);

        // Stage 4: chain-locked block (rescan with stronger context)
        let cl_context =
            TransactionContext::InChainLockedBlock(BlockInfo::new(1000, block_hash, 1700000000));
        let result = ctx.check_transaction(&tx, cl_context).await;
        assert!(!result.is_new_transaction);
        assert_eq!(ctx.managed_wallet.balance.spendable(), 200_000);

        // Stage 5: late IS lock on already-confirmed tx should be ignored
        let balance_before = ctx.managed_wallet.balance;
        let result = ctx
            .check_transaction(&tx, TransactionContext::InstantSend(InstantLock::default()))
            .await;
        assert!(result.is_relevant);
        assert!(!result.is_new_transaction);
        assert_eq!(ctx.managed_wallet.balance.spendable(), balance_before.spendable());
    }

    /// Test that a new transaction arriving directly with IS context populates the dedup set
    #[tokio::test]
    async fn test_new_transaction_with_instantsend_context() {
        let mut ctx = TestWalletContext::new_random();
        let tx = Transaction::dummy(&ctx.receive_address, 0..1, &[150_000]);
        let txid = tx.txid();

        // Arrive directly as IS (skipping plain mempool)
        let result = ctx
            .check_transaction(&tx, TransactionContext::InstantSend(InstantLock::default()))
            .await;
        assert!(result.is_relevant);
        assert!(result.is_new_transaction);
        assert_eq!(result.total_received, 150_000);

        // Should be IS-locked and spendable immediately
        assert!(ctx.first_utxo().is_instantlocked);
        assert_eq!(ctx.managed_wallet.balance.spendable(), 150_000);
        assert!(ctx.managed_wallet.instant_send_locks.contains(&txid));

        // A follow-up IS lock should be a no-op
        let result2 = ctx
            .check_transaction(&tx, TransactionContext::InstantSend(InstantLock::default()))
            .await;
        assert!(!result2.is_new_transaction);
        assert_eq!(ctx.managed_wallet.balance.spendable(), 150_000);
    }

    /// Test that the InstantSend branch backfills a `TransactionRecord` on accounts
    /// that match the transaction but have no prior record. This mirrors the
    /// confirmation path's backfill: a tx pays outputs to two accounts but only
    /// the first holds a record (e.g., a missed mempool delivery on the second
    /// account); when the IS lock arrives, the wallet-level `is_new` is `false`,
    /// yet the second account must still be backfilled or its UTXOs would be
    /// IS-locked without a matching `TransactionRecord`.
    #[tokio::test]
    async fn test_instantsend_backfills_missing_record_in_other_account() {
        let mut wallet =
            Wallet::new_random(Network::Testnet, WalletAccountCreationOptions::Default)
                .expect("Should create wallet");
        wallet
            .add_account(
                AccountType::Standard {
                    index: 1,
                    standard_account_type: StandardAccountType::BIP44Account,
                },
                None,
            )
            .expect("Should add second BIP44 account");

        let mut managed_wallet =
            ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string(), 0);

        let xpub0 = wallet
            .accounts
            .standard_bip44_accounts
            .get(&0)
            .expect("Should have BIP44 account 0")
            .account_xpub;
        let address0 = managed_wallet
            .bip44_managed_account_at_index_mut(0)
            .expect("Should have managed account 0")
            .next_receive_address(Some(&xpub0), true)
            .expect("Should generate address for account 0");

        let xpub1 = wallet
            .accounts
            .standard_bip44_accounts
            .get(&1)
            .expect("Should have BIP44 account 1")
            .account_xpub;
        let address1 = managed_wallet
            .bip44_managed_account_at_index_mut(1)
            .expect("Should have managed account 1")
            .next_receive_address(Some(&xpub1), true)
            .expect("Should generate address for account 1");

        // Build a tx with outputs to both accounts.
        let mut tx = Transaction::dummy(&address0, 0..1, &[100_000]);
        tx.output.push(TxOut {
            value: 50_000,
            script_pubkey: address1.script_pubkey(),
        });
        let txid = tx.txid();

        // Process as mempool first so both accounts record the tx.
        let mut wallet_mut = wallet;
        let mempool_result = managed_wallet
            .check_core_transaction(&tx, TransactionContext::Mempool, &mut wallet_mut, true, true)
            .await;
        assert!(mempool_result.is_relevant);
        assert!(mempool_result.is_new_transaction);
        assert_eq!(mempool_result.affected_accounts.len(), 2);

        // Drop the record + UTXOs from account 1 to simulate a missed delivery
        // there. Account 0 keeps the record so wallet-level `is_new` will be
        // `false` when the IS lock arrives, exercising the backfill branch.
        let account1 = managed_wallet
            .bip44_managed_account_at_index_mut(1)
            .expect("Should have managed account 1");
        account1.transactions_mut().remove(&txid);
        account1.utxos.clear();
        assert!(!account1.transactions().contains_key(&txid));
        assert!(account1.utxos.is_empty());

        let is_result = managed_wallet
            .check_core_transaction(
                &tx,
                TransactionContext::InstantSend(InstantLock::default()),
                &mut wallet_mut,
                true,
                true,
            )
            .await;
        assert!(is_result.is_relevant);
        assert!(!is_result.is_new_transaction, "Account 0 still holds the record");
        assert!(is_result.state_modified);

        // Account 0 was already known: classified as updated.
        assert_eq!(is_result.updated_records.len(), 1);
        assert_eq!(is_result.updated_records[0].txid, txid);
        // Account 1 was backfilled: classified as new.
        assert_eq!(is_result.new_records.len(), 1);
        assert_eq!(is_result.new_records[0].txid, txid);

        // Both accounts should now hold the record with IS context and IS-locked UTXOs.
        for account_index in 0..=1 {
            let account = managed_wallet
                .bip44_managed_account_at_index(account_index)
                .expect("Should have account");
            let record = account
                .transactions()
                .get(&txid)
                .expect("Both accounts should hold the record after IS backfill");
            assert!(matches!(record.context, TransactionContext::InstantSend(_)));
            assert!(
                account.utxos.values().any(|u| u.outpoint.txid == txid && u.is_instantlocked),
                "Account {account_index} should have an IS-locked UTXO from this tx"
            );
        }
        assert!(managed_wallet.instant_send_locks.contains(&txid));
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
        assert!(account.transactions().contains_key(&txid));
        account.transactions_mut().remove(&txid);
        assert!(!account.transactions().contains_key(&txid));

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

    /// Test `confirm_transaction` backfill directly on `ManagedCoreFundsAccount` when the
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
        account.transactions_mut().remove(&txid);
        account.utxos.clear();
        assert!(!account.transactions().contains_key(&txid));
        assert!(account.utxos.is_empty());

        // Call `confirm_transaction` directly — the backfill path should create the record
        let block_hash = BlockHash::from_slice(&[9u8; 32]).expect("hash");
        let block_context =
            TransactionContext::InBlock(BlockInfo::new(600, block_hash, 1700000000));
        let tx_type = TransactionRouter::classify_transaction(&tx);
        let backfilled = account.confirm_transaction(
            &tx,
            &account_match,
            block_context,
            tx_type,
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        assert!(backfilled.is_some(), "Should return Some when backfilling a missing record");

        // Verify the transaction was recorded with block context
        let record = account.transactions().get(&txid).expect("Should have backfilled record");
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
        assert!(account.transactions().contains_key(&txid));
        assert!(!account.transactions().get(&txid).unwrap().is_confirmed());

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
        let confirmed = account.confirm_transaction(
            &tx,
            &account_match,
            block_context,
            tx_type,
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        assert!(confirmed.is_some(), "Should return Some when confirming unconfirmed tx");

        let record = account.transactions().get(&txid).expect("Should have record");
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
            ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string(), 0);

        let xpub =
            wallet.accounts.coinjoin_accounts.get(&0).expect("coinjoin account").account_xpub;

        let managed_account =
            managed_wallet.first_coinjoin_managed_account_mut().expect("managed coinjoin");

        // Get an address from the CoinJoin external (receive) pool
        let coinjoin_address = if let ManagedAccountType::CoinJoin {
            external_addresses,
            ..
        } = managed_account.managed_account_type_mut()
        {
            external_addresses
                .next_unused(&KeySource::Public(xpub), true)
                .expect("coinjoin address")
        } else {
            panic!("Expected CoinJoin account type");
        };

        // Build a CoinJoin-like tx: 3+ inputs, 3+ outputs with denomination amounts
        let denomination = 100_001u64; // 0.001 DASH + per-round fee
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
        let record = account.transactions().get(&tx.txid()).expect("should have record");
        assert_eq!(record.direction, TransactionDirection::CoinJoin);
        assert_eq!(record.transaction_type, TransactionType::CoinJoin);
        assert!(record.input_details.is_empty(), "CoinJoin test has no funded UTXOs");
        assert_eq!(record.output_details.len(), 1, "One output to our CoinJoin address");
        assert_eq!(record.output_details[0].role, OutputRole::Received);
    }

    /// A change output produced by a mempool transaction that also spends one of
    /// our own UTXOs is just our previously-tracked funds returning. It should
    /// land in the confirmed balance rather than the unconfirmed balance, so the
    /// user's confirmed total does not appear to drop by the entire input value
    /// while the change waits in the mempool.
    #[tokio::test]
    async fn test_self_send_change_in_mempool_lands_in_confirmed_balance() {
        let mut ctx = TestWalletContext::new_random();
        let external_address = Address::p2pkh(
            &dashcore::PublicKey::from_slice(&[0x02; 33]).expect("pubkey"),
            Network::Testnet,
        );

        // Confirmed funding UTXO at the receive address.
        let funding_value = 1_000_000u64;
        let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[funding_value]);
        let block_context = TransactionContext::InBlock(BlockInfo::new(
            100,
            BlockHash::from_slice(&[1u8; 32]).expect("hash"),
            1_700_000_000,
        ));
        ctx.check_transaction(&funding_tx, block_context).await;
        assert_eq!(ctx.managed_wallet.balance.confirmed(), funding_value);
        assert_eq!(ctx.managed_wallet.balance.unconfirmed(), 0);

        let change_address = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .next_change_address(Some(&ctx.xpub), true)
            .expect("change address");

        // Spend the funding UTXO: send some out, send the rest back to ourselves
        // as change. The transaction is broadcast into the mempool.
        let send_amount = 600_000u64;
        let fee = 1_000u64;
        let change_amount = funding_value - send_amount - fee;
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

        let result = ctx.check_transaction(&spend_tx, TransactionContext::Mempool).await;
        assert!(result.is_relevant);
        assert!(result.is_new_transaction);

        // The transaction record itself is still tagged as mempool.
        let record = ctx.transaction(&spend_tx.txid());
        assert_eq!(record.context, TransactionContext::Mempool);
        assert!(!record.is_confirmed());
        assert_eq!(record.direction, TransactionDirection::Outgoing);

        // The change UTXO should be flagged via `is_trusted` so that
        // `update_balance` credits it to the confirmed bucket, despite the
        // parent transaction still being in the mempool.
        let change_outpoint = OutPoint {
            txid: spend_tx.txid(),
            vout: 1,
        };
        let change_utxo =
            ctx.bip44_account().utxos.get(&change_outpoint).expect("change UTXO recorded");
        // The parent transaction is still in the mempool, so `is_confirmed`
        // stays false; the trust signal is what shifts the UTXO into the
        // confirmed balance bucket.
        assert!(!change_utxo.is_confirmed);
        assert!(!change_utxo.is_instantlocked);
        assert!(change_utxo.is_trusted, "self-send change UTXO should be trusted");
        assert_eq!(change_utxo.txout.value, change_amount);

        // Account-level balance: change lives in `confirmed`, not `unconfirmed`.
        assert_eq!(ctx.managed_wallet.balance.confirmed(), change_amount);
        assert_eq!(ctx.managed_wallet.balance.unconfirmed(), 0);
        assert_eq!(ctx.managed_wallet.balance.spendable(), change_amount);
    }

    /// The in-core restore above has one boundary, and it is the pruning of
    /// finalized records, not the restore itself.
    ///
    /// Under the default `keep-finalized-transactions = off` a
    /// chainlock-finalized funding transaction keeps only its txid: its
    /// `TxOut` is gone, so the released coin cannot be rebuilt from anything
    /// the wallet still holds, and re-delivery cannot insert it either
    /// (`has_transaction` stays true, so `confirm_transaction` returns before
    /// `update_utxos`). The coin stays absent until a rescan deep enough to
    /// re-fetch the block, which is above this layer. With the feature on
    /// nothing is pruned and the restore works normally — which is what pins
    /// the pruning as the cause.
    #[tokio::test]
    async fn test_restore_cannot_reach_a_chainlock_pruned_funding_record() {
        let mut ctx = TestWalletContext::new_random();
        let external_address = Address::p2pkh(
            &dashcore::PublicKey::from_slice(&[0x02; 33]).expect("pubkey"),
            Network::Testnet,
        );

        let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[1_000_000]);
        let finalized = TransactionContext::InChainLockedBlock(BlockInfo::new(
            100,
            BlockHash::from_slice(&[5u8; 32]).expect("hash"),
            1_700_000_000,
        ));
        ctx.check_transaction(&funding_tx, finalized.clone()).await;

        let change_address = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .next_change_address(Some(&ctx.xpub), true)
            .expect("change address");
        let spend = Transaction {
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
                    value: 900_000,
                    script_pubkey: external_address.script_pubkey(),
                },
                TxOut {
                    value: 99_000,
                    script_pubkey: change_address.script_pubkey(),
                },
            ],
            special_transaction_payload: None,
        };
        ctx.check_transaction(&spend, TransactionContext::Mempool).await;

        let outcome = ctx.managed_wallet.abandon_transaction(spend.txid());
        ctx.managed_wallet.update_balance();

        // Either way the coin is *reported* free: the release is decided from
        // the spent-mark bookkeeping, which pruning does not touch.
        let funding_outpoint = OutPoint {
            txid: funding_tx.txid(),
            vout: 0,
        };
        assert_eq!(outcome.released_outpoints, vec![funding_outpoint]);

        // Re-delivering the funding block cannot help either — this is the
        // path the restore used to depend on.
        ctx.check_transaction(&funding_tx, finalized).await;

        #[cfg(not(feature = "keep-finalized-transactions"))]
        assert_eq!(
            ctx.managed_wallet.balance.confirmed(),
            0,
            "a chainlock-pruned funding record keeps no output to rebuild the \
             coin from, and blocks the redelivery path too"
        );
        #[cfg(feature = "keep-finalized-transactions")]
        assert_eq!(
            ctx.managed_wallet.balance.confirmed(),
            1_000_000,
            "with the record retained there is nothing to stop the restore"
        );
    }

    /// A winner that spends our coin but pays only external addresses matches
    /// nothing: its outputs are not ours, and the input it shares with the
    /// loser was already removed from `utxos` when the loser was recorded. It
    /// is therefore classified irrelevant — and the sweep still has to run,
    /// or the loser's change stays credited with nothing left to clear it.
    #[tokio::test]
    async fn test_an_irrelevant_winner_still_sweeps_its_loser() {
        let mut ctx = TestWalletContext::new_random();
        let external_address = Address::p2pkh(
            &dashcore::PublicKey::from_slice(&[0x02; 33]).expect("pubkey"),
            Network::Testnet,
        );

        let funding_value = 1_000_000u64;
        let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[funding_value]);
        ctx.check_transaction(
            &funding_tx,
            TransactionContext::InBlock(BlockInfo::new(
                100,
                BlockHash::from_slice(&[1u8; 32]).expect("hash"),
                1_700_000_000,
            )),
        )
        .await;

        let funding_outpoint = OutPoint {
            txid: funding_tx.txid(),
            vout: 0,
        };
        let input = || TxIn {
            previous_output: funding_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: dashcore::Witness::new(),
        };

        // The loser pays us change, so it is relevant and gets recorded.
        let loser_change = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .next_change_address(Some(&ctx.xpub), true)
            .expect("change address");
        let loser = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![input()],
            output: vec![
                TxOut {
                    value: 600_000,
                    script_pubkey: external_address.script_pubkey(),
                },
                TxOut {
                    value: 399_000,
                    script_pubkey: loser_change.script_pubkey(),
                },
            ],
            special_transaction_payload: None,
        };
        ctx.check_transaction(&loser, TransactionContext::Mempool).await;
        assert_eq!(
            ctx.managed_wallet.balance.confirmed(),
            399_000,
            "trusted self-send change counts as confirmed"
        );

        // The winner spends the same coin and pays only outside the wallet.
        let winner = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![input()],
            output: vec![TxOut {
                value: 999_000,
                script_pubkey: external_address.script_pubkey(),
            }],
            special_transaction_payload: None,
        };
        let result = ctx
            .check_transaction(
                &winner,
                TransactionContext::InBlock(BlockInfo::new(
                    101,
                    BlockHash::from_slice(&[2u8; 32]).expect("hash"),
                    1_700_000_100,
                )),
            )
            .await;
        assert!(
            !result.is_relevant,
            "the precondition: nothing about this winner matches the wallet"
        );

        assert!(
            !ctx.bip44_account().transactions().contains_key(&loser.txid()),
            "the loser must be swept even though the winner is irrelevant"
        );
        assert_eq!(
            ctx.managed_wallet.balance.confirmed(),
            0,
            "and its change must stop counting as confirmed money"
        );
        assert!(
            result.released_outpoints.is_empty(),
            "the ordinary case: the winner spends the loser's only input, so nothing is freed"
        );
    }

    /// Pooled funding puts a loser's change in an account the winner never
    /// touches. Sweeping only the winner's matched accounts leaves it behind.
    #[tokio::test]
    async fn test_a_loser_in_a_sibling_account_is_swept() {
        let mut ctx = TestWalletContext::new_random();
        let external_address = Address::p2pkh(
            &dashcore::PublicKey::from_slice(&[0x02; 33]).expect("pubkey"),
            Network::Testnet,
        );

        // Fund the BIP32 account.
        let bip32_xpub = ctx
            .wallet
            .accounts
            .standard_bip32_accounts
            .get(&0)
            .expect("BIP32 account")
            .account_xpub;
        let bip32_address = ctx
            .managed_wallet
            .first_bip32_managed_account_mut()
            .expect("BIP32 managed account")
            .next_receive_address(Some(&bip32_xpub), true)
            .expect("BIP32 receive address");
        let funding_tx = Transaction::dummy(&bip32_address, 0..1, &[1_000_000]);
        ctx.check_transaction(
            &funding_tx,
            TransactionContext::InBlock(BlockInfo::new(
                100,
                BlockHash::from_slice(&[3u8; 32]).expect("hash"),
                1_700_000_000,
            )),
        )
        .await;

        let funding_outpoint = OutPoint {
            txid: funding_tx.txid(),
            vout: 0,
        };
        let spend = |change: &Address, change_amount: u64, sent: u64| Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: funding_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: 0xffffffff,
                witness: dashcore::Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: sent,
                    script_pubkey: external_address.script_pubkey(),
                },
                TxOut {
                    value: change_amount,
                    script_pubkey: change.script_pubkey(),
                },
            ],
            special_transaction_payload: None,
        };

        // The loser's change lands on BIP44 — an account the winner, whose
        // change goes back to BIP32, never matches.
        let loser_change = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .next_change_address(Some(&ctx.xpub), true)
            .expect("change address");
        let loser = spend(&loser_change, 399_000, 600_000);
        ctx.check_transaction(&loser, TransactionContext::Mempool).await;

        let winner_change = ctx
            .managed_wallet
            .first_bip32_managed_account_mut()
            .expect("BIP32 managed account")
            .next_change_address(Some(&bip32_xpub), true)
            .expect("BIP32 change address");
        let winner = spend(&winner_change, 299_000, 700_000);
        ctx.check_transaction(
            &winner,
            TransactionContext::InBlock(BlockInfo::new(
                101,
                BlockHash::from_slice(&[4u8; 32]).expect("hash"),
                1_700_000_100,
            )),
        )
        .await;

        assert!(
            !ctx.bip44_account().transactions().contains_key(&loser.txid()),
            "a loser in a sibling account must be swept too"
        );
        assert_eq!(
            ctx.managed_wallet.balance.confirmed(),
            299_000,
            "only the winner's change survives"
        );
    }

    /// The reverse arrival order: the winner confirms first, and the loser
    /// turns up afterwards from the mempool. No sweep can help — the sweep
    /// fires on the *arriving* transaction being final, and here the arrival
    /// is the loser. The refusal has to happen at record time.
    #[tokio::test]
    async fn test_a_loser_arriving_after_its_winner_is_never_credited() {
        let mut ctx = TestWalletContext::new_random();
        let external_address = Address::p2pkh(
            &dashcore::PublicKey::from_slice(&[0x02; 33]).expect("pubkey"),
            Network::Testnet,
        );

        let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[1_000_000]);
        ctx.check_transaction(
            &funding_tx,
            TransactionContext::InBlock(BlockInfo::new(
                100,
                BlockHash::from_slice(&[8u8; 32]).expect("hash"),
                1_700_000_000,
            )),
        )
        .await;

        let shared = OutPoint {
            txid: funding_tx.txid(),
            vout: 0,
        };
        let spend = |change: &Address, change_amount: u64, sent: u64| Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: shared,
                script_sig: ScriptBuf::new(),
                sequence: 0xffffffff,
                witness: dashcore::Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: sent,
                    script_pubkey: external_address.script_pubkey(),
                },
                TxOut {
                    value: change_amount,
                    script_pubkey: change.script_pubkey(),
                },
            ],
            special_transaction_payload: None,
        };

        // The winner confirms first.
        let winner_change = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .next_change_address(Some(&ctx.xpub), true)
            .expect("change address");
        let winner = spend(&winner_change, 299_000, 700_000);
        ctx.check_transaction(
            &winner,
            TransactionContext::InBlock(BlockInfo::new(
                101,
                BlockHash::from_slice(&[9u8; 32]).expect("hash"),
                1_700_000_100,
            )),
        )
        .await;
        assert_eq!(ctx.managed_wallet.balance.confirmed(), 299_000);

        // Then the loser turns up. Its input is provably spent, so its
        // outputs must never be credited.
        let loser_change = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .next_change_address(Some(&ctx.xpub), true)
            .expect("change address");
        let loser = spend(&loser_change, 399_000, 600_000);
        ctx.check_transaction(&loser, TransactionContext::Mempool).await;

        assert!(
            !ctx.bip44_account().utxos.keys().any(|o| o.txid == loser.txid()),
            "a transaction whose input a block already spent must not be credited"
        );
        assert_eq!(
            ctx.managed_wallet.balance.confirmed(),
            299_000,
            "only the winner's change counts"
        );
    }

    /// `abandon_transaction_with_spends`' external view: a descendant whose
    /// own record the load path never restored, a stale row naming a settled
    /// transaction that must not be followed, and a settled root refused
    /// outright. None of these are reachable through the no-argument form.
    #[tokio::test]
    async fn test_abandon_honours_the_external_spend_view_and_refuses_settled() {
        let mut ctx = TestWalletContext::new_random();
        let external_address = Address::p2pkh(
            &dashcore::PublicKey::from_slice(&[0x02; 33]).expect("pubkey"),
            Network::Testnet,
        );

        let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[1_000_000]);
        let block = TransactionContext::InBlock(BlockInfo::new(
            100,
            BlockHash::from_slice(&[7u8; 32]).expect("hash"),
            1_700_000_000,
        ));
        ctx.check_transaction(&funding_tx, block.clone()).await;

        let spend_of =
            |parent: OutPoint, change: &Address, change_amount: u64, sent: u64| Transaction {
                version: 2,
                lock_time: 0,
                input: vec![TxIn {
                    previous_output: parent,
                    script_sig: ScriptBuf::new(),
                    sequence: 0xffffffff,
                    witness: dashcore::Witness::new(),
                }],
                output: vec![
                    TxOut {
                        value: sent,
                        script_pubkey: external_address.script_pubkey(),
                    },
                    TxOut {
                        value: change_amount,
                        script_pubkey: change.script_pubkey(),
                    },
                ],
                special_transaction_payload: None,
            };
        let next_change = |ctx: &mut TestWalletContext| {
            ctx.managed_wallet
                .first_bip44_managed_account_mut()
                .expect("account")
                .next_change_address(Some(&ctx.xpub), true)
                .expect("change address")
        };

        // Root, then a child spending its change.
        let root_change = next_change(&mut ctx);
        let root = spend_of(
            OutPoint {
                txid: funding_tx.txid(),
                vout: 0,
            },
            &root_change,
            399_000,
            600_000,
        );
        ctx.check_transaction(&root, TransactionContext::Mempool).await;
        let child_change = next_change(&mut ctx);
        let child = spend_of(
            OutPoint {
                txid: root.txid(),
                vout: 1,
            },
            &child_change,
            298_000,
            100_000,
        );
        ctx.check_transaction(&child, TransactionContext::Mempool).await;

        // A settled root is refused outright, whatever the map says.
        ctx.check_transaction(&funding_tx, block).await;
        let refused = ctx.managed_wallet.abandon_transaction(funding_tx.txid());
        assert!(refused.is_empty(), "a settled root must be refused: {refused:?}");

        // Simulate the restore: the child's record is absent, so the plain
        // walk cannot reach it — only the mirror's linkage can.
        ctx.managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .keys_mut()
            .transactions_mut()
            .remove(&child.txid());

        let plain = ctx.managed_wallet.abandon_transaction(root.txid());
        assert_eq!(plain.abandoned.len(), 1, "without the map the walk stops at the root");
        assert!(
            ctx.bip44_account().utxos.keys().any(|o| o.txid == child.txid()),
            "the child's output is still credited"
        );

        // Now with the map, plus a stale row naming the settled funding tx —
        // which must not be followed.
        let mut external = BTreeMap::new();
        external.insert(
            OutPoint {
                txid: root.txid(),
                vout: 1,
            },
            child.txid(),
        );
        external.insert(
            OutPoint {
                txid: child.txid(),
                vout: 1,
            },
            funding_tx.txid(),
        );
        let outcome = ctx.managed_wallet.abandon_transaction_with_spends(root.txid(), &external);
        ctx.managed_wallet.update_balance();

        assert!(
            outcome.abandoned.contains(&child.txid()),
            "the map must reach a descendant whose record is gone"
        );
        assert!(
            !outcome.abandoned.contains(&funding_tx.txid()),
            "a settled spender named by a stale row must not be followed"
        );
        assert!(
            !ctx.bip44_account().utxos.keys().any(|o| o.txid == child.txid()),
            "the child's outputs must be gone"
        );
        assert!(
            ctx.bip44_account().transactions().contains_key(&funding_tx.txid()),
            "the settled funding record must survive"
        );
    }

    /// The sweep must never free the outpoint the winner itself spends.
    ///
    /// Two of the three arrival paths hide this: a block winner is already in
    /// `observed_spent_outpoints`, and a relevant winner re-marks the outpoint
    /// when it is recorded. An InstantSend winner has neither — the context
    /// carries no block info, so no observed spend is recorded, and an
    /// irrelevant one is never recorded at all. Releasing the shared coin
    /// there lets a rescan re-insert money that is spent on chain.
    #[tokio::test]
    async fn test_the_sweep_never_frees_the_winners_own_input() {
        let mut ctx = TestWalletContext::new_random();
        let external_address = Address::p2pkh(
            &dashcore::PublicKey::from_slice(&[0x02; 33]).expect("pubkey"),
            Network::Testnet,
        );

        let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[1_000_000]);
        let funding_context = TransactionContext::InBlock(BlockInfo::new(
            100,
            BlockHash::from_slice(&[6u8; 32]).expect("hash"),
            1_700_000_000,
        ));
        ctx.check_transaction(&funding_tx, funding_context.clone()).await;

        let shared_input = OutPoint {
            txid: funding_tx.txid(),
            vout: 0,
        };
        let input = || TxIn {
            previous_output: shared_input,
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: dashcore::Witness::new(),
        };

        // Loser first: recorded, so the coin leaves `utxos`.
        let loser_change = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .next_change_address(Some(&ctx.xpub), true)
            .expect("change address");
        let loser = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![input()],
            output: vec![
                TxOut {
                    value: 600_000,
                    script_pubkey: external_address.script_pubkey(),
                },
                TxOut {
                    value: 399_000,
                    script_pubkey: loser_change.script_pubkey(),
                },
            ],
            special_transaction_payload: None,
        };
        ctx.check_transaction(&loser, TransactionContext::Mempool).await;

        // The winner arrives InstantSend-locked and pays only outside the
        // wallet: no block info to record an observed spend, and nothing
        // about it matches, so it is never recorded either.
        let winner = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![input()],
            output: vec![TxOut {
                value: 999_000,
                script_pubkey: external_address.script_pubkey(),
            }],
            special_transaction_payload: None,
        };
        let is_lock = InstantLock {
            txid: winner.txid(),
            ..InstantLock::default()
        };
        let result = ctx.check_transaction(&winner, TransactionContext::InstantSend(is_lock)).await;
        assert!(!result.is_relevant, "the precondition: the winner matches nothing");
        assert!(
            !ctx.bip44_account().transactions().contains_key(&loser.txid()),
            "the loser is still swept"
        );

        // The shared coin is spent on chain by the winner. Re-delivering the
        // funding block must not bring it back.
        ctx.check_transaction(&funding_tx, funding_context).await;
        assert!(
            !ctx.bip44_account().utxos.contains_key(&shared_input),
            "a rescan must not resurrect a coin the winner consumed"
        );
        assert_eq!(ctx.managed_wallet.balance.confirmed(), 0);
    }

    /// A loser can spend inputs the winner does not. Sweeping it frees those
    /// coins from the spent set — and must put them back in the UTXO set in
    /// the same breath.
    ///
    /// The sweep reports them released, which tells a consumer to mark them
    /// spendable again; if this library's own coin selection could not see
    /// them until some later rescan, the two would disagree about the same
    /// coin, in the direction that strands funds. Nothing has to be invented
    /// to avoid that: the sweep removes the *loser*, so the funding
    /// transaction's record — and with it the exact `TxOut` — is still here.
    #[tokio::test]
    async fn test_a_swept_losers_extra_input_is_recredited_in_core() {
        let mut ctx = TestWalletContext::new_random();
        let external_address = Address::p2pkh(
            &dashcore::PublicKey::from_slice(&[0x02; 33]).expect("pubkey"),
            Network::Testnet,
        );

        // One funding transaction pays us twice: A and B.
        let funding_tx = Transaction::dummy(&ctx.receive_address, 0..2, &[500_000, 400_000]);
        let funding_context = TransactionContext::InBlock(BlockInfo::new(
            100,
            BlockHash::from_slice(&[1u8; 32]).expect("hash"),
            1_700_000_000,
        ));
        ctx.check_transaction(&funding_tx, funding_context.clone()).await;
        assert_eq!(ctx.managed_wallet.balance.confirmed(), 900_000);

        let coin_a = OutPoint {
            txid: funding_tx.txid(),
            vout: 0,
        };
        let coin_b = OutPoint {
            txid: funding_tx.txid(),
            vout: 1,
        };
        let spend =
            |inputs: Vec<OutPoint>, change: &Address, change_amount: u64, sent: u64| Transaction {
                version: 2,
                lock_time: 0,
                input: inputs
                    .into_iter()
                    .map(|previous_output| TxIn {
                        previous_output,
                        script_sig: ScriptBuf::new(),
                        sequence: 0xffffffff,
                        witness: dashcore::Witness::new(),
                    })
                    .collect(),
                output: vec![
                    TxOut {
                        value: sent,
                        script_pubkey: external_address.script_pubkey(),
                    },
                    TxOut {
                        value: change_amount,
                        script_pubkey: change.script_pubkey(),
                    },
                ],
                special_transaction_payload: None,
            };

        // The loser spends A and B; the winner spends only A, and confirms.
        let loser_change = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .next_change_address(Some(&ctx.xpub), true)
            .expect("change address");
        let loser = spend(vec![coin_a, coin_b], &loser_change, 99_000, 800_000);
        ctx.check_transaction(&loser, TransactionContext::Mempool).await;

        let winner_change = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .next_change_address(Some(&ctx.xpub), true)
            .expect("change address");
        let winner = spend(vec![coin_a], &winner_change, 99_000, 400_000);
        let result = ctx
            .check_transaction(
                &winner,
                TransactionContext::InBlock(BlockInfo::new(
                    101,
                    BlockHash::from_slice(&[2u8; 32]).expect("hash"),
                    1_700_000_100,
                )),
            )
            .await;

        // The loser is gone, and B is credited again — rebuilt from the
        // funding transaction's own retained record, which the sweep never
        // touched.
        assert!(!ctx.bip44_account().transactions().contains_key(&loser.txid()));
        let restored = ctx
            .bip44_account()
            .utxos
            .get(&coin_b)
            .expect("the sweep must put the loser's extra input back");
        assert_eq!(restored.txout.value, 400_000, "rebuilt from the funding output, not guessed");
        assert_eq!(restored.address, ctx.receive_address, "and from its own address");
        assert!(restored.is_confirmed, "the funding transaction is in a block");
        assert!(!restored.is_locked, "a restored coin is selectable");
        assert!(
            !ctx.bip44_account().utxos.contains_key(&coin_a),
            "A is the winner's own input and stays spent"
        );

        // The event carries exactly what was released: B, and not A — A is
        // the winner's own input, still spent on chain by `winner` itself.
        assert_eq!(
            result.released_outpoints,
            vec![coin_b],
            "the sweep must name B as released and must not name A"
        );

        // The balance agrees with the UTXO set: coin selection can spend B
        // again, without waiting for a rescan.
        assert_eq!(ctx.managed_wallet.balance.confirmed(), 499_000, "B plus the winner's change");
        assert_eq!(
            ctx.managed_wallet.balance.spendable(),
            499_000,
            "the released coin has to be spendable, not merely reported free"
        );

        // Re-delivering the funding block changes nothing — the restore is
        // idempotent, not a race against the rescan it used to depend on.
        ctx.check_transaction(&funding_tx, funding_context).await;
        assert!(ctx.bip44_account().utxos.contains_key(&coin_b));
        assert_eq!(ctx.managed_wallet.balance.confirmed(), 499_000);
    }

    /// The restore must not undo dashpay/rust-dashcore#649.
    ///
    /// A block spend of our coin that we could not attribute — the spender
    /// pays only external addresses, and during an out-of-order rescan the
    /// funding transaction had not been processed yet, so nothing matched —
    /// leaves no record for `release_spent_marks` to answer from. It reports
    /// the coin free, because from the live records it is. `update_utxos`
    /// already refuses to credit such an output; the restore has to refuse
    /// too, or coin selection is handed a coin the chain has spent.
    #[tokio::test]
    async fn test_the_restore_withholds_a_coin_seen_spent_in_a_block() {
        let mut ctx = TestWalletContext::new_random();
        let external_address = Address::p2pkh(
            &dashcore::PublicKey::from_slice(&[0x02; 33]).expect("pubkey"),
            Network::Testnet,
        );

        // The funding transaction pays us twice, but is not delivered yet.
        let funding_tx = Transaction::dummy(&ctx.receive_address, 0..2, &[500_000, 400_000]);
        let coin_a = OutPoint {
            txid: funding_tx.txid(),
            vout: 0,
        };
        let coin_b = OutPoint {
            txid: funding_tx.txid(),
            vout: 1,
        };
        let spend = |inputs: Vec<OutPoint>, change: Option<&Address>, sent: u64| Transaction {
            version: 2,
            lock_time: 0,
            input: inputs
                .into_iter()
                .map(|previous_output| TxIn {
                    previous_output,
                    script_sig: ScriptBuf::new(),
                    sequence: 0xffffffff,
                    witness: dashcore::Witness::new(),
                })
                .collect(),
            output: match change {
                Some(change) => vec![
                    TxOut {
                        value: sent,
                        script_pubkey: external_address.script_pubkey(),
                    },
                    TxOut {
                        value: 99_000,
                        script_pubkey: change.script_pubkey(),
                    },
                ],
                None => vec![TxOut {
                    value: sent,
                    script_pubkey: external_address.script_pubkey(),
                }],
            },
            special_transaction_payload: None,
        };

        // Out-of-order rescan: the block that spends B arrives first. Nothing
        // of ours matches — B is not in `utxos` yet and the outputs are
        // external — but the spend is remembered.
        let thief = spend(vec![coin_b], None, 390_000);
        let thief_result = ctx
            .check_transaction(
                &thief,
                TransactionContext::InBlock(BlockInfo::new(
                    99,
                    BlockHash::from_slice(&[9u8; 32]).expect("hash"),
                    1_699_999_000,
                )),
            )
            .await;
        assert!(!thief_result.is_relevant, "the precondition: we cannot attribute this spend");
        assert!(
            ctx.managed_wallet.observed_spent_outpoints().contains_key(&coin_b),
            "the precondition: #649 remembered the spend"
        );

        // Now the funding block arrives. A is credited; B is not — #649.
        ctx.check_transaction(
            &funding_tx,
            TransactionContext::InBlock(BlockInfo::new(
                100,
                BlockHash::from_slice(&[1u8; 32]).expect("hash"),
                1_700_000_000,
            )),
        )
        .await;
        assert!(ctx.bip44_account().utxos.contains_key(&coin_a));
        assert!(!ctx.bip44_account().utxos.contains_key(&coin_b), "#649 withheld it");

        // A loser claims both coins, then a winner takes A and confirms,
        // sweeping the loser. B is freed from the spent bookkeeping — no live
        // record claims it — so the sweep reports it released.
        let loser_change = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .next_change_address(Some(&ctx.xpub), true)
            .expect("change address");
        let loser = spend(vec![coin_a, coin_b], Some(&loser_change), 800_000);
        ctx.check_transaction(&loser, TransactionContext::Mempool).await;

        let winner_change = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .next_change_address(Some(&ctx.xpub), true)
            .expect("change address");
        let winner = spend(vec![coin_a], Some(&winner_change), 400_000);
        let result = ctx
            .check_transaction(
                &winner,
                TransactionContext::InBlock(BlockInfo::new(
                    101,
                    BlockHash::from_slice(&[2u8; 32]).expect("hash"),
                    1_700_000_100,
                )),
            )
            .await;
        assert!(
            result.released_outpoints.contains(&coin_b),
            "the precondition: from the live records alone B looks free"
        );

        // The load-bearing assertion: reported free, still not credited.
        assert!(
            !ctx.bip44_account().utxos.contains_key(&coin_b),
            "a coin seen spent in a block must never be restored to coin selection"
        );
        assert_eq!(
            ctx.managed_wallet.balance.confirmed(),
            99_000,
            "only the winner's change; B contributes nothing"
        );
    }

    /// The #649 withholding must survive the eviction of the very map it
    /// reads.
    ///
    /// `observed_spent_outpoints` is not permanent state:
    /// `prune_finalized_observed_spends` drops every entry at or below the
    /// finality boundary, which is exactly what keeps the map bounded. Gating
    /// the re-credit on that map alone therefore answers "was this coin spent
    /// in a block?" with "no" once the entry is gone — and rebuilds a coin the
    /// chain has already consumed.
    ///
    /// The funding record here is learned from the mempool, so it carries no
    /// block context and `apply_chain_lock` (which promotes and prunes only
    /// `InBlock` records) never touches it. That is what makes this reproduce
    /// under the default feature set too: the record-pruning that hides the
    /// hole for confirmed funding records does not apply.
    #[tokio::test]
    async fn test_a_block_spent_coin_is_not_recredited_once_its_observed_spend_is_evicted() {
        let mut ctx = TestWalletContext::new_random();
        let external_address = Address::p2pkh(
            &dashcore::PublicKey::from_slice(&[0x02; 33]).expect("pubkey"),
            Network::Testnet,
        );

        let funding_tx = Transaction::dummy(&ctx.receive_address, 0..2, &[500_000, 400_000]);
        let coin_a = OutPoint {
            txid: funding_tx.txid(),
            vout: 0,
        };
        let coin_b = OutPoint {
            txid: funding_tx.txid(),
            vout: 1,
        };
        let spend = |inputs: Vec<OutPoint>, change: Option<&Address>, sent: u64| Transaction {
            version: 2,
            lock_time: 0,
            input: inputs
                .into_iter()
                .map(|previous_output| TxIn {
                    previous_output,
                    script_sig: ScriptBuf::new(),
                    sequence: 0xffffffff,
                    witness: dashcore::Witness::new(),
                })
                .collect(),
            output: match change {
                Some(change) => vec![
                    TxOut {
                        value: sent,
                        script_pubkey: external_address.script_pubkey(),
                    },
                    TxOut {
                        value: 99_000,
                        script_pubkey: change.script_pubkey(),
                    },
                ],
                None => vec![TxOut {
                    value: sent,
                    script_pubkey: external_address.script_pubkey(),
                }],
            },
            special_transaction_payload: None,
        };

        // 1. Out-of-order delivery: the block at 101 that spends B is processed
        //    before the funding block at 100. Unattributable, so only #649
        //    remembers it.
        let thief = spend(vec![coin_b], None, 390_000);
        let thief_result = ctx
            .check_transaction(
                &thief,
                TransactionContext::InBlock(BlockInfo::new(
                    101,
                    BlockHash::from_slice(&[9u8; 32]).expect("hash"),
                    1_699_999_000,
                )),
            )
            .await;
        assert!(!thief_result.is_relevant);
        assert!(ctx.managed_wallet.observed_spent_outpoints().contains_key(&coin_b));

        // 2. The funding transaction is learned from the mempool (its record
        //    therefore never carries a block context, so no chainlock ever
        //    prunes it). A credited, B withheld by #649.
        ctx.check_transaction(&funding_tx, TransactionContext::Mempool).await;
        assert!(ctx.bip44_account().utxos.contains_key(&coin_a));
        assert!(!ctx.bip44_account().utxos.contains_key(&coin_b), "#649 withheld it");

        // 3. A loser claims A and B while the observed spend is still known, so
        //    `doomed_by_a_settled_spend` refuses to credit it and never marks
        //    B spent in the account.
        let loser_change = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .next_change_address(Some(&ctx.xpub), true)
            .expect("change address");
        let loser = spend(vec![coin_a, coin_b], Some(&loser_change), 800_000);
        ctx.check_transaction(&loser, TransactionContext::Mempool).await;
        assert!(
            !ctx.bip44_account().is_outpoint_spent_for_test(&coin_b),
            "precondition: the doomed loser never marked B spent"
        );

        // 4. Sync advances: a chainlock lands over both blocks and the sync
        //    checkpoint commits. #649's memory of the spend is evicted.
        ctx.managed_wallet.apply_chain_lock(dashcore::ephemerealdata::chain_lock::ChainLock {
            block_height: 101,
            block_hash: BlockHash::from_slice(&[9u8; 32]).expect("hash"),
            signature: dashcore::bls_sig_utils::BLSSignature::from([0u8; 96]),
        });
        ctx.managed_wallet.update_synced_height(101);
        assert!(
            !ctx.managed_wallet.observed_spent_outpoints().contains_key(&coin_b),
            "precondition: the finality boundary evicted the observed spend"
        );
        assert!(
            ctx.bip44_account().transactions().contains_key(&funding_tx.txid()),
            "precondition: a mempool funding record survives the chainlock in every \
             feature configuration, so record pruning is not a backstop here"
        );

        // 5. A winner takes A and confirms, sweeping the loser. B is released.
        let winner_change = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .next_change_address(Some(&ctx.xpub), true)
            .expect("change address");
        let winner = spend(vec![coin_a], Some(&winner_change), 400_000);
        let result = ctx
            .check_transaction(
                &winner,
                TransactionContext::InBlock(BlockInfo::new(
                    102,
                    BlockHash::from_slice(&[2u8; 32]).expect("hash"),
                    1_700_000_100,
                )),
            )
            .await;
        assert!(
            result.released_outpoints.contains(&coin_b),
            "the reported set is unchanged: B is still named as released"
        );

        // B is spent on chain at height 101. Its spent-status can no longer be
        // cross-checked against `observed_spent_outpoints`, so the re-credit
        // has to withhold it rather than guess.
        assert!(
            !ctx.bip44_account().utxos.contains_key(&coin_b),
            "a coin a block already spent must never be re-credited to coin selection"
        );
        assert!(
            !ctx.bip44_account().spendable_utxos(102).iter().any(|utxo| utxo.outpoint == coin_b),
            "and it must not reach coin selection by any other route"
        );
        assert_eq!(
            ctx.managed_wallet.balance.confirmed(),
            99_000,
            "only the winner's change; B contributes nothing"
        );
    }

    /// The re-credit must not resurrect a coin `update_utxos` refused to
    /// create.
    ///
    /// `update_utxos` never credits the outputs of a transaction whose input a
    /// block already spent (`doomed_by_a_settled_spend`) — it can never
    /// confirm, so its change is money that does not exist. The record is
    /// deliberately kept, for history. A re-credit that reads that record as a
    /// funding source without re-checking the same verdict materialises the
    /// output the credit path had already rejected.
    #[tokio::test]
    async fn test_the_recredit_refuses_a_funding_record_that_can_never_confirm() {
        let mut ctx = TestWalletContext::new_random();
        let external_address = Address::p2pkh(
            &dashcore::PublicKey::from_slice(&[0x02; 33]).expect("pubkey"),
            Network::Testnet,
        );

        // Block 100: two real coins.
        let genesis_tx = Transaction::dummy(&ctx.receive_address, 0..2, &[1_000_000, 300_000]);
        let coin_p = OutPoint {
            txid: genesis_tx.txid(),
            vout: 0,
        };
        let coin_q = OutPoint {
            txid: genesis_tx.txid(),
            vout: 1,
        };
        ctx.check_transaction(
            &genesis_tx,
            TransactionContext::InBlock(BlockInfo::new(
                100,
                BlockHash::from_slice(&[1u8; 32]).expect("hash"),
                1_700_000_000,
            )),
        )
        .await;
        assert!(ctx.bip44_account().utxos.contains_key(&coin_p));

        let spend =
            |inputs: Vec<OutPoint>, change: Option<&Address>, change_value: u64, sent: u64| {
                Transaction {
                    version: 2,
                    lock_time: 0,
                    input: inputs
                        .into_iter()
                        .map(|previous_output| TxIn {
                            previous_output,
                            script_sig: ScriptBuf::new(),
                            sequence: 0xffffffff,
                            witness: dashcore::Witness::new(),
                        })
                        .collect(),
                    output: match change {
                        Some(change) => vec![
                            TxOut {
                                value: sent,
                                script_pubkey: external_address.script_pubkey(),
                            },
                            TxOut {
                                value: change_value,
                                script_pubkey: change.script_pubkey(),
                            },
                        ],
                        None => vec![TxOut {
                            value: sent,
                            script_pubkey: external_address.script_pubkey(),
                        }],
                    },
                    special_transaction_payload: None,
                }
            };

        // Block 101: someone else spends P on chain, paying only externally.
        let thief = spend(vec![coin_p], None, 0, 990_000);
        ctx.check_transaction(
            &thief,
            TransactionContext::InBlock(BlockInfo::new(
                101,
                BlockHash::from_slice(&[9u8; 32]).expect("hash"),
                1_700_000_100,
            )),
        )
        .await;
        assert!(ctx.managed_wallet.observed_spent_outpoints().contains_key(&coin_p));

        // A doomed transaction of ours also spends P. `update_utxos` refuses to
        // credit its change X — P is already spent in a block, so this can
        // never confirm — but keeps the record.
        let doomed_change = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .next_change_address(Some(&ctx.xpub), true)
            .expect("change address");
        let doomed = spend(vec![coin_p], Some(&doomed_change), 500_000, 490_000);
        ctx.check_transaction(&doomed, TransactionContext::Mempool).await;
        let coin_x = OutPoint {
            txid: doomed.txid(),
            vout: 1,
        };
        assert!(
            !ctx.bip44_account().utxos.contains_key(&coin_x),
            "precondition: the doomed transaction's change was never credited"
        );
        assert!(
            ctx.bip44_account().transactions().contains_key(&doomed.txid()),
            "precondition: but its record is kept for history"
        );

        // A later unconfirmed transaction claims that phantom output X plus a
        // real coin Q.
        let loser_change = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .next_change_address(Some(&ctx.xpub), true)
            .expect("change address");
        let loser = spend(vec![coin_x, coin_q], Some(&loser_change), 90_000, 700_000);
        ctx.check_transaction(&loser, TransactionContext::Mempool).await;

        // A winner takes Q and confirms, sweeping the loser. X is released.
        let winner_change = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .next_change_address(Some(&ctx.xpub), true)
            .expect("change address");
        let winner = spend(vec![coin_q], Some(&winner_change), 200_000, 90_000);
        let result = ctx
            .check_transaction(
                &winner,
                TransactionContext::InBlock(BlockInfo::new(
                    102,
                    BlockHash::from_slice(&[2u8; 32]).expect("hash"),
                    1_700_000_200,
                )),
            )
            .await;
        assert!(
            result.released_outpoints.contains(&coin_x),
            "the reported set is unchanged: X is still named as released"
        );

        assert!(
            !ctx.bip44_account().utxos.contains_key(&coin_x),
            "a coin must never be rebuilt from a transaction that can never confirm"
        );
        assert!(
            !ctx.bip44_account().spendable_utxos(102).iter().any(|utxo| utxo.outpoint == coin_x),
            "and it must not reach coin selection by any other route"
        );
        assert_eq!(
            ctx.managed_wallet.balance.confirmed(),
            200_000,
            "only the winner's change; the phantom change X contributes nothing"
        );
        assert_eq!(ctx.managed_wallet.balance.unconfirmed(), 0);
    }

    /// A loser's change may already have funded further unconfirmed
    /// transactions, and the sweep removes those too — that is the descendant
    /// closure `drop_conflicted_transactions` walks. Their inputs land in
    /// `freed` like any other, including the ones pointing at a removed
    /// loser's own output.
    ///
    /// Such an outpoint must not be reported released. It is not a coin
    /// becoming spendable: it is an output of a transaction being deleted for
    /// never being able to confirm, so telling a mirror to mark it spendable
    /// re-credits money that does not exist — the exact class of bug the
    /// sweep exists to remove.
    #[tokio::test]
    async fn test_a_swept_descendants_claim_on_its_parents_output_is_not_released() {
        let mut ctx = TestWalletContext::new_random();
        let external_address = Address::p2pkh(
            &dashcore::PublicKey::from_slice(&[0x02; 33]).expect("pubkey"),
            Network::Testnet,
        );

        // Two confirmed coins: X, which the winner will take, and C, which
        // only the descendant spends.
        let funding_tx = Transaction::dummy(&ctx.receive_address, 0..2, &[500_000, 400_000]);
        ctx.check_transaction(
            &funding_tx,
            TransactionContext::InBlock(BlockInfo::new(
                100,
                BlockHash::from_slice(&[1u8; 32]).expect("hash"),
                1_700_000_000,
            )),
        )
        .await;

        let coin_x = OutPoint {
            txid: funding_tx.txid(),
            vout: 0,
        };
        let coin_c = OutPoint {
            txid: funding_tx.txid(),
            vout: 1,
        };
        let spend =
            |inputs: Vec<OutPoint>, change: &Address, change_amount: u64, sent: u64| Transaction {
                version: 2,
                lock_time: 0,
                input: inputs
                    .into_iter()
                    .map(|previous_output| TxIn {
                        previous_output,
                        script_sig: ScriptBuf::new(),
                        sequence: 0xffffffff,
                        witness: dashcore::Witness::new(),
                    })
                    .collect(),
                output: vec![
                    TxOut {
                        value: sent,
                        script_pubkey: external_address.script_pubkey(),
                    },
                    TxOut {
                        value: change_amount,
                        script_pubkey: change.script_pubkey(),
                    },
                ],
                special_transaction_payload: None,
            };

        // The parent spends X and pays itself change.
        let parent_change = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .next_change_address(Some(&ctx.xpub), true)
            .expect("change address");
        let parent = spend(vec![coin_x], &parent_change, 99_000, 400_000);
        ctx.check_transaction(&parent, TransactionContext::Mempool).await;
        let parent_change_outpoint = OutPoint {
            txid: parent.txid(),
            vout: 1,
        };

        // The descendant spends that change plus C — the ordinary shape of
        // chaining a second spend before the first confirms.
        let child_change = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .next_change_address(Some(&ctx.xpub), true)
            .expect("change address");
        let child = spend(vec![parent_change_outpoint, coin_c], &child_change, 89_000, 400_000);
        ctx.check_transaction(&child, TransactionContext::Mempool).await;

        // The winner takes X and confirms, sweeping the parent and, through
        // the descendant closure, the child.
        let winner_change = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .next_change_address(Some(&ctx.xpub), true)
            .expect("change address");
        let winner = spend(vec![coin_x], &winner_change, 99_000, 400_000);
        let result = ctx
            .check_transaction(
                &winner,
                TransactionContext::InBlock(BlockInfo::new(
                    101,
                    BlockHash::from_slice(&[2u8; 32]).expect("hash"),
                    1_700_000_100,
                )),
            )
            .await;

        assert!(
            result.swept_transactions.contains(&child.txid()),
            "sanity: the descendant is swept with its parent"
        );
        assert!(
            !result.released_outpoints.contains(&parent_change_outpoint),
            "an output of a transaction being deleted is not a coin becoming \
             spendable, got {:?}",
            result.released_outpoints
        );
        assert_eq!(
            result.released_outpoints,
            vec![coin_c],
            "only the real coin the descendant spent is released"
        );
    }

    /// A loser is removed from every account it was recorded in, and each of
    /// those accounts decides what it released from its own records alone. An
    /// account that never recorded the transaction still claiming one of the
    /// loser's inputs therefore sees nothing retaining that coin and calls it
    /// free — so the wallet-level union has to re-check the released set
    /// against every account before reporting it.
    ///
    /// Reachable through pooled funding: the loser's change lands in a second
    /// account, which is where its removal reports the release, while the
    /// surviving claim on that coin lives back in the funding account.
    #[tokio::test]
    async fn test_a_released_outpoint_another_account_still_claims_is_withheld() {
        let mut ctx = TestWalletContext::new_random();
        let external_address = Address::p2pkh(
            &dashcore::PublicKey::from_slice(&[0x02; 33]).expect("pubkey"),
            Network::Testnet,
        );

        // The BIP32 account is where the loser's change will land, which is
        // what gets the loser recorded in an account that knows nothing about
        // the coins it spent.
        let bip32_xpub = ctx
            .wallet
            .accounts
            .standard_bip32_accounts
            .get(&0)
            .expect("default options create BIP32 account 0")
            .account_xpub;
        let bip32_change = ctx
            .managed_wallet
            .first_bip32_managed_account_mut()
            .expect("BIP32 account")
            .next_receive_address(Some(&bip32_xpub), true)
            .expect("BIP32 address");

        let funding_tx = Transaction::dummy(&ctx.receive_address, 0..2, &[500_000, 400_000]);
        ctx.check_transaction(
            &funding_tx,
            TransactionContext::InBlock(BlockInfo::new(
                100,
                BlockHash::from_slice(&[1u8; 32]).expect("hash"),
                1_700_000_000,
            )),
        )
        .await;

        let coin_a = OutPoint {
            txid: funding_tx.txid(),
            vout: 0,
        };
        let coin_b = OutPoint {
            txid: funding_tx.txid(),
            vout: 1,
        };
        let spend =
            |inputs: Vec<OutPoint>, change: &Address, change_amount: u64, sent: u64| Transaction {
                version: 2,
                lock_time: 0,
                input: inputs
                    .into_iter()
                    .map(|previous_output| TxIn {
                        previous_output,
                        script_sig: ScriptBuf::new(),
                        sequence: 0xffffffff,
                        witness: dashcore::Witness::new(),
                    })
                    .collect(),
                output: vec![
                    TxOut {
                        value: sent,
                        script_pubkey: external_address.script_pubkey(),
                    },
                    TxOut {
                        value: change_amount,
                        script_pubkey: change.script_pubkey(),
                    },
                ],
                special_transaction_payload: None,
            };

        // The loser spends A and B, paying its change into the BIP32 account.
        let loser = spend(vec![coin_a, coin_b], &bip32_change, 99_000, 800_000);
        ctx.check_transaction(&loser, TransactionContext::Mempool).await;

        // A second unconfirmed transaction also claims B. Neither is final, so
        // neither sweeps the other, and this one survives what follows.
        let rival_change = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .next_change_address(Some(&ctx.xpub), true)
            .expect("change address");
        let rival = spend(vec![coin_b], &rival_change, 50_000, 340_000);
        ctx.check_transaction(&rival, TransactionContext::Mempool).await;

        // The winner takes A and confirms, sweeping the loser — but not the
        // rival, which shares no input with it.
        let winner_change = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .next_change_address(Some(&ctx.xpub), true)
            .expect("change address");
        let winner = spend(vec![coin_a], &winner_change, 99_000, 400_000);
        let result = ctx
            .check_transaction(
                &winner,
                TransactionContext::InBlock(BlockInfo::new(
                    101,
                    BlockHash::from_slice(&[2u8; 32]).expect("hash"),
                    1_700_000_100,
                )),
            )
            .await;

        assert!(
            !ctx.bip44_account().transactions().contains_key(&loser.txid()),
            "sanity: the loser was swept"
        );
        assert!(
            ctx.bip44_account().transactions().contains_key(&rival.txid()),
            "sanity: the rival is unconfirmed but shares no input with the winner"
        );
        assert!(!result.released_outpoints.contains(&coin_a), "A is the winner's own input");
        assert!(
            !result.released_outpoints.contains(&coin_b),
            "B is still claimed by the rival, whichever account noticed"
        );
        // And the withholding has to hold for the UTXO set too, not just the
        // report. Re-crediting a coin a surviving record still spends would
        // hand coin selection a guaranteed double spend — the reason the
        // restore runs only over the wallet-reconciled released set.
        let bip32_account =
            ctx.managed_wallet.first_bip32_managed_account().expect("BIP32 account");
        for account in [ctx.bip44_account(), bip32_account] {
            assert!(
                !account.utxos.contains_key(&coin_a),
                "A must not be re-credited: the winner spent it on chain"
            );
            assert!(
                !account.utxos.contains_key(&coin_b),
                "B must not be re-credited: the rival still claims it"
            );
        }
    }

    /// An InstantSend lock is final, so it settles the winner's inputs just as
    /// a block would — including when the winner was already sitting in the
    /// mempool alongside its loser, which is the transition that skips
    /// `record_transaction` and so skips the sweep it carries.
    #[tokio::test]
    async fn test_instant_send_on_an_existing_mempool_tx_drops_its_conflict() {
        let mut ctx = TestWalletContext::new_random();
        let external_address = Address::p2pkh(
            &dashcore::PublicKey::from_slice(&[0x02; 33]).expect("pubkey"),
            Network::Testnet,
        );

        let funding_value = 1_000_000u64;
        let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[funding_value]);
        ctx.check_transaction(
            &funding_tx,
            TransactionContext::InBlock(BlockInfo::new(
                100,
                BlockHash::from_slice(&[1u8; 32]).expect("hash"),
                1_700_000_000,
            )),
        )
        .await;

        let funding_outpoint = OutPoint {
            txid: funding_tx.txid(),
            vout: 0,
        };
        let spend_of = |change: &Address, change_amount: u64, sent: u64| Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: funding_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: 0xffffffff,
                witness: dashcore::Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: sent,
                    script_pubkey: external_address.script_pubkey(),
                },
                TxOut {
                    value: change_amount,
                    script_pubkey: change.script_pubkey(),
                },
            ],
            special_transaction_payload: None,
        };

        // Both competing spends land in the mempool, loser first.
        let loser_change = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .next_change_address(Some(&ctx.xpub), true)
            .expect("change address");
        let loser = spend_of(&loser_change, 399_000, 600_000);
        ctx.check_transaction(&loser, TransactionContext::Mempool).await;

        let winner_change = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .next_change_address(Some(&ctx.xpub), true)
            .expect("change address");
        let winner = spend_of(&winner_change, 299_000, 700_000);
        ctx.check_transaction(&winner, TransactionContext::Mempool).await;

        let loser_change_outpoint = OutPoint {
            txid: loser.txid(),
            vout: 1,
        };
        assert!(
            ctx.bip44_account().utxos.contains_key(&loser_change_outpoint),
            "both are live while neither is final"
        );

        // The winner is InstantSend-locked. It is already recorded, so this
        // takes the update-in-place branch rather than recording afresh.
        let is_lock = InstantLock {
            txid: winner.txid(),
            ..InstantLock::default()
        };
        ctx.check_transaction(&winner, TransactionContext::InstantSend(is_lock)).await;

        assert!(
            !ctx.bip44_account().utxos.contains_key(&loser_change_outpoint),
            "an IS lock settles the input, so the loser's change must not survive"
        );
        assert!(
            !ctx.bip44_account().transactions().contains_key(&loser.txid()),
            "the loser's record must be dropped too"
        );
    }

    /// Abandoning a transaction that never reached the network must take the
    /// transactions built on its change with it. This reproduces the shape
    /// seen on a testnet device: an asset-lock funding transaction stuck at
    /// `Built` whose broadcast never happened, then two further self-sends
    /// chained onto its phantom change. Five UTXOs from three transactions,
    /// none of which the network ever saw, and the whole chain has to go.
    #[tokio::test]
    async fn test_abandoning_an_unbroadcast_root_cascades_to_its_descendants() {
        let mut ctx = TestWalletContext::new_random();
        let external_address = Address::p2pkh(
            &dashcore::PublicKey::from_slice(&[0x02; 33]).expect("pubkey"),
            Network::Testnet,
        );

        // A real, confirmed coin funds the chain.
        let funding_value = 100_000_000u64;
        let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[funding_value]);
        ctx.check_transaction(
            &funding_tx,
            TransactionContext::InBlock(BlockInfo::new(
                100,
                BlockHash::from_slice(&[1u8; 32]).expect("hash"),
                1_700_000_000,
            )),
        )
        .await;
        assert_eq!(ctx.managed_wallet.balance.confirmed(), funding_value);

        // Build a three-link chain, each link spending its parent's change.
        // Every one of them stays in the mempool: nothing was ever broadcast.
        let mut parent = OutPoint {
            txid: funding_tx.txid(),
            vout: 0,
        };
        let mut change_left = funding_value;
        let mut chain = Vec::new();
        for (link, sent) in [40_000_000u64, 20_000_000, 5_000_000].into_iter().enumerate() {
            let fee = 226u64;
            let change = change_left - sent - fee;
            let change_address = ctx
                .managed_wallet
                .first_bip44_managed_account_mut()
                .expect("account")
                .next_change_address(Some(&ctx.xpub), true)
                .expect("change address");
            // The tip pays us twice, and nothing spends it onward, so both
            // outputs are still live when the cascade runs — exercising the
            // per-txid removal loops against a transaction contributing more
            // than one UTXO. A filter that dropped only the first would
            // otherwise pass every test here.
            let split = link == 2;
            let (change_a, change_b) = if split {
                (change / 2, change - change / 2)
            } else {
                (change, 0)
            };
            let mut outputs = vec![
                TxOut {
                    value: sent,
                    script_pubkey: external_address.script_pubkey(),
                },
                TxOut {
                    value: change_a,
                    script_pubkey: change_address.script_pubkey(),
                },
            ];
            if split {
                let second = ctx
                    .managed_wallet
                    .first_bip44_managed_account_mut()
                    .expect("account")
                    .next_change_address(Some(&ctx.xpub), true)
                    .expect("change address");
                outputs.push(TxOut {
                    value: change_b,
                    script_pubkey: second.script_pubkey(),
                });
            }
            let tx = Transaction {
                version: 2,
                lock_time: 0,
                input: vec![TxIn {
                    previous_output: parent,
                    script_sig: ScriptBuf::new(),
                    sequence: 0xffffffff,
                    witness: dashcore::Witness::new(),
                }],
                output: outputs,
                special_transaction_payload: None,
            };
            ctx.check_transaction(&tx, TransactionContext::Mempool).await;
            parent = OutPoint {
                txid: tx.txid(),
                vout: 1,
            };
            change_left = change;
            chain.push(tx);
        }

        let root = chain[0].txid();
        // Both live UTXOs belong to the tip, which pays us twice and is spent
        // onward by nothing — so the cascade has to drop two UTXOs for that
        // one txid rather than assuming one each. The earlier links' change
        // is consumed by the next link.
        assert_eq!(ctx.bip44_account().utxos.len(), 2, "live change outputs");

        let outcome = ctx.managed_wallet.abandon_transaction(root);
        ctx.managed_wallet.update_balance();

        assert_eq!(
            outcome.abandoned.len(),
            3,
            "the root and both descendants must be abandoned, got {:?}",
            outcome.abandoned
        );
        for tx in &chain {
            assert!(
                outcome.abandoned.contains(&tx.txid()),
                "chain member {} must be abandoned",
                tx.txid()
            );
            assert!(
                !ctx.bip44_account().transactions().contains_key(&tx.txid()),
                "chain member {} must lose its record",
                tx.txid()
            );
        }
        // Every phantom output is gone, and the one real coin the chain
        // consumed is back — rebuilt from the funding transaction's own
        // retained record, which the abandon never touched. The chain never
        // reached the network, so nothing ever spent that coin.
        let funding_outpoint = OutPoint {
            txid: funding_tx.txid(),
            vout: 0,
        };
        assert_eq!(
            ctx.bip44_account().utxos.keys().collect::<Vec<_>>(),
            vec![&funding_outpoint],
            "only the real funding coin may survive the cascade"
        );
        assert_eq!(
            outcome.released_outpoints,
            vec![funding_outpoint],
            "and the outcome must name it, so a persistence mirror follows"
        );
        // The load-bearing assertion. Trusted self-send change is bucketed as
        // *confirmed*, so the phantom counted as confirmed too; the balance
        // returning to exactly the funding value is what proves the phantoms
        // are gone and the real coin is not.
        assert_eq!(
            ctx.managed_wallet.balance.confirmed(),
            funding_value,
            "the phantoms counted as confirmed, so that is where their absence must show"
        );
        assert_eq!(ctx.managed_wallet.balance.unconfirmed(), 0);

        // Re-delivering the funding block changes nothing: the coin is
        // already back, and the restore does not depend on a rescan.
        let rediscovered = ctx
            .check_transaction(
                &funding_tx,
                TransactionContext::InBlock(BlockInfo::new(
                    100,
                    BlockHash::from_slice(&[1u8; 32]).expect("hash"),
                    1_700_000_000,
                )),
            )
            .await;
        assert!(rediscovered.is_relevant);
        assert_eq!(ctx.managed_wallet.balance.confirmed(), funding_value);
    }

    /// A transaction that loses a race for its inputs can never confirm, so
    /// the change it contributed is money that does not exist. Nothing else
    /// removes it — the loser is in no block, so no block processing revisits
    /// it — and it would otherwise sit in the `unconfirmed` bucket forever.
    #[tokio::test]
    async fn test_conflicting_confirmed_spend_drops_the_losing_transactions_outputs() {
        let mut ctx = TestWalletContext::new_random();
        let external_address = Address::p2pkh(
            &dashcore::PublicKey::from_slice(&[0x02; 33]).expect("pubkey"),
            Network::Testnet,
        );

        // Confirmed funding UTXO.
        let funding_value = 1_000_000u64;
        let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[funding_value]);
        ctx.check_transaction(
            &funding_tx,
            TransactionContext::InBlock(BlockInfo::new(
                100,
                BlockHash::from_slice(&[1u8; 32]).expect("hash"),
                1_700_000_000,
            )),
        )
        .await;

        let funding_outpoint = OutPoint {
            txid: funding_tx.txid(),
            vout: 0,
        };
        let spend_of = |change_address: &Address, change_amount: u64, sent: u64| Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: funding_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: 0xffffffff,
                witness: dashcore::Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: sent,
                    script_pubkey: external_address.script_pubkey(),
                },
                TxOut {
                    value: change_amount,
                    script_pubkey: change_address.script_pubkey(),
                },
            ],
            special_transaction_payload: None,
        };

        // First attempt: broadcast into the mempool, change comes back to us.
        let first_change = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .next_change_address(Some(&ctx.xpub), true)
            .expect("change address");
        let loser = spend_of(&first_change, 399_000, 600_000);
        ctx.check_transaction(&loser, TransactionContext::Mempool).await;

        let loser_change = OutPoint {
            txid: loser.txid(),
            vout: 1,
        };
        assert!(
            ctx.bip44_account().utxos.contains_key(&loser_change),
            "the first attempt's change is tracked while it is still live"
        );

        // Second attempt spends the same input and confirms in a block. The
        // first attempt can now never confirm.
        let second_change = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .next_change_address(Some(&ctx.xpub), true)
            .expect("change address");
        let winner = spend_of(&second_change, 299_000, 700_000);
        ctx.check_transaction(
            &winner,
            TransactionContext::InBlock(BlockInfo::new(
                101,
                BlockHash::from_slice(&[2u8; 32]).expect("hash"),
                1_700_000_100,
            )),
        )
        .await;

        assert!(
            !ctx.bip44_account().utxos.contains_key(&loser_change),
            "the losing transaction's change must not survive as spendable money"
        );
        assert!(
            !ctx.bip44_account().transactions().contains_key(&loser.txid()),
            "the losing transaction's record must be dropped too"
        );

        // Only the winner's change remains, and it is the whole balance.
        let winner_change = OutPoint {
            txid: winner.txid(),
            vout: 1,
        };
        assert!(ctx.bip44_account().utxos.contains_key(&winner_change));
        // Without the sweep this is 698_000 — the loser's change is trusted
        // self-send change and lands in the confirmed bucket, so only the
        // exact total catches a regression.
        assert_eq!(ctx.managed_wallet.balance.confirmed(), 299_000);
        assert_eq!(ctx.managed_wallet.balance.unconfirmed(), 0);
    }

    /// Pooled funding spans account families — an asset lock draws from BIP44,
    /// BIP32 and the DashPay contact-receiving accounts at once — so the
    /// trusted-self-send check must be answered by the whole wallet, not by
    /// the single account that happens to hold the change. Here the only input
    /// belongs to the BIP32 account while the change lands on BIP44: the
    /// transaction is still entirely ours, and its change must be trusted.
    #[tokio::test]
    async fn test_self_send_change_is_trusted_when_parent_is_in_a_sibling_account() {
        let mut ctx = TestWalletContext::new_random();
        let external_address = Address::p2pkh(
            &dashcore::PublicKey::from_slice(&[0x02; 33]).expect("pubkey"),
            Network::Testnet,
        );

        // Fund the *BIP32* account, confirmed in a block.
        let bip32_xpub = ctx
            .wallet
            .accounts
            .standard_bip32_accounts
            .get(&0)
            .expect("BIP32 account")
            .account_xpub;
        let bip32_address = ctx
            .managed_wallet
            .first_bip32_managed_account_mut()
            .expect("BIP32 managed account")
            .next_receive_address(Some(&bip32_xpub), true)
            .expect("BIP32 receive address");

        let funding_value = 1_000_000u64;
        let funding_tx = Transaction::dummy(&bip32_address, 0..1, &[funding_value]);
        let block_context = TransactionContext::InBlock(BlockInfo::new(
            100,
            BlockHash::from_slice(&[7u8; 32]).expect("hash"),
            1_700_000_000,
        ));
        ctx.check_transaction(&funding_tx, block_context).await;
        assert_eq!(ctx.managed_wallet.balance.confirmed(), funding_value);

        // Change goes to the BIP44 account, which holds none of the inputs.
        let change_address = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .next_change_address(Some(&ctx.xpub), true)
            .expect("change address");

        let send_amount = 600_000u64;
        let fee = 1_000u64;
        let change_amount = funding_value - send_amount - fee;
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

        let result = ctx.check_transaction(&spend_tx, TransactionContext::Mempool).await;
        assert!(result.is_relevant);

        let change_outpoint = OutPoint {
            txid: spend_tx.txid(),
            vout: 1,
        };
        let change_utxo =
            ctx.bip44_account().utxos.get(&change_outpoint).expect("change UTXO recorded");
        assert!(!change_utxo.is_confirmed);
        assert!(
            change_utxo.is_trusted,
            "change of a wallet-owned transfer must be trusted even when the spent \
             parent lives in a sibling account"
        );

        // And therefore it is confirmed, not unconfirmed, in the balance split.
        assert_eq!(ctx.managed_wallet.balance.unconfirmed(), 0);
        assert_eq!(ctx.managed_wallet.balance.confirmed(), change_amount);
    }

    /// Sibling of `test_self_send_change_in_mempool_lands_in_confirmed_balance`:
    /// a self-send change output is only trusted when the spent parent is
    /// itself final. `Utxo::is_trusted` mirrors Bitcoin Core's
    /// `CWalletTx::IsTrusted`, which is recursive: a 0-conf output is trusted
    /// only if every parent resolves to confirmed, InstantSend-locked, or
    /// trusted. Change spending an unconfirmed external parent must therefore
    /// stay in the unconfirmed bucket, otherwise non-final funds surface as
    /// confirmed/spendable and downstream asset locks get built on them.
    #[tokio::test]
    async fn test_self_send_change_with_unconfirmed_parent_is_not_trusted() {
        let mut ctx = TestWalletContext::new_random();
        let external_address = Address::p2pkh(
            &dashcore::PublicKey::from_slice(&[0x02; 33]).expect("pubkey"),
            Network::Testnet,
        );

        // Unconfirmed external funding UTXO: the parent stays in the mempool.
        let funding_value = 1_000_000u64;
        let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[funding_value]);
        ctx.check_transaction(&funding_tx, TransactionContext::Mempool).await;
        assert_eq!(ctx.managed_wallet.balance.confirmed(), 0);
        assert_eq!(ctx.managed_wallet.balance.unconfirmed(), funding_value);

        let change_address = ctx
            .managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .next_change_address(Some(&ctx.xpub), true)
            .expect("change address");

        // Spend the still-unconfirmed funding UTXO: some out, the rest back
        // to ourselves as change, broadcast into the mempool.
        let send_amount = 600_000u64;
        let fee = 1_000u64;
        let change_amount = funding_value - send_amount - fee;
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
        ctx.check_transaction(&spend_tx, TransactionContext::Mempool).await;

        let change_outpoint = OutPoint {
            txid: spend_tx.txid(),
            vout: 1,
        };
        let change_utxo =
            ctx.bip44_account().utxos.get(&change_outpoint).expect("change UTXO recorded");

        assert!(
            !change_utxo.is_trusted,
            "change spending an unconfirmed parent must not be trusted"
        );
        assert_eq!(
            ctx.managed_wallet.balance.confirmed(),
            0,
            "non-final funds must not be counted as confirmed"
        );
        assert_eq!(ctx.managed_wallet.balance.unconfirmed(), change_amount);
    }

    /// Sibling of `test_self_send_change_in_mempool_lands_in_confirmed_balance`:
    /// when the wallet receives a mempool payment but does not own any of the
    /// inputs, an output that happens to land on one of our addresses must
    /// remain in the unconfirmed bucket. The "self-send" carve-out only applies
    /// when at least one input is one of our own UTXOs.
    #[tokio::test]
    async fn test_external_mempool_payment_remains_unconfirmed() {
        let mut ctx = TestWalletContext::new_random();
        let payment_value = 250_000u64;
        let payment_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[payment_value]);

        let result = ctx.check_transaction(&payment_tx, TransactionContext::Mempool).await;
        assert!(result.is_relevant);
        assert!(result.is_new_transaction);

        let utxo = ctx.first_utxo();
        assert!(!utxo.is_confirmed, "external mempool payment must stay unconfirmed");
        assert!(!utxo.is_trusted, "external payment is not a self-send change");
        assert_eq!(ctx.managed_wallet.balance.confirmed(), 0);
        assert_eq!(ctx.managed_wallet.balance.unconfirmed(), payment_value);
    }
}
