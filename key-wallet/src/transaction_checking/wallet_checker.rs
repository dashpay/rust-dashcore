//! Wallet-level transaction checking
//!
//! This module provides methods on ManagedWalletInfo for checking
//! if transactions belong to the wallet.

pub(crate) use super::account_checker::TransactionCheckResult;
use super::transaction_router::TransactionRouter;
use crate::wallet::immature_transaction::ImmatureTransaction;
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::wallet::managed_wallet_info::ManagedWalletInfo;
use crate::{Network, Utxo, Wallet};
use dashcore::blockdata::transaction::Transaction;
use dashcore::BlockHash;
use dashcore::{Address as DashAddress, OutPoint};
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
                            AccountTypeMatch::DashpayReceivingFunds {
                                ..
                            }
                            | AccountTypeMatch::DashpayExternalAccount {
                                ..
                            } => {
                                // DashPay managed accounts are not persisted here yet
                                None
                            }
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
                                                // Construct TxOut clone explicitly to avoid trait assumptions
                                                let txout = dashcore::TxOut {
                                                    value: output.value,
                                                    script_pubkey: output.script_pubkey.clone(),
                                                };
                                                let mut utxo = Utxo::new(
                                                    outpoint,
                                                    txout,
                                                    addr,
                                                    utxo_height,
                                                    tx.is_coin_base(),
                                                );
                                                utxo.is_confirmed = is_confirmed;
                                                account.utxos.insert(outpoint, utxo);
                                            }
                                        }
                                    }

                                    // Remove any UTXOs that are being spent by this transaction
                                    for input in &tx.input {
                                        // If this input spends one of our UTXOs, remove it
                                        account.utxos.remove(&input.previous_output);
                                    }
                                }
                                _ => {
                                    // Skip UTXO ingestion for identity/provider accounts
                                }
                            }

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

                    // Emit a concise log for this detected transaction with net wallet change
                    let wallet_net: i64 =
                        (result.total_received as i64) - (result.total_sent as i64);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::{ManagedWalletInfo, Wallet};
    use dashcore::blockdata::script::ScriptBuf;
    use dashcore::blockdata::transaction::Transaction;
    use dashcore::OutPoint;
    use dashcore::TxOut;
    use dashcore::{Address, BlockHash, TxIn, Txid};

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

    /// Test wallet checker with no accounts for the network
    #[test]
    fn test_wallet_checker_no_accounts_for_network() {
        let network = Network::Testnet;
        let other_network = Network::Dash;

        // Create wallet on testnet but check transaction on mainnet
        let wallet = Wallet::new_random(&[network], WalletAccountCreationOptions::Default)
            .expect("Should create wallet");

        let mut managed_wallet =
            ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

        // Create a dummy transaction
        let dummy_address = Address::p2pkh(
            &dashcore::PublicKey::from_slice(&[0x02; 33]).expect("Should create pubkey"),
            other_network,
        );
        let tx = create_transaction_to_address(&dummy_address, 100_000);

        let context = TransactionContext::Mempool;

        // Check transaction on different network (should have no accounts)
        let result = managed_wallet.check_transaction(&tx, other_network, context, None);

        // Should return default result with no relevance
        assert!(!result.is_relevant);
        assert_eq!(result.total_received, 0);
        assert_eq!(result.total_sent, 0);
        assert!(result.affected_accounts.is_empty());
    }

    /// Test wallet checker with different account types to cover error branches
    #[test]
    fn test_wallet_checker_different_account_types() {
        let network = Network::Testnet;

        // Create wallet with multiple account types
        let mut wallet = Wallet::new_random(&[network], WalletAccountCreationOptions::None)
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
                network,
                None,
            )
            .expect("Should add BIP32 account");

        // Add CoinJoin account
        wallet
            .add_account(
                AccountType::CoinJoin {
                    index: 0,
                },
                network,
                None,
            )
            .expect("Should add CoinJoin account");

        // Add identity accounts
        wallet
            .add_account(AccountType::IdentityRegistration, network, None)
            .expect("Should add identity registration account");

        let mut managed_wallet =
            ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

        // Get addresses from different accounts to trigger different branches
        let account_collection = wallet.accounts.get(&network).expect("Should have accounts");

        // Get BIP32 account address
        if let Some(bip32_account) = account_collection.standard_bip32_accounts.get(&0) {
            let xpub = bip32_account.account_xpub;
            if let Some(managed_account) = managed_wallet.first_bip32_managed_account_mut(network) {
                let address = managed_account
                    .next_receive_address(Some(&xpub), true)
                    .expect("Should get BIP32 address");

                let tx = create_transaction_to_address(&address, 50_000);

                let context = TransactionContext::InBlock {
                    height: 100000,
                    block_hash: Some(
                        BlockHash::from_slice(&[0u8; 32]).expect("Should create block hash"),
                    ),
                    timestamp: Some(1234567890),
                };

                // This should exercise BIP32 account branch in the update logic
                let result = managed_wallet.check_transaction(&tx, network, context, Some(&wallet));

                // Should be relevant since it's our address
                assert!(result.is_relevant);
                assert_eq!(result.total_received, 50_000);
            }
        }

        // Get CoinJoin account address
        if let Some(coinjoin_account) = account_collection.coinjoin_accounts.get(&0) {
            let xpub = coinjoin_account.account_xpub;
            if let Some(managed_account) =
                managed_wallet.first_coinjoin_managed_account_mut(network)
            {
                let address = managed_account
                    .next_address(Some(&xpub), true)
                    .expect("Should get CoinJoin address");

                let tx = create_transaction_to_address(&address, 75_000);

                let context = TransactionContext::InChainLockedBlock {
                    height: 100001,
                    block_hash: Some(
                        BlockHash::from_slice(&[1u8; 32]).expect("Should create block hash"),
                    ),
                    timestamp: Some(1234567891),
                };

                // This should exercise CoinJoin account branch in the update logic
                let result = managed_wallet.check_transaction(&tx, network, context, Some(&wallet));

                // Since this is not a coinjoin looking transaction, we should not pick up on it.
                assert!(!result.is_relevant);
                assert_eq!(result.total_received, 0);
            }
        }
    }

    /// Test coinbase transaction handling for immature transaction logic
    #[test]
    fn test_wallet_checker_coinbase_immature_handling() {
        let network = Network::Testnet;
        let wallet = Wallet::new_random(&[network], WalletAccountCreationOptions::Default)
            .expect("Should create wallet");

        let mut managed_wallet =
            ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

        // Get a wallet address
        let account_collection = wallet.accounts.get(&network).expect("Should have accounts");
        let account =
            account_collection.standard_bip44_accounts.get(&0).expect("Should have BIP44 account");
        let xpub = account.account_xpub;

        let address = managed_wallet
            .first_bip44_managed_account_mut(network)
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

        // Test with InBlock context (should trigger immature transaction handling)
        let context = TransactionContext::InBlock {
            height: 100000,
            block_hash: Some(BlockHash::from_slice(&[1u8; 32]).expect("Should create block hash")),
            timestamp: Some(1234567890),
        };

        let result =
            managed_wallet.check_transaction(&coinbase_tx, network, context, Some(&wallet));

        // Should be relevant
        assert!(result.is_relevant);
        assert_eq!(result.total_received, 5_000_000_000);

        // The transaction should be stored even though it's immature
        let managed_account = managed_wallet
            .first_bip44_managed_account(network)
            .expect("Should have managed account");

        assert!(managed_account.transactions.contains_key(&coinbase_tx.txid()));
    }

    /// Test that spending a wallet-owned UTXO without creating change is detected
    #[test]
    fn test_wallet_checker_detects_spend_only_transaction() {
        let network = Network::Testnet;
        let wallet = Wallet::new_random(&[network], WalletAccountCreationOptions::Default)
            .expect("Should create wallet");

        let mut managed_wallet =
            ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

        // Prepare a managed BIP44 account and derive a receive address
        let account_collection = wallet.accounts.get(&network).expect("Should have accounts");
        let wallet_account =
            account_collection.standard_bip44_accounts.get(&0).expect("Should have BIP44 account");

        let receive_address = managed_wallet
            .first_bip44_managed_account_mut(network)
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
            managed_wallet.check_transaction(&funding_tx, network, funding_context, Some(&wallet));
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
            managed_wallet.check_transaction(&spend_tx, network, spend_context, Some(&wallet));

        assert!(spend_result.is_relevant, "Spend transaction should be detected");
        assert_eq!(spend_result.total_received, 0);
        assert_eq!(spend_result.total_sent, funding_value);

        // Ensure the UTXO was removed and the transaction record reflects the spend
        let account = managed_wallet
            .accounts
            .get(&network)
            .expect("Should have managed accounts")
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

    /// Test mempool context for timestamp/height handling
    #[test]
    fn test_wallet_checker_mempool_context() {
        let network = Network::Testnet;
        let wallet = Wallet::new_random(&[network], WalletAccountCreationOptions::Default)
            .expect("Should create wallet");

        let mut managed_wallet =
            ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

        // Get a wallet address
        let account_collection = wallet.accounts.get(&network).expect("Should have accounts");
        let account =
            account_collection.standard_bip44_accounts.get(&0).expect("Should have BIP44 account");
        let xpub = account.account_xpub;

        let address = managed_wallet
            .first_bip44_managed_account_mut(network)
            .expect("Should have managed account")
            .next_receive_address(Some(&xpub), true)
            .expect("Should get address");

        let tx = create_transaction_to_address(&address, 100_000);

        // Test with Mempool context
        let context = TransactionContext::Mempool;

        let result = managed_wallet.check_transaction(&tx, network, context, Some(&wallet));

        // Should be relevant
        assert!(result.is_relevant);
        assert_eq!(result.total_received, 100_000);

        // Check that transaction was stored with correct context (no height, no block hash)
        let managed_account = managed_wallet
            .first_bip44_managed_account(network)
            .expect("Should have managed account");

        let stored_tx =
            managed_account.transactions.get(&tx.txid()).expect("Should have stored transaction");
        assert_eq!(stored_tx.height, None, "Mempool transaction should have no height");
        assert_eq!(stored_tx.block_hash, None, "Mempool transaction should have no block hash");
        assert_eq!(stored_tx.timestamp, 0, "Mempool transaction should have timestamp 0");
    }
}
