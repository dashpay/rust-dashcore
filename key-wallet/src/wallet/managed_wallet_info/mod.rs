//! Managed wallet information
//!
//! This module contains the mutable metadata and information about a wallet
//! that is managed separately from the core wallet structure.

pub mod asset_lock_builder;
pub mod coin_selection;
pub mod fee;
pub mod helpers;
pub mod managed_account_operations;
pub mod managed_accounts;
pub mod transaction_builder;
pub mod transaction_building;
pub mod wallet_info_interface;

pub use managed_account_operations::ManagedAccountOperations;

use super::balance::WalletCoreBalance;
use super::metadata::WalletMetadata;
use crate::account::ManagedAccountCollection;
use crate::changeset::{BalanceChangeSet, Merge, WalletChangeSet};
use crate::Network;
use dashcore::blockdata::transaction::txout::TxOut;
use dashcore::prelude::CoreBlockHeight;
use dashcore::Txid;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Information about a managed wallet
///
/// This struct contains the mutable metadata and descriptive information
/// about a wallet, kept separate from the core wallet structure to maintain
/// immutability of the wallet itself.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ManagedWalletInfo {
    /// Network this wallet info is associated with
    pub network: Network,
    /// Unique wallet ID (SHA256 hash of root public key) - should match the Wallet's wallet_id
    pub wallet_id: [u8; 32],
    /// Wallet name
    pub name: Option<String>,
    /// Wallet description
    pub description: Option<String>,
    /// Wallet metadata
    pub metadata: WalletMetadata,
    /// All managed accounts
    pub accounts: ManagedAccountCollection,
    /// Cached wallet core balance - should be updated when accounts change
    pub balance: WalletCoreBalance,
    /// Transactions that have received an InstantSend lock.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub(crate) instant_send_locks: HashSet<Txid>,
}

impl ManagedWalletInfo {
    /// Create new managed wallet info with network and wallet ID
    pub fn new(network: Network, wallet_id: [u8; 32]) -> Self {
        Self {
            network,
            wallet_id,
            name: None,
            description: None,
            metadata: WalletMetadata::default(),
            accounts: ManagedAccountCollection::new(),
            balance: WalletCoreBalance::default(),
            instant_send_locks: HashSet::new(),
        }
    }

    /// Create managed wallet info with network, wallet ID and name
    pub fn with_name(network: Network, wallet_id: [u8; 32], name: String) -> Self {
        Self {
            network,
            wallet_id,
            name: Some(name),
            description: None,
            metadata: WalletMetadata::default(),
            accounts: ManagedAccountCollection::new(),
            balance: WalletCoreBalance::default(),
            instant_send_locks: HashSet::new(),
        }
    }

    /// Create managed wallet info from a Wallet
    pub fn from_wallet(wallet: &super::super::Wallet) -> Self {
        Self {
            network: wallet.network,
            wallet_id: wallet.wallet_id,
            name: None,
            description: None,
            metadata: WalletMetadata::default(),
            accounts: ManagedAccountCollection::from_account_collection(&wallet.accounts),
            balance: WalletCoreBalance::default(),
            instant_send_locks: HashSet::new(),
        }
    }

    /// Create managed wallet info from a Wallet with a name
    pub fn from_wallet_with_name(wallet: &super::super::Wallet, name: String) -> Self {
        let mut info = Self::from_wallet(wallet);
        info.name = Some(name);
        info
    }

    /// Create managed wallet info with birth height
    pub fn with_birth_height(
        network: Network,
        wallet_id: [u8; 32],
        birth_height: CoreBlockHeight,
    ) -> Self {
        let mut info = Self::new(network, wallet_id);
        info.metadata.birth_height = birth_height;
        info
    }

    /// Get the network for this wallet info
    pub fn network(&self) -> Network {
        self.network
    }

    /// Increment the transaction count
    pub fn increment_transactions(&mut self) {
        self.metadata.total_transactions += 1;
    }

    /// Update the wallet balance and return a `BalanceChangeSet` capturing the aggregate delta.
    pub fn update_balance_with_changeset(&mut self) -> BalanceChangeSet {
        let mut balance = WalletCoreBalance::default();
        let synced_height = self.metadata.synced_height;
        let mut combined = BalanceChangeSet::default();
        for account in self.accounts.all_accounts_mut() {
            let acct_cs = account.update_balance(synced_height);
            balance += account.balance;
            combined.merge(acct_cs);
        }
        self.balance = balance;
        combined
    }

    /// Apply a [`WalletChangeSet`] to this wallet info, updating all relevant
    /// state in place.
    ///
    /// Each sub-changeset is applied independently when present:
    /// - **chain**: updates `synced_height` and related metadata.
    /// - **utxos**: adds, removes, and IS-locks UTXOs in the owning accounts.
    /// - **transactions**: inserts transaction records into owning accounts.
    /// - **accounts**: advances revealed indices and marks addresses as used.
    /// - **balance**: applies signed deltas to the cached wallet balance.
    pub fn apply(&mut self, changeset: &WalletChangeSet) {
        // 1. Chain ----------------------------------------------------------
        if let Some(chain) = &changeset.chain {
            if let Some(height) = chain.height {
                self.metadata.synced_height = height;
            }
        }

        // 2. UTXOs ----------------------------------------------------------
        if let Some(utxos) = &changeset.utxos {
            // 2a. Added UTXOs – find owning account by address and insert.
            for (outpoint, entry) in &utxos.added {
                if let Some(account) = self
                    .accounts
                    .all_accounts_mut()
                    .into_iter()
                    .find(|a| a.contains_address(&entry.address))
                {
                    let utxo = Utxo::new(
                        *outpoint,
                        TxOut {
                            value: entry.value,
                            script_pubkey: entry.script_pubkey.clone(),
                        },
                        entry.address.clone(),
                        self.metadata.synced_height,
                        false, // not coinbase – changeset doesn't carry this info
                    );
                    // Propagate the IS-lock flag from the entry.
                    let mut utxo = utxo;
                    utxo.is_instantlocked = entry.is_instant_locked;
                    account.utxos.insert(*outpoint, utxo);
                }
            }

            // 2b. Spent UTXOs – remove from whichever account holds them.
            for outpoint in &utxos.spent {
                for account in self.accounts.all_accounts_mut() {
                    if account.utxos.remove(outpoint).is_some() {
                        break;
                    }
                }
            }

            // 2c. InstantSend-locked UTXOs – mark existing UTXOs.
            for outpoint in &utxos.instant_locked {
                for account in self.accounts.all_accounts_mut() {
                    if let Some(utxo) = account.utxos.get_mut(outpoint) {
                        utxo.is_instantlocked = true;
                        break;
                    }
                }
            }
        }

        // 3. Transactions ---------------------------------------------------
        if let Some(tx_cs) = &changeset.transactions {
            use crate::managed_account::transaction_record::{TransactionDirection, TransactionRecord};
            use crate::transaction_checking::transaction_router::TransactionType;
            use crate::transaction_checking::TransactionContext;

            for (txid, entry) in &tx_cs.records {
                // Build a TransactionContext from the entry's block info.
                let context = match (entry.block_height, entry.block_hash) {
                    (Some(h), Some(bh)) => {
                        use crate::transaction_checking::BlockInfo;
                        let block_info = BlockInfo::new(h, bh, entry.timestamp as u32);
                        if entry.is_chain_locked {
                            TransactionContext::InChainLockedBlock(block_info)
                        } else {
                            TransactionContext::InBlock(block_info)
                        }
                    }
                    _ => {
                        if entry.is_instant_locked {
                            TransactionContext::InstantSend
                        } else {
                            TransactionContext::Mempool
                        }
                    }
                };

                let direction = if entry.net_amount >= 0 {
                    TransactionDirection::Incoming
                } else {
                    TransactionDirection::Outgoing
                };

                let record = TransactionRecord::new(
                    entry.transaction.clone(),
                    context,
                    TransactionType::Standard, // best-effort default
                    direction,
                    Vec::new(), // input_details – not available from changeset
                    Vec::new(), // output_details – not available from changeset
                    entry.net_amount,
                );

                // Try to find the account that owns an address in this
                // transaction's outputs, and insert the record there.
                let mut inserted = false;
                for account in self.accounts.all_accounts_mut() {
                    for output in &entry.transaction.output {
                        if let Ok(addr) = crate::Address::from_script(
                            &output.script_pubkey,
                            self.network,
                        ) {
                            if account.contains_address(&addr) {
                                account.transactions.insert(*txid, record.clone());
                                inserted = true;
                                break;
                            }
                        }
                    }
                    if inserted {
                        break;
                    }
                }

                // Fallback: if no account matched via outputs, try inputs or
                // just insert into the first standard account.
                if !inserted {
                    if let Some(account) = self
                        .accounts
                        .standard_bip44_accounts
                        .values_mut()
                        .next()
                    {
                        account.transactions.insert(*txid, record);
                    }
                }
            }
        }

        // 4. Accounts -------------------------------------------------------
        if let Some(acct_cs) = &changeset.accounts {
            // 4a. last_revealed – advance the highest_generated index on
            // address pools for the given account indices.
            for (&account_index, &new_index) in &acct_cs.last_revealed {
                if let Some(account) = self
                    .accounts
                    .standard_bip44_accounts
                    .get_mut(&account_index)
                {
                    for pool in account.account_type.address_pools_mut() {
                        if let Some(current) = pool.highest_generated {
                            if new_index > current {
                                pool.highest_generated = Some(new_index);
                            }
                        } else {
                            pool.highest_generated = Some(new_index);
                        }
                    }
                }
            }

            // 4b. addresses_used – mark each address as used in its account.
            for (_, address) in &acct_cs.addresses_used {
                for account in self.accounts.all_accounts_mut() {
                    if account.contains_address(address) {
                        account.account_type.mark_address_used(address);
                        break;
                    }
                }
            }
        }

        // 5. Balance --------------------------------------------------------
        if let Some(balance_cs) = &changeset.balance {
            self.balance.apply_delta(balance_cs);
        }
    }
}

/// Re-export types from account module for convenience
pub use crate::account::TransactionRecord;
pub use crate::utxo::Utxo;
