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
use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::wallet::managed_wallet_info::transaction_building::AccountTypePreference;
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::{Network, Wallet};
use dashcore::hash_types::ProTxHash;
use dashcore::prelude::CoreBlockHeight;
use dashcore::{Address, Txid};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};

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
    /// proTxHashes of the masternodes this wallet controls, watched so a later
    /// masternode-update special transaction is caught by the compact-filter
    /// scan.
    ///
    /// A `ProUpServTx`/`ProUpRevTx` carries only the masternode's `proTxHash`
    /// in the block's BIP158 compact filter (Dash Core inserts it as a bare
    /// 32-byte element via `AddHashElement`) and none of the wallet's
    /// scriptPubKeys, so owner/voting-key matching cannot catch it. The set is
    /// populated internally by transaction processing: when a matched
    /// `ProRegTx`/`ProUpRegTx` is discovered via the wallet's owner/voting key
    /// its `proTxHash` is recorded here. It is transient sync state derived
    /// from the chain, not wallet identity, so it is never persisted.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub(crate) watched_pro_tx_hashes: BTreeSet<ProTxHash>,
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
            watched_pro_tx_hashes: BTreeSet::new(),
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
            watched_pro_tx_hashes: BTreeSet::new(),
        }
    }

    /// Create managed wallet info from a Wallet
    /// Create managed wallet info from a Wallet, seeding the sync checkpoint at `birth_height`.
    ///
    /// Sets `birth_height` and seeds both `synced_height` and `last_processed_height` to
    /// `birth_height.saturating_sub(1)` so that the next block to scan is `birth_height`.
    pub fn from_wallet(wallet: &super::super::Wallet, birth_height: CoreBlockHeight) -> Self {
        let initial_height = birth_height.saturating_sub(1);
        Self {
            network: wallet.network,
            wallet_id: wallet.wallet_id,
            name: None,
            description: None,
            metadata: WalletMetadata {
                birth_height,
                synced_height: initial_height,
                last_processed_height: initial_height,
                ..WalletMetadata::default()
            },
            accounts: ManagedAccountCollection::from_account_collection(&wallet.accounts),
            balance: WalletCoreBalance::default(),
            instant_send_locks: HashSet::new(),
            watched_pro_tx_hashes: BTreeSet::new(),
        }
    }

    /// Create managed wallet info from a Wallet with a name, seeding the sync checkpoint
    /// at `birth_height` (see `from_wallet` for details).
    pub fn from_wallet_with_name(
        wallet: &super::super::Wallet,
        name: String,
        birth_height: CoreBlockHeight,
    ) -> Self {
        let mut info = Self::from_wallet(wallet, birth_height);
        info.name = Some(name);
        info
    }

    /// Get the network for this wallet info
    pub fn network(&self) -> Network {
        self.network
    }

    /// Read-only access to the InstantSend lock txid set.
    ///
    /// Exposes `instant_send_locks` (a `pub(crate)` field marked
    /// `serde(skip)`) so external diagnostic surfaces (e.g. the iOS
    /// memory explorer) can list the txids that have received an
    /// IS-lock without bypassing the encapsulation that keeps mutation
    /// inside this crate.
    pub fn instant_send_locks(&self) -> &HashSet<Txid> {
        &self.instant_send_locks
    }

    /// Watch a masternode's `proTxHash` so a later masternode-update special
    /// transaction is caught by the compact-filter scan.
    ///
    /// Called by transaction processing when a `ProRegTx`/`ProUpRegTx` matched
    /// via the wallet's owner/voting key is discovered. Idempotent: watching an
    /// already-watched `proTxHash` is a no-op. See `watched_pro_tx_hashes` for
    /// why the `proTxHash` has to be carried in the query directly.
    pub(crate) fn watch_pro_tx_hash(&mut self, pro_tx_hash: ProTxHash) {
        self.watched_pro_tx_hashes.insert(pro_tx_hash);
    }

    pub fn next_change_address(
        &mut self,
        wallet: &Wallet,
        account_index: u32,
        account_type_pref: AccountTypePreference,
        mark_as_used: bool,
    ) -> Option<Address> {
        let collection = self.accounts_mut();

        let address = match account_type_pref {
            AccountTypePreference::BIP44 => {
                let managed_account = collection.standard_bip44_accounts.get_mut(&account_index)?;
                let wallet_account = wallet.get_bip44_account(account_index)?;

                let address = managed_account
                    .next_change_address(Some(&wallet_account.account_xpub), true)
                    .ok();

                if let (Some(address), true) = (&address, mark_as_used) {
                    managed_account.mark_address_used(address);
                }

                address
            }
            AccountTypePreference::BIP32 => {
                let managed_account = collection.standard_bip32_accounts.get_mut(&account_index)?;
                let wallet_account = wallet.get_bip32_account(account_index)?;

                let address = managed_account
                    .next_change_address(Some(&wallet_account.account_xpub), true)
                    .ok();

                if let (Some(address), true) = (&address, mark_as_used) {
                    managed_account.mark_address_used(address);
                }

                address
            }
            AccountTypePreference::CoinJoin => {
                debug_assert!(false, "CoinJoin accounts are spend-only in our current use cases");
                None
            }
        };

        address
    }

    pub fn next_receive_address(
        &mut self,
        wallet: &Wallet,
        account_index: u32,
        account_type_pref: AccountTypePreference,
        mark_as_used: bool,
    ) -> Option<Address> {
        let collection = self.accounts_mut();

        let address = match account_type_pref {
            AccountTypePreference::BIP44 => {
                let managed_account = collection.standard_bip44_accounts.get_mut(&account_index)?;
                let wallet_account = wallet.get_bip44_account(account_index)?;

                let address = managed_account
                    .next_receive_address(Some(&wallet_account.account_xpub), true)
                    .ok();

                if let (Some(address), true) = (&address, mark_as_used) {
                    managed_account.mark_address_used(address);
                }

                address
            }
            AccountTypePreference::BIP32 => {
                let managed_account = collection.standard_bip32_accounts.get_mut(&account_index)?;
                let wallet_account = wallet.get_bip32_account(account_index)?;

                let address = managed_account
                    .next_receive_address(Some(&wallet_account.account_xpub), true)
                    .ok();

                if let (Some(address), true) = (&address, mark_as_used) {
                    managed_account.mark_address_used(address);
                }

                address
            }
            AccountTypePreference::CoinJoin => {
                debug_assert!(false, "CoinJoin accounts are spend-only in our current use cases");
                None
            }
        };

        address
    }
}

/// Re-export types from account module for convenience
pub use crate::account::TransactionRecord;
pub use crate::utxo::Utxo;
