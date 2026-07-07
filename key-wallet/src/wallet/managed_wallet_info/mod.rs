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
use dashcore::blockdata::transaction::OutPoint;
use dashcore::prelude::CoreBlockHeight;
use dashcore::{Address, Transaction, Txid};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

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
    /// Outpoints observed spent by transactions seen in a processed block,
    /// mapped to the height of the block that spent them.
    ///
    /// This is the wallet-level, classification-independent record of "this
    /// coin was consumed on-chain" used to keep out-of-order rescan delivery
    /// from resurrecting a spent UTXO (dashpay/rust-dashcore#649). A spend can
    /// be delivered before the transaction that funded the coin it spends, and
    /// it may be routed away from — or fail to match — the account that owns
    /// the coin; recording every block-observed spend here, independent of the
    /// spending transaction's classification, lets the funding-side insert be
    /// reconciled away whichever order the two blocks arrive in.
    ///
    /// Membership is intentionally permanent and one-way: an entry is only ever
    /// added, never removed, and reorg rollback does NOT retract it. Treating a
    /// coin as spendable again after a spend was observed is the failure this
    /// set exists to prevent, and the block heights are retained for diagnostics
    /// and future height-bounded pruning rather than for rollback. Only spends
    /// seen in a block (`InBlock` / `InChainLockedBlock`) are recorded —
    /// mempool-context spends are never recorded, so an unconfirmed spend can
    /// never wrongly invalidate a coin.
    ///
    /// Persisted (survives restart) so the guard holds across a cold reload;
    /// `#[serde(default)]` keeps wallet files written before this field existed
    /// loadable, seeding an empty set. Serialized as a sequence of
    /// `(OutPoint, height)` pairs rather than a map, because `OutPoint`'s
    /// human-readable serialization is not a valid JSON object key.
    #[cfg_attr(feature = "serde", serde(default, with = "observed_spent_outpoints_serde"))]
    pub(crate) observed_spent_outpoints: BTreeMap<OutPoint, CoreBlockHeight>,
}

/// Serde adapter for [`ManagedWalletInfo::observed_spent_outpoints`] that
/// encodes the map as a sequence of `(OutPoint, height)` pairs. A plain
/// `BTreeMap<OutPoint, _>` cannot round-trip through JSON, whose object keys
/// must be strings while `OutPoint` serializes to a string only as a *value*.
#[cfg(feature = "serde")]
mod observed_spent_outpoints_serde {
    use super::{BTreeMap, CoreBlockHeight, OutPoint};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(super) fn serialize<S>(
        map: &BTreeMap<OutPoint, CoreBlockHeight>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        map.iter().collect::<Vec<(&OutPoint, &CoreBlockHeight)>>().serialize(serializer)
    }

    pub(super) fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<BTreeMap<OutPoint, CoreBlockHeight>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Vec::<(OutPoint, CoreBlockHeight)>::deserialize(deserializer)?.into_iter().collect())
    }
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
            observed_spent_outpoints: BTreeMap::new(),
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
            observed_spent_outpoints: BTreeMap::new(),
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
            observed_spent_outpoints: BTreeMap::new(),
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

    /// Read-only access to the wallet-level observed-spent outpoint set
    /// (dashpay/rust-dashcore#649), mapping each on-chain-spent outpoint to the
    /// height of the block that spent it. See the field's doc comment for the
    /// invariants; exposed for diagnostics and tests.
    pub fn observed_spent_outpoints(&self) -> &BTreeMap<OutPoint, CoreBlockHeight> {
        &self.observed_spent_outpoints
    }

    /// Record every outpoint `tx` spends into [`Self::observed_spent_outpoints`]
    /// at `height`. Insert-only bookkeeping — it never touches account UTXO sets,
    /// so it is safe to call before `record_transaction` builds a spend's
    /// `input_details` from the still-present funding UTXO.
    ///
    /// A coinbase spends nothing real (its single input is the null prevout), so
    /// it is skipped. Call this only for block-context transactions
    /// (`InBlock` / `InChainLockedBlock`); mempool spends must never be recorded
    /// (see the field doc — an unconfirmed spend may never be mined).
    pub(crate) fn record_observed_spends(&mut self, tx: &Transaction, height: CoreBlockHeight) {
        if tx.is_coin_base() {
            return;
        }
        for input in &tx.input {
            self.observed_spent_outpoints.insert(input.previous_output, height);
        }
    }

    /// Drop any live UTXO consumed by `tx`'s inputs from whichever funding
    /// account currently holds it, scanning ALL funding accounts independently
    /// of the spending transaction's classification (dashpay/rust-dashcore#649).
    /// Returns whether any UTXO was removed.
    ///
    /// This is the un-gated counterpart to the normal spend path in
    /// `update_utxos`: it covers spends the wallet cannot attribute to the
    /// owning account (routed away by tx-type narrowing, or unmatched because
    /// the funding was seen in a different account). It is idempotent — a coin
    /// the normal path already removed is simply absent — so it never
    /// double-counts a spend. Coinbase inputs are skipped (null prevout).
    pub(crate) fn remove_spent_from_accounts(&mut self, tx: &Transaction) -> bool {
        if tx.is_coin_base() {
            return false;
        }
        let mut removed = false;
        for input in &tx.input {
            let outpoint = input.previous_output;
            for account in self.accounts.all_funding_accounts_mut() {
                if account.utxos.remove(&outpoint).is_some() {
                    account.bump_monitor_revision();
                    removed = true;
                    break;
                }
            }
        }
        removed
    }

    /// Reconcile UTXOs just inserted for `tx`'s outputs against the observed
    /// spent set: if an output this transaction creates was already recorded as
    /// spent by a higher-height block processed earlier (out-of-order rescan
    /// delivery), drop it from whichever funding account it landed in
    /// (dashpay/rust-dashcore#649). Returns whether any UTXO was removed.
    ///
    /// This is the funding-side half of the invariant — the spend-first
    /// ordering — complementing [`Self::remove_spent_from_accounts`], which
    /// handles the funding-first ordering.
    pub(crate) fn reconcile_inserts_with_observed_spends(&mut self, tx: &Transaction) -> bool {
        if self.observed_spent_outpoints.is_empty() {
            return false;
        }
        let txid = tx.txid();
        let mut removed = false;
        for vout in 0..tx.output.len() as u32 {
            let outpoint = OutPoint {
                txid,
                vout,
            };
            if !self.observed_spent_outpoints.contains_key(&outpoint) {
                continue;
            }
            for account in self.accounts.all_funding_accounts_mut() {
                if account.utxos.remove(&outpoint).is_some() {
                    account.bump_monitor_revision();
                    removed = true;
                    break;
                }
            }
        }
        removed
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
