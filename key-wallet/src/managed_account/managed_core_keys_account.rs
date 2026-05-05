//! Managed core keys account: address pools and key derivation without funds tracking
//!
//! This module contains a lightweight mutable account state that omits the funds
//! bookkeeping (balance, UTXOs, spent outpoints) carried by [`crate::managed_account::ManagedCoreFundsAccount`].
//! It is intended for accounts that exist primarily to derive keys/addresses for
//! special-purpose flows (identity registration, asset locks, masternode provider
//! keys) rather than to hold and spend Dash directly.

#[cfg(feature = "bls")]
use crate::account::BLSAccount;
#[cfg(feature = "eddsa")]
use crate::account::EdDSAAccount;
use crate::account::TransactionRecord;
use crate::managed_account::address_pool;
use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::managed_account::managed_account_type::ManagedAccountType;
use crate::Network;
use dashcore::Txid;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(any(feature = "keep_txs_in_memory", feature = "serde"))]
use std::collections::BTreeMap;
use std::collections::HashSet;

/// Managed core keys account with mutable state but no funds tracking.
///
/// Like [`crate::managed_account::ManagedCoreFundsAccount`] but without
/// `balance`, `utxos`, or `spent_outpoints`. Used for accounts that derive
/// special-purpose keys (identity registration, asset locks, masternode
/// provider keys) where per-account UTXO/balance bookkeeping is not
/// meaningful.
///
/// Most behavior comes from [`ManagedAccountTrait`] default methods; this
/// type only owns the primitive state.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ManagedCoreKeysAccount {
    /// Account type with embedded address pools and index
    managed_account_type: ManagedAccountType,
    /// Network this account belongs to
    network: Network,
    /// Whether this is a watch-only account
    is_watch_only: bool,
    /// Transaction history for this account.
    ///
    /// Only present when the `keep_txs_in_memory` Cargo feature is enabled.
    /// With the feature off, processed transactions update UTXOs and balance
    /// (on the funds variant) but no per-tx history is retained here.
    #[cfg(feature = "keep_txs_in_memory")]
    transactions: BTreeMap<Txid, TransactionRecord>,
    /// Txids of every transaction this account has already processed.
    ///
    /// Always populated regardless of `keep_txs_in_memory`, so dedup of
    /// re-events (mempool→block, late IS-lock arrivals) works in either
    /// feature configuration. Rebuilt from `transactions` during
    /// deserialization when the feature is enabled.
    #[cfg_attr(feature = "serde", serde(skip))]
    processed_txids: HashSet<Txid>,
    /// Revision counter incremented when the monitored address set changes
    /// (e.g. new addresses generated). Used to detect bloom filter staleness.
    #[cfg_attr(feature = "serde", serde(skip))]
    monitor_revision: u64,
}

impl ManagedCoreKeysAccount {
    /// Create a new managed keys account
    pub fn new(
        managed_account_type: ManagedAccountType,
        network: Network,
        is_watch_only: bool,
    ) -> Self {
        Self {
            managed_account_type,
            network,
            is_watch_only,
            #[cfg(feature = "keep_txs_in_memory")]
            transactions: BTreeMap::new(),
            processed_txids: HashSet::new(),
            monitor_revision: 0,
        }
    }

    /// Returns `true` if this account has already processed `txid`.
    ///
    /// Backed by an always-present `processed_txids` set, so this works
    /// regardless of whether the `keep_txs_in_memory` Cargo feature is
    /// enabled. Use [`Self::get_transaction`] to retrieve the full record
    /// (only available when the feature is enabled).
    pub fn has_transaction(&self, txid: &Txid) -> bool {
        self.processed_txids.contains(txid)
    }

    /// Returns the stored transaction record for `txid`, if any.
    ///
    /// Always returns `None` when the `keep_txs_in_memory` Cargo feature is
    /// disabled, since no records are retained.
    #[cfg(feature = "keep_txs_in_memory")]
    pub fn get_transaction(&self, txid: &Txid) -> Option<&TransactionRecord> {
        self.transactions.get(txid)
    }

    /// Always returns `None` because the `keep_txs_in_memory` Cargo feature
    /// is disabled, so no records are retained.
    #[cfg(not(feature = "keep_txs_in_memory"))]
    pub fn get_transaction(&self, _txid: &Txid) -> Option<&TransactionRecord> {
        None
    }

    /// Insert a transaction record. Used by the funds variant; always
    /// updates `processed_txids` regardless of feature.
    #[cfg(feature = "keep_txs_in_memory")]
    pub(crate) fn insert_transaction(&mut self, txid: Txid, record: TransactionRecord) {
        self.processed_txids.insert(txid);
        self.transactions.insert(txid, record);
    }

    /// Insert a transaction record. With the feature off, only the
    /// `processed_txids` set is updated.
    #[cfg(not(feature = "keep_txs_in_memory"))]
    pub(crate) fn insert_transaction(&mut self, txid: Txid, _record: TransactionRecord) {
        self.processed_txids.insert(txid);
    }

    /// Forget that `txid` was ever processed. Test-only escape hatch for
    /// simulating a "lost record" state.
    #[cfg(test)]
    pub(crate) fn forget_transaction(&mut self, txid: &Txid) {
        self.processed_txids.remove(txid);
        #[cfg(feature = "keep_txs_in_memory")]
        self.transactions.remove(txid);
    }

    /// Create a `ManagedCoreKeysAccount` from an [`Account`](super::super::Account).
    pub fn from_account(account: &super::super::Account) -> Self {
        let key_source = address_pool::KeySource::Public(account.account_xpub);
        let managed_type = ManagedAccountType::from_account_type(
            account.account_type,
            account.network,
            &key_source,
        )
        .unwrap_or_else(|_| {
            let no_key_source = address_pool::KeySource::NoKeySource;
            ManagedAccountType::from_account_type(
                account.account_type,
                account.network,
                &no_key_source,
            )
            .expect("Should succeed with NoKeySource")
        });

        Self::new(managed_type, account.network, account.is_watch_only)
    }

    /// Create a `ManagedCoreKeysAccount` from a [`BLSAccount`].
    #[cfg(feature = "bls")]
    pub fn from_bls_account(account: &BLSAccount) -> Self {
        let key_source = address_pool::KeySource::BLSPublic(account.bls_public_key.clone());
        let managed_type = ManagedAccountType::from_account_type(
            account.account_type,
            account.network,
            &key_source,
        )
        .unwrap_or_else(|_| {
            let no_key_source = address_pool::KeySource::NoKeySource;
            ManagedAccountType::from_account_type(
                account.account_type,
                account.network,
                &no_key_source,
            )
            .expect("Should succeed with NoKeySource")
        });

        Self::new(managed_type, account.network, account.is_watch_only)
    }

    /// Create a `ManagedCoreKeysAccount` from an [`EdDSAAccount`].
    #[cfg(feature = "eddsa")]
    pub fn from_eddsa_account(account: &EdDSAAccount) -> Self {
        // EdDSA requires hardened derivation, so we cannot generate addresses without the private key.
        let key_source = address_pool::KeySource::NoKeySource;
        let managed_type = ManagedAccountType::from_account_type(
            account.account_type,
            account.network,
            &key_source,
        )
        .expect("Should succeed with NoKeySource");

        Self::new(managed_type, account.network, account.is_watch_only)
    }
}

impl ManagedAccountTrait for ManagedCoreKeysAccount {
    fn managed_account_type(&self) -> &ManagedAccountType {
        &self.managed_account_type
    }

    fn managed_account_type_mut(&mut self) -> &mut ManagedAccountType {
        &mut self.managed_account_type
    }

    fn network(&self) -> Network {
        self.network
    }

    fn is_watch_only(&self) -> bool {
        self.is_watch_only
    }

    #[cfg(feature = "keep_txs_in_memory")]
    fn transactions(&self) -> &BTreeMap<Txid, TransactionRecord> {
        &self.transactions
    }

    #[cfg(feature = "keep_txs_in_memory")]
    fn transactions_mut(&mut self) -> &mut BTreeMap<Txid, TransactionRecord> {
        &mut self.transactions
    }

    fn has_transaction(&self, txid: &Txid) -> bool {
        self.processed_txids.contains(txid)
    }

    fn monitor_revision(&self) -> u64 {
        self.monitor_revision
    }

    fn bump_monitor_revision(&mut self) {
        self.monitor_revision += 1;
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for ManagedCoreKeysAccount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            managed_account_type: ManagedAccountType,
            network: Network,
            is_watch_only: bool,
            #[serde(default)]
            transactions: BTreeMap<Txid, TransactionRecord>,
        }

        let helper = Helper::deserialize(deserializer)?;
        let processed_txids: HashSet<Txid> = helper.transactions.keys().copied().collect();

        Ok(ManagedCoreKeysAccount {
            managed_account_type: helper.managed_account_type,
            network: helper.network,
            is_watch_only: helper.is_watch_only,
            #[cfg(feature = "keep_txs_in_memory")]
            transactions: helper.transactions,
            processed_txids,
            monitor_revision: 0,
        })
    }
}
