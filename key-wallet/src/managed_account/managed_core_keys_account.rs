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
use std::collections::BTreeMap;

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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ManagedCoreKeysAccount {
    /// Account type with embedded address pools and index
    managed_account_type: ManagedAccountType,
    /// Network this account belongs to
    network: Network,
    /// Whether this is a watch-only account
    is_watch_only: bool,
    /// Transaction history for this account
    transactions: BTreeMap<Txid, TransactionRecord>,
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
            transactions: BTreeMap::new(),
            monitor_revision: 0,
        }
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

    fn transactions(&self) -> &BTreeMap<Txid, TransactionRecord> {
        &self.transactions
    }

    fn transactions_mut(&mut self) -> &mut BTreeMap<Txid, TransactionRecord> {
        &mut self.transactions
    }

    fn monitor_revision(&self) -> u64 {
        self.monitor_revision
    }

    fn bump_monitor_revision(&mut self) {
        self.monitor_revision += 1;
    }
}
