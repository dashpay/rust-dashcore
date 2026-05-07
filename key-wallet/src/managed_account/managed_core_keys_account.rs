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
use crate::managed_account::transaction_record::TransactionDirection;
use crate::transaction_checking::account_checker::AccountMatch;
use crate::transaction_checking::transaction_router::TransactionType;
use crate::transaction_checking::TransactionContext;
use crate::Network;
use dashcore::{Transaction, Txid};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[cfg(not(feature = "keep-finalized-transactions"))]
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ManagedCoreKeysAccount {
    /// Account type with embedded address pools and index
    managed_account_type: ManagedAccountType,
    /// Network this account belongs to
    network: Network,
    /// Transaction history for this account.
    ///
    /// With the `keep-finalized-transactions` Cargo feature ON, every
    /// processed transaction lives here for the wallet's lifetime —
    /// including ones that have been chainlocked. With the feature OFF
    /// (the default), records of chainlocked transactions are dropped
    /// from this map and only their txids are retained in
    /// `finalized_txids` to bound memory growth.
    transactions: BTreeMap<Txid, TransactionRecord>,
    /// Txids of transactions that have been finalized in a chainlocked
    /// block and whose full records have been dropped from
    /// `transactions` to save memory.
    ///
    /// Only present when the `keep-finalized-transactions` Cargo feature
    /// is OFF — with the feature on, finalized records stay in
    /// `transactions` and there's no need for a separate set.
    ///
    /// Note: an InstantSend lock alone does NOT add a txid here. We
    /// wait for the surrounding block to be chainlocked so the record
    /// can absorb the block-confirmation event (height / block hash)
    /// before being dropped.
    #[cfg(not(feature = "keep-finalized-transactions"))]
    #[cfg_attr(feature = "serde", serde(default))]
    finalized_txids: HashSet<Txid>,
    /// Revision counter incremented when the monitored address set changes
    /// (e.g. new addresses generated). Used to detect bloom filter staleness.
    #[cfg_attr(feature = "serde", serde(skip))]
    monitor_revision: u64,
}

impl ManagedCoreKeysAccount {
    /// Create a new managed keys account
    pub fn new(managed_account_type: ManagedAccountType, network: Network) -> Self {
        Self {
            managed_account_type,
            network,
            transactions: BTreeMap::new(),
            #[cfg(not(feature = "keep-finalized-transactions"))]
            finalized_txids: HashSet::new(),
            monitor_revision: 0,
        }
    }

    /// Drop the full record for `txid` and remember only its txid.
    ///
    /// Only defined when the `keep-finalized-transactions` Cargo feature
    /// is OFF (the default). Called when a transaction transitions into
    /// `InChainLockedBlock` — the record's information is no longer
    /// expected to change, so we save memory by replacing it with a
    /// txid-only entry. [`ManagedAccountTrait::has_transaction`] keeps
    /// reporting it as known, and
    /// [`ManagedAccountTrait::transaction_is_finalized`] keeps
    /// returning `true`.
    ///
    /// With the feature on the full record stays in `transactions`
    /// indefinitely, so there's nothing to do — the function does not
    /// exist in that mode.
    #[cfg(not(feature = "keep-finalized-transactions"))]
    pub(crate) fn drop_finalized_transaction(&mut self, txid: &Txid) {
        self.finalized_txids.insert(*txid);
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

        Self::new(managed_type, account.network)
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

        Self::new(managed_type, account.network)
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

        Self::new(managed_type, account.network)
    }

    /// Record a new transaction for this keys account.
    ///
    /// The keys-account record is intentionally a thin marker: it captures
    /// "this tx involved this keys account" plus the `net_amount` flowing
    /// to our addresses, and no more. The wallet-level details
    /// (per-input UTXO origins, per-output roles) live on the **funding
    /// account's** record — keys-account flows (identity registration,
    /// asset lock, provider-key registration / update) are typically
    /// funded from a Standard or CoinJoin account in the same wallet,
    /// and that account's `record_transaction` already populates
    /// `input_details` (from its UTXO set) and `output_details`
    /// (classified into receive / change / sent). Duplicating that work
    /// on the keys-account side would double-count and de-sync if the
    /// classification ever changes.
    ///
    /// Direction is [`TransactionDirection::Internal`]: from the wallet's
    /// perspective these txs move funds from one of its accounts to
    /// another, even when only the keys account is matched here.
    pub(crate) fn record_transaction(
        &mut self,
        tx: &Transaction,
        account_match: &AccountMatch,
        context: TransactionContext,
        transaction_type: TransactionType,
    ) -> TransactionRecord {
        let net_amount = account_match.received as i64 - account_match.sent as i64;

        let tx_record = TransactionRecord::new(
            tx.clone(),
            self.managed_account_type.to_account_type(),
            context.clone(),
            transaction_type,
            TransactionDirection::Internal,
            Vec::new(),
            Vec::new(),
            net_amount,
        );

        let record = tx_record.clone();
        let txid = tx.txid();
        self.transactions.insert(txid, tx_record);

        // If this first sighting is already chainlocked (e.g. a wallet
        // rescan from storage), drop the full record now and keep only the
        // txid in `finalized_txids`. No-op when the feature is on (we want
        // to keep the full record).
        #[cfg(not(feature = "keep-finalized-transactions"))]
        if context.is_chain_locked() {
            self.drop_finalized_transaction(&txid);
        }

        record
    }

    /// Re-process a transaction with updated context for this keys account.
    ///
    /// Mirrors [`ManagedCoreFundsAccount::confirm_transaction`](crate::managed_account::ManagedCoreFundsAccount::confirm_transaction)
    /// but without UTXO updates. Returns the updated record only when the
    /// confirmation status actually changes (e.g. mempool → in-block).
    pub(crate) fn confirm_transaction(
        &mut self,
        tx: &Transaction,
        account_match: &AccountMatch,
        context: TransactionContext,
        transaction_type: TransactionType,
    ) -> Option<TransactionRecord> {
        let txid = tx.txid();

        // Already finalized via a chainlock: the tx is immutable —
        // no record update, no event needed.
        if self.transaction_is_finalized(&txid) {
            return None;
        }

        if !self.has_transaction(&txid) {
            // Genuinely new sighting — delegate to record_transaction
            // (which handles finalize-on-record itself).
            let record = self.record_transaction(tx, account_match, context, transaction_type);
            return Some(record);
        }

        let mut changed = false;
        if let Some(tx_record) = self.transactions.get_mut(&txid) {
            debug_assert_eq!(
                tx_record.transaction_type,
                transaction_type,
                "transaction_type changed between recordings for {}",
                tx.txid()
            );
            if tx_record.context != context {
                let was_confirmed = tx_record.context.confirmed();
                tx_record.update_context(context.clone());
                changed = !was_confirmed;
            }
        }

        let record_after = if changed {
            self.transactions.get(&txid).cloned()
        } else {
            None
        };

        // Drop the full record on chainlock when the feature is off; the
        // surrounding block-confirmation event has already updated context.
        #[cfg(not(feature = "keep-finalized-transactions"))]
        if context.is_chain_locked() {
            self.drop_finalized_transaction(&txid);
        }

        let _ = account_match;

        record_after
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

    fn transactions(&self) -> &BTreeMap<Txid, TransactionRecord> {
        &self.transactions
    }

    fn transactions_mut(&mut self) -> &mut BTreeMap<Txid, TransactionRecord> {
        &mut self.transactions
    }

    /// With the `keep-finalized-transactions` feature ON, every record
    /// we have ever processed stays in `transactions` — that map is the
    /// authoritative dedup set.
    #[cfg(feature = "keep-finalized-transactions")]
    fn has_transaction(&self, txid: &Txid) -> bool {
        self.transactions.contains_key(txid)
    }

    /// With the feature OFF (the default), chainlocked records are
    /// pruned from `transactions` and only their txids are retained in
    /// `finalized_txids`. Both sets need to be consulted.
    #[cfg(not(feature = "keep-finalized-transactions"))]
    fn has_transaction(&self, txid: &Txid) -> bool {
        self.transactions.contains_key(txid) || self.finalized_txids.contains(txid)
    }

    /// With the feature ON, finalized records live in `transactions`,
    /// so we resolve the answer purely off the live record's context.
    #[cfg(feature = "keep-finalized-transactions")]
    fn transaction_is_finalized(&self, txid: &Txid) -> bool {
        self.transactions.get(txid).is_some_and(|r| r.context.is_chain_locked())
    }

    /// With the feature OFF, chainlocked records are dropped from
    /// `transactions` and only their txids are retained in
    /// `finalized_txids`. A live record can never satisfy this check
    /// (it would have been pruned at the chainlock event), so the only
    /// `true` answer comes from the txid set.
    #[cfg(not(feature = "keep-finalized-transactions"))]
    fn transaction_is_finalized(&self, txid: &Txid) -> bool {
        self.finalized_txids.contains(txid)
    }

    fn monitor_revision(&self) -> u64 {
        self.monitor_revision
    }

    fn bump_monitor_revision(&mut self) {
        self.monitor_revision += 1;
    }
}
