//! Managed account structure with mutable state
//!
//! This module contains the mutable account state that changes during wallet operation,
//! kept separate from the immutable Account structure.

use crate::account::AccountMetadata;
use crate::account::AccountType;
#[cfg(feature = "bls")]
use crate::account::BLSAccount;
#[cfg(feature = "eddsa")]
use crate::account::EdDSAAccount;
use crate::account::ManagedAccountTrait;
use crate::account::TransactionRecord;
use crate::changeset::{AccountChangeSet, BalanceChangeSet, Merge, WalletChangeSet};
#[cfg(feature = "bls")]
use crate::derivation_bls_bip32::ExtendedBLSPubKey;
#[cfg(any(feature = "bls", feature = "eddsa"))]
use crate::managed_account::address_pool::PublicKeyType;
use crate::managed_account::transaction_record::{
    InputDetail, OutputDetail, OutputRole, TransactionDirection,
};
use crate::transaction_checking::transaction_router::TransactionType;
use crate::transaction_checking::{AccountMatch, TransactionContext};
use crate::utxo::Utxo;
use crate::wallet::balance::WalletCoreBalance;
#[cfg(feature = "eddsa")]
use crate::AddressInfo;
use crate::{ExtendedPubKey, Network};
use dashcore::blockdata::transaction::OutPoint;
use dashcore::{Address, ScriptBuf};
use dashcore::{Transaction, Txid};
use managed_account_type::ManagedAccountType;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::{BTreeSet, HashSet};

pub mod address_pool;
pub mod managed_account_collection;
pub mod managed_account_trait;
pub mod managed_account_type;
pub mod managed_platform_account;
pub mod metadata;
pub mod platform_address;
pub mod transaction_record;

/// Managed account with mutable state
///
/// This struct contains the mutable state of an account including address pools,
/// metadata, and balance information. It is managed separately from
/// the immutable Account structure.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ManagedCoreAccount {
    /// Account type with embedded address pools and index
    pub account_type: ManagedAccountType,
    /// Network this account belongs to
    pub network: Network,
    /// Account metadata
    pub metadata: AccountMetadata,
    /// Whether this is a watch-only account
    pub is_watch_only: bool,
    /// Account balance information
    pub balance: WalletCoreBalance,
    /// Transaction history for this account
    pub transactions: BTreeMap<Txid, TransactionRecord>,
    /// UTXO set for this account
    pub utxos: BTreeMap<OutPoint, Utxo>,
    /// Outpoints spent by recorded transactions.
    /// Rebuilt from `transactions` during deserialization.
    #[cfg_attr(feature = "serde", serde(skip_serializing))]
    spent_outpoints: HashSet<OutPoint>,
    /// Revision counter incremented when the monitored address set changes
    /// (e.g. new addresses generated). Used to detect bloom filter staleness.
    #[cfg_attr(feature = "serde", serde(skip_serializing))]
    monitor_revision: u64,
}

impl ManagedCoreAccount {
    /// Create a new managed account
    pub fn new(account_type: ManagedAccountType, network: Network, is_watch_only: bool) -> Self {
        Self {
            account_type,
            network,
            metadata: AccountMetadata::default(),
            is_watch_only,
            balance: WalletCoreBalance::default(),
            transactions: BTreeMap::new(),
            utxos: BTreeMap::new(),
            spent_outpoints: HashSet::new(),
            monitor_revision: 0,
        }
    }

    /// Return the current monitor revision.
    pub fn monitor_revision(&self) -> u64 {
        self.monitor_revision
    }

    /// Increment the monitor revision to signal that the monitored address set changed.
    pub fn bump_monitor_revision(&mut self) {
        self.monitor_revision += 1;
    }

    /// Check if an outpoint was spent by a previously recorded transaction.
    fn is_outpoint_spent(&self, outpoint: &OutPoint) -> bool {
        self.spent_outpoints.contains(outpoint)
    }

    /// Create a ManagedAccount from an Account
    pub fn from_account(account: &super::Account) -> Self {
        // Use the account's public key as the key source
        let key_source = address_pool::KeySource::Public(account.account_xpub);
        let managed_type = ManagedAccountType::from_account_type(
            account.account_type,
            account.network,
            &key_source,
        )
        .unwrap_or_else(|_| {
            // Fallback: create without pre-generated addresses
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

    /// Create a ManagedAccount from a BLS Account
    #[cfg(feature = "bls")]
    pub fn from_bls_account(account: &BLSAccount) -> Self {
        // Use the BLS public key as the key source
        let key_source = address_pool::KeySource::BLSPublic(account.bls_public_key.clone());
        let managed_type = ManagedAccountType::from_account_type(
            account.account_type,
            account.network,
            &key_source,
        )
        .unwrap_or_else(|_| {
            // Fallback: create without pre-generated addresses
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

    /// Create a ManagedAccount from an EdDSA Account
    #[cfg(feature = "eddsa")]
    pub fn from_eddsa_account(account: &EdDSAAccount) -> Self {
        // EdDSA requires hardened derivation, so we can't generate addresses without private key
        let key_source = address_pool::KeySource::NoKeySource;
        let managed_type = ManagedAccountType::from_account_type(
            account.account_type,
            account.network,
            &key_source,
        )
        .expect("Should succeed with NoKeySource");

        Self::new(managed_type, account.network, account.is_watch_only)
    }

    /// Get the account index
    pub fn index(&self) -> Option<u32> {
        self.account_type.index()
    }

    /// Get the account index or 0 if none exists
    pub fn index_or_default(&self) -> u32 {
        self.account_type.index_or_default()
    }

    /// Get the managed account type
    pub fn managed_type(&self) -> &ManagedAccountType {
        &self.account_type
    }

    /// Get the next unused receive address index for standard accounts
    /// Note: This requires a key source which is not available in ManagedAccount
    /// Address generation should be done through a method that has access to the Account's keys
    pub fn get_next_receive_address_index(&self) -> Option<u32> {
        // Only applicable for standard accounts
        if let ManagedAccountType::Standard {
            external_addresses,
            ..
        } = &self.account_type
        {
            // Get the first unused address or the next index after the last used one
            if let Some(addr) = external_addresses.unused_addresses().first() {
                external_addresses.address_index(addr)
            } else {
                // If no unused addresses, return the next index based on stats
                let stats = external_addresses.stats();
                Some(stats.highest_generated.map(|h| h + 1).unwrap_or(0))
            }
        } else {
            None
        }
    }

    /// Get the next unused change address index for standard accounts
    /// Note: This requires a key source which is not available in ManagedAccount
    /// Address generation should be done through a method that has access to the Account's keys
    pub fn get_next_change_address_index(&self) -> Option<u32> {
        // Only applicable for standard accounts
        if let ManagedAccountType::Standard {
            internal_addresses,
            ..
        } = &self.account_type
        {
            // Get the first unused address or the next index after the last used one
            if let Some(addr) = internal_addresses.unused_addresses().first() {
                internal_addresses.address_index(addr)
            } else {
                // If no unused addresses, return the next index based on stats
                let stats = internal_addresses.stats();
                Some(stats.highest_generated.map(|h| h + 1).unwrap_or(0))
            }
        } else {
            None
        }
    }

    /// Get the next unused address index for single-pool account types
    pub fn get_next_address_index(&self) -> Option<u32> {
        match &self.account_type {
            ManagedAccountType::Standard {
                ..
            } => self.get_next_receive_address_index(),
            ManagedAccountType::CoinJoin {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityRegistration {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityTopUp {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityTopUpNotBoundToIdentity {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityInvitation {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityAuthenticationEcdsa {
                addresses,
                ..
            }
            | ManagedAccountType::AssetLockAddressTopUp {
                addresses,
                ..
            }
            | ManagedAccountType::AssetLockShieldedAddressTopUp {
                addresses,
                ..
            }
            | ManagedAccountType::ProviderVotingKeys {
                addresses,
                ..
            }
            | ManagedAccountType::ProviderOwnerKeys {
                addresses,
                ..
            }
            | ManagedAccountType::ProviderOperatorKeys {
                addresses,
                ..
            }
            | ManagedAccountType::ProviderPlatformKeys {
                addresses,
                ..
            }
            | ManagedAccountType::DashpayReceivingFunds {
                addresses,
                ..
            }
            | ManagedAccountType::DashpayExternalAccount {
                addresses,
                ..
            }
            | ManagedAccountType::PlatformPayment {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityAuthenticationBls {
                addresses,
                ..
            } => {
                addresses.unused_addresses().first().and_then(|addr| addresses.address_index(addr))
            }
        }
    }

    /// Mark an address as used, returning a changeset describing the effect.
    ///
    /// Returns `(changed, cs)` where the per-account delta lives at
    /// `cs.per_account[self.account_type.to_account_type()].addresses_used`.
    /// `changed` is `false` on replay or for unknown addresses, and the
    /// changeset is empty in that case (idempotent).
    pub fn mark_address_used(&mut self, address: &Address) -> (bool, WalletChangeSet) {
        // Update metadata timestamp
        self.metadata.last_used = Some(Self::current_timestamp());

        let changed = self.account_type.mark_address_used(address);
        let mut cs = WalletChangeSet::default();
        if changed {
            cs.account_bucket(self.account_type.to_account_type())
                .addresses_used
                .insert(address.clone());
        }
        (changed, cs)
    }

    /// Add new UTXOs for received outputs and remove spent ones.
    ///
    /// Returns a [`WalletChangeSet`] whose per-account bucket carries
    /// the additions and removals. Non-spendable account types
    /// (Identity*, Provider*, etc.) return an empty changeset.
    fn update_utxos(
        &mut self,
        tx: &Transaction,
        account_match: &AccountMatch,
        context: TransactionContext,
    ) -> WalletChangeSet {
        let mut cs = WalletChangeSet::default();

        // Non-spendable account types (Identity*, Provider*, …) have
        // nothing to record.
        match &self.account_type {
            ManagedAccountType::Standard {
                ..
            }
            | ManagedAccountType::CoinJoin {
                ..
            }
            | ManagedAccountType::DashpayReceivingFunds {
                ..
            }
            | ManagedAccountType::DashpayExternalAccount {
                ..
            } => {}
            _ => return cs,
        }

        let involved_addrs: BTreeSet<_> = account_match
            .account_type_match
            .all_involved_addresses()
            .iter()
            .map(|info| info.address.clone())
            .collect();

        let txid = tx.txid();
        let account_type_key = self.account_type.to_account_type();
        let mut utxos_changed = false;

        // Insert UTXOs for outputs paying to our addresses.
        for (vout, output) in tx.output.iter().enumerate() {
            let Ok(addr) = Address::from_script(&output.script_pubkey, self.network) else {
                continue;
            };
            if !involved_addrs.contains(&addr) {
                continue;
            }
            let outpoint = OutPoint {
                txid,
                vout: vout as u32,
            };

            // Out-of-order block processing: if a spending tx at a higher
            // height was processed before this creation, skip to avoid
            // resurrecting a dead UTXO.
            // TODO: timing issue in wallet rescan from storage; revisit.
            if self.is_outpoint_spent(&outpoint) {
                tracing::debug!(
                    outpoint = %outpoint,
                    "Skipping UTXO already spent by previously processed transaction"
                );
                continue;
            }

            let txout = dashcore::TxOut {
                value: output.value,
                script_pubkey: output.script_pubkey.clone(),
            };
            let block_height = context.block_info().map_or(0, |info| info.height);
            let mut utxo = Utxo::new(outpoint, txout, addr, block_height, tx.is_coin_base());
            utxo.is_confirmed = context.confirmed();
            utxo.is_instantlocked = matches!(context, TransactionContext::InstantSend(_));

            // Emit on state transition: either a new UTXO, or an existing
            // one whose `is_confirmed` / `is_instantlocked` flags flipped
            // (e.g. mempool → InBlock upgrade). Both reach the persister
            // so the on-disk row is upserted — otherwise replay sees a
            // stale Utxo.
            let needs_write = match self.utxos.get(&outpoint) {
                None => true,
                Some(existing) => {
                    existing.is_confirmed != utxo.is_confirmed
                        || existing.is_instantlocked != utxo.is_instantlocked
                }
            };
            if needs_write {
                cs.account_bucket(account_type_key).utxos_added.insert(outpoint, utxo.clone());
                self.utxos.insert(outpoint, utxo);
                utxos_changed = true;
            }
        }

        // Remove UTXOs spent by this transaction and track spent outpoints.
        for input in &tx.input {
            self.spent_outpoints.insert(input.previous_output);

            if self.utxos.remove(&input.previous_output).is_some() {
                tracing::debug!(
                    outpoint = %input.previous_output,
                    txid = %tx.txid(),
                    "Removed spent UTXO"
                );
                cs.account_bucket(account_type_key).utxos_spent.insert(input.previous_output);
                utxos_changed = true;
            }
        }

        if utxos_changed {
            self.monitor_revision += 1;
        }

        cs
    }

    /// Re-process an existing transaction with updated context (e.g., mempool→block confirmation)
    /// and potentially new address matches from gap limit rescans.
    ///
    /// Returns `(changed, cs)`:
    /// - `changed` is `true` iff the confirmation status transitioned from
    ///   unconfirmed → confirmed (not for InBlock → InChainLockedBlock).
    /// - `cs` carries any transaction context update and any UTXO delta from
    ///   `update_utxos`.
    pub(crate) fn confirm_transaction(
        &mut self,
        tx: &Transaction,
        account_match: &AccountMatch,
        context: TransactionContext,
        transaction_type: TransactionType,
    ) -> (bool, WalletChangeSet) {
        if !self.transactions.contains_key(&tx.txid()) {
            let (_record, cs) =
                self.record_transaction(tx, account_match, context, transaction_type);
            return (true, cs);
        }

        let mut changed = false;
        let mut cs = WalletChangeSet::default();
        if let Some(tx_record) = self.transactions.get_mut(&tx.txid()) {
            debug_assert_eq!(
                tx_record.transaction_type,
                transaction_type,
                "transaction_type changed between recordings for {}",
                tx.txid()
            );
            if tx_record.context != context {
                let was_confirmed = tx_record.context.confirmed();
                tx_record.update_context(context.clone());
                cs.account_bucket(self.account_type.to_account_type())
                    .transactions
                    .insert(tx.txid(), tx_record.clone());
                // Only signal a change when confirmation status actually changes,
                // not for upgrades within the confirmed state (e.g. InBlock → InChainLockedBlock).
                // TODO: emit a change event for InBlock → InChainLockedBlock once chainlock
                // wallet transaction events are properly handled
                changed = !was_confirmed;
            }
        }
        cs.merge(self.update_utxos(tx, account_match, context));
        (changed, cs)
    }

    /// Record a new transaction and update UTXOs for spendable account types.
    ///
    /// Returns `(record, cs)`:
    /// - `record` is the new [`TransactionRecord`] for caller-side reporting.
    ///   It is also present in
    ///   `cs.per_account[self.account_type.to_account_type()].transactions`.
    /// - `cs` carries both the transaction record insertion and any UTXO
    ///   delta from `update_utxos`.
    pub(crate) fn record_transaction(
        &mut self,
        tx: &Transaction,
        account_match: &AccountMatch,
        context: TransactionContext,
        transaction_type: TransactionType,
    ) -> (TransactionRecord, WalletChangeSet) {
        let net_amount = account_match.received as i64 - account_match.sent as i64;

        let receive_addrs: HashSet<_> = account_match
            .account_type_match
            .involved_receive_addresses()
            .iter()
            .map(|info| &info.address)
            .collect();
        let change_addrs: HashSet<_> = account_match
            .account_type_match
            .involved_change_addresses()
            .iter()
            .map(|info| &info.address)
            .collect();

        // Input details must be built before `update_utxos` removes spent UTXOs
        let mut input_details = Vec::new();
        if !tx.is_coin_base() {
            for (idx, input) in tx.input.iter().enumerate() {
                if let Some(utxo) = self.utxos.get(&input.previous_output) {
                    input_details.push(InputDetail {
                        index: idx as u32,
                        value: utxo.txout.value,
                        address: utxo.address.clone(),
                    });
                }
            }
        }

        // Use both UTXO-based input details and `account_match.sent` as signals
        // that we created this transaction. The UTXO set may be incomplete
        // (e.g., partial rescan) so `account_match.sent > 0` catches cases where
        // the transaction still spent our funds even without matching UTXOs.
        let has_inputs = !input_details.is_empty() || account_match.sent > 0;

        let resolved_outputs: Vec<Option<Address>> = tx
            .output
            .iter()
            .map(|output| Address::from_script(&output.script_pubkey, self.network).ok())
            .collect();

        // Build output details — annotate every output with its role
        let mut output_details = Vec::new();
        for (idx, output) in tx.output.iter().enumerate() {
            let role = match &resolved_outputs[idx] {
                Some(addr) if receive_addrs.contains(addr) => OutputRole::Received,
                Some(addr) if change_addrs.contains(addr) => OutputRole::Change,
                Some(_) if has_inputs => OutputRole::Sent,
                Some(_) => continue,
                None => {
                    if output.script_pubkey.is_provably_unspendable() {
                        OutputRole::Unspendable
                    } else if has_inputs {
                        OutputRole::Sent
                    } else {
                        continue;
                    }
                }
            };
            output_details.push(OutputDetail {
                index: idx as u32,
                role,
                address: resolved_outputs[idx].clone(),
                value: output.value,
            });
        }

        // Determine direction
        let has_sent = output_details.iter().any(|d| d.role == OutputRole::Sent);
        let has_our_outputs = output_details
            .iter()
            .any(|d| d.role == OutputRole::Received || d.role == OutputRole::Change);
        let direction = if transaction_type == TransactionType::CoinJoin {
            TransactionDirection::CoinJoin
        } else if !has_sent && has_inputs && has_our_outputs {
            TransactionDirection::Internal
        } else if has_inputs {
            TransactionDirection::Outgoing
        } else {
            TransactionDirection::Incoming
        };

        let tx_record = TransactionRecord::new(
            tx.clone(),
            context.clone(),
            transaction_type,
            direction,
            input_details,
            output_details,
            net_amount,
        );

        let txid = tx.txid();
        let mut cs = WalletChangeSet::default();
        cs.account_bucket(self.account_type.to_account_type())
            .transactions
            .insert(txid, tx_record.clone());
        self.transactions.insert(txid, tx_record.clone());
        cs.merge(self.update_utxos(tx, account_match, context));
        (tx_record, cs)
    }

    /// Mark all UTXOs belonging to a transaction as InstantSend-locked.
    ///
    /// Returns `(changed, cs)`:
    /// - `changed` is `true` iff at least one UTXO transitioned from
    ///   not-locked to locked.
    /// - `cs.per_account[self.account_type.to_account_type()].utxos_instant_locked`
    ///   contains the newly-locked outpoints.
    ///
    /// Note: this method only emits entries for UTXOs still present in
    /// `self.utxos`. If an outpoint has already been spent, it's no
    /// longer in the map, so no spurious `instant_locked` entry can be
    /// produced for a spent outpoint. This is why
    /// `ManagedCoreAccount::apply_changeset` can safely process
    /// `utxos_spent` before `utxos_instant_locked` without losing state.
    pub(crate) fn mark_utxos_instant_send(&mut self, txid: &Txid) -> (bool, WalletChangeSet) {
        let mut cs = WalletChangeSet::default();
        let account_type_key = self.account_type.to_account_type();
        let mut any_changed = false;
        for utxo in self.utxos.values_mut() {
            if utxo.outpoint.txid == *txid && !utxo.is_instantlocked {
                utxo.is_instantlocked = true;
                cs.account_bucket(account_type_key).utxos_instant_locked.insert(utxo.outpoint);
                any_changed = true;
            }
        }
        (any_changed, cs)
    }

    /// Update the stored [`TransactionContext`] on an existing transaction
    /// record and return a changeset describing the change.
    ///
    /// Idempotent: if the record does not exist, or its context already
    /// equals `new_context`, returns an empty [`WalletChangeSet`].
    /// Otherwise updates the record in place and emits it in
    /// `cs.per_account[self.account_type.to_account_type()].transactions`.
    pub(crate) fn update_transaction_context(
        &mut self,
        txid: &Txid,
        new_context: TransactionContext,
    ) -> WalletChangeSet {
        let mut cs = WalletChangeSet::default();
        if let Some(record) = self.transactions.get_mut(txid) {
            if record.context != new_context {
                record.update_context(new_context);
                cs.account_bucket(self.account_type.to_account_type())
                    .transactions
                    .insert(*txid, record.clone());
            }
        }
        cs
    }

    /// Return the UTXOs of this account for which
    /// [`Utxo::is_spendable`] holds at `synced_height`. See that method
    /// for the exact policy. Call this per-account rather than
    /// aggregating across the wallet, since spendability is
    /// account-type specific.
    pub fn spendable_utxos(&self, synced_height: u32) -> BTreeSet<&Utxo> {
        self.utxos.values().filter(|utxo| utxo.is_spendable(synced_height)).collect()
    }

    /// Recompute the account balance from its UTXO set.
    ///
    /// Mature, non-locked UTXOs land in either the `confirmed` bucket
    /// (in a block or InstantSend-locked) or the `unconfirmed` bucket
    /// (mempool only). Both are spendable per [`Utxo::is_spendable`];
    /// the split is only for display.
    ///
    /// Returns a [`WalletChangeSet`] carrying the signed balance delta
    /// between the new and old balance buckets. An empty changeset
    /// means the balance did not change.
    pub fn update_balance(&mut self, synced_height: u32) -> WalletChangeSet {
        let mut confirmed = 0u64;
        let mut unconfirmed = 0u64;
        let mut immature = 0u64;
        let mut locked = 0u64;
        for utxo in self.utxos.values() {
            let value = utxo.txout.value;
            if utxo.is_locked {
                locked += value;
            } else if !utxo.is_mature(synced_height) {
                immature += value;
            } else if utxo.is_confirmed || utxo.is_instantlocked {
                confirmed += value;
            } else {
                unconfirmed += value;
            }
        }

        let old = self.balance;
        let new = WalletCoreBalance::new(confirmed, unconfirmed, immature, locked);
        self.balance = new;
        self.metadata.last_used = Some(Self::current_timestamp());

        let bal = BalanceChangeSet {
            confirmed_delta: new.confirmed() as i64 - old.confirmed() as i64,
            unconfirmed_delta: new.unconfirmed() as i64 - old.unconfirmed() as i64,
            immature_delta: new.immature() as i64 - old.immature() as i64,
            locked_delta: new.locked() as i64 - old.locked() as i64,
        };
        let mut cs = WalletChangeSet::default();
        if !bal.is_empty() {
            cs.balance = Some(bal);
        }
        cs
    }

    /// Apply an [`AccountChangeSet`] to this account during restore.
    ///
    /// Idempotent: replaying the same changeset twice converges to the
    /// same state as applying it once. State-flag transitions on UTXOs
    /// (`is_confirmed`, `is_instantlocked`) are monotonic — true wins,
    /// false loses — so a stale persisted changeset can't downgrade
    /// in-memory state under a race.
    ///
    /// This method does not emit a new changeset. It's the inverse of
    /// the mutation methods on this type, called from
    /// [`crate::wallet::managed_wallet_info::ManagedWalletInfo::apply_changeset`]
    /// once a per-account bucket has been routed.
    ///
    /// `expected_account_type` is the `AccountType` key under which `cs`
    /// was stored in [`crate::changeset::WalletChangeSet::per_account`].
    /// Used only by a `debug_assert` that the caller routed the bucket
    /// to the correct account — a mismatch indicates a routing bug at
    /// the call site.
    pub fn apply_changeset(&mut self, expected_account_type: AccountType, cs: AccountChangeSet) {
        debug_assert_eq!(
            self.account_type.to_account_type(),
            expected_account_type,
            "apply_changeset called on the wrong account — routing bug"
        );
        // Destructure the changeset so every field is a fresh owned value
        // we can drain into the wallet maps. No clones — `Utxo` and
        // `TransactionRecord` (which contains a full `Transaction`) move
        // straight from the persisted blob into in-memory state.
        let AccountChangeSet {
            addresses_used,
            highest_used,
            utxos_added,
            utxos_spent,
            utxos_instant_locked,
            transactions,
        } = cs;

        // Addresses marked used — mark_address_used is idempotent.
        for address in addresses_used {
            let _ = self.account_type.mark_address_used(&address);
        }
        // Highest-used watermark per pool type — max-wins via the
        // pool's own `set_highest_used`.
        for pool in self.account_type.address_pools_mut() {
            if let Some(highest_used) = highest_used.get(&pool.pool_type).copied() {
                pool.set_highest_used(highest_used);
            }
        }
        // UTXO additions / upgrades. Monotonic state flags: true wins.
        // Move each `Utxo` directly into the map; if an entry already
        // exists at this outpoint, OR its existing flags into the
        // incoming UTXO before insertion (no clone of either side).
        for (outpoint, mut utxo) in utxos_added {
            if let Some(existing) = self.utxos.get(&outpoint) {
                utxo.is_confirmed |= existing.is_confirmed;
                utxo.is_instantlocked |= existing.is_instantlocked;
            }
            self.utxos.insert(outpoint, utxo);
        }
        // UTXO removals.
        for outpoint in utxos_spent {
            self.utxos.remove(&outpoint);
            self.spent_outpoints.insert(outpoint);
        }
        // UTXO instant-lock transitions. Only flips false → true; a
        // UTXO already spent (removed above) is silently skipped, which
        // is correct because we don't track IS state for spent outputs.
        for outpoint in utxos_instant_locked {
            if let Some(utxo) = self.utxos.get_mut(&outpoint) {
                utxo.is_instantlocked = true;
            }
        }
        // Transaction records. Last write wins per txid — apply is
        // idempotent because identical records insert over themselves.
        // Move each `TransactionRecord` (and its embedded `Transaction`)
        // directly from the changeset into the map.
        for (txid, record) in transactions {
            self.transactions.insert(txid, record);
        }
    }

    /// Get all addresses from all pools
    pub fn all_addresses(&self) -> Vec<Address> {
        self.account_type.all_addresses()
    }

    /// Check if an address belongs to this account
    pub fn contains_address(&self, address: &Address) -> bool {
        self.account_type.contains_address(address)
    }

    /// Check if a script pub key belongs to this account
    pub fn contains_script_pub_key(&self, script_pub_key: &ScriptBuf) -> bool {
        self.account_type.contains_script_pub_key(script_pub_key)
    }

    /// Get address info for a given address
    pub fn get_address_info(&self, address: &Address) -> Option<address_pool::AddressInfo> {
        self.account_type.get_address_info(address)
    }

    /// Generate the next receive address, persisting it into the external
    /// pool's state.
    ///
    /// If no xpub is provided, only returns a pre-generated unused address
    /// from the pool; if the pool needs to derive, this fails with
    /// `NoKeySource`.
    pub fn next_receive_address(
        &mut self,
        account_xpub: Option<&ExtendedPubKey>,
    ) -> Result<Address, &'static str> {
        if let ManagedAccountType::Standard {
            external_addresses,
            ..
        } = &mut self.account_type
        {
            let key_source = match account_xpub {
                Some(xpub) => address_pool::KeySource::Public(*xpub),
                None => address_pool::KeySource::NoKeySource,
            };

            let addr = external_addresses.next_unused(&key_source).map_err(|e| match e {
                crate::error::Error::NoKeySource => {
                    "No unused addresses available and no key source provided"
                }
                _ => "Failed to generate receive address",
            })?;
            self.monitor_revision += 1;
            Ok(addr)
        } else {
            Err("Cannot generate receive address for non-standard account type")
        }
    }

    /// Generate the next change address, persisting it into the internal
    /// pool's state.
    ///
    /// If no xpub is provided, only returns a pre-generated unused address
    /// from the pool; if the pool needs to derive, this fails with
    /// `NoKeySource`.
    pub fn next_change_address(
        &mut self,
        account_xpub: Option<&ExtendedPubKey>,
    ) -> Result<Address, &'static str> {
        if let ManagedAccountType::Standard {
            internal_addresses,
            ..
        } = &mut self.account_type
        {
            let key_source = match account_xpub {
                Some(xpub) => address_pool::KeySource::Public(*xpub),
                None => address_pool::KeySource::NoKeySource,
            };

            let addr = internal_addresses.next_unused(&key_source).map_err(|e| match e {
                crate::error::Error::NoKeySource => {
                    "No unused addresses available and no key source provided"
                }
                _ => "Failed to generate change address",
            })?;
            self.monitor_revision += 1;
            Ok(addr)
        } else {
            Err("Cannot generate change address for non-standard account type")
        }
    }

    /// Generate multiple receive addresses at once, persisting each into
    /// the external pool's state.
    ///
    /// More efficient than calling `next_receive_address` multiple times.
    /// If no xpub is provided, only returns pre-generated unused addresses.
    pub fn next_receive_addresses(
        &mut self,
        account_xpub: Option<&ExtendedPubKey>,
        count: usize,
    ) -> Result<Vec<Address>, String> {
        if let ManagedAccountType::Standard {
            external_addresses,
            ..
        } = &mut self.account_type
        {
            let key_source = match account_xpub {
                Some(xpub) => address_pool::KeySource::Public(*xpub),
                None => address_pool::KeySource::NoKeySource,
            };

            let addresses = external_addresses.next_unused_multiple(count, &key_source);
            if addresses.is_empty() && count > 0 {
                Err("Failed to generate any receive addresses".to_string())
            } else if addresses.len() < count
                && matches!(key_source, address_pool::KeySource::NoKeySource)
            {
                Err(format!(
                    "Could only generate {} out of {} requested addresses (no key source)",
                    addresses.len(),
                    count
                ))
            } else {
                Ok(addresses)
            }
        } else {
            Err("Cannot generate receive addresses for non-standard account type".to_string())
        }
    }

    /// Generate multiple change addresses at once, persisting each into
    /// the internal pool's state.
    ///
    /// More efficient than calling `next_change_address` multiple times.
    /// If no xpub is provided, only returns pre-generated unused addresses.
    pub fn next_change_addresses(
        &mut self,
        account_xpub: Option<&ExtendedPubKey>,
        count: usize,
    ) -> Result<Vec<Address>, String> {
        if let ManagedAccountType::Standard {
            internal_addresses,
            ..
        } = &mut self.account_type
        {
            let key_source = match account_xpub {
                Some(xpub) => address_pool::KeySource::Public(*xpub),
                None => address_pool::KeySource::NoKeySource,
            };

            let addresses = internal_addresses.next_unused_multiple(count, &key_source);
            if addresses.is_empty() && count > 0 {
                Err("Failed to generate any change addresses".to_string())
            } else if addresses.len() < count
                && matches!(key_source, address_pool::KeySource::NoKeySource)
            {
                Err(format!(
                    "Could only generate {} out of {} requested addresses (no key source)",
                    addresses.len(),
                    count
                ))
            } else {
                Ok(addresses)
            }
        } else {
            Err("Cannot generate change addresses for non-standard account type".to_string())
        }
    }

    /// Generate the next address for non-standard accounts, persisting
    /// it into the single pool's state.
    ///
    /// This method is for special accounts like Identity, Provider
    /// accounts, etc. Standard accounts (BIP44/BIP32) should use
    /// `next_receive_address` or `next_change_address`.
    pub fn next_address(
        &mut self,
        account_xpub: Option<&ExtendedPubKey>,
    ) -> Result<Address, &'static str> {
        match &mut self.account_type {
            ManagedAccountType::Standard {
                ..
            } => Err("Standard accounts must use next_receive_address or next_change_address"),
            ManagedAccountType::CoinJoin {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityRegistration {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityTopUpNotBoundToIdentity {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityInvitation {
                addresses,
                ..
            }
            | ManagedAccountType::AssetLockAddressTopUp {
                addresses,
                ..
            }
            | ManagedAccountType::AssetLockShieldedAddressTopUp {
                addresses,
                ..
            }
            | ManagedAccountType::ProviderVotingKeys {
                addresses,
                ..
            }
            | ManagedAccountType::ProviderOwnerKeys {
                addresses,
                ..
            }
            | ManagedAccountType::ProviderOperatorKeys {
                addresses,
                ..
            }
            | ManagedAccountType::ProviderPlatformKeys {
                addresses,
                ..
            }
            | ManagedAccountType::DashpayReceivingFunds {
                addresses,
                ..
            }
            | ManagedAccountType::DashpayExternalAccount {
                addresses,
                ..
            }
            | ManagedAccountType::PlatformPayment {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityAuthenticationEcdsa {
                addresses,
                ..
            } => {
                // Create appropriate key source based on whether xpub is provided
                let key_source = match account_xpub {
                    Some(xpub) => address_pool::KeySource::Public(*xpub),
                    None => address_pool::KeySource::NoKeySource,
                };

                addresses.next_unused(&key_source).map_err(|e| match e {
                    crate::error::Error::NoKeySource => {
                        "No unused addresses available and no key source provided"
                    }
                    _ => "Failed to generate address",
                })
            }
            ManagedAccountType::IdentityAuthenticationBls {
                addresses,
                ..
            } => {
                // `account_xpub` is an ECDSA extended pubkey and is useless for a
                // BLS key pool. Callers that need to generate BLS identity-auth
                // addresses must go through a dedicated BLS-aware API path
                // (similar to `next_bls_operator_key` for ProviderOperatorKeys).
                // Here we only allow progression when the pool already has a
                // pre-derived address cached (NoKeySource).
                addresses.next_unused(&address_pool::KeySource::NoKeySource).map_err(|e| match e {
                    crate::error::Error::NoKeySource => {
                        "No unused addresses available and no key source provided"
                    }
                    _ => "Failed to generate address",
                })
            }
            ManagedAccountType::IdentityTopUp {
                addresses,
                ..
            } => {
                // Identity top-up has an address pool
                let key_source = match account_xpub {
                    Some(xpub) => address_pool::KeySource::Public(*xpub),
                    None => address_pool::KeySource::NoKeySource,
                };

                addresses.next_unused(&key_source).map_err(|e| match e {
                    crate::error::Error::NoKeySource => {
                        "No unused addresses available and no key source provided"
                    }
                    _ => "Failed to generate address",
                })
            }
        }
    }

    /// Generate the next address with full info for non-standard
    /// accounts, persisting it into the single pool's state.
    ///
    /// This method is for special accounts like Identity, Provider
    /// accounts, etc. Standard accounts (BIP44/BIP32) should use
    /// `next_receive_address_with_info` or `next_change_address_with_info`.
    pub fn next_address_with_info(
        &mut self,
        account_xpub: Option<&ExtendedPubKey>,
    ) -> Result<address_pool::AddressInfo, &'static str> {
        match &mut self.account_type {
            ManagedAccountType::Standard {
                ..
            } => Err("Standard accounts must use next_receive_address_with_info or next_change_address_with_info"),
            ManagedAccountType::CoinJoin {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityRegistration {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityTopUpNotBoundToIdentity {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityInvitation {
                addresses,
                ..
            }
            | ManagedAccountType::AssetLockAddressTopUp {
                addresses,
                ..
            }
            | ManagedAccountType::AssetLockShieldedAddressTopUp {
                addresses,
                ..
            }
            | ManagedAccountType::ProviderVotingKeys {
                addresses,
                ..
            }
            | ManagedAccountType::ProviderOwnerKeys {
                addresses,
                ..
            }
            | ManagedAccountType::ProviderOperatorKeys {
                addresses,
                ..
            }
            | ManagedAccountType::ProviderPlatformKeys {
                addresses,
                ..
            }
            | ManagedAccountType::DashpayReceivingFunds {
                addresses,
                ..
            }
            | ManagedAccountType::DashpayExternalAccount {
                addresses,
                ..
            }
            | ManagedAccountType::PlatformPayment {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityAuthenticationEcdsa {
                addresses,
                ..
            } => {
                // Create appropriate key source based on whether xpub is provided
                let key_source = match account_xpub {
                    Some(xpub) => address_pool::KeySource::Public(*xpub),
                    None => address_pool::KeySource::NoKeySource,
                };

                addresses.next_unused_with_info(&key_source).map_err(|e| match e {
                    crate::error::Error::NoKeySource => {
                        "No unused addresses available and no key source provided"
                    }
                    _ => "Failed to generate address with info",
                })
            }
            ManagedAccountType::IdentityAuthenticationBls {
                addresses,
                ..
            } => {
                // `account_xpub` is an ECDSA extended pubkey and is useless for a
                // BLS key pool. Callers that need to generate BLS identity-auth
                // addresses must go through a dedicated BLS-aware API path
                // (similar to `next_bls_operator_key` for ProviderOperatorKeys).
                // Here we only allow progression when the pool already has a
                // pre-derived address cached (NoKeySource).
                addresses
                    .next_unused_with_info(&address_pool::KeySource::NoKeySource)
                    .map_err(|e| match e {
                        crate::error::Error::NoKeySource => {
                            "No unused addresses available and no key source provided"
                        }
                        _ => "Failed to generate address with info",
                    })
            }
            ManagedAccountType::IdentityTopUp {
                addresses,
                ..
            } => {
                // Identity top-up has an address pool
                let key_source = match account_xpub {
                    Some(xpub) => address_pool::KeySource::Public(*xpub),
                    None => address_pool::KeySource::NoKeySource,
                };

                addresses.next_unused_with_info(&key_source).map_err(|e| match e {
                    crate::error::Error::NoKeySource => {
                        "No unused addresses available and no key source provided"
                    }
                    _ => "Failed to generate address with info",
                })
            }
        }
    }

    /// Generate the next BLS operator key (only for ProviderOperatorKeys accounts)
    /// Returns the BLS public key at the next unused index
    #[cfg(feature = "bls")]
    pub fn next_bls_operator_key(
        &mut self,
        account_xpub: Option<ExtendedBLSPubKey>,
    ) -> Result<dashcore::blsful::PublicKey<dashcore::blsful::Bls12381G2Impl>, &'static str> {
        match &mut self.account_type {
            ManagedAccountType::ProviderOperatorKeys {
                addresses,
                ..
            } => {
                // Create key source from the optional BLS public key
                let key_source = match account_xpub {
                    Some(xpub) => address_pool::KeySource::BLSPublic(xpub),
                    None => address_pool::KeySource::NoKeySource,
                };

                // Use next_unused_with_info to get the next address (handles caching and derivation)
                let info = addresses
                    .next_unused_with_info(&key_source)
                    .map_err(|_| "Failed to get next unused address")?;

                // Extract the BLS public key from the address info
                let Some(PublicKeyType::BLS(pub_key_bytes)) = info.public_key else {
                    return Err("Expected BLS public key but got different key type");
                };

                // Mark as used
                addresses.mark_index_used(info.index);

                // Convert bytes to BLS public key
                use dashcore::blsful::{Bls12381G2Impl, PublicKey, SerializationFormat};
                let public_key = PublicKey::<Bls12381G2Impl>::from_bytes_with_mode(
                    &pub_key_bytes,
                    SerializationFormat::Modern,
                )
                .map_err(|_| "Failed to deserialize BLS public key")?;

                Ok(public_key)
            }
            _ => Err("This method only works for ProviderOperatorKeys accounts"),
        }
    }

    /// Generate the next EdDSA platform key (only for ProviderPlatformKeys accounts)
    /// Returns the Ed25519 public key and address info at the next unused index
    #[cfg(feature = "eddsa")]
    pub fn next_eddsa_platform_key(
        &mut self,
        account_xpriv: crate::derivation_slip10::ExtendedEd25519PrivKey,
    ) -> Result<(crate::derivation_slip10::VerifyingKey, AddressInfo), &'static str> {
        match &mut self.account_type {
            ManagedAccountType::ProviderPlatformKeys {
                addresses,
                ..
            } => {
                // Create key source from the EdDSA private key
                let key_source = address_pool::KeySource::EdDSAPrivate(account_xpriv);

                // Use next_unused_with_info to get the next address (handles caching and derivation)
                let info = addresses
                    .next_unused_with_info(&key_source)
                    .map_err(|_| "Failed to get next unused address")?;

                // Extract the EdDSA public key from the address info
                let Some(PublicKeyType::EdDSA(pub_key_bytes)) = info.public_key.clone() else {
                    return Err("Expected EdDSA public key but got different key type");
                };

                // Mark as used
                addresses.mark_index_used(info.index);

                let verifying_key = crate::derivation_slip10::VerifyingKey::from_bytes(
                    &pub_key_bytes.try_into().map_err(|_| "Invalid EdDSA public key length")?,
                )
                .map_err(|_| "Failed to deserialize EdDSA public key")?;

                Ok((verifying_key, info))
            }
            _ => Err("This method only works for ProviderPlatformKeys accounts"),
        }
    }

    /// Consume the next unused address and derive its private key.
    ///
    /// Used for one-time keys (asset lock funding, identity registration, etc.).
    /// The address is marked as used so subsequent calls return fresh keys.
    ///
    /// Only works for single-pool account types (not Standard accounts).
    pub fn next_private_key(
        &mut self,
        root_xpriv: &crate::wallet::root_extended_keys::RootExtendedPrivKey,
        network: Network,
    ) -> Result<[u8; 32], &'static str> {
        if matches!(self.account_type, ManagedAccountType::Standard { .. }) {
            return Err("Standard accounts must use next_receive_address or next_change_address");
        }

        let mut pools = self.account_type.address_pools_mut();
        let pool = pools.first_mut().ok_or("Account has no address pool")?;

        let info = pool
            .next_unused_with_info(&address_pool::KeySource::NoKeySource)
            .map_err(|_| "No unused address available")?;

        pool.mark_index_used(info.index);

        let secp = secp256k1::Secp256k1::new();
        let root_ext_priv = root_xpriv.to_extended_priv_key(network);
        let derived_xpriv =
            root_ext_priv.derive_priv(&secp, &info.path).map_err(|_| "Key derivation failed")?;

        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&derived_xpriv.private_key[..]);
        Ok(private_key)
    }

    /// Peek at the next unused address's path and index **without** marking
    /// the index used.
    ///
    /// Intended for two-phase flows where path consumption must not commit
    /// until an external operation (e.g. an async signer request) has
    /// succeeded. Pair with [`Self::mark_first_pool_index_used`] to
    /// commit, or drop the result to leave the pool untouched. Calling
    /// `peek_next_path` twice without committing in between returns the
    /// same `(path, index)`.
    ///
    /// Only works for single-pool account types (not Standard accounts).
    pub fn peek_next_path(&mut self) -> Result<(crate::DerivationPath, u32), &'static str> {
        if matches!(self.account_type, ManagedAccountType::Standard { .. }) {
            return Err("Standard accounts must use next_receive_address or next_change_address");
        }

        let mut pools = self.account_type.address_pools_mut();
        let pool = pools.first_mut().ok_or("Account has no address pool")?;

        let info = pool
            .next_unused_with_info(&address_pool::KeySource::NoKeySource)
            .map_err(|_| "No unused address available")?;

        Ok((info.path, info.index))
    }

    /// Mark an index on the account's first address pool as used.
    ///
    /// Commits what [`Self::peek_next_path`] returned. Accepts any index —
    /// callers are responsible for passing back the index they peeked, not
    /// an arbitrary one.
    ///
    /// Only works for single-pool account types (not Standard accounts).
    pub fn mark_first_pool_index_used(&mut self, index: u32) -> Result<(), &'static str> {
        if matches!(self.account_type, ManagedAccountType::Standard { .. }) {
            return Err("Standard accounts must use next_receive_address or next_change_address");
        }

        let mut pools = self.account_type.address_pools_mut();
        let pool = pools.first_mut().ok_or("Account has no address pool")?;
        pool.mark_index_used(index);
        Ok(())
    }

    /// Consume the next unused address and return only its derivation path.
    ///
    /// Analogous to [`Self::next_private_key`] but does not require any
    /// root extended private key: used when signing is delegated to an
    /// external [`Signer`](crate::signer::Signer), which holds the keys
    /// and only needs the path to produce signatures or public keys.
    ///
    /// Consumes the index immediately; callers that need to defer the
    /// commit until after an external operation succeeds should use
    /// [`Self::peek_next_path`] + [`Self::mark_first_pool_index_used`]
    /// instead.
    ///
    /// Only works for single-pool account types (not Standard accounts).
    pub fn next_path(&mut self) -> Result<crate::DerivationPath, &'static str> {
        let (path, index) = self.peek_next_path()?;
        self.mark_first_pool_index_used(index)?;
        Ok(path)
    }

    /// Get the derivation path for an address if it belongs to this account
    pub fn address_derivation_path(&self, address: &Address) -> Option<crate::DerivationPath> {
        self.account_type.get_address_derivation_path(address)
    }

    /// Get the current timestamp (for metadata)
    pub fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Get total address count across all pools
    pub fn total_address_count(&self) -> usize {
        self.account_type
            .address_pools()
            .iter()
            .map(|pool| pool.stats().total_generated as usize)
            .sum()
    }

    /// Get used address count across all pools
    pub fn used_address_count(&self) -> usize {
        self.account_type.address_pools().iter().map(|pool| pool.stats().used_count as usize).sum()
    }

    /// Get the external gap limit for standard accounts
    pub fn external_gap_limit(&self) -> Option<u32> {
        match &self.account_type {
            ManagedAccountType::Standard {
                external_addresses,
                ..
            } => Some(external_addresses.gap_limit),
            _ => None,
        }
    }

    /// Get the internal gap limit for standard accounts
    pub fn internal_gap_limit(&self) -> Option<u32> {
        match &self.account_type {
            ManagedAccountType::Standard {
                internal_addresses,
                ..
            } => Some(internal_addresses.gap_limit),
            _ => None,
        }
    }

    /// Get the gap limit for non-standard (single-pool) accounts
    pub fn gap_limit(&self) -> Option<u32> {
        match &self.account_type {
            ManagedAccountType::Standard {
                ..
            } => None,
            ManagedAccountType::CoinJoin {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityRegistration {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityTopUp {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityTopUpNotBoundToIdentity {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityInvitation {
                addresses,
                ..
            }
            | ManagedAccountType::AssetLockAddressTopUp {
                addresses,
                ..
            }
            | ManagedAccountType::AssetLockShieldedAddressTopUp {
                addresses,
                ..
            }
            | ManagedAccountType::ProviderVotingKeys {
                addresses,
                ..
            }
            | ManagedAccountType::ProviderOwnerKeys {
                addresses,
                ..
            }
            | ManagedAccountType::ProviderOperatorKeys {
                addresses,
                ..
            }
            | ManagedAccountType::ProviderPlatformKeys {
                addresses,
                ..
            }
            | ManagedAccountType::DashpayReceivingFunds {
                addresses,
                ..
            }
            | ManagedAccountType::DashpayExternalAccount {
                addresses,
                ..
            }
            | ManagedAccountType::PlatformPayment {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityAuthenticationEcdsa {
                addresses,
                ..
            }
            | ManagedAccountType::IdentityAuthenticationBls {
                addresses,
                ..
            } => Some(addresses.gap_limit),
        }
    }

    /// Idempotent UTXO insert. Returns true if this is a new UTXO, false if
    /// an entry already existed for this outpoint (in which case the old
    /// value is replaced). Used by `apply(changeset)` to route UTXO additions
    /// from a persisted changeset back into the account state.
    pub fn insert_utxo(&mut self, outpoint: OutPoint, utxo: Utxo) -> bool {
        self.utxos.insert(outpoint, utxo).is_none()
    }

    /// Idempotent UTXO remove. Returns the removed UTXO if it was present,
    /// or `None` if the outpoint wasn't in this account. Used by
    /// `apply(changeset)` to route UTXO spends.
    pub fn remove_utxo(&mut self, outpoint: &OutPoint) -> Option<Utxo> {
        self.utxos.remove(outpoint)
    }
}

impl ManagedAccountTrait for ManagedCoreAccount {
    fn account_type(&self) -> &ManagedAccountType {
        &self.account_type
    }

    fn account_type_mut(&mut self) -> &mut ManagedAccountType {
        &mut self.account_type
    }

    fn network(&self) -> Network {
        self.network
    }

    fn metadata(&self) -> &AccountMetadata {
        &self.metadata
    }

    fn metadata_mut(&mut self) -> &mut AccountMetadata {
        &mut self.metadata
    }

    fn is_watch_only(&self) -> bool {
        self.is_watch_only
    }

    fn balance(&self) -> &WalletCoreBalance {
        &self.balance
    }

    fn balance_mut(&mut self) -> &mut WalletCoreBalance {
        &mut self.balance
    }

    fn transactions(&self) -> &BTreeMap<Txid, TransactionRecord> {
        &self.transactions
    }

    fn transactions_mut(&mut self) -> &mut BTreeMap<Txid, TransactionRecord> {
        &mut self.transactions
    }

    fn utxos(&self) -> &BTreeMap<OutPoint, Utxo> {
        &self.utxos
    }

    fn utxos_mut(&mut self) -> &mut BTreeMap<OutPoint, Utxo> {
        &mut self.utxos
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for ManagedCoreAccount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            account_type: ManagedAccountType,
            network: Network,
            metadata: AccountMetadata,
            is_watch_only: bool,
            balance: WalletCoreBalance,
            transactions: BTreeMap<Txid, TransactionRecord>,
            utxos: BTreeMap<OutPoint, Utxo>,
        }

        let helper = Helper::deserialize(deserializer)?;

        let spent_outpoints = helper
            .transactions
            .values()
            .flat_map(|record| &record.transaction.input)
            .map(|input| input.previous_output)
            .collect();

        Ok(ManagedCoreAccount {
            account_type: helper.account_type,
            network: helper.network,
            metadata: helper.metadata,
            is_watch_only: helper.is_watch_only,
            balance: helper.balance,
            transactions: helper.transactions,
            utxos: helper.utxos,
            spent_outpoints,
            monitor_revision: 0,
        })
    }
}
