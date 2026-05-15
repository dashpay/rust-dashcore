//! Managed core funds account: keys-account state plus balance, UTXOs, and spent outpoints.
//!
//! Composed of an inner [`ManagedCoreKeysAccount`] (which carries the address
//! pools, transactions, network, and monitor revision) plus the funds-specific
//! bookkeeping needed for accounts that hold and spend Dash directly
//! (Standard, CoinJoin, DashPay).
//!
//! Shared address-pool / key-derivation behavior is provided by
//! [`ManagedAccountTrait`] default methods; only the funds-specific pieces
//! (balance, UTXO updates, transaction recording, the Standard-account
//! receive/change paths) live here as inherent methods.

#[cfg(feature = "bls")]
use crate::account::BLSAccount;
#[cfg(feature = "eddsa")]
use crate::account::EdDSAAccount;
use crate::account::TransactionRecord;
use crate::managed_account::address_pool;
use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::managed_account::managed_account_type::ManagedAccountType;
use crate::managed_account::managed_core_keys_account::ManagedCoreKeysAccount;
use crate::managed_account::transaction_record::{
    InputDetail, OutputDetail, OutputRole, TransactionDirection,
};
use crate::transaction_checking::transaction_router::TransactionType;
use crate::transaction_checking::{AccountMatch, TransactionContext};
use crate::utxo::Utxo;
use crate::wallet::balance::WalletCoreBalance;
use crate::{ExtendedPubKey, Network};
use dashcore::blockdata::transaction::OutPoint;
use dashcore::prelude::CoreBlockHeight;
use dashcore::{Address, Transaction, Txid};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::{BTreeSet, HashSet};

/// Managed core funds account with mutable state including balance and UTXOs.
///
/// Wraps a [`ManagedCoreKeysAccount`] (the shared address-pool / transaction
/// state) and adds the funds-specific bookkeeping used by accounts that hold
/// and spend Dash directly (Standard, CoinJoin, DashPay).
///
/// Most read/write surface comes from [`ManagedAccountTrait`] default methods
/// — which delegate to the inner keys account via the primitive accessors —
/// so this struct only carries the funds-specific inherent methods (transaction
/// recording, the Standard-account receive/change paths, etc.). The
/// funds-specific state (`balance`, `utxos`) is reachable as a public field
/// directly.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ManagedCoreFundsAccount {
    /// Shared keys-account state (address pools, transactions, network,
    /// monitor revision).
    keys: ManagedCoreKeysAccount,
    /// Account balance information
    pub balance: WalletCoreBalance,
    /// UTXO set for this account
    pub utxos: BTreeMap<OutPoint, Utxo>,
    /// Outpoints spent by recorded transactions.
    /// Rebuilt from `transactions` during deserialization.
    #[cfg_attr(feature = "serde", serde(skip_serializing))]
    spent_outpoints: HashSet<OutPoint>,
}

impl ManagedCoreFundsAccount {
    /// Create a new managed funds account
    pub fn new(managed_account_type: ManagedAccountType, network: Network) -> Self {
        Self {
            keys: ManagedCoreKeysAccount::new(managed_account_type, network),
            balance: WalletCoreBalance::default(),
            utxos: BTreeMap::new(),
            spent_outpoints: HashSet::new(),
        }
    }

    /// Create a `ManagedCoreFundsAccount` from an [`Account`](super::super::Account).
    pub fn from_account(account: &super::super::Account) -> Self {
        Self::wrap(ManagedCoreKeysAccount::from_account(account))
    }

    /// Create a `ManagedCoreFundsAccount` from a [`BLSAccount`].
    #[cfg(feature = "bls")]
    pub fn from_bls_account(account: &BLSAccount) -> Self {
        Self::wrap(ManagedCoreKeysAccount::from_bls_account(account))
    }

    /// Create a `ManagedCoreFundsAccount` from an [`EdDSAAccount`].
    #[cfg(feature = "eddsa")]
    pub fn from_eddsa_account(account: &EdDSAAccount) -> Self {
        Self::wrap(ManagedCoreKeysAccount::from_eddsa_account(account))
    }

    fn wrap(keys: ManagedCoreKeysAccount) -> Self {
        Self {
            keys,
            balance: WalletCoreBalance::default(),
            utxos: BTreeMap::new(),
            spent_outpoints: HashSet::new(),
        }
    }

    /// Get a reference to the inner keys-account state.
    pub fn keys(&self) -> &ManagedCoreKeysAccount {
        &self.keys
    }

    /// Get a mutable reference to the inner keys-account state.
    pub fn keys_mut(&mut self) -> &mut ManagedCoreKeysAccount {
        &mut self.keys
    }

    /// Check if an outpoint was spent by a previously recorded transaction.
    fn is_outpoint_spent(&self, outpoint: &OutPoint) -> bool {
        self.spent_outpoints.contains(outpoint)
    }

    /// Add new UTXOs for received outputs, remove spent ones.
    fn update_utxos(
        &mut self,
        tx: &Transaction,
        account_match: &AccountMatch,
        context: TransactionContext,
    ) {
        // Update UTXOs only for spendable account types
        match self.keys.managed_account_type() {
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
            } => {
                let involved_addrs: BTreeSet<_> = account_match
                    .account_type_match
                    .all_involved_addresses()
                    .iter()
                    .map(|info| info.address.clone())
                    .collect();
                let change_addrs: BTreeSet<_> = account_match
                    .account_type_match
                    .involved_change_addresses()
                    .iter()
                    .map(|info| info.address.clone())
                    .collect();

                // Detect a self-send: this account owns at least one input being
                // spent. `account_match.sent` is computed by matching inputs against
                // this account's UTXO set, so a non-zero value means we owned at
                // least one of the spent outpoints.
                let has_owned_input = account_match.sent > 0;

                let txid = tx.txid();
                let mut utxos_changed = false;

                let network = self.keys.network();

                // Insert UTXOs for outputs paying to our addresses
                for (vout, output) in tx.output.iter().enumerate() {
                    if let Ok(addr) = Address::from_script(&output.script_pubkey, network) {
                        if involved_addrs.contains(&addr) {
                            let outpoint = OutPoint {
                                txid,
                                vout: vout as u32,
                            };

                            // Check if this outpoint was already spent by a transaction we've seen.
                            // This handles out-of-order block processing during rescan where a
                            // spending transaction at a higher height may be processed before
                            // the transaction that created the UTXO.
                            // TODO: This is mostly needed for wallet rescan from storage with the
                            //       there is a timing issue with event processing which might lead to
                            //       invalid UTXO set / balances. There might be a way around it.
                            if self.is_outpoint_spent(&outpoint) {
                                tracing::debug!(
                                    outpoint = %outpoint,
                                    "Skipping UTXO already spent by previously processed transaction"
                                );
                                continue;
                            }

                            // Flag outputs from a "trusted" mempool transaction we created —
                            // one that spends at least one of our own UTXOs and pays this
                            // output back to one of our internal (change) addresses. Such
                            // an output is just our previously-tracked funds returning, so
                            // `update_balance` credits it to the confirmed bucket even
                            // before the parent transaction settles.
                            let is_trusted_output = has_owned_input && change_addrs.contains(&addr);
                            let txout = dashcore::TxOut {
                                value: output.value,
                                script_pubkey: output.script_pubkey.clone(),
                            };
                            let block_height = context.block_info().map_or(0, |info| info.height);
                            let mut utxo =
                                Utxo::new(outpoint, txout, addr, block_height, tx.is_coin_base());
                            utxo.is_confirmed = context.confirmed();
                            utxo.is_instantlocked =
                                matches!(context, TransactionContext::InstantSend(_));
                            utxo.is_trusted = is_trusted_output;
                            self.utxos.insert(outpoint, utxo);
                            utxos_changed = true;
                        }
                    }
                }

                // Remove UTXOs spent by this transaction and track spent outpoints
                for input in &tx.input {
                    self.spent_outpoints.insert(input.previous_output);

                    if self.utxos.remove(&input.previous_output).is_some() {
                        tracing::debug!(
                            outpoint = %input.previous_output,
                            txid = %tx.txid(),
                            "Removed spent UTXO"
                        );
                        utxos_changed = true;
                    }
                }

                if utxos_changed {
                    self.keys.bump_monitor_revision();
                }
            }
            _ => {}
        }
    }

    /// Re-process an existing transaction with updated context (e.g.,
    /// mempool→block confirmation) and potentially new address matches
    /// from gap limit rescans.
    ///
    /// Returns `Some(record)` when the call results in a state change the
    /// caller should surface (record newly inserted or context updated).
    /// The record is cloned BEFORE any chainlock-driven pruning, so the
    /// caller can always include it in an event even when the
    /// `keep-finalized-transactions` Cargo feature is off and the record
    /// is dropped from `transactions` immediately after.
    ///
    /// Returns `None` when:
    /// - the tx is already finalized in a chainlocked block (record is
    ///   immutable; further events are redundant), or
    /// - the existing record's context already matches and confirmation
    ///   status didn't change.
    pub(crate) fn confirm_transaction(
        &mut self,
        tx: &Transaction,
        account_match: &AccountMatch,
        context: TransactionContext,
        transaction_type: TransactionType,
    ) -> Option<TransactionRecord> {
        let txid = tx.txid();

        // Already finalized via a chainlock: the tx is immutable —
        // no record update, no UTXO refresh, no event needed.
        if self.keys.transaction_is_finalized(&txid) {
            return None;
        }

        if !self.keys.has_transaction(&txid) {
            // Genuinely new sighting — delegate to record_transaction
            // (which handles finalize-on-record itself).
            let record = self.record_transaction(tx, account_match, context, transaction_type);
            return Some(record);
        }

        let mut changed = false;
        if let Some(tx_record) = self.keys.transactions_mut().get_mut(&txid) {
            debug_assert_eq!(
                tx_record.transaction_type,
                transaction_type,
                "transaction_type changed between recordings for {}",
                tx.txid()
            );
            if tx_record.context != context {
                let was_confirmed = tx_record.context.confirmed();
                tx_record.update_context(context.clone());
                // Confirm-time upgrades within the confirmed state (e.g.
                // InBlock → InChainLockedBlock) are not signaled here.
                // Chainlock-driven promotions go through the dedicated
                // `apply_chain_lock` path which emits a single batched
                // ChainLockProcessed event.
                changed = !was_confirmed;
            }
        }

        // Capture the (possibly updated) record before any pruning so the
        // caller can still emit it in an event.
        let record_after = if changed {
            self.keys.transactions().get(&txid).cloned()
        } else {
            None
        };

        // The chainlock is the trigger for dropping the full record under
        // the default feature configuration; an IS-lock alone is *not*
        // enough — we keep the record so the surrounding block
        // confirmation can still write its height / block hash before the
        // chainlock catches up.
        #[cfg(not(feature = "keep-finalized-transactions"))]
        let drop_now = context.is_chain_locked();
        self.update_utxos(tx, account_match, context);
        #[cfg(not(feature = "keep-finalized-transactions"))]
        if drop_now {
            self.keys.drop_finalized_transaction(&txid);
        }
        record_after
    }

    /// Record a new transaction and update UTXOs for spendable account types
    pub(crate) fn record_transaction(
        &mut self,
        tx: &Transaction,
        account_match: &AccountMatch,
        context: TransactionContext,
        transaction_type: TransactionType,
    ) -> TransactionRecord {
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

        let network = self.keys.network();
        let resolved_outputs: Vec<Option<Address>> = tx
            .output
            .iter()
            .map(|output| Address::from_script(&output.script_pubkey, network).ok())
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
            self.keys.managed_account_type().to_account_type(),
            context.clone(),
            transaction_type,
            direction,
            input_details,
            output_details,
            net_amount,
        );

        let record = tx_record.clone();
        let txid = tx.txid();
        self.keys.transactions_mut().insert(txid, tx_record);

        // If the very first sighting is already chainlocked (e.g.
        // a wallet rescan from storage), drop the full record now and
        // keep only the txid in `finalized_txids`. No-op when the
        // feature is on (we want to keep the full record).
        #[cfg(not(feature = "keep-finalized-transactions"))]
        let drop_now = context.is_chain_locked();
        self.update_utxos(tx, account_match, context);
        #[cfg(not(feature = "keep-finalized-transactions"))]
        if drop_now {
            self.keys.drop_finalized_transaction(&txid);
        }

        record
    }

    /// Mark all UTXOs belonging to a transaction as InstantSend-locked.
    /// Returns `true` if any UTXO was newly marked.
    pub(crate) fn mark_utxos_instant_send(&mut self, txid: &Txid) -> bool {
        let mut any_changed = false;
        for utxo in self.utxos.values_mut() {
            if utxo.outpoint.txid == *txid && !utxo.is_instantlocked {
                utxo.is_instantlocked = true;
                any_changed = true;
            }
        }
        any_changed
    }

    /// Return the UTXOs of this account for which
    /// [`Utxo::is_spendable`] holds at `last_processed_height`. See that method
    /// for the exact policy. Call this per-account rather than
    /// aggregating across the wallet, since spendability is
    /// account-type specific.
    pub fn spendable_utxos(&self, last_processed_height: u32) -> BTreeSet<&Utxo> {
        self.utxos.values().filter(|utxo| utxo.is_spendable(last_processed_height)).collect()
    }

    /// Promote any `InBlock` records at height `<= cl_height` to
    /// [`TransactionContext::InChainLockedBlock`] and return the
    /// promoted txids.
    ///
    /// Delegates the per-record promotion to
    /// [`ManagedCoreKeysAccount::apply_chain_lock`] (which under the
    /// default `keep-finalized-transactions=OFF` feature drops the
    /// full records and retains only txids). UTXO state and account
    /// balance are unaffected: a chainlock does not change a UTXO's
    /// spentness or maturity, only the certainty of its parent
    /// transaction.
    pub(crate) fn apply_chain_lock(&mut self, cl_height: CoreBlockHeight) -> Vec<Txid> {
        self.keys.apply_chain_lock(cl_height)
    }

    /// Update the account balance.
    ///
    /// Mature, non-locked UTXOs land in either the `confirmed` bucket
    /// (in a block, InstantSend-locked, or trusted mempool change) or
    /// the `unconfirmed` bucket (untrusted mempool only). Trusted
    /// mempool change is surfaced as confirmed because it is just our
    /// previously-tracked funds returning, see [`Utxo::is_trusted`].
    /// Both buckets are spendable per [`Utxo::is_spendable`]. The split
    /// is only for display.
    pub fn update_balance(&mut self, last_processed_height: u32) {
        let mut confirmed = 0;
        let mut unconfirmed = 0;
        let mut immature = 0;
        let mut locked = 0;
        for utxo in self.utxos.values() {
            let value = utxo.txout.value;
            if utxo.is_locked {
                locked += value;
            } else if !utxo.is_mature(last_processed_height) {
                immature += value;
            } else if utxo.is_confirmed || utxo.is_instantlocked || utxo.is_trusted {
                confirmed += value;
            } else {
                unconfirmed += value;
            }
        }
        self.balance = WalletCoreBalance::new(confirmed, unconfirmed, immature, locked);
    }

    /// Generate the next receive address using the optionally provided extended public key
    /// If no key is provided, can only return pre-generated unused addresses.
    /// Only valid for Standard accounts.
    pub fn next_receive_address(
        &mut self,
        account_xpub: Option<&ExtendedPubKey>,
        add_to_state: bool,
    ) -> Result<Address, &'static str> {
        if let ManagedAccountType::Standard {
            external_addresses,
            ..
        } = self.keys.managed_account_type_mut()
        {
            let key_source = match account_xpub {
                Some(xpub) => address_pool::KeySource::Public(*xpub),
                None => address_pool::KeySource::NoKeySource,
            };

            let addr =
                external_addresses.next_unused(&key_source, add_to_state).map_err(|e| match e {
                    crate::error::Error::NoKeySource => {
                        "No unused addresses available and no key source provided"
                    }
                    _ => "Failed to generate receive address",
                })?;
            self.keys.bump_monitor_revision();
            Ok(addr)
        } else {
            Err("Cannot generate receive address for non-standard account type")
        }
    }

    /// Generate the next change address using the optionally provided extended public key.
    /// Only valid for Standard accounts.
    pub fn next_change_address(
        &mut self,
        account_xpub: Option<&ExtendedPubKey>,
        add_to_state: bool,
    ) -> Result<Address, &'static str> {
        if let ManagedAccountType::Standard {
            internal_addresses,
            ..
        } = self.keys.managed_account_type_mut()
        {
            let key_source = match account_xpub {
                Some(xpub) => address_pool::KeySource::Public(*xpub),
                None => address_pool::KeySource::NoKeySource,
            };

            let addr =
                internal_addresses.next_unused(&key_source, add_to_state).map_err(|e| match e {
                    crate::error::Error::NoKeySource => {
                        "No unused addresses available and no key source provided"
                    }
                    _ => "Failed to generate change address",
                })?;
            self.keys.bump_monitor_revision();
            Ok(addr)
        } else {
            Err("Cannot generate change address for non-standard account type")
        }
    }

    /// Generate multiple receive addresses at once using the optionally provided extended public key.
    /// Only valid for Standard accounts.
    pub fn next_receive_addresses(
        &mut self,
        account_xpub: Option<&ExtendedPubKey>,
        count: usize,
        add_to_state: bool,
    ) -> Result<Vec<Address>, String> {
        if let ManagedAccountType::Standard {
            external_addresses,
            ..
        } = self.keys.managed_account_type_mut()
        {
            let key_source = match account_xpub {
                Some(xpub) => address_pool::KeySource::Public(*xpub),
                None => address_pool::KeySource::NoKeySource,
            };

            let addresses =
                external_addresses.next_unused_multiple(count, &key_source, add_to_state);
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

    /// Generate multiple change addresses at once using the optionally provided extended public key.
    /// Only valid for Standard accounts.
    pub fn next_change_addresses(
        &mut self,
        account_xpub: Option<&ExtendedPubKey>,
        count: usize,
        add_to_state: bool,
    ) -> Result<Vec<Address>, String> {
        if let ManagedAccountType::Standard {
            internal_addresses,
            ..
        } = self.keys.managed_account_type_mut()
        {
            let key_source = match account_xpub {
                Some(xpub) => address_pool::KeySource::Public(*xpub),
                None => address_pool::KeySource::NoKeySource,
            };

            let addresses =
                internal_addresses.next_unused_multiple(count, &key_source, add_to_state);
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

    /// Get the external gap limit for standard accounts
    pub fn external_gap_limit(&self) -> Option<u32> {
        match self.keys.managed_account_type() {
            ManagedAccountType::Standard {
                external_addresses,
                ..
            } => Some(external_addresses.gap_limit),
            _ => None,
        }
    }

    /// Get the internal gap limit for standard accounts
    pub fn internal_gap_limit(&self) -> Option<u32> {
        match self.keys.managed_account_type() {
            ManagedAccountType::Standard {
                internal_addresses,
                ..
            } => Some(internal_addresses.gap_limit),
            _ => None,
        }
    }
}

impl ManagedAccountTrait for ManagedCoreFundsAccount {
    fn managed_account_type(&self) -> &ManagedAccountType {
        self.keys.managed_account_type()
    }

    fn managed_account_type_mut(&mut self) -> &mut ManagedAccountType {
        self.keys.managed_account_type_mut()
    }

    fn network(&self) -> Network {
        self.keys.network()
    }

    fn transactions(&self) -> &BTreeMap<Txid, TransactionRecord> {
        self.keys.transactions()
    }

    fn transactions_mut(&mut self) -> &mut BTreeMap<Txid, TransactionRecord> {
        self.keys.transactions_mut()
    }

    fn has_transaction(&self, txid: &Txid) -> bool {
        self.keys.has_transaction(txid)
    }

    fn transaction_is_finalized(&self, txid: &Txid) -> bool {
        self.keys.transaction_is_finalized(txid)
    }

    fn monitor_revision(&self) -> u64 {
        self.keys.monitor_revision()
    }

    fn bump_monitor_revision(&mut self) {
        self.keys.bump_monitor_revision()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for ManagedCoreFundsAccount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            keys: ManagedCoreKeysAccount,
            balance: WalletCoreBalance,
            utxos: BTreeMap<OutPoint, Utxo>,
        }

        let helper = Helper::deserialize(deserializer)?;

        let spent_outpoints = helper
            .keys
            .transactions()
            .values()
            .flat_map(|record| &record.transaction.input)
            .map(|input| input.previous_output)
            .collect();

        Ok(ManagedCoreFundsAccount {
            keys: helper.keys,
            balance: helper.balance,
            utxos: helper.utxos,
            spent_outpoints,
        })
    }
}
