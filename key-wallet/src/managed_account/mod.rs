//! Managed account structure with mutable state
//!
//! This module contains the mutable account state that changes during wallet operation,
//! kept separate from the immutable Account structure.

use crate::account::AccountMetadata;
#[cfg(feature = "bls")]
use crate::account::BLSAccount;
#[cfg(feature = "eddsa")]
use crate::account::EdDSAAccount;
use crate::account::ManagedAccountTrait;
use crate::account::TransactionRecord;
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
            } => {
                addresses.unused_addresses().first().and_then(|addr| addresses.address_index(addr))
            }
        }
    }

    /// Mark an address as used
    pub fn mark_address_used(&mut self, address: &Address) -> bool {
        // Update metadata timestamp
        self.metadata.last_used = Some(Self::current_timestamp());

        // Use the account type's mark_address_used method
        // The address pools already track gap limits internally
        self.account_type.mark_address_used(address)
    }

    /// Add new ones for received outputs, remove spent ones
    fn update_utxos(
        &mut self,
        tx: &Transaction,
        account_match: &AccountMatch,
        context: TransactionContext,
    ) {
        // Update UTXOs only for spendable account types
        match &mut self.account_type {
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

                let txid = tx.txid();
                let mut utxos_changed = false;

                // Insert UTXOs for outputs paying to our addresses
                for (vout, output) in tx.output.iter().enumerate() {
                    if let Ok(addr) = Address::from_script(&output.script_pubkey, self.network) {
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
                    self.monitor_revision += 1;
                }
            }
            _ => {}
        }
    }

    /// Re-process an existing transaction with updated context (e.g., mempool→block confirmation)
    /// and potentially new address matches from gap limit rescans.
    pub(crate) fn confirm_transaction(
        &mut self,
        tx: &Transaction,
        account_match: &AccountMatch,
        context: TransactionContext,
        transaction_type: TransactionType,
    ) -> bool {
        if !self.transactions.contains_key(&tx.txid()) {
            self.record_transaction(tx, account_match, context, transaction_type);
            return true;
        }

        let mut changed = false;
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
                // Only signal a change when confirmation status actually changes,
                // not for upgrades within the confirmed state (e.g. InBlock → InChainLockedBlock).
                // TODO: emit a change event for InBlock → InChainLockedBlock once chainlock
                // wallet transaction events are properly handled
                changed = !was_confirmed;
            }
        }
        self.update_utxos(tx, account_match, context);
        changed
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

        let record = tx_record.clone();
        self.transactions.insert(tx.txid(), tx_record);

        self.update_utxos(tx, account_match, context);
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

    /// Update the account balance
    pub fn update_balance(&mut self, synced_height: u32) {
        let mut spendable = 0;
        let mut unconfirmed = 0;
        let mut immature = 0;
        let mut locked = 0;
        for utxo in self.utxos.values() {
            let value = utxo.txout.value;
            if utxo.is_locked {
                locked += value;
            } else if !utxo.is_mature(synced_height) {
                immature += value;
            } else if utxo.is_spendable(synced_height) {
                spendable += value;
            } else {
                unconfirmed += value;
            }
        }
        self.balance = WalletCoreBalance::new(spendable, unconfirmed, immature, locked);
        self.metadata.last_used = Some(Self::current_timestamp());
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

    /// Generate the next receive address using the optionally provided extended public key
    /// If no key is provided, can only return pre-generated unused addresses
    /// This method derives a new address from the account's xpub but does not add it to the pool
    /// The address must be added to the pool separately with proper tracking
    pub fn next_receive_address(
        &mut self,
        account_xpub: Option<&ExtendedPubKey>,
        add_to_state: bool,
    ) -> Result<Address, &'static str> {
        // For standard accounts, use the address pool to get the next unused address
        if let ManagedAccountType::Standard {
            external_addresses,
            ..
        } = &mut self.account_type
        {
            // Create appropriate key source based on whether xpub is provided
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
            self.monitor_revision += 1;
            Ok(addr)
        } else {
            Err("Cannot generate receive address for non-standard account type")
        }
    }

    /// Generate the next change address using the optionally provided extended public key
    /// If no key is provided, can only return pre-generated unused addresses
    /// This method uses the address pool to properly track and generate addresses
    pub fn next_change_address(
        &mut self,
        account_xpub: Option<&ExtendedPubKey>,
        add_to_state: bool,
    ) -> Result<Address, &'static str> {
        // For standard accounts, use the address pool to get the next unused address
        if let ManagedAccountType::Standard {
            internal_addresses,
            ..
        } = &mut self.account_type
        {
            // Create appropriate key source based on whether xpub is provided
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
            self.monitor_revision += 1;
            Ok(addr)
        } else {
            Err("Cannot generate change address for non-standard account type")
        }
    }

    /// Generate multiple receive addresses at once using the optionally provided extended public key
    ///
    /// Returns the requested number of unused receive addresses, generating new ones if needed.
    /// This is more efficient than calling `next_receive_address` multiple times.
    /// If no key is provided, can only return pre-generated unused addresses.
    pub fn next_receive_addresses(
        &mut self,
        account_xpub: Option<&ExtendedPubKey>,
        count: usize,
        add_to_state: bool,
    ) -> Result<Vec<Address>, String> {
        // For standard accounts, use the address pool to get multiple unused addresses
        if let ManagedAccountType::Standard {
            external_addresses,
            ..
        } = &mut self.account_type
        {
            // Create appropriate key source based on whether xpub is provided
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

    /// Generate multiple change addresses at once using the optionally provided extended public key
    ///
    /// Returns the requested number of unused change addresses, generating new ones if needed.
    /// This is more efficient than calling `next_change_address` multiple times.
    /// If no key is provided, can only return pre-generated unused addresses.
    pub fn next_change_addresses(
        &mut self,
        account_xpub: Option<&ExtendedPubKey>,
        count: usize,
        add_to_state: bool,
    ) -> Result<Vec<Address>, String> {
        // For standard accounts, use the address pool to get multiple unused addresses
        if let ManagedAccountType::Standard {
            internal_addresses,
            ..
        } = &mut self.account_type
        {
            // Create appropriate key source based on whether xpub is provided
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

    /// Generate the next address for non-standard accounts
    /// This method is for special accounts like Identity, Provider accounts, etc.
    /// Standard accounts (BIP44/BIP32) should use next_receive_address or next_change_address
    pub fn next_address(
        &mut self,
        account_xpub: Option<&ExtendedPubKey>,
        add_to_state: bool,
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
            } => {
                // Create appropriate key source based on whether xpub is provided
                let key_source = match account_xpub {
                    Some(xpub) => address_pool::KeySource::Public(*xpub),
                    None => address_pool::KeySource::NoKeySource,
                };

                addresses.next_unused(&key_source, add_to_state).map_err(|e| match e {
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

                addresses.next_unused(&key_source, add_to_state).map_err(|e| match e {
                    crate::error::Error::NoKeySource => {
                        "No unused addresses available and no key source provided"
                    }
                    _ => "Failed to generate address",
                })
            }
        }
    }

    /// Generate the next address with full info for non-standard accounts
    /// This method is for special accounts like Identity, Provider accounts, etc.
    /// Standard accounts (BIP44/BIP32) should use next_receive_address_with_info or next_change_address_with_info
    pub fn next_address_with_info(
        &mut self,
        account_xpub: Option<&ExtendedPubKey>,
        add_to_state: bool,
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
            } => {
                // Create appropriate key source based on whether xpub is provided
                let key_source = match account_xpub {
                    Some(xpub) => address_pool::KeySource::Public(*xpub),
                    None => address_pool::KeySource::NoKeySource,
                };

                addresses.next_unused_with_info(&key_source, add_to_state).map_err(|e| match e {
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

                addresses.next_unused_with_info(&key_source, add_to_state).map_err(|e| match e {
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
        add_to_state: bool,
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
                    .next_unused_with_info(&key_source, add_to_state)
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
        add_to_state: bool,
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
                    .next_unused_with_info(&key_source, add_to_state)
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
            .next_unused_with_info(&address_pool::KeySource::NoKeySource, false)
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

    /// Get the derivation path for an address if it belongs to this account
    pub fn address_derivation_path(&self, address: &Address) -> Option<crate::DerivationPath> {
        self.account_type.get_address_derivation_path(address)
    }

    /// Get the current timestamp (for metadata)
    fn current_timestamp() -> u64 {
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
            } => Some(addresses.gap_limit),
        }
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
