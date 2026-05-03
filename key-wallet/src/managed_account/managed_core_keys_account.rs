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
#[cfg(feature = "bls")]
use crate::derivation_bls_bip32::ExtendedBLSPubKey;
use crate::managed_account::address_pool;
#[cfg(any(feature = "bls", feature = "eddsa"))]
use crate::managed_account::address_pool::PublicKeyType;
use crate::managed_account::managed_account_type::ManagedAccountType;
use crate::managed_account::transaction_record::{OutputDetail, OutputRole, TransactionDirection};
use crate::transaction_checking::account_checker::{
    AccountMatch, AddressClassification, CoreAccountTypeMatch,
};
use crate::transaction_checking::transaction_router::TransactionType;
use crate::transaction_checking::TransactionContext;
#[cfg(feature = "eddsa")]
use crate::AddressInfo;
use crate::{ExtendedPubKey, Network};
use dashcore::address::Payload;
use dashcore::transaction::TransactionPayload;
use dashcore::{Address, ScriptBuf, Transaction, Txid};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "keep_txs_in_memory")]
use std::collections::BTreeMap;
use std::collections::HashSet;

/// Managed core keys account with mutable state but no funds tracking
///
/// Like [`crate::managed_account::ManagedCoreFundsAccount`] but without `balance`, `utxos`, or
/// `spent_outpoints`. Used for accounts that derive special-purpose keys
/// (identity registration, asset locks, masternode provider keys) where
/// per-account UTXO/balance bookkeeping is not meaningful.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ManagedCoreKeysAccount {
    /// Account type with embedded address pools and index
    pub managed_account_type: ManagedAccountType,
    /// Network this account belongs to
    pub network: Network,
    /// Transaction history for this account.
    ///
    /// Only present when the `keep_txs_in_memory` Cargo feature is enabled.
    /// With the feature off, processed transactions update `processed_txids`
    /// only — no per-tx history is retained.
    #[cfg(feature = "keep_txs_in_memory")]
    pub transactions: BTreeMap<Txid, TransactionRecord>,
    /// Txids of every transaction this account has already processed.
    ///
    /// Always populated regardless of `keep_txs_in_memory`, so the
    /// dedup guard in `confirm_transaction` works in either feature
    /// configuration. Rebuilt from `transactions` during deserialization
    /// when the feature is enabled.
    #[cfg_attr(feature = "serde", serde(skip_serializing))]
    pub(crate) processed_txids: HashSet<Txid>,
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
    /// disabled.
    #[cfg(feature = "keep_txs_in_memory")]
    pub fn get_transaction(&self, txid: &Txid) -> Option<&TransactionRecord> {
        self.transactions.get(txid)
    }

    /// Returns the stored transaction record for `txid`, if any.
    ///
    /// Always returns `None` when the `keep_txs_in_memory` Cargo feature is
    /// disabled.
    #[cfg(not(feature = "keep_txs_in_memory"))]
    pub fn get_transaction(&self, txid: &Txid) -> Option<&TransactionRecord> {
        let _ = txid;
        None
    }

    /// Return the current monitor revision.
    pub fn monitor_revision(&self) -> u64 {
        self.monitor_revision
    }

    /// Increment the monitor revision to signal that the monitored address set changed.
    pub fn bump_monitor_revision(&mut self) {
        self.monitor_revision += 1;
    }

    /// Create a ManagedCoreKeysAccount from an Account
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

    /// Create a ManagedCoreKeysAccount from a BLS Account
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

    /// Create a ManagedCoreKeysAccount from an EdDSA Account
    #[cfg(feature = "eddsa")]
    pub fn from_eddsa_account(account: &EdDSAAccount) -> Self {
        let key_source = address_pool::KeySource::NoKeySource;
        let managed_type = ManagedAccountType::from_account_type(
            account.account_type,
            account.network,
            &key_source,
        )
        .expect("Should succeed with NoKeySource");

        Self::new(managed_type, account.network)
    }

    /// Get the account index
    pub fn index(&self) -> Option<u32> {
        self.managed_account_type.index()
    }

    /// Get the account index or 0 if none exists
    pub fn index_or_default(&self) -> u32 {
        self.managed_account_type.index_or_default()
    }

    /// Get the managed account type
    pub fn managed_type(&self) -> &ManagedAccountType {
        &self.managed_account_type
    }

    /// Get the next unused receive address index for standard accounts
    pub fn get_next_receive_address_index(&self) -> Option<u32> {
        if let ManagedAccountType::Standard {
            external_addresses,
            ..
        } = &self.managed_account_type
        {
            if let Some(addr) = external_addresses.unused_addresses().first() {
                external_addresses.address_index(addr)
            } else {
                let stats = external_addresses.stats();
                Some(stats.highest_generated.map(|h| h + 1).unwrap_or(0))
            }
        } else {
            None
        }
    }

    /// Get the next unused change address index for standard accounts
    pub fn get_next_change_address_index(&self) -> Option<u32> {
        if let ManagedAccountType::Standard {
            internal_addresses,
            ..
        } = &self.managed_account_type
        {
            if let Some(addr) = internal_addresses.unused_addresses().first() {
                internal_addresses.address_index(addr)
            } else {
                let stats = internal_addresses.stats();
                Some(stats.highest_generated.map(|h| h + 1).unwrap_or(0))
            }
        } else {
            None
        }
    }

    /// Get the next unused address index for single-pool account types
    pub fn get_next_address_index(&self) -> Option<u32> {
        match &self.managed_account_type {
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
        self.managed_account_type.mark_address_used(address)
    }

    /// Get all addresses from all pools
    pub fn all_addresses(&self) -> Vec<Address> {
        self.managed_account_type.all_addresses()
    }

    /// Check if an address belongs to this account
    pub fn contains_address(&self, address: &Address) -> bool {
        self.managed_account_type.contains_address(address)
    }

    /// Check if a script pub key belongs to this account
    pub fn contains_script_pub_key(&self, script_pub_key: &ScriptBuf) -> bool {
        self.managed_account_type.contains_script_pub_key(script_pub_key)
    }

    /// Get address info for a given address
    pub fn get_address_info(&self, address: &Address) -> Option<address_pool::AddressInfo> {
        self.managed_account_type.get_address_info(address)
    }

    /// Generate the next address for non-standard accounts
    pub fn next_address(
        &mut self,
        account_xpub: Option<&ExtendedPubKey>,
        add_to_state: bool,
    ) -> Result<Address, &'static str> {
        match &mut self.managed_account_type {
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
            | ManagedAccountType::IdentityTopUp {
                addresses,
                ..
            } => {
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
    pub fn next_address_with_info(
        &mut self,
        account_xpub: Option<&ExtendedPubKey>,
        add_to_state: bool,
    ) -> Result<address_pool::AddressInfo, &'static str> {
        match &mut self.managed_account_type {
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
            | ManagedAccountType::IdentityTopUp {
                addresses,
                ..
            } => {
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
    #[cfg(feature = "bls")]
    pub fn next_bls_operator_key(
        &mut self,
        account_xpub: Option<ExtendedBLSPubKey>,
        add_to_state: bool,
    ) -> Result<dashcore::blsful::PublicKey<dashcore::blsful::Bls12381G2Impl>, &'static str> {
        match &mut self.managed_account_type {
            ManagedAccountType::ProviderOperatorKeys {
                addresses,
                ..
            } => {
                let key_source = match account_xpub {
                    Some(xpub) => address_pool::KeySource::BLSPublic(xpub),
                    None => address_pool::KeySource::NoKeySource,
                };

                let info = addresses
                    .next_unused_with_info(&key_source, add_to_state)
                    .map_err(|_| "Failed to get next unused address")?;

                let Some(PublicKeyType::BLS(pub_key_bytes)) = info.public_key else {
                    return Err("Expected BLS public key but got different key type");
                };

                addresses.mark_index_used(info.index);

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
    #[cfg(feature = "eddsa")]
    pub fn next_eddsa_platform_key(
        &mut self,
        account_xpriv: crate::derivation_slip10::ExtendedEd25519PrivKey,
        add_to_state: bool,
    ) -> Result<(crate::derivation_slip10::VerifyingKey, AddressInfo), &'static str> {
        match &mut self.managed_account_type {
            ManagedAccountType::ProviderPlatformKeys {
                addresses,
                ..
            } => {
                let key_source = address_pool::KeySource::EdDSAPrivate(account_xpriv);

                let info = addresses
                    .next_unused_with_info(&key_source, add_to_state)
                    .map_err(|_| "Failed to get next unused address")?;

                let Some(PublicKeyType::EdDSA(pub_key_bytes)) = info.public_key.clone() else {
                    return Err("Expected EdDSA public key but got different key type");
                };

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
    pub fn next_private_key(
        &mut self,
        root_xpriv: &crate::wallet::root_extended_keys::RootExtendedPrivKey,
        network: Network,
    ) -> Result<[u8; 32], &'static str> {
        if matches!(self.managed_account_type, ManagedAccountType::Standard { .. }) {
            return Err("Standard accounts must use next_receive_address or next_change_address");
        }

        let mut pools = self.managed_account_type.address_pools_mut();
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

    /// Peek at the next unused address's path and index without marking the index used.
    pub fn peek_next_path(&mut self) -> Result<(crate::DerivationPath, u32), &'static str> {
        if matches!(self.managed_account_type, ManagedAccountType::Standard { .. }) {
            return Err("Standard accounts must use next_receive_address or next_change_address");
        }

        let mut pools = self.managed_account_type.address_pools_mut();
        let pool = pools.first_mut().ok_or("Account has no address pool")?;

        let info = pool
            .next_unused_with_info(&address_pool::KeySource::NoKeySource, false)
            .map_err(|_| "No unused address available")?;

        Ok((info.path, info.index))
    }

    /// Mark an index on the account's first address pool as used.
    pub fn mark_first_pool_index_used(&mut self, index: u32) -> Result<(), &'static str> {
        if matches!(self.managed_account_type, ManagedAccountType::Standard { .. }) {
            return Err("Standard accounts must use next_receive_address or next_change_address");
        }

        let mut pools = self.managed_account_type.address_pools_mut();
        let pool = pools.first_mut().ok_or("Account has no address pool")?;
        pool.mark_index_used(index);
        Ok(())
    }

    /// Consume the next unused address and return only its derivation path.
    pub fn next_path(&mut self) -> Result<crate::DerivationPath, &'static str> {
        let (path, index) = self.peek_next_path()?;
        self.mark_first_pool_index_used(index)?;
        Ok(path)
    }

    /// Get the derivation path for an address if it belongs to this account
    pub fn address_derivation_path(&self, address: &Address) -> Option<crate::DerivationPath> {
        self.managed_account_type.get_address_derivation_path(address)
    }

    /// Get total address count across all pools
    pub fn total_address_count(&self) -> usize {
        self.managed_account_type
            .address_pools()
            .iter()
            .map(|pool| pool.stats().total_generated as usize)
            .sum()
    }

    /// Get used address count across all pools
    pub fn used_address_count(&self) -> usize {
        self.managed_account_type
            .address_pools()
            .iter()
            .map(|pool| pool.stats().used_count as usize)
            .sum()
    }

    /// Get the gap limit for non-standard (single-pool) accounts
    pub fn gap_limit(&self) -> Option<u32> {
        match &self.managed_account_type {
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

    /// Record a new transaction for this keys account.
    ///
    /// Unlike [`ManagedCoreFundsAccount::record_transaction`](crate::managed_account::ManagedCoreFundsAccount::record_transaction),
    /// this variant performs no UTXO bookkeeping or balance updates: keys
    /// accounts (identity, asset-lock, provider) do not track per-account
    /// UTXOs, so input details are always empty and output annotation is
    /// limited to outputs paying to addresses we own.
    ///
    /// Always inserts into `processed_txids`; only inserts into
    /// `transactions` when the `keep_txs_in_memory` feature is enabled.
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

        // Keys accounts have no UTXO state to look up — input details
        // come from UTXOs only, so there is nothing to record.
        let input_details = Vec::new();

        // Use `account_match.sent` as the sole signal that we contributed
        // to this transaction's inputs (UTXO-based detection isn't
        // available here).
        let has_inputs = account_match.sent > 0;

        let resolved_outputs: Vec<Option<Address>> = tx
            .output
            .iter()
            .map(|output| Address::from_script(&output.script_pubkey, self.network).ok())
            .collect();

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
            self.managed_account_type.to_account_type(),
            context.clone(),
            transaction_type,
            direction,
            input_details,
            output_details,
            net_amount,
        );

        let record = tx_record.clone();
        self.processed_txids.insert(tx.txid());
        #[cfg(feature = "keep_txs_in_memory")]
        self.transactions.insert(tx.txid(), tx_record);
        #[cfg(not(feature = "keep_txs_in_memory"))]
        let _ = tx_record;

        // Silence unused-variable warnings when `keep_txs_in_memory` is off
        // and `context` was not consumed by the record store.
        #[cfg(not(feature = "keep_txs_in_memory"))]
        let _ = context;

        record
    }

    /// Re-process an existing transaction with updated context for this keys account.
    ///
    /// Mirrors [`ManagedCoreFundsAccount::confirm_transaction`](crate::managed_account::ManagedCoreFundsAccount::confirm_transaction)
    /// but without UTXO updates. Returns `true` if the transaction transitioned
    /// from unconfirmed to confirmed.
    pub(crate) fn confirm_transaction(
        &mut self,
        tx: &Transaction,
        account_match: &AccountMatch,
        context: TransactionContext,
        transaction_type: TransactionType,
    ) -> bool {
        if !self.processed_txids.contains(&tx.txid()) {
            self.record_transaction(tx, account_match, context, transaction_type);
            return true;
        }

        #[cfg_attr(not(feature = "keep_txs_in_memory"), allow(unused_mut))]
        let mut changed = false;
        #[cfg(feature = "keep_txs_in_memory")]
        if let Some(tx_record) = self.transactions.get_mut(&tx.txid()) {
            debug_assert_eq!(
                tx_record.transaction_type,
                transaction_type,
                "transaction_type changed between recordings for {}",
                tx.txid()
            );
            if tx_record.context != context {
                let was_confirmed = tx_record.context.confirmed();
                tx_record.update_context(context);
                changed = !was_confirmed;
            }
        }
        #[cfg(not(feature = "keep_txs_in_memory"))]
        {
            // Silence unused-binding warnings.
            let _ = (transaction_type, context, account_match);
        }
        // Silence unused-variable warning when keep_txs_in_memory is off
        #[cfg(not(feature = "keep_txs_in_memory"))]
        let _ = tx;
        changed
    }

    /// Classify an address within this account.
    ///
    /// Keys accounts only ever return [`AddressClassification::Other`],
    /// because they don't model the external/internal split that standard
    /// (BIP44/BIP32) accounts use.
    pub fn classify_address(&self, address: &Address) -> AddressClassification {
        let _ = address;
        AddressClassification::Other
    }

    /// Check if a script pubkey is a provider payout that belongs to this account
    fn check_provider_payout(
        &self,
        script_pubkey: &ScriptBuf,
    ) -> Option<address_pool::AddressInfo> {
        if self.contains_script_pub_key(script_pubkey) {
            if let Ok(address) = Address::from_script(script_pubkey, self.network) {
                return self.get_address_info(&address);
            }
        }
        None
    }

    /// Check a single keys account for transaction involvement.
    ///
    /// Mirrors [`ManagedCoreFundsAccount::check_transaction_for_match`](crate::managed_account::ManagedCoreFundsAccount::check_transaction_for_match)
    /// but skips UTXO-based input matching (`sent` is always 0 for keys accounts).
    pub fn check_transaction_for_match(
        &self,
        tx: &Transaction,
        index: Option<u32>,
    ) -> Option<AccountMatch> {
        let mut involved_other_addresses = Vec::new();
        let mut received = 0u64;
        let mut provider_payout_involved = false;

        // Check provider payouts in special transactions
        if let Some(payload) = &tx.special_transaction_payload {
            let script_payout = match payload {
                TransactionPayload::ProviderRegistrationPayloadType(reg) => {
                    Some(&reg.script_payout)
                }
                TransactionPayload::ProviderUpdateRegistrarPayloadType(update) => {
                    Some(&update.script_payout)
                }
                TransactionPayload::ProviderUpdateServicePayloadType(update) => {
                    Some(&update.script_payout)
                }
                _ => None,
            };

            if let Some(payout_script) = script_payout {
                if let Some(payout_info) = self.check_provider_payout(payout_script) {
                    provider_payout_involved = true;
                    if Address::from_script(payout_script, self.network).is_ok() {
                        involved_other_addresses.push(payout_info);
                    }
                }
            }
        }

        // Check outputs (received) — keys accounts never own change addresses,
        // so every match goes into `involved_other_addresses`.
        for output in &tx.output {
            if self.contains_script_pub_key(&output.script_pubkey) {
                if let Ok(address) = Address::from_script(&output.script_pubkey, self.network) {
                    if let Some(address_info) = self.get_address_info(&address) {
                        involved_other_addresses.push(address_info);
                    }
                }
                received += output.value;
            }
        }

        // Keys accounts don't track UTXOs, so we cannot detect spends from this
        // account based on the input set. `sent` is always 0.
        let sent = 0u64;

        let has_addresses = !involved_other_addresses.is_empty() || provider_payout_involved;

        if has_addresses {
            let account_type_match = match &self.managed_account_type {
                ManagedAccountType::IdentityRegistration {
                    ..
                } => CoreAccountTypeMatch::IdentityRegistration {
                    involved_addresses: involved_other_addresses,
                },
                ManagedAccountType::IdentityTopUp {
                    ..
                } => CoreAccountTypeMatch::IdentityTopUp {
                    account_index: index.unwrap_or(0),
                    involved_addresses: involved_other_addresses,
                },
                ManagedAccountType::IdentityTopUpNotBoundToIdentity {
                    ..
                } => CoreAccountTypeMatch::IdentityTopUpNotBound {
                    involved_addresses: involved_other_addresses,
                },
                ManagedAccountType::IdentityInvitation {
                    ..
                } => CoreAccountTypeMatch::IdentityInvitation {
                    involved_addresses: involved_other_addresses,
                },
                ManagedAccountType::AssetLockAddressTopUp {
                    ..
                } => CoreAccountTypeMatch::AssetLockAddressTopUp {
                    involved_addresses: involved_other_addresses,
                },
                ManagedAccountType::AssetLockShieldedAddressTopUp {
                    ..
                } => CoreAccountTypeMatch::AssetLockShieldedAddressTopUp {
                    involved_addresses: involved_other_addresses,
                },
                ManagedAccountType::ProviderVotingKeys {
                    ..
                } => CoreAccountTypeMatch::ProviderVotingKeys {
                    involved_addresses: involved_other_addresses,
                },
                ManagedAccountType::ProviderOwnerKeys {
                    ..
                } => CoreAccountTypeMatch::ProviderOwnerKeys {
                    involved_addresses: involved_other_addresses,
                },
                ManagedAccountType::ProviderOperatorKeys {
                    ..
                } => CoreAccountTypeMatch::ProviderOperatorKeys {
                    involved_addresses: involved_other_addresses,
                },
                ManagedAccountType::ProviderPlatformKeys {
                    ..
                } => CoreAccountTypeMatch::ProviderPlatformKeys {
                    involved_addresses: involved_other_addresses,
                },
                // Funds-only variants are not expected on keys accounts.
                _ => return None,
            };

            Some(AccountMatch {
                account_type_match,
                received,
                sent,
                received_for_credit_conversion: 0,
            })
        } else {
            None
        }
    }

    /// Check AssetLock transaction credit_outputs for this keys account.
    ///
    /// Mirrors [`ManagedCoreFundsAccount::check_asset_lock_transaction_for_match`](crate::managed_account::ManagedCoreFundsAccount::check_asset_lock_transaction_for_match).
    pub fn check_asset_lock_transaction_for_match(
        &self,
        tx: &Transaction,
        index: Option<u32>,
    ) -> Option<AccountMatch> {
        if let Some(TransactionPayload::AssetLockPayloadType(ref payload)) =
            tx.special_transaction_payload
        {
            let mut involved_addresses = Vec::new();
            let mut received = 0u64;

            for credit_output in &payload.credit_outputs {
                if self.contains_script_pub_key(&credit_output.script_pubkey) {
                    if let Ok(address) =
                        Address::from_script(&credit_output.script_pubkey, self.network)
                    {
                        if let Some(address_info) = self.get_address_info(&address) {
                            involved_addresses.push(address_info.clone());
                        }
                    }
                    received += credit_output.value;
                }
            }

            if !involved_addresses.is_empty() {
                let account_type_match = match &self.managed_account_type {
                    ManagedAccountType::IdentityRegistration {
                        ..
                    } => CoreAccountTypeMatch::IdentityRegistration {
                        involved_addresses,
                    },
                    ManagedAccountType::IdentityTopUp {
                        ..
                    } => CoreAccountTypeMatch::IdentityTopUp {
                        account_index: index.unwrap_or(0),
                        involved_addresses,
                    },
                    ManagedAccountType::IdentityTopUpNotBoundToIdentity {
                        ..
                    } => CoreAccountTypeMatch::IdentityTopUpNotBound {
                        involved_addresses,
                    },
                    ManagedAccountType::IdentityInvitation {
                        ..
                    } => CoreAccountTypeMatch::IdentityInvitation {
                        involved_addresses,
                    },
                    ManagedAccountType::AssetLockAddressTopUp {
                        ..
                    } => CoreAccountTypeMatch::AssetLockAddressTopUp {
                        involved_addresses,
                    },
                    ManagedAccountType::AssetLockShieldedAddressTopUp {
                        ..
                    } => CoreAccountTypeMatch::AssetLockShieldedAddressTopUp {
                        involved_addresses,
                    },
                    _ => return None,
                };

                return Some(AccountMatch {
                    account_type_match,
                    received: 0,
                    sent: 0,
                    received_for_credit_conversion: received,
                });
            }
        }

        None
    }

    /// Check if transaction contains provider voting key from this account.
    pub fn check_provider_voting_key_in_transaction_for_match(
        &self,
        tx: &Transaction,
    ) -> Option<AccountMatch> {
        if let ManagedAccountType::ProviderVotingKeys {
            addresses,
        } = &self.managed_account_type
        {
            if let Some(payload) = &tx.special_transaction_payload {
                let voting_key_hash = match payload {
                    TransactionPayload::ProviderRegistrationPayloadType(reg) => {
                        &reg.voting_key_hash
                    }
                    TransactionPayload::ProviderUpdateRegistrarPayloadType(update) => {
                        &update.voting_key_hash
                    }
                    _ => return None,
                };

                for (address, &addr_index) in &addresses.address_index {
                    if let Payload::PubkeyHash(addr_hash) = address.payload() {
                        if addr_hash == voting_key_hash {
                            if let Some(address_info) = addresses.addresses.get(&addr_index) {
                                return Some(AccountMatch {
                                    account_type_match: CoreAccountTypeMatch::ProviderVotingKeys {
                                        involved_addresses: vec![address_info.clone()],
                                    },
                                    received: 0,
                                    sent: 0,
                                    received_for_credit_conversion: 0,
                                });
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// Check if transaction contains provider owner key from this account.
    pub fn check_provider_owner_key_in_transaction_for_match(
        &self,
        tx: &Transaction,
    ) -> Option<AccountMatch> {
        if let ManagedAccountType::ProviderOwnerKeys {
            addresses,
        } = &self.managed_account_type
        {
            if let Some(payload) = &tx.special_transaction_payload {
                let owner_key_hash = match payload {
                    TransactionPayload::ProviderRegistrationPayloadType(reg) => &reg.owner_key_hash,
                    _ => return None,
                };

                for (address, &addr_index) in &addresses.address_index {
                    if let Payload::PubkeyHash(addr_hash) = address.payload() {
                        if addr_hash == owner_key_hash {
                            if let Some(address_info) = addresses.addresses.get(&addr_index) {
                                return Some(AccountMatch {
                                    account_type_match: CoreAccountTypeMatch::ProviderOwnerKeys {
                                        involved_addresses: vec![address_info.clone()],
                                    },
                                    received: 0,
                                    sent: 0,
                                    received_for_credit_conversion: 0,
                                });
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// Check if transaction contains provider operator key from this account.
    pub fn check_provider_operator_key_in_transaction_for_match(
        &self,
        tx: &Transaction,
    ) -> Option<AccountMatch> {
        if let ManagedAccountType::ProviderOperatorKeys {
            addresses,
        } = &self.managed_account_type
        {
            #[cfg(feature = "bls")]
            if let Some(payload) = &tx.special_transaction_payload {
                let operator_public_key = match payload {
                    TransactionPayload::ProviderRegistrationPayloadType(reg) => {
                        &reg.operator_public_key
                    }
                    TransactionPayload::ProviderUpdateRegistrarPayloadType(reg) => {
                        &reg.operator_public_key
                    }
                    _ => return None,
                };

                for address_info in addresses.addresses.values() {
                    if let Some(PublicKeyType::BLS(bls_key)) = &address_info.public_key {
                        let operator_key_bytes: &[u8; 48] = operator_public_key.as_ref();
                        if bls_key.len() == 48 && bls_key.as_slice() == operator_key_bytes {
                            return Some(AccountMatch {
                                account_type_match: CoreAccountTypeMatch::ProviderOperatorKeys {
                                    involved_addresses: vec![address_info.clone()],
                                },
                                received: 0,
                                sent: 0,
                                received_for_credit_conversion: 0,
                            });
                        }
                    }
                }
            }
            // Without the `bls` feature there's no way to compare operator keys.
            #[cfg(not(feature = "bls"))]
            let _ = (tx, addresses);
        }

        None
    }

    /// Check if transaction contains provider platform key from this account.
    pub fn check_provider_platform_key_in_transaction_for_match(
        &self,
        tx: &Transaction,
    ) -> Option<AccountMatch> {
        if let ManagedAccountType::ProviderPlatformKeys {
            addresses,
        } = &self.managed_account_type
        {
            if let Some(payload) = &tx.special_transaction_payload {
                let platform_node_id = match payload {
                    TransactionPayload::ProviderRegistrationPayloadType(reg) => {
                        if let Some(platform_node_id) = &reg.platform_node_id {
                            platform_node_id
                        } else {
                            return None;
                        }
                    }
                    _ => return None,
                };

                for (address, &addr_index) in &addresses.address_index {
                    if let Payload::PubkeyHash(addr_hash) = address.payload() {
                        if addr_hash == platform_node_id {
                            if let Some(address_info) = addresses.addresses.get(&addr_index) {
                                return Some(AccountMatch {
                                    account_type_match:
                                        CoreAccountTypeMatch::ProviderPlatformKeys {
                                            involved_addresses: vec![address_info.clone()],
                                        },
                                    received: 0,
                                    sent: 0,
                                    received_for_credit_conversion: 0,
                                });
                            }
                        }
                    }
                }
            }
        }

        None
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
            #[cfg(feature = "keep_txs_in_memory")]
            #[serde(default)]
            transactions: BTreeMap<Txid, TransactionRecord>,
        }

        let helper = Helper::deserialize(deserializer)?;

        #[cfg(feature = "keep_txs_in_memory")]
        let processed_txids: HashSet<Txid> = helper.transactions.keys().copied().collect();
        #[cfg(not(feature = "keep_txs_in_memory"))]
        let processed_txids: HashSet<Txid> = HashSet::new();

        Ok(ManagedCoreKeysAccount {
            managed_account_type: helper.managed_account_type,
            network: helper.network,
            #[cfg(feature = "keep_txs_in_memory")]
            transactions: helper.transactions,
            processed_txids,
            monitor_revision: 0,
        })
    }
}
