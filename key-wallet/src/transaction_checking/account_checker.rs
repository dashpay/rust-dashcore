//! Account-level transaction checking
//!
//! This module provides methods for checking if transactions belong to
//! specific accounts within a ManagedAccountCollection.

use super::transaction_router::AccountTypeToCheck;
use crate::account::{ManagedAccount, ManagedAccountCollection};
use crate::managed_account::address_pool::{AddressInfo, PublicKeyType};
use crate::managed_account::managed_account_type::ManagedAccountType;
use crate::Address;
use alloc::vec::Vec;
use dashcore::address::Payload;
use dashcore::blockdata::transaction::Transaction;
use dashcore::transaction::TransactionPayload;
use dashcore::ScriptBuf;

/// Classification of an address within an account
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressClassification {
    /// External (receive) address for standard accounts
    External,
    /// Internal (change) address for standard accounts
    Internal,
    /// Other address type (for non-standard accounts or unknown)
    Other,
}

/// Result of checking a transaction against accounts
#[derive(Debug, Clone)]
pub struct TransactionCheckResult {
    /// Whether the transaction belongs to any account
    pub is_relevant: bool,
    /// Set to false if the transaction was already stored and is being re-processed (e.g., during rescan)
    pub is_new_transaction: bool,
    /// Accounts that the transaction affects
    pub affected_accounts: Vec<AccountMatch>,
    /// Total value received by our accounts
    pub total_received: u64,
    /// Total value sent from our accounts
    pub total_sent: u64,
    /// Total value received for Platform credit conversion
    pub total_received_for_credit_conversion: u64,
    /// New addresses generated during gap limit maintenance
    pub new_addresses: Vec<Address>,
}

/// Enum representing the type of account that matched with embedded data
#[derive(Debug, Clone)]
pub enum AccountTypeMatch {
    /// Standard BIP44 account with index and involved addresses
    StandardBIP44 {
        account_index: u32,
        involved_receive_addresses: Vec<AddressInfo>,
        involved_change_addresses: Vec<AddressInfo>,
    },
    /// Standard BIP32 account with index and involved addresses
    StandardBIP32 {
        account_index: u32,
        involved_receive_addresses: Vec<AddressInfo>,
        involved_change_addresses: Vec<AddressInfo>,
    },
    /// CoinJoin account with index and involved addresses (no change addresses)
    CoinJoin {
        account_index: u32,
        involved_addresses: Vec<AddressInfo>,
    },
    /// Identity registration account (no index)
    IdentityRegistration {
        involved_addresses: Vec<AddressInfo>,
    },
    /// Identity top-up account with index
    IdentityTopUp {
        account_index: u32,
        involved_addresses: Vec<AddressInfo>,
    },
    /// Identity top-up not bound account (no index)
    IdentityTopUpNotBound {
        involved_addresses: Vec<AddressInfo>,
    },
    /// Identity invitation account (no index)
    IdentityInvitation {
        involved_addresses: Vec<AddressInfo>,
    },
    /// Provider voting keys account (no index)
    ProviderVotingKeys {
        involved_addresses: Vec<AddressInfo>,
    },
    /// Provider owner keys account (no index)
    ProviderOwnerKeys {
        involved_addresses: Vec<AddressInfo>,
    },
    /// Provider operator keys account (no index)
    ProviderOperatorKeys {
        involved_addresses: Vec<AddressInfo>,
    },
    /// Provider platform keys account (no index)
    ProviderPlatformKeys {
        involved_addresses: Vec<AddressInfo>,
    },
    /// DashPay receiving funds account (single-pool)
    DashpayReceivingFunds {
        account_index: u32,
        involved_addresses: Vec<AddressInfo>,
    },
    /// DashPay external account (single-pool)
    DashpayExternalAccount {
        account_index: u32,
        involved_addresses: Vec<AddressInfo>,
    },
    /// Platform Payment account (DIP-17)
    /// Note: Platform addresses are NOT used in Core chain transactions
    PlatformPayment {
        account_index: u32,
        key_class: u32,
        involved_addresses: Vec<AddressInfo>,
    },
}

impl AccountTypeMatch {
    /// Get all involved addresses (both receive and change combined)
    pub fn all_involved_addresses(&self) -> Vec<AddressInfo> {
        match self {
            AccountTypeMatch::StandardBIP44 {
                involved_receive_addresses,
                involved_change_addresses,
                ..
            }
            | AccountTypeMatch::StandardBIP32 {
                involved_receive_addresses,
                involved_change_addresses,
                ..
            } => {
                let mut all = involved_receive_addresses.clone();
                all.extend(involved_change_addresses.clone());
                all
            }
            AccountTypeMatch::CoinJoin {
                involved_addresses,
                ..
            } => involved_addresses.clone(),
            AccountTypeMatch::IdentityRegistration {
                involved_addresses,
            }
            | AccountTypeMatch::IdentityTopUp {
                involved_addresses,
                ..
            }
            | AccountTypeMatch::IdentityTopUpNotBound {
                involved_addresses,
            }
            | AccountTypeMatch::IdentityInvitation {
                involved_addresses,
            }
            | AccountTypeMatch::ProviderVotingKeys {
                involved_addresses,
            }
            | AccountTypeMatch::ProviderOwnerKeys {
                involved_addresses,
            }
            | AccountTypeMatch::ProviderOperatorKeys {
                involved_addresses,
            }
            | AccountTypeMatch::ProviderPlatformKeys {
                involved_addresses,
            } => involved_addresses.clone(),
            AccountTypeMatch::DashpayReceivingFunds {
                involved_addresses,
                ..
            }
            | AccountTypeMatch::DashpayExternalAccount {
                involved_addresses,
                ..
            }
            | AccountTypeMatch::PlatformPayment {
                involved_addresses,
                ..
            } => involved_addresses.clone(),
        }
    }

    /// Get the account index if applicable
    pub fn account_index(&self) -> Option<u32> {
        match self {
            AccountTypeMatch::StandardBIP44 {
                account_index,
                ..
            }
            | AccountTypeMatch::StandardBIP32 {
                account_index,
                ..
            }
            | AccountTypeMatch::CoinJoin {
                account_index,
                ..
            }
            | AccountTypeMatch::IdentityTopUp {
                account_index,
                ..
            } => Some(*account_index),
            AccountTypeMatch::DashpayReceivingFunds {
                account_index,
                ..
            }
            | AccountTypeMatch::DashpayExternalAccount {
                account_index,
                ..
            }
            | AccountTypeMatch::PlatformPayment {
                account_index,
                ..
            } => Some(*account_index),
            _ => None,
        }
    }

    /// Convert to AccountTypeToCheck for routing
    pub fn to_account_type_to_check(&self) -> AccountTypeToCheck {
        match self {
            AccountTypeMatch::StandardBIP44 {
                ..
            } => AccountTypeToCheck::StandardBIP44,
            AccountTypeMatch::StandardBIP32 {
                ..
            } => AccountTypeToCheck::StandardBIP32,
            AccountTypeMatch::CoinJoin {
                ..
            } => AccountTypeToCheck::CoinJoin,
            AccountTypeMatch::IdentityRegistration {
                ..
            } => AccountTypeToCheck::IdentityRegistration,
            AccountTypeMatch::IdentityTopUp {
                ..
            } => AccountTypeToCheck::IdentityTopUp,
            AccountTypeMatch::IdentityTopUpNotBound {
                ..
            } => AccountTypeToCheck::IdentityTopUpNotBound,
            AccountTypeMatch::IdentityInvitation {
                ..
            } => AccountTypeToCheck::IdentityInvitation,
            AccountTypeMatch::ProviderVotingKeys {
                ..
            } => AccountTypeToCheck::ProviderVotingKeys,
            AccountTypeMatch::ProviderOwnerKeys {
                ..
            } => AccountTypeToCheck::ProviderOwnerKeys,
            AccountTypeMatch::ProviderOperatorKeys {
                ..
            } => AccountTypeToCheck::ProviderOperatorKeys,
            AccountTypeMatch::ProviderPlatformKeys {
                ..
            } => AccountTypeToCheck::ProviderPlatformKeys,
            AccountTypeMatch::DashpayReceivingFunds {
                ..
            } => AccountTypeToCheck::DashpayReceivingFunds,
            AccountTypeMatch::DashpayExternalAccount {
                ..
            } => AccountTypeToCheck::DashpayExternalAccount,
            AccountTypeMatch::PlatformPayment {
                ..
            } => AccountTypeToCheck::PlatformPayment,
        }
    }
}

/// Information about a matched account
#[derive(Debug, Clone)]
pub struct AccountMatch {
    /// The type of account that matched with embedded data
    pub account_type_match: AccountTypeMatch,
    /// Value received by this account
    pub received: u64,
    /// Value sent from this account
    pub sent: u64,
    /// Value received for Platform credit conversion (e.g., from AssetLock credit_outputs)
    pub received_for_credit_conversion: u64,
}

impl ManagedAccountCollection {
    /// Check if a transaction belongs to any accounts in the collection
    pub fn check_transaction(
        &self,
        tx: &Transaction,
        account_types: &[AccountTypeToCheck],
    ) -> TransactionCheckResult {
        let mut result = TransactionCheckResult {
            is_relevant: false,
            is_new_transaction: true,
            affected_accounts: Vec::new(),
            total_received: 0,
            total_sent: 0,
            total_received_for_credit_conversion: 0,
            new_addresses: Vec::new(),
        };

        for account_type in account_types {
            let matches = self.check_account_type(tx, *account_type);
            for match_info in matches {
                result.is_relevant = true;
                result.total_received += match_info.received;
                result.total_sent += match_info.sent;
                result.total_received_for_credit_conversion +=
                    match_info.received_for_credit_conversion;
                result.affected_accounts.push(match_info);
            }
        }

        result
    }

    /// Check a specific account type for transaction involvement
    fn check_account_type(
        &self,
        tx: &Transaction,
        account_type: AccountTypeToCheck,
    ) -> Vec<AccountMatch> {
        match account_type {
            AccountTypeToCheck::StandardBIP44 => {
                Self::check_indexed_accounts(&self.standard_bip44_accounts, tx)
            }
            AccountTypeToCheck::StandardBIP32 => {
                Self::check_indexed_accounts(&self.standard_bip32_accounts, tx)
            }
            AccountTypeToCheck::CoinJoin => {
                Self::check_indexed_accounts(&self.coinjoin_accounts, tx)
            }
            AccountTypeToCheck::IdentityRegistration => self
                .identity_registration
                .as_ref()
                .and_then(|account| account.check_asset_lock_transaction_for_match(tx, None))
                .into_iter()
                .collect(),
            AccountTypeToCheck::IdentityTopUp => {
                Self::check_indexed_accounts(&self.identity_topup, tx)
            }
            AccountTypeToCheck::IdentityTopUpNotBound => self
                .identity_topup_not_bound
                .as_ref()
                .and_then(|account| account.check_asset_lock_transaction_for_match(tx, None))
                .into_iter()
                .collect(),
            AccountTypeToCheck::IdentityInvitation => self
                .identity_invitation
                .as_ref()
                .and_then(|account| account.check_asset_lock_transaction_for_match(tx, None))
                .into_iter()
                .collect(),
            AccountTypeToCheck::ProviderVotingKeys => self
                .provider_voting_keys
                .as_ref()
                .and_then(|account| account.check_provider_voting_key_in_transaction_for_match(tx))
                .into_iter()
                .collect(),
            AccountTypeToCheck::ProviderOwnerKeys => self
                .provider_owner_keys
                .as_ref()
                .and_then(|account| account.check_provider_owner_key_in_transaction_for_match(tx))
                .into_iter()
                .collect(),
            AccountTypeToCheck::ProviderOperatorKeys => self
                .provider_operator_keys
                .as_ref()
                .and_then(|account| {
                    account.check_provider_operator_key_in_transaction_for_match(tx)
                })
                .into_iter()
                .collect(),
            AccountTypeToCheck::ProviderPlatformKeys => self
                .provider_platform_keys
                .as_ref()
                .and_then(|account| {
                    account.check_provider_platform_key_in_transaction_for_match(tx)
                })
                .into_iter()
                .collect(),
            AccountTypeToCheck::DashpayReceivingFunds => {
                let mut matches = Vec::new();
                for (key, account) in &self.dashpay_receival_accounts {
                    if let Some(m) = account.check_transaction_for_match(tx, Some(key.index)) {
                        matches.push(m);
                    }
                }
                matches
            }
            AccountTypeToCheck::DashpayExternalAccount => {
                let mut matches = Vec::new();
                for (key, account) in &self.dashpay_external_accounts {
                    if let Some(m) = account.check_transaction_for_match(tx, Some(key.index)) {
                        matches.push(m);
                    }
                }
                matches
            }
            AccountTypeToCheck::PlatformPayment => {
                // Platform Payment addresses (DIP-17) are NOT used in Core chain transactions.
                // They are only for Platform-side payments. This account type should never match
                // any Core chain transaction by design.
                Vec::new()
            }
        }
    }

    /// Check indexed accounts (BTreeMap of accounts)
    fn check_indexed_accounts(
        accounts: &alloc::collections::BTreeMap<u32, ManagedAccount>,
        tx: &Transaction,
    ) -> Vec<AccountMatch> {
        let mut matches = Vec::new();
        for (index, account) in accounts {
            if let Some(match_info) = account.check_transaction_for_match(tx, Some(*index)) {
                matches.push(match_info);
            }
        }
        matches
    }
}

impl ManagedAccount {
    /// Classify an address within this account
    pub fn classify_address(&self, address: &Address) -> AddressClassification {
        match &self.account_type {
            ManagedAccountType::Standard {
                external_addresses,
                internal_addresses,
                ..
            } => {
                if external_addresses.contains_address(address) {
                    AddressClassification::External
                } else if internal_addresses.contains_address(address) {
                    AddressClassification::Internal
                } else {
                    AddressClassification::Other
                }
            }
            ManagedAccountType::CoinJoin {
                addresses,
                ..
            } => {
                if addresses.contains_address(address) {
                    AddressClassification::External
                } else {
                    AddressClassification::Other
                }
            }
            _ => {
                // For non-standard accounts, all addresses are "Other"
                AddressClassification::Other
            }
        }
    }

    /// Check if a script pubkey is a provider payout that belongs to this account
    fn check_provider_payout(&self, script_pubkey: &ScriptBuf) -> Option<AddressInfo> {
        // Check if this script pubkey belongs to any address in this account
        if self.contains_script_pub_key(script_pubkey) {
            // Try to create an address from the script pubkey and get its info
            if let Ok(address) = Address::from_script(script_pubkey, self.network) {
                return self.get_address_info(&address);
            }
        }
        None
    }

    /// Check a single account for transaction involvement
    pub fn check_transaction_for_match(
        &self,
        tx: &Transaction,
        index: Option<u32>,
    ) -> Option<AccountMatch> {
        // Check regular outputs
        let mut involved_receive_addresses = Vec::new();
        let mut involved_change_addresses = Vec::new();
        let mut involved_other_addresses = Vec::new(); // For non-standard accounts
        let mut received = 0u64;
        let mut sent = 0u64;
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

            // Check if the provider payout script belongs to this account
            if let Some(payout_script) = script_payout {
                if let Some(payout_info) = self.check_provider_payout(payout_script) {
                    provider_payout_involved = true;
                    // Classify the payout address
                    if let Ok(payout_address) = Address::from_script(payout_script, self.network) {
                        match self.classify_address(&payout_address) {
                            AddressClassification::External => {
                                involved_receive_addresses.push(payout_info);
                            }
                            AddressClassification::Internal => {
                                involved_change_addresses.push(payout_info);
                            }
                            AddressClassification::Other => {
                                involved_other_addresses.push(payout_info);
                            }
                        }
                    }
                }
            }
        }

        // Check outputs (received)
        for output in &tx.output {
            if self.contains_script_pub_key(&output.script_pubkey) {
                if let Ok(address) = Address::from_script(&output.script_pubkey, self.network) {
                    // Try to find the address info from the account
                    if let Some(address_info) = self.get_address_info(&address) {
                        // Use the new classification method
                        match self.classify_address(&address) {
                            AddressClassification::External => {
                                involved_receive_addresses.push(address_info.clone());
                            }
                            AddressClassification::Internal => {
                                involved_change_addresses.push(address_info.clone());
                            }
                            AddressClassification::Other => {
                                involved_other_addresses.push(address_info.clone());
                            }
                        }
                    }
                }
                received += output.value;
            }
        }

        // Check inputs (sent) - rely on tracked UTXOs to determine spends
        if !tx.is_coin_base() {
            for input in &tx.input {
                if let Some(utxo) = self.utxos.get(&input.previous_output) {
                    sent = sent.saturating_add(utxo.txout.value);

                    if let Some(address_info) = self.get_address_info(&utxo.address) {
                        match self.classify_address(&utxo.address) {
                            AddressClassification::External => {
                                involved_receive_addresses.push(address_info);
                            }
                            AddressClassification::Internal => {
                                involved_change_addresses.push(address_info);
                            }
                            AddressClassification::Other => {
                                involved_other_addresses.push(address_info);
                            }
                        }
                    }
                }
            }
        }

        // Create the appropriate AccountTypeMatch based on account type
        let has_addresses = !involved_receive_addresses.is_empty()
            || !involved_change_addresses.is_empty()
            || !involved_other_addresses.is_empty()
            || provider_payout_involved
            || sent > 0;

        if has_addresses {
            let account_type_match = match &self.account_type {
                ManagedAccountType::Standard {
                    standard_account_type,
                    ..
                } => match standard_account_type {
                    crate::account::account_type::StandardAccountType::BIP44Account => {
                        AccountTypeMatch::StandardBIP44 {
                            account_index: index.unwrap_or(0),
                            involved_receive_addresses,
                            involved_change_addresses,
                        }
                    }
                    crate::account::account_type::StandardAccountType::BIP32Account => {
                        AccountTypeMatch::StandardBIP32 {
                            account_index: index.unwrap_or(0),
                            involved_receive_addresses,
                            involved_change_addresses,
                        }
                    }
                },
                ManagedAccountType::CoinJoin {
                    ..
                } => AccountTypeMatch::CoinJoin {
                    account_index: index.unwrap_or(0),
                    // For CoinJoin, use both receive addresses and other addresses
                    // since CoinJoin addresses can be classified as either
                    involved_addresses: {
                        let mut all_addresses = involved_receive_addresses.clone();
                        all_addresses.extend(involved_other_addresses.clone());
                        all_addresses
                    },
                },
                ManagedAccountType::IdentityRegistration {
                    ..
                } => AccountTypeMatch::IdentityRegistration {
                    involved_addresses: involved_other_addresses,
                },
                ManagedAccountType::IdentityTopUp {
                    ..
                } => AccountTypeMatch::IdentityTopUp {
                    account_index: index.unwrap_or(0),
                    involved_addresses: involved_other_addresses,
                },
                ManagedAccountType::IdentityTopUpNotBoundToIdentity {
                    ..
                } => AccountTypeMatch::IdentityTopUpNotBound {
                    involved_addresses: involved_other_addresses,
                },
                ManagedAccountType::IdentityInvitation {
                    ..
                } => AccountTypeMatch::IdentityInvitation {
                    involved_addresses: involved_other_addresses,
                },
                ManagedAccountType::ProviderVotingKeys {
                    ..
                } => AccountTypeMatch::ProviderVotingKeys {
                    involved_addresses: involved_other_addresses,
                },
                ManagedAccountType::ProviderOwnerKeys {
                    ..
                } => AccountTypeMatch::ProviderOwnerKeys {
                    involved_addresses: involved_other_addresses,
                },
                ManagedAccountType::ProviderOperatorKeys {
                    ..
                } => AccountTypeMatch::ProviderOperatorKeys {
                    involved_addresses: involved_other_addresses,
                },
                ManagedAccountType::ProviderPlatformKeys {
                    ..
                } => AccountTypeMatch::ProviderPlatformKeys {
                    involved_addresses: involved_other_addresses,
                },
                ManagedAccountType::DashpayReceivingFunds {
                    ..
                } => AccountTypeMatch::DashpayReceivingFunds {
                    account_index: index.unwrap_or(0),
                    involved_addresses: involved_other_addresses,
                },
                ManagedAccountType::DashpayExternalAccount {
                    ..
                } => AccountTypeMatch::DashpayExternalAccount {
                    account_index: index.unwrap_or(0),
                    involved_addresses: involved_other_addresses,
                },
                ManagedAccountType::PlatformPayment {
                    account,
                    key_class,
                    ..
                } => AccountTypeMatch::PlatformPayment {
                    account_index: *account,
                    key_class: *key_class,
                    involved_addresses: involved_other_addresses,
                },
            };

            Some(AccountMatch {
                account_type_match,
                received,
                sent,
                received_for_credit_conversion: 0, // Regular transactions don't convert to credits
            })
        } else {
            None
        }
    }

    /// Check AssetLock transaction credit_outputs for account involvement
    pub fn check_asset_lock_transaction_for_match(
        &self,
        tx: &Transaction,
        index: Option<u32>,
    ) -> Option<AccountMatch> {
        use dashcore::transaction::TransactionPayload;

        if let Some(TransactionPayload::AssetLockPayloadType(ref payload)) =
            tx.special_transaction_payload
        {
            let mut involved_addresses = Vec::new();
            let mut received = 0u64;

            // Check credit_outputs in the AssetLock payload
            for credit_output in &payload.credit_outputs {
                if self.contains_script_pub_key(&credit_output.script_pubkey) {
                    if let Ok(address) =
                        Address::from_script(&credit_output.script_pubkey, self.network)
                    {
                        // Try to find the address info from the account
                        if let Some(address_info) = self.get_address_info(&address) {
                            involved_addresses.push(address_info.clone());
                        }
                    }
                    received += credit_output.value;
                }
            }

            if !involved_addresses.is_empty() {
                // Create the appropriate AccountTypeMatch for identity accounts
                let account_type_match = match &self.account_type {
                    ManagedAccountType::IdentityRegistration {
                        ..
                    } => AccountTypeMatch::IdentityRegistration {
                        involved_addresses,
                    },
                    ManagedAccountType::IdentityTopUp {
                        ..
                    } => AccountTypeMatch::IdentityTopUp {
                        account_index: index.unwrap_or(0),
                        involved_addresses,
                    },
                    ManagedAccountType::IdentityTopUpNotBoundToIdentity {
                        ..
                    } => AccountTypeMatch::IdentityTopUpNotBound {
                        involved_addresses,
                    },
                    ManagedAccountType::IdentityInvitation {
                        ..
                    } => AccountTypeMatch::IdentityInvitation {
                        involved_addresses,
                    },
                    _ => {
                        // This shouldn't happen for AssetLock transactions
                        return None;
                    }
                };

                return Some(AccountMatch {
                    account_type_match,
                    received: 0,
                    sent: 0,
                    received_for_credit_conversion: received, // These funds are locked for Platform credits
                });
            }
        }

        None
    }

    /// Check if transaction contains provider voting key from this account
    pub fn check_provider_voting_key_in_transaction_for_match(
        &self,
        tx: &Transaction,
    ) -> Option<AccountMatch> {
        // Only check if this is a provider voting keys account
        if let ManagedAccountType::ProviderVotingKeys {
            addresses,
        } = &self.account_type
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

                // Check if voting_key_hash matches any of our address hashes
                for (address, &addr_index) in &addresses.address_index {
                    if let Payload::PubkeyHash(addr_hash) = address.payload() {
                        if addr_hash == voting_key_hash {
                            // Get the address info
                            if let Some(address_info) = addresses.addresses.get(&addr_index) {
                                return Some(AccountMatch {
                                    account_type_match: AccountTypeMatch::ProviderVotingKeys {
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

    /// Check if transaction contains provider owner key from this account
    pub fn check_provider_owner_key_in_transaction_for_match(
        &self,
        tx: &Transaction,
    ) -> Option<AccountMatch> {
        // Only check if this is a provider owner keys account
        if let ManagedAccountType::ProviderOwnerKeys {
            addresses,
        } = &self.account_type
        {
            if let Some(payload) = &tx.special_transaction_payload {
                let owner_key_hash = match payload {
                    TransactionPayload::ProviderRegistrationPayloadType(reg) => &reg.owner_key_hash,
                    _ => return None,
                };

                // Check if owner_key_hash matches any of our address hashes
                for (address, &addr_index) in &addresses.address_index {
                    if let Payload::PubkeyHash(addr_hash) = address.payload() {
                        if addr_hash == owner_key_hash {
                            // Get the address info
                            if let Some(address_info) = addresses.addresses.get(&addr_index) {
                                return Some(AccountMatch {
                                    account_type_match: AccountTypeMatch::ProviderOwnerKeys {
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

    /// Check if transaction contains provider operator key from this account
    pub fn check_provider_operator_key_in_transaction_for_match(
        &self,
        tx: &Transaction,
    ) -> Option<AccountMatch> {
        // Only check if this is a provider voting keys account
        if let ManagedAccountType::ProviderOperatorKeys {
            addresses,
        } = &self.account_type
        {
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

                // Check if operator_public_key matches any of our BLS public keys
                for address_info in addresses.addresses.values() {
                    if let Some(PublicKeyType::BLS(bls_key)) = &address_info.public_key {
                        // Compare the byte arrays - BLSPublicKey implements AsRef<[u8; 48]>
                        let operator_key_bytes: &[u8; 48] = operator_public_key.as_ref();
                        if bls_key.len() == 48 && bls_key.as_slice() == operator_key_bytes {
                            return Some(AccountMatch {
                                account_type_match: AccountTypeMatch::ProviderOperatorKeys {
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

        None
    }

    /// Check if transaction contains provider platform key from this account
    pub fn check_provider_platform_key_in_transaction_for_match(
        &self,
        tx: &Transaction,
    ) -> Option<AccountMatch> {
        // Only check if this is a provider voting keys account
        if let ManagedAccountType::ProviderPlatformKeys {
            addresses,
        } = &self.account_type
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

                // Check if platform_node_id matches any of our address hashes
                for (address, &addr_index) in &addresses.address_index {
                    if let Payload::PubkeyHash(addr_hash) = address.payload() {
                        if addr_hash == platform_node_id {
                            // Get the address info
                            if let Some(address_info) = addresses.addresses.get(&addr_index) {
                                return Some(AccountMatch {
                                    account_type_match: AccountTypeMatch::ProviderPlatformKeys {
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

    /// Check if an address belongs to any account in the collection
    pub fn find_address_account(
        collection: &ManagedAccountCollection,
        address: &Address,
    ) -> Option<(AccountTypeToCheck, Option<u32>)> {
        // Check standard BIP44 accounts
        for (index, account) in &collection.standard_bip44_accounts {
            if account.contains_address(address) {
                return Some((AccountTypeToCheck::StandardBIP44, Some(*index)));
            }
        }

        // Check standard BIP32 accounts
        for (index, account) in &collection.standard_bip32_accounts {
            if account.contains_address(address) {
                return Some((AccountTypeToCheck::StandardBIP32, Some(*index)));
            }
        }

        // Check CoinJoin accounts
        for (index, account) in &collection.coinjoin_accounts {
            if account.contains_address(address) {
                return Some((AccountTypeToCheck::CoinJoin, Some(*index)));
            }
        }

        // Check identity registration
        if let Some(account) = &collection.identity_registration {
            if account.contains_address(address) {
                return Some((AccountTypeToCheck::IdentityRegistration, None));
            }
        }

        // Check identity top-up accounts
        for (index, account) in &collection.identity_topup {
            if account.contains_address(address) {
                return Some((AccountTypeToCheck::IdentityTopUp, Some(*index)));
            }
        }

        // Check identity top-up not bound
        if let Some(account) = &collection.identity_topup_not_bound {
            if account.contains_address(address) {
                return Some((AccountTypeToCheck::IdentityTopUpNotBound, None));
            }
        }

        // Check identity invitation
        if let Some(account) = &collection.identity_invitation {
            if account.contains_address(address) {
                return Some((AccountTypeToCheck::IdentityInvitation, None));
            }
        }

        // Check provider accounts
        if let Some(account) = &collection.provider_voting_keys {
            if account.contains_address(address) {
                return Some((AccountTypeToCheck::ProviderVotingKeys, None));
            }
        }

        if let Some(account) = &collection.provider_owner_keys {
            if account.contains_address(address) {
                return Some((AccountTypeToCheck::ProviderOwnerKeys, None));
            }
        }

        if let Some(account) = &collection.provider_operator_keys {
            if account.contains_address(address) {
                return Some((AccountTypeToCheck::ProviderOperatorKeys, None));
            }
        }

        if let Some(account) = &collection.provider_platform_keys {
            if account.contains_address(address) {
                return Some((AccountTypeToCheck::ProviderPlatformKeys, None));
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coinjoin_account_type_match_no_change_addresses() {
        // Create a CoinJoin AccountTypeMatch - note it only has involved_addresses, no split
        let coinjoin_match = AccountTypeMatch::CoinJoin {
            account_index: 5,
            involved_addresses: vec![], // Empty for simplicity
        };

        // Verify that account_index() returns the correct index
        assert_eq!(coinjoin_match.account_index(), Some(5));

        // Verify that to_account_type_to_check() returns the correct type
        assert!(matches!(coinjoin_match.to_account_type_to_check(), AccountTypeToCheck::CoinJoin));

        // Verify that all_involved_addresses() works correctly
        let all_addresses = coinjoin_match.all_involved_addresses();
        assert_eq!(all_addresses.len(), 0);
    }

    #[test]
    fn test_standard_accounts_have_separate_receive_and_change() {
        // Test StandardBIP44 account has both receive and change addresses
        let bip44_match = AccountTypeMatch::StandardBIP44 {
            account_index: 0,
            involved_receive_addresses: vec![],
            involved_change_addresses: vec![],
        };

        // Verify the structure exists with separate fields
        assert_eq!(bip44_match.account_index(), Some(0));

        // Test StandardBIP32 account also has separate receive and change addresses
        let bip32_match = AccountTypeMatch::StandardBIP32 {
            account_index: 1,
            involved_receive_addresses: vec![],
            involved_change_addresses: vec![],
        };

        assert_eq!(bip32_match.account_index(), Some(1));
    }
}
