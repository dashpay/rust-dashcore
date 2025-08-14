//! Account-level transaction checking
//!
//! This module provides methods for checking if transactions belong to
//! specific accounts within a ManagedAccountCollection.

use crate::account::{ManagedAccount, ManagedAccountCollection};
use crate::Address;
use super::transaction_router::AccountTypeToCheck;
use dashcore::blockdata::transaction::Transaction;
use dashcore::blockdata::script::ScriptBuf;
use alloc::vec::Vec;

/// Result of checking a transaction against accounts
#[derive(Debug, Clone)]
pub struct TransactionCheckResult {
    /// Whether the transaction belongs to any account
    pub is_relevant: bool,
    /// Accounts that the transaction affects
    pub affected_accounts: Vec<AccountMatch>,
    /// Total value received by our accounts
    pub total_received: u64,
    /// Total value sent from our accounts
    pub total_sent: u64,
}

/// Information about a matched account
#[derive(Debug, Clone)]
pub struct AccountMatch {
    /// The type of account that matched
    pub account_type: AccountTypeToCheck,
    /// Index of the account (if applicable)
    pub account_index: Option<u32>,
    /// Addresses involved in the transaction
    pub involved_addresses: Vec<Address>,
    /// Value received by this account
    pub received: u64,
    /// Value sent from this account
    pub sent: u64,
}

/// Checker for account-level transaction checking
pub struct AccountTransactionChecker;

impl AccountTransactionChecker {
    /// Check if a transaction belongs to any accounts in the collection
    pub fn check_transaction(
        collection: &ManagedAccountCollection,
        tx: &Transaction,
        account_types: &[AccountTypeToCheck],
    ) -> TransactionCheckResult {
        let mut result = TransactionCheckResult {
            is_relevant: false,
            affected_accounts: Vec::new(),
            total_received: 0,
            total_sent: 0,
        };

        for account_type in account_types {
            if let Some(match_info) = Self::check_account_type(collection, tx, account_type) {
                result.is_relevant = true;
                result.total_received += match_info.received;
                result.total_sent += match_info.sent;
                result.affected_accounts.push(match_info);
            }
        }

        result
    }

    /// Check a specific account type for transaction involvement
    fn check_account_type(
        collection: &ManagedAccountCollection,
        tx: &Transaction,
        account_type: &AccountTypeToCheck,
    ) -> Option<AccountMatch> {
        match account_type {
            AccountTypeToCheck::StandardBIP44 => {
                Self::check_indexed_accounts(&collection.standard_bip44_accounts, tx, account_type.clone())
            }
            AccountTypeToCheck::StandardBIP32 => {
                Self::check_indexed_accounts(&collection.standard_bip32_accounts, tx, account_type.clone())
            }
            AccountTypeToCheck::CoinJoin => {
                Self::check_indexed_accounts(&collection.coinjoin_accounts, tx, account_type.clone())
            }
            AccountTypeToCheck::IdentityRegistration => {
                collection.identity_registration.as_ref().and_then(|account| {
                    Self::check_single_account(account, tx, account_type.clone(), None)
                })
            }
            AccountTypeToCheck::IdentityTopUp => {
                Self::check_indexed_accounts(&collection.identity_topup, tx, account_type.clone())
            }
            AccountTypeToCheck::IdentityTopUpNotBound => {
                collection.identity_topup_not_bound.as_ref().and_then(|account| {
                    Self::check_single_account(account, tx, account_type.clone(), None)
                })
            }
            AccountTypeToCheck::IdentityInvitation => {
                collection.identity_invitation.as_ref().and_then(|account| {
                    Self::check_single_account(account, tx, account_type.clone(), None)
                })
            }
            AccountTypeToCheck::ProviderVotingKeys => {
                collection.provider_voting_keys.as_ref().and_then(|account| {
                    Self::check_single_account(account, tx, account_type.clone(), None)
                })
            }
            AccountTypeToCheck::ProviderOwnerKeys => {
                collection.provider_owner_keys.as_ref().and_then(|account| {
                    Self::check_single_account(account, tx, account_type.clone(), None)
                })
            }
            AccountTypeToCheck::ProviderOperatorKeys => {
                collection.provider_operator_keys.as_ref().and_then(|account| {
                    Self::check_single_account(account, tx, account_type.clone(), None)
                })
            }
            AccountTypeToCheck::ProviderPlatformKeys => {
                collection.provider_platform_keys.as_ref().and_then(|account| {
                    Self::check_single_account(account, tx, account_type.clone(), None)
                })
            }
        }
    }

    /// Check indexed accounts (BTreeMap of accounts)
    fn check_indexed_accounts(
        accounts: &alloc::collections::BTreeMap<u32, ManagedAccount>,
        tx: &Transaction,
        account_type: AccountTypeToCheck,
    ) -> Option<AccountMatch> {
        for (index, account) in accounts {
            if let Some(match_info) = Self::check_single_account(account, tx, account_type.clone(), Some(*index)) {
                return Some(match_info);
            }
        }
        None
    }

    /// Check a single account for transaction involvement
    fn check_single_account(
        account: &ManagedAccount,
        tx: &Transaction,
        account_type: AccountTypeToCheck,
        index: Option<u32>,
    ) -> Option<AccountMatch> {
        let mut involved_addresses = Vec::new();
        let mut received = 0u64;
        let sent = 0u64;

        // Check outputs (received)
        for output in &tx.output {
            if let Some(address) = Self::extract_address_from_script(&output.script_pubkey) {
                if account.contains_address(&address) {
                    involved_addresses.push(address);
                    received += output.value;
                }
            }
        }

        // Check inputs (sent) - would need UTXO information to properly calculate
        // For now, we just mark that addresses are involved
        // In a real implementation, we'd look up the previous outputs being spent

        if !involved_addresses.is_empty() {
            Some(AccountMatch {
                account_type,
                account_index: index,
                involved_addresses,
                received,
                sent,
            })
        } else {
            None
        }
    }

    /// Extract address from a script (simplified)
    fn extract_address_from_script(script: &ScriptBuf) -> Option<Address> {
        // This is a simplified implementation
        // Real implementation would properly parse all script types
        Address::from_script(script, dashcore::Network::Dash).ok()
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