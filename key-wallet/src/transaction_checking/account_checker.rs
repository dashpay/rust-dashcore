//! Account-level transaction checking
//!
//! This module provides methods for checking if transactions belong to
//! specific accounts within a ManagedAccountCollection.

use super::transaction_router::AccountTypeToCheck;
use crate::account::{ManagedAccount, ManagedAccountCollection};
use crate::Address;
use alloc::vec::Vec;
use dashcore::blockdata::transaction::Transaction;

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

impl ManagedAccountCollection {
    /// Check if a transaction belongs to any accounts in the collection
    pub fn check_transaction(
        &self,
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
            if let Some(match_info) = self.check_account_type(tx, *account_type) {
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
        &self,
        tx: &Transaction,
        account_type: AccountTypeToCheck,
    ) -> Option<AccountMatch> {
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
                .and_then(|account| account.check_transaction_for_match(tx, None)),
            AccountTypeToCheck::IdentityTopUp => {
                Self::check_indexed_accounts(&self.identity_topup, tx)
            }
            AccountTypeToCheck::IdentityTopUpNotBound => self
                .identity_topup_not_bound
                .as_ref()
                .and_then(|account| account.check_transaction_for_match(tx, None)),
            AccountTypeToCheck::IdentityInvitation => self
                .identity_invitation
                .as_ref()
                .and_then(|account| account.check_transaction_for_match(tx, None)),
            AccountTypeToCheck::ProviderVotingKeys => self
                .provider_voting_keys
                .as_ref()
                .and_then(|account| account.check_transaction_for_match(tx, None)),
            AccountTypeToCheck::ProviderOwnerKeys => self
                .provider_owner_keys
                .as_ref()
                .and_then(|account| account.check_transaction_for_match(tx, None)),
            AccountTypeToCheck::ProviderOperatorKeys => self
                .provider_operator_keys
                .as_ref()
                .and_then(|account| account.check_transaction_for_match(tx, None)),
            AccountTypeToCheck::ProviderPlatformKeys => self
                .provider_platform_keys
                .as_ref()
                .and_then(|account| account.check_transaction_for_match(tx, None)),
        }
    }

    /// Check indexed accounts (BTreeMap of accounts)
    fn check_indexed_accounts(
        accounts: &alloc::collections::BTreeMap<u32, ManagedAccount>,
        tx: &Transaction,
    ) -> Option<AccountMatch> {
        for (index, account) in accounts {
            if let Some(match_info) = account.check_transaction_for_match(tx, Some(*index)) {
                return Some(match_info);
            }
        }
        None
    }
}

impl ManagedAccount {
    /// Check a single account for transaction involvement
    pub fn check_transaction_for_match(
        &self,
        tx: &Transaction,
        index: Option<u32>,
    ) -> Option<AccountMatch> {
        let mut involved_addresses = Vec::new();
        let mut received = 0u64;
        let sent = 0u64;

        // Check outputs (received)
        for output in &tx.output {
            if self.contains_script_pub_key(&output.script_pubkey) {
                if let Ok(address) = Address::from_script(&output.script_pubkey, self.network) {
                    involved_addresses.push(address);
                }
                received += output.value;
            }
        }

        // Check inputs (sent) - would need UTXO information to properly calculate
        // For now, we just mark that addresses are involved
        // In a real implementation, we'd look up the previous outputs being spent

        if !involved_addresses.is_empty() {
            Some(AccountMatch {
                account_type: (&self.account_type).into(),
                account_index: index,
                involved_addresses,
                received,
                sent,
            })
        } else {
            None
        }
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
